"""Java SAST adapter (tree-sitter-java) for OWASP-Benchmark-style servlets.

Detects taint flows from request sources to dangerous sinks, plus simple
pattern-based signals for the non-taint categories (weak crypto, weak hash,
weak randomness, insecure cookies). Emits findings whose ``category`` matches the
OWASP Benchmark category names (``sqli``, ``cmdi``, ``pathtraver``, ``xss``,
``ldapi``, ``xpathi``, ``trustbound``, ``crypto``, ``hash``, ``weakrand``,
``securecookie``).
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Set

from tree_sitter import Node

from ..analysis import AnalysisResult, Finding
from ..ir import EdgeKind, Graph, NodeKind
from .driver import parser_for

# request methods that introduce untrusted data (plus OWASP helper names).
_SOURCE_METHODS = {
    "getParameter", "getParameterValues", "getParameterMap", "getHeader",
    "getHeaders", "getCookies", "getQueryString", "getInputStream", "getReader",
    "getPathInfo", "getPathTranslated", "getRequestURI", "getRequestedSessionId",
    "getRemoteUser", "getAttribute", "getTheValue", "getTheParameter",
    "getTheCookie", "getTheParameterMap", "getValue", "getenv", "getProperty",
}

# sink method name -> category.
_SINKS: Dict[str, str] = {
    "execute": "sqli", "executeQuery": "sqli", "executeUpdate": "sqli",
    "executeLargeUpdate": "sqli", "prepareStatement": "sqli",
    "prepareCall": "sqli", "addBatch": "sqli",
    "exec": "cmdi", "start": "cmdi", "loadLibrary": "cmdi", "eval": "cmdi",
    "write": "xss", "println": "xss", "print": "xss", "append": "xss",
    "sendError": "xss",
    "search": "ldapi", "lookup": "ldapi",
    "evaluate": "xpathi", "compile": "xpathi",
    "setAttribute": "trustbound",
}

# constructor types that open files (path traversal).
_PATHTRAVER_TYPES = {"FileInputStream", "FileReader", "FileWriter", "RandomAccessFile", "File", "FileOutputStream"}

_SANITIZERS = {"encodeForSQL", "encodeForHTML", "encodeForJavaScript", "encodeForOS", "encodeForLDAP", "escapeSql", "escapeHtml"}


def _name_of(node: Optional[Node]) -> str:
    if node is None:
        return ""
    name = node.child_by_field_name("name")
    return name.text.decode() if name else ""


def _args(node: Optional[Node]) -> List[Node]:
    args = node.child_by_field_name("arguments") if node else None
    if args is None:
        return []
    return list(args.named_children)


class JavaIngest:
    def analyze(self, code: str, path: str = "<java>") -> AnalysisResult:
        parser = parser_for("java")
        tree = parser.parse(code.encode())
        root = tree.root_node

        graph = Graph()
        graph.meta = {"language": "java", "file": path}
        findings: List[Finding] = []
        env: Dict[str, Set[str]] = {}

        self._walk(root, graph, env, findings, path)
        findings.extend(self._pattern_findings(code, path))
        return AnalysisResult(graph=graph, findings=findings)

    # -- taint over statements --------------------------------------------
    def _walk(self, node: Node, graph: Graph, env: Dict[str, Set[str]], findings: List[Finding], path: str) -> None:
        for child in node.named_children:
            t = child.type
            if t == "local_variable_declaration":
                for d in child.named_children:
                    if d.type == "variable_declarator":
                        self._assign(d, env, findings, path)
            elif t == "expression_statement":
                self._expression(child.named_children[0] if child.named_children else None, env, findings, path)
            elif t == "assignment_expression":
                self._assign(child, env, findings, path)
            elif t == "return_statement":
                for c in child.named_children:
                    if c.type not in ("return", ";"):
                        self._taint(c, env, findings, path)
            else:
                self._walk(child, graph, env, findings, path)

    def _assign(self, node: Node, env: Dict[str, Set[str]], findings: List[Finding], path: str) -> None:
        # variable_declarator: name = value ; assignment_expression: left = right
        left = node.child_by_field_name("left")
        if left is None:
            left = node.child_by_field_name("name")
        right = node.child_by_field_name("right")
        if right is None:
            right = node.child_by_field_name("value")
        target = left.text.decode() if left is not None and left.type == "identifier" else ""
        if not target:
            return
        tags = self._taint(right, env, findings, path)
        if tags:
            env[target] = tags
        else:
            env.pop(target, None)

    def _expression(self, expr: Optional[Node], env: Dict[str, Set[str]], findings: List[Finding], path: str) -> None:
        if expr is None:
            return
        if expr.type == "assignment_expression":
            self._assign(expr, env, findings, path)
        else:
            self._taint(expr, env, findings, path)

    def _taint(self, node: Optional[Node], env: Dict[str, Set[str]], findings: List[Finding], path: str) -> Set[str]:
        if node is None:
            return set()
        t = node.type

        if t == "identifier":
            return set(env.get(node.text.decode(), set()))

        if t == "method_invocation":
            name = _name_of(node)
            obj = node.child_by_field_name("object")
            tags: Set[str] = set()
            if name in _SOURCE_METHODS or "getParameter" in name or "getHeader" in name or "getCookie" in name:
                tags.add("input")
            if name in _SANITIZERS:
                return set()
            if name in _SINKS:
                self._sink(node, name, obj, _SINKS[name], env, findings, path)
                return set()
            # Propagate the receiver's taint (e.g. taintedEnum.nextElement()).
            if obj is not None:
                tags |= self._taint(obj, env, findings, path)
            # Propagate through arguments.
            for arg in _args(node):
                tags |= self._taint(arg, env, findings, path)
            return tags

        if t == "object_creation_expression":
            type_node = node.child_by_field_name("type")
            type_name = type_node.text.decode() if type_node else ""
            if type_name.split(".")[-1] in _PATHTRAVER_TYPES:
                self._sink(node, type_name, None, "pathtraver", env, findings, path)
                return set()
            tags = set()
            for arg in _args(node):
                tags |= self._taint(arg, env, findings, path)
            return tags

        if t == "binary_expression":
            tags: Set[str] = set()
            for c in node.named_children:
                tags |= self._taint(c, env, findings, path)
            return tags

        if t in ("string_literal", "integer_literal", "decimal_floating_point_literal", "true", "false", "null_literal", "character_literal"):
            return set()

        if t in ("parenthesized_expression", "cast_expression"):
            return self._taint(node.named_children[-1] if node.named_children else None, env, findings, path)

        # default: union over named children
        tags: Set[str] = set()
        for c in node.named_children:
            tags |= self._taint(c, env, findings, path)
        return tags

    def _sink(self, node, name, obj, category, env, findings, path) -> None:
        args = _args(node)
        arg_tags: Set[str] = set()
        for arg in args:
            arg_tags |= self._taint(arg, env, findings, path)
        if not arg_tags:
            return
        findings.append(
            Finding(
                kind="taint",
                title=f"{category} via {name}",
                description=f"Untrusted input reaches {category} sink {name}.",
                severity="high" if category in ("sqli", "cmdi") else "medium",
                category=category,
                file=path,
                line=node.start_point[0] + 1,
                source_names=["input"],
                sink_name=name,
            )
        )

    # -- pattern categories -------------------------------------------------
    def _pattern_findings(self, code: str, path: str) -> List[Finding]:
        findings: List[Finding] = []

        def add(category: str, title: str, line: int) -> None:
            findings.append(
                Finding(
                    kind="pattern", title=title, description=title,
                    severity="medium", category=category, file=path,
                    line=line, sink_name=category,
                )
            )

        # weak crypto (DES / RC4 / Blowfish / RC2)
        for m in re.finditer(r'Cipher\.getInstance\s*\(\s*"([^"]+)"', code):
            algo = m.group(1)
            if re.search(r"DES|RC4|RC2|Blowfish|DESede", algo, re.I):
                add("crypto", f"weak cipher {algo}", code.count("\n", 0, m.start()) + 1)

        # weak hash (MD5 / SHA-1)
        for m in re.finditer(r'MessageDigest\.getInstance\s*\(\s*"([^"]+)"', code):
            algo = m.group(1)
            if re.search(r"MD5|SHA-?1\b", algo, re.I):
                add("hash", f"weak hash {algo}", code.count("\n", 0, m.start()) + 1)

        # weak randomness (Math.random / new Random, not SecureRandom)
        for m in re.finditer(r'Math\.random|new\s+Random\s*\(', code):
            add("weakrand", "weak randomness", code.count("\n", 0, m.start()) + 1)

        # insecure cookie flags
        for m in re.finditer(r'\.setSecure\s*\(\s*false\s*\)', code):
            add("securecookie", "cookie not secure", code.count("\n", 0, m.start()) + 1)

        return findings

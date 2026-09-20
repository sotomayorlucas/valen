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
    "printf": "xss", "format": "xss", "sendError": "xss",
    "search": "ldapi", "lookup": "ldapi",
    "evaluate": "xpathi", "compile": "xpathi",
    "setAttribute": "trustbound",
}

# constructor types that open files (path traversal).
_PATHTRAVER_TYPES = {"FileInputStream", "FileReader", "FileWriter", "RandomAccessFile", "File", "FileOutputStream"}

_SANITIZERS = {"encodeForSQL", "encodeForHTML", "encodeForJavaScript", "encodeForOS", "encodeForLDAP", "escapeSql", "escapeHtml"}

# methods that store their argument into the receiver object (state taint).
_MUTATORS = {
    "add", "put", "putAll", "append", "command", "setString", "setObject",
    "setInt", "setHeader", "setAttribute", "insert", "write", "println", "print",
}


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


def enumerate_sinks(code: str) -> List[dict]:
    """Enumerate *every* sink call in the file (tainted or not).

    This is the candidate set for the prioritization-oracle experiment: the
    vulnerable sink must be ranked highly among all sinks.
    """
    parser = parser_for("java")
    tree = parser.parse(code.encode())
    return enumerate_sinks_root(tree.root_node)


def enumerate_sinks_root(root: Node) -> List[dict]:
    out: List[dict] = []

    def walk(node: Node) -> None:
        if node.type == "method_invocation":
            name = _name_of(node)
            if name in _SINKS:
                out.append({"line": node.start_point[0] + 1, "name": name, "category": _SINKS[name]})
        elif node.type == "object_creation_expression":
            type_node = node.child_by_field_name("type")
            type_name = type_node.text.decode() if type_node else ""
            if type_name.split(".")[-1] in _PATHTRAVER_TYPES:
                out.append({"line": node.start_point[0] + 1, "name": type_name, "category": "pathtraver"})
        for c in node.named_children:
            walk(c)

    walk(root)
    return out


def methods_of_cached(root: Node) -> List[dict]:
    """Method declarations under ``root``: ``{name, line, end_line}``."""
    out: List[dict] = []

    def walk(node: Node) -> None:
        if node.type == "method_declaration":
            name = node.child_by_field_name("name")
            out.append({
                "name": name.text.decode() if name else "?",
                "line": node.start_point[0] + 1,
                "end_line": node.end_point[0] + 1,
            })
        for c in node.named_children:
            walk(c)

    walk(root)
    return out


def methods_of(code: str) -> List[dict]:
    """Return method declarations as ``{name, line, end_line}``."""
    parser = parser_for("java")
    tree = parser.parse(code.encode())
    return methods_of_cached(tree.root_node)


class JavaIngest:
    def analyze(self, code: str, path: str = "<java>") -> AnalysisResult:
        parser = parser_for("java")
        tree = parser.parse(code.encode())
        root = tree.root_node

        graph = Graph()
        graph.meta = {"language": "java", "file": path}
        findings: List[Finding] = []
        env: Dict[str, Set[str]] = {}
        self._seen: Set[tuple] = set()
        self._writers: Set[str] = set()

        self._walk(root, graph, env, findings, path)
        findings.extend(self._pattern_findings(code, path))
        self._build_graph(root, graph, findings, path)
        return AnalysisResult(graph=graph, findings=findings)

    def _build_graph(self, root: Node, graph: Graph, findings: List[Finding], path: str) -> None:
        """Emit the IR: methods, call edges, and source/sink/taint nodes."""
        methods = methods_of_cached(root)
        name_to_id: Dict[str, str] = {}
        for i, m in enumerate(methods, 1):
            nid = f"fn{i}"
            name_to_id.setdefault(m["name"], nid)
            graph.add_node(
                nid, NodeKind.FUNCTION, m["name"], file=path,
                line=m["line"], end_line=m["end_line"],
            )

        def walk_calls(node: Node, current: str) -> None:
            for c in node.named_children:
                if c.type == "method_declaration":
                    nm = c.child_by_field_name("name")
                    walk_calls(c, nm.text.decode() if nm else current)
                elif c.type == "method_invocation":
                    nm = c.child_by_field_name("name")
                    callee = nm.text.decode() if nm else ""
                    if current in name_to_id and callee in name_to_id:
                        graph.add_edge(name_to_id[current], name_to_id[callee], EdgeKind.CALL)
                    walk_calls(c, current)
                else:
                    walk_calls(c, current)

        walk_calls(root, "")

        # One SINK node per candidate (tainted or not), attached to its enclosing
        # method so structural signals reach it; tainted candidates also get a
        # SOURCE node and a TAINT edge.
        tainted_keys = {(f.category, f.line) for f in findings}

        def enclosing(line: int) -> Optional[str]:
            for m in methods:
                if m["line"] <= line <= m["end_line"]:
                    return name_to_id.get(m["name"])
            return None

        for i, s in enumerate(enumerate_sinks_root(root), 1):
            snk = f"sink_{i}"
            graph.add_node(
                snk, NodeKind.SINK, s["name"], file=path, line=s["line"],
                attrs={"category": s["category"]},
            )
            host = enclosing(s["line"])
            if host is not None:
                graph.add_edge(host, snk, EdgeKind.CALL)
            if (s["category"], s["line"]) in tainted_keys:
                src = f"src_{i}"
                graph.add_node(src, NodeKind.SOURCE, "input", file=path, line=s["line"])
                graph.add_edge(src, snk, EdgeKind.TAINT)

    def _emit(self, node: Node, name: str, category: str, findings: List[Finding], path: str) -> None:
        key = (category, name, node.start_point[0])
        if key in self._seen:
            return
        self._seen.add(key)
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
            elif t == "if_statement":
                self._if_statement(child, graph, env, findings, path)
            elif t == "return_statement":
                for c in child.named_children:
                    if c.type not in ("return", ";"):
                        self._taint(c, env, findings, path)
            else:
                self._walk(child, graph, env, findings, path)

    @staticmethod
    def _clone_env(env: Dict[str, Set[str]]) -> Dict[str, Set[str]]:
        return {k: set(v) for k, v in env.items()}

    def _if_statement(self, node: Node, graph: Graph, env: Dict[str, Set[str]], findings: List[Finding], path: str) -> None:
        """Branch-aware taint: join (union) the two branch environments."""
        consequence = node.child_by_field_name("consequence")
        alternative = node.child_by_field_name("alternative")

        snapshot = self._clone_env(env)
        if consequence is not None:
            self._walk(consequence, graph, env, findings, path)
        then_env = self._clone_env(env)

        env.clear()
        env.update(snapshot)
        if alternative is not None:
            self._walk(alternative, graph, env, findings, path)
        else_env = self._clone_env(env)

        merged: Dict[str, Set[str]] = {}
        for key in set(then_env) | set(else_env):
            tags = set(then_env.get(key, set())) | set(else_env.get(key, set()))
            if tags:
                merged[key] = tags
        env.clear()
        env.update(merged)

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
        if right is not None and "getWriter" in right.text.decode():
            self._writers.add(target)
        if tags:
            env[target] = tags
        else:
            env.pop(target, None)

    def _is_response_writer(self, obj: Optional[Node]) -> bool:
        if obj is None:
            return False
        if obj.type == "method_invocation" and _name_of(obj) == "getWriter":
            return True
        if obj.type == "identifier" and obj.text.decode() in self._writers:
            return True
        return False

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
            if name in _SANITIZERS:
                return set()
            tags: Set[str] = set()
            if name in _SOURCE_METHODS or "getParameter" in name or "getHeader" in name or "getCookie" in name:
                tags.add("input")
            # receiver taint (e.g. taintedEnum.nextElement(), taintedStmt.execute()).
            if obj is not None:
                tags |= self._taint(obj, env, findings, path)
            # argument taint.
            arg_tags: Set[str] = set()
            for arg in _args(node):
                arg_tags |= self._taint(arg, env, findings, path)
            tags |= arg_tags

            if name in _SINKS:
                category = _SINKS[name]
                # Only writes to the HTTP response writer are XSS; System.out /
                # logger / exception prints are not.
                if category == "xss" and not self._is_response_writer(obj):
                    return tags
                if tags:
                    self._emit(node, name, category, findings, path)
                # Propagate so the result object stays tainted (prepareStatement
                # -> statement -> execute()).
                return tags

            # state taint: a mutator stores its argument into the receiver.
            if name in _MUTATORS and arg_tags and obj is not None and obj.type == "identifier":
                env.setdefault(obj.text.decode(), set()).update(arg_tags)
            return tags

        if t == "object_creation_expression":
            type_node = node.child_by_field_name("type")
            type_name = type_node.text.decode() if type_node else ""
            tags = set()
            for arg in _args(node):
                tags |= self._taint(arg, env, findings, path)
            if type_name.split(".")[-1] in _PATHTRAVER_TYPES and tags:
                self._emit(node, type_name, "pathtraver", findings, path)
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

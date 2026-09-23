"""Generic C-like taint adapter for tree-sitter languages.

One implementation drives many grammars (C, C++, Rust, C#, Go, PHP, Ruby,
JavaScript). The per-language knowledge lives entirely in the ``LanguageProfile``
(sources / sinks / sanitizers), so adding a language is registering its grammar
and profile.

The pass is a **local, syntactic taint**:

* every call expression resolves its callee name (including a receiver, e.g.
  ``os.Remove``, ``std::env::args``, ``$conn->query``);
* a source is either a call to a known source *or* a bare variable whose name
  matches the profile (e.g. ``$_GET``, ``argv``, ``getenv``);
* straight-line assignments ``x = <source>`` taint ``x``;
* a sink reached by a tainted value (a call argument or a tracked variable)
  emits a finding; a sink with no tracked source is still recorded as a
  candidate node (so the ranking oracle can enumerate sinks).

Honest limits: no interprocedural, aliasing, or control-flow sensitivity.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Set

from tree_sitter import Node

from ..analysis import AnalysisResult, Finding
from ..ir import EdgeKind, Graph, NodeKind
from .driver import parser_for
from .sources_sinks import CATEGORY_SEVERITY, LanguageProfile

_CALL_TYPES = (
    "call_expression", "function_call", "function_call_expression", "method_invocation",
    "method_call_expression", "call", "command_call", "macro_invocation",
    "member_call_expression", "navigation_expression", "invocation_expression",
)
_VAR_TYPES = ("identifier", "name", "variable_name", "field_identifier",
              "property_identifier", "type_identifier", "method_name", "function_name",
              "namespace_identifier")
_ASSIGN_TYPES = ("assignment_expression", "assignment_statement", "assignment",
                 "let_declaration", "short_var_declaration", "variable_declarator",
                 "init_declarator")


def _text(node: Node) -> str:
    return (node.text or b"").decode("utf-8", "replace")


def _leaf_name(name: str) -> str:
    for sep in (".", "->", "::", "\\", "#", ":"):
        name = name.rsplit(sep, 1)[-1]
    return name


def _is_call(node: Node) -> bool:
    return node.type in _CALL_TYPES or node.type.endswith("_call_expression")


class CLikeIngest:
    """Taint adapter driven by a ``LanguageProfile``."""

    def __init__(self, profile: LanguageProfile) -> None:
        self.profile = profile
        self._seq = 0

    def _new_id(self, prefix: str) -> str:
        self._seq += 1
        return f"{prefix}{self._seq}"

    def analyze(self, code: str, path: str = "<source>") -> AnalysisResult:
        parser = parser_for(self.profile.name)
        tree = parser.parse(code.encode())

        graph = Graph()
        graph.meta = {"language": self.profile.name, "file": path,
                      "lines": code.count("\n") + 1}
        findings: List[Finding] = []
        self._walk(tree.root_node, graph, {}, findings, path)
        return AnalysisResult(graph=graph, findings=findings)

    # -- profile resolution ------------------------------------------------
    def _match(self, name: str, table: Dict[str, str]) -> Optional[str]:
        if not name:
            return None
        if name in table:
            return name
        leaf = _leaf_name(name)
        if leaf in table:
            return leaf
        for key in table:
            if key.rsplit(".", 1)[-1] == leaf or key.rsplit("::", 1)[-1] == leaf:
                return key
        return None

    def _is_source_name(self, name: str) -> bool:
        return self._match(name, self.profile.sources) is not None

    # -- call helpers ------------------------------------------------------
    def _callee_name(self, node: Node) -> str:
        fn = node.child_by_field_name("function")
        if fn is not None:
            return _text(fn)
        for ch in node.children:
            if ch.type in _VAR_TYPES:
                return _text(ch)
            if ch.type in ("scoped_identifier", "field_expression", "member_expression",
                           "selector_expression", "call_expression", "member_call_expression",
                           "navigation_expression", "name"):
                return _text(ch)
        return ""

    def _call_args(self, node: Node) -> List[Node]:
        """Argument subtrees of a call (skip the callee and punctuation)."""
        args: List[Node] = []
        for ch in node.children:
            if ch.type in ("arguments", "argument_list", "call_suffix", "call_arguments"):
                args.extend(ch.children)
            elif ch.type not in _VAR_TYPES and ch.type not in (
                "scoped_identifier", "field_expression", "member_expression",
                "selector_expression", "field_access", "name", "namespace_identifier",
                "call_expression", "member_call_expression", "navigation_expression",
                "(", ")", ".", "->", "::", ":", "?", ";", ",",
            ):
                args.append(ch)
        return args

    # -- taint helpers -----------------------------------------------------
    def _node_taint(self, node: Node, env: Dict[str, Set[str]]) -> Set[str]:
        """Tags carried by ``node``: a source name or a tracked variable."""
        tags: Set[str] = set()
        if node.type in _VAR_TYPES:
            var = _text(node)
            if var in env:
                tags |= env[var]
            if self._is_source_name(var):
                tags.add(f"src:{self._match(var, self.profile.sources)}")
            return tags
        if _is_call(node):
            name = self._callee_name(node)
            if self._match(name, self.profile.sources):
                tags.add(f"src:{self._match(name, self.profile.sources)}")
        for ch in node.children:
            tags |= self._node_taint(ch, env)
        return tags

    def _args_taint(self, node: Node, env: Dict[str, Set[str]]) -> Set[str]:
        tags: Set[str] = set()
        for a in self._call_args(node):
            tags |= self._node_taint(a, env)
        return tags

    # -- walk --------------------------------------------------------------
    def _walk(self, node: Node, graph: Graph, env: Dict[str, Set[str]],
              findings: List[Finding], path: str) -> Dict[str, Set[str]]:
        env = dict(env)
        for child in node.children:
            env = self._step(child, graph, env, findings, path)
        return env

    def _step(self, node: Node, graph: Graph, env: Dict[str, Set[str]],
              findings: List[Finding], path: str) -> Dict[str, Set[str]]:
        # assignment: x = expr  (or x := expr)
        if node.type in _ASSIGN_TYPES:
            lhs = node.child_by_field_name("left") or node.child_by_field_name("name") \
                or node.child_by_field_name("declarator")
            rhs = node.child_by_field_name("right") or node.child_by_field_name("value")
            if lhs is None:
                ids = [c for c in node.children if c.type in _VAR_TYPES]
                lhs = ids[0] if ids else None
            if rhs is None:
                # positional: the expression after the assignment operator
                op_seen = False
                for c in node.children:
                    if c.type in ("=", ":=", ":"):
                        op_seen = True
                        continue
                    if op_seen and c.type not in (",", ";"):
                        rhs = c
                        break
            if lhs is not None and rhs is not None:
                var = self._lhs_name(lhs)
                tags = self._node_taint(rhs, env)
                if var and tags:
                    env[var] = set(tags)
                elif var:
                    env.pop(var, None)
                return self._step(rhs, graph, env, findings, path)

        # call
        if _is_call(node):
            name = self._callee_name(node)
            sink_key = self._match(name, self.profile.sinks) if name else None
            if sink_key is not None:
                line = node.start_point[0] + 1
                category = self.profile.sinks[sink_key]
                severity = CATEGORY_SEVERITY.get(category, "medium")
                sink_id = self._new_id("sink")
                graph.add_node(sink_id, NodeKind.SINK, sink_key, file=path, line=line,
                               attrs={"category": category})
                tags = self._args_taint(node, env)
                if tags:
                    src_id = self._new_id("src")
                    graph.add_node(src_id, NodeKind.SOURCE, next(iter(tags)), file=path, line=line)
                    graph.add_edge(src_id, sink_id, EdgeKind.TAINT)
                    findings.append(Finding(
                        kind="taint",
                        title=f"{self.profile.name}: untrusted input reaches {sink_key}",
                        description=f"Data from {sorted(tags)} flows into {sink_key}.",
                        severity=severity,
                        category=category,
                        file=path,
                        line=line,
                        source_names=sorted(tags),
                        sink_name=sink_key,
                    ))
            # output-parameter sources: fgets(b, ...), gets(b), scanf(..., &b).
            # A name may be both sink and source (e.g. C gets) — taint too.
            src_key = self._match(name, self.profile.sources) if name else None
            if src_key is not None:
                tag = f"src:{src_key}"
                for a in self._call_args(node):
                    for var_node in self._var_nodes(a):
                        var = _leaf_name(_text(var_node))
                        if var:
                            env.setdefault(var, set()).add(tag)
            return self._walk(node, graph, env, findings, path)

        return self._walk(node, graph, env, findings, path)

    @staticmethod
    def _lhs_name(node: Node) -> str:
        """Declarator/assignment target -> bare variable name (``*cmd`` -> ``cmd``)."""
        if node.type in _VAR_TYPES:
            return _leaf_name(_text(node))
        for ch in node.children:
            name = CLikeIngest._lhs_name(ch)
            if name:
                return name
        return ""

    @staticmethod
    def _var_nodes(node: Node) -> List[Node]:
        """Variable-ish leaves of ``node`` (handles ``&b``, ``*b``, ``b[i]``)."""
        if node.type in _VAR_TYPES:
            return [node]
        if node.type in ("unary_expression", "pointer_expression", "subscript_expression",
                         "argument_list", "arguments"):
            out: List[Node] = []
            for ch in node.children:
                out.extend(CLikeIngest._var_nodes(ch))
            return out
        return []

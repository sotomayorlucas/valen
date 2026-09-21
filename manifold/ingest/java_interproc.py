"""Interprocedural taint for Java (context-insensitive fixpoint).

The intraprocedural adapter misses flows that cross method boundaries (a caller
passes untrusted data to a callee's parameter; a callee returns tainted data).
This analyzer runs a fixpoint over the call graph:

1. every method is analyzed, recording (a) which arguments flow to a known
   callee's parameters and (b) whether the method returns a tainted value;
2. a callee parameter becomes tainted if some call site passes tainted data to
   it, and a call becomes tainted if its callee returns tainted data;
3. the fixpoint is re-run until stable, then a final pass emits findings.

It is deliberately coarse (context-insensitive, by method name) but recovers the
cross-class flows that the intraprocedural adapter drops on Juliet and on
framework-mediated real CVEs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from ..analysis import AnalysisResult, Finding
from ..ir import EdgeKind, Graph, NodeKind
from .driver import parser_for
from .java import (
    _MUTATORS,
    _PATHTRAVER_TYPES,
    _SANITIZERS,
    _SINKS,
    _SOURCE_METHODS,
    _args,
    _name_of,
)
from .sources_sinks import CATEGORY_SEVERITY


def _is_source(name: str) -> bool:
    return name in _SOURCE_METHODS or "getParameter" in name or "getHeader" in name or "getCookie" in name


@dataclass
class Method:
    name: str
    params: List[str]
    body: object
    line: int
    end_line: int
    nid: str


@dataclass
class Facts:
    callee_params: Set[Tuple[int, int]] = field(default_factory=set)  # (method index, param index)
    returns_tainted: bool = False


class JavaInterproceduralIngest:
    def analyze(self, code: str, path: str = "<java>", context_sensitive: bool = False) -> AnalysisResult:
        parser = parser_for("java")
        tree = parser.parse(code.encode())
        root = tree.root_node

        methods = self._collect(root)
        by_name: Dict[str, int] = {}
        for i, m in enumerate(methods):
            by_name.setdefault(m.name, i)

        return_tainted: Set = set()
        self._cs = context_sensitive
        self._cur_method_name = ""

        if context_sensitive:
            # Caller-context sensitivity: a method is analyzed once per distinct
            # caller method, so a parameter tainted by one caller does not taint
            # the same parameter reached by a clean caller. Return-taint is also
            # tracked per context.
            seeds: Dict[Tuple[int, str], Set[int]] = {}
            processed: Set[Tuple[int, str, Tuple[int, ...]]] = set()
            work: List[Tuple[int, str, Tuple[int, ...]]] = [(i, "<entry>", ()) for i in range(len(methods))]
            while work:
                i, ctx, seed = work.pop()
                key = (i, ctx, seed)
                if key in processed:
                    continue
                processed.add(key)
                facts = self._run(methods[i], set(seed), by_name, return_tainted, None, path)
                if facts.returns_tainted:
                    return_tainted.add((i, ctx))
                for (mi, pi) in facts.callee_params:
                    if mi >= len(methods) or pi >= len(methods[mi].params):
                        continue
                    k = (mi, methods[i].name)
                    cur = seeds.setdefault(k, set())
                    if pi not in cur:
                        cur.add(pi)
                        work.append((mi, methods[i].name, tuple(sorted(cur))))
            final_runs = [(i, set(seed)) for (i, _, seed) in processed]
        else:
            tainted_params: List[Set[int]] = [set() for _ in methods]
            for _ in range(len(methods) + 2):
                changed = False
                for i, m in enumerate(methods):
                    facts = self._run(m, tainted_params[i], by_name, return_tainted, None, path)
                    for (mi, pi) in facts.callee_params:
                        if 0 <= mi < len(methods) and pi < len(methods[mi].params):
                            if pi not in tainted_params[mi]:
                                tainted_params[mi].add(pi)
                                changed = True
                    if facts.returns_tainted and i not in return_tainted:
                        return_tainted.add(i)
                        changed = True
                if not changed:
                    break
            final_runs = [(i, tainted_params[i]) for i in range(len(methods))]

        # final pass -> findings
        findings: List[Finding] = []
        graph = Graph()
        graph.meta = {"language": "java", "file": path, "interprocedural": True,
                      "context_sensitive": context_sensitive}
        for m in methods:
            graph.add_node(m.nid, NodeKind.FUNCTION, m.name, file=path, line=m.line, end_line=m.end_line)
        for i, seed in final_runs:
            self._run(methods[i], seed, by_name, return_tainted, findings=findings, path=path)

        # Coverage parity: union with the full intraprocedural adapter so
        # interprocedural reachability only *adds* findings (XSS-writer
        # restriction, mutators, patterns), never drops them.
        from .java import JavaIngest

        seen = {(f.category, f.sink_name, f.line) for f in findings}
        for f in JavaIngest().analyze(code, path=path).findings:
            key = (f.category, f.sink_name, f.line)
            if key not in seen:
                seen.add(key)
                findings.append(f)

        self._attach_sinks(graph, findings, path)
        return AnalysisResult(graph=graph, findings=findings)

    # -- collection --------------------------------------------------------
    def _collect(self, root) -> List[Method]:
        out: List[Method] = []
        seq = 0

        def walk(node):
            nonlocal seq
            for c in node.named_children:
                if c.type == "method_declaration":
                    name = c.child_by_field_name("name")
                    params_node = c.child_by_field_name("parameters")
                    params: List[str] = []
                    if params_node is not None:
                        for p in params_node.named_children:
                            nm = p.child_by_field_name("name") or p
                            if getattr(nm, "type", "") == "identifier":
                                params.append(nm.text.decode())
                    seq += 1
                    out.append(Method(
                        name=name.text.decode() if name else "?",
                        params=params,
                        body=c.child_by_field_name("body"),
                        line=c.start_point[0] + 1,
                        end_line=c.end_point[0] + 1,
                        nid=f"fn{seq}",
                    ))
                else:
                    walk(c)

        walk(root)
        return out

    # -- one method --------------------------------------------------------
    def _run(self, m: Method, seed_indices, by_name, return_tainted, findings, path) -> Facts:
        self._cur_method_name = m.name
        facts = Facts()
        env: Dict[str, Set[str]] = {}
        for idx, p in enumerate(m.params):
            if idx in seed_indices:
                env[p] = {"param"}
        self._walk(m.body, env, facts, by_name, return_tainted, findings, path)
        return facts

    def _walk(self, block, env, facts, by_name, return_tainted, findings, path):
        if block is None:
            return
        for child in block.named_children:
            t = child.type
            if t == "local_variable_declaration":
                for d in child.named_children:
                    if d.type == "variable_declarator":
                        self._assign(d, env, facts, by_name, return_tainted, findings, path)
            elif t == "expression_statement":
                inner = child.named_children[0] if child.named_children else None
                self._expr(inner, env, facts, by_name, return_tainted, findings, path)
            elif t == "assignment_expression":
                self._assign(child, env, facts, by_name, return_tainted, findings, path)
            elif t == "if_statement":
                self._if(child, env, facts, by_name, return_tainted, findings, path)
            elif t == "return_statement":
                tags = set()
                for c in child.named_children:
                    if c.type != "return":
                        tags |= self._eval(c, env, facts, by_name, return_tainted, findings, path)
                if tags:
                    facts.returns_tainted = True
            else:
                self._walk(child, env, facts, by_name, return_tainted, findings, path)

    def _assign(self, node, env, facts, by_name, return_tainted, findings, path):
        left = node.child_by_field_name("left") or node.child_by_field_name("name")
        right = node.child_by_field_name("right") or node.child_by_field_name("value")
        target = left.text.decode() if left is not None and getattr(left, "type", "") == "identifier" else ""
        if not target:
            return
        tags = self._eval(right, env, facts, by_name, return_tainted, findings, path)
        if tags:
            env[target] = tags
        else:
            env.pop(target, None)

    def _if(self, node, env, facts, by_name, return_tainted, findings, path):
        cons = node.child_by_field_name("consequence")
        alt = node.child_by_field_name("alternative")
        snap = {k: set(v) for k, v in env.items()}
        self._walk(cons, env, facts, by_name, return_tainted, findings, path)
        then = {k: set(v) for k, v in env.items()}
        env.clear(); env.update(snap)
        self._walk(alt, env, facts, by_name, return_tainted, findings, path)
        els = {k: set(v) for k, v in env.items()}
        merged = {}
        for k in set(then) | set(els):
            t = then.get(k, set()) | els.get(k, set())
            if t:
                merged[k] = t
        env.clear(); env.update(merged)

    def _expr(self, node, env, facts, by_name, return_tainted, findings, path):
        if node is None:
            return
        if node.type == "assignment_expression":
            self._assign(node, env, facts, by_name, return_tainted, findings, path)
        else:
            self._eval(node, env, facts, by_name, return_tainted, findings, path)

    def _eval(self, node, env, facts, by_name, return_tainted, findings, path) -> Set[str]:
        if node is None:
            return set()
        t = node.type
        if t == "identifier":
            return set(env.get(node.text.decode(), set()))
        if t in ("string_literal", "integer_literal", "decimal_floating_point_literal", "true", "false", "null_literal", "character_literal"):
            return set()
        if t == "method_invocation":
            return self._call(node, env, facts, by_name, return_tainted, findings, path)
        if t == "object_creation_expression":
            type_node = node.child_by_field_name("type")
            type_name = type_node.text.decode() if type_node else ""
            tags = set()
            for a in _args(node):
                tags |= self._eval(a, env, facts, by_name, return_tainted, findings, path)
            if type_name.split(".")[-1] in _PATHTRAVER_TYPES and tags and findings is not None:
                self._emit(node, type_name, "pathtraver", findings, path)
            return tags
        if t in ("parenthesized_expression", "cast_expression"):
            return self._eval(node.named_children[-1] if node.named_children else None, env, facts, by_name, return_tainted, findings, path)
        if t == "attribute":
            return self._eval(node.child_by_field_name("object"), env, facts, by_name, return_tainted, findings, path)
        tags = set()
        for c in node.named_children:
            tags |= self._eval(c, env, facts, by_name, return_tainted, findings, path)
        return tags

    def _call(self, node, env, facts, by_name, return_tainted, findings, path) -> Set[str]:
        name = _name_of(node)
        obj = node.child_by_field_name("object")
        if name in _SANITIZERS:
            return set()

        arg_tags: List[Set[str]] = []
        for a in _args(node):
            arg_tags.append(self._eval(a, env, facts, by_name, return_tainted, findings, path))
        tags = set().union(*arg_tags) if arg_tags else set()
        if obj is not None:
            tags |= self._eval(obj, env, facts, by_name, return_tainted, findings, path)

        if _is_source(name):
            return {name}

        if name in _SINKS:
            if tags and findings is not None:
                self._emit(node, name, _SINKS[name], findings, path)
            return set()

        # propagate into known callees' parameters
        if name in by_name:
            mi = by_name[name]
            for idx, at in enumerate(arg_tags):
                if at:
                    facts.callee_params.add((mi, idx))
            if self._ret_tainted(mi, return_tainted):
                tags = set(tags) | {"call"}
        return tags

    def _ret_tainted(self, mi: int, return_tainted) -> bool:
        """Context-sensitive return-taint lookup when in CS mode."""
        if self._cs:
            return (mi, self._cur_method_name) in return_tainted
        return mi in return_tainted

    def _emit(self, node, name, category, findings, path):
        key = (category, name, node.start_point[0])
        for f in findings:
            if (f.category, f.sink_name, f.line) == (category, name, node.start_point[0] + 1):
                return
        findings.append(Finding(
            kind="taint", title=f"{category} via {name}",
            description=f"Untrusted input reaches {category} sink {name} (interprocedural).",
            severity=CATEGORY_SEVERITY.get(category, "medium"), category=category,
            file=path, line=node.start_point[0] + 1, source_names=["input"], sink_name=name,
        ))

    def _attach_sinks(self, graph, findings, path):
        for i, f in enumerate(findings, 1):
            src = f"src_{i}"; snk = f"sink_{i}"
            graph.add_node(src, NodeKind.SOURCE, "input", file=path, line=f.line)
            graph.add_node(snk, NodeKind.SINK, f.sink_name, file=path, line=f.line, attrs={"category": f.category})
            graph.add_edge(src, snk, EdgeKind.TAINT)

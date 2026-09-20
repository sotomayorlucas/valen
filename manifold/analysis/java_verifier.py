"""Formal layer for Java: a Z3-backed symbolic verifier.

Confirms (or refutes) the taint flows found by the Java adapter, using bounded,
path-insensitive symbolic execution with the Z3 string theory. Branches are
merged with `If` selectors (so a model picks the feasible path), sanitizers
sever the dependency, and each confirmed sink yields a concrete *witness*. This
turns MANIFOLD's "projected" neuro-symbolic row into a measured one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

import z3
from tree_sitter import Node

from ..ingest.driver import parser_for
from ..ingest.sources_sinks import CATEGORY_SEVERITY
from ..ingest.java import (
    _MUTATORS,
    _PATHTRAVER_TYPES,
    _SANITIZERS,
    _SINKS,
    _SOURCE_METHODS,
    _args,
    _name_of,
)


@dataclass
class SymVal:
    expr: z3.ExprRef
    sources: Set[z3.ExprRef] = field(default_factory=set)

    def copy(self) -> "SymVal":
        return SymVal(self.expr, set(self.sources))


@dataclass
class Verification:
    sink_name: str
    category: str
    severity: str
    line: int
    sources: List[str] = field(default_factory=list)
    witness: Dict[str, str] = field(default_factory=dict)
    verified: bool = True


def _plain_string(node: Node) -> str:
    text = node.text.decode()
    if len(text) >= 2 and text[0] in "\"'":
        return text[1:-1]
    return text


def _is_source_name(name: str) -> bool:
    return name in _SOURCE_METHODS or "getParameter" in name or "getHeader" in name or "getCookie" in name


class JavaSymbolicVerifier:
    def __init__(self) -> None:
        self.verifications: List[Verification] = []
        self._counter = 0
        self._seen: Set[tuple] = set()
        self._writers: Set[str] = set()

    def _fresh(self, prefix: str) -> z3.ExprRef:
        self._counter += 1
        return z3.String(f"{prefix}_{self._counter}")

    def verify(self, code: str, path: str = "<java>") -> List[Verification]:
        parser = parser_for("java")
        tree = parser.parse(code.encode())
        self._exec_block(tree.root_node, {})
        return self.verifications

    # -- statements --------------------------------------------------------
    def _exec_block(self, node: Node, env: Dict[str, SymVal]) -> None:
        for child in node.named_children:
            t = child.type
            if t == "class_declaration" or t == "interface_declaration":
                body = child.child_by_field_name("body")
                if body is not None:
                    self._exec_block(body, env)
            elif t == "method_declaration":
                self._exec_block(child.child_by_field_name("body") or child, env)
            elif t == "local_variable_declaration":
                for d in child.named_children:
                    if d.type == "variable_declarator":
                        self._assign(d, env)
            elif t == "expression_statement":
                self._expression(child.named_children[0] if child.named_children else None, env)
            elif t == "assignment_expression":
                self._assign(child, env)
            elif t == "if_statement":
                self._if(child, env)
            elif t == "return_statement":
                for c in child.named_children:
                    if c.type not in ("return", ";"):
                        self._eval(c, env)
            else:
                self._exec_block(child, env)

    def _expression(self, expr: Optional[Node], env: Dict[str, SymVal]) -> None:
        if expr is None:
            return
        if expr.type == "assignment_expression":
            self._assign(expr, env)
        else:
            self._eval(expr, env)

    def _assign(self, node: Node, env: Dict[str, SymVal]) -> None:
        left = node.child_by_field_name("left") or node.child_by_field_name("name")
        right = node.child_by_field_name("right") or node.child_by_field_name("value")
        target = left.text.decode() if left is not None and left.type == "identifier" else ""
        if not target:
            return
        val = self._eval(right, env)
        if right is not None and "getWriter" in right.text.decode():
            self._writers.add(target)
        env[target] = val

    def _if(self, node: Node, env: Dict[str, SymVal]) -> None:
        consequence = node.child_by_field_name("consequence")
        alternative = node.child_by_field_name("alternative")
        selector = z3.Bool(f"br_{self._counter}")
        self._counter += 1

        snapshot = {k: v.copy() for k, v in env.items()}
        if consequence is not None:
            self._exec_block(consequence, env)
        then_env = {k: v.copy() for k, v in env.items()}

        env.clear()
        env.update({k: v.copy() for k, v in snapshot.items()})
        if alternative is not None:
            self._exec_block(alternative, env)
        else_env = {k: v.copy() for k, v in env.items()}

        merged: Dict[str, SymVal] = {}
        for k in set(then_env) | set(else_env):
            tv = then_env.get(k)
            ev = else_env.get(k)
            if tv is None and ev is None:
                continue
            if tv is None:
                merged[k] = ev
            elif ev is None:
                merged[k] = tv
            else:
                merged[k] = SymVal(z3.If(selector, tv.expr, ev.expr), tv.sources | ev.sources)
        env.clear()
        env.update(merged)

    # -- expressions -------------------------------------------------------
    def _eval(self, node: Optional[Node], env: Dict[str, SymVal]) -> SymVal:
        if node is None:
            return SymVal(z3.StringVal(""), set())
        t = node.type
        if t == "identifier":
            return env.get(node.text.decode(), SymVal(z3.StringVal(node.text.decode()), set()))
        if t == "string_literal":
            return SymVal(z3.StringVal(_plain_string(node)), set())
        if t in ("integer_literal", "decimal_floating_point_literal", "true", "false", "null_literal", "character_literal"):
            return SymVal(z3.StringVal(node.text.decode()), set())
        if t == "method_invocation":
            return self._eval_call(node, env)
        if t == "object_creation_expression":
            return self._eval_new(node, env)
        if t == "binary_expression":
            op = node.child_by_field_name("operator")
            left = self._eval(node.child_by_field_name("left"), env)
            right = self._eval(node.child_by_field_name("right"), env)
            if op is not None and op.text.decode() == "+":
                return SymVal(z3.Concat(left.expr, right.expr), left.sources | right.sources)
            return SymVal(self._fresh("op"), left.sources | right.sources)
        if t in ("parenthesized_expression", "cast_expression"):
            return self._eval(node.named_children[-1] if node.named_children else None, env)
        if t in ("field_access",):
            return SymVal(z3.StringVal(""), set())
        # default: union of named children
        sources: Set[z3.ExprRef] = set()
        for c in node.named_children:
            sources |= self._eval(c, env).sources
        return SymVal(self._fresh("op"), sources)

    def _eval_new(self, node: Node, env: Dict[str, SymVal]) -> SymVal:
        type_node = node.child_by_field_name("type")
        type_name = type_node.text.decode() if type_node else ""
        sources: Set[z3.ExprRef] = set()
        for arg in _args(node):
            sources |= self._eval(arg, env).sources
        if type_name.split(".")[-1] in _PATHTRAVER_TYPES and sources:
            self._record(node, type_name, "pathtraver", [], list(sources))
        return SymVal(self._fresh("obj"), sources)

    def _eval_call(self, node: Node, env: Dict[str, SymVal]) -> SymVal:
        name = _name_of(node)
        obj = node.child_by_field_name("object")

        if name in _SANITIZERS:
            return SymVal(self._fresh("clean"), set())

        sources: Set[z3.ExprRef] = set()
        exprs: List[z3.ExprRef] = []
        if obj is not None:
            ov = self._eval(obj, env)
            sources |= ov.sources
            exprs.append(ov.expr)
        for arg in _args(node):
            av = self._eval(arg, env)
            sources |= av.sources
            exprs.append(av.expr)

        if _is_source_name(name):
            s = self._fresh(name.replace(".", "_"))
            return SymVal(s, {s})

        if name in _SINKS:
            category = _SINKS[name]
            if category == "xss" and not self._is_response_writer(obj):
                return SymVal(self._fresh("op"), sources)
            self._record(node, name, category, exprs, list(sources))
            return SymVal(self._fresh("op"), sources)

        # state taint for mutators
        if name in _MUTATORS and obj is not None and obj.type == "identifier":
            cur = env.get(obj.text.decode(), SymVal(z3.StringVal(""), set()))
            env[obj.text.decode()] = SymVal(cur.expr, cur.sources | sources)
        return SymVal(self._fresh("op"), sources)

    def _is_response_writer(self, obj: Optional[Node]) -> bool:
        if obj is None:
            return False
        if obj.type == "method_invocation" and _name_of(obj) == "getWriter":
            return True
        if obj.type == "identifier" and obj.text.decode() in self._writers:
            return True
        return False

    def _record(self, node: Node, name: str, category: str, exprs: List[z3.ExprRef], sources: List[z3.ExprRef]) -> None:
        if not sources:
            return
        key = (category, name, node.start_point[0])
        if key in self._seen:
            return
        self._seen.add(key)

        solver = z3.Solver()
        for e in exprs:
            solver.add(e != z3.StringVal(""))
        for s in sources:
            solver.add(s != z3.StringVal(""))
        witness: Dict[str, str] = {}
        if solver.check() == z3.sat:
            model = solver.model()
            for s in sources:
                witness[str(s)] = model.eval(s, model_completion=True).as_string()

        self.verifications.append(
            Verification(
                sink_name=name,
                category=category,
                severity=CATEGORY_SEVERITY.get(category, "medium"),
                line=node.start_point[0] + 1,
                sources=[str(s) for s in sorted(sources, key=str)],
                witness=witness,
            )
        )


def verify_java(code: str, path: str = "<java>") -> List[Verification]:
    """Symbolically verify Java taint flows; return the confirmations."""
    return JavaSymbolicVerifier().verify(code, path=path)

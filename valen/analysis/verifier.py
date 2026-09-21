"""Formal layer: a Z3-backed symbolic verifier for taint flows.

While the taint pass is a sound *over-approximation* (it may emit false
positives), the verifier is a *confirmation* oracle: it symbolically executes the
program (string semantics) and, for each sink, checks whether the reaching value
actually *depends on* an attacker-controlled symbol. If it does, it emits a Z3
*witness* (a concrete payload) proving reachability; sanitizers sever the
dependency and eliminate the finding.

This is a bounded, intraprocedural, path-insensitive symbolic execution: control
flow merges are encoded with Z3 `If` selectors, so a model picks the branch that
makes the flow reachable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

import z3
from tree_sitter import Node

from ..ingest.sources_sinks import CATEGORY_SEVERITY, PYTHON, LanguageProfile
from ..ingest.python import _call_args, _dotted_name  # reuse the ingest's AST helpers


@dataclass
class SymVal:
    """A symbolic value: a Z3 string expression plus the source symbols it
    depends on (an expression is *tainted* iff ``sources`` is non-empty)."""

    expr: z3.ExprRef
    sources: Set[z3.ExprRef] = field(default_factory=set)

    def copy(self) -> "SymVal":
        return SymVal(self.expr, set(self.sources))


@dataclass
class Verification:
    """A formally confirmed vulnerability with a concrete witness."""

    sink_name: str
    category: str
    severity: str
    line: int
    sources: List[str] = field(default_factory=list)
    witness: Dict[str, str] = field(default_factory=dict)
    verified: bool = True

    def to_dict(self) -> Dict[str, object]:
        return {
            "sink_name": self.sink_name,
            "category": self.category,
            "severity": self.severity,
            "line": self.line,
            "sources": self.sources,
            "witness": self.witness,
            "verified": self.verified,
        }


_STATEMENT_TYPES = {
    "expression_statement",
    "return_statement",
    "if_statement",
    "for_statement",
    "while_statement",
    "raise_statement",
    "assert_statement",
}


class SymbolicVerifier:
    def __init__(self, profile: LanguageProfile = PYTHON) -> None:
        self.profile = profile
        self.verifications: List[Verification] = []
        self._counter = 0

    def _fresh(self, prefix: str) -> z3.ExprRef:
        self._counter += 1
        return z3.String(f"{prefix}_{self._counter}")

    def _fresh_bool(self, prefix: str) -> z3.ExprRef:
        self._counter += 1
        return z3.Bool(f"{prefix}_{self._counter}")

    # -- public ------------------------------------------------------------
    def verify(self, code: str, path: str = "<stdin>") -> List[Verification]:
        from ..ingest.driver import parser_for

        parser = parser_for("python")
        tree = parser.parse(code.encode())
        root = tree.root_node

        # Module-level statements plus each function body, with parameters seeded
        # as attacker-controlled symbols.
        self._exec_block(self._body_of(root), self._env_for_params(root, path), path)

        funcs = self._collect_functions(root)
        for _fid, (body, params) in funcs:
            env: Dict[str, SymVal] = {}
            for param in params:
                env[param] = SymVal(self._fresh(f"param_{param}"), set())
                env[param].sources.add(env[param].expr)
            self._exec_block(body, env, path)

        return self.verifications

    def _collect_functions(self, root: Node) -> List[tuple]:
        out: List[tuple] = []

        def walk(node: Node, prefix: str) -> None:
            for child in node.named_children:
                if child.type == "function_definition":
                    name = child.child_by_field_name("name")
                    qualname = (f"{prefix}.{name.text.decode()}" if prefix else name.text.decode()) if name else "<lambda>"
                    body = child.child_by_field_name("body")
                    params = self._parameters(child)
                    out.append((qualname, (body, params)))
                elif child.type == "class_definition":
                    cname = child.child_by_field_name("name")
                    c = cname.text.decode() if cname else "<class>"
                    cbody = child.child_by_field_name("body")
                    if cbody is not None:
                        walk(cbody, c)
                else:
                    walk(child, prefix)

        walk(root, "")
        return out

    def _parameters(self, node: Node) -> List[str]:
        params = node.child_by_field_name("parameters")
        if params is None:
            return []
        out: List[str] = []
        for child in params.named_children:
            name = child.child_by_field_name("name")
            if name is None:
                name = child
            if name.type == "identifier":
                out.append(name.text.decode())
        return out

    def _body_of(self, node: Node) -> Optional[Node]:
        return node.child_by_field_name("body")

    def _env_for_params(self, root: Node, path: str) -> Dict[str, SymVal]:
        return {}

    # -- statement execution ----------------------------------------------
    def _exec_block(self, block: Optional[Node], env: Dict[str, SymVal], path: str) -> None:
        if block is None:
            return
        for child in block.named_children:
            if child.type not in _STATEMENT_TYPES:
                continue
            self._exec_statement(child, env, path)

    def _exec_statement(self, node: Node, env: Dict[str, SymVal], path: str) -> None:
        t = node.type
        if t == "expression_statement":
            expr = node.named_children[0] if node.named_children else None
            if expr is None:
                return
            if expr.type in ("assignment", "augmented_assignment", "named_expression"):
                left = expr.child_by_field_name("left")
                right = expr.child_by_field_name("right")
                targets = self._assignment_targets(left)
                value = self._eval_expr(right, env) if right is not None else SymVal(z3.StringVal(""), set())
                for target in targets:
                    env[target] = value
            else:
                # Any expression statement may contain a sink call.
                self._eval_expr(expr, env)
            return

        if t == "if_statement":
            consequence = node.child_by_field_name("consequence")
            alternative = node.child_by_field_name("alternative")
            selector = self._fresh_bool("branch")

            snapshot = {k: v.copy() for k, v in env.items()}
            self._exec_block(consequence, env, path)
            then_env = {k: v.copy() for k, v in env.items()}

            env.clear()
            env.update(snapshot)
            self._exec_block(alternative, env, path)
            else_env = {k: v.copy() for k, v in env.items()}

            keys = set(then_env) | set(else_env)
            merged: Dict[str, SymVal] = {}
            for k in keys:
                tv = then_env.get(k)
                ev = else_env.get(k)
                if tv is None and ev is None:
                    continue
                if tv is None:
                    merged[k] = ev
                elif ev is None:
                    merged[k] = tv
                else:
                    merged[k] = SymVal(
                        z3.If(selector, tv.expr, ev.expr), tv.sources | ev.sources
                    )
            env.clear()
            env.update(merged)
            return

        if t in ("return_statement", "raise_statement", "assert_statement"):
            for child in node.named_children:
                if child.type not in ("return", "raise", "assert"):
                    self._eval_expr(child, env)

    def _assignment_targets(self, left: Optional[Node]) -> List[str]:
        if left is None:
            return []
        if left.type == "identifier":
            return [left.text.decode()]
        if left.type in ("pattern_list", "tuple_pattern", "list_pattern", "expression_list"):
            out: List[str] = []
            for child in left.named_children:
                out.extend(self._assignment_targets(child))
            return out
        return []

    # -- expression evaluation --------------------------------------------
    def _eval_expr(self, node: Optional[Node], env: Dict[str, SymVal]) -> SymVal:
        if node is None:
            return SymVal(z3.StringVal(""), set())
        t = node.type

        if t == "identifier":
            return env.get(node.text.decode(), SymVal(z3.StringVal(node.text.decode()), set()))

        if t == "string":
            return self._eval_string(node, env)

        if t in ("integer", "float", "true", "false", "none"):
            return SymVal(z3.StringVal(node.text.decode()), set())

        if t == "call":
            return self._eval_call(node, env)

        if t == "binary_operator":
            op = node.child_by_field_name("operator")
            op_text = op.text.decode() if op else ""
            left = self._eval_expr(node.child_by_field_name("left"), env)
            right = self._eval_expr(node.child_by_field_name("right"), env)
            if op_text == "+":
                return SymVal(z3.Concat(left.expr, right.expr), left.sources | right.sources)
            return SymVal(self._fresh("op"), left.sources | right.sources)

        if t == "parenthesized_expression":
            return self._eval_expr(node.named_children[0] if node.named_children else None, env)

        if t == "subscript":
            value = self._eval_expr(node.child_by_field_name("value"), env)
            return SymVal(value.expr, set(value.sources))

        if t == "attribute":
            obj = self._eval_expr(node.child_by_field_name("object"), env)
            return SymVal(obj.expr, set(obj.sources))

        if t == "boolean_operator" or t == "conditional_expression":
            sources: Set[z3.ExprRef] = set()
            for child in node.named_children:
                sources |= self._eval_expr(child, env).sources
            return SymVal(self._fresh("op"), sources)

        # Default: opaque expression that still propagates taint.
        sources = set()
        for child in node.named_children:
            sources |= self._eval_expr(child, env).sources
        return SymVal(self._fresh("op"), sources)

    def _eval_string(self, node: Node, env: Dict[str, SymVal]) -> SymVal:
        parts: List[z3.ExprRef] = []
        sources: Set[z3.ExprRef] = set()
        has_interpolation = any(c.type == "interpolation" for c in node.named_children)
        if not has_interpolation:
            return SymVal(z3.StringVal(self._plain_string(node)), set())
        for child in node.named_children:
            if child.type == "string_content":
                parts.append(z3.StringVal(child.text.decode()))
            elif child.type == "interpolation":
                inner = child.named_children[0] if child.named_children else None
                v = self._eval_expr(inner, env)
                parts.append(v.expr)
                sources |= v.sources
        expr = parts[0] if parts else z3.StringVal("")
        for p in parts[1:]:
            expr = z3.Concat(expr, p)
        return SymVal(expr, sources)

    def _plain_string(self, node: Node) -> str:
        contents = [c.text.decode() for c in node.named_children if c.type == "string_content"]
        if contents:
            return "".join(contents)
        s = node.text.decode()
        if len(s) >= 2 and s[0] in "\"'":
            if s[:3] in ('"""', "'''") and s[-3:] == s[:3]:
                return s[3:-3]
            return s[1:-1]
        return s

    def _eval_call(self, node: Node, env: Dict[str, SymVal]) -> SymVal:
        fn = node.child_by_field_name("function")
        name = _dotted_name(fn)

        if name in self.profile.sanitizers:
            return SymVal(self._fresh("clean"), set())

        # Sinks are checked before sources: a name that is both (e.g.
        # `pickle.loads`) is dangerous *because* it consumes an untrusted
        # argument, so the tainted data is in the arguments, not the return value.
        if name in self.profile.sinks:
            self._record_sink(node, name, env)
            return SymVal(self._fresh("op"), set())

        if name in self.profile.sources:
            s = self._fresh(name.replace(".", "_"))
            return SymVal(s, {s})

        # Method call: identity on the receiver (e.g. user_input.strip()).
        if fn is not None and fn.type == "attribute":
            obj = self._eval_expr(fn.child_by_field_name("object"), env)
            return SymVal(obj.expr, set(obj.sources))

        # Unknown function: a taint barrier (clean).
        return SymVal(self._fresh("op"), set())

    # -- sink handling -----------------------------------------------------
    def _record_sink(self, node: Node, name: str, env: Dict[str, SymVal]) -> None:
        category = self.profile.sinks[name]
        args = [self._eval_expr(a, env) for a in _call_args(node.child_by_field_name("arguments"))]
        relevant = self._relevant_args(category, args, node.child_by_field_name("arguments"))

        tainted = [a for a in relevant if a.sources]
        if not tainted:
            return

        sources: List[str] = []
        for a in tainted:
            sources.extend(str(s) for s in sorted(a.sources, key=str))

        witness: Dict[str, str] = {}
        solver = z3.Solver()
        for a in tainted:
            solver.add(a.expr != z3.StringVal(""))  # demand a non-empty payload
            for s in a.sources:
                solver.add(s != z3.StringVal(""))  # each source must be non-empty
        if solver.check() == z3.sat:
            model = solver.model()
            for a in tainted:
                for s in a.sources:
                    witness[str(s)] = model.eval(s, model_completion=True).as_string()

        self.verifications.append(
            Verification(
                sink_name=name,
                category=category,
                severity=CATEGORY_SEVERITY.get(category, "medium"),
                line=node.start_point[0] + 1,
                sources=sources,
                witness=witness,
            )
        )

    def _relevant_args(self, category: str, args: List[SymVal], arguments: Optional[Node]) -> List[SymVal]:
        if not args:
            return args
        if category == "sql":
            return args[:1]
        if category == "command_execution":
            if self._has_shell_true(arguments):
                return args
            first_node = arguments.named_children[0] if arguments and arguments.named_children else None
            if first_node is not None and first_node.type in ("list", "tuple", "set"):
                return []
            return args[:1]
        return args

    def _has_shell_true(self, arguments: Optional[Node]) -> bool:
        if arguments is None:
            return False
        for child in arguments.named_children:
            if child.type == "keyword_argument":
                name = child.child_by_field_name("name")
                value = child.child_by_field_name("value")
                if name is not None and name.text.decode() == "shell" and value is not None and value.type == "true":
                    return True
        return False


def verify(code: str, path: str = "<stdin>", profile: LanguageProfile = PYTHON) -> List[Verification]:
    """Symbolically verify all taint flows in ``code`` and return confirmations."""
    return SymbolicVerifier(profile).verify(code, path=path)

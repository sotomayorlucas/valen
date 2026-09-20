"""Python SAST ingest: source code -> unified IR graph + taint findings.

This adapter parses Python with tree-sitter and produces:

* a typed :class:`~manifold.ir.Graph` with ``control`` / ``call`` / ``data`` /
  ``taint`` edges plus ``source`` / ``sink`` nodes, and
* a list of :class:`~manifold.analysis.taint.Finding` produced by an
  intraprocedural, path-insensitive taint pass.

The control-flow graph emitted here is a *statement-sequence approximation*
(branch headers are linked to their bodies and a loop back-edge is added). A
precise CFG will be constructed in the Rust core (F2); this approximation is
sufficient for the taint pass and for the first spectral/topological signals.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Set, Tuple

from tree_sitter import Node

from ..analysis import AnalysisResult, Finding
from ..analysis.taint import TaintEngine
from ..ir import EdgeKind, Graph, NodeKind
from .driver import parser_for
from .sources_sinks import CATEGORY_SEVERITY, PYTHON, LanguageProfile

# tree-sitter-python node types that are executable statements.
_STATEMENT_TYPES = {
    "expression_statement",
    "return_statement",
    "if_statement",
    "for_statement",
    "while_statement",
    "try_statement",
    "with_statement",
    "match_statement",
    "pass_statement",
    "break_statement",
    "continue_statement",
    "raise_statement",
    "assert_statement",
    "delete_statement",
    "import_statement",
    "import_from_statement",
    "future_import_statement",
    "class_definition",
    "function_definition",
    "decorated_definition",
}

_LITERAL_TYPES = {"integer", "float", "true", "false", "none"}


def _dotted_name(node: Optional[Node]) -> str:
    """Resolve an identifier/attribute/call chain to a dotted name string."""
    if node is None:
        return ""
    t = node.type
    if t == "identifier":
        return node.text.decode()
    if t == "attribute":
        obj = _dotted_name(node.child_by_field_name("object"))
        attr = node.child_by_field_name("attribute")
        name = attr.text.decode() if attr else ""
        return f"{obj}.{name}" if obj else name
    if t == "call":
        return _dotted_name(node.child_by_field_name("function"))
    if t == "subscript":
        return _dotted_name(node.child_by_field_name("value"))
    return ""


def _has_shell_true(arguments: Optional[Node]) -> bool:
    """Return True if a call passes ``shell=True``."""
    if arguments is None:
        return False
    for child in arguments.named_children:
        if child.type == "keyword_argument":
            name = child.child_by_field_name("name")
            value = child.child_by_field_name("value")
            if (
                name is not None
                and name.text.decode() == "shell"
                and value is not None
                and value.type == "true"
            ):
                return True
    return False


def _call_args(arguments: Optional[Node]) -> List[Node]:
    """Return the positional/keyword *expression* children of an argument_list."""
    if arguments is None:
        return []
    out: List[Node] = []
    for child in arguments.named_children:
        if child.type == "keyword_argument":
            value = child.child_by_field_name("value")
            if value is not None:
                out.append(value)
        elif child.type not in ("comment",):
            out.append(child)
    return out


def _expr_taint(node: Node, engine: TaintEngine) -> Set[str]:
    """Compute the taint tags carried by an expression (structural recursion)."""
    t = node.type

    if t == "identifier":
        return engine.lookup(node.text.decode())

    if t == "call":
        fn = node.child_by_field_name("function")
        name = _dotted_name(fn)
        # A sanitizer maps any input to clean (bottom of the taint lattice).
        if engine.is_sanitizer(name):
            return set()
        tags: Set[str] = set()
        # A call to a known source introduces fresh taint.
        if engine.is_source(name):
            tags.add(name)
        # A method call on a tainted object propagates that object's taint.
        if fn is not None and fn.type == "attribute":
            obj = fn.child_by_field_name("object")
            if obj is not None:
                tags |= _expr_taint(obj, engine)
        # Otherwise propagate through arguments (covers concatenation wrappers).
        for arg in _call_args(node.child_by_field_name("arguments")):
            tags |= _expr_taint(arg, engine)
        return tags

    if t in _LITERAL_TYPES:
        return set()

    # Default: union taint over named children (binary ops, subscripts, lists,
    # tuples, dicts, f-string interpolations, boolean/conditional exprs, ...).
    tags = set()
    for child in node.named_children:
        tags |= _expr_taint(child, engine)
    return tags


def _assignment_targets(left: Optional[Node]) -> List[str]:
    """Return the variable names assigned by an assignment target."""
    if left is None:
        return []
    t = left.type
    if t == "identifier":
        return [left.text.decode()]
    if t in ("pattern_list", "tuple_pattern", "list_pattern", "expression_list"):
        out: List[str] = []
        for child in left.named_children:
            out.extend(_assignment_targets(child))
        return out
    if t == "attribute":
        return [_dotted_name(left)]
    return []


class PythonIngest:
    """Build the IR graph and run the taint pass for a Python source file."""

    def __init__(self, profile: LanguageProfile = PYTHON) -> None:
        self.profile = profile
        self._node_seq = 0
        self._funcs: Dict[str, Tuple[str, Node, List[str]]] = {}
        self._var_def: Dict[Tuple[str, str], str] = {}

    # -- public ------------------------------------------------------------
    def analyze(self, code: str, path: str = "<stdin>") -> AnalysisResult:
        parser = parser_for("python")
        tree = parser.parse(code.encode())

        graph = Graph()
        graph.meta = {
            "language": "python",
            "file": path,
            "lines": code.count("\n") + 1,
        }

        module_id = self._new_id("mod")
        graph.add_node(
            module_id, NodeKind.MODULE, path, file=path, line=1, end_line=code.count("\n") + 1
        )

        findings: List[Finding] = []

        self._collect_functions(tree.root_node, graph, path)

        # Process each function body (module-level statements run in a synthetic
        # "<module>" function so top-level taint is not missed).
        engine = TaintEngine(self.profile.sources, self.profile.sinks, self.profile.sanitizers)
        module_body = self._body_of(tree.root_node)
        self._process_block(module_body, graph, module_id, "<module>", path, engine, findings)

        for func_id, (qualname, body, params) in self._funcs.items():
            fengine = TaintEngine(self.profile.sources, self.profile.sinks, self.profile.sanitizers)
            self._seed_parameters(fengine, params, graph, path)
            self._process_block(body, graph, func_id, qualname, path, fengine, findings)

        return AnalysisResult(graph=graph, findings=findings)

    def _seed_parameters(
        self, engine: TaintEngine, params: List[str], graph: Graph, path: str
    ) -> None:
        """Treat function parameters as taint sources (external callers are untrusted)."""
        for param in params:
            tag = f"param:{param}"
            engine.assign(param, {tag})
            sid = self._new_id("src")
            graph.add_node(
                sid,
                NodeKind.SOURCE,
                tag,
                file=path,
                line=0,
                attrs={"description": "function parameter (untrusted caller data)"},
            )

    # -- id helpers --------------------------------------------------------
    def _new_id(self, prefix: str) -> str:
        self._node_seq += 1
        return f"{prefix}{self._node_seq}"

    # -- function collection ----------------------------------------------
    def _collect_functions(self, root: Node, graph: Graph, path: str) -> None:
        def add_function(fn_node: Node, prefix: str, decorators: List[str]) -> None:
            name = self._function_name(fn_node)
            qualname = f"{prefix}.{name}" if prefix else name
            body = self._body_of(fn_node)
            params = self._parameters(fn_node)
            fid = self._new_id("fn")
            auth = [d for d in decorators if d in self.profile.auth_gates]
            attrs: dict = {"params": params, "qualname": qualname}
            if auth:
                attrs["auth"] = auth
            graph.add_node(
                fid,
                NodeKind.FUNCTION,
                qualname,
                file=path,
                line=fn_node.start_point[0] + 1,
                end_line=fn_node.end_point[0] + 1,
                attrs=attrs,
            )
            self._funcs[fid] = (qualname, body, params)
            # Privilege boundaries become GATE nodes with an `auth` edge to the
            # protected function (operationalizing the L4 naturality check).
            for gate_name in auth:
                gid = self._new_id("gate")
                graph.add_node(
                    gid,
                    NodeKind.GATE,
                    gate_name,
                    file=path,
                    line=fn_node.start_point[0] + 1,
                    attrs={"description": self.profile.auth_gates[gate_name]},
                )
                graph.add_edge(gid, fid, EdgeKind.AUTH)

        def walk(node: Node, prefix: str) -> None:
            for child in node.named_children:
                t = child.type
                if t == "function_definition":
                    add_function(child, prefix, [])
                elif t == "decorated_definition":
                    decorators = self._decorator_names(child)
                    definition = child.child_by_field_name("definition")
                    if definition is not None and definition.type == "function_definition":
                        add_function(definition, prefix, decorators)
                    else:
                        walk(child, prefix)
                elif t == "class_definition":
                    cname = self._class_name(child)
                    body = child.child_by_field_name("body")
                    if body is not None:
                        walk(body, cname)
                else:
                    walk(child, prefix)

        walk(root, "")

    def _decorator_names(self, node: Node) -> List[str]:
        names: List[str] = []
        for child in node.named_children:
            if child.type == "decorator":
                expr = child.named_children[0] if child.named_children else None
                if expr is not None:
                    names.append(_dotted_name(expr))
        return names

    def _function_name(self, node: Node) -> str:
        name = node.child_by_field_name("name")
        return name.text.decode() if name else "<lambda>"

    def _class_name(self, node: Node) -> str:
        name = node.child_by_field_name("name")
        return name.text.decode() if name else "<class>"

    def _parameters(self, node: Node) -> List[str]:
        params = node.child_by_field_name("parameters")
        if params is None:
            return []
        out: List[str] = []
        for child in params.named_children:
            if child.type in ("identifier", "typed_parameter", "default_parameter", "typed_default_parameter"):
                name = child.child_by_field_name("name")
                if name is None:
                    name = child
                if name.type == "identifier":
                    out.append(name.text.decode())
            elif child.type in ("list_splat_pattern", "dictionary_splat_pattern"):
                pass
        return out

    def _body_of(self, node: Node) -> Optional[Node]:
        return node.child_by_field_name("body")

    # -- statement processing ---------------------------------------------
    def _process_block(
        self,
        block: Optional[Node],
        graph: Graph,
        func_id: str,
        qualname: str,
        path: str,
        engine: TaintEngine,
        findings: List[Finding],
        prev: Optional[str] = None,
    ) -> Optional[str]:
        if block is None:
            return prev
        cur = prev
        for child in block.named_children:
            if child.type in _STATEMENT_TYPES:
                cur = self._process_statement(child, graph, func_id, qualname, path, engine, findings, cur)
        return cur

    def _process_statement(
        self,
        node: Node,
        graph: Graph,
        func_id: str,
        qualname: str,
        path: str,
        engine: TaintEngine,
        findings: List[Finding],
        prev: Optional[str],
    ) -> Optional[str]:
        t = node.type
        nid = self._new_id("st")
        line = node.start_point[0] + 1
        end_line = node.end_point[0] + 1

        kind, label = self._statement_kind_label(node)
        graph.add_node(nid, kind, label, file=path, line=line, end_line=end_line)
        if prev:
            graph.add_edge(prev, nid, EdgeKind.CONTROL)

        if t == "expression_statement":
            self._handle_expression(node, graph, func_id, qualname, path, engine, findings, nid)
            return nid

        if t in ("return_statement", "raise_statement", "assert_statement", "yield"):
            self._scan_calls(node, graph, func_id, qualname, path, engine, findings, nid)
            return nid

        if t == "if_statement":
            consequence = node.child_by_field_name("consequence")
            alternative = node.child_by_field_name("alternative")
            last = self._process_block(consequence, graph, func_id, qualname, path, engine, findings, nid)
            if alternative is not None:
                last = self._process_block(alternative, graph, func_id, qualname, path, engine, findings, nid)
            return nid

        if t in ("for_statement", "while_statement"):
            body = self._body_of(node)
            last = self._process_block(body, graph, func_id, qualname, path, engine, findings, nid)
            if last is not None:
                graph.add_edge(last, nid, EdgeKind.CONTROL)  # back edge
            return nid

        if t in ("try_statement", "with_statement"):
            body = self._body_of(node)
            self._process_block(body, graph, func_id, qualname, path, engine, findings, nid)
            return nid

        return nid

    def _statement_kind_label(self, node: Node) -> Tuple[NodeKind, str]:
        t = node.type
        if t == "expression_statement":
            expr = node.named_children[0] if node.named_children else None
            if expr is not None:
                if expr.type in ("assignment", "augmented_assignment", "named_expression"):
                    return NodeKind.ASSIGN, expr.text.decode()[:80]
                if expr.type == "call":
                    return NodeKind.CALL, _dotted_name(expr.child_by_field_name("function")) or expr.text.decode()[:80]
            return NodeKind.STATEMENT, node.text.decode()[:80]
        return NodeKind.STATEMENT, t.replace("_statement", "")

    # -- expression handling ----------------------------------------------
    def _scan_calls(
        self,
        node: Node,
        graph: Graph,
        func_id: str,
        qualname: str,
        path: str,
        engine: TaintEngine,
        findings: List[Finding],
        stmt_id: str,
    ) -> None:
        if node.type == "call":
            self._handle_call(node, graph, func_id, qualname, path, engine, findings, stmt_id)
        for child in node.named_children:
            self._scan_calls(child, graph, func_id, qualname, path, engine, findings, stmt_id)

    def _handle_expression(
        self,
        node: Node,
        graph: Graph,
        func_id: str,
        qualname: str,
        path: str,
        engine: TaintEngine,
        findings: List[Finding],
        stmt_id: str,
    ) -> None:
        expr = node.named_children[0] if node.named_children else None
        if expr is None:
            return

        if expr.type in ("assignment", "augmented_assignment", "named_expression"):
            self._handle_assignment(expr, graph, func_id, qualname, path, engine, findings, stmt_id)
        elif expr.type == "call":
            self._handle_call(expr, graph, func_id, qualname, path, engine, findings, stmt_id)
        else:
            for child in expr.named_children:
                if child.type == "call":
                    self._handle_call(child, graph, func_id, qualname, path, engine, findings, stmt_id)

    def _handle_assignment(
        self,
        node: Node,
        graph: Graph,
        func_id: str,
        qualname: str,
        path: str,
        engine: TaintEngine,
        findings: List[Finding],
        stmt_id: str,
    ) -> None:
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        targets = _assignment_targets(left)

        rhs_tags = _expr_taint(right, engine) if right is not None else set()

        if node.type == "augmented_assignment" and targets:
            rhs_tags |= engine.lookup(targets[0])

        for target in targets:
            # def-use DATA edge
            if right is not None and right.type == "identifier":
                def_id = self._var_def.get((func_id, right.text.decode()))
                if def_id:
                    graph.add_edge(def_id, stmt_id, EdgeKind.DATA)
            engine.assign(target, rhs_tags)
            self._var_def[(func_id, target)] = stmt_id

        # Emit call-graph edges and source/sink nodes for any calls in the RHS
        # (e.g. `x = read_balance()` or `x = eval(user_input)`).
        if right is not None:
            self._scan_calls(right, graph, func_id, qualname, path, engine, findings, stmt_id)

    def _handle_call(
        self,
        node: Node,
        graph: Graph,
        func_id: str,
        qualname: str,
        path: str,
        engine: TaintEngine,
        findings: List[Finding],
        stmt_id: str,
    ) -> None:
        fn = node.child_by_field_name("function")
        name = _dotted_name(fn)

        # Call-graph edge to a user-defined function.
        for fid, (fqualname, _body, _params) in self._funcs.items():
            if fqualname == name or fqualname.endswith("." + name):
                graph.add_edge(func_id, fid, EdgeKind.CALL)
                break

        if engine.is_sink(name):
            self._handle_sink(node, name, fn, graph, path, engine, findings, stmt_id)
            return

        # Source call in expression position (not an assignment) is still a node.
        if engine.is_source(name):
            src_id = self._new_id("src")
            graph.add_node(
                src_id,
                NodeKind.SOURCE,
                name,
                file=path,
                line=node.start_point[0] + 1,
                end_line=node.end_point[0] + 1,
                attrs={"description": engine.source_description(name)},
            )
            graph.add_edge(src_id, stmt_id, EdgeKind.DATA)

    def _handle_sink(
        self,
        node: Node,
        name: str,
        fn: Optional[Node],
        graph: Graph,
        path: str,
        engine: TaintEngine,
        findings: List[Finding],
        stmt_id: str,
    ) -> None:
        category = engine.sink_category(name)
        line = node.start_point[0] + 1

        sink_id = self._new_id("sink")
        graph.add_node(
            sink_id,
            NodeKind.SINK,
            name,
            file=path,
            line=line,
            end_line=node.end_point[0] + 1,
            attrs={"category": category},
        )

        # Find tainted arguments, applying a small amount of per-category
        # context sensitivity so parameterized queries / argv-form commands are
        # not flagged (these are the two most common false positives in naive
        # taint analyzers).
        args = _call_args(node.child_by_field_name("arguments"))
        relevant_args = self._sink_relevant_args(category, args, node.child_by_field_name("arguments"))

        arg_tags: Dict[str, Set[str]] = {}
        for arg in relevant_args:
            tags = _expr_taint(arg, engine)
            if tags:
                arg_tags[arg.text.decode()] = tags

        tainted_sources = set().union(*arg_tags.values()) if arg_tags else set()

        if not tainted_sources:
            return

        for source_name in sorted(tainted_sources):
            # TAINT edge from a representative source node to this sink.
            src_id = self._find_or_create_source_node(source_name, graph, path, engine, node)
            graph.add_edge(src_id, sink_id, EdgeKind.TAINT, attrs={"category": category})
            severity = CATEGORY_SEVERITY.get(category, "medium")
            findings.append(
                Finding(
                    kind="taint",
                    title=f"{_title(category)} via {name}",
                    description=(
                        f"Untrusted data ({source_name}: "
                        f"{engine.source_description(source_name)}) reaches "
                        f"dangerous sink {name} ({category})."
                    ),
                    severity=severity,
                    category=category,
                    file=path,
                    line=line,
                    source_names=[source_name],
                    sink_name=name,
                    variable=sorted(arg_tags.keys())[0] if arg_tags else "",
                    path=[],
                )
            )

    def _sink_relevant_args(
        self, category: str, args: List[Node], arguments: Optional[Node]
    ) -> List[Node]:
        """Return the arguments of a sink whose taint actually matters."""
        if not args:
            return args
        if category == "sql":
            # Only the query string matters; later args are bound parameters.
            return args[:1]
        if category == "command_execution":
            if _has_shell_true(arguments):
                return args
            first = args[0]
            if first.type in ("list", "tuple", "set"):
                # argv form without shell=True: elements are not shell-interpreted.
                return []
            return args[:1]
        return args

    def _find_or_create_source_node(
        self,
        source_name: str,
        graph: Graph,
        path: str,
        engine: TaintEngine,
        near: Node,
    ) -> str:
        # Reuse an existing SOURCE node with the same label, else create one.
        for n in graph.nodes:
            if n.kind == NodeKind.SOURCE and n.label == source_name:
                return n.id
        sid = self._new_id("src")
        graph.add_node(
            sid,
            NodeKind.SOURCE,
            source_name,
            file=path,
            line=near.start_point[0] + 1,
            end_line=near.end_point[0] + 1,
            attrs={"description": engine.source_description(source_name)},
        )
        return sid


def _title(category: str) -> str:
    return {
        "command_execution": "OS command injection",
        "code_execution": "Code execution",
        "deserialization": "Insecure deserialization",
        "sql": "SQL injection",
        "path_traversal": "Path traversal",
        "file_write": "Arbitrary file write",
        "logging": "Sensitive data in logs",
        "network": "Untrusted network use",
    }.get(category, category.replace("_", " ").capitalize())

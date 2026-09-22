"""Solidity adapter: parse a smart contract into the typed IR.

Smart contracts are the domain where *state cycles* are the vulnerability and
taint analysis is blind (the data is legitimate; only the order of external calls
and state writes matters). This adapter turns a ``.sol`` file into the IR:

* contracts and functions become FUNCTION nodes;
* internal calls and low-level external calls (``call``/``delegatecall``/
  ``transfer``/``send``) become CALL edges;
* state writes are recorded as node attributes so the reentrancy detector
  (``valen.analysis.reentrancy``) can check the checks-effects-interactions
  ordering.

Requires ``tree-sitter-solidity``.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from tree_sitter import Node

from ..analysis import AnalysisResult, Finding
from ..ir import EdgeKind, Graph, NodeKind
from .driver import parser_for


def _name(node: Node, code: bytes) -> str:
    # function_definition -> name is the 2nd child (identifier after function kw)
    for child in node.children:
        if child.type == "identifier":
            return code[child.start_byte:child.end_byte].decode()
    return ""


def _functions(root: Node) -> List[Node]:
    out: List[Node] = []
    stack = [root]
    while stack:
        n = stack.pop()
        if n.type == "function_definition":
            out.append(n)
        stack.extend(n.children)
    return out


def _contracts(root: Node) -> List[Node]:
    out: List[Node] = []
    stack = [root]
    while stack:
        n = stack.pop()
        if n.type == "contract_declaration":
            out.append(n)
        stack.extend(n.children)
    return out


class SolidityIngest:
    def analyze(self, code: str, path: str = "<contract>") -> AnalysisResult:
        parser = parser_for("solidity")
        code_b = code.encode()
        tree = parser.parse(code_b)
        root = tree.root_node

        graph = Graph()
        graph.meta = {"language": "solidity", "file": path}

        findings: List[Finding] = []
        seq = 0

        # contracts as module-ish nodes
        contract_by_range: Dict[tuple, str] = {}
        for c in _contracts(root):
            seq += 1
            cid = f"c{seq}"
            cname = _name(c, code_b) or "contract"
            graph.add_node(cid, NodeKind.MODULE, cname, file=path,
                           line=c.start_point[0] + 1, end_line=c.end_point[0] + 1)
            contract_by_range[(c.start_byte, c.end_byte)] = cid

        func_id: Dict[Node, str] = {}
        for f in _functions(root):
            seq += 1
            fid = f"f{seq}"
            fname = _name(f, code_b)
            graph.add_node(fid, NodeKind.FUNCTION, fname, file=path,
                           line=f.start_point[0] + 1, end_line=f.end_point[0] + 1,
                           attrs={"calls": [], "external": [], "state_writes": []})
            func_id[f] = fid
            # attach to enclosing contract
            for (a, b), cid in contract_by_range.items():
                if a <= f.start_byte and f.end_byte <= b:
                    graph.add_edge(cid, fid, EdgeKind.CALL, attrs={"relation": "defines"})

        # calls and state writes per function
        for f, fid in func_id.items():
            attrs = graph.node(fid).attrs
            for n in _walk(f):
                if n.type == "call_expression":
                    callee = _callee_text(n, code_b)
                    if callee:
                        attrs["calls"].append(callee)
                    if _is_external_call(n, code_b):
                        kind = _external_kind(n, code_b)
                        attrs["external"].append({"text": callee, "kind": kind,
                                                  "offset": n.start_byte,
                                                  "line": n.start_point[0] + 1})
                if n.type in ("assignment_expression", "augmented_assignment_expression"):
                    attrs["state_writes"].append(n.start_byte)

        # internal call edges (call to a local function) + external edges
        for f, fid in func_id.items():
            for n in _walk(f):
                if n.type == "call_expression":
                    callee = _callee_text(n, code_b)
                    for g, gid in func_id.items():
                        if g is not f and _name(g, code_b) == callee:
                            graph.add_edge(fid, gid, EdgeKind.CALL, attrs={"relation": "internal"})
        return AnalysisResult(graph=graph, findings=findings)


def _walk(root: Node):
    stack = [root]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(n.children)


def _callee_text(node: Node, code: bytes) -> str:
    fn = node.child_by_field_name("function")
    if fn is not None:
        return code[fn.start_byte:fn.end_byte].decode(errors="replace").strip()
    return ""


def _external_kind(node: Node, code: bytes) -> Optional[str]:
    text = code[node.start_byte:node.end_byte].decode(errors="replace")
    low = text.lower()
    if ".delegatecall" in low:
        return "delegatecall"
    if ".call" in low:
        return "call"
    if ".send" in low:
        return "send"
    if ".transfer" in low:
        return "transfer"
    return None


def _is_external_call(node: Node, code: bytes) -> bool:
    return _external_kind(node, code) is not None

"""Reentrancy detection for smart contracts (checks-effects-interactions).

A reentrancy flaw is a *state-cycle*: a function makes a low-level external call
(``call`` / ``delegatecall``) before it updates its state, so the callee can
re-enter the function and act on stale state. Taint analysis is blind here (the
data is legitimate); the signal is the *ordering* of the external call relative
to the state write, i.e. the directed cycle in the control-flow/call graph.

Primary signal (ordering): an external call whose byte offset precedes a state
write in the same function. ``transfer``/``send`` are excluded (2300-gas stipend
cannot re-enter); only ``call``/``delegatecall`` are reentrancy-capable.

``reentrancy_cycle_graph`` additionally models the reentrancy as a directed cycle
(a synthetic ``EXT`` node, ``f -> EXT -> f``) so GLMY path homology can detect it
topologically.
"""

from __future__ import annotations

from typing import Dict, List

from ..ingest.solidity import SolidityIngest
from ..ir import EdgeKind, Graph, NodeKind
from .taint import Finding

_REENTRANT_KINDS = ("call", "delegatecall")


def reentrancy_findings(graph: Graph) -> List[Finding]:
    """Flag functions with a low-level external call *before* a state write."""
    out: List[Finding] = []
    for n in graph.nodes:
        if n.kind != NodeKind.FUNCTION:
            continue
        externals = n.attrs.get("external", [])
        writes = n.attrs.get("state_writes", [])
        for e in externals:
            if e.get("kind") not in _REENTRANT_KINDS:
                continue
            if any(e["offset"] < w for w in writes):
                out.append(Finding(
                    kind="reentrancy",
                    title=f"Reentrancy: {e['text']} before state write in '{n.label}'",
                    description=(
                        f"'{n.label}' makes a low-level {e['kind']} call before updating "
                        "state, so the callee can re-enter on stale state "
                        "(checks-effects-interactions violation)."
                    ),
                    severity="high",
                    category="reentrancy",
                    file=n.file,
                    line=e.get("line", n.line),
                    sink_name=e["text"],
                    source_names=[n.label],
                ))
                break  # one finding per function is enough
    return out


def reentrancy_cycle_graph(graph: Graph) -> Graph:
    """Model each reentrancy-capable external call as a directed 2-cycle.

    For every function with a low-level external call, add a synthetic ``EXT``
    node and the edges ``f -> EXT -> f`` (the callee can call back into ``f``).
    GLMY path homology then reports a nonzero H1 for the reentrancy loop.
    """
    g = Graph()
    g.meta = dict(graph.meta)
    for n in graph.nodes:
        g.add_node(n.id, n.kind, n.label, file=n.file, line=n.line,
                   end_line=n.end_line, attrs=dict(n.attrs))
    for e in graph.edges():
        g.add_edge(e.src, e.dst, e.kind, attrs=dict(e.attrs))
    seq = 0
    for n in graph.nodes:
        if n.kind != NodeKind.FUNCTION:
            continue
        for ext in n.attrs.get("external", []):
            if ext.get("kind") not in _REENTRANT_KINDS:
                continue
            seq += 1
            ext_id = f"EXT{seq}"
            g.add_node(ext_id, NodeKind.FUNCTION, "external", attrs={"kind": "external"})
            g.add_edge(n.id, ext_id, EdgeKind.CALL, attrs={"relation": "call"})
            g.add_edge(ext_id, n.id, EdgeKind.CALL, attrs={"relation": "callback"})
    return g


def analyze(code: str, path: str = "<contract>") -> Dict:
    """Full analysis: IR + reentrancy findings + the reentrancy cycle graph."""
    result = SolidityIngest().analyze(code, path=path)
    findings = reentrancy_findings(result.graph)
    cycle_graph = reentrancy_cycle_graph(result.graph)
    return {"graph": result.graph, "findings": findings, "cycle_graph": cycle_graph}

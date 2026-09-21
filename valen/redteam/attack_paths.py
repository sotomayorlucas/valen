"""Attack paths and escalation chains over an identity/permission (IAM) graph.

Given entry identities (compromised / low-privilege) and high-value targets, this
computes ordered *escalation chains* --- each a sequence of trust/assume/access
edges --- and tags every step with a MITRE tactic. A small SMT encoding then
confirms, step by step, that the attacker can escalate from the entry to the
target (``attacker_has`` propagates along the policy edges).
"""

from __future__ import annotations

from typing import Dict, List, Tuple

import z3

from ..ir import EdgeKind, Graph
from .mitre import tactic_for_relation


def escalation_chains(
    graph: Graph,
    sources: List[str],
    targets: List[str],
    max_len: int = 5,
) -> List[List[Tuple[str, str, str]]]:
    """All simple directed chains from a source to a target.

    Each returned step is ``(src, relation, dst)``, in order. Chains longer than
    ``max_len`` are pruned.
    """
    sources = set(sources)
    targets = set(targets)
    chains: List[List[Tuple[str, str, str]]] = []

    def dfs(path: List[str], rels: List[str]):
        node = path[-1]
        if len(path) > max_len:
            return
        if node in targets and len(path) > 1:
            chains.append(list(zip(path[:-1], rels, path[1:])))
            return
        for e in graph.out_edges(node, EdgeKind.CALL):
            if e.dst in path:
                continue  # simple paths only
            dfs(path + [e.dst], rels + [e.attrs.get("relation", "trust")])

    for s in sources:
        if graph.has_node(s):
            dfs([s], [])
    return chains


def _bfs_reachable(graph: Graph, entry: str) -> set:
    from collections import deque
    seen = {entry}
    q = deque([entry])
    while q:
        u = q.popleft()
        for e in graph.out_edges(u, EdgeKind.CALL):
            if e.dst not in seen:
                seen.add(e.dst)
                q.append(e.dst)
    return seen


def z3_escalation(graph: Graph, entry: str, target: str) -> Dict:
    """SMT confirmation of an escalation: is ``target`` *forced* reachable?

    Encodes ``attacker_has(role)`` booleans and, for each policy edge, the
    implication ``attacker_has(src) => attacker_has(dst)``. The target is
    reachable iff the negation ``not attacker_has(target)`` is UNSAT under these
    constraints (i.e. the constraints *entail* the target, not merely permit it).
    The witness set is the least fixpoint (BFS), returned alongside.
    """
    nodes = [n.id for n in graph.nodes]
    if entry not in nodes or target not in nodes:
        return {"entry": entry, "target": target, "reachable": False,
                "escalation_witness": []}
    has = {nid: z3.Bool(f"has_{nid}") for nid in nodes}
    s = z3.Solver()
    s.add(has[entry])
    for e in graph.edges(EdgeKind.CALL):
        s.add(z3.Implies(has[e.src], has[e.dst]))
    reachable = s.check(z3.Not(has[target])) == z3.unsat
    return {
        "entry": entry,
        "target": target,
        "reachable": reachable,
        "escalation_witness": sorted(_bfs_reachable(graph, entry)),
    }


def tagged_chains(graph: Graph, sources: List[str], targets: List[str]) -> List[Dict]:
    """Escalation chains tagged with MITRE tactics, ready for an attack plan."""
    out = []
    for chain in escalation_chains(graph, sources, targets):
        steps = []
        for src, rel, dst in chain:
            tid, tname = tactic_for_relation(rel)
            steps.append({"from": src, "relation": rel, "to": dst,
                          "tactic_id": tid, "tactic": tname})
        target = chain[-1][2]
        z = z3_escalation(graph, chain[0][0], target)
        out.append({"entry": chain[0][0], "target": target, "steps": steps,
                    "z3": z})
    return out

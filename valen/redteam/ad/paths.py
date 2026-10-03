"""AD attack-path analysis: paths to tier-0 targets + structural ranking.

Reuses the escalation-chain / Z3 machinery on the AD graph (edges carry
``relation`` buckets) and adds a *structural* ranking of principals by
betweenness over the attack graph (the bridges an attacker pivots through).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from ...ir import EdgeKind
from .collect import ADGraph
from .graph import node_id
from ..attack_paths import escalation_chains, z3_escalation

TIER0_GROUPS = ("DOMAIN ADMINS", "ENTERPRISE ADMINS", "ADMINISTRATORS",
                "SCHEMA ADMINS", "DOMAIN CONTROLLERS")


def high_value_targets(ad: ADGraph) -> List[str]:
    """Node ids of tier-0 groups (+ the domain itself as a DCSync target)."""
    out = []
    for g in ad.records["groups"]:
        name = (g.get("name") or "").upper()
        if any(t in name for t in TIER0_GROUPS):
            out.append(node_id("group", g["name"]))
    for d in ad.records["domains"]:
        out.append(node_id("domain", d["name"]))
    return sorted(set(out))


def owned_principals(ad: ADGraph, names: Optional[List[str]] = None) -> List[str]:
    """Entry points: explicitly-owned principals, or all enabled users."""
    if names:
        known = {u["name"].upper(): node_id("user", u["name"])
                 for u in ad.records["users"]}
        out: List[str] = []
        for n in names:
            key = n.upper()
            if key in known:
                out.append(known[key])
                continue
            for k, v in known.items():
                if k.split("@", 1)[0] == key:
                    out.append(v)
                    break
        return out
    return [node_id("user", u["name"]) for u in ad.records["users"] if u.get("enabled")]


def attack_paths(ad: ADGraph, entries: Optional[List[str]] = None,
                 max_len: int = 5) -> List[Dict[str, Any]]:
    """Ranked tier-0 reachability paths from the entry principals.

    Each path is ``{entry, target, length, steps:[{from,relation,technique,
    tactic_id,to}], z3}``, sorted by length (shortest first).
    """
    sources = owned_principals(ad, entries)
    targets = high_value_targets(ad)
    chains = escalation_chains(ad.graph, sources, targets, max_len=max_len)

    # enrich relations with MITRE techniques from the edge attrs
    meta = {}
    for e in ad.graph.edges(EdgeKind.CALL):
        meta[(e.src, e.dst)] = (e.attrs.get("ad_relation", e.attrs.get("relation", "")),
                                e.attrs.get("technique", ""), e.attrs.get("tactic_id", ""))

    out: List[Dict[str, Any]] = []
    for chain in chains:
        steps = []
        for src, _bucket, dst in chain:
            rel, tech, tactic = meta.get((src, dst), ("", "", ""))
            steps.append({"from": src, "to": dst, "relation": rel,
                          "technique": tech, "tactic_id": tactic})
        entry, target = chain[0][0], chain[-1][2]
        out.append({
            "entry": entry, "target": target, "length": len(steps),
            "steps": steps, "z3": z3_escalation(ad.graph, entry, target),
        })
    out.sort(key=lambda p: p["length"])
    return out


def betweenness_ranking(ad: ADGraph, limit: int = 20) -> List[Dict[str, Any]]:
    """Principals ranked by betweenness over the attack graph (pivot bridges).

    Uses the pure-Python numeric core so it works without the Rust binary.
    """
    from ...analysis.math_core import run_core

    try:
        math = run_core(ad.graph)
        block = math["centrality"]["call"]["betweenness"]
    except Exception:  # noqa: BLE001
        return []
    labels = {n.id: n.label for n in ad.graph.nodes}
    ranked = sorted(block, key=lambda kv: -kv[1])[:limit]
    return [{"id": nid, "label": labels.get(nid, nid), "betweenness": round(v, 5)}
            for nid, v in ranked if v > 0]


# -- advanced attack-graph analytics (flow / probability / cost) -------------
def chokepoints(ad: ADGraph, entries: Optional[List[str]] = None) -> Dict[str, Any]:
    """Menger min-cut: the obligatory principals separating entry from tier-0."""
    from ...analysis.network import min_vertex_cut

    sources = owned_principals(ad, entries)
    targets = high_value_targets(ad)
    value, cut = min_vertex_cut(ad.graph, sources, targets)
    labels = {n.id: n.label for n in ad.graph.nodes}
    return {"min_cut": value,
            "chokepoints": [{"id": c, "label": labels.get(c, c)} for c in cut]}


def hitting_rank(ad: ADGraph, entries: Optional[List[str]] = None) -> Dict[str, float]:
    """Hitting probability to tier-0 (absorbing Markov chain) per principal."""
    from ...analysis.network import hitting_probabilities

    targets = high_value_targets(ad)
    prob = hitting_probabilities(ad.graph, targets)
    sources = set(owned_principals(ad, entries))
    return {k: v for k, v in sorted(prob.items(), key=lambda kv: -kv[1])
            if k in sources and v > 0}


def cheapest_paths(ad: ADGraph, entries: Optional[List[str]] = None,
                   max_len: int = 10) -> List[Dict[str, Any]]:
    """Least-cost (stealth+effort) paths to tier-0 via Dijkstra."""
    from ...analysis.network import edge_costs, weighted_shortest_paths

    sources = owned_principals(ad, entries)
    targets = high_value_targets(ad)
    costs = edge_costs(ad.graph)
    best = weighted_shortest_paths(ad.graph, sources, targets, cost_fn=lambda s, d: costs.get((s, d), 1.0))
    labels = {n.id: n.label for n in ad.graph.nodes}
    out = []
    for t, (cost, path) in sorted(best.items(), key=lambda kv: kv[1][0]):
        if len(path) - 1 > max_len:
            continue
        out.append({"entry": path[0], "target": t, "cost": round(cost, 3),
                    "length": len(path) - 1,
                    "path": [labels.get(p, p) for p in path]})
    return out


def synthesize_attack(ad: ADGraph, entries: Optional[List[str]] = None,
                      max_steps: int = 8) -> List[Dict[str, Any]]:
    """Minimal-cost ordered exploit plans (Z3 Optimize bounded model checking).

    Unlike ``attack_paths`` (boolean reachability), this returns the *ordered
    sequence of actions* (technique-by-technique) with the cheapest total cost.
    """
    from ...analysis.formal_planner import synthesize_plan

    sources = owned_principals(ad, entries)
    targets = high_value_targets(ad)
    return synthesize_plan(ad.graph, sources, targets, max_steps=max_steps)


def multi_target_plans(ad: ADGraph, entries: Optional[List[str]] = None,
                       budget: int = 3) -> Dict[str, Any]:
    """Cheapest ``budget`` vertex-disjoint attack paths (min-cost flow).

    "With k compromises available, these are the k cheapest independent routes to
    tier-0." Returns ``{cost, flow, paths}`` with principal labels.
    """
    from ...analysis.network import min_cost_flow

    sources = owned_principals(ad, entries)
    targets = high_value_targets(ad)
    res = min_cost_flow(ad.graph, sources, targets, flow=budget)
    labels = {n.id: n.label for n in ad.graph.nodes}
    res["paths"] = [[labels.get(p, p) for p in path] for path in res.get("paths", [])]
    return res
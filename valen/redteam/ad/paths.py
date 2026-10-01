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
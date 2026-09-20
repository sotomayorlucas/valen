"""The vulnerability scalar field V(x).

Fuses the per-layer signals into a node-level score. In the current phase the
weights are *uniform* (alpha_i = 1/N over the available signals); calibrated
weights (a logistic classifier over labeled traces) are future work. The field
is the ranking for the agent, the Mapper filter, and the cost field for
navigation.
"""

from __future__ import annotations

import math as _math
from typing import Any, Dict, List, Optional

from ..ir import EdgeKind, Graph, NodeKind


def _normalize(scores: Dict[str, float]) -> Dict[str, float]:
    mx = max(scores.values(), default=0.0)
    if mx <= 0.0:
        return {k: 0.0 for k in scores}
    return {k: v / mx for k, v in scores.items()}


def vulnerability_field(
    graph: Graph,
    math: Optional[Dict[str, Any]] = None,
    findings: Optional[List[Any]] = None,
    weights: Optional[Dict[str, float]] = None,
) -> Dict[str, float]:
    """Compute V(x) for every node (raw fused score in [0, 1]).

    Signals (normalized to [0,1]): ``taint`` (on a taint edge / source / sink),
    ``spectral`` (|Fiedler| over the call graph), ``topological`` (member of an
    H1 cycle), ``geometric`` (negative Forman--Ricci incidence), ``formal``
    (a confirmed sink).
    """
    node_ids = [n.id for n in graph.nodes]

    # taint
    taint_nodes: set = set()
    for e in graph.edges(EdgeKind.TAINT):
        taint_nodes.add(e.src)
        taint_nodes.add(e.dst)
    signals: Dict[str, Dict[str, float]] = {
        "taint": {nid: (1.0 if nid in taint_nodes else 0.0) for nid in node_ids}
    }

    # spectral (fiedler magnitude, call graph)
    spectral = {nid: 0.0 for nid in node_ids}
    if math and math.get("spectral", {}).get("call", {}).get("fiedler"):
        order = math["node_order"]
        fmap = dict(zip(order, math["spectral"]["call"]["fiedler"]))
        spectral = {nid: abs(fmap.get(nid, 0.0)) for nid in node_ids}
    signals["spectral"] = spectral

    # topological (cycle membership)
    cycle_nodes: set = set()
    if math:
        for c in math.get("topology", {}).get("call", {}).get("h1_cycles", []):
            cycle_nodes.update(c.get("nodes", []))
    signals["topological"] = {nid: (1.0 if nid in cycle_nodes else 0.0) for nid in node_ids}

    # geometric (negative Forman-Ricci incidence)
    geometric = {nid: 0.0 for nid in node_ids}
    if math:
        for e in math.get("geometry", {}).get("call", {}).get("forman_ricci", []):
            k = -e["kappa"] if e["kappa"] < 0 else 0.0
            for endpoint in (e["src"], e["dst"]):
                geometric[endpoint] = max(geometric.get(endpoint, 0.0), k)
    signals["geometric"] = geometric

    # formal (confirmed sink nodes)
    formal = {nid: 0.0 for nid in node_ids}
    if findings:
        sink_labels: set = set()
        for f in findings:
            for n in graph.nodes:
                if n.kind == NodeKind.SINK and n.label == getattr(f, "sink_name", ""):
                    sink_labels.add(n.id)
        for nid in node_ids:
            formal[nid] = 1.0 if nid in sink_labels else 0.0
    signals["formal"] = formal

    keys = list(signals.keys())
    weights = weights or {k: 1.0 / len(keys) for k in keys}

    fused = {nid: 0.0 for nid in node_ids}
    for k in keys:
        norm = _normalize(signals[k])
        for nid in node_ids:
            fused[nid] += weights.get(k, 0.0) * norm[nid]

    return fused


def probability_field(fused: Dict[str, float]) -> Dict[str, float]:
    """Logistic squeeze of a fused score into a (0,1) probability."""
    return {k: 1.0 / (1.0 + _math.exp(-(v - 0.5))) for k, v in fused.items()}

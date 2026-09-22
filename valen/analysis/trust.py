"""Trust-topology analysis: privilege bridges and lateral movement.

On an identity/permission graph (see ``valen.ingest.iam``) two structural
signals surface where the trust boundary leaks:

* the **Fiedler cut** (algebraic connectivity) partitions the graph into trust
  domains; edges/nodes straddling the cut are candidates for *trust-segmentation
  breaks*;
* **Forman--Ricci curvature**: a strongly negative edge is a
  *privilege bridge* --- the sole connector between two disparate trust subnets
  (the ideal pivot for lateral movement).

Here, negative curvature is not a detection artifact but the exact thing we look
for.
"""

from __future__ import annotations

from typing import Dict, List, Tuple

from ..ir import Graph
from .math_core import betweenness_ranking, run_core


def _label(graph: Graph) -> Dict[str, str]:
    return {n.id: n.label for n in graph.nodes}


def fiedler_boundary(graph: Graph, top_k: int = 5) -> List[Tuple[str, str, float]]:
    """Nodes on the spectral-cut boundary, ranked by |Fiedler value|."""
    result = run_core(graph)
    order = result["node_order"]
    fiedler = result["spectral"]["call"]["fiedler"]
    labels = _label(graph)
    ranked = sorted(zip(order, fiedler), key=lambda p: abs(p[1]), reverse=True)
    return [(nid, labels.get(nid, nid), val) for nid, val in ranked[:top_k]]


def privilege_bridges(graph: Graph, top_k: int = 5) -> List[Dict[str, object]]:
    """Edges with the most-negative Forman--Ricci curvature (trust bridges)."""
    result = run_core(graph)
    labels = _label(graph)
    edges = result["geometry"]["call"]["forman_ricci"]
    ranked = sorted(edges, key=lambda e: e["kappa"])
    return [
        {
            "src": e["src"],
            "dst": e["dst"],
            "src_label": labels.get(e["src"], e["src"]),
            "dst_label": labels.get(e["dst"], e["dst"]),
            "kappa": e["kappa"],
        }
        for e in ranked[:top_k]
    ]


def bridge_nodes(graph: Graph, top_k: int = 5) -> List[Tuple[str, str, float]]:
    """Bridge nodes by betweenness centrality (high = sole connector between
    trust subnets — the attacker's pivot). Complements Fiedler cut + Forman-Ricci.
    """
    return betweenness_ranking(graph, kind="call")[:top_k]


def trust_analysis(graph: Graph, top_k: int = 5) -> Dict[str, object]:
    """Combined trust-topology report (Fiedler boundary + privilege bridges + bridge nodes)."""
    return {
        "fiedler_boundary": [list(x) for x in fiedler_boundary(graph, top_k)],
        "privilege_bridges": privilege_bridges(graph, top_k),
        "bridge_nodes": [list(x) for x in bridge_nodes(graph, top_k)],
    }

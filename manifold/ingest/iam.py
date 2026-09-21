"""IAM / cloud-trust adapter: identity-and-permission graphs into the IR.

Consumes a JSON spec of identities (users, roles, services, resources) with
``group`` labels (trust domains such as DMZ / app / data / core) and ``edges``
carrying a ``relation`` (``assume``, ``access``, ``trust``). The graph encodes
the *trust topology*; the same spectral (Fiedler cut) and discrete-curvature
(Forman--Ricci) kernels then surface privilege bridges and lateral-movement
chains --- see ``manifold.analysis.trust``.

The adapter maps identity nodes to FUNCTION nodes (with a ``group`` attribute)
and privilege/trust relations to ``call`` edges (with a ``relation`` attribute);
the ``call`` kind is the relation subgraph the numeric kernels already consume.
"""

from __future__ import annotations

import json
from typing import Any

from ..analysis import AnalysisResult
from ..ir import EdgeKind, Graph, NodeKind


class IAMIgest:
    def analyze(self, spec: Any, path: str = "<iam>") -> AnalysisResult:
        if isinstance(spec, str):
            spec = json.loads(spec)

        graph = Graph()
        graph.meta = {"language": "iam", "file": path, "name": spec.get("name", "iam")}

        for node in spec.get("nodes") or []:
            nid = node["id"]
            graph.add_node(
                nid,
                NodeKind.FUNCTION,
                node.get("label", nid),
                file=path,
                attrs={"group": node.get("group", ""), "kind": node.get("kind", "identity")},
            )

        for edge in spec.get("edges") or []:
            src = edge["src"]
            dst = edge["dst"]
            if not graph.has_node(src) or not graph.has_node(dst):
                continue
            graph.add_edge(
                src, dst, EdgeKind.CALL,
                attrs={"relation": edge.get("relation", "trust")},
            )

        return AnalysisResult(graph=graph, findings=[])

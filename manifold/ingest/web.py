"""Web/API adapter: turn an OpenAPI 3.0 spec into the IR.

Each operation becomes a node; its parameters (query/path/body) become taint
*sources* (untrusted input), ``security`` requirements become *gate* nodes with
``auth`` edges (L4), and an optional ``x-manifold-sinks`` extension declares
which parameters reach a dangerous sink. The same spectral / topological /
geometric kernels then operate on the resulting API-surface graph.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from ..analysis import AnalysisResult, Finding
from ..ir import EdgeKind, Graph, NodeKind

_SINK_CATEGORIES = {
    "sql": "sql",
    "command": "command_execution",
    "eval": "code_execution",
    "deserialize": "deserialization",
    "file": "file_write",
    "path": "path_traversal",
}


class WebIngest:
    def analyze(self, spec: Any, path: str = "<api>") -> AnalysisResult:
        if isinstance(spec, str):
            spec = json.loads(spec)

        graph = Graph()
        graph.meta = {"language": "openapi", "file": path}
        findings: List[Finding] = []
        seq = 0

        for url, methods in (spec.get("paths") or {}).items():
            for method, op in methods.items():
                if not isinstance(op, dict):
                    continue
                seq += 1
                op_id = op.get("operationId", f"{method.upper()} {url}")
                endpoint = f"op{seq}"
                graph.add_node(
                    endpoint, NodeKind.FUNCTION, f"{method.upper()} {url}",
                    file=path, attrs={"operationId": op_id},
                )

                param_sources: Dict[str, str] = {}  # param name -> source node id
                for p in op.get("parameters") or []:
                    seq += 1
                    name = p.get("name", "?")
                    src = f"src{seq}"
                    graph.add_node(
                        src, NodeKind.SOURCE, name, file=path,
                        attrs={"location": p.get("in", "query")},
                    )
                    graph.add_edge(src, endpoint, EdgeKind.DATA)
                    param_sources[name] = src

                # Security requirements become auth gates (trust boundary).
                for sec in op.get("security") or []:
                    for scheme in sec:
                        seq += 1
                        gate = f"gate{seq}"
                        graph.add_node(
                            gate, NodeKind.GATE, scheme, file=path,
                            attrs={"description": "security scheme"},
                        )
                        graph.add_edge(gate, endpoint, EdgeKind.AUTH)

                # Declared sinks: x-manifold-sinks = ["paramName"].
                for name in op.get("x-manifold-sinks") or []:
                    seq += 1
                    sink = f"sink{seq}"
                    category = "sql"  # default
                    graph.add_node(
                        sink, NodeKind.SINK, f"{op_id}:{name}", file=path,
                        attrs={"category": category},
                    )
                    if name in param_sources:
                        graph.add_edge(param_sources[name], sink, EdgeKind.TAINT)
                    findings.append(
                        Finding(
                            kind="taint",
                            title=f"Untrusted parameter reaches sink in {op_id}",
                            description=(
                                f"Parameter `{name}` of `{method.upper()} {url}` "
                                f"flows to a dangerous operation."
                            ),
                            severity="high",
                            category=category,
                            file=path,
                            line=0,
                            source_names=[name],
                            sink_name=op_id,
                        )
                    )

        return AnalysisResult(graph=graph, findings=findings)

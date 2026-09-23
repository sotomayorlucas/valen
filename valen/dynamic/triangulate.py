"""Triangulation: cross the runtime trace against the static analysis.

This is where the dynamic evidence earns its keep. Given the static
``AnalysisResult`` (the over-approximation) and a ``DynamicResult`` (one concrete
execution), we:

* compute **coverage** -- which static nodes were actually executed;
* classify every static taint finding against the run:

  - ``confirmed``   -- the sink executed AND a concrete value reached it at runtime;
  - ``hit``         -- the sink executed, but the captured args carried no usable
                      payload (weak evidence);
  - ``unexecuted``  -- the sink never ran in this execution (static FP for this
                      input, or simply not on the path taken).

This is the honest two-sided boundary: the static layer says "taint reaches the
sink"; the dynamic layer says whether a *real* run agrees. Neither is truth --
they triangulate.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..ir import Graph
from .runner import DynamicResult


@dataclass
class FindingAgreement:
    title: str
    sink_name: str
    line: int
    static_severity: str
    dynamic: str  # confirmed | hit | unexecuted
    matched_value: Optional[str] = None
    sink_args: Dict[str, str] = field(default_factory=dict)


def _is_object_repr(s: str) -> bool:
    return s.startswith("<") and " object at " in s


def triangulate(static_result, dyn: DynamicResult) -> Dict[str, Any]:
    """Cross static findings vs dynamic run. Returns a JSON-serializable report.

    ``static_result`` is an ``AnalysisResult`` (has ``.findings`` and ``.graph``).
    """
    graph: Graph = static_result.graph
    findings = getattr(static_result, "findings", [])

    # -- coverage of static nodes ------------------------------------------
    covered = dyn.covered_lines

    nodes_covered = 0
    for n in graph.nodes:
        if n.line and (n.file or "") in ("",):
            if any(ln == n.line for _, ln in covered):
                nodes_covered += 1
        elif (n.file or "", n.line) in covered:
            nodes_covered += 1
    total_nodes = max(graph.node_count, 1)

    # -- agreement on static findings --------------------------------------
    hits_by_line: Dict[int, List[Dict[str, Any]]] = {}
    for s in dyn.sinks:
        hits_by_line.setdefault(s.get("line", 0), []).append(s)

    agreements: List[FindingAgreement] = []
    for f in findings:
        hits = hits_by_line.get(f.line, [])
        if not hits:
            agreements.append(FindingAgreement(
                title=f.title, sink_name=f.sink_name, line=f.line,
                static_severity=f.severity, dynamic="unexecuted",
            ))
            continue
        matched = None
        for h in hits:
            candidates = [str(v) for v in h.get("args", {}).values()
                          if str(v) and not _is_object_repr(str(v))]
            if candidates:
                # the most informative payload is usually the longest string
                # (e.g. the fully-built SQL / command, not the raw parameter)
                matched = max(candidates, key=len)
                break
        agreements.append(FindingAgreement(
            title=f.title, sink_name=f.sink_name, line=f.line,
            static_severity=f.severity,
            dynamic="confirmed" if matched else "hit",
            matched_value=matched,
            sink_args=hits[0].get("args", {}),
        ))

    # -- sinks seen at runtime that the static layer did NOT flag -----------
    static_lines = {f.line for f in findings}
    dynamic_only = [s for s in dyn.sinks if s.get("line", 0) not in static_lines]

    return {
        "target": dyn.target,
        "exit_code": dyn.exit_code,
        "timed_out": dyn.timed_out,
        "coverage": {
            "nodes": nodes_covered,
            "total_nodes": total_nodes,
            "ratio": round(nodes_covered / total_nodes, 4),
            "lines": len(covered),
        },
        "sinks": dyn.sinks,
        "sources": dyn.sources,
        "agreement": [a.__dict__ for a in agreements],
        "dynamic_only_sinks": dynamic_only,
        "evidence": dyn.evidence,
    }

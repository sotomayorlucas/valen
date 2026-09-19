"""Analysis layer: dataflow/taint engines and shared result types."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from ..ir import Graph
from .taint import Finding

__all__ = ["Finding", "TaintEngine", "AnalysisResult"]


@dataclass
class AnalysisResult:
    """The output of an ingest + analysis pass: the IR graph plus findings."""

    graph: Graph
    findings: List[Finding] = field(default_factory=list)

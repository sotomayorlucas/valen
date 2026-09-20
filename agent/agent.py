"""The autonomous agent loop: map -> rank -> hypothesize -> verify -> report."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from manifold.analysis.math_core import run_core
from manifold.analysis.verifier import Verification, verify
from manifold.analysis.authorization import annotate_findings
from manifold.ingest.python import PythonIngest
from manifold.ingest.sources_sinks import LanguageProfile, PYTHON
from manifold.ir import Graph, NodeKind
from .llm import LLMClient
from .prompts import SYSTEM, hypothesis_prompt

# Signal -> default CWE (offline heuristic).
_CWE_BY_CATEGORY = {
    "command_execution": "CWE-78",
    "code_execution": "CWE-94",
    "deserialization": "CWE-502",
    "sql": "CWE-89",
    "path_traversal": "CWE-22",
    "file_write": "CWE-73",
    "logging": "CWE-532",
}

_CWE_CYCLE = "CWE-835"
_CWE_CHOKEPOINT = "CWE-863"

# A negative-curvature node is very often a *legitimate* chokepoint (auth
# middleware, a sanitizer, a dispatcher, a logger). We down-rank these as
# defensive rather than reporting them as privilege-escalation leads.
_DEFENSIVE_SUBSTRINGS = (
    "auth", "login", "logout", "validate", "sanitize", "escape", "check",
    "guard", "verify", "middleware", "permission", "session", "crypto",
    "hash", "filter", "gateway", "proxy", "dispatch", "log",
)


@dataclass
class Region:
    name: str
    signal: str
    detail: str
    code: str
    line: int = 0
    sink_name: str = ""
    category: str = ""
    auth_gates: List[str] = field(default_factory=list)


@dataclass
class Hypothesis:
    region: str
    signal: str
    detail: str
    vulnerable: Optional[bool]
    cwe: str
    title: str
    description: str
    confidence: float
    source: str
    line: int = 0
    sink_name: str = ""
    category: str = ""
    auth_gates: List[str] = field(default_factory=list)


@dataclass
class ReportEntry:
    region: str
    signal: str
    cwe: str
    title: str
    description: str
    confidence: float
    status: str  # "confirmed" | "candidate"
    evidence: str
    line: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "region": self.region,
            "signal": self.signal,
            "cwe": self.cwe,
            "title": self.title,
            "description": self.description,
            "confidence": self.confidence,
            "status": self.status,
            "evidence": self.evidence,
            "line": self.line,
        }


@dataclass
class Report:
    entries: List[ReportEntry] = field(default_factory=list)

    @property
    def confirmed(self) -> List[ReportEntry]:
        return [e for e in self.entries if e.status == "confirmed"]

    def to_dict(self) -> Dict[str, Any]:
        return {"entries": [e.to_dict() for e in self.entries]}


def _parse_json(text: str) -> Optional[Dict[str, Any]]:
    """Extract a JSON object from an LLM reply (tolerates markdown fences)."""
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:]
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    try:
        return json.loads(text[start : end + 1])
    except json.JSONDecodeError:
        return None


class ManifoldAgent:
    """Navigates the vulnerability manifold and verifies hypotheses.

    With an LLM available, hypotheses come from the model; otherwise a
    deterministic heuristic maps each mathematical signal to a vulnerability
    class. In both cases the formal layer is the arbiter of ``confirmed`` vs
    ``candidate``.
    """

    def __init__(self, llm: Optional[LLMClient] = None, profile: LanguageProfile = PYTHON) -> None:
        self.llm = llm if llm is not None else LLMClient()
        self.profile = profile

    # -- public ------------------------------------------------------------
    def run(self, code: str, path: str = "<stdin>") -> Report:
        result = PythonIngest(self.profile).analyze(code, path=path)
        graph = result.graph
        math = self._math_signals(graph)

        regions = self._build_regions(result, graph, math, code)
        hypotheses = [self._hypothesize(r) for r in regions]
        verifications = verify(code, path=path) if result.findings else []
        return self._assemble(hypotheses, verifications)

    # -- math signals ------------------------------------------------------
    def _math_signals(self, graph: Graph) -> Optional[Dict[str, Any]]:
        try:
            return run_core(graph)
        except Exception:
            return None

    # -- region construction ----------------------------------------------
    def _function_map(self, graph: Graph) -> Dict[str, Dict[str, int]]:
        return {
            n.id: {"line": n.line, "end_line": n.end_line, "label": n.label}
            for n in graph.nodes
            if n.kind == NodeKind.FUNCTION
        }

    def _snippet(self, graph: Graph, code: str, line: int) -> tuple:
        lines = code.splitlines()
        funcs = sorted(
            self._function_map(graph).values(),
            key=lambda f: (f["line"], f["end_line"]),
        )
        for f in funcs:
            if f["line"] <= line <= f["end_line"]:
                text = "\n".join(lines[f["line"] - 1 : f["end_line"]])
                return f["label"], text
        return "<module>", code

    def _label_of(self, graph: Graph, node_id: str) -> str:
        for n in graph.nodes:
            if n.id == node_id:
                return n.label
        return node_id

    def _build_regions(
        self, result: Any, graph: Graph, math: Optional[Dict[str, Any]], code: str
    ) -> List[Region]:
        regions: List[Region] = []
        seen: set = set()

        # 1. Taint findings (the strongest signal).
        annotate_findings(graph, result.findings)
        for finding in result.findings:
            name, snippet = self._snippet(graph, code, finding.line)
            key = ("taint", finding.sink_name, finding.line)
            if key in seen:
                continue
            seen.add(key)
            regions.append(
                Region(
                    name=name,
                    signal="taint",
                    detail=f"{finding.title} (sink {finding.sink_name}, source {finding.source_names})",
                    code=snippet,
                    line=finding.line,
                    sink_name=finding.sink_name,
                    category=finding.category,
                    auth_gates=finding.auth_gates,
                )
            )

        if math is None:
            return regions

        # 2. Topological cycles (reentrancy / recursion).
        cycles = math.get("topology", {}).get("call", {}).get("h1_cycles", [])
        for cycle in cycles:
            labels = [self._label_of(graph, nid) for nid in cycle["nodes"]]
            name = " -> ".join(labels)
            key = ("cycle", name)
            if key in seen:
                continue
            seen.add(key)
            line = self._line_of_first_label(graph, labels)
            _, snippet = self._snippet(graph, code, line)
            regions.append(
                Region(name=name, signal="cycle", detail="H1 generator (persistent cycle)", code=snippet, line=line)
            )

        # 3. Spectral outliers (Fiedler vector magnitude): a *lead*, only on
        #    non-trivial graphs (>= 3 functions) and only the single strongest
        #    boundary node, to avoid flagging every function on tiny graphs.
        n_funcs = sum(1 for n in graph.nodes if n.kind == NodeKind.FUNCTION)
        fiedler = math.get("spectral", {}).get("call", {}).get("fiedler", [])
        order = math.get("node_order", [])
        if n_funcs >= 3 and fiedler:
            node_id, value = max(zip(order, fiedler), key=lambda p: abs(p[1]))
            if abs(value) > 1e-9:
                label = self._label_of(graph, node_id)
                if label not in ("<module>", "") and label != graph.meta.get("file"):
                    key = ("spectral", label)
                    if key not in seen:
                        seen.add(key)
                        line = self._line_of_label(graph, label)
                        _, snippet = self._snippet(graph, code, line)
                        regions.append(
                            Region(
                                name=label,
                                signal="spectral",
                                detail=f"Fiedler boundary value {value:+.3f}",
                                code=snippet,
                                line=line,
                            )
                        )

        # 4. Negative curvature chokepoints (call graph), with defensive
        #    discrimination (see the bottleneck-paradox note above).
        ricci = math.get("geometry", {}).get("call", {}).get("forman_ricci", [])
        for edge in ricci:
            if edge["kappa"] >= 0:
                continue
            src_label = self._label_of(graph, edge["src"])
            dst_label = self._label_of(graph, edge["dst"])
            defensive = self._is_defensive(src_label) or self._is_defensive(dst_label)
            label = src_label
            key = ("chokepoint", label, defensive)
            if key in seen:
                continue
            seen.add(key)
            line = self._line_of_label(graph, label)
            _, snippet = self._snippet(graph, code, line)
            regions.append(
                Region(
                    name=label,
                    signal="chokepoint-defensive" if defensive else "chokepoint",
                    detail=f"Forman-Ricci kappa {edge['kappa']:+.1f}",
                    code=snippet,
                    line=line,
                )
            )

        return regions

    def _is_defensive(self, name: str) -> bool:
        lowered = name.lower()
        return any(sub in lowered for sub in _DEFENSIVE_SUBSTRINGS)

    def _line_of_label(self, graph: Graph, label: str) -> int:
        for n in graph.nodes:
            if n.kind == NodeKind.FUNCTION and n.label == label:
                return n.line
        return 1

    def _line_of_first_label(self, graph: Graph, labels: List[str]) -> int:
        for label in labels:
            line = self._line_of_label(graph, label)
            if line > 1:
                return line
        return 1

    # -- hypothesize -------------------------------------------------------
    def _hypothesize(self, region: Region) -> Hypothesis:
        if self.llm.available:
            reply = self.llm.complete(
                [
                    {"role": "system", "content": SYSTEM},
                    {"role": "user", "content": hypothesis_prompt(region.name, region.signal, region.detail, region.code)},
                ]
            )
            parsed = _parse_json(reply) if reply else None
            if parsed:
                return Hypothesis(
                    region=region.name,
                    signal=region.signal,
                    detail=region.detail,
                    vulnerable=bool(parsed.get("vulnerable")),
                    cwe=parsed.get("cwe", ""),
                    title=parsed.get("title", region.signal),
                    description=parsed.get("description", ""),
                    confidence=float(parsed.get("confidence", 0.5)),
                    source="llm",
                    line=region.line,
                    sink_name=region.sink_name,
                    category=region.category,
                    auth_gates=region.auth_gates,
                )
        return self._heuristic_hypothesis(region)

    def _heuristic_hypothesis(self, region: Region) -> Hypothesis:
        if region.signal == "taint":
            cwe = _CWE_BY_CATEGORY.get(region.category, "CWE-20")
            return Hypothesis(
                region=region.name,
                signal="taint",
                detail=region.detail,
                vulnerable=True,
                cwe=cwe,
                title=region.detail,
                description=f"Untrusted data reaches dangerous sink {region.sink_name} ({region.category}).",
                confidence=0.85,
                source="heuristic",
                line=region.line,
                sink_name=region.sink_name,
                category=region.category,
                auth_gates=region.auth_gates,
            )
        if region.signal == "cycle":
            return Hypothesis(
                region=region.name,
                signal="cycle",
                detail=region.detail,
                vulnerable=True,
                cwe=_CWE_CYCLE,
                title="Uncontrolled recursion / reentrancy (cycle in call graph)",
                description="A persistent H1 cycle indicates mutual recursion or a reentrant entry point.",
                confidence=0.8,
                source="heuristic",
                line=region.line,
            )
        if region.signal == "chokepoint":
            return Hypothesis(
                region=region.name,
                signal="chokepoint",
                detail=region.detail,
                vulnerable=None,
                cwe=_CWE_CHOKEPOINT,
                title="Chokepoint (negative curvature)",
                description="A high-degree funnel where authorization or validation may be bypassed.",
                confidence=0.5,
                source="heuristic",
                line=region.line,
            )
        if region.signal == "chokepoint-defensive":
            return Hypothesis(
                region=region.name,
                signal="chokepoint-defensive",
                detail=region.detail,
                vulnerable=False,
                cwe="",
                title="Defensive chokepoint (likely intentional)",
                description="Negative curvature, but the node resembles an auth/sanitization gate.",
                confidence=0.1,
                source="heuristic",
                line=region.line,
            )
        return Hypothesis(
            region=region.name,
            signal=region.signal,
            detail=region.detail,
            vulnerable=None,
            cwe="",
            title="Structural anomaly",
            description=region.detail,
            confidence=0.3,
            source="heuristic",
            line=region.line,
        )

    # -- assemble ----------------------------------------------------------
    def _assemble(self, hypotheses: List[Hypothesis], verifications: List[Verification]) -> Report:
        verif_by_key = {(v.sink_name, v.line): v for v in verifications}
        entries: List[ReportEntry] = []

        for h in hypotheses:
            if h.vulnerable is False:
                # Explicitly ruled out (e.g. a defensive chokepoint) — drop it.
                continue
            if h.signal == "taint":
                v = verif_by_key.get((h.sink_name, h.line))
                if v is not None:
                    evidence = f"Z3 witness: {v.witness}"
                    if h.auth_gates:
                        evidence += f"; crosses auth boundary ({', '.join(h.auth_gates)}) — naturality violation (L4)"
                    entries.append(
                        ReportEntry(
                            region=h.region,
                            signal=h.signal,
                            cwe=h.cwe,
                            title=h.title,
                            description=h.description,
                            confidence=1.0,
                            status="confirmed",
                            evidence=evidence,
                            line=h.line,
                        )
                    )
                else:
                    entries.append(
                        ReportEntry(
                            region=h.region,
                            signal=h.signal,
                            cwe=h.cwe,
                            title=h.title,
                            description=h.description,
                            confidence=h.confidence,
                            status="candidate",
                            evidence="not confirmed by the formal layer",
                            line=h.line,
                        )
                    )
            elif h.signal == "cycle":
                entries.append(
                    ReportEntry(
                        region=h.region,
                        signal=h.signal,
                        cwe=h.cwe,
                        title=h.title,
                        description=h.description,
                        confidence=0.9,
                        status="confirmed",
                        evidence="H1 generator (persistent homology of the call graph)",
                        line=h.line,
                    )
                )
            else:
                entries.append(
                    ReportEntry(
                        region=h.region,
                        signal=h.signal,
                        cwe=h.cwe,
                        title=h.title,
                        description=h.description,
                        confidence=h.confidence,
                        status="candidate",
                        evidence="mathematical signal (needs manual or deeper analysis)",
                        line=h.line,
                    )
                )

        entries.sort(key=lambda e: (e.status != "confirmed", -e.confidence))
        return Report(entries)

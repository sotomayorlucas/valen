"""Intraprocedural taint analysis and vulnerability findings."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set


@dataclass
class Finding:
    """A candidate vulnerability discovered by a mathematical signal.

    ``kind`` is the analysis that produced it (``taint`` in this first phase);
    later phases will add ``spectral``, ``topological``, ``formal``.
    """

    kind: str
    title: str
    description: str
    severity: str
    category: str
    file: str
    line: int
    source_names: List[str] = field(default_factory=list)
    sink_name: str = ""
    variable: str = ""
    path: List[str] = field(default_factory=list)
    auth_gates: List[str] = field(default_factory=list)  # privilege boundaries crossed (L4)

    def to_dict(self) -> Dict[str, object]:
        return {
            "kind": self.kind,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "category": self.category,
            "file": self.file,
            "line": self.line,
            "source_names": self.source_names,
            "sink_name": self.sink_name,
            "variable": self.variable,
            "path": self.path,
            "auth_gates": self.auth_gates,
        }


class TaintEngine:
    """A forward, path-insensitive, intraprocedural taint engine.

    It consumes an ordered stream of *events* (assignments and calls) emitted by
    an ingest adapter and maintains a per-variable environment mapping each
    variable to the set of taint tags (source names) it carries.

    The engine is intentionally small and transparent so it can later be lifted
    into a proper abstract-interpretation lattice (the algebraic layer).
    """

    def __init__(
        self,
        sources: Dict[str, str],
        sinks: Dict[str, str],
        sanitizers: Optional[Dict[str, str]] = None,
    ) -> None:
        self._sources = sources
        self._sinks = sinks
        self._sanitizers = sanitizers or {}
        self._env: Dict[str, Set[str]] = {}
        self.findings: List[Finding] = []

    # -- public API --------------------------------------------------------
    def assign(self, target: str, tags: Set[str]) -> None:
        """Record that ``target`` now holds ``tags``."""
        if tags:
            self._env[target] = set(tags)
        else:
            self._env.pop(target, None)

    def lookup(self, name: str) -> Set[str]:
        """Return the taint tags currently carried by ``name``."""
        return self._env.get(name, set())

    def is_source(self, name: str) -> bool:
        return name in self._sources

    def is_sink(self, name: str) -> bool:
        return name in self._sinks

    def is_sanitizer(self, name: str) -> bool:
        return name in self._sanitizers

    def source_description(self, name: str) -> str:
        if name.startswith("param:"):
            return "function parameter (untrusted caller data)"
        return self._sources.get(name, "untrusted input")

    def sink_category(self, name: str) -> str:
        return self._sinks.get(name, "unknown")

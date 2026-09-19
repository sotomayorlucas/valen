"""Unified Intermediate Representation (IR) for MANIFOLD.

The IR is a typed, attributed, directed multigraph. It is the single source of
truth that every ingest adapter must produce, and that every analysis module
(spectral, topological, algebraic, formal) consumes.

Design principles
-----------------
* Typed nodes and edges (no free-form strings leaking through).
* JSON-serializable so the Python layer can hand off to the Rust core.
* Deterministic node ids so analyses are reproducible across runs.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, Iterator, List, Optional, Tuple


class NodeKind(str, Enum):
    """The semantic role of a node in the program structure."""

    MODULE = "module"
    FUNCTION = "function"
    BLOCK = "block"
    STATEMENT = "statement"
    CALL = "call"
    ASSIGN = "assign"
    VARIABLE = "variable"
    PARAMETER = "parameter"
    SOURCE = "source"  # an untrusted-data entry point (taint source)
    SINK = "sink"  # a dangerous operation (taint sink)


class EdgeKind(str, Enum):
    """The semantic relation encoded by an edge.

    These map onto the mathematical layers:
    * CONTROL / DATA / CALL  -> the base digraph (spectral + topological layer)
    * TAINT / TRUST / AUTH   -> the security lattice / categorical layer
    """

    CONTROL = "control"
    DATA = "data"
    CALL = "call"
    TAINT = "taint"
    TRUST = "trust"
    AUTH = "auth"


@dataclass
class Node:
    id: str
    kind: NodeKind
    label: str
    file: str = ""
    line: int = 0
    end_line: int = 0
    attrs: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["kind"] = self.kind.value
        return d


@dataclass
class Edge:
    src: str
    dst: str
    kind: EdgeKind
    attrs: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "src": self.src,
            "dst": self.dst,
            "kind": self.kind.value,
            "attrs": self.attrs,
        }


class Graph:
    """A typed directed multigraph with adjacency indexing.

    Nodes are stored by id; edges are stored as a list plus an adjacency index
    keyed by ``(src, kind)`` for fast traversal. This is the object that the
    spectral/topological/geometric kernels consume (after JSON round-trip to the
    Rust core).
    """

    def __init__(self) -> None:
        self._nodes: Dict[str, Node] = {}
        self._edges: List[Edge] = []
        self._adj: Dict[Tuple[str, str], List[Edge]] = {}
        self._in_adj: Dict[Tuple[str, str], List[Edge]] = {}
        self.meta: Dict[str, Any] = {}

    # -- nodes -------------------------------------------------------------
    def add_node(
        self,
        node_id: str,
        kind: NodeKind,
        label: str = "",
        *,
        file: str = "",
        line: int = 0,
        end_line: int = 0,
        attrs: Optional[Dict[str, Any]] = None,
    ) -> Node:
        node = Node(
            id=node_id,
            kind=kind,
            label=label,
            file=file,
            line=line,
            end_line=end_line,
            attrs=dict(attrs or {}),
        )
        self._nodes[node_id] = node
        return node

    def node(self, node_id: str) -> Node:
        return self._nodes[node_id]

    def has_node(self, node_id: str) -> bool:
        return node_id in self._nodes

    @property
    def nodes(self) -> Iterator[Node]:
        return iter(self._nodes.values())

    def __len__(self) -> int:
        return len(self._nodes)

    # -- edges -------------------------------------------------------------
    def add_edge(
        self,
        src: str,
        dst: str,
        kind: EdgeKind,
        attrs: Optional[Dict[str, Any]] = None,
    ) -> Edge:
        edge = Edge(src=src, dst=dst, kind=kind, attrs=dict(attrs or {}))
        self._edges.append(edge)
        key = (src, kind.value)
        self._adj.setdefault(key, []).append(edge)
        in_key = (dst, kind.value)
        self._in_adj.setdefault(in_key, []).append(edge)
        return edge

    def edges(self, kind: Optional[EdgeKind] = None) -> List[Edge]:
        if kind is None:
            return list(self._edges)
        return [e for e in self._edges if e.kind == kind]

    def out_edges(self, src: str, kind: Optional[EdgeKind] = None) -> List[Edge]:
        if kind is None:
            return [e for e in self._edges if e.src == src]
        return list(self._adj.get((src, kind.value), []))

    def in_edges(self, dst: str, kind: Optional[EdgeKind] = None) -> List[Edge]:
        if kind is None:
            return [e for e in self._edges if e.dst == dst]
        return list(self._in_adj.get((dst, kind.value), []))

    def neighbors(self, src: str, kind: Optional[EdgeKind] = None) -> List[str]:
        return [e.dst for e in self.out_edges(src, kind)]

    # -- stats -------------------------------------------------------------
    @property
    def node_count(self) -> int:
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        return len(self._edges)

    def edge_kind_counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for e in self._edges:
            counts[e.kind.value] = counts.get(e.kind.value, 0) + 1
        return counts

    # -- serialization -----------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        return {
            "meta": self.meta,
            "nodes": [n.to_dict() for n in self._nodes.values()],
            "edges": [e.to_dict() for e in self._edges],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Graph":
        g = cls()
        g.meta = dict(data.get("meta", {}))
        for n in data.get("nodes", []):
            g.add_node(
                n["id"],
                NodeKind(n["kind"]),
                n.get("label", ""),
                file=n.get("file", ""),
                line=n.get("line", 0),
                end_line=n.get("end_line", 0),
                attrs=n.get("attrs", {}),
            )
        for e in data.get("edges", []):
            g.add_edge(e["src"], e["dst"], EdgeKind(e["kind"]), e.get("attrs", {}))
        return g

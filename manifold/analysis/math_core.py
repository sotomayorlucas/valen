"""Bridge to the Rust numeric core (`manifold-core`).

The Python layer serializes the IR graph to JSON, hands it to the compiled Rust
binary, and parses the spectral/geometric results. The JSON schema is the single
contract between the two layers (see `manifold/ir.py` and `core/src/graph.rs`).
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Tuple

from ..ir import Graph

_REPO_ROOT = Path(__file__).resolve().parents[2]


def core_binary() -> Path:
    """Locate the `manifold-core` binary, preferring an explicit override."""
    override = os.environ.get("MANIFOLD_CORE_BIN")
    if override:
        return Path(override)
    for build in ("release", "debug"):
        candidate = _REPO_ROOT / "core" / "target" / build / "manifold-core"
        if candidate.exists():
            return candidate
    raise FileNotFoundError(
        "manifold-core binary not found; run `cargo build --release` in core/ "
        "or set MANIFOLD_CORE_BIN"
    )


def run_core(graph: Graph) -> Dict[str, Any]:
    """Compute spectral + geometric signals over the graph via the Rust core."""
    payload = json.dumps(graph.to_dict())
    proc = subprocess.run(
        [str(core_binary())],
        input=payload,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"manifold-core failed: {proc.stderr}")
    return json.loads(proc.stdout)


def fiedler_ranking(graph: Graph, kind: str = "call") -> List[Tuple[str, str, float]]:
    """Return (node_id, label, fiedler_value) sorted by |value| descending.

    High absolute values mark nodes on the boundary of the spectral cut — the
    natural candidates for inspection.
    """
    result = run_core(graph)
    order = result["node_order"]
    fiedler = result["spectral"][kind]["fiedler"]
    labels = {n.id: n.label for n in graph.nodes}
    ranked = sorted(
        zip(order, fiedler),
        key=lambda pair: abs(pair[1]),
        reverse=True,
    )
    return [(node_id, labels.get(node_id, ""), value) for node_id, value in ranked]


def topology(graph: Graph, kind: str = "call") -> Dict[str, Any]:
    """Return the topological signal block (beta0/beta1, cycles, Mapper)."""
    return run_core(graph)["topology"][kind]


def cycle_ranking(graph: Graph, kind: str = "call") -> List[List[str]]:
    """Return the H1 cycle basis as lists of node labels (one list per cycle)."""
    labels = {n.id: n.label for n in graph.nodes}
    topo = topology(graph, kind)
    return [[labels.get(nid, nid) for nid in cycle["nodes"]] for cycle in topo["h1_cycles"]]


"""Tests for the Python <-> Rust numeric core bridge."""

from pathlib import Path

import pytest

from manifold.analysis.math_core import (
    core_binary,
    cycle_ranking,
    fiedler_ranking,
    run_core,
    topology,
)
from manifold.ingest.python import PythonIngest

EXAMPLES = Path(__file__).resolve().parent.parent / "examples" / "python"


def _analyze(name: str):
    code = (EXAMPLES / name).read_text()
    return PythonIngest().analyze(code, path=name)


@pytest.fixture(scope="module")
def binary_available() -> bool:
    try:
        core_binary()
        return True
    except FileNotFoundError:
        return False


def test_core_binary_found(binary_available):
    if not binary_available:
        pytest.skip("manifold-core binary not built")
    assert core_binary().exists()


def test_reentrancy_call_graph_has_nonzero_fiedler(binary_available):
    if not binary_available:
        pytest.skip("manifold-core binary not built")
    res = _analyze("reentrancy.py")
    result = run_core(res.graph)
    call = result["spectral"]["call"]
    # The mutual-recursion cycle makes the call graph connected and non-trivial.
    assert call["lambda2"] > 0
    assert len(call["fiedler"]) == len(result["node_order"])


def test_fiedler_ranking_returns_labels(binary_available):
    if not binary_available:
        pytest.skip("manifold-core binary not built")
    res = _analyze("reentrancy.py")
    ranked = fiedler_ranking(res.graph, kind="call")
    assert ranked
    assert all(isinstance(label, str) for _, label, _ in ranked)


def test_topology_detects_reentrancy_cycle(binary_available):
    if not binary_available:
        pytest.skip("manifold-core binary not built")
    # reentrancy.py has a mutual-recursion cycle -> beta1 >= 1.
    res = _analyze("reentrancy.py")
    topo = topology(res.graph, kind="call")
    assert topo["beta1"] >= 1
    assert topo["h1_cycles"]


def test_topology_safe_has_no_cycle(binary_available):
    if not binary_available:
        pytest.skip("manifold-core binary not built")
    res = _analyze("safe.py")
    topo = topology(res.graph, kind="call")
    assert topo["beta1"] == 0


def test_cycle_ranking_returns_labels(binary_available):
    if not binary_available:
        pytest.skip("manifold-core binary not built")
    res = _analyze("reentrancy.py")
    cycles = cycle_ranking(res.graph, kind="call")
    assert cycles
    # The cycle should mention at least one of the mutually recursive functions.
    flat = [label for cycle in cycles for label in cycle]
    assert any("read_balance" in label or "update_balance" in label for label in flat)


def test_directed_path_homology_present_and_differs(binary_available):
    if not binary_available:
        pytest.skip("manifold-core binary not built")
    res = _analyze("reentrancy.py")
    topo = topology(res.graph, kind="call")
    assert "directed_path" in topo
    dp = topo["directed_path"]
    assert dp["beta0"] >= 1 and dp["beta1"] >= 0
    # Direction matters: the undirected homology sees a cycle (the triangle),
    # while GLMY path homology fills it via the apex and reports beta1 = 0.
    assert topo["beta1"] >= 1
    assert dp["beta1"] == 0

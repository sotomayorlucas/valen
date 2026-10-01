"""Tests for the pure-Python numeric-core fallback (no Rust toolchain needed)."""

from pathlib import Path

import pytest

from valen.analysis.math_core import centrality, cycle_ranking, run_core, topology
from valen.ingest.python import PythonIngest

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


@pytest.fixture(autouse=True)
def force_fallback(monkeypatch):
    monkeypatch.setenv("VALEN_NO_CORE", "1")


def _analyze(path: str):
    p = EXAMPLES / path
    return PythonIngest().analyze(p.read_text(), path=p.name)


def test_fallback_schema():
    res = _analyze("python/reentrancy.py")
    m = run_core(res.graph)
    assert m.get("engine") == "python-fallback"
    assert set(m) >= {"node_order", "spectral", "geometry", "topology", "centrality"}
    for kind in ("call", "data", "control"):
        assert set(m["spectral"][kind]) >= {"lambda2", "fiedler", "embedding", "directed"}
        assert set(m["topology"][kind]) >= {"beta0", "beta1", "h1_cycles", "directed_path"}
        assert set(m["centrality"][kind]) >= {"betweenness", "pagerank"}
    assert len(m["node_order"]) == res.graph.node_count


def test_fallback_fiedler_is_positive_on_cycle():
    res = _analyze("python/reentrancy.py")
    m = run_core(res.graph)
    assert m["spectral"]["call"]["lambda2"] > 0
    assert len(m["spectral"]["call"]["fiedler"]) == len(m["node_order"])


def test_fallback_topology_detects_cycle():
    res = _analyze("python/reentrancy.py")
    topo = topology(res.graph, "call")
    assert topo["beta1"] >= 1
    assert topo["h1_cycles"]
    assert topo["directed_path"]["beta0"] >= 1


def test_fallback_safe_has_no_cycle():
    res = _analyze("python/safe.py")
    assert topology(res.graph, "call")["beta1"] == 0


def test_fallback_cycle_mentions_recursion():
    res = _analyze("python/reentrancy.py")
    cycles = cycle_ranking(res.graph, "call")
    flat = [label for c in cycles for label in c]
    assert any("read_balance" in x or "update_balance" in x or "withdraw" in x for x in flat)


def test_fallback_centrality_runs():
    res = _analyze("python/reentrancy.py")
    c = centrality(res.graph, "call")
    assert len(c["betweenness"]) == res.graph.node_count
    assert abs(sum(v for _, v in c["pagerank"]) - 1.0) < 1e-6


def test_fallback_runs_on_multilang_examples():
    for path in ("c/command_injection.c", "rust/command_injection.rs",
                 "php/command_injection.php", "go/command_injection.go"):
        p = EXAMPLES / path
        res = __import__("valen.ingest", fromlist=["analyze"]).analyze(
            p.read_text(), path=str(p)
        )
        m = run_core(res.graph)
        assert m["node_order"]
        assert "topology" in m

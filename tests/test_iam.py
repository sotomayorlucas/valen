"""Tests for the IAM / cloud-trust adapter and privilege-bridge analysis."""

import json
from pathlib import Path

import pytest

from manifold.analysis.math_core import core_binary
from manifold.analysis.trust import privilege_bridges, trust_analysis
from manifold.ingest.iam import IAMIgest

EX = Path(__file__).resolve().parent.parent / "examples" / "iam"


@pytest.fixture(scope="module")
def binary_available() -> bool:
    try:
        core_binary()
        return True
    except FileNotFoundError:
        return False


def test_iam_builds_trust_graph():
    graph = IAMIgest().analyze((EX / "demo.json").read_text()).graph
    assert graph.meta["language"] == "iam"
    assert graph.node_count == 5
    assert graph.edge_count == 4


def test_privilege_bridges_flag_trust_crossing(binary_available):
    if not binary_available:
        pytest.skip("manifold-core binary not built")
    graph = IAMIgest().analyze((EX / "demo.json").read_text()).graph
    bridges = privilege_bridges(graph)
    assert bridges
    # the app -> data assume is the most negative (the trust bridge)
    top = bridges[0]
    assert {top["src"], top["dst"]} == {"frontend-role", "db-role"}
    assert top["kappa"] < 0


def test_trust_analysis_fiedler_surfaces_sensitive_resource(binary_available):
    if not binary_available:
        pytest.skip("manifold-core binary not built")
    graph = IAMIgest().analyze((EX / "demo.json").read_text()).graph
    report = trust_analysis(graph)
    boundary = [b[0] for b in report["fiedler_boundary"]]
    assert "secrets-bucket" in boundary or "admin-role" in boundary

"""Tests for the centrality kernels (betweenness, PageRank) and bridge analysis."""

from pathlib import Path

import pytest

from valen.analysis.math_core import (
    betweenness_ranking,
    centrality,
    core_binary,
    pagerank_ranking,
)
from valen.analysis.trust import bridge_nodes, trust_analysis
from valen.ingest.iam import IAMIgest

EX = Path(__file__).resolve().parent.parent / "examples" / "iam"


@pytest.fixture(scope="module")
def binary_available():
    try:
        core_binary()
        return True
    except FileNotFoundError:
        return False


@pytest.fixture(scope="module")
def iam_graph():
    return IAMIgest().analyze((EX / "demo.json").read_text()).graph


def test_centrality_block(binary_available, iam_graph):
    if not binary_available:
        pytest.skip("valen-core binary not built")
    block = centrality(iam_graph, "call")
    assert "betweenness" in block and "pagerank" in block


def test_betweenness_ranking(binary_available, iam_graph):
    if not binary_available:
        pytest.skip("valen-core binary not built")
    ranking = betweenness_ranking(iam_graph, "call")
    assert ranking and len(ranking) == 5
    scores = [s for _, _, s in ranking]
    assert scores == sorted(scores, reverse=True)


def test_pagerank_ranking(binary_available, iam_graph):
    if not binary_available:
        pytest.skip("valen-core binary not built")
    ranking = pagerank_ranking(iam_graph, "call")
    assert ranking and len(ranking) == 5
    scores = [s for _, _, s in ranking]
    assert scores == sorted(scores, reverse=True)


def test_bridge_nodes_in_trust_analysis(binary_available, iam_graph):
    if not binary_available:
        pytest.skip("valen-core binary not built")
    report = trust_analysis(iam_graph)
    assert "bridge_nodes" in report
    assert report["bridge_nodes"]

"""Tests for the advanced network algorithms (flow / probability / cost)."""

import json
from pathlib import Path

from valen.analysis.network import (
    eigenvector_centrality,
    hitting_probabilities,
    hits,
    katz_centrality,
    min_vertex_cut,
    weighted_shortest_paths,
)
from valen.ir import EdgeKind, Graph, NodeKind
from valen.redteam.ad import (
    cheapest_paths,
    chokepoints,
    hitting_rank,
    parse_sharphound,
)
from valen.redteam.creds import rank_passwords, spray_batches

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "ad_sharphound.json"


def _path(n):
    g = Graph()
    for i in range(n):
        g.add_node(str(i), NodeKind.GATE, str(i))
    for i in range(n - 1):
        g.add_edge(str(i), str(i + 1), EdgeKind.CALL)
    return g


def test_hitting_probabilities_deterministic():
    g = _path(4)
    h = hitting_probabilities(g, ["3"])
    assert h["0"] == 1.0 and h["3"] == 1.0


def test_hitting_probabilities_branching():
    g = Graph()
    for n in ["s", "a", "b", "t"]:
        g.add_node(n, NodeKind.GATE, n)
    g.add_edge("s", "a", EdgeKind.CALL)
    g.add_edge("s", "b", EdgeKind.CALL)
    g.add_edge("a", "t", EdgeKind.CALL)
    g.add_edge("b", "x", EdgeKind.CALL)  # dead end
    g.add_node("x", NodeKind.GATE, "x")
    h = hitting_probabilities(g, ["t"])
    assert abs(h["s"] - 0.5) < 1e-6


def test_centralities_hub_detection():
    g = Graph()
    for n in ["A", "B", "C", "H"]:
        g.add_node(n, NodeKind.GATE, n)
    for n in ["A", "B", "C"]:
        g.add_edge(n, "H", EdgeKind.CALL)
    hubs, auth = hits(g)
    assert hubs["H"] == 1.0
    assert auth["A"] > 0
    assert eigenvector_centrality(g)["H"] == 1.0
    assert katz_centrality(g)["H"] == 1.0


def test_weighted_shortest_paths_prefers_cheap():
    g = Graph()
    for n in ["A", "B", "C"]:
        g.add_node(n, NodeKind.GATE, n)
    g.add_edge("A", "B", EdgeKind.CALL, attrs={"cost": 10})
    g.add_edge("A", "C", EdgeKind.CALL, attrs={"cost": 1})
    g.add_edge("C", "B", EdgeKind.CALL, attrs={"cost": 1})
    best = weighted_shortest_paths(g, ["A"], ["B"])
    assert best["B"][0] == 2.0
    assert best["B"][1] == ["A", "C", "B"]


def test_min_vertex_cut_path_and_disjoint():
    assert min_vertex_cut(_path(5), ["0"], ["4"]) == (1, ["1"])
    g = Graph()
    for n in ["s", "a", "b", "t"]:
        g.add_node(n, NodeKind.GATE, n)
    g.add_edge("s", "a", EdgeKind.CALL)
    g.add_edge("a", "t", EdgeKind.CALL)
    g.add_edge("s", "b", EdgeKind.CALL)
    g.add_edge("b", "t", EdgeKind.CALL)
    assert min_vertex_cut(g, ["s"], ["t"]) == (2, ["a", "b"])


def test_min_vertex_cut_direct_edge_is_zero():
    g = Graph()
    for n in ["s", "t"]:
        g.add_node(n, NodeKind.GATE, n)
    g.add_edge("s", "t", EdgeKind.CALL)
    assert min_vertex_cut(g, ["s"], ["t"]) == (0, [])


def _ad():
    return parse_sharphound(json.loads(FIXTURE.read_text()))


def test_ad_chokepoints_via_group():
    ad = _ad()
    out = chokepoints(ad, ["BOB"])
    assert out["min_cut"] == 1
    assert any("IT" in c["label"].upper() for c in out["chokepoints"])


def test_ad_hitting_rank_and_cheapest():
    ad = _ad()
    h = hitting_rank(ad, ["ALICE", "BOB"])
    assert h["user:ALICE@CORP.LOCAL"] == 1.0
    assert 0 < h["user:BOB@CORP.LOCAL"] < 1.0
    cheap = cheapest_paths(ad, ["ALICE"])
    assert cheap and cheap[0]["cost"] >= 1.0
    assert cheap[0]["target"].endswith("DOMAIN ADMINS@CORP.LOCAL")


def test_password_ranking_and_batches():
    ranked = rank_passwords()
    assert ranked and ranked[0]["score"] >= ranked[-1]["score"]
    assert all("passpass" not in c["password"] for c in ranked)
    batches = spray_batches("C", "d", "u.txt", candidates=["a", "b", "c"], per_batch=2)
    assert len(batches) == 3 and batches[0]["command"][0] == "kerbrute"

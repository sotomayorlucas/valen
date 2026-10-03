"""Tests for the advanced network algorithms (flow / probability / cost)."""

import json
from pathlib import Path

from valen.analysis.network import (
    articulation_points,
    bridges,
    eigenvector_centrality,
    hitting_probabilities,
    hitting_probabilities_exact,
    hits,
    katz_centrality,
    min_vertex_cut,
    vertex_connectivity,
    weighted_shortest_paths,
)
from valen.analysis.formal_planner import synthesize_plan
from valen.ir import EdgeKind, Graph, NodeKind
from valen.redteam.ad import (
    cheapest_paths,
    chokepoints,
    hitting_rank,
    parse_sharphound,
)
from valen.redteam.creds import rank_passwords, spray_batches
from valen.redteam.pcfg import PCFG, structure_of, tokenize

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


def test_pcfg_tokenize_and_structure():
    assert tokenize("Summer2024!") == [("L", "Summer"), ("D", "2024"), ("S", "!")]
    assert structure_of(tokenize("Summer2024!")) == "L6D4S1"


def test_pcfg_ranks_corpus_and_no_cross_length():
    corpus = ["password123", "summer2024", "admin123", "password123",
              "password123", "welcome1"]
    p = PCFG().train(corpus)
    gen = [g["password"] for g in p.generate(200)]
    # exactly the learned combos, most frequent first, no cross-length mixing
    assert gen == ["password123", "summer2024", "admin123", "welcome1"]
    assert "summer123" not in gen


def test_pcfg_monotonic_and_unique_on_seed():
    p = PCFG().train([])  # seed corpus
    g = p.generate(200)
    probs = [x["prob"] for x in g]
    assert all(probs[i] >= probs[i + 1] - 1e-9 for i in range(len(probs) - 1))
    assert len({x["password"] for x in g}) == len(g)


def test_pcfg_from_potfile_seeds_when_empty(tmp_path):
    p = PCFG.from_potfile(str(tmp_path / "nope"))
    assert p._total > 0  # fell back to the seed corpus
    assert p.generate(5)


def test_synthesize_plan_finds_cheapest():
    g = Graph()
    for n in ["s", "a", "b", "t"]:
        g.add_node(n, NodeKind.GATE, n)
    g.add_edge("s", "a", EdgeKind.CALL, attrs={"relation": "assume", "technique": "T1", "cost": 1})
    g.add_edge("s", "b", EdgeKind.CALL, attrs={"relation": "assume", "technique": "T2", "cost": 10})
    g.add_edge("a", "t", EdgeKind.CALL, attrs={"relation": "assume", "technique": "T3", "cost": 1})
    g.add_edge("b", "t", EdgeKind.CALL, attrs={"relation": "assume", "technique": "T4", "cost": 1})
    plans = synthesize_plan(g, ["s"], ["t"], max_steps=4)
    assert plans and plans[0]["target"] == "t"
    assert plans[0]["cost"] == 2.0          # s->a->t (1+1), not s->b->t (11)
    assert [s["to"] for s in plans[0]["steps"]] == ["a", "t"]


def test_synthesize_attack_ad():
    ad = _ad()
    from valen.redteam.ad import node_id, synthesize_attack

    plans = synthesize_attack(ad, ["ALICE"])
    by_target = {p["target"]: p for p in plans}
    da = node_id("group", "DOMAIN ADMINS@CORP.LOCAL")
    assert by_target[da]["cost"] == 3.0
    assert [s["technique"] for s in by_target[da]["steps"]] == ["T1098"]
    # BOB cannot reach DA (only the domain via DCSync)
    bob_plans = synthesize_attack(ad, ["BOB"])
    assert all(p["target"] != da for p in bob_plans)


def test_synthesize_plan_and_preconditions():
    g = Graph()
    for n in ["s", "a", "b", "t"]:
        g.add_node(n, NodeKind.GATE, n)
    g.add_edge("s", "a", EdgeKind.CALL, attrs={"relation": "assume", "technique": "T1", "cost": 1})
    g.add_edge("s", "b", EdgeKind.CALL, attrs={"relation": "assume", "technique": "T2", "cost": 1})
    # t requires BOTH a and b (compound action); without it, t is unreachable
    assert synthesize_plan(g, ["s"], ["t"], max_steps=4) == []
    plans = synthesize_plan(g, ["s"], ["t"], max_steps=4, compound_actions=[
        {"sources": ["a", "b"], "target": "t", "relation": "AND", "technique": "T99", "cost": 5},
    ])
    assert plans and plans[0]["cost"] == 7.0
    assert plans[0]["steps"][-1]["relation"] == "AND"


def test_hitting_probabilities_exact_matches_iterative():
    g = Graph()
    for n in ["s", "a", "b", "t", "x"]:
        g.add_node(n, NodeKind.GATE, n)
    g.add_edge("s", "a", EdgeKind.CALL)
    g.add_edge("s", "b", EdgeKind.CALL)
    g.add_edge("a", "t", EdgeKind.CALL)
    g.add_edge("b", "x", EdgeKind.CALL)
    it = hitting_probabilities(g, ["t"])
    ex = hitting_probabilities_exact(g, ["t"])
    for n in ["s", "a", "b", "t"]:
        assert abs(it[n] - ex[n]) < 1e-6


def test_articulation_points_and_bridges():
    g = Graph()
    for n in ["a", "b", "c", "d", "e"]:
        g.add_node(n, NodeKind.GATE, n)
    for u, v in [("a", "b"), ("b", "c"), ("c", "a"), ("c", "d"), ("d", "e")]:
        g.add_edge(u, v, EdgeKind.CALL)
    assert articulation_points(g) == ["c", "d"]
    assert set(bridges(g)) == {("c", "d"), ("d", "e")}
    assert vertex_connectivity(g, ["c"], ["e"]) == 1

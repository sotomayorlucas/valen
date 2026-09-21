"""Tests for the prioritization-oracle experiment."""

from manifold.oracle import (
    Candidate,
    analyze_case,
    cost_curve,
    global_metrics,
    order,
    paired_permutation,
    rank_of_target,
)

CODE = """
class T {
  void a(HttpServletRequest req, java.sql.Statement s) {
    String p = req.getParameter("x");
    s.executeQuery("SELECT " + p);        // tainted sqli
  }
  void b(HttpServletResponse resp) throws Exception {
    resp.getWriter().println("hello");    // xss, not tainted
  }
}
"""


def _cache():
    return (analyze_case(CODE), "sqli")


def test_candidates_are_enumerated_with_taint_flags():
    cands = analyze_case(CODE)
    cats = {c.category for c in cands}
    assert "sqli" in cats and "xss" in cats
    assert any(c.tainted for c in cands if c.category == "sqli")
    assert not any(c.tainted for c in cands if c.category == "xss")


def test_taint_order_ranks_target_first():
    cands = analyze_case(CODE)
    assert rank_of_target(order(cands, "taint"), "sqli") == 1
    assert rank_of_target(order(cands, "field"), "sqli") == 1


def test_cost_curve_is_monotone_and_bounded():
    ranks = [1, 1, 2, 3, 5]
    curve = cost_curve(ranks, 5)
    assert curve == sorted(curve)
    assert curve[-1] == 1.0
    assert curve[0] == 2 / 5


def test_paired_permutation_detects_consistent_difference():
    a = [1.0] * 8
    b = [0.5] * 8
    r = paired_permutation(a, b, iters=2000)
    assert r["mean_diff"] > 0
    assert r["p_value"] < 0.05


def test_global_metrics_rewards_taint_first_ordering():
    c_vuln = [Candidate(1, "exec", "sql", True, 0.9), Candidate(2, "println", "xss", False, 0.0)]
    c_safe = [Candidate(1, "exec", "sql", True, 0.5)]
    entries = [(c_vuln, "sql", True), (c_safe, "sql", False)]
    taint = global_metrics(entries, method="taint", ks=(1,))
    rand = global_metrics(entries, method="random", ks=(1,))
    assert taint["average_precision"] >= rand["average_precision"]
    assert taint["relevant"] == 1

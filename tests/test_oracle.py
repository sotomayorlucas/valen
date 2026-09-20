"""Tests for the prioritization-oracle experiment."""

from manifold.oracle import analyze_case, cost_curve, order, rank_of_target

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

"""Tests for the interprocedural Java taint analyzer."""

from manifold.ingest.java import JavaIngest
from manifold.ingest.java_interproc import JavaInterproceduralIngest

CODE = """class T {
  void handle(HttpServletRequest req) throws Exception {
    String p = req.getParameter("x");
    action(p);
  }
  void action(String data) throws Exception {
    java.sql.Statement s = null;
    s.executeQuery("SELECT " + data);
  }
}"""


def test_intraprocedural_misses_cross_method_flow():
    assert JavaIngest().analyze(CODE).findings == []


def test_interprocedural_recovers_cross_method_flow():
    findings = JavaInterproceduralIngest().analyze(CODE).findings
    assert findings
    assert findings[0].category == "sqli"
    assert findings[0].sink_name == "executeQuery"


def test_interprocedural_no_taint_stays_clean():
    code = (
        "class T { void a() throws Exception { action(\"safe\"); }"
        " void action(String data) throws Exception {"
        "  java.sql.Statement s = null; s.executeQuery(\"SELECT \" + data); } }"
    )
    assert JavaInterproceduralIngest().analyze(code).findings == []


RETURN_CTX = """class T {
  String f(String x) { return x; }
  void bad(HttpServletRequest req) throws Exception { String p = req.getParameter("x"); f(p); }
  void good() throws Exception { String r = f("safe"); sink(r); }
  void sink(String d) throws Exception { java.sql.Statement s = null; s.executeQuery("SELECT " + d); }
}"""


def test_context_sensitivity_prunes_return_false_positive():
    analyzer = JavaInterproceduralIngest()
    # context-insensitive return-taint over-approximates and fires the clean caller
    assert analyzer.analyze(RETURN_CTX).findings
    # per-context return-taint prunes it
    assert analyzer.analyze(RETURN_CTX, context_sensitive=True).findings == []

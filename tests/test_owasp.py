"""Tests for the OWASP Benchmark runner."""

from manifold.owasp import evaluate, load_expected


def test_load_expected_parses_csv(tmp_path):
    csv = tmp_path / "expectedresults.csv"
    csv.write_text(
        "# test name, category, real vulnerability, cwe\n"
        "BenchmarkTest00001,pathtraver,true,22\n"
        "BenchmarkTest00002,sqli,false,89\n"
    )
    cases = load_expected(str(csv))
    assert len(cases) == 2
    assert cases[0].category == "pathtraver" and cases[0].vulnerable
    assert cases[1].category == "sqli" and not cases[1].vulnerable


def test_evaluate_on_tiny_corpus(tmp_path):
    testcode = tmp_path / "testcode"
    testcode.mkdir()
    # vulnerable: request param flows to executeQuery
    (testcode / "BenchmarkTest90001.java").write_text(
        "class T { void f(HttpServletRequest r, java.sql.Statement s) {"
        " String p = r.getParameter(\"x\");"
        " s.executeQuery(\"SELECT \" + p); } }"
    )
    # safe: no sink
    (testcode / "BenchmarkTest90002.java").write_text(
        "class T { void f() { int a = 1 + 1; } }"
    )
    csv = tmp_path / "expectedresults.csv"
    csv.write_text(
        "# test name, category, real vulnerability, cwe\n"
        "BenchmarkTest90001,sqli,true,89\n"
        "BenchmarkTest90002,sqli,false,89\n"
    )
    metrics = evaluate(str(testcode), str(csv), categories=["sqli"])
    m = metrics["overall"]
    assert (m.tp, m.fp, m.fn, m.tn) == (1, 0, 0, 1)
    assert m.precision == 1.0 and m.recall == 1.0

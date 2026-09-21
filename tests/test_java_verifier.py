"""Tests for the Java Z3 symbolic verifier."""

from valen.analysis.java_verifier import verify_java


def test_confirms_reachable_taint_flow_with_witness():
    code = (
        "class T { void f(HttpServletRequest req, java.sql.Statement s) {"
        "  String p = req.getParameter(\"x\");"
        "  s.executeQuery(\"SELECT \" + p);"
        "} }"
    )
    v = verify_java(code)
    assert len(v) == 1
    assert v[0].category == "sqli"
    assert v[0].witness  # a concrete payload


def test_rejects_sanitized_flow():
    code = (
        "class T { void f(HttpServletRequest req, HttpServletResponse resp) throws Exception {"
        "  String p = req.getParameter(\"x\");"
        "  resp.getWriter().println(org.owasp.esapi.ESAPI.encoder().encodeForHTML(p));"
        "} }"
    )
    assert verify_java(code) == []


def test_branch_join_confirms_null_guard_flow():
    code = (
        "class T { void f(HttpServletRequest req, java.sql.Statement s) {"
        "  String p = req.getParameter(\"x\");"
        "  if (p == null) p = \"\";"
        "  s.executeQuery(\"SELECT \" + p);"
        "} }"
    )
    assert len(verify_java(code)) == 1


def test_system_out_is_not_xss():
    code = (
        "class T { void f(HttpServletRequest req) {"
        "  String p = req.getParameter(\"x\");"
        "  System.out.println(p);"
        "} }"
    )
    assert verify_java(code) == []

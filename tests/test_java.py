"""Tests for the Java SAST adapter improvements (found on OWASP Benchmark)."""

from valen.ingest.java import JavaIngest


def _cats(code: str) -> set:
    return {f.category for f in JavaIngest().analyze(code, path="T.java").findings}


def test_branch_join_preserves_taint_through_null_guard():
    # `if (param == null) param = ""` must not clear the taint on the other path.
    code = (
        "class T { void f(HttpServletRequest request, java.sql.Statement s) {"
        "  String param = request.getParameter(\"x\");"
        "  if (param == null) param = \"\";"
        "  s.executeQuery(\"SELECT \" + param);"
        "} }"
    )
    assert "sqli" in _cats(code)


def test_system_out_is_not_xss():
    code = (
        "class T { void f(HttpServletRequest request) {"
        "  String p = request.getParameter(\"x\");"
        "  System.out.println(p);"
        "} }"
    )
    assert "xss" not in _cats(code)


def test_response_writer_is_xss():
    code = (
        "class T { void f(HttpServletRequest request, HttpServletResponse response) throws Exception {"
        "  String p = request.getParameter(\"x\");"
        "  response.getWriter().println(p);"
        "} }"
    )
    assert "xss" in _cats(code)


def test_receiver_taint_through_prepared_statement():
    code = (
        "class T { void f(HttpServletRequest request, java.sql.Connection c) throws Exception {"
        "  String p = request.getParameter(\"x\");"
        "  java.sql.PreparedStatement s = c.prepareStatement(\"SELECT \" + p);"
        "  s.execute();"
        "} }"
    )
    assert "sqli" in _cats(code)


def test_state_taint_through_collection_and_process_builder():
    code = (
        "class T { void f(HttpServletRequest request) throws Exception {"
        "  String p = request.getParameter(\"x\");"
        "  java.util.List<String> args = new java.util.ArrayList<String>();"
        "  args.add(p);"
        "  ProcessBuilder pb = new ProcessBuilder();"
        "  pb.command(args);"
        "  pb.start();"
        "} }"
    )
    assert "cmdi" in _cats(code)


def test_sanitizer_kills_xss():
    code = (
        "class T { void f(HttpServletRequest request, HttpServletResponse response) throws Exception {"
        "  String p = request.getParameter(\"x\");"
        "  response.getWriter().println(org.owasp.esapi.ESAPI.encoder().encodeForHTML(p));"
        "} }"
    )
    assert "xss" not in _cats(code)

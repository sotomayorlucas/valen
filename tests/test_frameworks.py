"""Tests for framework/library summaries (attribute sources + ORM/SSTI sinks)."""

from pathlib import Path

from manifold.ingest.python import PythonIngest

EXAMPLES = Path(__file__).resolve().parent.parent / "examples" / "python"


def _lines(name: str):
    code = (EXAMPLES / name).read_text()
    return {f.line for f in PythonIngest().analyze(code, path=name).findings}


def test_django_attribute_source_reaches_sql_sink():
    lines = _lines("framework_sqli.py")
    assert 14 in lines          # search(): request.GET -> cursor.execute(concat)
    assert 22 not in lines      # safe_search(): parameterized query


def test_flask_ssti_sink_with_literal_template_is_safe():
    lines = _lines("framework_ssti.py")
    assert 8 in lines           # page(): request.args -> render_template_string
    assert 13 not in lines      # safe_page(): literal template, tainted var bound


def test_attribute_source_tag_is_recorded():
    code = (EXAMPLES / "framework_sqli.py").read_text()
    findings = PythonIngest().analyze(code, path="framework_sqli.py").findings
    sources = {s for f in findings for s in f.source_names}
    assert any("request.GET" in s for s in sources)

"""Tests for the manifold visualization."""

from pathlib import Path

from agent.agent import ManifoldAgent
from manifold.ingest.python import PythonIngest
from manifold.viz import render_html, write_html

EXAMPLES = Path(__file__).resolve().parent.parent / "examples" / "python"


def test_render_html_contains_graph_and_findings(tmp_path):
    code = (EXAMPLES / "sqli.py").read_text()
    result = PythonIngest().analyze(code, path="sqli.py")
    report = ManifoldAgent().run(code, path="sqli.py")

    html = render_html(result.graph, report=report)
    assert html.startswith("<!doctype html>")
    assert "<svg" in html
    assert "SQL injection" in html
    assert '"taint"' in html or '"call"' in html  # typed edges present


def test_write_html_creates_file(tmp_path):
    code = (EXAMPLES / "safe.py").read_text()
    result = PythonIngest().analyze(code, path="safe.py")
    report = ManifoldAgent().run(code, path="safe.py")

    out = tmp_path / "safe.html"
    write_html(result.graph, str(out), report=report)
    assert out.exists()
    text = out.read_text()
    assert text.startswith("<!doctype html>")
    assert "no findings" in text or '"findings":[]' in text

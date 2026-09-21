"""Tests for the dashboard generator."""

from valen.dashboard import build_html, load_data, write_dashboard


def test_dashboard_embeds_experiments_and_methodology(tmp_path):
    out = tmp_path / "dashboard.html"
    write_dashboard(str(out))
    html = out.read_text()
    assert html.startswith("<!doctype html>")
    assert "Methodology" in html and "pipeline" in html
    assert "Mapping hypotheses" in html and "Evaluation protocol" in html
    assert "const DATA" in html


def test_load_data_has_experiments_and_examples():
    data = load_data()
    assert "examples" in data and len(data["examples"]) >= 6
    assert "scale" in data

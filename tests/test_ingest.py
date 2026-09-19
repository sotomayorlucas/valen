"""End-to-end tests for the Python SAST ingest + taint pass."""

from pathlib import Path

from manifold.ingest.python import PythonIngest

EXAMPLES = Path(__file__).resolve().parent.parent / "examples" / "python"


def _analyze(name: str):
    code = (EXAMPLES / name).read_text()
    return PythonIngest().analyze(code, path=name)


def _findings_by_category(result):
    return {f.category: f for f in result.findings}


def test_sqli_detected():
    res = _analyze("sqli.py")
    cats = _findings_by_category(res)
    assert "sql" in cats, f"expected a SQL finding, got {res.findings}"
    f = cats["sql"]
    assert f.sink_name == "cursor.execute"
    assert f.source_names
    assert f.line > 0


def test_command_injection_detected():
    res = _analyze("command_injection.py")
    cats = _findings_by_category(res)
    assert "command_execution" in cats
    assert cats["command_execution"].sink_name == "subprocess.run"


def test_code_execution_detected():
    res = _analyze("code_execution.py")
    cats = _findings_by_category(res)
    assert "code_execution" in cats
    assert "command_execution" in cats
    assert "deserialization" in cats


def test_safe_has_no_findings():
    res = _analyze("safe.py")
    assert res.findings == []


def test_graph_has_expected_structure():
    res = _analyze("sqli.py")
    g = res.graph
    kinds = {n.kind for n in g.nodes}
    assert "function" in {k.value for k in kinds}
    assert "sink" in {k.value for k in kinds}
    assert "source" in {k.value for k in kinds}
    counts = g.edge_kind_counts()
    assert counts.get("taint", 0) >= 1
    assert counts.get("control", 0) >= 1

"""Tests for the vulnerability scalar field V(x)."""

from pathlib import Path

import pytest

from valen.analysis.field import probability_field, vulnerability_field
from valen.analysis.math_core import core_binary, run_core
from valen.ingest.python import PythonIngest

EXAMPLES = Path(__file__).resolve().parent.parent / "examples" / "python"


@pytest.fixture(scope="module")
def binary_available() -> bool:
    try:
        core_binary()
        return True
    except FileNotFoundError:
        return False


def test_field_highlights_tainted_nodes(binary_available):
    if not binary_available:
        pytest.skip("valen-core binary not built")
    code = (EXAMPLES / "sqli.py").read_text()
    result = PythonIngest().analyze(code, path="sqli.py")
    math = run_core(result.graph)
    field = vulnerability_field(result.graph, math=math, findings=result.findings)

    assert field
    # The sink node must be among the highest-scored nodes.
    sink = [n for n in result.graph.nodes if n.kind.value == "sink"][0]
    assert field[sink.id] > 0.0
    assert field[sink.id] >= max(field.values()) - 1e-9


def test_field_is_low_on_safe(binary_available):
    if not binary_available:
        pytest.skip("valen-core binary not built")
    code = (EXAMPLES / "safe.py").read_text()
    result = PythonIngest().analyze(code, path="safe.py")
    math = run_core(result.graph)
    field = vulnerability_field(result.graph, math=math, findings=result.findings)
    # No taint/formal/topological/geometric signal: only a weak structural
    # (spectral) contribution remains, so the max stays well below the taint case.
    assert max(field.values()) < 0.3


def test_probability_field_is_in_unit_interval():
    probs = probability_field({"a": 0.0, "b": 0.5, "c": 1.0})
    assert all(0.0 < p < 1.0 for p in probs.values())

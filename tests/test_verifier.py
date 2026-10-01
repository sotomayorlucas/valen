"""Tests for the Z3-backed symbolic verifier (formal layer)."""

from pathlib import Path

from valen.analysis.verifier import verify
from valen.ingest.python import PythonIngest

EXAMPLES = Path(__file__).resolve().parent.parent / "examples" / "python"


def _verify(name: str):
    code = (EXAMPLES / name).read_text()
    return verify(code, path=name)


def _by_category(verifications):
    return {v.category: v for v in verifications}


def test_sqli_vulnerable_verified_but_parameterized_not():
    vs = _verify("sqli.py")
    cats = _by_category(vs)
    assert "sql" in cats
    # Only the concatenated query (line 9) is verified; the parameterized
    # safe_search is not.
    assert cats["sql"].line == 9


def test_command_injection_vulnerable_verified_argv_not():
    vs = _verify("command_injection.py")
    cats = _by_category(vs)
    assert "command_execution" in cats
    assert cats["command_execution"].line == 7


def test_sanitizer_neutralizes_flow():
    vs = _verify("sanitized.py")
    # Only the unsanitized concatenation is verified.
    assert len(vs) == 1
    assert vs[0].line == 9  # vulnerable_ping's sink
    assert vs[0].sink_name == "subprocess.run"


def test_safe_and_reentrancy_have_no_verified_flows():
    assert _verify("safe.py") == []
    assert _verify("reentrancy.py") == []


def test_witness_is_non_empty():
    vs = _verify("sqli.py")
    for v in vs:
        for source, value in v.witness.items():
            assert value != ""


def test_verifier_aligns_with_taint_findings():
    # Every taint finding (minus the parameterized/argv false positives we
    # already exclude) should be confirmed by the verifier.
    code = (EXAMPLES / "code_execution.py").read_text()
    taint = PythonIngest().analyze(code, path="code_execution.py").findings
    vs = _verify("code_execution.py")
    assert len(vs) == len(taint)
    taint_lines = sorted(f.line for f in taint)
    verif_lines = sorted(v.line for v in vs)
    assert taint_lines == verif_lines

"""Tests for the BOLA / IDOR + missing-authorization (CWE-639/862) detector.

This is the *trust & logic* pivot: classic taint analysis is structurally blind
here (the object selector is a clean cast value; a bound parameter carries no
taint), while VALEN's structural signal --- an ungated, user-controlled
resource access --- surfaces the flaw.
"""

from pathlib import Path

from valen.analysis.authorization import bola_idor_candidates
from valen.ingest.python import PythonIngest

BOLA = Path(__file__).resolve().parent.parent / "examples" / "python" / "bola"


def _analyze(name: str):
    code = (BOLA / name).read_text()
    return PythonIngest().analyze(code, path=name)


def test_bola_taint_is_blind_on_cast_selector():
    # The object id is cast to int -> taint sees it as clean and reports nothing.
    res = _analyze("idor_vuln.py")
    assert res.findings == [], "taint must be blind to the clean (cast) selector"


def test_bola_detector_flags_ungated_idor():
    res = _analyze("idor_vuln.py")
    cands = bola_idor_candidates(res.graph)
    assert len(cands) == 1
    assert cands[0].kind == "bola"
    assert cands[0].category == "idor"
    assert "request.args.get" in cands[0].source_names
    assert cands[0].sink_name == "db.execute"


def test_bola_missing_authorization_cwe862():
    res = _analyze("cwe862_vuln.py")
    cands = bola_idor_candidates(res.graph)
    assert len(cands) == 1


def test_bola_gated_variants_are_silent():
    # login_required / admin_required introduce the auth edge -> no finding.
    for name in ("idor_fixed_gate.py", "idor_fixed_ownership.py", "cwe862_fixed.py"):
        res = _analyze(name)
        assert bola_idor_candidates(res.graph) == [], f"{name} must be silent"


def test_bola_benign_is_silent():
    # resource sink but NO user-controlled selector -> silent.
    res = _analyze("benign.py")
    assert bola_idor_candidates(res.graph) == []


def test_bola_corpus_precision_recall():
    import json
    import subprocess
    import sys
    root = BOLA.parent.parent.parent
    subprocess.run(
        [sys.executable, str(root / "benchmarks" / "run_bola.py"), "--corpus", "small"],
        capture_output=True, text=True, check=True,
    )
    data = json.loads((root / "benchmarks" / "bola_results.json").read_text())
    assert data["recall"] == 1.0
    assert data["precision"] == 1.0
    assert data["n"] == 6


def test_bola_large_corpus_metrics():
    import json
    import subprocess
    import sys
    root = BOLA.parent.parent.parent
    subprocess.run(
        [sys.executable, str(root / "benchmarks" / "run_bola.py"), "--corpus", "large"],
        capture_output=True, text=True, check=True,
    )
    data = json.loads((root / "benchmarks" / "bola_results.json").read_text())
    assert data["n"] == 39
    assert data["recall"] == 1.0
    assert 0.6 <= data["precision"] <= 0.8
    # the false positives are the *documented* over-approximation limits
    assert data["fp"] == 7
    assert data["fn"] == 0

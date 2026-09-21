"""Tests for the specification-mining ablation (offline smoke)."""

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_spec_mining_offline_runs(tmp_path):
    out = tmp_path / "spec.json"
    proc = subprocess.run(
        [sys.executable, str(ROOT / "benchmarks" / "run_spec_mining.py"), "--out", str(out)],
        capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stderr
    data = json.loads(out.read_text())
    assert data["summary"]["n"] == 8
    # offline: the LLM returns no answer, so everything is scored as hallucinated
    assert data["summary"]["live"] is False
    assert data["summary"]["hallucination_rate"] == 1.0

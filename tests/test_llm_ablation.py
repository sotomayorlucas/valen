"""Tests for the larger LLM ablation (offline mode).

The online (LiteLLM) run needs a local proxy, so we only smoke-test offline here:
with the heuristic agent on both sides, detection and ranking must be invariant
and interpretation must be identical (CWE change rate 0).
"""

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _run(args, out):
    proc = subprocess.run(
        [sys.executable, str(ROOT / "benchmarks" / "run_llm_ablation.py"),
         *args, "--out", str(out)],
        capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stderr
    return json.loads(out.read_text())


def test_ablation_offline_detection_and_ranking_invariant(tmp_path):
    out = tmp_path / "abl.json"
    data = _run(["--limit", "10"], out)
    assert data["summary"]["live"] is False
    assert data["summary"]["detection_agreement"] == 1.0
    assert data["summary"]["ranking_agreement"] == 1.0
    assert data["summary"]["cwe_change_rate"] == 0.0
    assert data["summary"]["n_confirmed"] >= 5


def test_ablation_corpus_has_confirmed_findings(tmp_path):
    out = tmp_path / "abl.json"
    data = _run(["--limit", "20"], out)
    assert data["summary"]["n_confirmed"] >= 8

"""Tests for the real-data crAPI object-level-authorization detector."""

import json
import subprocess
import sys
from pathlib import Path

from manifold.analysis.api_bola import api_bola_candidates

ROOT = Path(__file__).resolve().parent.parent
SPEC = ROOT / "examples" / "api" / "crapi-openapi-spec.json"


def test_detector_recovers_documented_bola_endpoints():
    spec = json.loads(SPEC.read_text())
    flagged = {f"{m} {p}" for m, p, _ in api_bola_candidates(spec)}
    labels = json.loads((ROOT / "examples" / "api" / "crapi_bola_labels.json").read_text())
    for k in labels["vulnerable"]:
        assert k in flagged, f"must flag {k}"


def test_crapi_benchmark_metrics():
    subprocess.run(
        [sys.executable, str(ROOT / "benchmarks" / "run_crapi_bola.py")],
        capture_output=True, text=True, check=True,
    )
    data = json.loads((ROOT / "benchmarks" / "crapi_bola_results.json").read_text())
    assert data["recall"] == 1.0
    assert data["precision"] >= 0.85
    assert data["n_vulnerable"] == 9
    # every BOLA endpoint is authenticated -> missing-auth check is blind to BOLA
    assert data["vulnerable_authenticated"] == data["n_vulnerable"]

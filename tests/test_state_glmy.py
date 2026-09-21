"""Tests for the GLMY-vs-undirected state-cycle benchmark."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from manifold.analysis.math_core import core_binary

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def binary_available() -> bool:
    try:
        core_binary()
        return True
    except FileNotFoundError:
        return False


def test_glmy_dominates_symmetrized(binary_available):
    if not binary_available:
        pytest.skip("manifold-core binary not built")
    subprocess.run(
        [sys.executable, str(ROOT / "benchmarks" / "run_state_glmy.py")],
        capture_output=True, text=True, check=True,
    )
    data = json.loads((ROOT / "benchmarks" / "glmy_state_results.json").read_text())
    glmy, und = data["glmy"], data["undirected"]
    assert glmy["recall"] == 1.0  # catches every true feedback cycle
    assert glmy["fn"] == 0
    # undirected misses the 2-cycles and flags the filled triangle
    assert und["recall"] < glmy["recall"]
    assert und["precision"] < glmy["precision"]


def test_glmy_catches_2cycle_and_avoids_filled_triangle(binary_available):
    if not binary_available:
        pytest.skip("manifold-core binary not built")
    data = json.loads((ROOT / "benchmarks" / "glmy_state_results.json").read_text())
    rows = {r["name"]: r for r in data["rows"]}
    # the two cases where symmetrization is wrong in opposite directions
    assert rows["cycle2"]["glmy_beta1"] == 1 and rows["cycle2"]["undirected_beta1"] == 0
    assert rows["filled_triangle"]["glmy_beta1"] == 0 and rows["filled_triangle"]["undirected_beta1"] == 1

"""Test the mechanized formal core (Lean 4) if Lean is available."""

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
LEAN = shutil.which("lean") or (
    str(Path.home() / ".elan" / "bin" / "lean")
    if (Path.home() / ".elan" / "bin" / "lean").exists()
    else None
)


@pytest.mark.skipif(LEAN is None, reason="Lean not installed")
def test_formal_core_compiles():
    r = subprocess.run(
        [LEAN, str(ROOT / "formal" / "Valen.lean")],
        capture_output=True, text=True, timeout=600,
    )
    assert r.returncode == 0, r.stderr

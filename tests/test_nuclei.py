"""Tests for nuclei integration and the full attack plan."""

import json
import subprocess
import sys
from pathlib import Path

from valen.redteam.nuclei import build_nuclei_args, parse_nuclei_json, to_plan_steps
from valen.redteam.stealth import PRESETS

ROOT = Path(__file__).resolve().parent.parent
NUCLEI = (ROOT / "examples" / "recon" / "nuclei.jsonl").read_text()


def test_parse_nuclei_json():
    findings = parse_nuclei_json(NUCLEI)
    assert len(findings) == 4
    high = [f for f in findings if f["severity"] == "high"]
    assert high and high[0]["template_id"] == "CVE-2021-41773"
    assert high[0]["tactic_id"] == "TA0002"


def test_to_plan_steps_tagged():
    steps = to_plan_steps(parse_nuclei_json(NUCLEI))
    assert any(s["tactic_id"] == "TA0002" for s in steps)   # rce/code-exec
    assert any(s["tactic_id"] == "TA0006" for s in steps)   # sql/credential


def test_build_nuclei_args_stealth():
    args = build_nuclei_args(["http://x"], PRESETS["sneaky"])
    assert args[0] == "nuclei"
    assert "-silent" in args and "-jsonl" in args and "-rate-limit" in args


def test_full_attack_plan_phases():
    subprocess.run(
        [sys.executable, str(ROOT / "benchmarks" / "run_attack_plan.py")],
        capture_output=True, text=True, check=True,
    )
    data = json.loads((ROOT / "benchmarks" / "attack_plan.json").read_text())
    steps = data["steps"]
    phases = {s["phase"] for s in steps}
    # the five kill-chain phases are all present
    assert phases >= {"Discovery", "Execution", "Privilege Escalation",
                      "Credential Access", "Collection"}
    # ordered by kill-chain phase
    from valen.redteam.mitre import PHASE_ORDER
    order = [PHASE_ORDER[s["tactic_id"]] for s in steps]
    assert order == sorted(order)
    # at least one step carries a PoC and one carries a Z3 witness
    assert any("poc" in s for s in steps)
    assert any("z3_reachable" in s for s in steps)

"""Tests for kill-chain/MITRE mapping and IAM escalation chains."""

import json
import subprocess
import sys
from pathlib import Path

from valen.ingest.iam import IAMIgest
from valen.redteam.attack_paths import escalation_chains, tagged_chains, z3_escalation
from valen.redteam.mitre import PHASE_ORDER, tactic_for_category, tactic_for_relation

ROOT = Path(__file__).resolve().parent.parent
IAM = ROOT / "examples" / "iam" / "demo.json"


def _graph():
    return IAMIgest().analyze(IAM.read_text()).graph


def test_tactic_mapping():
    assert tactic_for_category("idor") == ("TA0009", "Collection")
    assert tactic_for_category("command_execution") == ("TA0002", "Execution")
    assert tactic_for_category("missing_authorization") == ("TA0004", "Privilege Escalation")
    assert tactic_for_relation("assume") == ("TA0004", "Privilege Escalation")
    assert tactic_for_relation("access") == ("TA0008", "Lateral Movement")


def test_kill_chain_order_discovery_before_escalation():
    assert PHASE_ORDER["TA0007"] < PHASE_ORDER["TA0004"] < PHASE_ORDER["TA0009"]


def test_escalation_chains_found():
    g = _graph()
    chains = escalation_chains(g, ["public-api"], ["secrets-bucket", "admin-role"])
    # two escalation chains expected
    targets = {c[-1][2] for c in chains}
    assert targets == {"secrets-bucket", "admin-role"}


def test_z3_escalation_confirms_reachability():
    g = _graph()
    assert z3_escalation(g, "public-api", "admin-role")["reachable"] is True
    assert z3_escalation(g, "public-api", "secrets-bucket")["reachable"] is True
    # a target with no path from the entry is not reachable
    assert z3_escalation(g, "admin-role", "public-api")["reachable"] is False


def test_tagged_chains_carry_tactics():
    g = _graph()
    chains = tagged_chains(g, ["public-api"], ["admin-role"])
    assert chains and chains[0]["steps"][0]["tactic_id"] == "TA0004"


def test_attack_plan_generation():
    subprocess.run(
        [sys.executable, str(ROOT / "benchmarks" / "run_attack_plan.py")],
        capture_output=True, text=True, check=True,
    )
    data = json.loads((ROOT / "benchmarks" / "attack_plan.json").read_text())
    steps = data["steps"]
    # ordered by kill-chain phase
    order = [PHASE_ORDER[s["tactic_id"]] for s in steps]
    assert order == sorted(order)
    # the three phases are all present
    assert {s["phase"] for s in steps} >= {"Discovery", "Privilege Escalation", "Collection"}

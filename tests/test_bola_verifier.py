"""Tests for the Z3 BOLA/IDOR ownership-witness verifier."""

from pathlib import Path

from valen.analysis.bola_verifier import bola_witness, ownership_predicate_present, verify_bola

BOLA = Path(__file__).resolve().parent.parent / "examples" / "python" / "bola"


def _verify(name):
    return verify_bola((BOLA / name).read_text())


def test_ownership_predicate_detection():
    assert ownership_predicate_present("SELECT * FROM o WHERE id = ? AND owner = ?")
    assert ownership_predicate_present("... request.user.id ...")
    assert not ownership_predicate_present("SELECT * FROM o WHERE id = ?")


def test_violation_sat_without_ownership():
    sat, w = bola_witness(enforce_ownership=False)
    assert sat and w is not None
    assert w["owner(object_id)"] != w["session_user_id"]  # the victim's object


def test_violation_unsat_when_ownership_enforced():
    sat, w = bola_witness(enforce_ownership=True)
    assert not sat and w is None


def test_idor_vulnerable_is_bola_possible():
    assert _verify("idor_vuln.py")["verdict"] == "bola-possible"


def test_auth_gate_does_not_block_bola():
    # login_required is authentication, not object-level authorization: an
    # authenticated user can still read another user's row.
    r = _verify("idor_fixed_gate.py")
    assert r["verdict"] == "bola-possible"


def test_ownership_check_blocks_bola():
    r = _verify("idor_fixed_ownership.py")
    assert r["verdict"] == "bola-blocked"
    assert r["enforces_ownership"] is True

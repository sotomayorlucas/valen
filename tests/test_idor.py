"""Tests for active IDOR enumeration (hermetic mock fetch)."""

from valen.redteam.idor import detect_idor, enumerate_ids


def _fetch(resources):
    def f(oid):
        if oid in resources:
            return {"status": 200, "body": "", "json": resources[oid]}
        return {"status": 404, "body": "", "json": None}
    return f


def test_enumerate_ids_detects_cross_user():
    fetch = _fetch({
        "self": {"full_name": "Attacker"},
        "1": {"full_name": "Victim"},
        "2": {"full_name": "Victim"},
        "3": {"full_name": "Attacker"},
    })
    hits = enumerate_ids(fetch, ["1", "2", "3"], baseline_owner="Attacker")
    assert {h["object_id"] for h in hits} == {"1", "2"}
    assert hits[0]["evidence"] == ""


def test_detect_idor_uses_baseline():
    resources = {"0": {"full_name": "Attacker"}, "1": {"full_name": "Victim"}}
    hits = detect_idor(_fetch(resources), start=0, count=3, baseline_id="0")
    assert [h["object_id"] for h in hits] == ["1"]


def test_no_hits_when_all_same_owner():
    fetch = _fetch({"self": {"full_name": "A"}, "1": {"full_name": "A"}})
    assert enumerate_ids(fetch, ["1"], baseline_owner="A") == []

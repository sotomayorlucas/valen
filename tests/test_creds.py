"""Tests for credential recovery (potfile parsing + recording)."""

from valen.ops import build_board
from valen.redteam.creds import parse_potfile, read_hashcat_potfile, record_creds
from valen.store import Store


def test_parse_hashcat_potfile(tmp_path):
    p = tmp_path / "hashcat.potfile"
    p.write_text("$krb5tgs$23$abc:Passw0rd!\n$krb5tgs$23$def:Other123\n")
    creds = read_hashcat_potfile(str(p))
    assert creds == [
        {"hash": "$krb5tgs$23$abc", "plaintext": "Passw0rd!"},
        {"hash": "$krb5tgs$23$def", "plaintext": "Other123"},
    ]


def test_parse_potfile_missing_file(tmp_path):
    assert parse_potfile(str(tmp_path / "nope")) == []


def test_record_creds_to_store(tmp_path):
    s = Store(str(tmp_path / "d"))
    e = s.create_engagement("e1")
    n = record_creds(s, [{"hash": "h1", "plaintext": "pw1"}], engagement_id=e["id"])
    assert n == 1
    runs = s.recent_runs(kind="creds")
    assert runs[0]["adapter"] == "potfile" and "pw1" in runs[0]["summary"]
    assert record_creds(None, [{"hash": "x", "plaintext": "y"}]) == 0


def test_creds_run_maps_to_credential_access():
    board = build_board([{"kind": "creds", "name": "h1", "adapter": "potfile",
                          "summary": "recovered pw1", "engagement_id": 1, "created_at": 1.0}])
    assert board["phases"][0]["tactic_id"] == "TA0006"
    assert "T1555" in board["techniques"]


def test_creds_potfile_endpoint(tmp_path):
    from valen.server import _creds_potfile

    p = tmp_path / "pot"
    p.write_text("$krb5tgs$23$h:Secret1\n")
    out = _creds_potfile({"path": str(p)})
    assert out["credentials"] == [{"hash": "$krb5tgs$23$h", "plaintext": "Secret1"}]
    assert "error" in _creds_potfile({})

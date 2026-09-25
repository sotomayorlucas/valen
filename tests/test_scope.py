"""Scope normalization: a deep link must reduce to its origin."""

import pytest

from valen.redteam.auth import CrApiClient, normalize_scope


@pytest.mark.parametrize("raw,expected", [
    ("http://127.0.0.1:8888/login", "http://127.0.0.1:8888"),
    ("http://127.0.0.1:8888/", "http://127.0.0.1:8888"),
    ("http://127.0.0.1:8888", "http://127.0.0.1:8888"),
    ("https://x.lab:8443/path?q=1#frag", "https://x.lab:8443"),
    ("  http://host/app/identity  ", "http://host"),
])
def test_normalize_scope(raw, expected):
    assert normalize_scope(raw) == expected


@pytest.mark.parametrize("bad", ["", "127.0.0.1:8888", "ftp://x", "javascript:alert(1)", "//host"])
def test_normalize_scope_rejects_non_http(bad):
    with pytest.raises(ValueError):
        normalize_scope(bad)


def test_client_normalizes_deep_link():
    client = CrApiClient("http://127.0.0.1:8888/login")
    assert client.base_url == "http://127.0.0.1:8888"


def test_pentest_server_normalizes_scope():
    from valen.server import _pentest

    # unknown goal short-circuits before any network call
    out = _pentest({"scope": "http://127.0.0.1:8888/login", "goal": "nope"})
    assert "error" in out
    # malformed scope is rejected
    assert "error" in _pentest({"scope": "ftp://x"})


def test_pentest_warning_reported(monkeypatch, tmp_path):
    import valen.server as srv

    class _FakeAgent:
        def __init__(self, base_url, **kw):
            self.base_url = base_url

        def solve(self, c):
            return {"solved": False, "requests": 0, "seconds": 0.0, "audit": []}

    import valen.redteam.executor as ex
    monkeypatch.setattr(ex, "AutonomousAgent", _FakeAgent)
    monkeypatch.setattr(srv, "BENCH", tmp_path)  # don't touch the committed artifact
    out = srv._pentest({"scope": "http://127.0.0.1:8888/login", "goal": "ch14_unauthenticated"})
    assert out["scope"] == "http://127.0.0.1:8888"
    assert out["warning"]


def test_pentest_persists_for_report_and_console(monkeypatch, tmp_path):
    import json

    import valen.server as srv

    class _FakeAgent:
        def __init__(self, base_url, **kw):
            pass

        def solve(self, c):
            return {"challenge": c["id"], "solved": True, "requests": 1,
                    "seconds": 0.1, "audit": []}

    import valen.redteam.executor as ex
    monkeypatch.setattr(ex, "AutonomousAgent", _FakeAgent)
    monkeypatch.setattr(srv, "BENCH", tmp_path)

    out = srv._pentest({"scope": "http://127.0.0.1:8888",
                        "goal": "ch14_unauthenticated", "authorize": True})
    assert out["solved"] == 1
    saved = json.loads((tmp_path / "autopentest_results.json").read_text())
    # the shape the report + console read
    assert saved["solved"] == 1 and saved["n"] == 1
    assert saved["results"][0]["challenge"] == "ch14_unauthenticated"

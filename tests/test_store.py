"""Tests for the persistent engagement/run store and its HTTP endpoints."""

import json
import threading
import urllib.request
from http.server import ThreadingHTTPServer

from valen.server import Handler, ServerConfig
from valen.store import Store


def test_store_crud(tmp_path):
    s = Store(str(tmp_path / "data"))
    e = s.create_engagement("crAPI", client="Acme", scope="http://127.0.0.1:8888")
    assert e["id"] and e["name"] == "crAPI"
    s.record("analyze", {"findings": [{"category": "sql"}]}, engagement_id=e["id"],
             name="sqli.py", adapter="python", summary="1 finding")
    s.record("pentest", {"solved": 18, "total": 18}, engagement_id=e["id"],
             name="crAPI", summary="18/18")
    assert s.count() == {"engagements": 1, "runs": 2}
    engs = s.list_engagements()
    assert engs[0]["run_count"] == 2
    got = s.get_engagement(e["id"])
    assert len(got["runs"]) == 2
    assert got["runs"][0]["payload"]  # deserialized
    assert len(s.recent_runs()) == 2
    assert len(s.recent_runs(kind="pentest")) == 1
    s.delete_engagement(e["id"])
    assert s.count() == {"engagements": 0, "runs": 0}


def test_store_default_dir_env(monkeypatch, tmp_path):
    monkeypatch.setenv("VALEN_DATA_DIR", str(tmp_path / "d"))
    s = Store()
    assert s.dir == tmp_path / "d"


def _server(store):
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    httpd.cfg = ServerConfig(store=store)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, httpd.server_address[1]


def _req(port, path, method="GET", body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data,
                                 headers={"Content-Type": "application/json"}, method=method)
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())


def test_engagement_endpoints(tmp_path):
    httpd, port = _server(Store(str(tmp_path / "d")))
    try:
        eng = _req(port, "/api/engagements", "POST",
                   {"name": "eng1", "client": "Acme", "scope": "http://127.0.0.1:8888"})
        assert eng["name"] == "eng1"
        # analyze attached to the engagement gets recorded
        out = _req(port, "/api/analyze", "POST",
                   {"code": "def f(db, q):\n    db.execute('SELECT ' + q)\n",
                    "adapter": "python", "path": "sqli.py", "engagement_id": eng["id"]})
        assert out["findings"]
        hist = _req(port, "/api/history")
        assert hist["count"] == {"engagements": 1, "runs": 1}
        assert hist["runs"][0]["kind"] == "analyze"
        assert hist["runs"][0]["engagement_id"] == eng["id"]
        detail = _req(port, f"/api/engagements/{eng['id']}")
        assert len(detail["runs"]) == 1
        # delete
        _req(port, f"/api/engagements/{eng['id']}", "DELETE")
        assert _req(port, "/api/engagements") == []
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_store_disabled_returns_403():
    httpd, port = _server(None)
    try:
        try:
            _req(port, "/api/engagements")
            raise AssertionError("expected 403")
        except urllib.error.HTTPError as e:
            assert e.code == 403
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_artifacts_store_and_endpoint(tmp_path):
    s = Store(str(tmp_path / "d"))
    e = s.create_engagement("e1", owner_id=1)
    s.record_artifact(e["id"], "screenshot.png", kind="image", data={"note": "admin panel"})
    s.record_artifact(e["id"], "creds.txt", kind="text", data="user:pass")
    arts = s.list_artifacts(e["id"])
    assert len(arts) == 2
    assert arts[0]["kind"] == "text"  # newest first
    assert arts[1]["data"] == {"note": "admin panel"}  # JSON round-trips

    httpd, port = _server(Store(str(tmp_path / "d")))
    try:
        _req(port, f"/api/engagements/{e['id']}/artifacts", "POST",
             {"name": "loot", "kind": "note", "data": "x"})
        arts = _req(port, f"/api/engagements/{e['id']}/artifacts")
        assert len(arts) == 3
    finally:
        httpd.shutdown()
        httpd.server_close()

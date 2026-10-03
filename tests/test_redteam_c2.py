"""Tests for C2 (Sliver) integration and payload builders."""

import json

from valen.redteam.c2 import (
    c2_plan,
    generate_implant_command,
    parse_sessions,
    session_command,
    sessions_to_ir,
    start_listener_command,
)
from valen.redteam.payloads import (
    catalog,
    handler_resource,
    hta_template,
    msfvenom_command,
    payload_plan,
)

SAMPLE = json.dumps([{
    "ID": "abc123", "Name": "SLIVER-1", "Hostname": "WEB01",
    "Username": "CORP\\svc", "OperatingSystem": "windows",
    "Architecture": "amd64", "RemoteAddress": "10.0.0.9",
    "Transport": "mtls", "PID": 4242,
}])


def test_c2_command_builders():
    cmd = generate_implant_command("sess", "10.0.0.5:443")
    assert cmd[:2] == ["sliver-client", "generate"]
    assert "--mtls" in cmd and "10.0.0.5:443" in cmd
    assert start_listener_command("10.0.0.5", 443)[:3] == ["sliver-client", "mtls", "--lhost"]
    assert "use abc123" in session_command("abc123", "ls", "C:\\")[2]


def test_parse_sessions_json():
    out = parse_sessions(SAMPLE)
    assert out[0]["id"] == "abc123"
    assert out[0]["hostname"] == "WEB01"
    assert out[0]["os"] == "windows"
    assert parse_sessions("not json") == []
    assert parse_sessions("") == []


def test_sessions_to_ir():
    g = sessions_to_ir(parse_sessions(SAMPLE))
    assert g.has_node("host:WEB01")
    assert g.has_node("implant:abc123")
    assert g.node_count == 2 and g.edge_count == 1


def test_c2_plan():
    plan = c2_plan("10.0.0.5", 443)
    assert plan["listener"] and plan["implant"]


def test_payload_builder():
    cmd = msfvenom_command("10.0.0.5", 443, fmt="dll", out="x.dll")
    assert cmd[0] == "msfvenom" and "LHOST=10.0.0.5" in cmd and "LPORT=443" in cmd
    assert "-f" in cmd and "dll" in cmd
    assert len(catalog()) >= 5
    assert "multi/handler" in handler_resource("h", 1)
    assert "10.0.0.5" in hta_template("10.0.0.5", 443)
    plan = payload_plan("10.0.0.5", 443)
    assert plan["builds"] and plan["handler"]


def test_c2_endpoints():
    from valen.server import _c2_plan, _payloads

    assert _c2_plan({"lhost": "h", "lport": 1})["listener"]
    assert _payloads({"lhost": "h", "lport": 1})["builds"]
    assert "error" in _c2_plan({})


def test_save_sessions_to_store(tmp_path):
    from valen.redteam.c2 import save_sessions, parse_sessions
    from valen.store import Store

    store = Store(str(tmp_path / "d"))
    e = store.create_engagement("e1")
    n = save_sessions(store, parse_sessions(SAMPLE), engagement_id=e["id"])
    assert n == 1
    runs = store.recent_runs(kind="c2")
    assert runs and runs[0]["adapter"] == "sliver"
    assert "WEB01" in runs[0]["name"]
    assert save_sessions(None, parse_sessions(SAMPLE)) == 0


def test_sliver_client_fallback():
    from valen.redteam.c2 import SliverClient

    c = SliverClient()
    # gRPC may or may not be available; either path returns a dict with 'sessions' or 'command'
    out = c.sessions(execute=False)
    assert "sessions" in out or "command" in out or "installed" in out


def test_c2_sessions_endpoint_save(tmp_path):
    import threading
    from http.server import ThreadingHTTPServer

    from valen.events import EventBus
    from valen.server import Handler, ServerConfig
    from valen.store import Store

    store = Store(str(tmp_path / "d"))
    e = store.create_engagement("e1")
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    httpd.cfg = ServerConfig(store=store, events=EventBus())
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        import urllib.request

        port = httpd.server_address[1]
        body = json.dumps({"output": SAMPLE, "save": True, "engagement_id": e["id"]}).encode()
        req = urllib.request.Request(f"http://127.0.0.1:{port}/api/c2/sessions", data=body,
                                     headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req) as r:
            out = json.loads(r.read())
        assert out["saved"] == 1
        assert store.recent_runs(kind="c2")[0]["adapter"] == "sliver"
    finally:
        httpd.shutdown()
        httpd.server_close()

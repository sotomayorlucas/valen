"""Tests for the safe external-tool runner and the live C2/AD drivers."""

import json
import threading
import urllib.request
from http.server import ThreadingHTTPServer

from valen.redteam.ad.runner import ADRunner
from valen.redteam.c2.sliver import SliverRunner
from valen.redteam.exec import available, installed, run
from valen.redteam.agent_web import ApprovalQueue
from valen.server import Handler, ServerConfig


def test_allowlist_refuses_non_allowed():
    out = run(["echo", "hi"])
    assert "refused" in out["error"]


def test_missing_tool_reports_hint():
    out = run(["sliver-client", "sessions", "-j"])
    if available("sliver-client"):
        return  # installed on this host; nothing to assert
    assert out["installed"] is False and "hint" in out


def test_installed_has_core_tools():
    tools = installed()
    assert isinstance(tools, dict) and "nmap" in tools


def test_runs_allowlisted_installed_tool():
    if not available("nmap"):
        return
    out = run(["nmap", "--version"])
    assert out["ok"] is True and out["code"] == 0


def test_sliver_runner_dry_and_live():
    r = SliverRunner()
    dry = r.sessions(execute=False)
    assert dry.get("command") and dry.get("note") == "dry-run"
    if not r.available():
        live = r.sessions(execute=True)
        assert live.get("installed") is False
    assert r.listener("10.0.0.5", 443)["command"][:2] == ["sliver-client", "mtls"]


def test_ad_runner_dry_and_live():
    r = ADRunner()
    dry = r.kerberoast("CORP.LOCAL", "10.0.0.1", "u", "p", execute=False)
    assert dry["command"][0] == "impacket-GetUserSPNs" and "dry-run" in dry["note"]
    if not available("impacket-GetUserSPNs"):
        live = r.kerberoast("CORP.LOCAL", "10.0.0.1", "u", "p", execute=True)
        assert live.get("installed") is False
    assert r.tools()  # subset dict


def _server(**cfg):
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    httpd.cfg = ServerConfig(**cfg)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, httpd.server_address[1]


def _req(port, path, method="GET", body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data,
                                 headers={"Content-Type": "application/json"}, method=method)
    with urllib.request.urlopen(req) as r:
        return r.status, json.loads(r.read())


def test_exec_tools_endpoint():
    httpd, port = _server(allow_exec=True)
    try:
        _, out = _req(port, "/api/exec/tools")
        assert out["allow_exec"] is True and "tools" in out
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_agent_execute_path_degrades_gracefully():
    httpd, port = _server(approvals=ApprovalQueue(), allow_exec=True)
    try:
        ctx = {"target": "http://127.0.0.1:8888", "services": [443]}
        _, out = _req(port, "/api/agent/propose", "POST", {"context": ctx})
        intr = next(a for a in out["proposed"] if a["tier"] == "intrusive")
        _, dec = _req(port, "/api/agent/decide", "POST",
                      {"id": intr["id"], "approve": True, "authorize": True, "execute": True})
        # C2 implant command uses sliver-client; if absent, execution reports it
        assert "execution" in dec
        assert dec["execution"].get("installed") is False or dec["execution"].get("ok") is True
    finally:
        httpd.shutdown()
        httpd.server_close()

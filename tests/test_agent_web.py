"""Tests for the hybrid web-pentest agent (planner + approval queue + API)."""

import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from valen.redteam.agent_web import ApprovalQueue, plan_actions
from valen.server import Handler, ServerConfig

CTX = {
    "target": "http://127.0.0.1:8888",
    "services": [80, 443],
    "findings": [{"category": "sql"}, {"category": "idor"}],
    "path": "/api/report",
    "method": "GET",
    "id_params": ["report_id"],
}


def test_plan_actions_cover_phases():
    acts = plan_actions(CTX)
    techniques = {a["technique"] for a in acts}
    assert "T1083" in techniques          # enum
    assert "T1190" in techniques          # exploit (sqlmap)
    assert any(a["tier"] == "intrusive" for a in acts)


def test_plan_recon_when_no_services():
    acts = plan_actions({"target": "http://x"})
    assert any(a["technique"] == "T1046" for a in acts)


def test_queue_approval_gating():
    q = ApprovalQueue()
    created = q.propose(CTX, engagement_id=7)
    assert all(a.engagement_id == 7 for a in created)
    assert len(q.list(engagement_id=7, status="pending")) == len(created)
    bounded = next(a for a in created if a.tier == "bounded")
    out = q.decide(bounded.id, approve=True)
    assert out["status"] == "approved" and out["command"]
    intrusive = next(a for a in created if a.tier == "intrusive")
    assert "error" in q.decide(intrusive.id, approve=True)          # needs authorize
    assert q.decide(intrusive.id, approve=True, authorize=True)["status"] == "approved"
    # double-decide rejected
    assert "error" in q.decide(bounded.id, approve=False)


def _server(**cfg):
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    httpd.cfg = ServerConfig(**cfg)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, httpd.server_address[1]


def _req(port, path, method="GET", body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data,
                                 headers={"Content-Type": "application/json"}, method=method)
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_agent_endpoints():
    httpd, port = _server(approvals=ApprovalQueue(), allow_exec=True)
    try:
        code, out = _req(port, "/api/agent/propose", "POST",
                         {"context": CTX, "engagement_id": 1})
        assert code == 200 and out["proposed"]
        aid = out["proposed"][0]["id"]
        code, lst = _req(port, "/api/agent/actions?engagement_id=1&status=pending")
        assert code == 200 and any(a["id"] == aid for a in lst)
        code, dec = _req(port, "/api/agent/decide", "POST", {"id": aid, "approve": True})
        assert code == 200 and dec["status"] == "approved"
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_agent_intrusive_requires_allow_exec():
    # allow_exec False -> approving an intrusive action is rejected
    httpd, port = _server(approvals=ApprovalQueue(), allow_exec=False)
    try:
        _, out = _req(port, "/api/agent/propose", "POST", {"context": CTX})
        intr = next(a for a in out["proposed"] if a["tier"] == "intrusive")
        code, dec = _req(port, "/api/agent/decide", "POST",
                         {"id": intr["id"], "approve": True, "authorize": True})
        assert code == 403 and "error" in dec
    finally:
        httpd.shutdown()
        httpd.server_close()

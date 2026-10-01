"""Tests for the crAPI lab reset helper + the /api/lab/reset endpoint gate."""

import json
import threading
import urllib.request
from http.server import ThreadingHTTPServer

from valen.redteam.lab import reset_lab
from valen.server import Handler, ServerConfig, _lab_reset


def test_reset_requires_authorize():
    out = _lab_reset({})
    assert "error" in out and "authorize" in out["error"]


def test_reset_rejects_bad_scope():
    out = _lab_reset({"authorize": True, "scope": "ftp://x"})
    assert "error" in out


def test_reset_missing_compose_dir():
    out = reset_lab(compose="/nonexistent/path", scope="http://127.0.0.1:8888", timeout=1)
    assert out["ok"] is False
    assert "docker-compose.yml" in out["error"]
    assert "hint" in out


def test_lab_reset_route_gate_ephemeral_port():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    httpd.cfg = ServerConfig(allow_exec=True)  # pass the exec gate to reach the authorize check
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        body = json.dumps({}).encode()  # no authorize
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/lab/reset", data=body,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req) as r:
            out = json.loads(r.read())
        assert "authorize" in out.get("error", "")
    finally:
        httpd.shutdown()
        httpd.server_close()

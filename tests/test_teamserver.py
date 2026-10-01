"""End-to-end tests for the multi-user team server (auth + RBAC + SSE)."""

import json
import socket
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from valen.authz import Authz
from valen.events import EventBus
from valen.server import Handler, ServerConfig
from valen.store import Store


def _team(tmp_path):
    az = Authz(str(tmp_path / "d"))
    store = Store(str(tmp_path / "d"))
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    httpd.cfg = ServerConfig(authz=az, store=store, events=EventBus(), allow_exec=True)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, httpd.server_address[1], az


def _req(port, path, method="GET", body=None, token=None):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data,
                                 headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except Exception:
            return e.code, {}


def test_requires_login(tmp_path):
    httpd, port, az = _team(tmp_path)
    try:
        code, _ = _req(port, "/api/adapters")
        assert code == 401
        code, _ = _req(port, "/api/health")
        assert code == 200
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_login_and_me(tmp_path):
    httpd, port, az = _team(tmp_path)
    try:
        az.create_user("admin", "passw0rd123", "admin")
        code, out = _req(port, "/api/login", "POST",
                         {"username": "admin", "password": "passw0rd123"})
        assert code == 200 and out["token"]
        token = out["token"]
        code, me = _req(port, "/api/me", token=token)
        assert code == 200 and me["username"] == "admin" and me["role"] == "admin"
        # bad creds
        code, _ = _req(port, "/api/login", "POST",
                       {"username": "admin", "password": "nope"})
        assert code == 401
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_viewer_rbac(tmp_path):
    httpd, port, az = _team(tmp_path)
    try:
        az.create_user("viewer", "passw0rd123", "viewer")
        _, out = _req(port, "/api/login", "POST",
                      {"username": "viewer", "password": "passw0rd123"})
        tok = out["token"]
        # viewer can read
        assert _req(port, "/api/adapters", token=tok)[0] == 200
        # viewer cannot execute or manage users
        assert _req(port, "/api/pentest", "POST", {"scope": "http://127.0.0.1:8888"}, token=tok)[0] == 403
        assert _req(port, "/api/users", token=tok)[0] == 403
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_admin_manages_users(tmp_path):
    httpd, port, az = _team(tmp_path)
    try:
        az.create_user("admin", "passw0rd123", "admin")
        _, out = _req(port, "/api/login", "POST",
                      {"username": "admin", "password": "passw0rd123"})
        tok = out["token"]
        code, user = _req(port, "/api/users", "POST",
                          {"username": "ops", "password": "passw0rd123", "role": "operator"},
                          token=tok)
        assert code == 200 and user["role"] == "operator"
        _, users = _req(port, "/api/users", token=tok)
        assert {u["username"] for u in users} == {"admin", "ops"}
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_engagement_scoped_to_user(tmp_path):
    httpd, port, az = _team(tmp_path)
    try:
        az.create_user("admin", "passw0rd123", "admin")
        _, out = _req(port, "/api/login", "POST",
                      {"username": "admin", "password": "passw0rd123"})
        tok = out["token"]
        _, eng = _req(port, "/api/engagements", "POST", {"name": "e1"}, token=tok)
        _, lst = _req(port, "/api/engagements", token=tok)
        assert any(e["id"] == eng["id"] for e in lst)
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_events_sse(tmp_path):
    httpd, port, az = _team(tmp_path)
    try:
        az.create_user("admin", "passw0rd123", "admin")
        _, out = _req(port, "/api/login", "POST",
                      {"username": "admin", "password": "passw0rd123"})
        tok = out["token"]
        # open SSE and read the opening frames
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        s.sendall(f"GET /api/events HTTP/1.1\r\nHost: x\r\n"
                  f"Authorization: Bearer {tok}\r\nConnection: close\r\n\r\n".encode())
        buf = s.recv(1024).decode(errors="replace")
        s.close()
        assert "200" in buf.split("\r\n", 1)[0]
        assert "text/event-stream" in buf
    finally:
        httpd.shutdown()
        httpd.server_close()

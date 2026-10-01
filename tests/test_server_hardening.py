"""Trust-boundary tests for the local server (Phase B hardening)."""

import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from valen.server import Handler, ServerConfig


def _server(**cfg):
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    httpd.cfg = ServerConfig(**cfg)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, port


def _req(port, path, method="GET", body=None, token=None, raw=False):
    data = None
    if body is not None:
        data = body.encode() if raw else json.dumps(body).encode()
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data,
                                 headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def _with(httpd, fn):
    try:
        return fn()
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_token_required_on_api():
    httpd, port = _server(token="s3cr3t")
    try:
        code, _ = _req(port, "/api/adapters")
        assert code == 401
        code, _ = _req(port, "/api/adapters", token="s3cr3t")
        assert code == 200
        # token can also be supplied as a query param (remote clients)
        code, _ = _req(port, "/api/adapters?token=s3cr3t")
        assert code == 200
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_token_injected_into_page_for_loopback():
    httpd, port = _server(token="s3cr3t")
    try:
        code, body = _req(port, "/")
        assert code == 200
        text = body.decode()
        assert "__VALEN_TOKEN__" not in text
        assert "s3cr3t" in text
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_no_token_page_has_empty_placeholder():
    httpd, port = _server()
    try:
        _, body = _req(port, "/")
        assert "__VALEN_TOKEN__" not in body.decode()
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_allow_exec_gate_dynamic():
    httpd, port = _server()
    try:
        code, body = _req(port, "/api/dynamic", "POST", {"code": "x=1", "adapter": "c"})
        assert code == 403
        assert b"allow-exec" in body
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_allow_exec_gate_lab_reset():
    httpd, port = _server()
    try:
        code, _ = _req(port, "/api/lab/reset", "POST", {"authorize": True})
        assert code == 403
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_ssrf_guard_blocks_non_loopback_scope():
    httpd, port = _server()
    try:
        code, body = _req(port, "/api/pentest", "POST",
                          {"scope": "http://10.0.0.5:8888", "goal": "ch14_unauthenticated"})
        assert code == 403
        assert b"allow-host" in body
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_ssrf_guard_allows_loopback():
    httpd, port = _server()
    try:
        # unknown goal short-circuits before any network call, so no lab needed
        code, _ = _req(port, "/api/pentest", "POST",
                       {"scope": "http://127.0.0.1:8888", "goal": "nope"})
        assert code == 200
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_body_size_limit():
    httpd, port = _server(max_body=16)
    try:
        code, body = _req(port, "/api/cvss", "POST",
                          {"vector": "CVSS:3.1/" + "A" * 200})
        assert code == 413
        assert b"too large" in body
    finally:
        httpd.shutdown()
        httpd.server_close()

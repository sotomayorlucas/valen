"""Tests for the VALEN web server."""

import json
import threading
import urllib.request
from http.server import ThreadingHTTPServer

from valen.server import Handler, _analyze, _compare, _example_index, _read_example, _results


def test_analyze_python_offline():
    out = _analyze({
        "code": "def f(db, q):\n    db.execute('SELECT ' + q)\n",
        "adapter": "python",
        "verify": True,
        "agent": True,
    })
    assert out["adapter"] == "python"
    assert out["findings"]
    assert "nodes" in out and "edges" in out
    assert isinstance(out.get("verifications", []), list)


def test_analyze_java_via_api():
    out = _analyze({
        "code": "class T { void f(HttpServletRequest r, java.sql.Statement s){"
                " String p=r.getParameter(\"x\"); s.executeQuery(\"SELECT \"+p);} }",
        "adapter": "java",
        "verify": True,
    })
    assert out["findings"]
    assert out.get("verifications")


def test_examples_and_results():
    ex = _example_index()
    assert any(e["name"].endswith("sqli.py") for e in ex)
    sample = _read_example(ex[0]["name"])
    assert "code" in sample
    res = _results()
    assert set(res.keys()) >= {"oracle", "owasp", "ablation", "scale"}


def test_analyze_includes_topology():
    out = _analyze({"code": "def a():\n    b()\ndef b():\n    a()\n", "adapter": "python"})
    assert "topology" in out
    topo = out["topology"]
    assert topo["undirected_beta1"] is not None
    assert topo["directed_beta1"] is not None


def test_compare_resolves_vulnerability():
    out = _compare({
        "vulnerable": "def f(db, q):\n    db.execute('SELECT ' + q)\n",
        "patched": "def f(db, q):\n    db.execute('SELECT %s', (q,))\n",
        "adapter": "python",
    })
    assert out["vulnerable"]["findings"]
    assert not out["patched"]["findings"]
    assert out["diff"]["resolved"]           # the sqli finding was resolved
    assert out["diff"]["introduced"] == []


def test_http_roundtrip_ephemeral_port():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/examples") as r:
            assert r.status == 200
            assert isinstance(json.loads(r.read()), list)

        body = json.dumps({"code": "def f(db, q):\n    db.execute('SELECT ' + q)\n",
                           "adapter": "python"}).encode()
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/analyze", data=body,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req) as r:
            out = json.loads(r.read())
        assert out["findings"]
    finally:
        httpd.shutdown()
        httpd.server_close()

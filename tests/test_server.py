"""Tests for the VALEN web server."""

import json
import threading
import urllib.request
from http.server import ThreadingHTTPServer

from valen.server import (
    Handler,
    _adapters,
    _analyze,
    _challenges,
    _compare,
    _dynamic,
    _example_index,
    _pentest,
    _read_example,
    _results,
    _viz,
)


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

        # new endpoints reachable
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/adapters") as r:
            names = {a["name"] for a in json.loads(r.read())}
        assert {"python", "java", "c", "rust"} <= names

        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/challenges") as r:
            ch = json.loads(r.read())
        assert len(ch) == 18

        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/viz", data=body,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req) as r:
            assert r.headers.get_content_type() == "text/html"
            assert b"VALEN" in r.read()
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_adapters_include_new_languages():
    names = {a["name"] for a in _adapters()}
    assert {"c", "cpp", "rust", "csharp", "go", "php", "ruby",
            "javascript", "java", "python"} <= names


def test_examples_include_multilang():
    names = {e["name"] for e in _example_index()}
    assert any(n.endswith(".c") for n in names)
    assert any(n.endswith(".rs") for n in names)
    assert any(n.endswith(".php") for n in names)
    assert any(n.endswith(".java") for n in names)


def test_challenges_registry():
    ch = _challenges()
    assert len(ch) == 18
    assert ch[0]["id"].startswith("ch")


def test_viz_returns_html():
    html = _viz({"code": "def f(db, q):\n    db.execute('SELECT ' + q)\n",
                 "adapter": "python"})
    assert html.lstrip().startswith("<!doctype html>")
    assert "VALEN" in html


def test_dynamic_python_ok():
    code = ("import sys\n"
            "def f(db, q):\n"
            "    db.execute('SELECT ' + q)\n"
            "if __name__ == '__main__':\n"
            "    pass\n")
    out = _dynamic({"code": code, "argv": ["x"], "timeout": 15})
    assert "error" not in out
    assert "coverage" in out and "agreement" in out
    assert out["exit_code"] == 0


def test_dynamic_rejects_non_python():
    out = _dynamic({"code": "int main(){}", "adapter": "c"})
    assert "error" in out and "python" in out["error"]


def test_pentest_validation():
    assert "error" in _pentest({})
    assert "http" in _pentest({"scope": "ftp://x"})["error"]
    assert "unknown" in _pentest({"scope": "http://127.0.0.1:1",
                                  "goal": "nope"})["error"]

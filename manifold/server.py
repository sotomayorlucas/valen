"""Web server for MANIFOLD (Python standard library only).

    python -m manifold.server --port 8000
    # open http://127.0.0.1:8000

Endpoints:
    GET  /                 the single-page UI
    GET  /api/examples     list bundled examples
    GET  /api/example      ?name=... -> {name, adapter, code}
    GET  /api/results      experiment artifacts (oracle/owasp/ablation/scale)
    POST /api/analyze      {code, path?, adapter?, verify?, agent?} -> results

The analysis is fully static: user code is parsed (tree-sitter), reasoned over,
and (for the Rust kernels) passed as JSON to a subprocess. It is never executed.
"""

from __future__ import annotations

import argparse
import csv
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import parse_qs, urlparse

from .analysis.field import vulnerability_field
from .analysis.math_core import run_core
from .ingest import analyze, infer_adapter
from .viz import _edge_data, _node_data
from .webui import PAGE

ROOT = Path(__file__).resolve().parent.parent
BENCH = ROOT / "benchmarks"
EXAMPLES = ROOT / "examples"


# --------------------------------------------------------------------------
def _example_index() -> List[Dict[str, str]]:
    out = []
    for source in sorted(EXAMPLES.rglob("*")):
        if source.is_file() and source.suffix in (".py", ".json", ".asm"):
            rel = str(source.relative_to(EXAMPLES))
            out.append({"name": rel, "adapter": infer_adapter(source.read_text(), source.name)})
    return out


def _read_example(name: str) -> Dict[str, str]:
    # prevent path traversal
    path = (EXAMPLES / name).resolve()
    if not str(path).startswith(str(EXAMPLES.resolve())) or not path.is_file():
        raise ValueError("unknown example")
    code = path.read_text()
    return {"name": name, "adapter": infer_adapter(code, path.name), "code": code}


def _analyze(payload: Dict[str, Any]) -> Dict[str, Any]:
    code = payload.get("code", "") or ""
    path = payload.get("path") or "<web>"
    adapter = payload.get("adapter") or infer_adapter(code, path)
    if adapter == "angr-binary":
        result = analyze("", path=path, adapter="angr-binary")
    else:
        result = analyze(code, path=path, adapter=adapter)

    try:
        math = run_core(result.graph)
        nodes = _node_data(result.graph, math)
    except Exception:
        math, nodes = None, _node_data(result.graph, None)
    edges = _edge_data(result.graph)

    field_map = vulnerability_field(result.graph, math=math, findings=result.findings) if math else {}
    labels = {n.id: n.label for n in result.graph.nodes}
    top = sorted(field_map.items(), key=lambda kv: -kv[1])[:12]

    out: Dict[str, Any] = {
        "adapter": adapter,
        "nodes": nodes,
        "edges": edges,
        "findings": [f.to_dict() for f in result.findings],
        "top": [{"id": k, "label": labels.get(k, ""), "value": round(v, 4)} for k, v in top],
    }

    if math:
        t = math.get("topology", {}).get("call", {})
        dp = t.get("directed_path", {})
        out["topology"] = {
            "undirected_beta0": t.get("beta0"),
            "undirected_beta1": t.get("beta1"),
            "directed_beta0": dp.get("beta0"),
            "directed_beta1": dp.get("beta1"),
        }

    if payload.get("verify"):
        try:
            if adapter == "python":
                from .analysis.verifier import verify

                out["verifications"] = [v.to_dict() for v in verify(code, path=path)]
            elif adapter == "java":
                from .analysis.java_verifier import verify_java

                out["verifications"] = [
                    {"sink_name": v.sink_name, "category": v.category, "severity": v.severity,
                     "line": v.line, "witness": v.witness, "sources": v.sources}
                    for v in verify_java(code, path=path)
                ]
        except Exception as exc:  # pragma: no cover
            out["verify_error"] = str(exc)

    if payload.get("agent") and adapter == "python":
        try:
            from agent.agent import ManifoldAgent

            report = ManifoldAgent().run(code, path=path)
            out["agent"] = [e.to_dict() for e in report.entries]
        except Exception as exc:
            out["agent_error"] = str(exc)

    return out


def _read_scale() -> List[dict]:
    path = BENCH / "scale_results.csv"
    if not path.exists():
        return []
    rows = []
    with path.open() as f:
        for row in csv.reader(f):
            if len(row) != 4 or row[0] == "kernel" or row[3] in ("", "NA"):
                continue
            rows.append({"kernel": row[0], "edges": int(row[1]), "nodes": int(row[2]), "ms": float(row[3])})
    return rows


def _compare(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze a vulnerable/patched pair and diff their findings."""
    vuln_code = payload.get("vulnerable", "") or ""
    patched_code = payload.get("patched", "") or ""
    path = payload.get("path") or "<web>"
    adapter = payload.get("adapter") or infer_adapter(vuln_code, path)

    def run(code: str) -> Dict[str, Any]:
        return _analyze({"code": code, "path": path, "adapter": adapter,
                         "verify": payload.get("verify")})

    vuln, patched = run(vuln_code), run(patched_code)

    def keys(out: Dict[str, Any]) -> set:
        return {(f["category"], f["sink_name"]) for f in out["findings"]}

    vk, pk = keys(vuln), keys(patched)
    return {
        "adapter": adapter,
        "vulnerable": vuln,
        "patched": patched,
        "diff": {
            "resolved": sorted([list(k) for k in vk - pk]),
            "introduced": sorted([list(k) for k in pk - vk]),
            "persisting": sorted([list(k) for k in vk & pk]),
        },
    }


def _results() -> Dict[str, Any]:
    def j(name):
        p = BENCH / name
        return json.loads(p.read_text()) if p.exists() else {}

    return {
        "oracle": j("oracle_results.json"),
        "owasp": j("owasp_results.json"),
        "ablation": j("ablation_results.json"),
        "cves": j("cve_results.json"),
        "scale": _read_scale(),
    }


# --------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    server_version = "manifold/0.1"

    def log_message(self, *args):  # quieter
        pass

    def _send(self, code: int, body: str, ctype: str = "application/json; charset=utf-8") -> None:
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _json(self, obj: Any, code: int = 200) -> None:
        self._send(code, json.dumps(obj))

    def do_GET(self) -> None:  # noqa: N802
        u = urlparse(self.path)
        if u.path in ("/", "/index.html"):
            return self._send(200, PAGE, "text/html; charset=utf-8")
        if u.path == "/api/examples":
            return self._json(_example_index())
        if u.path == "/api/example":
            name = parse_qs(u.query).get("name", [""])[0]
            try:
                return self._json(_read_example(name))
            except ValueError as exc:
                return self._json({"error": str(exc)}, 404)
        if u.path == "/api/results":
            return self._json(_results())
        if u.path == "/api/cves":
            p = BENCH / "cve_pairs.json"
            return self._json(json.loads(p.read_text()) if p.exists() else [])
        return self._json({"error": "not found"}, 404)

    def do_POST(self) -> None:  # noqa: N802
        u = urlparse(self.path)
        if u.path not in ("/api/analyze", "/api/compare"):
            return self._json({"error": "not found"}, 404)
        length = int(self.headers.get("Content-Length", "0"))
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return self._json({"error": "invalid JSON body"}, 400)
        try:
            if u.path == "/api/compare":
                return self._json(_compare(payload))
            return self._json(_analyze(payload))
        except Exception as exc:
            return self._json({"error": str(exc)}, 500)


def serve(host: str = "127.0.0.1", port: int = 8000) -> None:
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"MANIFOLD web UI  ->  http://{host}:{port}  (Ctrl+C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


def main() -> int:
    ap = argparse.ArgumentParser(description="MANIFOLD web UI (stdlib server).")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8000)
    args = ap.parse_args()
    serve(args.host, args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

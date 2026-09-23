"""Web server for VALEN (Python standard library only).

    python -m valen.server --port 8000
    # open http://127.0.0.1:8000

Endpoints:
    GET  /                 the single-page UI
    GET  /api/adapters     supported analysis adapters
    GET  /api/examples     list bundled examples
    GET  /api/example      ?name=... -> {name, adapter, code}
    GET  /api/results      experiment artifacts (oracle/owasp/ablation/scale)
    GET  /api/challenges   crAPI challenge ids (for the pentest panel)
    POST /api/analyze      {code, path?, adapter?, verify?, agent?} -> results
    POST /api/compare      {vulnerable, patched, adapter?} -> diff
    POST /api/viz          {code, path?, adapter?} -> text/html valen document
    POST /api/dynamic      {code, path?, argv?, timeout?} -> sandboxed run + triangulation (python)
    POST /api/pentest      {scope, goal?, authorize?, profile?, max_requests?} -> engagement results
    POST /api/validate     BOLA/IDOR live replay (authorized)
    POST /api/recon        stealth tool command builder

The analysis is fully static: user code is parsed (tree-sitter), reasoned over,
and (for the Rust kernels) passed as JSON to a subprocess. It is never executed.
``/api/dynamic`` is the explicit exception: it writes the posted python code to
a temp file and runs it under the sandboxed tracer (``valen.dynamic``).
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
from .console import build_console
from .ingest import analyze, infer_adapter
from .viz import _edge_data, _node_data
from .webui import PAGE

ROOT = Path(__file__).resolve().parent.parent
BENCH = ROOT / "benchmarks"
EXAMPLES = ROOT / "examples"

_SOURCE_EXTS = (
    ".py", ".json", ".asm", ".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".hh", ".hxx",
    ".rs", ".cs", ".go", ".php", ".rb", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx",
    ".java", ".yaml", ".yml", ".xml", ".sol",
)


# --------------------------------------------------------------------------
def _adapters() -> List[Dict[str, str]]:
    from .ingest import LANGUAGE_TO_INGEST

    out = []
    for name, cls in sorted(LANGUAGE_TO_INGEST.items()):
        out.append({"name": name, "class": cls.__name__})
    return out


def _example_index() -> List[Dict[str, str]]:
    out = []
    for source in sorted(EXAMPLES.rglob("*")):
        if source.is_file() and source.suffix in _SOURCE_EXTS:
            rel = str(source.relative_to(EXAMPLES))
            out.append({"name": rel, "adapter": infer_adapter(source.read_text(errors="replace"), source.name)})
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
            from agent.agent import ValenAgent

            report = ValenAgent().run(code, path=path)
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
        "llm": j("llm_results.json"),
        "scale": _read_scale(),
    }


def _redteam() -> Dict[str, Any]:
    from .console import collect

    return collect()


def _validate(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Replay a BOLA/IDOR plan against a live target (authorized engagements)."""
    from .redteam.live import LiveValidator

    base_url = payload.get("base_url", "")
    if not base_url:
        return {"error": "base_url required"}
    v = LiveValidator(base_url, timeout=float(payload.get("timeout", 5.0)))
    return v.check(
        payload.get("method", "GET"),
        payload.get("path", ""),
        payload.get("id_params", []),
        payload.get("victim_id", ""),
        payload.get("token", ""),
        payload.get("leak_hint", ""),
    )


def _recon(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Build stealth tool commands (does NOT execute; the operator runs them)."""
    from .redteam.stealth import PRESETS, StealthProfile, build_masscan_args, build_nmap_args

    targets = payload.get("targets") or ["<scope>"]
    ports = payload.get("ports") or "1-1000"
    profile = PRESETS.get(payload.get("profile", "sneaky"), PRESETS["sneaky"])
    return {
        "profile": profile.name,
        "nmap": build_nmap_args(profile, targets, ports, payload.get("extra")),
        "masscan": build_masscan_args(profile, targets, ports),
        "note": "run these against an authorized scope, then feed the output to /api/recon ingestion",
    }


def _viz(payload: Dict[str, Any]) -> str:
    """Render the interactive valen HTML document (same as CLI ``--viz``)."""
    from .analysis.math_core import run_core
    from .viz import render_html

    code = payload.get("code", "") or ""
    path = payload.get("path") or "<web>"
    adapter = payload.get("adapter") or infer_adapter(code, path)
    if adapter == "angr-binary":
        result = analyze("", path=path, adapter="angr-binary")
    else:
        result = analyze(code, path=path, adapter=adapter)
    try:
        math = run_core(result.graph)
    except Exception:
        math = None
    return render_html(
        result.graph,
        math,
        None,
        title="VALEN",
        subtitle=f"{path} ({adapter}) — {result.graph.node_count} nodes, "
                 f"{result.graph.edge_count} edges",
    )


def _dynamic(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Sandboxed dynamic run + triangulation (CLI ``--dynamic``, python only)."""
    import tempfile

    from .dynamic import run_module, triangulate

    code = payload.get("code", "") or ""
    path = payload.get("path") or "<web>"
    adapter = payload.get("adapter") or infer_adapter(code, path)
    if adapter != "python":
        return {"error": "--dynamic is only supported for python targets "
                         f"(got {adapter!r})"}

    argv = payload.get("argv")
    if isinstance(argv, str):
        argv = argv.split()
    timeout = float(payload.get("timeout", 30.0))

    result = analyze(code, path=path, adapter="python")
    with tempfile.NamedTemporaryFile(
        "w", suffix=".py", prefix="valen-dyn-", delete=False
    ) as fh:
        fh.write(code)
        target = fh.name
    try:
        dyn = run_module(target, argv=argv, timeout=timeout)
    except Exception as exc:  # noqa: BLE001
        return {"error": f"dynamic run failed: {exc}"}
    finally:
        try:
            Path(target).unlink()
        except OSError:
            pass

    report = triangulate(result, dyn)
    report["static_findings"] = [f.to_dict() for f in result.findings]
    return report


def _challenges() -> List[Dict[str, str]]:
    from .redteam.challenges import CHALLENGES

    return [
        {"id": cid, "goal": str(c.get("goal", ""))[:200]}
        for cid, c in CHALLENGES.items()
    ]


def _pentest(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Autonomous red-team engagement (CLI ``valen pentest``)."""
    from .redteam.challenges import CHALLENGES
    from .redteam.executor import AutonomousAgent

    scope = (payload.get("scope") or "").rstrip("/")
    if not scope:
        return {"error": "scope required (target base URL, authorized scope)"}
    if not scope.startswith(("http://", "https://")):
        return {"error": "scope must be an http(s) base URL"}

    goal = payload.get("goal") or "all"
    authorize = bool(payload.get("authorize"))
    max_requests = int(payload.get("max_requests", 40))
    profile = payload.get("profile", "sneaky")

    if goal != "all" and goal not in CHALLENGES:
        return {"error": f"unknown challenge {goal!r}",
                "challenges": list(CHALLENGES)}

    ids = [goal] if goal != "all" else list(CHALLENGES)
    results = []
    for cid in ids:
        c = dict(CHALLENGES[cid])
        c["id"] = cid
        agent = AutonomousAgent(scope, authorize=authorize, max_steps=max_requests)
        r = agent.solve(c)
        r["challenge"] = cid
        results.append(r)

    solved = sum(1 for r in results if r.get("solved"))
    return {
        "scope": scope,
        "profile": profile,
        "authorize": authorize,
        "challenges": results,
        "solved": solved,
        "total": len(results),
    }


# --------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    server_version = "valen/0.1"

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
        if u.path == "/api/adapters":
            return self._json(_adapters())
        if u.path == "/api/challenges":
            return self._json(_challenges())
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
        if u.path == "/console":
            return self._send(200, build_console(), "text/html; charset=utf-8")
        if u.path == "/api/redteam":
            return self._json(_redteam())
        return self._json({"error": "not found"}, 404)

    def do_POST(self) -> None:  # noqa: N802
        u = urlparse(self.path)
        allowed = ("/api/analyze", "/api/compare", "/api/validate",
                   "/api/recon", "/api/viz", "/api/dynamic", "/api/pentest")
        if u.path not in allowed:
            return self._json({"error": "not found"}, 404)
        length = int(self.headers.get("Content-Length", "0"))
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return self._json({"error": "invalid JSON body"}, 400)
        try:
            if u.path == "/api/compare":
                return self._json(_compare(payload))
            if u.path == "/api/validate":
                return self._json(_validate(payload))
            if u.path == "/api/recon":
                return self._json(_recon(payload))
            if u.path == "/api/pentest":
                return self._json(_pentest(payload))
            if u.path == "/api/dynamic":
                return self._json(_dynamic(payload))
            if u.path == "/api/viz":
                return self._send(200, _viz(payload), "text/html; charset=utf-8")
            return self._json(_analyze(payload))
        except Exception as exc:
            return self._json({"error": str(exc)}, 500)


def serve(host: str = "127.0.0.1", port: int = 8000) -> None:
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"VALEN web UI  ->  http://{host}:{port}  (Ctrl+C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


def main() -> int:
    ap = argparse.ArgumentParser(description="VALEN web UI (stdlib server).")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8000)
    args = ap.parse_args()
    serve(args.host, args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

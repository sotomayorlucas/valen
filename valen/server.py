"""Web server for VALEN (Python standard library only).

    python -m valen.server --port 8000
    # open http://127.0.0.1:8000

Endpoints:
    GET  /                 the single-page UI
    GET  /api/adapters     supported analysis adapters
    GET  /api/categories   vulnerability category registry (CWE/OWASP/CVSS/MITRE)
    GET  /api/examples     list bundled examples
    GET  /api/example      ?name=... -> {name, adapter, code}
    GET  /api/results      experiment artifacts (oracle/owasp/ablation/scale)
    GET  /api/challenges   crAPI challenge ids (for the pentest panel)
    POST /api/analyze      {code, path?, adapter?, verify?, agent?} -> results
    POST /api/compare      {vulnerable, patched, adapter?} -> diff
    POST /api/viz          {code, path?, adapter?} -> text/html valen document
    POST /api/dynamic      {code, path?, argv?, timeout?} -> sandboxed run + triangulation (python)
    POST /api/pentest      {scope, goal?, authorize?, profile?, max_requests?} -> engagement results
    POST /api/report       {format?, engagement?, ...} -> report in html|md|json|sarif
    GET  /api/report/download ?format=html|md|json|sarif|pdf -> generated artifact
    POST /api/cvss         {vector} or {category} -> {vector, score, severity}
    GET  /api/cve          ?q=CVE-... | ?product=...&version=... -> CVE intelligence
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
import sys
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


def _report(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Generate a pentest report in the requested format (CLI ``valen report``)."""
    import tempfile

    from .redteam.report import (
        _BUILDERS,
        Engagement,
        build_html,
        build_json,
        build_markdown,
        build_sarif,
        collect_report_data,
        to_pdf,
    )

    fmt = (payload.get("format") or "html").lower()
    engagement = Engagement.from_dict(payload.get("engagement"))
    data = collect_report_data(engagement)

    if fmt in ("html", "md", "markdown", "json", "sarif"):
        key = "md" if fmt == "markdown" else fmt
        return {"format": key, "content": _BUILDERS[key](data), "n": len(data["findings"])}
    if fmt == "pdf":
        with tempfile.NamedTemporaryFile("w", suffix=".html", delete=False) as fh:
            fh.write(build_html(data))
            html_path = Path(fh.name)
        pdf_path = html_path.with_suffix(".pdf")
        ok = to_pdf(html_path, pdf_path)
        body = pdf_path.read_bytes().decode("latin-1") if ok else ""
        try:
            html_path.unlink()
            pdf_path.unlink()
        except OSError:
            pass
        return {"format": "pdf", "ok": ok, "content_b64_len": len(body), "n": len(data["findings"])}
    return {"error": f"unknown format {fmt!r} (html|md|json|sarif|pdf)"}


def _report_download(query: Dict[str, List[str]]) -> Dict[str, Any]:
    """Serve a freshly generated report artifact (for the console buttons)."""
    fmt = (query.get("format", ["html"])[0] or "html").lower()
    out = _report({"format": fmt})
    return out


def _cvss(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Score a CVSS vector or a category's default metrics (CLI ``valen cvss``)."""
    from . import categories as _categories
    from .cvss import cvss31_base, cvss40_base, parse_vector, severity_name

    if payload.get("vector"):
        try:
            norm, score = parse_vector(str(payload["vector"]))
        except ValueError as exc:
            return {"error": str(exc)}
        return {"vector": norm, "score": score, "severity": severity_name(score)}

    if payload.get("category"):
        info = _categories.get(str(payload["category"]))
        v31, s31 = cvss31_base(*info.cvss31)
        v40, s40 = cvss40_base(*info.cvss40)
        return {
            "category": info.name,
            "cwe": list(info.cwe),
            "owasp": info.owasp,
            "mitre_tactic": info.mitre_tactic,
            "remediation": info.remediation,
            "severity": info.severity,
            "cvss31": {"vector": v31, "score": s31},
            "cvss40": {"vector": v40, "score": s40},
        }

    # raw metric dict: {"metrics": {AV:..., ...}, "version": "3.1"}
    metrics = payload.get("metrics") or {}
    version = str(payload.get("version") or "3.1")
    if metrics:
        try:
            if version.startswith("4"):
                vec, score = cvss40_base(
                    metrics.get("AV", "N"), metrics.get("AC", "L"),
                    metrics.get("AT", "N"), metrics.get("PR", "N"),
                    metrics.get("UI", "N"), metrics.get("VC", "H"),
                    metrics.get("VI", "H"), metrics.get("VA", "H"),
                    metrics.get("SC", "H"), metrics.get("SI", "H"),
                    metrics.get("SA", "H"),
                )
            else:
                vec, score = cvss31_base(
                    metrics.get("AV", "N"), metrics.get("AC", "L"),
                    metrics.get("PR", "N"), metrics.get("UI", "N"),
                    metrics.get("S", "U"), metrics.get("C", "H"),
                    metrics.get("I", "H"), metrics.get("A", "H"),
                )
        except KeyError as exc:
            return {"error": f"unknown metric value: {exc}"}
        return {"vector": vec, "score": score, "severity": severity_name(score)}

    return {"error": "provide 'vector', 'category' or 'metrics'"}


def _pentest(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Autonomous red-team engagement (CLI ``valen pentest``)."""
    from .redteam.auth import normalize_scope
    from .redteam.challenges import CHALLENGES
    from .redteam.executor import AutonomousAgent

    raw_scope = payload.get("scope") or ""
    if not raw_scope.strip():
        return {"error": "scope required (target base URL, authorized scope)"}
    try:
        scope = normalize_scope(raw_scope)
    except ValueError as exc:
        return {"error": str(exc)}
    warning = ""
    if scope != raw_scope.rstrip("/"):
        warning = (f"scope normalized to its origin {scope!r} "
                   f"(the agent appends API paths to it)")

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
        "warning": warning,
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
        # Any unhandled exception in a GET handler would make socketserver close
        # the connection without a response — the browser would then report
        # "TypeError: Failed to fetch". Always answer with JSON instead.
        try:
            return self._dispatch_get()
        except Exception as exc:  # noqa: BLE001
            return self._json({"error": str(exc)}, 500)

    def _dispatch_get(self) -> None:
        u = urlparse(self.path)
        if u.path in ("/", "/index.html"):
            return self._send(200, PAGE, "text/html; charset=utf-8")
        if u.path == "/api/examples":
            return self._json(_example_index())
        if u.path == "/api/adapters":
            return self._json(_adapters())
        if u.path == "/api/categories":
            from . import categories as _categories

            return self._json([
                {"name": c.name, "severity": c.severity, "cwe": list(c.cwe),
                 "owasp": c.owasp, "mitre_tactic": c.mitre_tactic,
                 "cvss31": list(c.cvss31), "cvss40": list(c.cvss40),
                 "remediation": c.remediation}
                for c in _categories.all_categories()
            ])
        if u.path == "/api/challenges":
            return self._json(_challenges())
        if u.path == "/api/cve":
            from . import cve_intel

            q = parse_qs(u.query)
            if q.get("q"):
                return self._json(cve_intel.lookup(q["q"][0]))
            if q.get("product"):
                ids = cve_intel.version_hints(q["product"][0], q.get("version", [""])[0])
                return self._json([cve_intel.lookup(i) for i in ids])
            return self._json(cve_intel.all_cves())
        if u.path == "/api/report/download":
            q = parse_qs(u.query)
            out = _report_download(q)
            fmt = q.get("format", ["html"])[0] or "html"
            ctype = {
                "html": "text/html; charset=utf-8",
                "md": "text/markdown; charset=utf-8",
                "markdown": "text/markdown; charset=utf-8",
                "json": "application/json; charset=utf-8",
                "sarif": "application/json; charset=utf-8",
            }.get(fmt, "text/plain; charset=utf-8")
            if fmt in ("html", "md", "markdown", "json", "sarif"):
                return self._send(200, str(out.get("content", "")), ctype)
            return self._json(out)
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
        try:
            return self._dispatch_post()
        except Exception as exc:  # noqa: BLE001
            return self._json({"error": str(exc)}, 500)

    def _dispatch_post(self) -> None:
        u = urlparse(self.path)
        allowed = ("/api/analyze", "/api/compare", "/api/validate",
                   "/api/recon", "/api/viz", "/api/dynamic", "/api/pentest",
                   "/api/report", "/api/cvss")
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
            if u.path == "/api/report":
                return self._json(_report(payload))
            if u.path == "/api/cvss":
                return self._json(_cvss(payload))
            if u.path == "/api/dynamic":
                return self._json(_dynamic(payload))
            if u.path == "/api/viz":
                return self._send(200, _viz(payload), "text/html; charset=utf-8")
            return self._json(_analyze(payload))
        except Exception as exc:
            return self._json({"error": str(exc)}, 500)


def serve(host: str = "127.0.0.1", port: int = 8000) -> None:
    try:
        httpd = ThreadingHTTPServer((host, port), Handler)
    except OSError as exc:
        print(f"error: cannot bind {host}:{port} ({exc}). "
              f"Is another `valen.server` already running? Try --port 8001.",
              file=sys.stderr)
        raise SystemExit(1)
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

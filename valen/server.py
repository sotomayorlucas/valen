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
    POST /api/pentest      {scope, goal?, authorize?, profile?, max_requests?, reset?} -> engagement results
    POST /api/lab/reset    {compose?, scope?, authorize} -> docker compose down -v + up -d + wait
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
import logging
import os
import queue
import sys
from dataclasses import dataclass
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import parse_qs, urlsplit, urlparse

from .analysis.field import vulnerability_field
from .analysis.math_core import run_core
from .authz import role_can
from .console import build_console
from .events import EventBus
from .ingest import analyze, infer_adapter
from .viz import _edge_data, _node_data
from .webui import PAGE

ROOT = Path(__file__).resolve().parent.parent
BENCH = ROOT / "benchmarks"
EXAMPLES = ROOT / "examples"

logger = logging.getLogger("valen.server")


@dataclass
class ServerConfig:
    """Trust boundary for the local server.

    ``token`` gates ``/api/*``; ``allow_host`` permits non-loopback pentest/validate
    targets (SSRF guard); ``allow_exec`` permits operations that run code or the
    container runtime (``/api/dynamic``, ``/api/lab/reset``); ``max_body`` caps
    request bodies.
    """

    token: str = ""
    allow_host: bool = False
    allow_exec: bool = False
    max_body: int = 5_000_000
    store: Any = None  # valen.store.Store | None
    authz: Any = None  # valen.authz.Authz | None (None => legacy single-token mode)
    events: Any = None  # valen.events.EventBus | None


_DEFAULT_CFG = ServerConfig()

_LOOPBACK = {"127.0.0.1", "::1", "localhost"}


def _is_loopback_host(host: str) -> bool:
    if not host:
        return False
    host = host.lower()
    return host in _LOOPBACK or host.startswith("127.")

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
    from .redteam.stealth import PRESETS, build_masscan_args, build_nmap_args

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


def _ad_plan(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze BloodHound/SharpHound JSON: tier-0 paths, roasts, GPP."""
    from .redteam.ad import attack_plan, gpp_from_xml, parse_sharphound

    data = payload.get("data")
    if not data:
        return {"error": "provide 'data' (SharpHound JSON object or string)"}
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except Exception as exc:  # noqa: BLE001
            return {"error": f"invalid JSON: {exc}"}
    ad = parse_sharphound(data)
    plan = attack_plan(ad, entries=payload.get("entries"))
    if payload.get("gpp_xml"):
        plan["gpp_passwords"] = gpp_from_xml(payload["gpp_xml"])
    plan["stats"] = {
        "nodes": ad.graph.node_count,
        "edges": ad.graph.edge_count,
        "users": len(ad.records["users"]),
        "groups": len(ad.records["groups"]),
        "computers": len(ad.records["computers"]),
    }
    return plan


def _payloads(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Build msfvenom commands + a handler + an HTA lure (does not execute)."""
    from .redteam.payloads import payload_plan

    lhost = payload.get("lhost")
    lport = payload.get("lport")
    if not lhost or not lport:
        return {"error": "lhost and lport required"}
    return payload_plan(lhost, int(lport), payload.get("output_dir", "payloads"))


def _c2_plan(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Plan a Sliver listener + implant (does not execute)."""
    from .redteam.c2 import c2_plan

    lhost, lport = payload.get("lhost"), payload.get("lport")
    if not lhost or not lport:
        return {"error": "lhost and lport required"}
    return c2_plan(lhost, int(lport), payload.get("name", "sess"))


def _c2_sessions(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Parse sliver-client 'sessions -j' output and fold it into the IR."""
    from .redteam.c2 import parse_sessions, sessions_to_ir

    sessions = parse_sessions(payload.get("output", ""))
    graph = sessions_to_ir(sessions)
    return {
        "sessions": sessions,
        "nodes": _node_data(graph, None),
        "edges": _edge_data(graph),
    }


def _lab_reset(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Reset the crAPI lab: docker compose down -v + up -d (authorized only)."""
    from .redteam.auth import normalize_scope
    from .redteam.lab import reset_lab

    if not bool(payload.get("authorize")):
        return {"error": "lab reset is destructive; set authorize=true"}
    raw = payload.get("scope") or "http://127.0.0.1:8888"
    try:
        scope = normalize_scope(raw)
    except ValueError as exc:
        return {"error": str(exc)}
    return reset_lab(compose=payload.get("compose"), scope=scope)


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
    lab_reset = None
    if payload.get("reset"):
        from .redteam.lab import reset_lab

        lab_reset = reset_lab(compose=payload.get("compose"), scope=scope)
        if not lab_reset.get("ok"):
            return {"error": "lab reset failed", "lab_reset": lab_reset}

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
    payload_out = {
        "scope": scope,
        "warning": warning,
        "profile": profile,
        "authorize": authorize,
        "challenges": results,
        "solved": solved,
        "total": len(results),
    }
    if lab_reset is not None:
        payload_out["lab_reset"] = lab_reset
    # Persist the engagement so the Report/Console panels pick it up (the report
    # reads benchmarks/autopentest_results.json). Best-effort only.
    try:
        (BENCH / "autopentest_results.json").write_text(
            json.dumps({"solved": solved, "n": len(results), "results": results}, indent=2)
        )
    except Exception:
        pass
    return payload_out


# --------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    server_version = "valen/0.1"

    def log_message(self, *args):  # quieter
        pass

    # -- config / auth / guards -------------------------------------------
    def _cfg(self) -> "ServerConfig":
        return getattr(self.server, "cfg", _DEFAULT_CFG)

    def _store(self):
        return self._cfg().store

    def _record(self, kind: str, out: Any, payload: Dict[str, Any], summary: str) -> None:
        st = self._store()
        if st is None:
            return
        try:
            st.record(
                kind, out,
                engagement_id=payload.get("engagement_id"),
                name=payload.get("path") or payload.get("name") or "<web>",
                adapter=(out or {}).get("adapter", "") if isinstance(out, dict) else "",
                path=payload.get("path") or "",
                summary=summary,
            )
        except Exception:  # noqa: BLE001
            logger.exception("failed to persist %s run", kind)
        self._publish(kind, summary,
                      engagement_id=payload.get("engagement_id"),
                      name=payload.get("path") or payload.get("name") or "")

    def _client_loopback(self) -> bool:
        return _is_loopback_host(self.client_address[0])

    def _legacy_token_ok(self) -> bool:
        cfg = self._cfg()
        if not cfg.token:
            return True
        if self.headers.get("Authorization", "") == f"Bearer {cfg.token}":
            return True
        q = parse_qs(urlparse(self.path).query).get("token", [""])
        return bool(q) and q[0] == cfg.token

    def _bearer(self) -> str:
        h = self.headers.get("Authorization", "")
        if h.startswith("Bearer "):
            return h[7:].strip()
        q = parse_qs(urlparse(self.path).query).get("token", [""])
        if q and q[0]:
            return q[0]
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        morsel = cookie.get("valen_session")
        return morsel.value if morsel else ""

    def _user(self):
        az = self._cfg().authz
        return az.resolve(self._bearer()) if az is not None else None

    @staticmethod
    def _public_path(path: str) -> bool:
        return path in ("/", "/index.html", "/console", "/api/login",
                        "/api/health", "/favicon.ico")

    @staticmethod
    def _capability(path: str, method: str) -> str:
        if path.startswith("/api/users"):
            return "manage_users"
        if path in ("/api/pentest", "/api/dynamic", "/api/lab/reset",
                    "/api/validate", "/api/recon", "/api/ad",
                    "/api/payloads", "/api/c2/plan", "/api/c2/sessions"):
            return "execute"
        if method != "GET" and path in ("/api/analyze", "/api/compare", "/api/report",
                                        "/api/engagements"):
            return "write"
        if method == "DELETE" and path.startswith("/api/engagements/"):
            return "write"
        return "read"

    def _gate(self, method: str) -> bool:
        """Authorize the request; sets ``self._user_ctx`` and returns True, or
        answers 401/403 and returns False. Legacy single-token mode when authz is
        not configured."""
        cfg = self._cfg()
        u = urlparse(self.path)
        if cfg.authz is None:
            if u.path.startswith("/api/") and not self._legacy_token_ok():
                self._json({"error": "unauthorized (set VALEN_TOKEN / --token)"}, 401)
                return False
            return True
        if self._public_path(u.path):
            return True
        user = self._user()
        if user is None:
            self._json({"error": "unauthorized"}, 401)
            return False
        cap = self._capability(u.path, method)
        if not role_can(user["role"], cap):
            self._json({"error": f"forbidden: role {user['role']!r} lacks {cap!r}"}, 403)
            return False
        self._user_ctx = user
        return True

    def _actor(self) -> str:
        u = getattr(self, "_user_ctx", None)
        return u["username"] if u else "anonymous"

    def _scope_allowed(self, scope: str) -> bool:
        host = (urlsplit(scope).hostname or "")
        if _is_loopback_host(host):
            return True
        return self._cfg().allow_host

    def _page(self, html: str) -> str:
        # Inject the token into the page only for loopback clients (Jupyter-style);
        # remote clients must pass ?token= on every request.
        if self._cfg().token and self._client_loopback():
            return html.replace("__VALEN_TOKEN__", self._cfg().token)
        return html.replace("__VALEN_TOKEN__", "")

    def _send(self, code: int, body: str, ctype: str = "application/json; charset=utf-8") -> None:
        self._last_status = code
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _json(self, obj: Any, code: int = 200) -> None:
        self._send(code, json.dumps(obj))

    # -- auth / users ------------------------------------------------------
    def _login(self, payload: Dict[str, Any]) -> None:
        az = self._cfg().authz
        if az is None:
            return self._json({"error": "server is in token mode (no user accounts)"}, 400)
        user = az.authenticate(payload.get("username", ""), payload.get("password", ""))
        if user is None:
            return self._json({"error": "invalid credentials"}, 401)
        token = az.create_session(user["id"])
        self._publish("login", f"{user['username']} logged in",
                      actor=user["username"], user=user["username"])
        # also set a cookie so the browser can use the SSE stream (EventSource
        # cannot send Authorization headers)
        self.send_response(200)
        body = json.dumps({"token": token, "user": user}).encode()
        self._last_status = 200
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Set-Cookie",
                         f"valen_session={token}; Path=/; HttpOnly; SameSite=Strict")
        self.end_headers()
        self.wfile.write(body)

    def _logout(self) -> None:
        az = self._cfg().authz
        if az is not None:
            az.revoke(self._bearer())

    def _create_user(self, payload: Dict[str, Any]) -> None:
        az = self._cfg().authz
        if az is None:
            return self._json({"error": "user management requires authz mode"}, 400)
        try:
            user = az.create_user(payload.get("username", ""), payload.get("password", ""),
                                  payload.get("role", "operator"))
        except ValueError as exc:
            return self._json({"error": str(exc)}, 400)
        self._publish("user_create", f"user {user['username']} ({user['role']}) created")
        return self._json(user)

    def _update_user(self, uid: int, payload: Dict[str, Any]) -> None:
        az = self._cfg().authz
        if az is None:
            return self._json({"error": "user management requires authz mode"}, 400)
        try:
            if "role" in payload:
                az.set_role(uid, payload["role"])
            if "password" in payload:
                az.set_password(uid, payload["password"])
            if "disabled" in payload:
                az.set_disabled(uid, bool(payload["disabled"]))
        except ValueError as exc:
            return self._json({"error": str(exc)}, 400)
        self._publish("user_update", f"user #{uid} updated")
        return self._json(az.get_user(uid) or {"error": "not found"})

    def _sse(self) -> None:
        events = self._cfg().events
        self.send_response(200)
        self._last_status = 200
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()
        if events is None:
            try:
                self.wfile.write(b": no event bus\n\n")
                self.wfile.flush()
            except OSError:
                pass
            return
        q = events.subscribe()
        try:
            self.wfile.write(b"retry: 3000\n\n")
            for ev in events.recent(20):
                self.wfile.write(EventBus.sse_format(ev).encode())
            self.wfile.flush()
            while True:
                try:
                    ev = q.get(timeout=15)
                    self.wfile.write(EventBus.sse_format(ev).encode())
                except queue.Empty:
                    self.wfile.write(b": keep-alive\n\n")
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            events.unsubscribe(q)

    def _publish(self, kind: str, summary: str, **fields: Any) -> None:
        events = self._cfg().events
        if events is not None:
            events.publish(kind, summary, actor=fields.pop("actor", self._actor()), **fields)

    def do_GET(self) -> None:  # noqa: N802
        # Any unhandled exception in a GET handler would make socketserver close
        # the connection without a response — the browser would then report
        # "TypeError: Failed to fetch". Always answer with JSON instead.
        try:
            if not self._gate("GET"):
                return
            u = urlparse(self.path)
            self._dispatch_get()
            logger.info("GET %s -> %s", u.path, getattr(self, "_last_status", 200))
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as exc:  # noqa: BLE001
            logger.exception("GET %s failed", self.path)
            return self._json({"error": str(exc)}, 500)

    def _dispatch_get(self) -> None:
        u = urlparse(self.path)
        if u.path in ("/", "/index.html"):
            return self._send(200, self._page(PAGE), "text/html; charset=utf-8")
        if u.path == "/api/health":
            return self._json({"ok": True, "auth": self._cfg().authz is not None})
        if u.path == "/api/me":
            return self._json(getattr(self, "_user_ctx", None) or {"legacy": True})
        if u.path == "/api/events":
            return self._sse()
        if u.path == "/api/users":
            az = self._cfg().authz
            if az is None:
                return self._json({"error": "user management requires authz mode"}, 400)
            return self._json(az.list_users())
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
        if u.path == "/api/history":
            st = self._store()
            if st is None:
                return self._json({"error": "store disabled (start without --no-store)"}, 403)
            q = parse_qs(u.query)
            limit = int(q.get("limit", ["50"])[0] or 50)
            kind = q.get("kind", [None])[0]
            return self._json({"engagements": st.list_engagements(),
                               "runs": st.recent_runs(limit, kind),
                               "count": st.count()})
        if u.path == "/api/engagements":
            st = self._store()
            if st is None:
                return self._json({"error": "store disabled"}, 403)
            user = getattr(self, "_user_ctx", None)
            return self._json(st.list_engagements(user_id=user["id"] if user else None))
        if u.path.startswith("/api/engagements/"):
            st = self._store()
            if st is None:
                return self._json({"error": "store disabled"}, 403)
            try:
                eid = int(u.path.rsplit("/", 1)[1])
            except ValueError:
                return self._json({"error": "bad engagement id"}, 400)
            user = getattr(self, "_user_ctx", None)
            if user is not None and not st.can_access(eid, user):
                return self._json({"error": "forbidden"}, 403)
            eng = st.get_engagement(eid)
            return self._json(eng) if eng else self._json({"error": "not found"}, 404)
        if u.path.startswith("/api/runs/"):
            st = self._store()
            if st is None:
                return self._json({"error": "store disabled"}, 403)
            try:
                rid = int(u.path.rsplit("/", 1)[1])
            except ValueError:
                return self._json({"error": "bad run id"}, 400)
            run = st.get_run(rid)
            return self._json(run) if run else self._json({"error": "not found"}, 404)
        if u.path == "/console":
            return self._send(200, self._page(build_console()), "text/html; charset=utf-8")
        if u.path == "/api/redteam":
            return self._json(_redteam())
        return self._json({"error": "not found"}, 404)

    def do_POST(self) -> None:  # noqa: N802
        try:
            if not self._gate("POST"):
                return
            self._dispatch_post()
            logger.info("POST %s -> %s", urlparse(self.path).path,
                        getattr(self, "_last_status", 200))
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as exc:  # noqa: BLE001
            logger.exception("POST %s failed", self.path)
            return self._json({"error": str(exc)}, 500)

    def _dispatch_post(self) -> None:
        u = urlparse(self.path)
        allowed = ("/api/analyze", "/api/compare", "/api/validate",
                   "/api/recon", "/api/viz", "/api/dynamic", "/api/pentest",
                   "/api/report", "/api/cvss", "/api/lab/reset", "/api/engagements", "/api/ad",
                   "/api/payloads", "/api/c2/plan", "/api/c2/sessions",
                   "/api/login", "/api/logout", "/api/users")
        if u.path not in allowed and not u.path.startswith("/api/users/"):
            return self._json({"error": "not found"}, 404)
        length = int(self.headers.get("Content-Length", "0"))
        if length > self._cfg().max_body:
            return self._json({"error": f"request body too large (>{self._cfg().max_body} bytes)"}, 413)
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return self._json({"error": "invalid JSON body"}, 400)
        # auth endpoints
        if u.path == "/api/login":
            return self._login(payload)
        if u.path == "/api/logout":
            self._logout()
            return self._json({"ok": True})
        if u.path == "/api/users":
            return self._create_user(payload)
        if u.path.startswith("/api/users/"):
            try:
                uid = int(u.path.rsplit("/", 1)[1])
            except ValueError:
                return self._json({"error": "bad user id"}, 400)
            return self._update_user(uid, payload)
        # dangerous operations (code execution / container runtime) gate
        if u.path in ("/api/dynamic", "/api/lab/reset") and not self._cfg().allow_exec:
            return self._json({"error": f"{u.path} disabled; start the server with --allow-exec"}, 403)
        # SSRF guard: non-loopback targets require --allow-host
        scope = payload.get("scope") or payload.get("base_url")
        if scope and u.path in ("/api/pentest", "/api/validate", "/api/lab/reset"):
            from .redteam.auth import normalize_scope

            try:
                norm = normalize_scope(scope)
            except ValueError as exc:
                return self._json({"error": str(exc)}, 400)
            if not self._scope_allowed(norm):
                return self._json(
                    {"error": f"scope {norm!r} is not loopback; start the server "
                              f"with --allow-host to authorize external targets"}, 403)
        try:
            if u.path == "/api/engagements":
                st = self._store()
                if st is None:
                    return self._json({"error": "store disabled"}, 403)
                name = (payload.get("name") or "").strip()
                if not name:
                    return self._json({"error": "name required"}, 400)
                user = getattr(self, "_user_ctx", None)
                eng = st.create_engagement(
                    name, payload.get("client", ""), payload.get("scope", ""),
                    payload.get("notes", ""), owner_id=user["id"] if user else None)
                self._publish("engagement_create", f"engagement #{eng['id']} {name}")
                return self._json(eng)
            if u.path == "/api/compare":
                out = _compare(payload)
                self._record("compare", out, payload,
                             f"resolved={len(out['diff']['resolved'])} "
                             f"introduced={len(out['diff']['introduced'])}")
                return self._json(out)
            if u.path == "/api/validate":
                return self._json(_validate(payload))
            if u.path == "/api/recon":
                return self._json(_recon(payload))
            if u.path == "/api/pentest":
                out = _pentest(payload)
                if "error" not in out:
                    self._record("pentest", out, payload,
                                 f"{out.get('solved', 0)}/{out.get('total', 0)} solved")
                return self._json(out)
            if u.path == "/api/ad":
                return self._json(_ad_plan(payload))
            if u.path == "/api/payloads":
                return self._json(_payloads(payload))
            if u.path == "/api/c2/plan":
                return self._json(_c2_plan(payload))
            if u.path == "/api/c2/sessions":
                return self._json(_c2_sessions(payload))
            if u.path == "/api/lab/reset":
                return self._json(_lab_reset(payload))
            if u.path == "/api/report":
                return self._json(_report(payload))
            if u.path == "/api/cvss":
                return self._json(_cvss(payload))
            if u.path == "/api/dynamic":
                out = _dynamic(payload)
                if "error" not in out:
                    self._record("dynamic", out, payload,
                                 f"exit={out.get('exit_code')}")
                return self._json(out)
            if u.path == "/api/viz":
                return self._send(200, _viz(payload), "text/html; charset=utf-8")
            out = _analyze(payload)
            self._record("analyze", out, payload, f"{len(out.get('findings', []))} findings")
            return self._json(out)
        except Exception as exc:
            return self._json({"error": str(exc)}, 500)

    def do_DELETE(self) -> None:  # noqa: N802
        try:
            if not self._gate("DELETE"):
                return
            u = urlparse(self.path)
            if u.path.startswith("/api/engagements/"):
                st = self._store()
                if st is None:
                    return self._json({"error": "store disabled"}, 403)
                try:
                    eid = int(u.path.rsplit("/", 1)[1])
                except ValueError:
                    return self._json({"error": "bad engagement id"}, 400)
                user = getattr(self, "_user_ctx", None)
                if user is not None and not st.can_access(eid, user):
                    return self._json({"error": "forbidden"}, 403)
                st.delete_engagement(eid)
                return self._json({"deleted": eid})
            return self._json({"error": "not found"}, 404)
        except Exception as exc:  # noqa: BLE001
            return self._json({"error": str(exc)}, 500)


def serve(host: str = "127.0.0.1", port: int = 8000,
          config: "ServerConfig | None" = None) -> None:
    cfg = config or _DEFAULT_CFG
    try:
        httpd = ThreadingHTTPServer((host, port), Handler)
    except OSError as exc:
        print(f"error: cannot bind {host}:{port} ({exc}). "
              f"Is another `valen.server` already running? Try --port 8001.",
              file=sys.stderr)
        raise SystemExit(1)
    httpd.cfg = cfg
    flags = []
    if cfg.authz is not None:
        flags.append(f"team server ({cfg.authz.count()} users)")
    elif cfg.token:
        flags.append("token auth")
    if cfg.allow_host:
        flags.append("allow-host")
    if cfg.allow_exec:
        flags.append("allow-exec")
    suffix = f"  [{', '.join(flags)}]" if flags else ""
    print(f"VALEN web UI  ->  http://{host}:{port}  (Ctrl+C to stop){suffix}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


def main(argv: list[str] | None = None) -> int:
    from .config import load_config

    scfg = load_config().get("server", {})
    ap = argparse.ArgumentParser(description="VALEN team server + web UI (stdlib).")
    ap.add_argument("--host", default=scfg.get("host", "127.0.0.1"))
    ap.add_argument("--port", type=int, default=int(scfg.get("port", 8000)))
    ap.add_argument("--token", default=os.environ.get("VALEN_TOKEN", scfg.get("token", "")),
                    help="shared-secret mode: require this bearer token on /api/* "
                         "(disables user accounts)")
    ap.add_argument("--create-admin", nargs="?", const="admin", default=None,
                    metavar="USER",
                    help="create the initial admin account (prints a generated "
                         "password if none is given) and continue serving")
    ap.add_argument("--allow-host", action="store_true", default=bool(scfg.get("allow_host", False)),
                    help="allow non-loopback pentest/validate targets (SSRF guard off)")
    ap.add_argument("--allow-exec", action="store_true", default=bool(scfg.get("allow_exec", False)),
                    help="enable /api/dynamic and /api/lab/reset (run code / docker)")
    ap.add_argument("--max-body", type=int, default=5_000_000,
                    help="maximum request body size in bytes")
    ap.add_argument("--no-store", action="store_true",
                    help="disable the SQLite engagement/run history store")
    ap.add_argument("--data-dir", default=os.environ.get("VALEN_DATA_DIR", scfg.get("data_dir", "")),
                    help="store directory (default ~/.local/share/valen)")
    ap.add_argument("--log-level", default="info",
                    choices=["debug", "info", "warning", "error"])
    args = ap.parse_args(argv)

    logging.basicConfig(level=getattr(logging, args.log_level.upper()),
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    store = None
    if not args.no_store:
        try:
            from .store import Store

            store = Store(args.data_dir or None)
        except Exception:  # noqa: BLE001
            logger.exception("failed to open the history store; continuing without it")

    events = EventBus()
    authz = None
    if not args.token:  # token mode => no user accounts
        from .authz import Authz, bootstrap_admin

        authz = Authz(args.data_dir or None)
        if args.create_admin:
            if authz.has_users():
                print("note: users already exist; --create-admin ignored", file=sys.stderr)
            else:
                user = bootstrap_admin(authz, args.create_admin)
                if user.get("generated_password"):
                    print(f"created admin {user['username']!r}  "
                          f"password: {user['generated_password']}")
        elif not authz.has_users():
            print("warning: no user accounts yet — run the first start with "
                  "`--create-admin [user]` to create the admin, or use --token "
                  "for shared-secret mode.", file=sys.stderr)

    cfg = ServerConfig(token=args.token, allow_host=args.allow_host,
                       allow_exec=args.allow_exec, max_body=args.max_body,
                       store=store, authz=authz, events=events)
    serve(args.host, args.port, cfg)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

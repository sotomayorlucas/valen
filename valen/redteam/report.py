"""Pentest report generator: HTML (self-contained), Markdown, JSON, SARIF 2.1.0
and PDF (Chrome headless).

Assembles the attack plan, findings, PoCs, exploitation evidence, recon,
enumeration and the autonomous-pentest results into a professional report with
an executive summary, per-finding CVSS 3.1 base scores (or a custom vector),
CWE / OWASP / MITRE enrichment, reproduction steps, evidence, CVE intelligence
and remediation.

The template uses ``__PLACEHOLDER__`` replacement (like ``console.py`` /
``viz.py``) so it can grow without ``{{}}`` brace-escaping.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .. import categories as _categories
from ..cvss import cvss31_base, parse_vector, severity_name

ROOT = Path(__file__).resolve().parents[2]
BENCH = ROOT / "benchmarks"

# Backwards-compatible aliases (kept so existing imports keep working).
cvss_base = cvss31_base


def cvss_for(category: str) -> Tuple[str, float]:
    """Vector + score for a category's default metrics (alias-aware)."""
    params = _categories.get(category).cvss31
    return cvss31_base(*params)


# ---------------------------------------------------------------------------
# Engagement metadata
# ---------------------------------------------------------------------------
@dataclass
class Engagement:
    """Who / what / when / under what rules this report covers."""

    client: str = ""
    scope: str = ""
    author: str = ""
    date_start: str = ""
    date_end: str = ""
    roe: str = ""  # rules of engagement
    limitations: str = ""

    @classmethod
    def from_dict(cls, d: Optional[Dict[str, Any]]) -> "Engagement":
        d = d or {}
        return cls(
            client=str(d.get("client", "")),
            scope=str(d.get("scope", "")),
            author=str(d.get("author", "")),
            date_start=str(d.get("date_start", "")),
            date_end=str(d.get("date_end", "")),
            roe=str(d.get("roe", "")),
            limitations=str(d.get("limitations", "")),
        )


# ---------------------------------------------------------------------------
# Data assembly
# ---------------------------------------------------------------------------
def _j(name: str) -> dict:
    p = BENCH / name
    return json.loads(p.read_text()) if p.exists() else {}


def _enrich_finding(f: Dict[str, Any]) -> Dict[str, Any]:
    """Attach CWE / OWASP / MITRE / default remediation from the registry."""
    cat = _categories.get(f.get("category", ""))
    f.setdefault("category", cat.name)
    f.setdefault("cwe", list(cat.cwe))
    f.setdefault("owasp", cat.owasp)
    f.setdefault("mitre_tactic", cat.mitre_tactic)
    f.setdefault("remediation", cat.remediation)
    if "vector" not in f or not f.get("vector"):
        vec, score = cvss31_base(*cat.cvss31)
        f.setdefault("vector", vec)
    if "cvss" not in f or f.get("cvss") in (None, 0, 0.0):
        try:
            _, score = parse_vector(f.get("vector", ""))
        except Exception:
            _, score = cvss31_base(*cat.cvss31)
        f["cvss"] = score
    f.setdefault("severity", severity_name(float(f.get("cvss", 0))))
    return f


def collect_report_data(engagement: Optional[Engagement] = None) -> Dict:
    plan = _j("attack_plan.json").get("steps", [])
    exploit = _j("exploit_results.json")
    bola = _j("crapi_bola_results.json")
    recon = _j("recon_plan.json")
    enum = _j("enum_results.json")
    pocs = _j("redteam_pocs.json")
    autopentest = _j("autopentest_results.json")

    findings: List[Dict] = []
    # exploit: account takeover + IDOR
    for t in exploit.get("takeover", []):
        if t.get("victim_data_in_response"):
            vec, score = cvss_for("account_takeover")
            findings.append({
                "title": f"JWT forgery -> account takeover ({t['technique']})",
                "category": "account_takeover", "severity": severity_name(score),
                "cvss": score, "vector": vec,
                "repro": f"forge JWT via {t['technique']}, call /identity/api/v2/user/dashboard",
                "evidence": t.get("evidence", ""),
            })
    for h in exploit.get("idor", []):
        vec, score = cvss_for("idor")
        findings.append({
            "title": f"BOLA/IDOR: cross-user access to {h['path']}",
            "category": "idor", "severity": severity_name(score),
            "cvss": score, "vector": vec,
            "repro": f"attacker token -> GET {h['path']}",
            "evidence": h.get("evidence", ""),
        })
    # nuclei-verified findings from the plan
    for s in plan:
        if s.get("tactic_id") in ("TA0002", "TA0006") and "detail" in s:
            cat = "sql" if s["tactic_id"] == "TA0006" else "code_execution"
            vec, score = cvss_for(cat)
            findings.append({
                "title": s["title"], "category": cat,
                "severity": severity_name(score),
                "cvss": score, "vector": vec,
                "repro": s.get("detail", ""), "evidence": s.get("detail", ""),
            })

    findings = [_enrich_finding(f) for f in findings]

    # CVE intelligence (KEV / EPSS) if the snapshot is present.
    try:
        from .. import cve_intel  # type: ignore
        findings = cve_intel.enrich_findings(findings)
        cve_hints = cve_intel.enrich_hints(recon.get("cve_hypotheses", []))
    except Exception:
        cve_hints = recon.get("cve_hypotheses", [])

    return {
        "engagement": asdict(engagement or Engagement()),
        "findings": findings,
        "plan_steps": plan,
        "bola": bola,
        "recon_hosts": recon.get("hosts", []),
        "recon_cve_hints": cve_hints,
        "enum_shadow": enum.get("shadow_endpoints", []),
        "pocs": pocs if isinstance(pocs, list) else pocs.get("pocs", pocs.get("items", [])),
        "pentest": autopentest,
    }


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------
def esc(s) -> str:
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;"))


def _sev_class(sev: str) -> str:
    return {
        "critical": "critical", "high": "high", "medium": "medium",
        "low": "low", "info": "info", "none": "info",
    }.get(sev.lower(), "info")


def _html_findings_rows(findings: List[Dict]) -> str:
    return "".join(
        f"<tr><td>{esc(f['title'])}</td>"
        f"<td><span class='sev {_sev_class(f['severity'])}'>{esc(f['severity'])}</span></td>"
        f"<td class='mono'>{float(f.get('cvss', 0)):.1f}</td>"
        f"<td class='mono'>{esc(f.get('vector', ''))}</td>"
        f"<td class='mono'>{esc(', '.join(f.get('cwe', [])) or '—')}</td>"
        f"<td>{esc(f.get('owasp', '—'))}</td></tr>"
        for f in findings
    )


def _html_finding_details(findings: List[Dict]) -> str:
    out = []
    for f in findings:
        cves = f.get("cve_ids") or []
        cve_line = ""
        if cves:
            badges = "".join(
                f"<span class='pill'>{esc(c)}{' · KEV' if f.get('kev') else ''}"
                f"{' · EPSS ' + format(float(f.get('epss', 0)), '.3f') if f.get('epss') else ''}"
                f"</span> "
                for c in cves
            )
            cve_line = f"<p><b>CVE:</b> {badges}</p>"
        out.append(
            f"<div class='finding'><h3>{esc(f['title'])}</h3>"
            f"<p><b>Severity:</b> {esc(f['severity'])} ({float(f.get('cvss', 0)):.1f}) · "
            f"<span class='mono'>{esc(f.get('vector', ''))}</span></p>"
            f"<p><b>Classification:</b> {esc(f.get('category', ''))} · "
            f"{esc(', '.join(f.get('cwe', [])) or '—')} · {esc(f.get('owasp', ''))} · "
            f"MITRE {esc(f.get('mitre_tactic', ''))}</p>"
            f"{cve_line}"
            f"<p><b>Reproduction:</b> {esc(f.get('repro', ''))}</p>"
            f"<pre>{esc(str(f.get('evidence', ''))[:600])}</pre>"
            f"<p><b>Remediation:</b> {esc(f.get('remediation', ''))}</p></div>"
        )
    return "".join(out)


def _html_killchain(plan: List[Dict]) -> str:
    if not plan:
        return "<p class='muted'>—</p>"
    rows = "".join(
        f"<tr><td class='mono'>{esc(s.get('tactic_id', ''))}</td>"
        f"<td>{esc(s.get('tactic', ''))}</td>"
        f"<td>{esc(s.get('phase', ''))}</td>"
        f"<td>{esc(s.get('title', ''))}</td>"
        f"<td>{esc(str(s.get('detail', ''))[:120])}</td></tr>"
        for s in plan
    )
    return (f"<table><tr><th>Tactic</th><th>Name</th><th>Phase</th>"
            f"<th>Step</th><th>Detail</th></tr>{rows}</table>")


def _html_pocs(pocs: Any) -> str:
    if not pocs:
        return "<p class='muted'>—</p>"
    if isinstance(pocs, dict):
        pocs = list(pocs.values())
    out = []
    for p in pocs:
        title = p.get("title", p.get("name", "PoC"))
        code = p.get("code", p.get("script", p.get("poc", "")))
        out.append(
            f"<div class='finding'><h3>{esc(title)}</h3>"
            f"<pre>{esc(str(code)[:4000])}</pre></div>"
        )
    return "".join(out)


def _html_pentest(pt: Dict) -> str:
    if not pt:
        return "<p class='muted'>—</p>"
    solved, total = pt.get("solved", 0), pt.get("n", 0) or pt.get("total", 0)
    rows = "".join(
        f"<tr><td class='mono'>{esc(r.get('challenge', ''))}</td>"
        f"<td>{'SOLVED' if r.get('solved') else 'not solved'}</td>"
        f"<td class='mono'>{r.get('requests', 0)}</td>"
        f"<td class='mono'>{r.get('seconds', 0)}</td></tr>"
        for r in pt.get("results", [])
    )
    return (f"<p><b>{solved}/{total}</b> challenges solved.</p>"
            f"<table><tr><th>Challenge</th><th>Result</th><th>Req</th><th>Sec</th></tr>{rows}</table>")


def _html_remediation_plan(findings: List[Dict]) -> str:
    """Dynamic remediation priority: ordered by CVSS score descending."""
    ranked = sorted(findings, key=lambda f: -float(f.get("cvss", 0)))
    if not ranked:
        return "<p class='muted'>No findings — no remediation required.</p>"
    items = []
    for i, f in enumerate(ranked[:15], 1):
        items.append(
            f"<li><b>{esc(f['title'])}</b> ({esc(f['severity'])} "
            f"{float(f.get('cvss', 0)):.1f}) — {esc(f.get('remediation', ''))}</li>"
        )
    return "<ol>" + "".join(items) + "</ol>"


def _html_engagement(e: Dict) -> str:
    rows = []
    for k, label in (
        ("client", "Client"), ("scope", "Scope"), ("author", "Author"),
        ("date_start", "Start"), ("date_end", "End"),
    ):
        if e.get(k):
            rows.append(f"<tr><td>{label}</td><td>{esc(e[k])}</td></tr>")
    if not rows:
        return ""
    return ("<table class='meta-table'><tr><th>Engagement</th><th></th></tr>"
            + "".join(rows) + "</table>")


def _html_risk_matrix(findings: List[Dict]) -> str:
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0, "None": 0}
    for f in findings:
        counts[f.get("severity", "Info")] = counts.get(f.get("severity", "Info"), 0) + 1
    scores = [float(f.get("cvss", 0)) for f in findings]
    max_s = max(scores) if scores else 0.0
    avg_s = (sum(scores) / len(scores)) if scores else 0.0
    return (
        f"<table><tr><th>Severity</th><th>Count</th></tr>"
        f"<tr><td><span class='sev critical'>Critical</span></td><td class='mono'>{counts['Critical']}</td></tr>"
        f"<tr><td><span class='sev high'>High</span></td><td class='mono'>{counts['High']}</td></tr>"
        f"<tr><td><span class='sev medium'>Medium</span></td><td class='mono'>{counts['Medium']}</td></tr>"
        f"<tr><td><span class='sev low'>Low</span></td><td class='mono'>{counts['Low']}</td></tr>"
        f"<tr><td><span class='sev info'>Info</span></td><td class='mono'>{counts['Info'] + counts['None']}</td></tr>"
        f"</table>"
        f"<p><b>Max CVSS:</b> <span class='mono'>{max_s:.1f}</span> · "
        f"<b>Mean CVSS:</b> <span class='mono'>{avg_s:.2f}</span></p>"
    )


def build_html(data: Dict) -> str:
    findings = data.get("findings", [])
    e = data.get("engagement", {}) or {}
    engagement_html = _html_engagement(e)

    meta_bits = []
    if e.get("client"):
        meta_bits.append(esc(e["client"]))
    if e.get("scope"):
        meta_bits.append(f"scope: {esc(e['scope'])}")
    if e.get("date_start") or e.get("date_end"):
        meta_bits.append(f"{esc(e.get('date_start', ''))} – {esc(e.get('date_end', ''))}")
    meta_bits.append("authorized engagement · generated from machine-checkable evidence")
    meta_line = " · ".join(meta_bits)

    recon_desc = ", ".join(esc(h.get("ip", "")) for h in data.get("recon_hosts", [])[:8])
    shadow = ", ".join(esc(s) for s in data.get("enum_shadow", [])[:8])
    bola = data.get("bola", {}) or {}
    n_crit = sum(1 for f in findings if f.get("severity") in ("Critical", "High"))

    replacements = {
        "__META__": meta_line,
        "__ENGAGEMENT__": engagement_html,
        "__N__": str(len(findings)),
        "__N_CRIT__": str(n_crit),
        "__BOLA_RECALL__": f"{bola.get('recall', 0):.2f}",
        "__BOLA_PREC__": f"{bola.get('precision', 0):.2f}",
        "__RISK__": _html_risk_matrix(findings),
        "__ROWS__": _html_findings_rows(findings),
        "__DETAILS__": _html_finding_details(findings),
        "__KILLCHAIN__": _html_killchain(data.get("plan_steps", [])),
        "__POCS__": _html_pocs(data.get("pocs", [])),
        "__PENTEST__": _html_pentest(data.get("pentest", {})),
        "__RECON__": recon_desc or "—",
        "__SHADOW__": shadow or "—",
        "__REMEDIATION__": _html_remediation_plan(findings),
    }
    html = _HTML
    for k, v in replacements.items():
        html = html.replace(k, v)
    return html


def build_report(data: Dict) -> str:
    """Backwards-compatible alias for :func:`build_html`."""
    return build_html(data)


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------
def build_markdown(data: Dict) -> str:
    findings = data.get("findings", [])
    e = data.get("engagement", {}) or {}
    bola = data.get("bola", {}) or {}
    lines: List[str] = []
    lines.append("# VALEN — Penetration Test Report")
    lines.append("")
    if any(e.get(k) for k in ("client", "scope", "author", "date_start", "date_end")):
        lines.append("| | |")
        lines.append("|---|---|")
        for k, label in (
            ("client", "Client"), ("scope", "Scope"), ("author", "Author"),
            ("date_start", "Start"), ("date_end", "End"), ("roe", "Rules of engagement"),
            ("limitations", "Limitations"),
        ):
            if e.get(k):
                lines.append(f"| {label} | {e[k]} |")
        lines.append("")

    n_crit = sum(1 for f in findings if f.get("severity") in ("Critical", "High"))
    lines.append("## Executive summary")
    lines.append("")
    lines.append(f"- **{len(findings)}** findings ({n_crit} critical/high)")
    lines.append(f"- **Max CVSS:** {max([float(f.get('cvss', 0)) for f in findings], default=0):.1f}")
    if bola:
        lines.append(f"- **BOLA detector (crAPI):** recall {bola.get('recall', 0):.2f} / "
                     f"precision {bola.get('precision', 0):.2f}")
    lines.append("")

    lines.append("## Risk matrix")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|---|---|")
    counts: Dict[str, int] = {}
    for f in findings:
        counts[f.get("severity", "Info")] = counts.get(f.get("severity", "Info"), 0) + 1
    for sev in ("Critical", "High", "Medium", "Low", "Info"):
        if counts.get(sev):
            lines.append(f"| {sev} | {counts[sev]} |")
    lines.append("")

    lines.append("## Findings")
    lines.append("")
    lines.append("| Finding | Severity | CVSS | Vector | CWE | OWASP |")
    lines.append("|---|---|---|---|---|---|")
    for f in findings:
        lines.append(
            f"| {f['title']} | {f.get('severity', '')} | {float(f.get('cvss', 0)):.1f} "
            f"| `{f.get('vector', '')}` | {', '.join(f.get('cwe', [])) or '—'} "
            f"| {f.get('owasp', '')} |"
        )
    lines.append("")

    lines.append("## Finding details")
    lines.append("")
    for f in findings:
        lines.append(f"### {f['title']}")
        lines.append("")
        lines.append(f"- **Severity:** {f.get('severity', '')} ({float(f.get('cvss', 0)):.1f})")
        lines.append(f"- **Vector:** `{f.get('vector', '')}`")
        lines.append(f"- **Classification:** {f.get('category', '')} · "
                     f"{', '.join(f.get('cwe', [])) or '—'} · {f.get('owasp', '')} · "
                     f"MITRE {f.get('mitre_tactic', '')}")
        if f.get("cve_ids"):
            marks = []
            for c in f["cve_ids"]:
                m = c
                if f.get("kev"):
                    m += " (KEV)"
                if f.get("epss"):
                    m += f" (EPSS {float(f['epss']):.3f})"
                marks.append(m)
            lines.append(f"- **CVE:** {', '.join(marks)}")
        lines.append(f"- **Reproduction:** {f.get('repro', '')}")
        lines.append("")
        lines.append("```")
        lines.append(str(f.get("evidence", ""))[:600])
        lines.append("```")
        lines.append("")
        lines.append(f"- **Remediation:** {f.get('remediation', '')}")
        lines.append("")

    plan = data.get("plan_steps", [])
    lines.append("## Attack plan (kill chain)")
    lines.append("")
    if plan:
        lines.append("| Tactic | Name | Phase | Step | Detail |")
        lines.append("|---|---|---|---|---|")
        for s in plan:
            lines.append(
                f"| {s.get('tactic_id', '')} | {s.get('tactic', '')} | {s.get('phase', '')} "
                f"| {s.get('title', '')} | {str(s.get('detail', ''))[:120]} |"
            )
    else:
        lines.append("—")
    lines.append("")

    pocs = data.get("pocs", [])
    if pocs:
        if isinstance(pocs, dict):
            pocs = list(pocs.values())
        lines.append("## Proof of concepts")
        lines.append("")
        for p in pocs:
            lines.append(f"### {p.get('title', p.get('name', 'PoC'))}")
            lines.append("")
            lines.append("```python")
            lines.append(str(p.get("code", p.get("script", p.get("poc", "")))[:4000]))
            lines.append("```")
            lines.append("")

    pt = data.get("pentest", {})
    if pt:
        lines.append("## Autonomous pentest results")
        lines.append("")
        lines.append(f"**{pt.get('solved', 0)}/{pt.get('n', 0) or pt.get('total', 0)}** "
                     f"challenges solved.")
        lines.append("")
        if pt.get("results"):
            lines.append("| Challenge | Result | Requests | Seconds |")
            lines.append("|---|---|---|---|")
            for r in pt["results"]:
                res = "SOLVED" if r.get("solved") else "not solved"
                lines.append(f"| {r.get('challenge', '')} | {res} "
                             f"| {r.get('requests', 0)} | {r.get('seconds', 0)} |")
        lines.append("")

    hints = data.get("recon_cve_hints", [])
    if hints:
        lines.append("## Reconnaissance — CVE hypotheses")
        lines.append("")
        lines.append("| Host | Hint | CVEs |")
        lines.append("|---|---|---|")
        for h in hints:
            cves = h.get("cves") or h.get("cve_ids") or []
            if isinstance(cves, str):
                cves = [cves]
            host = h.get("host", h.get("ip", ""))
            label = h.get("version") or h.get("hypothesis") or h.get("service", "")
            port = h.get("port")
            host_cell = f"{host}:{port}" if port else str(host)
            lines.append(f"| {host_cell} | {label} | {', '.join(cves) or '—'} |")
        lines.append("")

    hosts = data.get("recon_hosts", [])
    shadow = data.get("enum_shadow", [])
    if hosts or shadow:
        lines.append("## Reconnaissance")
        lines.append("")
        if hosts:
            lines.append("**Hosts:** " + ", ".join(h.get("ip", "") for h in hosts[:20]))
        if shadow:
            lines.append("")
            lines.append("**Shadow endpoints (not in the published spec):** "
                         + ", ".join(shadow[:20]))
        lines.append("")

    lines.append("## Remediation priority")
    lines.append("")
    ranked = sorted(findings, key=lambda f: -float(f.get("cvss", 0)))
    if ranked:
        for i, f in enumerate(ranked[:15], 1):
            lines.append(f"{i}. **{f['title']}** ({f.get('severity', '')} "
                         f"{float(f.get('cvss', 0)):.1f}) — {f.get('remediation', '')}")
    else:
        lines.append("No findings — no remediation required.")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------
def build_json(data: Dict) -> str:
    payload = {
        "schema": "valen.report/1",
        "engagement": data.get("engagement", {}),
        "summary": {
            "findings": len(data.get("findings", [])),
            "critical_high": sum(
                1 for f in data.get("findings", [])
                if f.get("severity") in ("Critical", "High")
            ),
            "max_cvss": max([float(f.get("cvss", 0)) for f in data.get("findings", [])],
                            default=0.0),
            "mean_cvss": (
                sum(float(f.get("cvss", 0)) for f in data.get("findings", []))
                / max(len(data.get("findings", [])), 1)
            ),
        },
        "findings": data.get("findings", []),
        "plan_steps": data.get("plan_steps", []),
        "pocs": data.get("pocs", []),
        "pentest": data.get("pentest", {}),
        "recon": {
            "hosts": data.get("recon_hosts", []),
            "cve_hints": data.get("recon_cve_hints", []),
            "shadow_endpoints": data.get("enum_shadow", []),
        },
        "bola": data.get("bola", {}),
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# SARIF 2.1.0
# ---------------------------------------------------------------------------
def _sarif_level(severity: str) -> str:
    s = severity.lower()
    if s in ("critical", "high"):
        return "error"
    if s == "medium":
        return "warning"
    return "note"


def build_sarif(data: Dict) -> str:
    findings = data.get("findings", [])
    rules = {}
    results = []
    for f in findings:
        cwe_list = f.get("cwe", []) or ["CWE-0"]
        rule_id = cwe_list[0] if cwe_list else "CWE-0"
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": f.get("category", "unknown"),
                "shortDescription": {"text": f.get("title", rule_id)},
                "fullDescription": {"text": f.get("remediation", "")},
                "properties": {
                    "cwe": list(cwe_list),
                    "owasp": f.get("owasp", ""),
                    "mitre_tactic": f.get("mitre_tactic", ""),
                },
            }
        entry = {
            "ruleId": rule_id,
            "level": _sarif_level(f.get("severity", "")),
            "message": {"text": f"{f.get('title', '')} — {f.get('description', '')}".strip(" —")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.get("file", "unknown")},
                    "region": {"startLine": int(f.get("line", 1) or 1)},
                }
            }],
            "properties": {
                "cvss_vector": f.get("vector", ""),
                "cvss_score": float(f.get("cvss", 0)),
                "severity": f.get("severity", ""),
                "category": f.get("category", ""),
                "cwe": list(cwe_list),
                "owasp": f.get("owasp", ""),
                "mitre_tactic": f.get("mitre_tactic", ""),
                "cve_ids": list(f.get("cve_ids", []) or []),
                "kev": bool(f.get("kev", False)),
                "epss": f.get("epss"),
                "repro": f.get("repro", ""),
                "evidence": str(f.get("evidence", ""))[:600],
                "remediation": f.get("remediation", ""),
            },
        }
        results.append(entry)

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "VALEN",
                    "informationUri": "https://github.com/anomalyco/valen",
                    "version": "0.1",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# PDF
# ---------------------------------------------------------------------------
def to_pdf(html_path: Path, pdf_path: Path) -> bool:
    """Render the HTML report to PDF via headless Chrome (no new deps)."""
    try:
        subprocess.run(
            ["google-chrome", "--headless=new", "--no-sandbox",
             f"--print-to-pdf={pdf_path}", "--no-pdf-header-footer",
             f"file://{html_path.resolve()}"],
            capture_output=True, timeout=120, check=True,
        )
        return pdf_path.exists()
    except Exception:
        return False


# ---------------------------------------------------------------------------
# HTML template (__PLACEHOLDER__ style — no brace escaping needed)
# ---------------------------------------------------------------------------
_HTML = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>VALEN — Penetration Test Report</title>
<style>
:root{--bg:#0b1020;--panel:#121a30;--line:#22304d;--fg:#e6ebf5;--muted:#8b96ad;--accent:#4f8cff}
*{box-sizing:border-box} body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;padding:28px}
h1{color:var(--accent);margin:0 0 4px} h2{color:var(--accent);border-bottom:1px solid var(--line);padding-bottom:6px;margin-top:28px}
.meta{color:var(--muted);font-size:12px;margin-bottom:20px}
.meta-table{width:auto;min-width:340px;margin-bottom:18px}
.kpi{display:flex;gap:16px;flex-wrap:wrap} .kpi div{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 20px}
.kpi b{font-size:22px} .kpi span{color:var(--muted);font-size:12px}
table{border-collapse:collapse;width:100%;margin:12px 0} th,td{text-align:left;padding:8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--accent)} .sev{padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600}
.sev.critical{background:#3a1016;color:#ff5c5c} .sev.high{background:#3a1016;color:#ff8c8c}
.sev.medium{background:#3a2a10;color:#f5b942} .sev.low{background:#16324a;color:#5cc5ff} .sev.info{background:#1c2a47;color:#8b96ad}
.mono{font-family:ui-monospace,monospace;font-size:12px} pre{background:#0a0f1d;border:1px solid var(--line);border-radius:8px;padding:10px;overflow:auto;white-space:pre-wrap}
.finding{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px;margin:12px 0}
.finding h3{margin:0 0 8px;color:var(--fg)} .finding p{margin:6px 0}
.pill{display:inline-flex;align-items:center;gap:4px;padding:2px 8px;border-radius:999px;
  border:1px solid var(--line);background:var(--panel2,#182238);font-size:11px;color:var(--muted);margin-right:4px}
.muted{color:var(--muted)}
</style></head><body>
<h1>VALEN — Penetration Test Report</h1>
<div class="meta">__META__</div>
__ENGAGEMENT__
<div class="kpi">
  <div><b>__N__</b><br><span>findings</span></div>
  <div><b>__N_CRIT__</b><br><span>critical / high</span></div>
  <div><b>recall __BOLA_RECALL__ / precision __BOLA_PREC__</b><br><span>BOLA detector (crAPI)</span></div>
</div>
<h2>Executive summary</h2>
<p>VALEN discovered and, where authorized, actively validated the following structural
security findings. Each carries a CVSS 3.1 base score (or a custom analyst-adjusted
vector), CWE / OWASP / MITRE classification and the reproduction evidence.</p>
<h2>Risk matrix</h2>
__RISK__
<h2>Findings</h2>
<table><tr><th>Finding</th><th>Severity</th><th>CVSS</th><th>Vector</th><th>CWE</th><th>OWASP</th></tr>__ROWS__</table>
<h2>Finding details</h2>
__DETAILS__
<h2>Attack plan (kill chain)</h2>
__KILLCHAIN__
<h2>Proof of concepts</h2>
__POCS__
<h2>Autonomous pentest results</h2>
__PENTEST__
<h2>Reconnaissance</h2>
<p>Hosts: __RECON__</p>
<p>Shadow endpoints (enumerated, not in the published spec): __SHADOW__</p>
<h2>Remediation priority</h2>
__REMEDIATION__
</body></html>"""


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
_BUILDERS = {
    "html": build_html,
    "md": build_markdown,
    "markdown": build_markdown,
    "json": build_json,
    "sarif": build_sarif,
}


def main() -> int:
    ap = argparse.ArgumentParser(
        prog="valen report",
        description="Generate a pentest report (HTML / Markdown / JSON / SARIF / PDF).",
    )
    ap.add_argument("--format", default="html",
                    choices=sorted(_BUILDERS) + ["pdf", "all"],
                    help="output format (default: html)")
    ap.add_argument("--out", default=None,
                    help="output path (default: benchmarks/report.<ext>)")
    ap.add_argument("--client", default="", help="engagement: client name")
    ap.add_argument("--scope", default="", help="engagement: target scope")
    ap.add_argument("--author", default="", help="engagement: report author")
    ap.add_argument("--date-start", default="", help="engagement: start date")
    ap.add_argument("--date-end", default="", help="engagement: end date")
    ap.add_argument("--roe", default="", help="engagement: rules of engagement")
    ap.add_argument("--limitations", default="", help="engagement: limitations")
    args = ap.parse_args()

    engagement = Engagement(
        client=args.client, scope=args.scope, author=args.author,
        date_start=args.date_start, date_end=args.date_end,
        roe=args.roe, limitations=args.limitations,
    )
    data = collect_report_data(engagement)

    def _ext(fmt: str) -> str:
        return {"markdown": "md", "md": "md", "html": "html", "pdf": "pdf",
                "json": "json", "sarif": "sarif"}.get(fmt, fmt)

    def _emit(fmt: str, path: Path) -> None:
        if fmt == "pdf":
            html_path = path.with_suffix(".html")
            html_path.write_text(build_html(data), encoding="utf-8")
            ok = to_pdf(html_path, path)
            print(f"pdf    -> {path.relative_to(ROOT) if path.is_relative_to(ROOT) else path} "
                  f"({'ok' if ok else 'chrome headless unavailable'})")
        else:
            body = _BUILDERS[fmt](data)
            path.write_text(body, encoding="utf-8")
            print(f"{fmt:6} -> {path.relative_to(ROOT) if path.is_relative_to(ROOT) else path}")

    fmts = ["html", "md", "json", "sarif"] if args.format == "all" else [args.format]
    for fmt in fmts:
        ext = _ext(fmt)
        out = Path(args.out) if args.out else (BENCH / f"report.{ext}")
        if args.format == "all":
            out = (BENCH / f"report.{ext}")
        _emit(fmt, out)

    print(f"findings: {len(data['findings'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

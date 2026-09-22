"""Pentest report generator: HTML (self-contained) + PDF (Chrome headless).

Assembles the attack plan, findings, PoCs, exploitation evidence, recon and
enumeration into a professional report with an executive summary, per-finding
CVSS 3.1 base scores, reproduction steps, evidence, and remediation.
"""

from __future__ import annotations

import json
import math
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple

ROOT = Path(__file__).resolve().parents[2]
BENCH = ROOT / "benchmarks"


# ---------------------------------------------------------------------------
# CVSS 3.1 base score (compact)
# ---------------------------------------------------------------------------
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}   # scope unchanged
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}    # scope changed
_UI = {"N": 0.85, "R": 0.62}
_IMP = {"H": 0.56, "L": 0.22, "N": 0.0}


def cvss_base(av: str, ac: str, pr: str, ui: str, s: str, c: str, i: str, a: str) -> Tuple[str, float]:
    scope_changed = s == "C"
    pr_w = _PR_C if scope_changed else _PR_U
    iss = 1 - (1 - _IMP[c]) * (1 - _IMP[i]) * (1 - _IMP[a])
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
    exploit = 8.22 * _AV[av] * _AC[ac] * pr_w[pr] * _UI[ui]
    score = math.ceil(min(impact + exploit, 10.0) * 10) / 10 if impact > 0 else 0.0
    vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"
    return vector, score


# category -> (AV, AC, PR, UI, S, C, I, A)
_CVSS_BY_CATEGORY = {
    "idor":               ("N", "L", "L", "N", "U", "H", "N", "N"),
    "missing_authorization": ("N", "L", "N", "N", "U", "H", "H", "N"),
    "sql":                ("N", "L", "L", "N", "U", "H", "H", "H"),
    "command_execution":  ("N", "L", "L", "N", "U", "H", "H", "H"),
    "code_execution":     ("N", "L", "L", "N", "U", "H", "H", "H"),
    "deserialization":    ("N", "L", "L", "N", "U", "H", "H", "H"),
    "path_traversal":     ("N", "L", "L", "N", "U", "H", "N", "N"),
    "file_write":         ("N", "L", "L", "N", "U", "H", "N", "N"),
    "account_takeover":   ("N", "L", "N", "N", "U", "H", "H", "H"),
    "reentrancy":         ("N", "H", "L", "N", "U", "H", "H", "H"),
    "state_cycle":        ("N", "H", "L", "N", "U", "H", "H", "H"),
}


def cvss_for(category: str) -> Tuple[str, float]:
    params = _CVSS_BY_CATEGORY.get(category, ("N", "L", "L", "N", "U", "H", "N", "N"))
    return cvss_base(*params)


def severity_name(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0:
        return "Low"
    return "Info"


# ---------------------------------------------------------------------------
# Data assembly
# ---------------------------------------------------------------------------
def _j(name: str) -> dict:
    p = BENCH / name
    return json.loads(p.read_text()) if p.exists() else {}


def collect_report_data() -> Dict:
    plan = _j("attack_plan.json").get("steps", [])
    exploit = _j("exploit_results.json")
    bola = _j("crapi_bola_results.json")
    recon = _j("recon_plan.json")
    enum = _j("enum_results.json")

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
                "evidence": t.get("evidence", ""), "remediation": "verify JWT signature; reject alg=none/HS256 with a key-id; pin the algorithm.",
            })
    for h in exploit.get("idor", []):
        vec, score = cvss_for("idor")
        findings.append({
            "title": f"BOLA/IDOR: cross-user access to {h['path']}",
            "category": "idor", "severity": severity_name(score), "cvss": score, "vector": vec,
            "repro": f"attacker token -> GET {h['path']}",
            "evidence": h.get("evidence", ""), "remediation": "enforce object-level ownership on every resource id.",
        })
    # nuclei-verified findings from the plan
    for s in plan:
        if s.get("tactic_id") in ("TA0002", "TA0006") and "detail" in s:
            cat = "sql" if s["tactic_id"] == "TA0006" else "code_execution"
            vec, score = cvss_for(cat)
            findings.append({
                "title": s["title"], "category": cat, "severity": severity_name(score),
                "cvss": score, "vector": vec, "repro": s.get("detail", ""),
                "evidence": s.get("detail", ""), "remediation": "apply the vendor patch for the matched template.",
            })

    return {
        "findings": findings,
        "plan_steps": plan,
        "bola": bola,
        "recon_hosts": recon.get("hosts", []),
        "recon_cve_hints": recon.get("cve_hypotheses", []),
        "enum_shadow": enum.get("shadow_endpoints", []),
    }


def build_report(data: Dict) -> str:
    findings = data["findings"]
    rows = "".join(
        f"<tr><td>{esc(f['title'])}</td><td><span class='sev {f['severity'].lower()}'>{f['severity']}</span></td>"
        f"<td class='mono'>{f['cvss']:.1f}</td><td class='mono'>{esc(f['vector'])}</td></tr>"
        for f in findings
    )
    details = "".join(
        f"<div class='finding'><h3>{esc(f['title'])}</h3>"
        f"<p><b>Severity:</b> {f['severity']} ({f['cvss']:.1f}) · <span class='mono'>{esc(f['vector'])}</span></p>"
        f"<p><b>Reproduction:</b> {esc(f['repro'])}</p>"
        f"<pre>{esc(f['evidence'][:600])}</pre>"
        f"<p><b>Remediation:</b> {esc(f['remediation'])}</p></div>"
        for f in findings
    )
    n_crit = sum(1 for f in findings if f["severity"] in ("Critical", "High"))
    recon_desc = ", ".join(f"{h['ip']}" for h in data["recon_hosts"][:8])
    shadow = ", ".join(data["enum_shadow"][:8])

    return _HTML.format(
        n=len(findings), n_crit=n_crit, rows=rows, details=details,
        recon=esc(recon_desc or "—"), shadow=esc(shadow or "—"),
        bola_recall=f"{data['bola'].get('recall', 0):.2f}",
        bola_prec=f"{data['bola'].get('precision', 0):.2f}",
    )


def esc(s) -> str:
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


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


_HTML = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>VALEN — Penetration Test Report</title>
<style>
:root{{--bg:#0b1020;--panel:#121a30;--line:#22304d;--fg:#e6ebf5;--muted:#8b96ad;--accent:#4f8cff}}
*{{box-sizing:border-box}} body{{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;padding:28px}}
h1{{color:var(--accent);margin:0 0 4px}} h2{{color:var(--accent);border-bottom:1px solid var(--line);padding-bottom:6px;margin-top:28px}}
.meta{{color:var(--muted);font-size:12px;margin-bottom:20px}}
.kpi{{display:flex;gap:16px;flex-wrap:wrap}} .kpi div{{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 20px}}
.kpi b{{font-size:22px}} .kpi span{{color:var(--muted);font-size:12px}}
table{{border-collapse:collapse;width:100%;margin:12px 0}} th,td{{text-align:left;padding:8px;border-bottom:1px solid var(--line);vertical-align:top}}
th{{color:var(--accent)}} .sev{{padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600}}
.sev.critical{{background:#3a1016;color:#ff5c5c}} .sev.high{{background:#3a1016;color:#ff8c8c}}
.sev.medium{{background:#3a2a10;color:#f5b942}} .sev.low{{background:#16324a;color:#5cc5ff}} .sev.info{{background:#1c2a47;color:#8b96ad}}
.mono{{font-family:ui-monospace,monospace;font-size:12px}} pre{{background:#0a0f1d;border:1px solid var(--line);border-radius:8px;padding:10px;overflow:auto;white-space:pre-wrap}}
.finding{{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px;margin:12px 0}}
.finding h3{{margin:0 0 8px;color:var(--fg)}} .finding p{{margin:6px 0}}
</style></head><body>
<h1>VALEN — Penetration Test Report</h1>
<div class="meta">Verification And Active Logic Engine, Neuro-symbolic · authorized engagement · generated from machine-checkable evidence</div>
<div class="kpi">
  <div><b>{n}</b><br><span>findings</span></div>
  <div><b>{n_crit}</b><br><span>critical / high</span></div>
  <div><b>recall {bola_recall} / precision {bola_prec}</b><br><span>BOLA detector (crAPI)</span></div>
</div>
<h2>Executive summary</h2>
<p>VALEN discovered and, where authorized, actively validated the following structural
security findings. Each carries a CVSS 3.1 base score and the reproduction evidence.</p>
<h2>Findings</h2>
<table><tr><th>Finding</th><th>Severity</th><th>CVSS</th><th>Vector</th></tr>{rows}</table>
<h2>Finding details</h2>{details}
<h2>Reconnaissance</h2>
<p>Hosts: {recon}</p>
<p>Shadow endpoints (enumerated, not in the published spec): {shadow}</p>
<h2>Remediation priority</h2>
<p>1. Enforce object-level authorization (ownership) on every resource id.<br>
2. Verify JWT signatures and pin the algorithm (reject alg=none and HS256 with a key-id).<br>
3. Patch the services matched by nuclei templates.</p>
</body></html>"""


def main() -> int:
    data = collect_report_data()
    html = build_report(data)
    html_path = ROOT / "benchmarks" / "report.html"
    html_path.write_text(html, encoding="utf-8")
    pdf_path = ROOT / "benchmarks" / "report.pdf"
    ok = to_pdf(html_path, pdf_path)
    print(f"report -> {html_path.relative_to(ROOT)}")
    print(f"pdf     -> {pdf_path.relative_to(ROOT)} ({'ok' if ok else 'chrome headless unavailable'})")
    print(f"findings: {len(data['findings'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

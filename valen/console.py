"""VALEN red-team console: a self-contained, styled HTML UI.

Reads the generated artifacts (recon plan, attack plan, PoCs, BOLA results, tool
status) and renders a single-file console. Works opened directly, or served from
``valen.server`` at ``/console``.

Usage:
    python -m valen.console            # writes valen_console.html
    python -m valen.console --out /tmp/c.html
    python -m valen.console --bootstrap  # also print install commands
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict

from .redteam.tools import bootstrap_commands, tool_status

ROOT = Path(__file__).resolve().parent.parent
BENCH = ROOT / "benchmarks"


def _j(name: str) -> Any:
    p = BENCH / name
    return json.loads(p.read_text()) if p.exists() else {}


def collect() -> Dict[str, Any]:
    return {
        "tools": tool_status(),
        "bootstrap": bootstrap_commands(),
        "recon": _j("recon_plan.json"),
        "plan": _j("attack_plan.json"),
        "pocs": _j("redteam_pocs.json"),
        "bola": _j("crapi_bola_results.json"),
        "llm": _j("llm_ablation.json").get("summary", {}),
    }


_PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VALEN — Red Team Console</title>
<style>
:root{
  --bg:#0b1020; --panel:#121a30; --panel2:#182238; --line:#22304d;
  --fg:#e6ebf5; --muted:#8b96ad; --accent:#4f8cff; --green:#2ecc71;
  --red:#ff5c5c; --amber:#f5b942; --violet:#a78bfa;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
  font:15px/1.5 -apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
header{padding:26px 32px 18px;border-bottom:1px solid var(--line);
  background:linear-gradient(180deg,#121a30,#0b1020)}
header h1{margin:0;font-size:26px;letter-spacing:.5px}
header h1 b{color:var(--accent)}
header .sub{color:var(--muted);margin-top:6px;font-size:13px}
header .acro{color:var(--violet);font-family:ui-monospace,monospace;font-size:12px;margin-top:8px}
.wrap{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:16px;padding:22px 32px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px 18px}
.card h2{margin:0 0 12px;font-size:15px;text-transform:uppercase;letter-spacing:.8px;color:var(--accent)}
.card.full{grid-column:1/-1}
.row{display:flex;align-items:center;justify-content:space-between;padding:7px 0;border-bottom:1px solid var(--panel2)}
.row:last-child{border-bottom:0}
.dot{width:9px;height:9px;border-radius:50%;display:inline-block;margin-right:8px}
.dot.ok{background:var(--green)} .dot.no{background:var(--red)}
.tool .pkg{color:var(--muted);font-size:12px}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600;margin-right:6px;background:#1c2a47;color:var(--muted)}
.badge.TA0007{background:#16324a;color:#5cc5ff}
.badge.TA0004{background:#3a2a10;color:var(--amber)}
.badge.TA0008{background:#3a2510;color:#ffb46b}
.badge.TA0009{background:#2a173a;color:var(--violet)}
.badge.TA0002{background:#3a1016;color:var(--red)}
.badge.TA0040{background:#3a1016;color:var(--red)}
.step{padding:9px 0;border-bottom:1px solid var(--panel2)}
.step .t{font-weight:600}
.step .d{color:var(--muted);font-size:12px;margin-top:2px;word-break:break-word}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;color:#c7d2ea}
pre{background:#0a0f1d;border:1px solid var(--line);border-radius:8px;padding:12px;overflow:auto;margin:8px 0}
code.hint{color:var(--amber)}
button{background:var(--accent);color:#04101f;border:0;border-radius:7px;padding:6px 12px;font-weight:600;cursor:pointer;font-size:12px}
button.ghost{background:transparent;color:var(--accent);border:1px solid var(--line)}
.metric{font-size:24px;font-weight:700;color:var(--green)}
.metric span{font-size:12px;color:var(--muted);font-weight:400}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.kpi{background:var(--panel2);border-radius:10px;padding:12px}
.cmd{background:#0a0f1d;border:1px solid var(--line);border-radius:8px;padding:10px;font-family:ui-monospace,monospace;font-size:12px;color:#9fe8b0;overflow:auto;white-space:pre-wrap}
details{margin:6px 0} summary{cursor:pointer;color:var(--accent);font-size:13px}
.hidden{display:none}
</style>
</head>
<body>
<header>
  <h1><b>VALEN</b> — Red Team Console</h1>
  <div class="sub">Verification And Active Logic Engine, Neuro-symbolic · structural invariants · machine-checkable witnesses</div>
  <div class="acro">recon → IR → hypotheses → PoC → live validation → kill-chain plan</div>
</header>
<div class="wrap" id="app"></div>
<script>
const DATA = JSON.parse(document.getElementById('data').textContent);
const esc = s => String(s).replace(/[&<>]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));

function toolsCard(){
  const rows = Object.entries(DATA.tools).map(([n,t]) =>
    `<div class="row tool"><div><span class="dot ${t.installed?'ok':'no'}"></span><b>${esc(n)}</b>
     <span class="pkg">· ${esc(t.pkg)} · ${esc(t.description)}</span></div>
     <span class="mono">${t.installed?esc(t.path||'ok'):'missing'}</span></div>`).join('');
  const boot = DATA.bootstrap && DATA.bootstrap.length
    ? `<pre>${esc(DATA.bootstrap.join('\n'))}</pre>` : '';
  return `<div class="card"><h2>Toolkit</h2>${rows}${boot}</div>`;
}

function reconCard(){
  const r = DATA.recon || {};
  const hyp = (r.cve_hypotheses||[]).map(h =>
    `<div class="row"><div>${esc(h.host)}:${h.port} <span class="mono">${esc(h.version)}</span></div><code class="hint">${esc(h.hypothesis)}</code></div>`).join('');
  return `<div class="card"><h2>Recon</h2>
    <div class="metric">${(r.hosts||[]).length}<span> hosts</span></div>
    <div class="row"><span>profile</span><span class="badge">${esc(r.profile||'-')}</span></div>
    ${r.nmap_command?`<div class="row"><span>nmap</span><span class="mono">${esc(r.nmap_command.join(' '))}</span></div>`:''}
    ${hyp?`<div class="step">CVE hypotheses</div>${hyp}`:''}</div>`;
}

function planCard(){
  const steps = (DATA.plan.steps || DATA.plan || []);
  const items = steps.map(s =>
    `<div class="step"><span class="badge ${esc(s.tactic_id)}">${esc(s.tactic_id)} ${esc(s.phase||'')}</span>
     <span class="t">${esc(s.title||'')}</span>
     ${s.chain?`<div class="d">${esc(s.chain.join(' · '))} ${s.z3_reachable?'· <span style="color:var(--green)">Z3 reachable</span>':''}</div>`:''}
     ${s.detail?`<div class="d">${esc(s.detail)}</div>`:''}</div>`).join('');
  return `<div class="card full"><h2>Attack Plan (kill-chain)</h2>${items}</div>`;
}

function pocsCard(){
  const ps = (DATA.pocs.pocs || DATA.pocs || []);
  const items = ps.map((p,i) =>
    `<details><summary><span class="badge">${esc(p.method)}</span> ${esc(p.path)}</summary>
     <pre>${esc(p.poc||'')}</pre>
     <button onclick="copyPoc(${i})">Copy</button></details>`).join('');
  return `<div class="card full"><h2>Proof-of-Concepts (${ps.length})</h2>${items}</div>`;
}

function bolaCard(){
  const b = DATA.bola || {};
  return `<div class="card"><h2>BOLA / IDOR (crAPI)</h2>
    <div class="grid2">
      <div class="kpi"><div class="metric">${b.recall!=null?b.recall.toFixed(2):'—'}<span> recall</span></div></div>
      <div class="kpi"><div class="metric">${b.precision!=null?b.precision.toFixed(2):'—'}<span> precision</span></div></div>
    </div>
    <div class="row"><span>documented BOLA/BFLA recovered</span><b>${b.tp}/${b.n_vulnerable}</b></div>
    <div class="row"><span>every BOLA endpoint authenticated</span><b>${b.vulnerable_authenticated==b.n_vulnerable?'yes':'no'}</b></div></div>`;
}

function llmCard(){
  const s = DATA.llm || {};
  return `<div class="card"><h2>Neuro-symbolic</h2>
    <div class="row"><span>detection/ranking agreement</span><b>${s.detection_agreement!=null?s.detection_agreement.toFixed(3):'—'}</b></div>
    <div class="row"><span>CWE change (interpretation)</span><b>${s.cwe_change_rate!=null?(s.cwe_change_rate*100).toFixed(0)+'%':'—'}</b></div></div>`;
}

window.copyPoc = i => {
  const ps = (DATA.pocs.pocs || DATA.pocs || []);
  navigator.clipboard && navigator.clipboard.writeText(ps[i].poc || '');
};

document.getElementById('app').innerHTML =
  toolsCard() + reconCard() + bolaCard() + llmCard() + planCard() + pocsCard();
</script>
<script type="application/json" id="data">__DATA__</script>
</body>
</html>
"""


def build_console() -> str:
    data = json.dumps(collect()).replace("</", "<\\/")
    return _PAGE.replace("__DATA__", data)


def main() -> int:
    ap = argparse.ArgumentParser(description="VALEN red-team console.")
    ap.add_argument("--out", type=str, default="valen_console.html")
    ap.add_argument("--bootstrap", action="store_true", help="print tool install commands")
    args = ap.parse_args()

    if args.bootstrap:
        from .redteam.tools import missing_tools
        missing = missing_tools()
        print("missing tools:", ", ".join(missing) if missing else "none")
        cmds = bootstrap_commands()
        print("\n".join(cmds) if cmds else "all tools installed")

    out = Path(args.out)
    out.write_text(build_console(), encoding="utf-8")
    print(f"VALEN console -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

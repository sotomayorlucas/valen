"""Shared visual identity for VALEN's web UI and dashboard.

Both ``webui.py`` (the live SPA served by ``server.py``) and ``dashboard.py``
(the static experiment dashboard) embed this fragment so they share the same
"modern terminal" look: a deep near-black palette, monospace for data, sans for
UI, and per-layer accent colours (spectral/topological/geometric/algebraic/
formal/taint) that double as the security-severity scale.

Self-contained by default, but the UI shells may opt into Tailwind / Chart.js /
D3 via CDN (the project's "no external deps" promise is about the *analysis*
core, not the presentation shell — and the pages still render without them).
"""

from __future__ import annotations

# Per-layer accent palette (also reused for severity and hypothesis status).
PALETTE = {
    "spectral": "#58a6ff",
    "topological": "#3fb950",
    "geometric": "#d29922",
    "algebraic": "#f85149",
    "formal": "#bc8cff",
    "directed": "#79c0ff",
    "taint": "#ff7b72",
    "bg": "#0a0e14",
    "panel": "#11161d",
    "panel2": "#161d27",
    "border": "#26303c",
    "text": "#e6edf3",
    "muted": "#8b949e",
}

# Accent colours for the layer cards / hypotheses, in display order.
LAYER_COLORS = [
    ("Spectral", "spectral"),
    ("Topological", "topological"),
    ("Geometric", "geometric"),
    ("Algebraic", "algebraic"),
    ("Formal", "formal"),
    ("Directed", "directed"),
]

CORE_CSS = r"""
:root{
  --bg:#0a0e14;--panel:#11161d;--panel2:#161d27;--border:#26303c;
  --text:#e6edf3;--muted:#8b949e;
  --spectral:#58a6ff;--topological:#3fb950;--geometric:#d29922;
  --algebraic:#f85149;--formal:#bc8cff;--directed:#79c0ff;--taint:#ff7b72;
  --mono:ui-monospace,'JetBrains Mono','IBM Plex Mono',Menlo,Consolas,monospace;
  --sans:system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;
}
*{box-sizing:border-box}
html,body{margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:var(--sans);font-size:14px;
  background-image:
    radial-gradient(1200px 600px at 15% -10%,rgba(88,166,255,.06),transparent 60%),
    radial-gradient(900px 500px at 100% 0%,rgba(188,140,255,.05),transparent 55%);
  background-attachment:fixed;}
.mono{font-family:var(--mono)}
.tab{display:none}.tab.on{display:block}
.panel{background:linear-gradient(180deg,var(--panel),var(--bg));border:1px solid var(--border);border-radius:12px}
.card{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:14px;
  transition:transform .12s ease,border-color .12s ease}
.card:hover{transform:translateY(-2px);border-color:var(--spectral)}
.metric{font-family:var(--mono);font-weight:700;font-size:22px;line-height:1.1}
.kicker{font-size:10px;text-transform:uppercase;letter-spacing:.12em;color:var(--muted)}
.h-sep{border-left:3px solid var(--spectral);padding-left:10px}
table{border-collapse:collapse;width:100%;font-size:12.5px}
th,td{padding:7px 10px;text-align:right;border-bottom:1px solid var(--border)}
th:first-child,td:first-child{text-align:left}
th{background:var(--panel2);color:var(--muted);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.04em}
tr:last-child td{border-bottom:none}
tbody tr:hover td{background:var(--panel2)}
.num{font-family:var(--mono)}
.pill{display:inline-flex;align-items:center;gap:6px;padding:2px 9px;border-radius:999px;
  border:1px solid var(--border);background:var(--panel2);font-size:11px;color:var(--muted)}
.dot{width:8px;height:8px;border-radius:50%;display:inline-block}
.scan{position:relative;overflow:hidden}
.scan::after{content:"";position:absolute;inset:0;pointer-events:none;
  background:repeating-linear-gradient(0deg,rgba(255,255,255,.015) 0 1px,transparent 1px 3px)}
.glow{box-shadow:0 0 24px -6px var(--spectral)}
a{color:var(--spectral);text-decoration:none}
button{cursor:pointer}
::-webkit-scrollbar{width:10px;height:10px}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:6px}
::-webkit-scrollbar-track{background:transparent}
"""


def head(title: str, *, tailwind: bool = True, extra: str = "") -> str:
    """Return the shared ``<head>`` fragment (styles + optional CDN shells)."""
    tw = (
        '<script src="https://cdn.tailwindcss.com"></script>'
        if tailwind
        else ""
    )
    return f"""<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>{title}</title>
{tw}
<style>{CORE_CSS}</style>
{extra}"""

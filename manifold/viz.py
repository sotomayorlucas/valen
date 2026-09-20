"""Visualization: render the vulnerability manifold as a self-contained HTML page.

The page draws the IR graph (nodes + typed edges) with a force-directed layout
seeded by the spectral embedding, colors nodes/edges by kind and taint, and lists
the agent's findings. No external JavaScript or CSS is required: the output is a
single ``.html`` file you can open in any browser.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from .ir import EdgeKind, Graph

if TYPE_CHECKING:
    from agent.agent import Report

_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>__TITLE__</title>
<style>
:root{--bg:#0d1117;--panel:#161b22;--text:#e6edf3;--muted:#8b949e;--border:#30363d;}
*{box-sizing:border-box;}
body{margin:0;font-family:system-ui,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--text);}
header{padding:14px 20px;border-bottom:1px solid var(--border);background:var(--panel);}
header h1{margin:0;font-size:18px;}
header .sub{color:var(--muted);font-size:12px;margin-top:4px;}
.layout{display:grid;grid-template-columns:1fr 340px;height:calc(100vh - 64px);}
svg{width:100%;height:100%;background:radial-gradient(circle at 50% 50%,#161b22 0%,#0d1117 100%);}
.node{cursor:pointer;}
.node circle{stroke-width:1.5px;}
.node text{fill:var(--text);font-size:11px;pointer-events:none;}
.node .lab{font-size:10px;fill:var(--muted);}
.edge{stroke-opacity:0.55;}
.side{overflow:auto;border-left:1px solid var(--border);background:var(--panel);padding:14px;}
.side h2{font-size:14px;margin:0 0 10px;}
.card{border:1px solid var(--border);border-radius:8px;padding:10px 12px;margin-bottom:10px;background:#0d1117;}
.card .status{font-size:10px;text-transform:uppercase;letter-spacing:.05em;font-weight:700;}
.card.confirmed .status{color:#3fb950;}
.card.candidate .status{color:#d29922;}
.card h3{margin:4px 0;font-size:13px;}
.card .meta{color:var(--muted);font-size:11px;}
.card .evidence{color:var(--muted);font-size:11px;margin-top:4px;font-family:ui-monospace,monospace;}
.legend{font-size:11px;color:var(--muted);margin-top:12px;line-height:1.7;}
.legend .sw{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:6px;vertical-align:middle;}
</style>
</head>
<body>
<header>
  <h1>MANIFOLD &mdash; vulnerability manifold</h1>
  <div class="sub">__SUBTITLE__</div>
</header>
<div class="layout">
  <svg id="map" viewBox="0 0 1200 800" preserveAspectRatio="xMidYMid meet"></svg>
  <aside class="side">
    <h2>Findings</h2>
    <div id="findings"></div>
    <div class="legend" id="legend"></div>
  </aside>
</div>
<script>
const data = __DATA__;
const COLORS = {
  source:"#f85149", sink:"#d29922", function:"#58a6ff", gate:"#bc8cff",
  module:"#30363d", assign:"#a5d6ff", call:"#bc8cff",
  statement:"#8b949e", block:"#8b949e", variable:"#79c0ff", parameter:"#79c0ff"
};
const EDGE_COLORS = { taint:"#f85149", call:"#58a6ff", data:"#3fb950", control:"#6e7681", trust:"#bc8cff", auth:"#d2a8ff" };
const W=1200, H=800, svg=document.getElementById("map");
const ns="http://www.w3.org/2000/svg";
const nodes=data.nodes, edges=data.edges;
const byId={}; nodes.forEach(n=>{ byId[n.id]=n; n.x=Math.random()*W; n.y=Math.random()*H; });

// force-directed layout
const N=nodes.length;
const iters = Math.max(60, 400 - N*2);
for(let it=0; it<iters; it++){
  for(let i=0;i<N;i++) for(let j=i+1;j<N;j++){
    let dx=nodes[i].x-nodes[j].x, dy=nodes[i].y-nodes[j].y;
    let d2=dx*dx+dy*dy+0.01, d=Math.sqrt(d2);
    let f=900/d2; dx/=d; dy/=d;
    nodes[i].x+=dx*f; nodes[i].y+=dy*f;
    nodes[j].x-=dx*f; nodes[j].y-=dy*f;
  }
  edges.forEach(e=>{
    const a=byId[e.src], b=byId[e.dst]; if(!a||!b) return;
    let dx=b.x-a.x, dy=b.y-a.y, d=Math.sqrt(dx*dx+dy*dy)||0.01;
    let f=(d-80)*0.015;
    a.x+=dx/d*f; a.y+=dy/d*f; b.x-=dx/d*f; b.y-=dy/d*f;
  });
  nodes.forEach(n=>{ n.x+=(W/2-n.x)*0.02; n.y+=(H/2-n.y)*0.02;
    n.x=Math.max(20,Math.min(W-20,n.x)); n.y=Math.max(20,Math.min(H-20,n.y)); });
}

// edges
edges.forEach(e=>{
  const a=byId[e.src], b=byId[e.dst]; if(!a||!b) return;
  const line=document.createElementNS(ns,"line");
  line.setAttribute("x1",a.x); line.setAttribute("y1",a.y);
  line.setAttribute("x2",b.x); line.setAttribute("y2",b.y);
  line.setAttribute("class","edge");
  line.setAttribute("stroke", EDGE_COLORS[e.kind]||"#6e7681");
  line.setAttribute("stroke-width", e.kind==="taint" ? 2.5 : 1);
  svg.appendChild(line);
});

// nodes
nodes.forEach(n=>{
  const g=document.createElementNS(ns,"g");
  g.setAttribute("class","node"); g.setAttribute("transform",`translate(${n.x},${n.y})`);
  const r = n.tainted ? 14 : 6 + Math.min(10, n.fiedler*8);
  const c=document.createElementNS(ns,"circle");
  c.setAttribute("r",r);
  c.setAttribute("fill", COLORS[n.kind]||"#8b949e");
  if(n.tainted) c.setAttribute("stroke","#f85149");
  g.appendChild(c);
  const t=document.createElementNS(ns,"text");
  t.setAttribute("y",-r-4); t.setAttribute("text-anchor","middle");
  t.textContent = n.label || n.id;
  g.appendChild(t);
  const t2=document.createElementNS(ns,"text");
  t2.setAttribute("y",r+14); t2.setAttribute("text-anchor","middle");
  t2.setAttribute("class","lab"); t2.textContent = n.kind;
  g.appendChild(t2);
  const title=document.createElementNS(ns,"title");
  title.textContent = `${n.kind} ${n.label||n.id} (line ${n.line})${n.tainted?" [tainted]":""}`;
  g.appendChild(title);
  svg.appendChild(g);
});

// findings panel
const panel=document.getElementById("findings");
(data.findings||[]).forEach(f=>{
  const d=document.createElement("div");
  d.className="card "+f.status;
  d.innerHTML = `<div class="status">${f.status}</div>
    <h3>${f.cwe?f.cwe+" &mdash; ":""}${f.title||""}</h3>
    <div class="meta">signal: ${f.signal} &middot; region: ${f.region} &middot; line ${f.line}</div>
    ${f.evidence?`<div class="evidence">${f.evidence}</div>`:""}`;
  panel.appendChild(d);
});
if(!(data.findings||[]).length){ panel.innerHTML="<div class='meta'>no findings</div>"; }

// legend
const legend=document.getElementById("legend");
legend.innerHTML = Object.keys(COLORS).map(k=>`<div><span class="sw" style="background:${COLORS[k]}"></span>${k}</div>`).join("") +
  Object.keys(EDGE_COLORS).map(k=>`<div><span class="sw" style="background:${EDGE_COLORS[k]};border-radius:2px;height:3px"></span>${k} edge</div>`).join("");
</script>
</body>
</html>
"""


def _node_data(graph: Graph, math: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    fiedler_map: Dict[str, float] = {}
    if math:
        order = math.get("node_order", [])
        fv = math.get("spectral", {}).get("call", {}).get("fiedler", [])
        fiedler_map = {oid: abs(v) for oid, v in zip(order, fv)}

    taint_nodes = set()
    for e in graph.edges(EdgeKind.TAINT):
        taint_nodes.add(e.src)
        taint_nodes.add(e.dst)

    return [
        {
            "id": n.id,
            "label": n.label or n.id,
            "kind": n.kind.value,
            "line": n.line,
            "fiedler": fiedler_map.get(n.id, 0.0),
            "tainted": n.id in taint_nodes,
        }
        for n in graph.nodes
    ]


def _edge_data(graph: Graph) -> List[Dict[str, str]]:
    return [{"src": e.src, "dst": e.dst, "kind": e.kind.value} for e in graph.edges()]


def _findings_data(report: Optional["Report"]) -> List[Dict[str, Any]]:
    if report is None:
        return []
    return [
        {
            "status": e.status,
            "cwe": e.cwe,
            "title": e.title,
            "signal": e.signal,
            "region": e.region,
            "line": e.line,
            "evidence": e.evidence,
        }
        for e in report.entries
    ]


def render_html(
    graph: Graph,
    math: Optional[Dict[str, Any]] = None,
    report: Optional["Report"] = None,
    *,
    title: str = "MANIFOLD",
    subtitle: str = "",
) -> str:
    """Render the manifold to a self-contained HTML document."""
    payload = {
        "nodes": _node_data(graph, math),
        "edges": _edge_data(graph),
        "findings": _findings_data(report),
    }
    html = _TEMPLATE.replace("__TITLE__", title)
    html = html.replace("__SUBTITLE__", subtitle)
    html = html.replace("__DATA__", json.dumps(payload))
    return html


def write_html(
    graph: Graph,
    path: str,
    math: Optional[Dict[str, Any]] = None,
    report: Optional["Report"] = None,
    *,
    title: str = "MANIFOLD",
    subtitle: str = "",
) -> None:
    """Write the rendered manifold HTML to ``path``."""
    with open(path, "w", encoding="utf-8") as f:
        f.write(render_html(graph, math, report, title=title, subtitle=subtitle))

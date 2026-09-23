"""Visualization: render the vulnerability valen as a self-contained HTML page.

The page draws the IR graph (nodes + typed edges) with an interactive
force-directed layout: pan & zoom (wheel + drag background), draggable nodes, a
live simulation that keeps spreading (so large graphs don't clump), hover that
highlights a node's neighbourhood, click-to-pin with a detail card, and
filter/search controls toggling node/edge kinds. No external JavaScript or CSS
is required: the output is a single ``.html`` file you can open in any browser.
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
:root{--bg:#0d1117;--panel:#161b22;--text:#e6edf3;--muted:#8b949e;--border:#30363d;
      --accent:#58a6ff;--danger:#f85149;}
*{box-sizing:border-box;}
body{margin:0;font-family:system-ui,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--text);}
header{padding:10px 16px;border-bottom:1px solid var(--border);background:var(--panel);
  display:flex;align-items:center;gap:14px;flex-wrap:wrap;}
header h1{margin:0;font-size:15px;white-space:nowrap;}
header .sub{color:var(--muted);font-size:12px;}
.toolbar{display:flex;align-items:center;gap:8px;margin-left:auto;}
.toolbar button{background:#21262d;border:1px solid var(--border);color:var(--text);
  border-radius:6px;padding:5px 10px;font-size:12px;cursor:pointer;}
.toolbar button:hover{background:#30363d;}
.toolbar input{background:#0d1117;border:1px solid var(--border);color:var(--text);
  border-radius:6px;padding:5px 10px;font-size:12px;width:170px;}
.layout{display:grid;grid-template-columns:1fr 340px;height:calc(100vh - 62px);}
#stage{position:relative;overflow:hidden;background:radial-gradient(circle at 50% 50%,#161b22 0%,#0d1117 100%);}
svg{position:absolute;inset:0;width:100%;height:100%;}
.node{cursor:grab;}
.node.dragging{cursor:grabbing;}
.node circle{stroke-width:1.5px;}
.node.dim, .edge.dim{opacity:0.12;}
.node text{fill:var(--text);font-size:11px;pointer-events:none;}
.node .lab{font-size:9px;fill:var(--muted);}
.edge{stroke-opacity:0.5;}
.side{overflow:auto;border-left:1px solid var(--border);background:var(--panel);padding:14px;}
.side h2{font-size:14px;margin:0 0 10px;}
.card{border:1px solid var(--border);border-radius:8px;padding:10px 12px;margin-bottom:10px;background:#0d1117;}
.card .status{font-size:10px;text-transform:uppercase;letter-spacing:.05em;font-weight:700;}
.card.confirmed .status{color:#3fb950;}
.card.candidate .status{color:#d29922;}
.card h3{margin:4px 0;font-size:13px;}
.card .meta{color:var(--muted);font-size:11px;}
.card .evidence{color:var(--muted);font-size:11px;margin-top:4px;font-family:ui-monospace,monospace;}
#detail{border:1px solid var(--accent);border-radius:8px;padding:10px 12px;margin-bottom:10px;background:#0d1117;display:none;}
#detail .k{color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.05em;}
#detail .t{font-size:13px;margin:3px 0;}
#detail .m{color:var(--muted);font-size:11px;font-family:ui-monospace,monospace;}
.legend{font-size:11px;color:var(--muted);margin-top:12px;line-height:1.9;}
.legend .row{cursor:pointer;user-select:none;}
.legend .row.off{opacity:0.35;}
.legend .sw{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:6px;vertical-align:middle;}
.legend .e-sw{display:inline-block;width:10px;height:3px;border-radius:2px;margin-right:6px;vertical-align:middle;}
#tooltip{position:absolute;pointer-events:none;background:#161b22;border:1px solid var(--border);
  border-radius:6px;padding:6px 9px;font-size:11px;max-width:260px;display:none;z-index:10;}
#hint{position:absolute;left:10px;bottom:10px;color:var(--muted);font-size:11px;pointer-events:none;}
</style>
</head>
<body>
<header>
  <h1>VALEN &mdash; vulnerability valen</h1>
  <div class="sub">__SUBTITLE__</div>
  <div class="toolbar">
    <input id="search" type="text" placeholder="filter by name / kind / line…"/>
    <button id="fit" title="fit to view">fit</button>
    <button id="zoomin" title="zoom in">+</button>
    <button id="zoomout" title="zoom out">&minus;</button>
    <button id="pause" title="pause / resume layout">pause</button>
  </div>
</header>
<div class="layout">
  <div id="stage">
    <svg id="map"></svg>
    <div id="tooltip"></div>
    <div id="hint">wheel = zoom &middot; drag background = pan &middot; drag node = move &middot; click node = pin</div>
  </div>
  <aside class="side">
    <h2>Node detail</h2>
    <div id="detail"></div>
    <h2>Findings</h2>
    <div id="findings"></div>
    <div class="legend" id="legend"></div>
  </aside>
</div>
<script>
"use strict";
const data = __DATA__;
const COLORS = {
  source:"#f85149", sink:"#d29922", function:"#58a6ff", gate:"#bc8cff",
  module:"#30363d", assign:"#a5d6ff", call:"#bc8cff",
  statement:"#8b949e", block:"#8b949e", variable:"#79c0ff", parameter:"#79c0ff"
};
const EDGE_COLORS = { taint:"#f85149", call:"#58a6ff", data:"#3fb950", control:"#6e7681", trust:"#bc8cff", auth:"#d2a8ff" };
const NS="http://www.w3.org/2000/svg";
const svg=document.getElementById("map");
const stage=document.getElementById("stage");

function radius(n){ return n.tainted ? 14 : 6 + Math.min(10, (n.fiedler||0)*8); }

const nodes = data.nodes.map(n => ({...n, x:0, y:0, vx:0, vy:0, r:radius(n), fixed:false}));
const byId = {}; nodes.forEach(n => byId[n.id] = n);
const edges = data.edges.slice();
const N = nodes.length;

// seed positions on a spiral (reduces the initial clump for large graphs)
nodes.forEach((n,i)=>{
  const a = i * 2.39996; const R = 30 * Math.sqrt(i+1);
  n.x = 600 + Math.cos(a)*R; n.y = 400 + Math.sin(a)*R;
});

// ---- world transform (pan/zoom) ----
const world = document.createElementNS(NS,"g");
svg.appendChild(world);
let view = {x:0, y:0, k:1};
function applyView(){ world.setAttribute("transform", `translate(${view.x},${view.y}) scale(${view.k})`); }

// ---- build static elements ----
const edgeEls = new Map();
edges.forEach((e,idx)=>{
  const line=document.createElementNS(NS,"line");
  line.setAttribute("class","edge");
  line.setAttribute("stroke", EDGE_COLORS[e.kind]||"#6e7681");
  line.setAttribute("stroke-width", e.kind==="taint" ? 2.5 : 1);
  line.setAttribute("data-src", e.src); line.setAttribute("data-dst", e.dst);
  line.setAttribute("data-kind", e.kind);
  world.appendChild(line);
  edgeEls.set(idx, line);
});

const nodeEls = new Map();
nodes.forEach(n=>{
  const g=document.createElementNS(NS,"g");
  g.setAttribute("class","node");
  g.setAttribute("data-id", n.id);
  const c=document.createElementNS(NS,"circle");
  c.setAttribute("r", n.r);
  c.setAttribute("fill", COLORS[n.kind]||"#8b949e");
  if(n.tainted) c.setAttribute("stroke","#f85149");
  g.appendChild(c);
  const t=document.createElementNS(NS,"text");
  t.setAttribute("y",-n.r-4); t.setAttribute("text-anchor","middle");
  t.textContent = n.label || n.id;
  g.appendChild(t);
  const t2=document.createElementNS(NS,"text");
  t2.setAttribute("y", n.r+13); t2.setAttribute("text-anchor","middle");
  t2.setAttribute("class","lab"); t2.textContent = n.kind;
  g.appendChild(t2);
  const title=document.createElementNS(NS,"title");
  title.textContent = `${n.kind} ${n.label||n.id} (line ${n.line})${n.tainted?" [tainted]":""}`;
  g.appendChild(title);
  world.appendChild(g);
  nodeEls.set(n.id, g);
});

// ---- visibility / filter state ----
const hiddenKinds = new Set();
const hiddenEdgeKinds = new Set();
let search = "";
let hovered = null, selected = null;
const neighborCache = new Map();

function neighbors(id){
  if(neighborCache.has(id)) return neighborCache.get(id);
  const s = new Set([id]);
  edges.forEach(e=>{ if(e.src===id) s.add(e.dst); if(e.dst===id) s.add(e.src); });
  neighborCache.set(id, s); return s;
}

function nodeVisible(n){
  if(hiddenKinds.has(n.kind)) return false;
  if(!search) return true;
  const q=search.toLowerCase();
  return (n.label||n.id).toLowerCase().includes(q)
      || n.kind.toLowerCase().includes(q)
      || String(n.line).includes(q);
}
function edgeVisible(e){
  if(hiddenEdgeKinds.has(e.kind)) return false;
  const a=byId[e.src], b=byId[e.dst];
  return a && b && nodeVisible(a) && nodeVisible(b);
}

function applyVisibility(){
  nodes.forEach(n=>{
    const el=nodeEls.get(n.id);
    el.style.display = nodeVisible(n) ? "" : "none";
  });
  edgeEls.forEach((line,idx)=>{
    const e=edges[idx];
    line.style.display = edgeVisible(e) ? "" : "none";
  });
  applyHighlight();
}

function applyHighlight(){
  const focusSet = hovered ? neighbors(hovered) : (selected ? neighbors(selected) : null);
  nodes.forEach(n=>{
    const el=nodeEls.get(n.id);
    if(!nodeVisible(n)) return;
    if(focusSet && !focusSet.has(n.id)) el.classList.add("dim");
    else el.classList.remove("dim");
  });
  edgeEls.forEach((line,idx)=>{
    const e=edges[idx];
    if(!edgeVisible(e)) return;
    if(focusSet && focusSet.has(e.src) && focusSet.has(e.dst)) line.classList.remove("dim");
    else if(focusSet) line.classList.add("dim");
    else line.classList.remove("dim");
  });
}

// ---- physics ----
let alpha=1, running=true;
const alphaMin=0.01, velocityDecay=0.6;
const K = 1200 * Math.sqrt(N);   // repulsion scale grows with graph size

function tick(){
  // repulsion + collision (soft, O(n^2) with a floor distance)
  for(let i=0;i<N;i++){
    const a=nodes[i];
    for(let j=i+1;j<N;j++){
      const b=nodes[j];
      let dx=a.x-b.x, dy=a.y-b.y;
      let d2=dx*dx+dy*dy;
      const min=(a.r+b.r+22); const m2=min*min;
      if(d2<m2){ d2=m2; dx*=min/Math.sqrt(dx*dx+dy*dy+1e-6); dy*=min/Math.sqrt(dx*dx+dy*dy+1e-6); }
      const d=Math.sqrt(d2), f=K/d2;
      const fx=dx/d*f, fy=dy/d*f;
      a.vx+=fx; a.vy+=fy; b.vx-=fx; b.vy-=fy;
    }
  }
  edges.forEach(e=>{
    const a=byId[e.src], b=byId[e.dst]; if(!a||!b) return;
    let dx=b.x-a.x, dy=b.y-a.y, d=Math.sqrt(dx*dx+dy*dy)||1;
    const rest=a.r+b.r+50, f=(d-rest)*0.06;
    a.vx+=dx/d*f; a.vy+=dy/d*f; b.vx-=dx/d*f; b.vy-=dy/d*f;
  });
  nodes.forEach(n=>{
    n.vx += (600-n.x)*0.0025; n.vy += (400-n.y)*0.0025;
  });
  nodes.forEach(n=>{
    if(n.fixed){ n.vx=0; n.vy=0; return; }
    n.vx*=velocityDecay; n.vy*=velocityDecay;
    n.x+=n.vx; n.y+=n.vy;
  });
  alpha = Math.max(alphaMin, alpha * 0.975);
}

function draw(){
  nodes.forEach(n=>{
    const el=nodeEls.get(n.id);
    el.setAttribute("transform", `translate(${n.x},${n.y})`);
  });
  edgeEls.forEach((line,idx)=>{
    const e=edges[idx]; const a=byId[e.src], b=byId[e.dst];
    if(!a||!b) return;
    line.setAttribute("x1",a.x); line.setAttribute("y1",a.y);
    line.setAttribute("x2",b.x); line.setAttribute("y2",b.y);
  });
}

function loop(){
  if(running){
    const steps = N>600 ? 1 : 3;
    for(let i=0;i<steps;i++) tick();
    draw();
    if(alpha>alphaMin*1.05) requestAnimationFrame(loop);
    else running=false;
  }
}
function reheat(){ alpha=1; if(!running){ running=true; loop(); } }

// ---- interaction: pan / zoom ----
function toWorld(px,py){
  const r=svg.getBoundingClientRect();
  return [(px-r.left-view.x)/view.k, (py-r.top-view.y)/view.k];
}
let panning=null;
svg.addEventListener("pointerdown", e=>{
  if(e.target.closest && e.target.closest(".node")) return;
  panning={x:e.clientX, y:e.clientY, vx:view.x, vy:view.y};
  svg.setPointerCapture(e.pointerId);
});
svg.addEventListener("pointermove", e=>{
  if(panning){
    view.x = panning.vx + (e.clientX-panning.x);
    view.y = panning.vy + (e.clientY-panning.y);
    applyView();
  }
});
svg.addEventListener("pointerup", e=>{ panning=null; });
svg.addEventListener("wheel", e=>{
  e.preventDefault();
  const r=svg.getBoundingClientRect();
  const mx=e.clientX-r.left, my=e.clientY-r.top;
  const k1 = Math.max(0.05, Math.min(8, view.k * (e.deltaY<0 ? 1.12 : 0.89)));
  view.x = mx - (mx-view.x)*(k1/view.k);
  view.y = my - (my-view.y)*(k1/view.k);
  view.k = k1;
  applyView();
}, {passive:false});

// ---- node drag ----
let dragNode=null;
nodes.forEach(n=>{
  const el=nodeEls.get(n.id);
  el.addEventListener("pointerdown", e=>{
    e.stopPropagation();
    dragNode={n, dx:0, dy:0};
    n.fixed=true;
    el.classList.add("dragging");
    el.setPointerCapture(e.pointerId);
    reheat();
  });
  el.addEventListener("pointermove", e=>{
    if(!dragNode || dragNode.n!==n) return;
    const [wx,wy]=toWorld(e.clientX,e.clientY);
    n.x=wx; n.y=wy; draw();
  });
  el.addEventListener("pointerup", e=>{
    if(dragNode){ dragNode=null; n.fixed=false; el.classList.remove("dragging"); reheat(); }
  });
  el.addEventListener("pointerenter", ()=>{ hovered=n.id; applyHighlight(); });
  el.addEventListener("pointerleave", ()=>{ if(hovered===n.id){ hovered=null; applyHighlight(); } });
  el.addEventListener("click", ()=>{ selected=n.id; showDetail(n); applyHighlight(); });
});

function showDetail(n){
  const d=document.getElementById("detail");
  d.style.display="block";
  d.innerHTML=`<div class="k">${n.kind}</div>
    <div class="t">${n.label||n.id}</div>
    <div class="m">line ${n.line}${n.tainted?" &middot; tainted":""} &middot; fiedler ${(n.fiedler||0).toFixed(3)} &middot; ${neighbors(n.id).size-1} neighbors</div>`;
}

// ---- toolbar ----
function fit(){
  if(!N) return;
  let x0=1e9,y0=1e9,x1=-1e9,y1=-1e9;
  nodes.forEach(n=>{ x0=Math.min(x0,n.x-n.r); y0=Math.min(y0,n.y-n.r); x1=Math.max(x1,n.x+n.r); y1=Math.max(y1,n.y+n.r); });
  const r=svg.getBoundingClientRect();
  const k=Math.min(r.width/(x1-x0||1), r.height/(y1-y0||1)) * 0.9;
  view.k=Math.max(0.05,Math.min(4,k));
  view.x=(r.width/2)-((x0+x1)/2)*view.k;
  view.y=(r.height/2)-((y0+y1)/2)*view.k;
  applyView();
}
document.getElementById("fit").onclick=fit;
document.getElementById("zoomin").onclick=()=>{ view.k=Math.min(8,view.k*1.3); applyView(); };
document.getElementById("zoomout").onclick=()=>{ view.k=Math.max(0.05,view.k*0.77); applyView(); };
document.getElementById("pause").onclick=e=>{
  running=!running; e.target.textContent=running?"pause":"resume"; if(running){ alpha=1; loop(); }
};
document.getElementById("search").addEventListener("input", e=>{
  search=e.target.value; applyVisibility();
});

// ---- findings panel ----
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

// ---- legend with toggles ----
const legend=document.getElementById("legend");
const nodeKinds=Object.keys(COLORS);
nodeKinds.forEach(k=>{
  const row=document.createElement("div"); row.className="row";
  row.innerHTML=`<span class="sw" style="background:${COLORS[k]}"></span>${k}`;
  row.onclick=()=>{ if(hiddenKinds.has(k)) hiddenKinds.delete(k); else hiddenKinds.add(k);
    row.classList.toggle("off", hiddenKinds.has(k)); applyVisibility(); };
  legend.appendChild(row);
});
legend.appendChild(document.createElement("div")).style.cssText="height:8px";
Object.keys(EDGE_COLORS).forEach(k=>{
  const row=document.createElement("div"); row.className="row";
  row.innerHTML=`<span class="e-sw" style="background:${EDGE_COLORS[k]}"></span>${k} edge`;
  row.onclick=()=>{ if(hiddenEdgeKinds.has(k)) hiddenEdgeKinds.delete(k); else hiddenEdgeKinds.add(k);
    row.classList.toggle("off", hiddenEdgeKinds.has(k)); applyVisibility(); };
  legend.appendChild(row);
});

// ---- start ----
applyView();
draw();
fit();
alpha=1; running=true; loop();
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
    title: str = "VALEN",
    subtitle: str = "",
) -> str:
    """Render the valen to a self-contained HTML document."""
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
    title: str = "VALEN",
    subtitle: str = "",
) -> None:
    """Write the rendered valen HTML to ``path``."""
    with open(path, "w", encoding="utf-8") as f:
        f.write(render_html(graph, math, report, title=title, subtitle=subtitle))

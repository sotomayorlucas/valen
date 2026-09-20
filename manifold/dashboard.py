"""Self-contained HTML dashboard for MANIFOLD.

Aggregates every experiment artifact into one page: the prioritization oracle
(MRR / AUC / cost curve), the OWASP Benchmark table, the ablation, the per-kernel
scalability curves, an interactive manifold explorer over the bundled examples,
and copy-paste usage recipes. No server or external JS is required.

    python -m manifold.dashboard --out dashboard.html
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any, Dict, List

from .analysis.math_core import run_core
from .ingest import analyze, infer_adapter
from .viz import _edge_data, _findings_data, _node_data

ROOT = Path(__file__).resolve().parent.parent
BENCH = ROOT / "benchmarks"


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text()) if path.exists() else None


def _read_scale() -> List[dict]:
    path = BENCH / "scale_results.csv"
    if not path.exists():
        return []
    rows = []
    with path.open() as f:
        for row in csv.reader(f):
            if len(row) != 4 or row[0] == "kernel":
                continue
            kernel, edges, nodes, ms = row
            if ms in ("", "NA"):
                continue
            rows.append({"kernel": kernel, "edges": int(edges),
                         "nodes": int(nodes), "ms": float(ms)})
    return rows


def _build_examples() -> List[dict]:
    examples = ROOT / "examples"
    out: List[dict] = []
    for source in sorted(examples.rglob("*")):
        if not source.is_file() or source.suffix not in (".py", ".json", ".asm"):
            continue
        code = source.read_text()
        adapter = infer_adapter(code, source.name)
        result = analyze(code, path=source.name, adapter=adapter)
        try:
            math = run_core(result.graph)
            nodes = _node_data(result.graph, math)
        except Exception:
            nodes = _node_data(result.graph, None)
        out.append({
            "name": str(source.relative_to(examples)),
            "adapter": adapter,
            "nodes": nodes,
            "edges": _edge_data(result.graph),
            "findings": [
                {"severity": f.severity, "category": f.category, "sink": f.sink_name, "line": f.line}
                for f in result.findings
            ],
        })
    return out


def load_data() -> Dict[str, Any]:
    oracle = _read_json(BENCH / "oracle_results.json") or {}
    owasp = _read_json(BENCH / "owasp_results.json") or {}
    ablation = _read_json(BENCH / "ablation_results.json") or {}
    cves = _read_json(BENCH / "cve_results.json") or []
    return {
        "oracle": oracle,
        "owasp": owasp,
        "ablation": ablation,
        "cves": cves,
        "scale": _read_scale(),
        "examples": _build_examples(),
    }


_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>MANIFOLD — dashboard</title>
<style>
:root{--bg:#0d1117;--panel:#161b22;--panel2:#1c2330;--text:#e6edf3;--muted:#8b949e;--border:#30363d;--accent:#58a6ff;--green:#3fb950;--red:#f85149;--amber:#d29922;--purple:#bc8cff;}
*{box-sizing:border-box;}
body{margin:0;font-family:system-ui,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--text);}
header{padding:18px 24px;border-bottom:1px solid var(--border);background:linear-gradient(120deg,#161b22,#0d1117);}
header h1{margin:0;font-size:22px;} header p{margin:4px 0 0;color:var(--muted);font-size:13px;}
main{padding:20px 24px;max-width:1200px;margin:0 auto;}
section{margin-bottom:28px;}
h2{font-size:16px;border-left:3px solid var(--accent);padding-left:10px;margin:0 0 12px;}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;}
.card{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:14px;}
.card .k{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.04em;}
.card .v{font-size:24px;font-weight:700;margin-top:6px;}
.card .s{color:var(--muted);font-size:11px;margin-top:2px;}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--border);border-radius:10px;overflow:hidden;font-size:13px;}
th,td{padding:7px 10px;text-align:right;border-bottom:1px solid var(--border);}
th:first-child,td:first-child{text-align:left;}
th{background:var(--panel2);color:var(--muted);font-weight:600;}
tr:last-child td{border-bottom:none;}
.two{display:grid;grid-template-columns:1fr 1fr;gap:16px;}
@media(max-width:820px){.two{grid-template-columns:1fr;}}
.chart{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:10px;}
pre{background:#0b0f14;border:1px solid var(--border);border-radius:8px;padding:12px;overflow:auto;font-size:12px;}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:8px;align-items:center;}
select,button{background:var(--panel2);color:var(--text);border:1px solid var(--border);border-radius:6px;padding:6px 10px;font-size:13px;}
#map{width:100%;height:460px;background:radial-gradient(circle at 50% 50%,#161b22,#0d1117);border:1px solid var(--border);border-radius:10px;}
.legend{font-size:11px;color:var(--muted);margin-top:8px;line-height:1.7;}
.sw{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:5px;vertical-align:middle;}
.badge{font-size:11px;padding:1px 7px;border-radius:10px;background:var(--panel2);color:var(--muted);}
</style>
</head>
<body>
<header>
  <h1>MANIFOLD — experiment dashboard</h1>
  <p>Prioritization oracle &middot; OWASP Benchmark 1.2 &middot; ablation &middot; scalability &middot; manifold explorer</p>
</header>
<main>
  <section id="summary"><h2>Summary</h2><div class="cards" id="cards"></div></section>

  <section id="methodology">
    <h2>Methodology</h2>
    <div class="chart" style="margin-bottom:14px"><svg id="pipeline" viewBox="0 0 1120 160"></svg></div>
    <div class="two">
      <div>
        <h3 style="font-size:13px;color:#8b949e">Mathematical layers &rarr; signal &rarr; evidence</h3>
        <div class="cards" id="layers"></div>
      </div>
      <div>
        <h3 style="font-size:13px;color:#8b949e">Evaluation protocol</h3>
        <div class="chart"><svg id="protocol" viewBox="0 0 560 360"></svg></div>
      </div>
    </div>
    <h3 style="font-size:13px;color:#8b949e;margin-top:16px">Mapping laws (feature &rarr; vulnerability class)</h3>
    <div id="laws"></div>
  </section>

  <section id="oracle">
    <h2>Prioritization oracle (main experiment)</h2>
    <div class="two">
      <div class="chart"><svg id="cost" viewBox="0 0 560 320"></svg></div>
      <div class="chart"><svg id="auc" viewBox="0 0 560 320"></svg></div>
    </div>
    <div id="oracle-table" style="margin-top:14px"></div>
  </section>

  <section id="owasp"><h2>OWASP Benchmark 1.2</h2><div id="owasp-tables"></div></section>
  <section id="cves"><h2>Real CVE fixes</h2><div id="cve-table"></div></section>
  <section id="ablation"><h2>Ablation (Java adapter)</h2><div id="ablation-table"></div></section>
  <section id="scale"><h2>Scalability</h2><div class="chart"><svg id="scale" viewBox="0 0 900 340"></svg></div></section>

  <section id="explorer">
    <h2>Manifold explorer</h2>
    <div class="grid2" style="margin-bottom:8px">
      <select id="case"></select>
      <span class="badge" id="case-meta"></span>
    </div>
    <svg id="map" viewBox="0 0 1000 460" preserveAspectRatio="xMidYMid meet"></svg>
    <div class="legend" id="mlegend"></div>
  </section>

  <section id="usage"><h2>Use it with the experiment data</h2><pre id="recipes"></pre></section>
</main>
<script>
const DATA = __DATA__;
const $ = (s)=>document.querySelector(s);
const NS="http://www.w3.org/2000/svg";

// ---------- summary cards ----------
const o = DATA.oracle, auc = (o.signals_auc||{});
const adapterJ = 0.168, z3J = 0.057;
const cards = [
  ["taint MRR", (o.metrics&&o.metrics.taint?o.metrics.taint.mrr:"-"), "prioritization (main)"],
  ["field MRR", (o.metrics&&o.metrics.field?o.metrics.field.mrr:"-"), "V(x) fused"],
  ["taint AUC", (auc.taint?auc.taint.auc:"-"), "predict vulnerable sink"],
  ["geometric AUC", (auc.geometric?auc.geometric.auc:"-"), "below chance"],
  ["adapter F1", "0.681", "OWASP all categories"],
  ["Youden J", "0.168", "measured (adapter, all categories)"],
];
$("#cards").innerHTML = cards.map(([k,v,s])=>`<div class="card"><div class="k">${k}</div><div class="v">${v}</div><div class="s">${s}</div></div>`).join("");

// ---------- methodology: pipeline ----------
(function(){
  const svg=$("#pipeline");
  const boxes=[["artifact",""],["IR\ntyped graph",""],["math\nlayers",""],["V(x)\nfield",""],["LLM\nagent",""],["Z3\nverifier",""]];
  const W=1120,bw=150,bh=54,gap=30,x0=24,y=38;
  let s=`<defs><marker id="arr" markerWidth="9" markerHeight="9" refX="6" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6" fill="#58a6ff"/></marker></defs>`;
  boxes.forEach(([t],i)=>{
    const x=x0+i*(bw+gap);
    s+=`<rect x="${x}" y="${y}" width="${bw}" height="${bh}" rx="9" fill="#1c2330" stroke="#58a6ff"/>`;
    const lines=t.split("\n");
    lines.forEach((ln,li)=>s+=`<text x="${x+bw/2}" y="${y+bh/2+5+(li-(lines.length-1)/2)*15}" fill="#e6edf3" font-size="13" text-anchor="middle">${ln}</text>`);
    if(i<boxes.length-1) s+=`<line x1="${x+bw}" y1="${y+bh/2}" x2="${x+bw+gap-3}" y2="${y+bh/2}" stroke="#58a6ff" stroke-width="2" marker-end="url(#arr)"/>`;
  });
  const cx1=x0+5*(bw+gap)+bw/2, cx2=x0+1*(bw+gap)+bw/2;
  s+=`<path d="M${cx1},${y+bh} L${cx1},${y+bh+58} L${cx2},${y+bh+58} L${cx2},${y+bh}" fill="none" stroke="#8b949e" stroke-dasharray="5 4"/>`;
  s+=`<text x="${(cx1+cx2)/2}" y="${y+bh+50}" fill="#8b949e" font-size="11" text-anchor="middle">re-embed (confirm / refute)</text>`;
  svg.innerHTML=s;
})();

// ---------- methodology: layers ----------
(function(){
  const a=auc;
  const layers=[
    ["Spectral","L=D−A · Fiedler f₂ · embedding","|Fiedler|","spectral"],
    ["Topological (TDA)","persistent H₀/H₁ · Mapper","H₁ membership","topological"],
    ["Geometric","Ollivier / Forman Ricci · Sinkhorn","curvature κ","geometric"],
    ["Algebraic","taint lattice · Galois (α,γ) · auth functor F","taint tags","taint"],
    ["Formal","symbolic execution + SMT (Z3)","SAT(φ_bad)","formal"],
    ["Directed","Chung Laplacian · SCC + Perron","directed λ₂","directed"],
  ];
  $("#layers").innerHTML=layers.map(([n,d,sig,key])=>{
    let badge="", cls="";
    if(a[key]){const v=a[key].auc; const good=v>0.7, bad=v<0.45; cls=good?"var(--green)":(bad?"var(--red)":"var(--muted)");
      badge=`<span class="badge" style="color:${cls}">AUC ${v.toFixed(3)}</span>`;}
    else {badge=`<span class="badge">defined</span>`;}
    return `<div class="card"><div class="k">${n}</div><div style="font-size:13px;margin-top:6px">${d}</div>
      <div class="s" style="margin-top:6px">signal: ${sig} &nbsp; ${badge}</div></div>`;
  }).join("");
})();

// ---------- methodology: protocol ----------
(function(){
  const svg=$("#protocol"); const W=560; const steps=[
    ["enumerate all sink candidates","(source → sink reachability)"],
    ["rank candidates","DFS · raw taint · V(x) · random"],
    ["metrics","MRR · R@1 · NDCG@k · cost curve"],
    ["Z3 arbiter","SAT + concrete witness"],
  ];
  const bh=56,gap=22,y0=16,bw=440,x=(W-bw)/2;
  let s=`<defs><marker id="arr2" markerWidth="9" markerHeight="9" refX="6" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6" fill="#8b949e"/></marker></defs>`;
  steps.forEach(([t,sub],i)=>{
    const y=y0+i*(bh+gap);
    s+=`<rect x="${x}" y="${y}" width="${bw}" height="${bh}" rx="9" fill="#161b22" stroke="#30363d"/>`;
    s+=`<text x="${W/2}" y="${y+24}" fill="#e6edf3" font-size="13" text-anchor="middle">${t}</text>`;
    s+=`<text x="${W/2}" y="${y+42}" fill="#8b949e" font-size="11" text-anchor="middle">${sub}</text>`;
    if(i<steps.length-1) s+=`<line x1="${W/2}" y1="${y+bh}" x2="${W/2}" y2="${y+bh+gap-3}" stroke="#8b949e" stroke-width="2" marker-end="url(#arr2)"/>`;
  });
  svg.innerHTML=s;
})();

// ---------- methodology: mapping laws ----------
(function(){
  const a=auc;
  const aucOf=k=>a[k]?a[k].auc:null;
  const laws=[
    ["L1","chokepoint: curvature κ ≪ 0","privilege escalation","geometric"],
    ["L2","persistent H₁ generator","reentrancy / recursion","topological"],
    ["L3","Fiedler spectral cut","injection across trust","spectral"],
    ["L4","taint crossing an `auth` edge","naturality violation","","definitional (Prop. 2)"],
    ["L5","persistence outlier","real vs. spurious feature","topological"],
    ["L6","SAT(φ_bad) (formal reachability)","concrete exploit","formal"],
  ];
  const rows=laws.map(([id,f,c,k,override])=>{
    const v=aucOf(k);
    let status=override||"—";
    if(!override && v!==null){ status = v>0.7 ? `<span style="color:var(--green)">supported (AUC ${v.toFixed(3)})</span>`
      : (v<0.45 ? `<span style="color:var(--red)">not supported (AUC ${v.toFixed(3)})</span>`
      : `<span style="color:var(--amber)">at chance (AUC ${v.toFixed(3)})</span>`); }
    return [id,f,c,status];
  });
  $("#laws").innerHTML=table(rows,["law","feature","class","status on OWASP Benchmark"]);
})();


// ---------- line chart ----------
function lineChart(svg, series, opts){
  const W=560,H=320, m={l:56,r:16,t:20,b:40};
  const xs=[].concat(...series.map(s=>s.pts.map(p=>p[0])));
  const ys=[].concat(...series.map(s=>s.pts.map(p=>p[1])));
  const xlog=opts.xlog, ylog=opts.ylog;
  const xmin=Math.min(...xs), xmax=Math.max(...xs);
  const ymin=Math.min(...ys), ymax=Math.max(...ys);
  const X=x=>{const t=xlog?(Math.log10(x)-Math.log10(xmin))/((Math.log10(xmax)-Math.log10(xmin))||1):(x-xmin)/((xmax-xmin)||1);return m.l+t*(W-m.l-m.r);};
  const Y=y=>{const t=ylog?(Math.log10(y)-Math.log10(ymin))/((Math.log10(ymax)-Math.log10(ymin))||1):(y-ymin)/((ymax-ymin)||1);return H-m.b-t*(H-m.t-m.b);};
  let s=`<rect x="${m.l}" y="${m.t}" width="${W-m.l-m.r}" height="${H-m.t-m.b}" fill="none" stroke="#30363d"/>`;
  for(let i=0;i<=4;i++){const gy=m.t+i*(H-m.t-m.b)/4; s+=`<line x1="${m.l}" y1="${gy}" x2="${W-m.r}" y2="${gy}" stroke="#21262d"/>`;}
  s+=`<text x="${(W)/2}" y="${H-8}" fill="#8b949e" font-size="11" text-anchor="middle">${opts.xlabel||""}</text>`;
  s+=`<text x="14" y="${H/2}" fill="#8b949e" font-size="11" text-anchor="middle" transform="rotate(-90 14 ${H/2})">${opts.ylabel||""}</text>`;
  series.forEach(ser=>{
    const d=ser.pts.map((p,i)=>(i?"L":"M")+X(p[0]).toFixed(1)+" "+Y(p[1]).toFixed(1)).join(" ");
    s+=`<path d="${d}" fill="none" stroke="${ser.color}" stroke-width="2" ${ser.dash?`stroke-dasharray="${ser.dash}"`:""}/>`;
    ser.pts.forEach(p=>{s+=`<circle cx="${X(p[0]).toFixed(1)}" cy="${Y(p[1]).toFixed(1)}" r="2.6" fill="${ser.color}"/>`;});
  });
  let ly=m.t+6;
  series.forEach(ser=>{s+=`<text x="${W-m.r-4}" y="${ly}" fill="${ser.color}" font-size="11" text-anchor="end">${ser.name}</text>`;ly+=13;});
  svg.innerHTML=s;
}

// ---------- cost curve ----------
const curves = o.curves||{};
const palette={dfs:"#8b949e",taint:"#3fb950",field:"#58a6ff",random:"#f85149"};
const series=Object.keys(curves).map(k=>({name:k,color:palette[k]||"#999",dash:k==="random"?"4 3":"",
  pts:curves[k].map((v,i)=>[i+1,v])}));
lineChart($("#cost"), series, {xlabel:"verification budget", ylabel:"cumulative recall"});

// ---------- AUC bars ----------
(function(){
  const svg=$("#auc"); const W=560,H=320,m={l:90,r:20,t:20,b:30};
  const keys=Object.keys(auc);
  const bh=(H-m.t-m.b)/Math.max(keys.length,1);
  svg.innerHTML=`<text x="${W/2}" y="${H-8}" fill="#8b949e" font-size="11" text-anchor="middle">AUC (0.5 = chance)</text>`;
  keys.forEach((k,i)=>{
    const a=auc[k].auc, w=(W-m.l-m.r)*a, y=m.t+i*bh+bh*0.15;
    const col=a>0.7?"#3fb950":(a>=0.45?"#d29922":"#f85149");
    svg.innerHTML+=`<text x="${m.l-8}" y="${y+12}" fill="#e6edf3" font-size="11" text-anchor="end">${k}</text>`;
    svg.innerHTML+=`<rect x="${m.l}" y="${y}" width="${w}" height="${bh*0.7}" fill="${col}" rx="3"/>`;
    svg.innerHTML+=`<line x1="${m.l+(W-m.l-m.r)*0.5}" y1="${m.t}" x2="${m.l+(W-m.l-m.r)*0.5}" y2="${H-m.b}" stroke="#8b949e" stroke-dasharray="3 3"/>`;
    svg.innerHTML+=`<text x="${m.l+w+6}" y="${y+12}" fill="#8b949e" font-size="11">${a.toFixed(3)}</text>`;
  });
})();

// ---------- tables ----------
function table(rows, cols){
  return `<table><thead><tr>${cols.map(c=>`<th>${c}</th>`).join("")}</tr></thead><tbody>`+
    rows.map(r=>`<tr>${r.map(c=>`<td>${c}</td>`).join("")}</tr>`).join("")+`</tbody></table>`;
}
(function(){
  const m=o.metrics||{};
  const rows=Object.keys(m).map(k=>[k,m[k].mrr,m[k]["recall@1"],m[k].mean_rank,m[k]["ndcg@5"]]);
  $("#oracle-table").innerHTML=table(rows,["ranking","MRR","R@1","mean rank","NDCG@5"]);
})();

(function(){
  const ow=DATA.owasp||{};
  function block(title, obj){
    if(!obj) return "";
    const rows=Object.keys(obj).filter(k=>k!=="overall").sort().map(k=>{
      const v=obj[k]; const fpr=v.fp/(v.fp+v.tn||1); const j=(v.recall-fpr);
      return [k,v.tp,v.fp,v.fn,v.tn,v.precision.toFixed(3),v.recall.toFixed(3),v.f1.toFixed(3),j.toFixed(3)];
    });
    const ov=obj.overall; const fpr=ov.fp/(ov.fp+ov.tn||1);
    rows.push(["<b>overall</b>",ov.tp,ov.fp,ov.fn,ov.tn,ov.precision.toFixed(3),ov.recall.toFixed(3),ov.f1.toFixed(3),(ov.recall-fpr).toFixed(3)]);
    return `<h3 style="font-size:13px;color:#8b949e">${title}</h3>`+table(rows,["category","TP","FP","FN","TN","P","R","F1","J"]);
  }
  $("#owasp-tables").innerHTML =
    block("adapter — all 11 categories", ow.adapter_all) +
    block("adapter — 7 taint categories", ow.adapter_taint) +
    block("adapter + Z3 verifier — 7 taint categories", ow.z3_taint);
})();

(function(){
  const ab=DATA.ablation||{};
  const rows=Object.keys(ab).map(k=>{const v=ab[k];return [k,v.precision.toFixed(3),v.recall.toFixed(3),v.f1.toFixed(3)];});
  $("#ablation-table").innerHTML=table(rows,["variant","precision","recall","F1"]);
})();

(function(){
  const crows=[];
  (DATA.cves||[]).forEach(c=>(c.files||[]).forEach(f=>{
    const res=f.resolved.length?`<span style="color:var(--green)">resolved</span>`:(f.persisting.length?`<span style="color:var(--amber)">persisting</span>`:"—");
    crows.push([c.cve,f.file,f.vuln_findings,f.patched_findings,res]);}));
  $("#cve-table").innerHTML=crows.length?table(crows,["CVE","file","vuln","patched","result"]):"<div class='small'>no data</div>";
})();

// ---------- scale chart ----------
(function(){
  const by={};
  DATA.scale.forEach(r=>{(by[r.kernel]=by[r.kernel]||[]).push([r.edges,r.ms]);});
  const colors={forman:"#3fb950",mapper:"#58a6ff",homology:"#f85149",sinkhorn:"#d29922",
    ollivier_exact:"#bc8cff",spectral_fiedler:"#79c0ff",directed_laplacian:"#ffa657"};
  const ser=Object.keys(by).map(k=>({name:k,color:colors[k]||"#999",pts:by[k].sort((a,b)=>a[0]-b[0])}));
  const svg=$("#scale"); const W=900,H=340,m={l:70,r:150,t:20,b:40};
  const xs=[].concat(...ser.map(s=>s.pts.map(p=>p[0]))), ys=[].concat(...ser.map(s=>s.pts.map(p=>p[1])));
  const lx=v=>Math.log10(v), ly=v=>Math.log10(v);
  const x0=lx(Math.min(...xs)),x1=lx(Math.max(...xs)),y0=ly(Math.min(...ys)),y1=ly(Math.max(...ys));
  const X=x=>m.l+(lx(x)-x0)/(x1-x0)*(W-m.l-m.r), Y=y=>H-m.b-(ly(y)-y0)/(y1-y0)*(H-m.t-m.b);
  let s=`<rect x="${m.l}" y="${m.t}" width="${W-m.l-m.r}" height="${H-m.t-m.b}" fill="none" stroke="#30363d"/>`;
  s+=`<text x="${W/2}" y="${H-8}" fill="#8b949e" font-size="11" text-anchor="middle">edges |E| (log)</text>`;
  s+=`<text x="16" y="${H/2}" fill="#8b949e" font-size="11" text-anchor="middle" transform="rotate(-90 16 ${H/2})">time ms (log)</text>`;
  ser.forEach((z,i)=>{const d=z.pts.map((p,j)=>(j?"L":"M")+X(p[0]).toFixed(1)+" "+Y(p[1]).toFixed(1)).join(" ");
    s+=`<path d="${d}" fill="none" stroke="${z.color}" stroke-width="2"/>`;
    s+=`<text x="${W-m.r+8}" y="${m.t+14+i*16}" fill="${z.color}" font-size="11">${z.name}</text>`;});
  svg.innerHTML=s;
})();

// ---------- manifold explorer ----------
const COLORS={source:"#f85149",sink:"#d29922",function:"#58a6ff",gate:"#bc8cff",module:"#30363d",
  assign:"#a5d6ff",call:"#bc8cff",statement:"#8b949e",block:"#8b949e",variable:"#79c0ff",parameter:"#79c0ff"};
const ECOL={taint:"#f85149",call:"#58a6ff",data:"#3fb950",control:"#6e7681",trust:"#bc8cff",auth:"#d2a8ff"};
function renderCase(idx){
  const ex=DATA.examples[idx]; const svg=$("#map"); const W=1000,H=460;
  const nodes=ex.nodes.map(n=>({...n,x:Math.random()*W,y:Math.random()*H}));
  const by={}; nodes.forEach(n=>by[n.id]=n);
  const N=nodes.length;
  for(let it=0;it<Math.max(60,400-N*2);it++){
    for(let i=0;i<N;i++)for(let j=i+1;j<N;j++){let dx=nodes[i].x-nodes[j].x,dy=nodes[i].y-nodes[j].y;let d2=dx*dx+dy*dy+0.01,d=Math.sqrt(d2),f=900/d2;dx/=d;dy/=d;
      nodes[i].x+=dx*f;nodes[i].y+=dy*f;nodes[j].x-=dx*f;nodes[j].y-=dy*f;}
    ex.edges.forEach(e=>{const a=by[e.src],b=by[e.dst];if(!a||!b)return;let dx=b.x-a.x,dy=b.y-a.y,d=Math.sqrt(dx*dx+dy*dy)||0.01,f=(d-90)*0.015;a.x+=dx/d*f;a.y+=dy/d*f;b.x-=dx/d*f;b.y-=dy/d*f;});
    nodes.forEach(n=>{n.x+=(W/2-n.x)*0.02;n.y+=(H/2-n.y)*0.02;n.x=Math.max(20,Math.min(W-20,n.x));n.y=Math.max(20,Math.min(H-20,n.y));});
  }
  let s="";
  ex.edges.forEach(e=>{const a=by[e.src],b=by[e.dst];if(!a||!b)return;
    s+=`<line x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" stroke="${ECOL[e.kind]||"#6e7681"}" stroke-width="${e.kind==="taint"?2.5:1}" stroke-opacity="0.55"/>`;});
  nodes.forEach(n=>{const r=n.tainted?14:6+Math.min(10,(n.fiedler||0)*8);
    s+=`<circle cx="${n.x}" cy="${n.y}" r="${r}" fill="${COLORS[n.kind]||"#8b949e"}" ${n.tainted?'stroke="#f85149" stroke-width="1.5"':""}/>`;
    s+=`<text x="${n.x}" y="${n.y-r-4}" fill="#e6edf3" font-size="10" text-anchor="middle">${n.label}</text>`;});
  svg.innerHTML=s;
  $("#case-meta").textContent = `${ex.adapter} · ${ex.nodes.length} nodes · ${ex.findings.length} findings`;
  const f=ex.findings.map(x=>`<div><span class="sw" style="background:var(--red)"></span>${x.severity} ${x.category} — ${x.sink} (line ${x.line})</div>`).join("");
  $("#mlegend").innerHTML = Object.keys(COLORS).map(k=>`<span><span class="sw" style="background:${COLORS[k]}"></span>${k}</span>`).join(" &nbsp; ") + (f?`<div style="margin-top:6px">${f}</div>`:"");
}
(function(){
  const sel=$("#case");
  DATA.examples.forEach((e,i)=>{const o=document.createElement("option");o.value=i;o.textContent=e.name;sel.appendChild(o);});
  sel.onchange=()=>renderCase(+sel.value);
  if(DATA.examples.length) renderCase(0);
})();

// ---------- recipes ----------
$("#recipes").textContent = DATA.recipes;
</script>
</body>
</html>
"""

_RECIPES = """# 1. Dashboard (this page)
python -m manifold.dashboard --out dashboard.html

# 2. Analyze any artifact (auto-detects the adapter)
python -m manifold.cli examples/python/sqli.py --agent --viz /tmp/sqli.html
python -m manifold.cli Foo.java --adapter java
python -m manifold.cli /path/to/binary --adapter angr-binary

# 3. OWASP Benchmark 1.2 (the corpus behind the numbers)
python benchmarks/run_owasp.py \\
  --testcode BenchmarkJava/src/main/java/org/owasp/benchmark/testcode \\
  --csv expectedresults-1.2.csv          # add --verify for the Z3 arbiter

# 4. Prioritization oracle (main experiment) + figures
python benchmarks/run_oracle.py --testcode <testcode> --csv <csv> --budget 6 --seeds 20
python scripts/make_figures.py

# 5. Ablation + scalability
python benchmarks/ablation.py --testcode <testcode> --csv <csv>
cargo run --release --manifest-path core/Cargo.toml --bin scale

# 6. Juliet / external corpora
python benchmarks/run_juliet.py --root /path/to/juliet-test-suite
python benchmarks/run_external.py <manifest.json | dir> --adapter python

# 7. Your own code: point the CLI at it, or load a labeled corpus
python -m manifold.cli your_project/file.py --agent --viz out.html
#   manifest:  [{"file": "a.py", "vulnerable": true}, ...]
#   directory: root/vulnerable/*  +  root/safe/*

# 8. Everything at once (reproducible artifact)
./scripts/reproduce.sh --fetch-owasp"""


def build_html(data: Dict[str, Any]) -> str:
    data = dict(data)
    data["recipes"] = _RECIPES
    return _TEMPLATE.replace("__DATA__", json.dumps(data))


def write_dashboard(path: str) -> None:
    Path(path).write_text(build_html(load_data()), encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate or serve the MANIFOLD dashboard / web UI.")
    ap.add_argument("--out", default="dashboard.html", help="write a static dashboard file (default)")
    ap.add_argument("--serve", action="store_true", help="serve the interactive web UI instead")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=None, help="implies --serve")
    args = ap.parse_args()

    if args.serve or args.port is not None:
        from .server import serve

        serve(args.host, args.port or 8000)
        return 0

    write_dashboard(args.out)
    print(f"dashboard -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""HTML dashboard for VALEN (static, self-contained by default).

Aggregates every experiment artifact into one page: the prioritization oracle
(MRR / AUC / cost curve), the OWASP Benchmark table, the ablation, the per-kernel
scalability curves, an interactive valen explorer over the bundled examples,
and copy-paste usage recipes.

    python -m valen.dashboard --out dashboard.html

The analysis core has no external dependencies; the page uses Tailwind +
Chart.js + D3 via CDN for a polished "modern terminal" look and degrades
gracefully offline (the tables and numbers still render without JS).
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any, Dict, List

from .analysis.math_core import run_core
from .ingest import analyze, infer_adapter
from .theme import head
from .viz import _edge_data, _node_data

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
        # recon fixtures are tool output (nmap/masscan), not runnable cases
        if "recon" in source.relative_to(examples).parts:
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
    llm = _read_json(BENCH / "llm_results.json") or {}
    return {
        "oracle": oracle,
        "owasp": owasp,
        "ablation": ablation,
        "cves": cves,
        "llm": llm,
        "scale": _read_scale(),
        "examples": _build_examples(),
    }


_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
__HEAD__
</head>
<body class="min-h-screen">
<header class="sticky top-0 z-40 backdrop-blur border-b" style="border-color:var(--border);background:rgba(10,14,20,.85)">
  <div class="max-w-[1280px] mx-auto px-6 py-4 flex items-center gap-4 flex-wrap">
    <div class="flex items-center gap-3">
      <div class="w-9 h-9 rounded-lg grid place-items-center glow" style="background:linear-gradient(135deg,var(--spectral),var(--formal));color:#08111c;font-weight:800;font-family:var(--mono)">V</div>
      <div>
        <h1 class="text-xl font-bold leading-none tracking-tight">VALEN — experiment dashboard</h1>
        <p class="text-xs mt-1" style="color:var(--muted)">Prioritization oracle · OWASP Benchmark 1.2 · ablation · scalability · valen explorer</p>
      </div>
    </div>
    <div class="ml-auto flex gap-2 flex-wrap" id="navlinks">
      <a href="#summary" class="pill">Summary</a>
      <a href="#methodology" class="pill">Methodology</a>
      <a href="#oracle" class="pill">Oracle</a>
      <a href="#owasp" class="pill">OWASP</a>
      <a href="#scale" class="pill">Scalability</a>
      <a href="#explorer" class="pill">Explorer</a>
    </div>
  </div>
</header>

<main class="max-w-[1280px] mx-auto px-6 py-6 space-y-8">

  <section id="summary">
    <div class="kicker h-sep">Summary</div>
    <div class="grid sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-3 mt-3" id="cards"></div>
  </section>

  <section id="methodology" class="panel p-5">
    <div class="kicker h-sep">Methodology</div>
    <div class="h-40 mt-3"><canvas id="pipeline"></canvas></div>
    <div class="grid lg:grid-cols-2 gap-6 mt-5">
      <div>
        <div class="kicker">Mathematical layers → signal → evidence</div>
        <div class="grid grid-cols-2 gap-3 mt-3" id="layers"></div>
      </div>
      <div>
        <div class="kicker">Evaluation protocol</div>
        <div class="h-80 mt-2"><canvas id="protocol"></canvas></div>
      </div>
    </div>
    <div class="kicker mt-5">Mapping hypotheses (feature → vulnerability class)</div>
    <div id="laws" class="mt-2"></div>
  </section>

  <section id="oracle" class="panel p-5">
    <div class="kicker h-sep">Prioritization oracle (main experiment)</div>
    <div class="grid lg:grid-cols-2 gap-5 mt-3">
      <div class="h-72"><canvas id="cost"></canvas></div>
      <div class="h-72"><canvas id="auc"></canvas></div>
    </div>
    <div id="oracle-table" class="mt-4"></div>
  </section>

  <section id="owasp" class="panel p-5">
    <div class="kicker h-sep">OWASP Benchmark 1.2</div>
    <div id="owasp-tables" class="mt-3"></div>
  </section>

  <div class="grid lg:grid-cols-2 gap-5">
    <section id="cves" class="panel p-5"><div class="kicker h-sep">Real CVE fixes</div><div id="cve-table" class="mt-3"></div></section>
    <section id="llm" class="panel p-5"><div class="kicker h-sep">LLM ablation</div><div id="llm-table" class="mt-3"></div></section>
  </div>

  <section id="ablation" class="panel p-5"><div class="kicker h-sep">Ablation (Java adapter)</div><div id="ablation-table" class="mt-3"></div></section>

  <section id="scale" class="panel p-5"><div class="kicker h-sep">Scalability</div><div class="h-80 mt-3"><canvas id="scale"></canvas></div></section>

  <section id="explorer" class="panel p-5">
    <div class="kicker h-sep">Valen explorer</div>
    <div class="flex items-center gap-3 mt-3 flex-wrap">
      <select id="case" class="bg-[#161d27] text-sm rounded-lg px-3 py-2 border flex-1 min-w-[200px]" style="border-color:var(--border)"></select>
      <span class="pill" id="case-meta"></span>
    </div>
    <svg id="map" class="w-full rounded-xl border mt-3" style="height:460px;border-color:var(--border);background:radial-gradient(circle at 50% 50%,#10161f,#0a0e14)"></svg>
    <div class="flex flex-wrap gap-2 mt-3" id="mlegend"></div>
  </section>

  <section id="usage" class="panel p-5">
    <div class="kicker h-sep">Use it with the experiment data</div>
    <pre class="mono mt-3 text-xs" id="recipes"></pre>
  </section>

</main>

<footer class="max-w-[1280px] mx-auto px-6 pb-8 text-[11px]" style="color:var(--muted)">
  <span class="mono">VALEN</span> — neuro-symbolic structural-invariant verifier · static (taint) + symbolic (Z3) + dynamic (sandboxed trace) triangulation.
</footer>

<script>
__JS__
</script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/d3@7/dist/d3.min.js"></script>
</body>
</html>
"""

_JS = r"""
const DATA = __DATA__;
const $ = (s)=>document.querySelector(s);
const NS="http://www.w3.org/2000/svg";

// ---------- summary cards ----------
const o = DATA.oracle || {}, auc = (o.signals_auc||{});
const cards = [
  ["taint MRR", (o.metrics&&o.metrics.taint?o.metrics.taint.mrr:"-"), "prioritization (main)", "taint"],
  ["field MRR", (o.metrics&&o.metrics.field?o.metrics.field.mrr:"-"), "V(x) fused", "spectral"],
  ["taint AUC", (auc.taint?auc.taint.auc:"-"), "predict vulnerable sink", "taint"],
  ["geometric AUC", (auc.geometric?auc.geometric.auc:"-"), "below chance", "geometric"],
  ["adapter F1", "0.681", "OWASP all categories", "topological"],
  ["Youden J", "0.168", "measured (adapter, all categories)", "formal"],
];
$("#cards").innerHTML = cards.map(([k,v,s,col])=>`<div class="card"><div class="kicker">${k}</div>
  <div class="metric" style="color:var(--${col})">${v}</div><div class="text-[11px]" style="color:var(--muted)">${s}</div></div>`).join("");

// ---------- charts ----------
function mkLine(id, series, xl, yl, opts={}){
  const c=document.getElementById(id); if(!c || !window.Chart) return;
  new Chart(c,{type:"line",data:{datasets:series.map(s=>({label:s.label,data:s.pts.map(p=>({x:p[0],y:p[1]})),borderColor:s.color,backgroundColor:s.color,borderWidth:2,pointRadius:2.5,tension:0.15}))},
    options:{scales:{x:{type:opts.log?"logarithmic":"linear",title:{display:true,text:xl}},y:{type:opts.log?"logarithmic":"linear",title:{display:true,text:yl},beginAtZero:!opts.log}},plugins:{legend:{labels:{color:"#8b949e"}}}}});
}
function mkBar(id, labels, vals){
  const c=document.getElementById(id); if(!c || !window.Chart) return;
  new Chart(c,{type:"bar",data:{labels,datasets:[{data:vals,backgroundColor:vals.map(v=>v>0.7?"#3fb950":(v>=0.45?"#d29922":"#f85149")),borderRadius:4}]},
    options:{indexAxis:"y",plugins:{legend:{display:false}},scales:{x:{min:0,max:1,title:{display:true,text:"AUC (0.5 = chance)"}}}}});
}
function table(rows,cols){return `<table><thead><tr>${cols.map(c=>`<th>${c}</th>`).join("")}</tr></thead><tbody>`+rows.map(r=>`<tr>${r.map(c=>`<td class="num">${c}</td>`).join("")}</tr>`).join("")+`</tbody></table>`;}

// ---------- methodology: pipeline ----------
(function(){
  const c=$("#pipeline"); if(!c) return;
  const svg=document.createElementNS(NS,"svg"); svg.setAttribute("viewBox","0 0 1120 160"); svg.style.width="100%"; svg.style.height="100%";
  c.style.display="none"; c.parentNode.insertBefore(svg,c);
  const boxes=["artifact","IR typed graph","math layers","V(x) field","LLM agent","Z3 verifier"];
  const bw=150,bh=54,gap=30,x0=24,y=38;
  let s=`<defs><marker id="a1" markerWidth="9" markerHeight="9" refX="6" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6" fill="#58a6ff"/></marker></defs>`;
  boxes.forEach((t,i)=>{const x=x0+i*(bw+gap);
    s+=`<rect x="${x}" y="${y}" width="${bw}" height="${bh}" rx="10" fill="#161d27" stroke="#58a6ff"/>`;
    const ws=t.split(" "); ws.forEach((w,wi)=>s+=`<text x="${x+bw/2}" y="${y+bh/2+5+(wi-(ws.length-1)/2)*16}" fill="#e6edf3" font-size="13" text-anchor="middle">${w}</text>`);
    if(i<boxes.length-1) s+=`<line x1="${x+bw}" y1="${y+bh/2}" x2="${x+bw+gap-3}" y2="${y+bh/2}" stroke="#58a6ff" stroke-width="2" marker-end="url(#a1)"/>`;});
  const cx1=x0+5*(bw+gap)+bw/2, cx2=x0+(bw+gap)+bw/2;
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
    let badge=`<span class="pill">defined</span>`;
    if(a[key]){const v=a[key].auc; const c=v>0.7?"var(--topological)":(v<0.45?"var(--algebraic)":"var(--muted)");
      badge=`<span class="pill" style="color:${c}">AUC ${v.toFixed(3)}</span>`;}
    return `<div class="card"><div class="kicker" style="color:var(--${key})">${n}</div>
      <div class="text-xs mt-2">${d}</div><div class="text-[11px] mt-2" style="color:var(--muted)">signal: ${sig} · ${badge}</div></div>`;
  }).join("");
})();

// ---------- methodology: protocol ----------
(function(){
  const c=$("#protocol"); if(!c) return;
  const svg=document.createElementNS(NS,"svg"); svg.setAttribute("viewBox","0 0 560 360"); svg.style.width="100%"; svg.style.height="100%";
  c.style.display="none"; c.parentNode.insertBefore(svg,c);
  const steps=[["enumerate all sink candidates","(source → sink reachability)"],["rank candidates","DFS · raw taint · V(x) · random"],["metrics","MRR · R@1 · NDCG@k · cost curve"],["Z3 arbiter","SAT + concrete witness"]];
  const W=560,bh=56,gap=22,bw=440,xx=(W-bw)/2;
  let s=`<defs><marker id="a2" markerWidth="9" markerHeight="9" refX="6" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6" fill="#8b949e"/></marker></defs>`;
  steps.forEach(([t,sub],i)=>{const yy=10+i*(bh+gap);
    s+=`<rect x="${xx}" y="${yy}" width="${bw}" height="${bh}" rx="10" fill="#11161d" stroke="#26303c"/>`;
    s+=`<text x="${W/2}" y="${yy+24}" fill="#e6edf3" font-size="13" text-anchor="middle">${t}</text><text x="${W/2}" y="${yy+42}" fill="#8b949e" font-size="11" text-anchor="middle">${sub}</text>`;
    if(i<steps.length-1) s+=`<line x1="${W/2}" y1="${yy+bh}" x2="${W/2}" y2="${yy+bh+gap-3}" stroke="#8b949e" stroke-width="2" marker-end="url(#a2)"/>`;});
  svg.innerHTML=s;
})();

// ---------- methodology: mapping laws ----------
(function(){
  const aucOf=k=>auc[k]?auc[k].auc:null;
  const laws=[["H1","chokepoint: curvature κ ≪ 0","privilege escalation","geometric"],["H2","persistent H₁ generator","reentrancy / recursion","topological"],["H3","Fiedler spectral cut","injection across trust","spectral"],["H4","taint crossing an `auth` edge","auth-invariant violation",""],["H5","persistence outlier","real vs. spurious feature","topological"],["H6","SAT(φ_bad) (formal reachability)","model witness","formal"]];
  const rows=laws.map(([id,f,c,k])=>{const v=aucOf(k);
    let status="—";
    if(k && v!==null){ status = v>0.7 ? `<span style="color:var(--topological)">supported (AUC ${v.toFixed(3)})</span>`
      : (v<0.45 ? `<span style="color:var(--algebraic)">not supported (AUC ${v.toFixed(3)})</span>`
      : `<span style="color:var(--geometric)">at chance (AUC ${v.toFixed(3)})</span>`); }
    if(!k) status="definitional (Prop. 2)";
    return [id,f,c,status];});
  $("#laws").innerHTML=table(rows,["hypothesis","feature","class","status on OWASP Benchmark"]);
})();

// ---------- oracle charts ----------
(function(){
  const pal={dfs:"#8b949e",taint:"#ff7b72",field:"#58a6ff",random:"#f85149"};
  const curves=o.curves||{};
  mkLine("cost",Object.keys(curves).map(k=>({label:k,color:pal[k]||"#999",pts:curves[k].map((v,i)=>[i+1,v])})),"verification budget","cumulative recall");
  if(window.Chart){ const labels=Object.keys(auc), vals=labels.map(k=>auc[k].auc); mkBar("auc",labels,vals); }

  const m=o.metrics||{};
  $("#oracle-table").innerHTML=table(Object.keys(m).map(k=>[k,m[k].mrr,m[k]["recall@1"],m[k].mean_rank,m[k]["ndcg@5"]]),["ranking","MRR","R@1","mean rank","NDCG@5"]);
  const pt=m.taint_vs_field;
  $("#oracle-table").innerHTML += (pt?`<div class="text-xs mt-2" style="color:var(--muted)">paired test taint−field: ${pt.mean_diff>=0?'+':''}${pt.mean_diff.toFixed(4)} CI95=[${pt.ci95[0].toFixed(4)}, ${pt.ci95[1].toFixed(4)}] p=${pt.p_value}</div>`:"");
})();

// ---------- tables ----------
(function(){
  const ow=DATA.owasp||{};
  function block(title,obj){if(!obj)return "";
    const rows=Object.keys(obj).filter(k=>k!=="overall").sort().map(k=>{const v=obj[k];const fpr=v.fp/(v.fp+v.tn||1);return[k,v.tp,v.fp,v.fn,v.tn,v.precision.toFixed(3),v.recall.toFixed(3),v.f1.toFixed(3),(v.recall-fpr).toFixed(3)];});
    const ov=obj.overall,fpr=ov.fp/(ov.fp+ov.tn||1);rows.push(["<b>overall</b>",ov.tp,ov.fp,ov.fn,ov.tn,ov.precision.toFixed(3),ov.recall.toFixed(3),ov.f1.toFixed(3),(ov.recall-fpr).toFixed(3)]);
    return `<div class="kicker mt-3">${title}</div>`+table(rows,["category","TP","FP","FN","TN","P","R","F1","J"]);}
  $("#owasp-tables").innerHTML=block("adapter — all 11 categories",ow.adapter_all)+block("adapter — 7 taint categories",ow.adapter_taint)+block("adapter + Z3 verifier — 7 taint categories",ow.z3_taint);
})();
(function(){const ab=DATA.ablation||{}; $("#ablation-table").innerHTML=table(Object.keys(ab).map(k=>[k,ab[k].precision.toFixed(3),ab[k].recall.toFixed(3),ab[k].f1.toFixed(3)]),["variant","precision","recall","F1"]);})();
(function(){const crows=[];(DATA.cves||[]).forEach(c=>(c.files||[]).forEach(f=>{const res=f.resolved.length?`<span style="color:var(--topological)">resolved</span>`:(f.persisting.length?`<span style="color:var(--geometric)">persisting</span>`:"—");crows.push([c.cve,f.file,f.vuln_findings,f.patched_findings,res]);}));
  $("#cve-table").innerHTML=crows.length?table(crows,["CVE","file","vuln","patched","result"]):"<div class='text-xs' style='color:var(--muted)'>no data</div>";})();
(function(){const llm=DATA.llm||{};const rows=[];(llm.results||[]).forEach(r=>rows.push([r.file,r.confirmed_offline,r.confirmed_online,r.llm_generated,r.stable?"stable":"varies"]));
  $("#llm-table").innerHTML=rows.length?table(rows,["file","offline","online","llm","stability"]):"<div class='text-xs' style='color:var(--muted)'>no data</div>";})();

// ---------- scale chart ----------
(function(){
  const by={}; DATA.scale.forEach(r=>{(by[r.kernel]=by[r.kernel]||[]).push([r.edges,r.ms]);});
  const colors={forman:"#3fb950",mapper:"#58a6ff",homology:"#f85149",sinkhorn:"#d29922",ollivier_exact:"#bc8cff",spectral_fiedler:"#79c0ff",directed_laplacian:"#ffa657"};
  const ser=Object.keys(by).map(k=>({label:k,color:colors[k]||"#999",pts:by[k].sort((a,b)=>a[0]-b[0])}));
  if(ser.length) mkLine("scale",ser,"edges |E| (log)","time ms (log)",{log:true});
})();

// ---------- valen explorer (interactive) ----------
const COLORS={source:"#f85149",sink:"#d29922",function:"#58a6ff",gate:"#bc8cff",module:"#30363d",
  assign:"#a5d6ff",call:"#bc8cff",statement:"#8b949e",block:"#8b949e",variable:"#79c0ff",parameter:"#79c0ff"};
const ECOL={taint:"#f85149",call:"#58a6ff",data:"#3fb950",control:"#6e7681",trust:"#bc8cff",auth:"#d2a8ff"};
function renderCase(idx){
  const ex=DATA.examples[idx]; const svg=$("#map"); svg.innerHTML="";
  const W=1000,H=460; svg.setAttribute("viewBox",`0 0 ${W} ${H}`);
  const world=document.createElementNS(NS,"g"); svg.appendChild(world);
  let view={x:0,y:0,k:1};
  const apply=()=>world.setAttribute("transform",`translate(${view.x},${view.y}) scale(${view.k})`);
  const r=n=>n.tainted?14:6+Math.min(10,(n.fiedler||0)*8);
  const nodes=ex.nodes.map((n,i)=>({...n,r:r(n),x:W/2+Math.cos(i*2.39996)*30*Math.sqrt(i+1),y:H/2+Math.sin(i*2.39996)*30*Math.sqrt(i+1),vx:0,vy:0,fixed:false}));
  const by={}; nodes.forEach(n=>by[n.id]=n); const edges=ex.edges.slice(); const N=nodes.length;
  const edgeEls=edges.map(e=>{const l=document.createElementNS(NS,"line"); l.setAttribute("stroke",ECOL[e.kind]||"#6e7681"); l.setAttribute("stroke-width",e.kind==="taint"?2.5:1); l.setAttribute("stroke-opacity","0.55"); world.appendChild(l); return l;});
  const nodeEls=new Map(); const neigh=new Map();
  nodes.forEach(n=>{const g=document.createElementNS(NS,"g"); g.setAttribute("class","node");
    const c=document.createElementNS(NS,"circle"); c.setAttribute("r",n.r); c.setAttribute("fill",COLORS[n.kind]||"#8b949e"); if(n.tainted)c.setAttribute("stroke","#f85149");
    const t=document.createElementNS(NS,"text"); t.setAttribute("y",-n.r-4); t.setAttribute("text-anchor","middle"); t.setAttribute("fill","#e6edf3"); t.setAttribute("font-size","10"); t.textContent=n.label;
    const t2=document.createElementNS(NS,"text"); t2.setAttribute("y",n.r+13); t2.setAttribute("text-anchor","middle"); t2.setAttribute("fill","#8b949e"); t2.setAttribute("font-size","8"); t2.textContent=n.kind;
    const ti=document.createElementNS(NS,"title"); ti.textContent=`${n.kind} ${n.label} (line ${n.line})${n.tainted?" [tainted]":""}`;
    g.append(c,t,t2,ti); world.appendChild(g); nodeEls.set(n.id,g);
    const s=new Set([n.id]); edges.forEach(e=>{if(e.src===n.id)s.add(e.dst);if(e.dst===n.id)s.add(e.src);}); neigh.set(n.id,s);});
  let hovered=null;
  function hl(){const f=hovered?neigh.get(hovered):null; nodes.forEach(n=>nodeEls.get(n.id).setAttribute("opacity",f&&!f.has(n.id)?"0.15":"1")); edgeEls.forEach((l,i)=>{const e=edges[i];l.setAttribute("stroke-opacity",f?(f.has(e.src)&&f.has(e.dst)?"0.9":"0.06"):"0.55");});}
  function draw(){nodes.forEach(n=>nodeEls.get(n.id).setAttribute("transform",`translate(${n.x},${n.y})`)); edgeEls.forEach((l,i)=>{const e=edges[i],a=by[e.src],b=by[e.dst]; if(a&&b){l.setAttribute("x1",a.x);l.setAttribute("y1",a.y);l.setAttribute("x2",b.x);l.setAttribute("y2",b.y);}});}
  let alpha=1,running=true; const K=1200*Math.sqrt(N);
  function tick(){for(let i=0;i<N;i++){const a=nodes[i];for(let j=i+1;j<N;j++){const b=nodes[j];let dx=a.x-b.x,dy=a.y-b.y,d2=dx*dx+dy*dy;const mn=a.r+b.r+22,m2=mn*mn;if(d2<m2){d2=m2;dx*=mn/Math.sqrt(dx*dx+dy*dy+1e-6);dy*=mn/Math.sqrt(dx*dx+dy*dy+1e-6);}const dd=Math.sqrt(d2),f=K/d2;a.vx+=dx/dd*f;a.vy+=dy/dd*f;b.vx-=dx/dd*f;b.vy-=dy/dd*f;}}
    edges.forEach(e=>{const a=by[e.src],b=by[e.dst];if(!a||!b)return;let dx=b.x-a.x,dy=b.y-a.y,dd=Math.sqrt(dx*dx+dy*dy)||1;const rest=a.r+b.r+50,f=(dd-rest)*0.06;a.vx+=dx/dd*f;a.vy+=dy/dd*f;b.vx-=dx/dd*f;b.vy-=dy/dd*f;});
    nodes.forEach(n=>{n.vx+=(W/2-n.x)*0.0025;n.vy+=(H/2-n.y)*0.0025;}); nodes.forEach(n=>{if(n.fixed){n.vx=0;n.vy=0;return;}n.vx*=0.6;n.vy*=0.6;n.x+=n.vx;n.y+=n.vy;}); alpha=Math.max(0.01,alpha*0.975);}
  function loop(){if(running){const st=N>600?1:3;for(let i=0;i<st;i++)tick();draw();if(alpha>0.0105)requestAnimationFrame(loop);else running=false;}}
  function reheat(){alpha=1;if(!running){running=true;loop();}}
  let pan=null;
  svg.addEventListener("pointerdown",e=>{if(e.target.closest(".node"))return;pan={x:e.clientX,y:e.clientY,vx:view.x,vy:view.y};svg.setPointerCapture(e.pointerId);});
  svg.addEventListener("pointermove",e=>{if(pan){view.x=pan.vx+(e.clientX-pan.x);view.y=pan.vy+(e.clientY-pan.y);apply();}});
  svg.addEventListener("pointerup",()=>pan=null);
  svg.addEventListener("wheel",e=>{e.preventDefault();const r=svg.getBoundingClientRect(),mx=e.clientX-r.left,my=e.clientY-r.top;const k1=Math.max(0.05,Math.min(8,view.k*(e.deltaY<0?1.12:0.89)));view.x=mx-(mx-view.x)*(k1/view.k);view.y=my-(my-view.y)*(k1/view.k);view.k=k1;apply();},{passive:false});
  function toW(cx,cy){const r=svg.getBoundingClientRect();return [(cx-r.left-view.x)/view.k,(cy-r.top-view.y)/view.k];}
  nodes.forEach(n=>{const el=nodeEls.get(n.id);let dr=null;
    el.addEventListener("pointerdown",e=>{e.stopPropagation();dr={n};n.fixed=true;el.setPointerCapture(e.pointerId);reheat();});
    el.addEventListener("pointermove",e=>{if(dr){const [x,y]=toW(e.clientX,e.clientY);n.x=x;n.y=y;draw();}});
    el.addEventListener("pointerup",()=>{if(dr){dr=null;n.fixed=false;reheat();}});
    el.addEventListener("pointerenter",()=>{hovered=n.id;hl();});
    el.addEventListener("pointerleave",()=>{if(hovered===n.id){hovered=null;hl();}});
    el.addEventListener("click",()=>{const f=neigh.get(n.id);nodes.forEach(m=>nodeEls.get(m.id).setAttribute("opacity",f.has(m.id)?"1":"0.15"));edgeEls.forEach((l,i)=>{const e=edges[i];l.setAttribute("stroke-opacity",f.has(e.src)&&f.has(e.dst)?"0.9":"0.06");});});});
  svg.addEventListener("pointerleave",()=>{hovered=null;hl();});
  if(N){let x0=1e9,y0=1e9,x1=-1e9,y1=-1e9;nodes.forEach(n=>{x0=Math.min(x0,n.x-n.r);y0=Math.min(y0,n.y-n.r);x1=Math.max(x1,n.x+n.r);y1=Math.max(y1,n.y+n.r);});
    const r=svg.getBoundingClientRect();const k=Math.min(r.width/(x1-x0||1),r.height/(y1-y0||1))*0.9;view.k=Math.max(0.05,Math.min(4,k));view.x=r.width/2-((x0+x1)/2)*view.k;view.y=r.height/2-((y0+y1)/2)*view.k;apply();}
  apply();draw();alpha=1;running=true;loop();
  $("#case-meta").textContent = `${ex.adapter} · ${ex.nodes.length} nodes · ${ex.findings.length} findings`;
  const f=ex.findings.map(x=>`<div><span class="dot" style="background:var(--algebraic)"></span>${x.severity} ${x.category} — ${x.sink} (line ${x.line})</div>`).join("");
  $("#mlegend").innerHTML = Object.keys(COLORS).map(k=>`<span class="pill"><span class="dot" style="background:${COLORS[k]}"></span>${k}</span>`).join("") + (f?`<div class="mt-3">${f}</div>`:"");
}
(function(){const sel=$("#case");DATA.examples.forEach((e,i)=>{const o=document.createElement("option");o.value=i;o.textContent=e.name;sel.appendChild(o);});sel.onchange=()=>renderCase(+sel.value);if(DATA.examples.length)renderCase(0);})();

$("#recipes").textContent = DATA.recipes;
"""

_RECIPES = """# 1. Dashboard (this page)
python -m valen.dashboard --out dashboard.html

# 2. Analyze any artifact (auto-detects the adapter)
python -m valen.cli examples/python/sqli.py --agent --viz /tmp/sqli.html
python -m valen.cli Foo.java --adapter java
python -m valen.cli /path/to/binary --adapter angr-binary

# 3. Dynamic analysis (sandboxed execution + static/dynamic triangulation)
python -m valen.cli your_script.py --dynamic --argv "untrusted input"

# 4. OWASP Benchmark 1.2 (the corpus behind the numbers)
python benchmarks/run_owasp.py \\
  --testcode BenchmarkJava/src/main/java/org/owasp/benchmark/testcode \\
  --csv expectedresults-1.2.csv          # add --verify for the Z3 arbiter

# 5. Prioritization oracle (main experiment) + figures
python benchmarks/run_oracle.py --testcode <testcode> --csv <csv> --budget 6 --seeds 20
python scripts/make_figures.py

# 6. Ablation + scalability
python benchmarks/ablation.py --testcode <testcode> --csv <csv>
cargo run --release --manifest-path core/Cargo.toml --bin scale

# 7. Juliet / external corpora
python benchmarks/run_juliet.py --root /path/to/juliet-test-suite
python benchmarks/run_external.py <manifest.json | dir> --adapter python

# 8. Everything at once (reproducible artifact)
./scripts/reproduce.sh --fetch-owasp"""


def build_html(data: Dict[str, Any]) -> str:
    data = dict(data)
    data["recipes"] = _RECIPES
    html = _TEMPLATE.replace("__DATA__", json.dumps(data))
    html = html.replace("__HEAD__", head("VALEN — dashboard"))
    html = html.replace("__JS__", _JS)
    return html


def write_dashboard(path: str) -> None:
    Path(path).write_text(build_html(load_data()), encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate or serve the VALEN dashboard / web UI.")
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

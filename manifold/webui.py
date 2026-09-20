"""Web UI for MANIFOLD: a single-page app served by the stdlib HTTP server.

The page talks to `/api/*` endpoints (see `manifold/server.py`) to analyze code
live, browse the bundled examples, and render the experiment dashboard and the
methodology diagrams. Everything is self-contained (no external JS/CSS).
"""

from __future__ import annotations

PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>MANIFOLD — web UI</title>
<style>
:root{--bg:#0d1117;--panel:#161b22;--panel2:#1c2330;--text:#e6edf3;--muted:#8b949e;--border:#30363d;--accent:#58a6ff;--green:#3fb950;--red:#f85149;--amber:#d29922;--purple:#bc8cff;}
*{box-sizing:border-box;}
body{margin:0;font-family:system-ui,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--text);}
header{padding:14px 22px;border-bottom:1px solid var(--border);background:linear-gradient(120deg,#161b22,#0d1117);display:flex;align-items:center;gap:18px;flex-wrap:wrap;}
header h1{margin:0;font-size:20px;} header .sub{color:var(--muted);font-size:12px;}
nav{display:flex;gap:6px;}
nav button{background:transparent;border:1px solid var(--border);color:var(--muted);border-radius:8px;padding:7px 14px;cursor:pointer;font-size:13px;}
nav button.on{background:var(--panel2);color:var(--text);border-color:var(--accent);}
main{padding:18px 22px;max-width:1300px;margin:0 auto;}
.tab{display:none;} .tab.on{display:block;}
h2{font-size:15px;border-left:3px solid var(--accent);padding-left:10px;margin:0 0 12px;}
.panel{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:12px;}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:10px;}
select,button,input,textarea{background:var(--panel2);color:var(--text);border:1px solid var(--border);border-radius:7px;padding:7px 10px;font-size:13px;}
textarea{width:100%;height:240px;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px;line-height:1.5;}
button.primary{background:var(--accent);color:#08111c;font-weight:700;border-color:var(--accent);cursor:pointer;}
label.chk{display:flex;gap:6px;align-items:center;color:var(--muted);font-size:12.5px;}
.two{display:grid;grid-template-columns:1fr 1fr;gap:16px;} @media(max-width:900px){.two{grid-template-columns:1fr;}}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--border);border-radius:10px;overflow:hidden;font-size:12.5px;}
th,td{padding:6px 9px;text-align:right;border-bottom:1px solid var(--border);} th:first-child,td:first-child{text-align:left;}
th{background:var(--panel2);color:var(--muted);font-weight:600;}
.finding{border-left:3px solid var(--red);background:#0b0f14;border-radius:6px;padding:8px 10px;margin-bottom:7px;}
.finding .sev{font-size:10px;text-transform:uppercase;font-weight:700;}
.finding.critical{border-color:var(--red)} .finding.high{border-color:var(--amber)} .finding.medium{border-color:var(--accent)}
.card{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:12px;}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:10px;}
.small{font-size:11px;color:var(--muted);}
pre{background:#0b0f14;border:1px solid var(--border);border-radius:8px;padding:12px;overflow:auto;font-size:12px;}
#map{width:100%;height:440px;background:radial-gradient(circle at 50% 50%,#161b22,#0d1117);border:1px solid var(--border);border-radius:10px;}
.badge{font-size:11px;padding:1px 7px;border-radius:10px;background:var(--panel2);color:var(--muted);}
.mode{cursor:pointer;padding:4px 10px;}
.mode.on{background:var(--accent);color:#08111c;font-weight:700;}
.resolved{color:var(--green);} .introduced{color:var(--red);} .persisting{color:var(--amber);}
.bar{height:8px;background:var(--panel2);border-radius:4px;overflow:hidden;} .bar>i{display:block;height:100%;background:var(--accent);}
</style>
</head>
<body>
<header>
  <h1>MANIFOLD</h1>
  <span class="sub">web UI — analyze, explore, reproduce</span>
  <nav>
    <button data-tab="analyze" class="on">Analyze</button>
    <button data-tab="experiments">Experiments</button>
    <button data-tab="methodology">Methodology</button>
  </nav>
</header>
<main>

<!-- ANALYZE -->
<section class="tab on" id="tab-analyze">
  <div class="row">
    <select id="example"></select>
    <select id="adapter">
      <option value="">auto</option>
      <option>python</option><option>java</option><option>binary</option>
      <option>angr-binary</option><option>web</option><option>llm-agent</option>
    </select>
    <input id="path" placeholder="path (optional)" style="width:200px"/>
    <label class="chk"><input type="checkbox" id="verify"/> verify (Z3)</label>
    <label class="chk"><input type="checkbox" id="agent"/> agent</label>
    <button class="primary" id="run">Analyze</button>
    <span class="badge" id="status"></span>
  </div>
  <div class="row">
    <span class="mode on" id="mode-single">Single</span>
    <span class="mode" id="mode-compare">Compare (vulnerable vs patched)</span>
  </div>
  <div id="single-pane">
    <textarea id="code" spellcheck="false"></textarea>
  </div>
  <div id="compare-pane" class="two" style="display:none">
    <div><textarea id="code-vuln" spellcheck="false"></textarea><div class="small">vulnerable version</div></div>
    <div><textarea id="code-patched" spellcheck="false"></textarea><div class="small">patched version</div></div>
  </div>
  <div class="small" style="margin-top:6px">Drag &amp; drop a file onto an editor to load it. Static analysis — your code is never executed.</div>

  <h2 style="margin-top:16px">Findings</h2>
  <div id="findings" class="small">Run an analysis to see results.</div>
  <div id="diff-block"></div>
  <div class="two" style="margin-top:14px">
    <div><h2 style="font-size:13px">V(x) ranking (top nodes)</h2><div id="top" class="small"></div></div>
    <div><div id="verify-block"></div><div id="agent-block"></div></div>
  </div>
  <h2 style="margin-top:18px">Manifold</h2>
  <svg id="map" viewBox="0 0 1000 440" preserveAspectRatio="xMidYMid meet"></svg>
  <div class="small" id="mlegend" style="margin-top:6px"></div>
</section>

<!-- EXPERIMENTS -->
<section class="tab" id="tab-experiments">
  <h2>Summary</h2><div class="cards" id="cards"></div>
  <h2 style="margin-top:18px">Prioritization oracle</h2>
  <div class="two">
    <div class="panel"><svg id="cost" viewBox="0 0 560 300"></svg></div>
    <div class="panel"><svg id="auc" viewBox="0 0 560 300"></svg></div>
  </div>
  <div id="oracle-table" style="margin-top:12px"></div>
  <h2 style="margin-top:18px">OWASP Benchmark 1.2</h2><div id="owasp-tables"></div>
  <h2 style="margin-top:18px">Real CVE fixes</h2><div id="cve-table"></div>
  <h2 style="margin-top:18px">Ablation</h2><div id="ablation-table"></div>
  <h2 style="margin-top:18px">Scalability</h2><div class="panel"><svg id="scale" viewBox="0 0 900 320"></svg></div>
</section>

<!-- METHODOLOGY -->
<section class="tab" id="tab-methodology">
  <h2>Pipeline</h2><div class="panel"><svg id="pipeline" viewBox="0 0 1120 160"></svg></div>
  <div class="two" style="margin-top:16px">
    <div><h2>Mathematical layers &rarr; signal &rarr; evidence</h2><div class="cards" id="layers"></div></div>
    <div><h2>Evaluation protocol</h2><div class="panel"><svg id="protocol" viewBox="0 0 560 360"></svg></div></div>
  </div>
  <h2 style="margin-top:16px">Mapping laws</h2><div id="laws"></div>
</section>

</main>
<script>
const $=s=>document.querySelector(s), NS="http://www.w3.org/2000/svg";
let RESULTS=null;

// ---- tabs ----
document.querySelectorAll("nav button").forEach(b=>b.onclick=()=>{
  document.querySelectorAll("nav button").forEach(x=>x.classList.remove("on"));
  document.querySelectorAll(".tab").forEach(x=>x.classList.remove("on"));
  b.classList.add("on"); $("#tab-"+b.dataset.tab).classList.add("on");
  if(b.dataset.tab!=="analyze" && !RESULTS) loadResults();
});

// ---- examples ----
async function loadExamples(){
  const ex=await (await fetch("/api/examples")).json();
  const sel=$("#example"); sel.innerHTML=`<option value="">— example —</option>`;
  ex.forEach(e=>{const o=document.createElement("option");o.value=e.name;o.textContent=`${e.name}  (${e.adapter})`;sel.appendChild(o);});
  sel.onchange=async()=>{ if(!sel.value)return; const d=await (await fetch("/api/example?name="+encodeURIComponent(sel.value))).json();
    $("#code").value=d.code; $("#adapter").value=d.adapter; $("#path").value=d.name; };
}
loadExamples();

// ---- mode + drag & drop ----
let MODE="single";
function setMode(m){ MODE=m;
  $("#mode-single").classList.toggle("on",m==="single");
  $("#mode-compare").classList.toggle("on",m==="compare");
  $("#single-pane").style.display=m==="single"?"":"none";
  $("#compare-pane").style.display=m==="compare"?"":"none";
  $("#diff-block").innerHTML=""; }
$("#mode-single").onclick=()=>setMode("single");
$("#mode-compare").onclick=()=>setMode("compare");

function makeDrop(el){
  el.addEventListener("dragover",e=>{e.preventDefault();el.style.borderColor="#58a6ff";});
  el.addEventListener("dragleave",()=>{el.style.borderColor="";});
  el.addEventListener("drop",e=>{e.preventDefault();el.style.borderColor="";
    const f=e.dataTransfer.files[0]; if(!f)return;
    const r=new FileReader();
    r.onload=()=>{el.value=r.result;
      const ext=(f.name.split(".").pop()||"").toLowerCase();
      const map={py:"python",java:"java",asm:"binary"}; if(map[ext])$("#adapter").value=map[ext];
      $("#path").value=f.name;};
    r.readAsText(f);});
}
["#code","#code-vuln","#code-patched"].forEach(s=>makeDrop($(s)));

// ---- analyze ----
$("#run").onclick=async()=>{
  $("#status").textContent="analyzing…";
  const common={path:$("#path").value||"<web>",adapter:$("#adapter").value||null,verify:$("#verify").checked,agent:$("#agent").checked};
  try{
    if(MODE==="compare"){
      const body={...common,vulnerable:$("#code-vuln").value,patched:$("#code-patched").value};
      const d=await (await fetch("/api/compare",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)})).json();
      if(d.error){$("#status").textContent="error: "+d.error;return;}
      renderCompare(d); $("#status").textContent=`${d.adapter} · compare`;
    } else {
      const body={...common,code:$("#code").value};
      const d=await (await fetch("/api/analyze",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)})).json();
      if(d.error){$("#status").textContent="error: "+d.error;return;}
      render(d); $("#diff-block").innerHTML="";
      $("#status").textContent=`${d.adapter} · ${d.nodes.length} nodes · ${d.findings.length} findings`;
    }
  }catch(e){$("#status").textContent="error: "+e;}
};

function findingsHtml(d){
  return d.findings.length? d.findings.map(f=>`<div class="finding ${f.severity}">
    <div class="sev" style="color:var(--${f.severity==='critical'?'red':(f.severity==='high'?'amber':'accent')})">${f.severity} · ${f.category}</div>
    <div>${f.title}</div><div class="small">line ${f.line} · sink ${f.sink_name} · sources ${(f.source_names||[]).join(", ")}</div></div>`).join("")
    : `<div class="small">no findings</div>`;
}
function topHtml(d){
  return (d.top||[]).map(t=>{const w=Math.max(2,Math.round(t.value*100));
    return `<div style="margin-bottom:5px"><div class="small">${t.label||t.id}</div><div class="bar"><i style="width:${w}%"></i></div></div>`;}).join("") || "<div class='small'>—</div>";
}
function verifyHtml(d){
  if(!d.verifications) return "";
  return `<h2 style="font-size:13px">Z3 verifications</h2>`+ (d.verifications.length? d.verifications.map(v=>`<div class="small">✓ ${v.category} · ${v.sink_name} (line ${v.line}) ${v.witness?('· witness '+JSON.stringify(v.witness)):''}</div>`).join("") : "<div class='small'>none confirmed</div>");
}
function agentHtml(d){
  if(!d.agent) return "";
  return `<h2 style="font-size:13px">Agent report</h2>`+ (d.agent.length? d.agent.map(a=>`<div class="small">[${a.status}] ${a.cwe} ${a.title} — ${a.signal}</div>`).join("") : "<div class='small'>no findings</div>");
}
function render(d){
  $("#findings").innerHTML=findingsHtml(d);
  $("#top").innerHTML=topHtml(d);
  $("#verify-block").innerHTML=verifyHtml(d);
  $("#agent-block").innerHTML=agentHtml(d);
  renderMap(d);
}
function renderCompare(d){
  const rows=(k,cls)=>`<div class="${cls}"><b>${k}</b>: ${d.diff[k].length? d.diff[k].map(x=>x[0]+":"+x[1]).join(", ") : "—"}</div>`;
  $("#diff-block").innerHTML=`<h2 style="margin-top:14px">Diff (vulnerable → patched)</h2>
    ${rows("resolved","resolved")}${rows("persisting","persisting")}${rows("introduced","introduced")}`;
  $("#findings").innerHTML=`<b>vulnerable</b>`+findingsHtml(d.vulnerable)+`<h2 style="font-size:13px;margin-top:12px">patched</h2>`+findingsHtml(d.patched);
  $("#top").innerHTML=topHtml(d.vulnerable);
  $("#verify-block").innerHTML=verifyHtml(d.vulnerable);
  $("#agent-block").innerHTML="";
  renderMap(d.vulnerable);
}

const COLORS={source:"#f85149",sink:"#d29922",function:"#58a6ff",gate:"#bc8cff",module:"#30363d",
  assign:"#a5d6ff",call:"#bc8cff",statement:"#8b949e",block:"#8b949e",variable:"#79c0ff",parameter:"#79c0ff"};
const ECOL={taint:"#f85149",call:"#58a6ff",data:"#3fb950",control:"#6e7681",trust:"#bc8cff",auth:"#d2a8ff"};
function renderMap(d){
  const svg=$("#map"); const W=1000,H=440;
  const nodes=d.nodes.map(n=>({...n,x:Math.random()*W,y:Math.random()*H})); const by={}; nodes.forEach(n=>by[n.id]=n);
  const N=nodes.length;
  for(let it=0;it<Math.max(60,400-N*2);it++){
    for(let i=0;i<N;i++)for(let j=i+1;j<N;j++){let dx=nodes[i].x-nodes[j].x,dy=nodes[i].y-nodes[j].y,d2=dx*dx+dy*dy+0.01,d=Math.sqrt(d2),f=900/d2;dx/=d;dy/=d;
      nodes[i].x+=dx*f;nodes[i].y+=dy*f;nodes[j].x-=dx*f;nodes[j].y-=dy*f;}
    d.edges.forEach(e=>{const a=by[e.src],b=by[e.dst];if(!a||!b)return;let dx=b.x-a.x,dy=b.y-a.y,dd=Math.sqrt(dx*dx+dy*dy)||0.01,f=(dd-90)*0.015;a.x+=dx/dd*f;a.y+=dy/dd*f;b.x-=dx/dd*f;b.y-=dy/dd*f;});
    nodes.forEach(n=>{n.x+=(W/2-n.x)*0.02;n.y+=(H/2-n.y)*0.02;n.x=Math.max(20,Math.min(W-20,n.x));n.y=Math.max(20,Math.min(H-20,n.y));});
  }
  let s="";
  d.edges.forEach(e=>{const a=by[e.src],b=by[e.dst];if(!a||!b)return;
    s+=`<line x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" stroke="${ECOL[e.kind]||"#6e7681"}" stroke-width="${e.kind==="taint"?2.5:1}" stroke-opacity="0.55"/>`;});
  nodes.forEach(n=>{const r=n.tainted?14:6+Math.min(10,(n.fiedler||0)*8);
    s+=`<circle cx="${n.x}" cy="${n.y}" r="${r}" fill="${COLORS[n.kind]||"#8b949e"}" ${n.tainted?'stroke="#f85149" stroke-width="1.5"':""}/>`;
    s+=`<text x="${n.x}" y="${n.y-r-4}" fill="#e6edf3" font-size="10" text-anchor="middle">${n.label}</text>`;});
  svg.innerHTML=s;
  $("#mlegend").innerHTML=Object.keys(COLORS).map(k=>`<span class="badge" style="margin-right:5px">${COLORS[k]} ${k}</span>`).join("");
}

// ---- experiments ----
async function loadResults(){ RESULTS=await (await fetch("/api/results")).json(); renderExperiments(RESULTS); renderMethodology(RESULTS); }
function lineChart(svg, series, opts){
  const W=560,H=300,m={l:56,r:16,t:16,b:38};
  const xs=[].concat(...series.map(s=>s.pts.map(p=>p[0]))), ys=[].concat(...series.map(s=>s.pts.map(p=>p[1])));
  const xlog=opts.xlog,ylog=opts.ylog,xmin=Math.min(...xs),xmax=Math.max(...xs),ymin=Math.min(...ys),ymax=Math.max(...ys);
  const X=x=>m.l+((xlog?(Math.log10(x)-Math.log10(xmin))/(Math.log10(xmax)-Math.log10(xmin)||1):(x-xmin)/((xmax-xmin)||1)))*(W-m.l-m.r);
  const Y=y=>H-m.b-((ylog?(Math.log10(y)-Math.log10(ymin))/(Math.log10(ymax)-Math.log10(ymin)||1):(y-ymin)/((ymax-ymin)||1)))*(H-m.t-m.b);
  let s=`<rect x="${m.l}" y="${m.t}" width="${W-m.l-m.r}" height="${H-m.t-m.b}" fill="none" stroke="#30363d"/>`;
  s+=`<text x="${W/2}" y="${H-6}" fill="#8b949e" font-size="11" text-anchor="middle">${opts.xlabel||""}</text>`;
  s+=`<text x="12" y="${H/2}" fill="#8b949e" font-size="11" text-anchor="middle" transform="rotate(-90 12 ${H/2})">${opts.ylabel||""}</text>`;
  series.forEach(ser=>{const dd=ser.pts.map((p,i)=>(i?"L":"M")+X(p[0]).toFixed(1)+" "+Y(p[1]).toFixed(1)).join(" ");
    s+=`<path d="${dd}" fill="none" stroke="${ser.color}" stroke-width="2"/>`;
    let ly=m.t+10+series.indexOf(ser)*13; s+=`<text x="${W-m.r-4}" y="${ly}" fill="${ser.color}" font-size="11" text-anchor="end">${ser.name}</text>`;});
  svg.innerHTML=s;
}
function table(rows,cols){return `<table><thead><tr>${cols.map(c=>`<th>${c}</th>`).join("")}</tr></thead><tbody>`+rows.map(r=>`<tr>${r.map(c=>`<td>${c}</td>`).join("")}</tr>`).join("")+`</tbody></table>`;}
function renderExperiments(R){
  const o=R.oracle||{}, a=o.signals_auc||{}, m=o.metrics||{};
  const cards=[["taint MRR",m.taint?m.taint.mrr:"-","prioritization"],["field MRR",m.field?m.field.mrr:"-","V(x) fused"],
    ["taint AUC",a.taint?a.taint.auc:"-","predict sink"],["geometric AUC",a.geometric?a.geometric.auc:"-","below chance"],
    ["adapter F1","0.681","OWASP all"],["Youden J","0.168","adapter"]];
  $("#cards").innerHTML=cards.map(([k,v,s])=>`<div class="card"><div class="small">${k}</div><div style="font-size:22px;font-weight:700">${v}</div><div class="small">${s}</div></div>`).join("");
  const pal={dfs:"#8b949e",taint:"#3fb950",field:"#58a6ff",random:"#f85149"};
  const curves=o.curves||{};
  lineChart($("#cost"),Object.keys(curves).map(k=>({name:k,color:pal[k]||"#999",pts:curves[k].map((v,i)=>[i+1,v])})),{xlabel:"verification budget",ylabel:"cumulative recall"});
  (function(){const svg=$("#auc");const W=560,H=300,mm={l:90,r:20,t:16,b:28};const keys=Object.keys(a);const bh=(H-mm.t-mm.b)/Math.max(keys.length,1);
    let s=`<text x="${W/2}" y="${H-6}" fill="#8b949e" font-size="11" text-anchor="middle">AUC (0.5 = chance)</text>`;
    keys.forEach((k,i)=>{const v=a[k].auc,w=(W-mm.l-mm.r)*v,y=mm.t+i*bh+bh*0.15,col=v>0.7?"#3fb950":(v>=0.45?"#d29922":"#f85149");
      s+=`<text x="${mm.l-8}" y="${y+12}" fill="#e6edf3" font-size="11" text-anchor="end">${k}</text>`;
      s+=`<rect x="${mm.l}" y="${y}" width="${w}" height="${bh*0.7}" fill="${col}" rx="3"/>`;
      s+=`<line x1="${mm.l+(W-mm.l-mm.r)*0.5}" y1="${mm.t}" x2="${mm.l+(W-mm.l-mm.r)*0.5}" y2="${H-mm.b}" stroke="#8b949e" stroke-dasharray="3 3"/>`;
      s+=`<text x="${mm.l+w+6}" y="${y+12}" fill="#8b949e" font-size="11">${v.toFixed(3)}</text>`;});
    svg.innerHTML=s;})();
  $("#oracle-table").innerHTML=table(Object.keys(m).map(k=>[k,m[k].mrr,m[k]["recall@1"],m[k].mean_rank,m[k]["ndcg@5"]]),["ranking","MRR","R@1","mean rank","NDCG@5"]);
  const ow=R.owasp||{};
  function block(t,obj){if(!obj)return "";const rows=Object.keys(obj).filter(k=>k!=="overall").sort().map(k=>{const v=obj[k];const fpr=v.fp/(v.fp+v.tn||1);return[k,v.tp,v.fp,v.fn,v.tn,v.precision.toFixed(3),v.recall.toFixed(3),v.f1.toFixed(3),(v.recall-fpr).toFixed(3)];});
    const ov=obj.overall,fpr=ov.fp/(ov.fp+ov.tn||1);rows.push(["<b>overall</b>",ov.tp,ov.fp,ov.fn,ov.tn,ov.precision.toFixed(3),ov.recall.toFixed(3),ov.f1.toFixed(3),(ov.recall-fpr).toFixed(3)]);
    return `<h3 style="font-size:12px;color:#8b949e">${t}</h3>`+table(rows,["category","TP","FP","FN","TN","P","R","F1","J"]);}
  $("#owasp-tables").innerHTML=block("adapter — all categories",ow.adapter_all)+block("adapter — taint",ow.adapter_taint)+block("adapter + Z3 — taint",ow.z3_taint);
  const ab=R.ablation||{}; $("#ablation-table").innerHTML=table(Object.keys(ab).map(k=>[k,ab[k].precision.toFixed(3),ab[k].recall.toFixed(3),ab[k].f1.toFixed(3)]),["variant","P","R","F1"]);
  const cves=R.cves||[]; const crows=[];
  cves.forEach(c=>{(c.files||[]).forEach(f=>{
    const res=f.resolved.length?`<span style="color:var(--green)">resolved</span>`:(f.persisting.length?`<span style="color:var(--amber)">persisting</span>`:"—");
    crows.push([c.cve, f.file, f.vuln_findings, f.patched_findings, res]);});});
  $("#cve-table").innerHTML = crows.length? table(crows,["CVE","file","vuln","patched","result"]) : "<div class='small'>no CVE data (run benchmarks/run_cves.py)</div>";
  (function(){const by={};R.scale.forEach(r=>{(by[r.kernel]=by[r.kernel]||[]).push([r.edges,r.ms]);});
    const col={forman:"#3fb950",mapper:"#58a6ff",homology:"#f85149",sinkhorn:"#d29922",ollivier_exact:"#bc8cff",spectral_fiedler:"#79c0ff",directed_laplacian:"#ffa657"};
    const ser=Object.keys(by).map(k=>({name:k,color:col[k]||"#999",pts:by[k].sort((x,y)=>x[0]-y[0])}));
    if(ser.length) lineChart($("#scale"),ser,{xlog:true,ylog:true,xlabel:"edges |E| (log)",ylabel:"ms (log)"});})();
}
// ---- methodology ----
function renderMethodology(R){
  const svg=$("#pipeline");const boxes=[["artifact",""],["IR\ntyped graph",""],["math\nlayers",""],["V(x)\nfield",""],["LLM\nagent",""],["Z3\nverifier",""]];
  const bw=150,bh=54,gap=30,x0=24,y=38;let s=`<defs><marker id="a1" markerWidth="9" markerHeight="9" refX="6" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6" fill="#58a6ff"/></marker></defs>`;
  boxes.forEach(([t],i)=>{const x=x0+i*(bw+gap);s+=`<rect x="${x}" y="${y}" width="${bw}" height="${bh}" rx="9" fill="#1c2330" stroke="#58a6ff"/>`;
    t.split("\n").forEach((ln,li)=>s+=`<text x="${x+bw/2}" y="${y+bh/2+5+(li-0.5)*15}" fill="#e6edf3" font-size="13" text-anchor="middle">${ln}</text>`);
    if(i<5)s+=`<line x1="${x+bw}" y1="${y+bh/2}" x2="${x+bw+gap-3}" y2="${y+bh/2}" stroke="#58a6ff" stroke-width="2" marker-end="url(#a1)"/>`;});
  const c1=x0+5*(bw+gap)+bw/2,c2=x0+(bw+gap)+bw/2;s+=`<path d="M${c1},${y+bh} L${c1},${y+bh+52} L${c2},${y+bh+52} L${c2},${y+bh}" fill="none" stroke="#8b949e" stroke-dasharray="5 4"/><text x="${(c1+c2)/2}" y="${y+bh+46}" fill="#8b949e" font-size="11" text-anchor="middle">re-embed</text>`;
  svg.innerHTML=s;
  const proto=$("#protocol");const steps=[["enumerate sink candidates","source→sink reachability"],["rank candidates","DFS · taint · V(x) · random"],["metrics","MRR · R@1 · NDCG@k · cost curve"],["Z3 arbiter","SAT + concrete witness"]];
  const W=560,bh2=56,g2=22,bw2=440,xx=(W-bw2)/2;let p=`<defs><marker id="a2" markerWidth="9" markerHeight="9" refX="6" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6" fill="#8b949e"/></marker></defs>`;
  steps.forEach(([t,sub],i)=>{const yy=16+i*(bh2+g2);p+=`<rect x="${xx}" y="${yy}" width="${bw2}" height="${bh2}" rx="9" fill="#161b22" stroke="#30363d"/><text x="${W/2}" y="${yy+24}" fill="#e6edf3" font-size="13" text-anchor="middle">${t}</text><text x="${W/2}" y="${yy+42}" fill="#8b949e" font-size="11" text-anchor="middle">${sub}</text>`;
    if(i<3)p+=`<line x1="${W/2}" y1="${yy+bh2}" x2="${W/2}" y2="${yy+bh2+g2-3}" stroke="#8b949e" stroke-width="2" marker-end="url(#a2)"/>`;});
  proto.innerHTML=p;
  const a=(R.oracle||{}).signals_auc||{};
  const layers=[["Spectral","L=D−A · Fiedler · embedding","|Fiedler|","spectral"],["Topological","persistent H₀/H₁ · Mapper","H₁ membership","topological"],["Geometric","Ollivier/Forman Ricci · Sinkhorn","curvature κ","geometric"],["Algebraic","taint lattice · Galois · auth functor","taint tags","taint"],["Formal","symbolic exec + SMT (Z3)","SAT(φ_bad)","formal"],["Directed","Chung Laplacian · SCC+Perron","directed λ₂","directed"]];
  $("#layers").innerHTML=layers.map(([n,d,sig,k])=>{let b=`<span class="badge">defined</span>`;if(a[k]){const v=a[k].auc;const c=v>0.7?"var(--green)":(v<0.45?"var(--red)":"var(--muted)");b=`<span class="badge" style="color:${c}">AUC ${v.toFixed(3)}</span>`;}
    return `<div class="card"><div class="small">${n}</div><div style="font-size:12.5px;margin-top:5px">${d}</div><div class="small" style="margin-top:5px">${sig} · ${b}</div></div>`;}).join("");
  const laws=[["L1","curvature κ≪0","priv. escalation","geometric"],["L2","persistent H₁","reentrancy","topological"],["L3","Fiedler cut","injection/trust","spectral"],["L4","taint crossing auth","naturality viol.",""],["L5","persistence outlier","real vs spurious","topological"],["L6","SAT(φ_bad)","concrete exploit","formal"]];
  const rows=laws.map(([id,f,c,k])=>{const v=k&&a[k]?a[k].auc:null;let st=k? "—" : "definitional (Prop. 2)";
    if(v!==null) st=v>0.7?`<span style="color:var(--green)">supported (${v.toFixed(3)})</span>`:(v<0.45?`<span style="color:var(--red)">not supported (${v.toFixed(3)})</span>`:`<span style="color:var(--amber)">at chance (${v.toFixed(3)})</span>`);
    return [id,f,c,st];});
  $("#laws").innerHTML=table(rows,["law","feature","class","status on OWASP"]);
}
</script>
</body>
</html>
"""

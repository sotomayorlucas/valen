"""Web UI for VALEN: a single-page app served by the stdlib HTTP server.

The page talks to ``/api/*`` endpoints (see ``valen/server.py``) to analyze code
live, browse the bundled examples, and render the experiment dashboard and the
methodology diagrams. The *analysis* core has no external dependencies; this
presentation shell uses Tailwind + Chart.js + D3 via CDN for a polished,
"modern terminal" look (the page still works offline with a graceful fallback).
"""

from __future__ import annotations

from .theme import head

PAGE = r"""<!doctype html>
<html lang="en">
<head>
__HEAD__
</head>
<body class="min-h-screen">
<div id="conn-banner" class="scan" style="display:none;background:#3a1016;color:#ff8c8c;padding:8px 16px;text-align:center;font-size:13px;border-bottom:1px solid #5c1f1f">
  Cannot reach the VALEN server (API fetch failed). Start it with <span class="mono">just serve</span> and open <span class="mono">http://127.0.0.1:8000</span> — do not open the HTML file directly.
</div>
<header class="sticky top-0 z-40 backdrop-blur border-b" style="border-color:var(--border);background:rgba(10,14,20,.85)">
  <div class="max-w-[1400px] mx-auto px-6 py-3 flex items-center gap-5 flex-wrap">
    <div class="flex items-center gap-3">
      <div class="w-8 h-8 rounded-lg grid place-items-center glow" style="background:linear-gradient(135deg,var(--spectral),var(--formal));color:#08111c;font-weight:800;font-family:var(--mono)">V</div>
      <div>
        <h1 class="text-lg font-bold leading-none tracking-tight">VALEN</h1>
        <div class="text-[11px]" style="color:var(--muted)">Verification And Active Logic Engine — neuro-symbolic</div>
      </div>
    </div>
    <nav class="flex gap-1.5 ml-auto">
      <button data-tab="analyze" class="on px-4 py-1.5 rounded-lg text-[13px]">Analyze</button>
      <button data-tab="dynamic" class="px-4 py-1.5 rounded-lg text-[13px]">Dynamic</button>
      <button data-tab="pentest" class="px-4 py-1.5 rounded-lg text-[13px]">Pentest</button>
      <button data-tab="cvss" class="px-4 py-1.5 rounded-lg text-[13px]">CVSS</button>
      <button data-tab="report" class="px-4 py-1.5 rounded-lg text-[13px]">Report</button>
      <button data-tab="cve" class="px-4 py-1.5 rounded-lg text-[13px]">CVE Intel</button>
      <button data-tab="history" class="px-4 py-1.5 rounded-lg text-[13px]">History</button>
      <button data-tab="experiments" class="px-4 py-1.5 rounded-lg text-[13px]">Experiments</button>
      <button data-tab="methodology" class="px-4 py-1.5 rounded-lg text-[13px]">Methodology</button>
    </nav>
  </div>
</header>

<main class="max-w-[1400px] mx-auto px-6 py-6">

<!-- ================= ANALYZE ================= -->
<section class="tab on" id="tab-analyze">
  <div class="grid lg:grid-cols-2 gap-5">
    <!-- left: input -->
    <div class="panel p-4">
      <div class="flex items-center gap-2 flex-wrap mb-3">
        <select id="example" class="bg-[#161d27] text-sm rounded-lg px-3 py-2 border" style="border-color:var(--border)"></select>
        <select id="adapter" class="bg-[#161d27] text-sm rounded-lg px-3 py-2 border" style="border-color:var(--border)">
          <option value="">auto</option>
          <option>python</option><option>java</option><option>java-interproc</option>
          <option>c</option><option>cpp</option><option>rust</option><option>csharp</option>
          <option>go</option><option>php</option><option>ruby</option><option>javascript</option>
          <option>binary</option><option>angr-binary</option><option>web</option>
          <option>llm-agent</option><option>iam</option>
        </select>
        <input id="path" placeholder="path (optional)" class="bg-[#161d27] text-sm rounded-lg px-3 py-2 border flex-1 min-w-[140px]" style="border-color:var(--border)"/>
        <select id="engagement" title="attach this run to an engagement" class="bg-[#161d27] text-sm rounded-lg px-3 py-2 border" style="border-color:var(--border)"></select>
      </div>
      <div class="flex items-center gap-4 flex-wrap mb-3">
        <span class="mode on" id="mode-single">Single</span>
        <span class="mode" id="mode-compare">Compare (vuln vs patched)</span>
        <label class="flex items-center gap-2 text-xs" style="color:var(--muted)"><input type="checkbox" id="verify" class="accent-blue-500"/> verify (Z3)</label>
        <label class="flex items-center gap-2 text-xs" style="color:var(--muted)"><input type="checkbox" id="agent" class="accent-blue-500"/> agent</label>
        <span class="ml-auto"><span class="pill" id="status">idle</span></span>
      </div>
      <div id="single-pane">
        <textarea id="code" spellcheck="false" class="mono w-full h-64 bg-[#0b0f14] border rounded-xl p-4 text-[12.5px] leading-relaxed" style="border-color:var(--border)"></textarea>
      </div>
      <div id="compare-pane" style="display:none" class="space-y-2">
        <div class="flex items-center gap-2">
          <select id="cve-pair" class="bg-[#161d27] text-sm rounded-lg px-3 py-2 border flex-1" style="border-color:var(--border)"><option value="">— load a real CVE fix pair —</option></select>
          <span class="pill" id="cve-meta"></span>
        </div>
        <textarea id="code-vuln" spellcheck="false" class="mono w-full h-40 bg-[#0b0f14] border rounded-xl p-3 text-[12.5px]" style="border-color:var(--border)"></textarea>
        <textarea id="code-patched" spellcheck="false" class="mono w-full h-40 bg-[#0b0f14] border rounded-xl p-3 text-[12.5px]" style="border-color:var(--border)"></textarea>
      </div>
      <button class="primary w-full mt-3 py-2.5 rounded-xl font-bold" id="run">Analyze</button>
      <div class="flex gap-2 mt-2">
        <button class="flex-1 py-2 rounded-xl text-[13px]" id="viz" style="border:1px solid var(--border);color:var(--muted)">Export valen HTML</button>
        <button class="flex-1 py-2 rounded-xl text-[13px]" id="json" style="border:1px solid var(--border);color:var(--muted)">Copy IR JSON</button>
      </div>
      <div class="text-[11px] mt-2" style="color:var(--muted)">Drag &amp; drop a file onto an editor. Static analysis — your code is never executed.</div>
    </div>

    <!-- right: results -->
    <div class="panel p-4 space-y-4">
      <div>
        <div class="kicker">Findings</div>
        <div id="findings" class="mt-2 space-y-2"></div>
      </div>
      <div id="diff-block"></div>
      <div class="grid grid-cols-2 gap-4">
        <div><div class="kicker">V(x) ranking</div><div id="top" class="mt-2 space-y-1"></div></div>
        <div><div class="kicker">Topology</div><div id="topology" class="mt-2 text-xs" style="color:var(--muted)"></div></div>
      </div>
      <div id="verify-block" class="text-xs" style="color:var(--muted)"></div>
      <div id="agent-block" class="text-xs" style="color:var(--muted)"></div>
    </div>
  </div>

  <div class="panel p-4 mt-5">
    <div class="flex items-center gap-3 mb-3">
      <div class="kicker">Valen — interactive vulnerability graph</div>
      <span class="text-[11px]" style="color:var(--muted)">wheel zoom · drag pan · drag node · hover highlights neighbours</span>
    </div>
    <svg id="map" class="w-full rounded-xl border" style="height:440px;border-color:var(--border);background:radial-gradient(circle at 50% 50%,#10161f,#0a0e14)"></svg>
    <div class="flex flex-wrap gap-2 mt-3" id="mlegend"></div>
  </div>
</section>

<!-- ================= DYNAMIC ================= -->
<section class="tab" id="tab-dynamic">
  <div class="grid lg:grid-cols-2 gap-5">
    <div class="panel p-4">
      <div class="kicker">Sandboxed dynamic run (python)</div>
      <div class="text-[11px] mt-1" style="color:var(--muted)">CLI parity: <span class="mono">valen --dynamic --argv … --timeout …</span> — executes the target in an isolated child process and triangulates the runtime trace against the static IR. Your code IS executed here (sandboxed).</div>
      <textarea id="dyn-code" spellcheck="false" class="mono w-full h-64 bg-[#0b0f14] border rounded-xl p-4 text-[12.5px] leading-relaxed mt-3" style="border-color:var(--border)"></textarea>
      <div class="flex items-center gap-3 mt-3 flex-wrap">
        <input id="dyn-argv" placeholder="--argv (space-separated)" class="bg-[#161d27] text-sm rounded-lg px-3 py-2 border flex-1 min-w-[180px]" style="border-color:var(--border)"/>
        <label class="text-xs" style="color:var(--muted)">timeout
          <input id="dyn-timeout" type="number" value="30" min="1" max="120" class="bg-[#161d27] text-sm rounded-lg px-2 py-2 border w-20 ml-1" style="border-color:var(--border)"/>
        </label>
        <button class="primary py-2 px-5 rounded-xl font-bold" id="dyn-run">Run</button>
        <span class="ml-auto"><span class="pill" id="dyn-status">idle</span></span>
      </div>
      <div id="dyn-error" class="text-xs mt-2" style="color:var(--algebraic)"></div>
    </div>
    <div class="panel p-4 space-y-4">
      <div class="grid grid-cols-3 gap-3">
        <div class="card"><div class="kicker">exit</div><div class="metric" id="dyn-exit">—</div></div>
        <div class="card"><div class="kicker">coverage</div><div class="metric" id="dyn-cov" style="color:var(--spectral)">—</div></div>
        <div class="card"><div class="kicker">lines</div><div class="metric" id="dyn-lines" style="color:var(--topological)">—</div></div>
      </div>
      <div>
        <div class="kicker">Agreement (static ↔ dynamic)</div>
        <div id="dyn-agree" class="mt-2 space-y-2"></div>
      </div>
      <div>
        <div class="kicker">Dynamic-only sinks (static missed)</div>
        <div id="dyn-only" class="mt-2 text-xs mono" style="color:var(--muted)"></div>
      </div>
    </div>
  </div>
</section>

<!-- ================= PENTEST ================= -->
<section class="tab" id="tab-pentest">
  <div class="panel p-4">
    <div class="kicker">Autonomous red-team engagement (crAPI lab)</div>
    <div class="text-[11px] mt-1" style="color:var(--muted)">CLI parity: <span class="mono">valen pentest --scope … --goal … --authorize --profile … --max-requests …</span>. Intrusive operators only run with explicit authorization.</div>
    <div class="flex items-end gap-3 mt-4 flex-wrap">
      <label class="text-xs" style="color:var(--muted)">scope
        <div><input id="pt-scope" placeholder="http://127.0.0.1:8888" class="bg-[#161d27] text-sm rounded-lg px-3 py-2 border w-64 mt-1" style="border-color:var(--border)"/></div>
      </label>
      <label class="text-xs" style="color:var(--muted)">goal
        <select id="pt-goal" class="bg-[#161d27] text-sm rounded-lg px-3 py-2 border mt-1" style="border-color:var(--border)">
          <option value="all">all (18 challenges)</option>
        </select>
      </label>
      <label class="text-xs" style="color:var(--muted)">profile
        <select id="pt-profile" class="bg-[#161d27] text-sm rounded-lg px-3 py-2 border mt-1" style="border-color:var(--border)">
          <option>paranoid</option><option selected>sneaky</option><option>polite</option><option>active</option>
        </select>
      </label>
      <label class="text-xs" style="color:var(--muted)">max requests
        <input id="pt-max" type="number" value="40" min="1" max="500" class="bg-[#161d27] text-sm rounded-lg px-2 py-2 border w-24 mt-1" style="border-color:var(--border)"/>
      </label>
      <label class="flex items-center gap-2 text-xs pb-2" style="color:var(--algebraic)">
        <input type="checkbox" id="pt-authorize" class="accent-red-500"/> --authorize (intrusive)
      </label>
      <label class="flex items-center gap-2 text-xs pb-2" style="color:var(--muted)">
        <input type="checkbox" id="pt-reset" class="accent-blue-500"/> reset lab first
      </label>
      <button class="primary py-2 px-5 rounded-xl font-bold" id="pt-run">Engage</button>
      <button class="py-2 px-4 rounded-xl text-[13px]" id="pt-lab-reset" style="border:1px solid var(--border);color:var(--geometric)">Reset lab</button>
      <span class="pb-2"><span class="pill" id="pt-status">idle</span></span>
    </div>
    <div id="pt-error" class="text-xs mt-2" style="color:var(--algebraic)"></div>
  </div>
  <div class="panel p-4 mt-5">
    <div class="flex items-center gap-3">
      <div class="kicker">Challenges</div>
      <span class="pill" id="pt-score"></span>
    </div>
    <div id="pt-results" class="mt-3 space-y-2"></div>
    <div class="flex items-center gap-2 mt-4 flex-wrap">
      <div class="kicker">Next step</div>
      <button class="primary py-2 px-5 rounded-xl font-bold" id="pt-report">Generate report →</button>
      <button class="py-2 px-4 rounded-xl text-[13px]" id="pt-report-dl" style="border:1px solid var(--border);color:var(--spectral)">Download HTML ↓</button>
      <a href="/console" target="_blank" class="py-2 px-4 rounded-xl text-[13px]" style="border:1px solid var(--border);color:var(--muted)">Open red-team console</a>
      <span class="text-[11px]" style="color:var(--muted)">the run is saved to benchmarks/autopentest_results.json and feeds the report + console</span>
    </div>
  </div>
</section>

<!-- ================= CVSS CALCULATOR ================= -->
<section class="tab" id="tab-cvss">
  <div class="grid lg:grid-cols-2 gap-5">
    <div class="panel p-4">
      <div class="flex items-center gap-3 mb-3">
        <div class="kicker">CVSS calculator (v3.1 + v4.0)</div>
        <select id="cvss-ver" class="bg-[#161d27] text-sm rounded-lg px-3 py-2 border ml-auto" style="border-color:var(--border)">
          <option value="3.1" selected>CVSS 3.1</option>
          <option value="4.0">CVSS 4.0</option>
        </select>
        <select id="cvss-preset" class="bg-[#161d27] text-sm rounded-lg px-3 py-2 border" style="border-color:var(--border)">
          <option value="">— preset category —</option>
        </select>
      </div>
      <div id="cvss-metrics" class="grid grid-cols-2 gap-2"></div>
      <div class="mt-3 p-3 rounded-xl" style="border:1px solid var(--border);background:var(--panel2)">
        <div class="kicker">Vector</div>
        <div class="mono text-[12px] mt-1" id="cvss-vector" style="word-break:break-all">—</div>
        <div class="flex items-center gap-3 mt-2">
          <div class="metric" id="cvss-score" style="color:var(--spectral)">0.0</div>
          <span class="pill" id="cvss-sev">None</span>
          <button class="ml-auto py-1.5 px-4 rounded-lg text-[12px]" id="cvss-copy" style="border:1px solid var(--border);color:var(--muted)">Copy vector</button>
        </div>
      </div>
    </div>
    <div class="panel p-4 space-y-3">
      <div class="kicker">Parse an existing vector</div>
      <div class="flex gap-2">
        <input id="cvss-input" placeholder="CVSS:3.1/AV:N/AC:L/..." class="bg-[#161d27] text-sm rounded-lg px-3 py-2 border flex-1" style="border-color:var(--border)"/>
        <button class="primary py-2 px-4 rounded-xl font-bold" id="cvss-parse">Score</button>
      </div>
      <div id="cvss-parse-out" class="text-xs mono" style="color:var(--muted)"></div>
      <div class="kicker mt-4">Category defaults (edit the vector on the left to adjust per finding)</div>
      <div id="cvss-cats" class="mt-2 space-y-1 text-[12px]"></div>
    </div>
  </div>
</section>

<!-- ================= REPORT ================= -->
<section class="tab" id="tab-report">
  <div class="panel p-4">
    <div class="kicker">Engagement metadata</div>
    <div class="grid sm:grid-cols-2 lg:grid-cols-3 gap-3 mt-3">
      <label class="text-xs" style="color:var(--muted)">client
        <input id="rp-client" class="bg-[#161d27] text-sm rounded-lg px-3 py-2 border w-full mt-1" style="border-color:var(--border)"/></label>
      <label class="text-xs" style="color:var(--muted)">scope
        <input id="rp-scope" placeholder="https://target.lab" class="bg-[#161d27] text-sm rounded-lg px-3 py-2 border w-full mt-1" style="border-color:var(--border)"/></label>
      <label class="text-xs" style="color:var(--muted)">author
        <input id="rp-author" class="bg-[#161d27] text-sm rounded-lg px-3 py-2 border w-full mt-1" style="border-color:var(--border)"/></label>
      <label class="text-xs" style="color:var(--muted)">start date
        <input id="rp-start" type="date" class="bg-[#161d27] text-sm rounded-lg px-3 py-2 border w-full mt-1" style="border-color:var(--border)"/></label>
      <label class="text-xs" style="color:var(--muted)">end date
        <input id="rp-end" type="date" class="bg-[#161d27] text-sm rounded-lg px-3 py-2 border w-full mt-1" style="border-color:var(--border)"/></label>
    </div>
    <label class="text-xs block mt-3" style="color:var(--muted)">rules of engagement
      <textarea id="rp-roe" class="mono w-full h-16 bg-[#0b0f14] border rounded-xl p-3 text-[12px] mt-1" style="border-color:var(--border)"></textarea></label>
    <label class="text-xs block mt-2" style="color:var(--muted)">limitations
      <textarea id="rp-limits" class="mono w-full h-16 bg-[#0b0f14] border rounded-xl p-3 text-[12px] mt-1" style="border-color:var(--border)"></textarea></label>
    <div class="flex items-center gap-2 mt-4 flex-wrap">
      <button class="primary py-2 px-5 rounded-xl font-bold" id="rp-generate">Generate</button>
      <button class="py-2 px-4 rounded-xl text-[13px]" id="rp-html" style="border:1px solid var(--border);color:var(--muted)">HTML</button>
      <button class="py-2 px-4 rounded-xl text-[13px]" id="rp-md" style="border:1px solid var(--border);color:var(--muted)">Markdown</button>
      <button class="py-2 px-4 rounded-xl text-[13px]" id="rp-json" style="border:1px solid var(--border);color:var(--muted)">JSON</button>
      <button class="py-2 px-4 rounded-xl text-[13px]" id="rp-sarif" style="border:1px solid var(--border);color:var(--muted)">SARIF</button>
      <span class="ml-auto"><span class="pill" id="rp-status">idle</span></span>
    </div>
    <div id="rp-error" class="text-xs mt-2" style="color:var(--algebraic)"></div>
  </div>
  <div class="panel p-4 mt-5">
    <div class="flex items-center gap-3">
      <div class="kicker">Preview</div>
      <span class="text-[11px]" style="color:var(--muted)">HTML render of the generated report</span>
    </div>
    <iframe id="rp-preview" class="w-full rounded-xl border mt-3" style="height:560px;border-color:var(--border);background:#0b1020"></iframe>
  </div>
</section>

<!-- ================= CVE INTEL ================= -->
<section class="tab" id="tab-cve">
  <div class="grid lg:grid-cols-2 gap-5">
    <div class="panel p-4">
      <div class="kicker">Lookup a CVE</div>
      <div class="flex gap-2 mt-3">
        <input id="cve-q" placeholder="CVE-2022-28346" class="bg-[#161d27] text-sm rounded-lg px-3 py-2 border flex-1" style="border-color:var(--border)"/>
        <button class="primary py-2 px-4 rounded-xl font-bold" id="cve-lookup">Lookup</button>
      </div>
      <div class="flex gap-2 mt-3">
        <input id="cve-prod" placeholder="product (e.g. Apache httpd)" class="bg-[#161d27] text-sm rounded-lg px-3 py-2 border flex-1" style="border-color:var(--border)"/>
        <input id="cve-ver" placeholder="version" class="bg-[#161d27] text-sm rounded-lg px-3 py-2 border w-32" style="border-color:var(--border)"/>
        <button class="py-2 px-4 rounded-xl text-[13px]" id="cve-prod-lookup" style="border:1px solid var(--border);color:var(--muted)">Product</button>
      </div>
      <div id="cve-out" class="mt-4 space-y-2"></div>
    </div>
    <div class="panel p-4">
      <div class="flex items-center gap-3">
        <div class="kicker">Offline snapshot (KEV + EPSS + NVD)</div>
        <button class="ml-auto py-1.5 px-4 rounded-lg text-[12px]" id="cve-all" style="border:1px solid var(--border);color:var(--muted)">Show all</button>
      </div>
      <div class="text-[11px] mt-1" style="color:var(--muted)">Refresh with <span class="mono">just cve-sync</span> (requires network). Works offline otherwise.</div>
      <div id="cve-list" class="mt-3 space-y-1 text-[12px] mono" style="color:var(--muted)"></div>
    </div>
  </div>
</section>

<!-- ================= HISTORY ================= -->
<section class="tab" id="tab-history">
  <div class="grid lg:grid-cols-3 gap-5">
    <div class="panel p-4">
      <div class="kicker">New engagement</div>
      <label class="text-xs block mt-3" style="color:var(--muted)">name
        <input id="eng-name" class="bg-[#161d27] text-sm rounded-lg px-3 py-2 border w-full mt-1" style="border-color:var(--border)"/></label>
      <label class="text-xs block mt-2" style="color:var(--muted)">client
        <input id="eng-client" class="bg-[#161d27] text-sm rounded-lg px-3 py-2 border w-full mt-1" style="border-color:var(--border)"/></label>
      <label class="text-xs block mt-2" style="color:var(--muted)">scope
        <input id="eng-scope" placeholder="http://127.0.0.1:8888" class="bg-[#161d27] text-sm rounded-lg px-3 py-2 border w-full mt-1" style="border-color:var(--border)"/></label>
      <button class="primary w-full mt-3 py-2 rounded-xl font-bold" id="eng-create">Create</button>
      <div id="eng-error" class="text-xs mt-2" style="color:var(--algebraic)"></div>
    </div>
    <div class="panel p-4 lg:col-span-2">
      <div class="kicker">Engagements</div>
      <div id="eng-list" class="mt-3 space-y-2"></div>
    </div>
  </div>
  <div class="panel p-4 mt-5">
    <div class="kick"> </div>
    <div class="flex items-center gap-3">
      <div class="kicker">Recent runs</div>
      <span class="pill" id="hist-count"></span>
      <button class="ml-auto py-1.5 px-4 rounded-lg text-[12px]" id="hist-refresh" style="border:1px solid var(--border);color:var(--muted)">Refresh</button>
    </div>
    <div id="hist-runs" class="mt-3"></div>
  </div>
</section>

<!-- ================= EXPERIMENTS ================= -->
<section class="tab" id="tab-experiments">
  <div class="grid sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-3" id="cards"></div>
  <div class="grid lg:grid-cols-2 gap-5 mt-5">
    <div class="panel p-4"><div class="kicker">Prioritization oracle — cost curve</div><div class="h-72 mt-2"><canvas id="cost"></canvas></div></div>
    <div class="panel p-4"><div class="kicker">Signal AUC (0.5 = chance)</div><div class="h-72 mt-2"><canvas id="auc"></canvas></div></div>
  </div>
  <div class="panel p-4 mt-5"><div class="kicker">Oracle metrics</div><div id="oracle-table" class="mt-2"></div></div>
  <div class="panel p-4 mt-5"><div class="kicker">OWASP Benchmark 1.2</div><div id="owasp-tables" class="mt-2"></div></div>
  <div class="grid lg:grid-cols-2 gap-5 mt-5">
    <div class="panel p-4"><div class="kicker">Real CVE fixes</div><div id="cve-table" class="mt-2"></div></div>
    <div class="panel p-4"><div class="kicker">LLM ablation</div><div id="llm-table" class="mt-2"></div></div>
  </div>
  <div class="panel p-4 mt-5"><div class="kicker">Ablation (Java adapter)</div><div id="ablation-table" class="mt-2"></div></div>
  <div class="panel p-4 mt-5"><div class="kicker">Scalability (log-log)</div><div class="h-80 mt-2"><canvas id="scale"></canvas></div></div>
</section>

<!-- ================= METHODOLOGY ================= -->
<section class="tab" id="tab-methodology">
  <div class="panel p-4">
    <div class="kicker">Pipeline</div>
    <div class="h-40 mt-2"><canvas id="pipeline"></canvas></div>
  </div>
  <div class="grid lg:grid-cols-2 gap-5 mt-5">
    <div class="panel p-4">
      <div class="kicker">Mathematical layers → signal → evidence</div>
      <div class="grid grid-cols-2 gap-3 mt-3" id="layers"></div>
    </div>
    <div class="panel p-4">
      <div class="kicker">Evaluation protocol</div>
      <div class="h-80 mt-2"><canvas id="protocol"></canvas></div>
    </div>
  </div>
  <div class="panel p-4 mt-5">
    <div class="kicker">Mapping hypotheses (feature → vulnerability class)</div>
    <div id="laws" class="mt-2"></div>
  </div>
</section>

</main>

<footer class="max-w-[1400px] mx-auto px-6 pb-8 text-[11px]" style="color:var(--muted)">
  <span class="mono">VALEN</span> — neuro-symbolic structural-invariant verifier · static (taint) + symbolic (Z3) + dynamic (sandboxed trace) triangulation.
</footer>

<script>
__SHELL__
</script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/d3@7/dist/d3.min.js"></script>
</body>
</html>
"""

# -- the page JS (tailwind classes on nav/mode are applied via inline style) --
SHELL_JS = r"""
// Optional bearer token injected by the server for loopback clients (--token).
const VALEN_TOKEN = "__VALEN_TOKEN__";
if(VALEN_TOKEN){
  const _f=window.fetch.bind(window);
  window.fetch=(u,o={})=>{
    if(typeof u==="string" && u.startsWith("/api/")){
      o={...o, headers:{...(o.headers||{}), "Authorization":"Bearer "+VALEN_TOKEN}};
    }
    return _f(u,o);
  };
}
const $=s=>document.querySelector(s), NS="http://www.w3.org/2000/svg";
const esc=s=>String(s==null?"":s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
let RESULTS=null;

// connectivity guard: surface a clear message instead of a cryptic
// "TypeError: Failed to fetch" when the server is down or the page was opened
// as a file:// (relative /api/* then cannot resolve).
function connBanner(show){
  const b=document.getElementById("conn-banner");
  if(b) b.style.display = show ? "block" : "none";
}
async function ping(){
  try{ await fetch("/api/adapters",{cache:"no-store"}); connBanner(false); }
  catch(e){ connBanner(true); }
}
ping();

// nav + tab styling (manual, no tailwind runtime dependency)
const NAVON="background:var(--spectral);color:#08111c;font-weight:700;border:1px solid var(--spectral)";
const NAVOFF="background:transparent;color:var(--muted);border:1px solid var(--border)";
document.querySelectorAll("nav button").forEach(b=>{b.style.cssText=NAVOFF; b.onclick=()=>{
  document.querySelectorAll("nav button").forEach(x=>x.style.cssText=NAVOFF);
  document.querySelectorAll(".tab").forEach(x=>x.classList.remove("on"));
  b.style.cssText=NAVON; b.classList.add("on"); $("#tab-"+b.dataset.tab).classList.add("on");
  if(b.dataset.tab==="history"){ loadEngagements(); loadHistory(); }
  else if(b.dataset.tab!=="analyze" && !RESULTS) loadResults();
};});
document.querySelector("nav button[data-tab=analyze]").style.cssText=NAVON;

// examples
async function loadExamples(){
  let ex=[]; try{ ex=await (await fetch("/api/examples")).json(); }catch(e){ connBanner(true); return; }
  const sel=$("#example"); sel.innerHTML=`<option value="">— example —</option>`;
  ex.forEach(e=>{const o=document.createElement("option");o.value=e.name;o.textContent=`${e.name}  (${e.adapter})`;sel.appendChild(o);});
  sel.onchange=async()=>{ if(!sel.value)return; const d=await (await fetch("/api/example?name="+encodeURIComponent(sel.value))).json();
    $("#code").value=d.code; $("#adapter").value=d.adapter; $("#path").value=d.name; };
}
loadExamples();

// CVE pairs
async function loadCves(){
  let pairs=[]; try{ pairs=await (await fetch("/api/cves")).json(); }catch(e){}
  const sel=$("#cve-pair");
  pairs.forEach((p,i)=>{const o=document.createElement("option");o.value=i;o.textContent=`${p.cve} · ${p.file.split("/").pop()}`;sel.appendChild(o);});
  sel.onchange=()=>{ if(sel.value==="")return; const p=pairs[+sel.value];
    setMode("compare"); $("#code-vuln").value=p.vulnerable; $("#code-patched").value=p.patched;
    $("#adapter").value=p.adapter; $("#path").value=p.file;
    $("#cve-meta").textContent=`${p.cve} · ${p.resolved?"resolved":"—"}`; };
}
loadCves();

// mode + drag & drop
let MODE="single";
function setMode(m){ MODE=m;
  $("#mode-single").style.cssText=m==="single"?"background:var(--spectral);color:#08111c;font-weight:700":"";
  $("#mode-compare").style.cssText=m==="compare"?"background:var(--spectral);color:#08111c;font-weight:700":"";
  $("#single-pane").style.display=m==="single"?"":"none";
  $("#compare-pane").style.display=m==="compare"?"":"none";
  $("#diff-block").innerHTML=""; }
document.querySelectorAll(".mode").forEach(m=>m.style.cssText="padding:4px 10px;border-radius:8px;cursor:pointer;border:1px solid var(--border)");
$("#mode-single").onclick=()=>setMode("single");
$("#mode-compare").onclick=()=>setMode("compare");
setMode("single");

function makeDrop(el){
  el.addEventListener("dragover",e=>{e.preventDefault();el.style.borderColor="#58a6ff";});
  el.addEventListener("dragleave",()=>{el.style.borderColor="";});
  el.addEventListener("drop",e=>{e.preventDefault();el.style.borderColor="";
    const f=e.dataTransfer.files[0]; if(!f)return;
    const r=new FileReader();
    r.onload=()=>{el.value=r.result;
      const ext=(f.name.split(".").pop()||"").toLowerCase();
      const map={py:"python",java:"java",asm:"binary",c:"c",h:"c",cpp:"cpp",cc:"cpp",cxx:"cpp",
        rs:"rust",cs:"csharp",go:"go",php:"php",rb:"ruby",js:"javascript",mjs:"javascript",
        cjs:"javascript",jsx:"javascript",ts:"javascript",tsx:"javascript"}; if(map[ext])$("#adapter").value=map[ext];
      $("#path").value=f.name;};
    r.readAsText(f);});
}
["#code","#code-vuln","#code-patched"].forEach(s=>makeDrop($(s)));

// analyze
$("#run").onclick=async()=>{
  $("#status").textContent="analyzing…";
  const common={path:$("#path").value||"<web>",adapter:$("#adapter").value||null,verify:$("#verify").checked,agent:$("#agent").checked,
    engagement_id: ($("#engagement")&&$("#engagement").value)? +$("#engagement").value : null};
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

// export viz HTML (POST /api/viz -> download)
$("#viz").onclick=async()=>{
  const body={path:$("#path").value||"<web>",adapter:$("#adapter").value||null,
    code:MODE==="compare"?$("#code-vuln").value:$("#code").value};
  $("#status").textContent="rendering valen…";
  try{
    const r=await fetch("/api/viz",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
    if(!r.ok){$("#status").textContent="viz error "+r.status;return;}
    const html=await r.text();
    const a=document.createElement("a");
    a.href=URL.createObjectURL(new Blob([html],{type:"text/html"}));
    a.download=(body.path.replace(/[^\w.-]+/g,"_")||"valen")+".html";
    a.click(); URL.revokeObjectURL(a.href);
    $("#status").textContent="valen exported";
  }catch(e){$("#status").textContent="error: "+e;}
};
$("#json").onclick=async()=>{
  const body={path:$("#path").value||"<web>",adapter:$("#adapter").value||null,
    code:MODE==="compare"?$("#code-vuln").value:$("#code").value};
  try{
    const d=await (await fetch("/api/analyze",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)})).json();
    if(d.error){$("#status").textContent="error: "+d.error;return;}
    await navigator.clipboard.writeText(JSON.stringify({nodes:d.nodes,edges:d.edges,findings:d.findings},null,2));
    $("#status").textContent="IR JSON copied";
  }catch(e){$("#status").textContent="error: "+e;}
};

// ---- dynamic panel ----
$("#dyn-run").onclick=async()=>{
  $("#dyn-error").textContent="";
  $("#dyn-status").textContent="running…";
  const argv=($("#dyn-argv").value||"").trim();
  const body={code:$("#dyn-code").value,adapter:"python",
    argv:argv?argv.split(/\s+/):null,
    timeout:parseFloat($("#dyn-timeout").value)||30};
  try{
    const d=await (await fetch("/api/dynamic",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)})).json();
    if(d.error){$("#dyn-status").textContent="error";$("#dyn-error").textContent=d.error;return;}
    const cov=d.coverage||{};
    $("#dyn-exit").textContent=d.exit_code;
    $("#dyn-cov").textContent=(cov.ratio!=null?Math.round(cov.ratio*100)+"%":"—");
    $("#dyn-lines").textContent=cov.lines!=null?cov.lines:"—";
    const SEV={confirmed:"var(--topological)",hit:"var(--geometric)",unexecuted:"var(--muted)"};
    const TAG={confirmed:"CONFIRMED",hit:"HIT",unexecuted:"UNEXECUTED"};
    $("#dyn-agree").innerHTML=(d.agreement||[]).length? d.agreement.map(a=>`<div class="card" style="padding:8px;border-left:3px solid ${SEV[a.dynamic]||'var(--muted)'}">
      <div class="mono text-[11px]"><span style="color:${SEV[a.dynamic]}">[${TAG[a.dynamic]||a.dynamic}]</span> line ${a.line}: ${a.sink_name}${a.matched_value?` · <span style="color:var(--geometric)">${String(a.matched_value).slice(0,80)}</span>`:""}</div></div>`).join("")
      : `<div class="text-xs" style="color:var(--muted)">no static sinks to triangulate</div>`;
    $("#dyn-only").innerHTML=(d.dynamic_only_sinks||[]).length? d.dynamic_only_sinks.map(s=>`<div>line ${s.line}: ${s.name} (${s.category})</div>`).join("") : "—";
    $("#dyn-status").textContent=`exit ${d.exit_code} · ${(cov.ratio!=null?Math.round(cov.ratio*100):0)}% cov`;
  }catch(e){$("#dyn-status").textContent="error";$("#dyn-error").textContent=String(e);}
};

// ---- pentest panel ----
async function loadChallenges(){
  try{
    const list=await (await fetch("/api/challenges")).json();
    const sel=$("#pt-goal");
    (list||[]).forEach(c=>{const o=document.createElement("option");o.value=c.id;o.textContent=c.id;sel.appendChild(o);});
  }catch(e){}
}
loadChallenges();
$("#pt-run").onclick=async()=>{
  $("#pt-error").textContent="";
  $("#pt-status").textContent="engaging…";
  const body={scope:$("#pt-scope").value.trim(),goal:$("#pt-goal").value,
    authorize:$("#pt-authorize").checked,profile:$("#pt-profile").value,
    max_requests:parseInt($("#pt-max").value)||40,reset:$("#pt-reset").checked,
    engagement_id: ($("#engagement")&&$("#engagement").value)? +$("#engagement").value : null};
  try{
    const d=await (await fetch("/api/pentest",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)})).json();
    if(d.error){$("#pt-status").textContent="error";$("#pt-error").textContent=d.error;return;}
    if(d.scope){$("#pt-scope").value=d.scope;}  // server normalizes to the origin
    if(d.warning){$("#pt-error").style.color="var(--geometric)";$("#pt-error").textContent="note: "+d.warning;}
    else{$("#pt-error").style.color="var(--algebraic)";$("#pt-error").textContent="";}
    $("#pt-score").textContent=`${d.solved}/${d.total} solved`;
    const auditHtml=(r)=>{
      const audit=r.audit||[]; const ev=r.evidence||"";
      if(!audit.length && !ev) return "";
      const rows=audit.map(a=>`<div class="mono text-[10px]" style="color:var(--muted)">${a.op||""} ${a.status!=null?"→ "+a.status:""} ${a.skipped?"(skipped: "+a.skipped+")":""} ${a.snippet?("· "+String(a.snippet).slice(0,90)):""}</div>`).join("");
      return `<details class="mt-2"><summary class="text-[10px]" style="color:var(--muted);cursor:pointer">audit (${audit.length} ops)${ev?" + evidence":""}</summary>${rows}${ev?`<pre class="mono text-[10px] mt-1" style="white-space:pre-wrap;color:var(--muted)">${String(ev).slice(0,400)}</pre>`:""}</details>`;
    };
    $("#pt-results").innerHTML=(d.challenges||[]).map(r=>`<div class="card" style="padding:10px;border-left:3px solid ${r.solved?'var(--topological)':'var(--muted)'}">
      <div class="flex items-center gap-2">
        <span class="mono text-[12px]">${r.challenge}</span>
        <span class="pill" style="color:${r.solved?'var(--topological)':'var(--muted)'}">${r.solved?'SOLVED':'not solved'}</span>
        <span class="text-[11px] ml-auto" style="color:var(--muted)">${r.requests} req · ${r.seconds}s</span>
      </div>${auditHtml(r)}</div>`).join("");
    $("#pt-status").textContent=`${d.solved}/${d.total}`;
  }catch(e){$("#pt-status").textContent="error";$("#pt-error").textContent=String(e);}
};
// after solving: hand off to the Report tab, prefilled with the engagement scope
function prefillEngagement(){
  const scope=$("#pt-scope").value.trim() || "http://127.0.0.1:8888";
  if(!$("#rp-scope").value) $("#rp-scope").value=scope;
  if(!$("#rp-client").value) $("#rp-client").value="crAPI lab";
}
$("#pt-report").onclick=async()=>{
  document.querySelector("nav button[data-tab=report]").click();
  await new Promise(r=>setTimeout(r,50));
  prefillEngagement();
  $("#rp-generate").click();
};
$("#pt-report-dl").onclick=()=>{ prefillEngagement(); downloadReport("html"); };
$("#pt-lab-reset").onclick=async()=>{
  if(!confirm("Reset the crAPI lab? This runs `docker compose down -v` (wipes all lab data).")) return;
  $("#pt-error").style.color="var(--algebraic)"; $("#pt-error").textContent="";
  $("#pt-status").textContent="resetting lab…";
  const body={scope:$("#pt-scope").value.trim()||"http://127.0.0.1:8888",authorize:true};
  try{
    const d=await (await fetch("/api/lab/reset",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)})).json();
    if(d.error){$("#pt-status").textContent="reset failed";$("#pt-error").textContent=d.error;return;}
    $("#pt-status").textContent=d.ok?"lab ready":"lab not healthy";
    $("#pt-error").style.color=d.ok?"var(--topological)":"var(--geometric)";
    $("#pt-error").textContent=(d.log||[]).join(" · ");
  }catch(e){$("#pt-status").textContent="error";$("#pt-error").textContent=String(e);}
};

// ---- CVSS calculator ----
const CVSS31_METRICS = [
  ["AV","Attack Vector",["N","A","L","P"],["Network","Adjacent","Local","Physical"]],
  ["AC","Attack Complexity",["L","H"],["Low","High"]],
  ["PR","Privileges Required",["N","L","H"],["None","Low","High"]],
  ["UI","User Interaction",["N","R"],["None","Required"]],
  ["S","Scope",["U","C"],["Unchanged","Changed"]],
  ["C","Confidentiality",["H","L","N"],["High","Low","None"]],
  ["I","Integrity",["H","L","N"],["High","Low","None"]],
  ["A","Availability",["H","L","N"],["High","Low","None"]],
];
const CVSS40_METRICS = [
  ["AV","Attack Vector",["N","A","L","P"],["Network","Adjacent","Local","Physical"]],
  ["AC","Attack Complexity",["L","H"],["Low","High"]],
  ["AT","Attack Requirements",["N","P"],["None","Present"]],
  ["PR","Privileges Required",["N","L","H"],["None","Low","High"]],
  ["UI","User Interaction",["N","P","A"],["None","Passive","Active"]],
  ["VC","Vuln Confidentiality",["H","L","N"],["High","Low","None"]],
  ["VI","Vuln Integrity",["H","L","N"],["High","Low","None"]],
  ["VA","Vuln Availability",["H","L","N"],["High","Low","None"]],
  ["SC","Subs Confidentiality",["H","L","N"],["High","Low","None"]],
  ["SI","Subs Integrity",["H","L","N"],["High","Low","None"]],
  ["SA","Subs Availability",["H","L","N"],["High","Low","None"]],
];
let CVSS_STATE = {AV:"N",AC:"L",PR:"N",UI:"N",S:"U",C:"H",I:"H",A:"H",
                  AT:"N",VC:"H",VI:"H",VA:"H",SC:"H",SI:"H",SA:"H"};

function cvssRender(){
  const ver = $("#cvss-ver").value;
  const metrics = ver.startsWith("4") ? CVSS40_METRICS : CVSS31_METRICS;
  $("#cvss-metrics").innerHTML = metrics.map(([k,label,vals,labels])=>`
    <div class="card" style="padding:8px">
      <div class="kicker">${label}</div>
      <div class="flex gap-1 mt-1 flex-wrap">${vals.map((v,i)=>`
        <span class="cvss-opt" data-k="${k}" data-v="${v}" style="cursor:pointer;padding:3px 8px;border-radius:6px;font-size:11px;border:1px solid var(--border);
          background:${CVSS_STATE[k]===v?'var(--spectral)':'var(--panel2)'};color:${CVSS_STATE[k]===v?'#08111c':'var(--muted)'}">${labels[i]}</span>`).join("")}
      </div>
    </div>`).join("");
  document.querySelectorAll(".cvss-opt").forEach(el=>{
    el.onclick=()=>{ CVSS_STATE[el.dataset.k]=el.dataset.v; cvssRender(); };
  });
  const body = metrics.map(([k])=>`${k}:${CVSS_STATE[k]}`).join("/");
  const vector = `CVSS:${ver}/${body}`;
  $("#cvss-vector").textContent = vector;
  scoreVector(vector);
}
async function scoreVector(vector){
  try{
    const d = await (await fetch("/api/cvss",{method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({vector})})).json();
    if(d.error){$("#cvss-score").textContent="—";$("#cvss-sev").textContent="error";return;}
    $("#cvss-score").textContent = d.score.toFixed(1);
    const col = d.severity==="Critical"?"var(--algebraic)":d.severity==="High"?"var(--geometric)":
      d.severity==="Medium"?"var(--spectral)":"var(--muted)";
    $("#cvss-score").style.color = col;
    const sev=$("#cvss-sev"); sev.textContent = d.severity; sev.style.color = col;
  }catch(e){$("#cvss-score").textContent="—";}
}
$("#cvss-ver").onchange=()=>{ cvssRender(); };
$("#cvss-copy").onclick=()=>{ navigator.clipboard && navigator.clipboard.writeText($("#cvss-vector").textContent); };
$("#cvss-parse").onclick=async()=>{
  const v = $("#cvss-input").value.trim();
  if(!v) return;
  const d = await (await fetch("/api/cvss",{method:"POST",
    headers:{"Content-Type":"application/json"},
    body:JSON.stringify({vector:v})})).json();
  $("#cvss-parse-out").textContent = d.error ? "error: "+d.error
    : `${d.vector}  →  ${d.score.toFixed(1)} (${d.severity})`;
};
async function loadCvssPresets(){
  try{
    const list = await (await fetch("/api/categories")).json();
    const sel = $("#cvss-preset");
    (list||[]).forEach(c=>{
      const o=document.createElement("option"); o.value=c.name;
      o.textContent=`${c.name} (${c.severity})`; sel.appendChild(o);
    });
    $("#cvss-cats").innerHTML = (list||[]).slice(0,20).map(c=>
      `<div class="mono truncate">${c.name} · ${c.severity} · ${(c.cwe||[]).join(", ")}</div>`).join("");
  }catch(e){}
}
loadCvssPresets();
$("#cvss-preset").onchange=async()=>{
  const name = $("#cvss-preset").value;
  if(!name) return;
  const d = await (await fetch("/api/cvss",{method:"POST",
    headers:{"Content-Type":"application/json"},
    body:JSON.stringify({category:name})})).json();
  if(d.error) return;
  if(d.cvss31){
    // parse the category's 3.1 vector into state and re-render
    (d.cvss31.vector.split("/").slice(1)||[]).forEach(p=>{
      const [k,v] = p.split(":"); if(k && v) CVSS_STATE[k]=v;
    });
    $("#cvss-ver").value = "3.1";
    cvssRender();
  }
};
cvssRender();

// ---- report panel ----
function engagementPayload(){
  return {client:$("#rp-client").value, scope:$("#rp-scope").value,
    author:$("#rp-author").value, date_start:$("#rp-start").value,
    date_end:$("#rp-end").value, roe:$("#rp-roe").value,
    limitations:$("#rp-limits").value};
}
async function generateReport(fmt){
  $("#rp-error").textContent="";
  $("#rp-status").textContent="generating…";
  const body = {format:fmt||"html", engagement:engagementPayload()};
  try{
    const d = await (await fetch("/api/report",{method:"POST",
      headers:{"Content-Type":"application/json"}, body:JSON.stringify(body)})).json();
    if(d.error){$("#rp-status").textContent="error";$("#rp-error").textContent=d.error;return null;}
    $("#rp-status").textContent=`${d.n} findings · ${d.format}`;
    return d;
  }catch(e){$("#rp-status").textContent="error";$("#rp-error").textContent=String(e);return null;}
}
$("#rp-generate").onclick=async()=>{
  const d = await generateReport("html");
  if(d && d.content) $("#rp-preview").srcdoc = d.content;
};
function downloadReport(fmt){
  generateReport(fmt).then(d=>{
    if(!d || !d.content) return;
    const ext = fmt==="markdown"?"md":fmt;
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([d.content], {type: fmt==="html"?"text/html":"text/plain"}));
    a.download = "valen-report." + ext;
    a.click(); URL.revokeObjectURL(a.href);
  });
}
$("#rp-html").onclick=()=>downloadReport("html");
$("#rp-md").onclick=()=>downloadReport("md");
$("#rp-json").onclick=()=>downloadReport("json");
$("#rp-sarif").onclick=()=>downloadReport("sarif");

// ---- CVE intel ----
function cveCard(r){
  if(!r || !r.cve) return `<div class="text-xs" style="color:var(--muted)">not found</div>`;
  const sev = r.cvss_score>=9?"var(--algebraic)":r.cvss_score>=7?"var(--geometric)":
    r.cvss_score>=4?"var(--spectral)":"var(--muted)";
  return `<div class="card" style="padding:12px">
    <div class="flex items-center gap-2 flex-wrap">
      <span class="mono font-bold">${r.cve}</span>
      ${r.kev?`<span class="pill" style="color:var(--algebraic)">KEV</span>`:""}
      <span class="pill">${(r.product||"").slice(0,24)}</span>
      <span class="metric ml-auto" style="color:${sev};font-size:18px">${(r.cvss_score||0).toFixed(1)}</span>
    </div>
    <div class="text-[11px] mt-2" style="color:var(--muted)">${(r.cwe||[]).join(", ")}${r.epss?` · EPSS ${Number(r.epss).toFixed(3)}`:""}${r.kev_date_added?` · KEV ${r.kev_date_added}`:""}</div>
    <div class="text-[12px] mt-2" style="color:var(--text)">${(r.description||"").slice(0,240)}</div>
    <div class="mono text-[10px] mt-2" style="color:var(--muted);word-break:break-all">${r.cvss_vector||""}</div>
  </div>`;
}
$("#cve-lookup").onclick=async()=>{
  const q = $("#cve-q").value.trim();
  if(!q) return;
  const d = await (await fetch("/api/cve?q="+encodeURIComponent(q))).json();
  $("#cve-out").innerHTML = cveCard(d);
};
$("#cve-prod-lookup").onclick=async()=>{
  const p = $("#cve-prod").value.trim(), v = $("#cve-ver").value.trim();
  if(!p) return;
  const url = "/api/cve?product="+encodeURIComponent(p)+(v?"&version="+encodeURIComponent(v):"");
  const list = await (await fetch(url)).json();
  $("#cve-out").innerHTML = (list&&list.length)? list.map(cveCard).join("")
    : `<div class="text-xs" style="color:var(--muted)">no CVEs for this product</div>`;
};
$("#cve-all").onclick=async()=>{
  const list = await (await fetch("/api/cve")).json();
  $("#cve-list").innerHTML = (list||[]).map(r=>
    `<div class="truncate">${r.cve} · ${(r.product||"").slice(0,18)} · ${(r.cvss_score||0).toFixed(1)}${r.kev?" ·KEV":""}${r.epss?` ·E ${Number(r.epss).toFixed(2)}`:""}</div>`).join("");
};

// ---- history / engagements ----
async function loadEngagements(){
  try{
    const list = await (await fetch("/api/engagements")).json();
    const sel=$("#engagement");
    if(sel){
      const cur=sel.value;
      sel.innerHTML=`<option value="">no engagement</option>`+
        (list||[]).map(e=>`<option value="${e.id}">#${e.id} ${esc(e.name)} (${e.run_count})</option>`).join("");
      sel.value=cur;
    }
    $("#eng-list").innerHTML=(list&&list.length)? list.map(e=>`<div class="card" style="padding:10px">
      <div class="flex items-center gap-2">
        <b>#${e.id} ${esc(e.name)}</b>
        <span class="pill ml-auto">${e.run_count} runs</span>
        <button class="py-1 px-2 rounded text-[11px]" style="border:1px solid var(--border);color:var(--algebraic)" onclick="delEng(${e.id})">delete</button>
      </div>
      <div class="text-[11px] mt-1" style="color:var(--muted)">${esc(e.client||"—")} · ${esc(e.scope||"")}</div></div>`).join("")
      : `<div class="text-xs" style="color:var(--muted)">no engagements yet</div>`;
  }catch(e){}
}
async function loadHistory(){
  try{
    const d = await (await fetch("/api/history?limit=50")).json();
    if(d.error){ $("#hist-count").textContent="store disabled"; return; }
    $("#hist-count").textContent=`${d.count.engagements} engagements · ${d.count.runs} runs`;
    $("#hist-runs").innerHTML=(d.runs||[]).length?
      `<table><thead><tr><th>when</th><th>kind</th><th>name</th><th>adapter</th><th>summary</th><th>engagement</th></tr></thead><tbody>`+
      d.runs.map(r=>`<tr><td class="mono text-[11px]">${new Date(r.created_at*1000).toLocaleString()}</td>
        <td>${esc(r.kind)}</td><td>${esc(r.name)}</td><td>${esc(r.adapter)}</td>
        <td>${esc(r.summary)}</td><td>${r.engagement_id?("#"+r.engagement_id):"—"}</td></tr>`).join("")+`</tbody></table>`
      : `<div class="text-xs" style="color:var(--muted)">no runs yet — analyze or pentest and they appear here</div>`;
  }catch(e){}
}
$("#eng-create").onclick=async()=>{
  $("#eng-error").textContent="";
  const name=$("#eng-name").value.trim();
  if(!name){ $("#eng-error").textContent="name required"; return; }
  try{
    const d=await (await fetch("/api/engagements",{method:"POST",headers:{"Content-Type":"application/json"},
      body:JSON.stringify({name,client:$("#eng-client").value,scope:$("#eng-scope").value})})).json();
    if(d.error){ $("#eng-error").textContent=d.error; return; }
    $("#eng-name").value=""; $("#eng-client").value=""; $("#eng-scope").value="";
    loadEngagements(); loadHistory();
  }catch(e){ $("#eng-error").textContent=String(e); }
};
window.delEng=async(id)=>{
  if(!confirm("Delete engagement #"+id+" and its runs?")) return;
  try{ await fetch("/api/engagements/"+id,{method:"DELETE"}); loadEngagements(); loadHistory(); }catch(e){}
};
$("#hist-refresh").onclick=()=>{ loadEngagements(); loadHistory(); };
loadEngagements();

const SEV={critical:"var(--algebraic)",high:"var(--geometric)",medium:"var(--spectral)",low:"var(--muted)"};
function findingsHtml(d){
  return d.findings.length? d.findings.map(f=>`<div class="card" style="padding:10px;border-left:3px solid ${SEV[f.severity]||'var(--muted)'}">
    <div class="kicker" style="color:${SEV[f.severity]||'var(--muted)'}">${f.severity} · ${f.category}</div>
    <div class="font-medium text-sm mt-1">${f.title}</div>
    <div class="text-[11px] mono mt-1" style="color:var(--muted)">line ${f.line} · sink ${f.sink_name} · sources ${(f.source_names||[]).join(", ")}</div></div>`).join("")
    : `<div class="text-xs" style="color:var(--muted)">no findings</div>`;
}
function topHtml(d){
  return (d.top||[]).map(t=>{const w=Math.max(2,Math.round(t.value*100));
    return `<div style="margin-bottom:5px"><div class="text-[11px] mono truncate">${t.label||t.id}</div><div class="bar" style="height:6px;background:var(--panel2);border-radius:3px;overflow:hidden"><i style="display:block;height:100%;width:${w}%;background:var(--spectral)"></i></div></div>`;}).join("") || "<div class='text-xs' style='color:var(--muted)'>—</div>";
}
function verifyHtml(d){
  if(!d.verifications) return "";
  return `<div class="kicker">Z3 verifications</div>`+ (d.verifications.length? d.verifications.map(v=>`<div class="mono text-[11px]" style="color:var(--topological)">✓ ${v.category} · ${v.sink_name} (line ${v.line}) ${v.witness?('· '+JSON.stringify(v.witness)):''}</div>`).join("") : "<div class='text-xs' style='color:var(--muted)'>none confirmed</div>");
}
function agentHtml(d){
  if(!d.agent) return "";
  return `<div class="kicker">Agent report</div>`+ (d.agent.length? d.agent.map(a=>`<div class="mono text-[11px]">[${a.status}] ${a.cwe} ${a.title} — ${a.signal}</div>`).join("") : "<div class='text-xs' style='color:var(--muted)'>no findings</div>");
}
function topologyHtml(d){
  if(!d.topology) return "";
  const t=d.topology;
  return `<div class="mono">undirected β₁ = ${t.undirected_beta1}<br>directed (GLMY) β₁ = ${t.directed_beta1} <span style="color:var(--muted)">(β₀=${t.directed_beta0})</span></div>`;
}
function render(d){
  $("#findings").innerHTML=findingsHtml(d);
  $("#top").innerHTML=topHtml(d);
  $("#topology").innerHTML=topologyHtml(d);
  $("#verify-block").innerHTML=verifyHtml(d);
  $("#agent-block").innerHTML=agentHtml(d);
  renderMap(d);
}
function renderCompare(d){
  const rows=(k,cls)=>`<div class="text-sm"><b>${k}</b>: ${d.diff[k].length? d.diff[k].map(x=>x[0]+":"+x[1]).join(", ") : "—"}</div>`;
  $("#diff-block").innerHTML=`<div class="card" style="padding:10px"><div class="kicker">Diff (vulnerable → patched)</div>
    <div class="mt-1" style="color:var(--topological)">${rows("resolved","resolved")}</div>
    <div style="color:var(--geometric)">${rows("persisting","persisting")}</div>
    <div style="color:var(--algebraic)">${rows("introduced","introduced")}</div></div>`;
  $("#findings").innerHTML=`<b class="text-sm">vulnerable</b>`+findingsHtml(d.vulnerable)+`<b class="text-sm">patched</b>`+findingsHtml(d.patched);
  $("#top").innerHTML=topHtml(d.vulnerable);
  $("#topology").innerHTML=topologyHtml(d.vulnerable);
  $("#verify-block").innerHTML=verifyHtml(d.vulnerable);
  $("#agent-block").innerHTML="";
  renderMap(d.vulnerable);
}

const COLORS={source:"#f85149",sink:"#d29922",function:"#58a6ff",gate:"#bc8cff",module:"#30363d",
  assign:"#a5d6ff",call:"#bc8cff",statement:"#8b949e",block:"#8b949e",variable:"#79c0ff",parameter:"#79c0ff"};
const ECOL={taint:"#f85149",call:"#58a6ff",data:"#3fb950",control:"#6e7681",trust:"#bc8cff",auth:"#d2a8ff"};

function renderMap(d){
  const svg=$("#map"); svg.innerHTML="";
  const W=1000,H=440; svg.setAttribute("viewBox",`0 0 ${W} ${H}`);
  const world=document.createElementNS(NS,"g"); svg.appendChild(world);
  let view={x:0,y:0,k:1};
  const apply=()=>world.setAttribute("transform",`translate(${view.x},${view.y}) scale(${view.k})`);
  const r=n=>n.tainted?14:6+Math.min(10,(n.fiedler||0)*8);
  const nodes=d.nodes.map((n,i)=>({...n,r:r(n),x:600+Math.cos(i*2.39996)*30*Math.sqrt(i+1),y:220+Math.sin(i*2.39996)*30*Math.sqrt(i+1),vx:0,vy:0,fixed:false}));
  const by={}; nodes.forEach(n=>by[n.id]=n);
  const edges=d.edges.slice(); const N=nodes.length;
  const edgeEls=edges.map(e=>{const l=document.createElementNS(NS,"line");
    l.setAttribute("stroke",ECOL[e.kind]||"#6e7681"); l.setAttribute("stroke-width",e.kind==="taint"?2.5:1); l.setAttribute("stroke-opacity","0.55");
    world.appendChild(l); return l;});
  const nodeEls=new Map(); const neigh=new Map();
  nodes.forEach(n=>{
    const g=document.createElementNS(NS,"g"); g.setAttribute("class","node");
    const c=document.createElementNS(NS,"circle"); c.setAttribute("r",n.r); c.setAttribute("fill",COLORS[n.kind]||"#8b949e");
    if(n.tainted) c.setAttribute("stroke","#f85149");
    const t=document.createElementNS(NS,"text"); t.setAttribute("y",-n.r-4); t.setAttribute("text-anchor","middle"); t.setAttribute("fill","#e6edf3"); t.setAttribute("font-size","10"); t.textContent=n.label;
    const t2=document.createElementNS(NS,"text"); t2.setAttribute("y",n.r+13); t2.setAttribute("text-anchor","middle"); t2.setAttribute("fill","#8b949e"); t2.setAttribute("font-size","8"); t2.textContent=n.kind;
    const ti=document.createElementNS(NS,"title"); ti.textContent=`${n.kind} ${n.label} (line ${n.line})${n.tainted?" [tainted]":""}`;
    g.append(c,t,t2,ti); world.appendChild(g); nodeEls.set(n.id,g);
    const s=new Set([n.id]); edges.forEach(e=>{if(e.src===n.id)s.add(e.dst);if(e.dst===n.id)s.add(e.src);}); neigh.set(n.id,s);
  });
  let hovered=null;
  function hl(){
    const f=hovered?neigh.get(hovered):null;
    nodes.forEach(n=>{const el=nodeEls.get(n.id); el.setAttribute("opacity",f&&!f.has(n.id)?"0.15":"1");});
    edgeEls.forEach((l,i)=>{const e=edges[i]; l.setAttribute("stroke-opacity",f?(f.has(e.src)&&f.has(e.dst)?"0.9":"0.06"):"0.55");});
  }
  function draw(){
    nodes.forEach(n=>nodeEls.get(n.id).setAttribute("transform",`translate(${n.x},${n.y})`));
    edgeEls.forEach((l,i)=>{const e=edges[i],a=by[e.src],b=by[e.dst]; if(a&&b){l.setAttribute("x1",a.x);l.setAttribute("y1",a.y);l.setAttribute("x2",b.x);l.setAttribute("y2",b.y);}});
  }
  let alpha=1,running=true; const K=1200*Math.sqrt(N);
  function tick(){
    for(let i=0;i<N;i++){const a=nodes[i]; for(let j=i+1;j<N;j++){const b=nodes[j];
      let dx=a.x-b.x,dy=a.y-b.y,d2=dx*dx+dy*dy; const mn=a.r+b.r+22,m2=mn*mn;
      if(d2<m2){d2=m2;dx*=mn/Math.sqrt(dx*dx+dy*dy+1e-6);dy*=mn/Math.sqrt(dx*dx+dy*dy+1e-6);}
      const dd=Math.sqrt(d2),f=K/d2;a.vx+=dx/dd*f;a.vy+=dy/dd*f;b.vx-=dx/dd*f;b.vy-=dy/dd*f;}}
    edges.forEach(e=>{const a=by[e.src],b=by[e.dst];if(!a||!b)return;let dx=b.x-a.x,dy=b.y-a.y,dd=Math.sqrt(dx*dx+dy*dy)||1;const rest=a.r+b.r+50,f=(dd-rest)*0.06;a.vx+=dx/dd*f;a.vy+=dy/dd*f;b.vx-=dx/dd*f;b.vy-=dy/dd*f;});
    nodes.forEach(n=>{n.vx+=(600-n.x)*0.0025;n.vy+=(220-n.y)*0.0025;});
    nodes.forEach(n=>{if(n.fixed){n.vx=0;n.vy=0;return;}n.vx*=0.6;n.vy*=0.6;n.x+=n.vx;n.y+=n.vy;});
    alpha=Math.max(0.01,alpha*0.975);
  }
  function loop(){if(running){const st=N>600?1:3;for(let i=0;i<st;i++)tick();draw();if(alpha>0.0105)requestAnimationFrame(loop);else running=false;}}
  function reheat(){alpha=1;if(!running){running=true;loop();}}
  let pan=null;
  svg.addEventListener("pointerdown",e=>{if(e.target.closest(".node"))return;pan={x:e.clientX,y:e.clientY,vx:view.x,vy:view.y};svg.setPointerCapture(e.pointerId);});
  svg.addEventListener("pointermove",e=>{if(pan){view.x=pan.vx+(e.clientX-pan.x);view.y=pan.vy+(e.clientY-pan.y);apply();}});
  svg.addEventListener("pointerup",()=>pan=null);
  svg.addEventListener("wheel",e=>{e.preventDefault();const r=svg.getBoundingClientRect(),mx=e.clientX-r.left,my=e.clientY-r.top;
    const k1=Math.max(0.05,Math.min(8,view.k*(e.deltaY<0?1.12:0.89)));view.x=mx-(mx-view.x)*(k1/view.k);view.y=my-(my-view.y)*(k1/view.k);view.k=k1;apply();},{passive:false});
  function toW(cx,cy){const r=svg.getBoundingClientRect();return [(cx-r.left-view.x)/view.k,(cy-r.top-view.y)/view.k];}
  nodes.forEach(n=>{
    const el=nodeEls.get(n.id); let dr=null;
    el.addEventListener("pointerdown",e=>{e.stopPropagation();dr={n};n.fixed=true;el.setPointerCapture(e.pointerId);reheat();});
    el.addEventListener("pointermove",e=>{if(dr){const [x,y]=toW(e.clientX,e.clientY);n.x=x;n.y=y;draw();}});
    el.addEventListener("pointerup",()=>{if(dr){dr=null;n.fixed=false;reheat();}});
    el.addEventListener("pointerenter",()=>{hovered=n.id;hl();});
    el.addEventListener("pointerleave",()=>{if(hovered===n.id){hovered=null;hl();}});
    el.addEventListener("click",()=>{const f=neigh.get(n.id);nodes.forEach(m=>nodeEls.get(m.id).setAttribute("opacity",f.has(m.id)?"1":"0.15"));edgeEls.forEach((l,i)=>{const e=edges[i];l.setAttribute("stroke-opacity",f.has(e.src)&&f.has(e.dst)?"0.9":"0.06");});});
  });
  svg.addEventListener("pointerleave",()=>{hovered=null;hl();});
  if(N){let x0=1e9,y0=1e9,x1=-1e9,y1=-1e9;nodes.forEach(n=>{x0=Math.min(x0,n.x-n.r);y0=Math.min(y0,n.y-n.r);x1=Math.max(x1,n.x+n.r);y1=Math.max(y1,n.y+n.r);});
    const r=svg.getBoundingClientRect();const k=Math.min(r.width/(x1-x0||1),r.height/(y1-y0||1))*0.9;view.k=Math.max(0.05,Math.min(4,k));view.x=r.width/2-((x0+x1)/2)*view.k;view.y=r.height/2-((y0+y1)/2)*view.k;apply();}
  apply();draw();alpha=1;running=true;loop();
  $("#mlegend").innerHTML=Object.keys(COLORS).map(k=>`<span class="pill"><span class="dot" style="background:${COLORS[k]}"></span>${k}</span>`).join("");
}

// ---- experiments ----
async function loadResults(){ RESULTS=await (await fetch("/api/results")).json(); renderExperiments(RESULTS); renderMethodology(RESULTS); }

function chartDefaults(){ if(!window.Chart) return null;
  Chart.defaults.color="#8b949e"; Chart.defaults.borderColor="#26303c";
  Chart.defaults.font.family="system-ui"; }

function table(rows,cols){return `<table><thead><tr>${cols.map(c=>`<th>${c}</th>`).join("")}</tr></thead><tbody>`+rows.map(r=>`<tr>${r.map(c=>`<td class="num">${c}</td>`).join("")}</tr>`).join("")+`</tbody></table>`;}

function renderExperiments(R){
  chartDefaults();
  const o=R.oracle||{}, a=o.signals_auc||{}, m=o.metrics||{};
  const cards=[["taint MRR",m.taint?m.taint.mrr:"-","prioritization (main)","taint"],["field MRR",m.field?m.field.mrr:"-","V(x) fused","spectral"],
    ["taint AUC",a.taint?a.taint.auc:"-","predict sink","taint"],["geometric AUC",a.geometric?a.geometric.auc:"-","below chance","geometric"],
    ["adapter F1","0.681","OWASP all","topological"],["Youden J","0.168","adapter","formal"]];
  $("#cards").innerHTML=cards.map(([k,v,s,col])=>`<div class="card"><div class="kicker">${k}</div>
    <div class="metric" style="color:var(--${col})">${v}</div><div class="text-[11px]" style="color:var(--muted)">${s}</div></div>`).join("");

  const pal={dfs:"#8b949e",taint:"#ff7b72",field:"#58a6ff",random:"#f85149"};
  const curves=o.curves||{};
  mkLine("cost",Object.keys(curves).map(k=>({label:k,color:pal[k]||"#999",pts:curves[k].map((v,i)=>[i+1,v])})),"verification budget","cumulative recall");

  if(window.Chart && a){
    const labels=Object.keys(a), vals=labels.map(k=>a[k].auc);
    mkBar("auc",labels,vals);
  }
  $("#oracle-table").innerHTML=table(Object.keys(m).map(k=>[k,m[k].mrr,m[k]["recall@1"],m[k].mean_rank,m[k]["ndcg@5"]]),["ranking","MRR","R@1","mean rank","NDCG@5"]);
  const pt=m.taint_vs_field;
  $("#oracle-table").innerHTML+= (pt?`<div class="text-xs mt-2" style="color:var(--muted)">paired test taint−field: ${pt.mean_diff>=0?'+':''}${pt.mean_diff.toFixed(4)} CI95=[${pt.ci95[0].toFixed(4)}, ${pt.ci95[1].toFixed(4)}] p=${pt.p_value}</div>`:"");

  const ow=R.owasp||{};
  function block(t,obj){if(!obj)return "";const rows=Object.keys(obj).filter(k=>k!=="overall").sort().map(k=>{const v=obj[k];const fpr=v.fp/(v.fp+v.tn||1);return[k,v.tp,v.fp,v.fn,v.tn,v.precision.toFixed(3),v.recall.toFixed(3),v.f1.toFixed(3),(v.recall-fpr).toFixed(3)];});
    const ov=obj.overall,fpr=ov.fp/(ov.fp+ov.tn||1);rows.push(["<b>overall</b>",ov.tp,ov.fp,ov.fn,ov.tn,ov.precision.toFixed(3),ov.recall.toFixed(3),ov.f1.toFixed(3),(ov.recall-fpr).toFixed(3)]);
    return `<div class="kicker mt-3">${t}</div>`+table(rows,["category","TP","FP","FN","TN","P","R","F1","J"]);}
  $("#owasp-tables").innerHTML=block("adapter — all categories",ow.adapter_all)+block("adapter — taint",ow.adapter_taint)+block("adapter + Z3 — taint",ow.z3_taint);
  const ab=R.ablation||{}; $("#ablation-table").innerHTML=table(Object.keys(ab).map(k=>[k,ab[k].precision.toFixed(3),ab[k].recall.toFixed(3),ab[k].f1.toFixed(3)]),["variant","P","R","F1"]);
  const cves=R.cves||[]; const crows=[];
  cves.forEach(c=>{(c.files||[]).forEach(f=>{const res=f.resolved.length?`<span style="color:var(--topological)">resolved</span>`:(f.persisting.length?`<span style="color:var(--geometric)">persisting</span>`:"—");crows.push([c.cve,f.file,f.vuln_findings,f.patched_findings,res]);});});
  $("#cve-table").innerHTML=crows.length?table(crows,["CVE","file","vuln","patched","result"]):"<div class='text-xs' style='color:var(--muted)'>no CVE data</div>";
  const llm=R.llm||{}; const lrows=[];
  (llm.results||[]).forEach(r=>lrows.push([r.file,r.confirmed_offline,r.confirmed_online,r.llm_generated,r.stable?"stable":"varies"]));
  $("#llm-table").innerHTML=lrows.length?table(lrows,["file","offline","online","llm","stability"]):"<div class='text-xs' style='color:var(--muted)'>no LLM data</div>";

  (function(){const by={};R.scale.forEach(r=>{(by[r.kernel]=by[r.kernel]||[]).push([r.edges,r.ms]);});
    const col={forman:"#3fb950",mapper:"#58a6ff",homology:"#f85149",sinkhorn:"#d29922",ollivier_exact:"#bc8cff",spectral_fiedler:"#79c0ff",directed_laplacian:"#ffa657"};
    const ser=Object.keys(by).map(k=>({label:k,color:col[k]||"#999",pts:by[k].sort((x,y)=>x[0]-y[0])}));
    if(ser.length) mkLine("scale",ser,"edges |E| (log)","time ms (log)",{log:true});})();
}

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

// ---- methodology ----
function renderMethodology(R){
  chartDefaults();
  mkPipe("pipeline",["artifact","IR typed graph","math layers","V(x) field","LLM agent","Z3 verifier"]);
  mkProto("protocol",[["enumerate sink candidates","source→sink reachability"],["rank candidates","DFS · taint · V(x) · random"],["metrics","MRR · R@1 · NDCG@k · cost curve"],["Z3 arbiter","SAT + concrete witness"]]);

  const a=(R.oracle||{}).signals_auc||{};
  const layers=[["Spectral","L=D−A · Fiedler · embedding","|Fiedler|","spectral"],["Topological","persistent H₀/H₁ · Mapper","H₁ membership","topological"],["Geometric","Ollivier/Forman Ricci · Sinkhorn","curvature κ","geometric"],["Algebraic","taint lattice · Galois · auth functor","taint tags","taint"],["Formal","symbolic exec + SMT (Z3)","SAT(φ_bad)","formal"],["Directed","Chung Laplacian · SCC+Perron","directed λ₂","directed"]];
  $("#layers").innerHTML=layers.map(([n,d,sig,k])=>{let b=`<span class="pill">defined</span>`;
    if(a[k]){const v=a[k].auc;const c=v>0.7?"var(--topological)":(v<0.45?"var(--algebraic)":"var(--muted)");b=`<span class="pill" style="color:${c}">AUC ${v.toFixed(3)}</span>`;}
    return `<div class="card"><div class="kicker" style="color:var(--${k})">${n}</div><div class="text-xs mt-2">${d}</div><div class="text-[11px] mt-2" style="color:var(--muted)">signal: ${sig} · ${b}</div></div>`;}).join("");

  const laws=[["H1","curvature κ≪0","priv. escalation","geometric"],["H2","persistent H₁","reentrancy","topological"],["H3","Fiedler cut","injection/trust","spectral"],["H4","taint crossing auth","auth-invariant viol.",""],["H5","persistence outlier","real vs spurious","topological"],["H6","SAT(φ_bad)","model witness","formal"]];
  const rows=laws.map(([id,f,c,k])=>{const v=k&&a[k]?a[k].auc:null;let st=k?"—":"definitional (Prop. 2)";
    if(v!==null) st=v>0.7?`<span style="color:var(--topological)">supported (${v.toFixed(3)})</span>`:(v<0.45?`<span style="color:var(--algebraic)">not supported (${v.toFixed(3)})</span>`:`<span style="color:var(--geometric)">at chance (${v.toFixed(3)})</span>`);
    return [id,f,c,st];});
  $("#laws").innerHTML=table(rows,["hypothesis","feature","class","status on OWASP"]);
}
function mkPipe(id, boxes){
  const c=document.getElementById(id); if(!c||!window.Chart) return;
  // custom pipeline drawing (Chart.js block plugin not worth it; use raw canvas)
  const cv=c; cv.style.display="none";
  const svg=document.createElementNS("http://www.w3.org/2000/svg","svg");
  svg.setAttribute("viewBox","0 0 1120 160"); svg.style.width="100%"; svg.style.height="100%";
  c.parentNode.insertBefore(svg,c);
  const bw=150,bh=54,gap=30,x0=24,y=38;
  let s=`<defs><marker id="p1" markerWidth="9" markerHeight="9" refX="6" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6" fill="#58a6ff"/></marker></defs>`;
  boxes.forEach((t,i)=>{const x=x0+i*(bw+gap);
    s+=`<rect x="${x}" y="${y}" width="${bw}" height="${bh}" rx="10" fill="#161d27" stroke="#58a6ff"/>`;
    t.split(" ").forEach((w,wi)=>s+=`<text x="${x+bw/2}" y="${y+bh/2+5+(wi-(t.split(' ').length-1)/2)*16}" fill="#e6edf3" font-size="13" text-anchor="middle">${w}</text>`);
    if(i<boxes.length-1) s+=`<line x1="${x+bw}" y1="${y+bh/2}" x2="${x+bw+gap-3}" y2="${y+bh/2}" stroke="#58a6ff" stroke-width="2" marker-end="url(#p1)"/>`;});
  const cx1=x0+5*(bw+gap)+bw/2, cx2=x0+(bw+gap)+bw/2;
  s+=`<path d="M${cx1},${y+bh} L${cx1},${y+bh+58} L${cx2},${y+bh+58} L${cx2},${y+bh}" fill="none" stroke="#8b949e" stroke-dasharray="5 4"/><text x="${(cx1+cx2)/2}" y="${y+bh+50}" fill="#8b949e" font-size="11" text-anchor="middle">re-embed (confirm / refute)</text>`;
  svg.innerHTML=s;
}
function mkProto(id, steps){
  const svg=document.createElementNS("http://www.w3.org/2000/svg","svg");
  svg.setAttribute("viewBox","0 0 560 360"); svg.style.width="100%"; svg.style.height="100%";
  const c=document.getElementById(id); c.style.display="none"; c.parentNode.insertBefore(svg,c);
  const W=560,bh=56,gap=22,bw=440,xx=(W-bw)/2;
  let s=`<defs><marker id="p2" markerWidth="9" markerHeight="9" refX="6" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6" fill="#8b949e"/></marker></defs>`;
  steps.forEach(([t,sub],i)=>{const yy=10+i*(bh+gap);
    s+=`<rect x="${xx}" y="${yy}" width="${bw}" height="${bh}" rx="10" fill="#11161d" stroke="#26303c"/>`;
    s+=`<text x="${W/2}" y="${yy+24}" fill="#e6edf3" font-size="13" text-anchor="middle">${t}</text><text x="${W/2}" y="${yy+42}" fill="#8b949e" font-size="11" text-anchor="middle">${sub}</text>`;
    if(i<steps.length-1) s+=`<line x1="${W/2}" y1="${yy+bh}" x2="${W/2}" y2="${yy+bh+gap-3}" stroke="#8b949e" stroke-width="2" marker-end="url(#p2)"/>`;});
  svg.innerHTML=s;
}
"""


def _render_page() -> str:
    return PAGE.replace("__HEAD__", head("VALEN — web UI", extra=_SHELL_HEAD)).replace(
        "__SHELL__", SHELL_JS
    )


_SHELL_HEAD = (
    '<link rel="preconnect" href="https://fonts.googleapis.com">'
    '<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">'
)


# Keep the module importable as `PAGE` for server.py; build it lazily once.
PAGE = _render_page()

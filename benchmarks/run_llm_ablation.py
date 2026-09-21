"""Larger LLM ablation over a varied Python corpus.

Compares the offline (heuristic) agent against the LiteLLM-backed agent on
~40 files across sink categories, measuring three axes:

* **detection invariance** — the confirmed finding set ``(sink, line)`` must be
  identical offline vs online (the SMT verifier is the arbiter, not the LLM).
* **ranking invariance** — the confidence/severity ordering of confirmed
  findings is produced by the field, not the LLM, so it must not change.
* **interpretation/reporting delta** — CWE labels, titles and descriptions may
  (and should) change: the LLM's value is interpretability, not detection.

Usage (offline is the default; online needs the local LiteLLM proxy):
    python benchmarks/run_llm_ablation.py
    # online:
    set -a; . ~/litellm/.env; set +a
    MANIFOLD_LLM_MODEL=openai/flash MANIFOLD_LLM_BASE_URL=http://127.0.0.1:4000 \
    MANIFOLD_LLM_API_KEY=$LITELLM_MASTER_KEY python benchmarks/run_llm_ablation.py

Writes benchmarks/llm_ablation.json.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.agent import ManifoldAgent
from agent.llm import LLMClient

CORPUS = ROOT / "examples" / "python" / "ablation"


class OfflineLLM:
    available = False

    def complete(self, messages):
        return None


def _confirmed(report):
    return [(e.sink_name if hasattr(e, "sink_name") else e.region, e.line, e.cwe, e.title,
             e.description, e.confidence, e.severity if hasattr(e, "severity") else "")
            for e in report.confirmed]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0, help="max files to run (0 = all)")
    ap.add_argument("--runs", type=int, default=1, help="online runs per file")
    ap.add_argument("--out", type=str, default="", help="output JSON path (default benchmarks/llm_ablation.json)")
    args = ap.parse_args()

    live = bool(os.environ.get("MANIFOLD_LLM_MODEL") and os.environ.get("MANIFOLD_LLM_BASE_URL"))
    print(f"LLM configured: {live}  (model={os.environ.get('MANIFOLD_LLM_MODEL','-')})")

    files = sorted(CORPUS.glob("*.py"))
    if args.limit:
        files = files[: args.limit]

    rows = []
    for src in files:
        code = src.read_text()
        offline = _confirmed(ManifoldAgent(llm=OfflineLLM()).run(code, path=src.name))
        online_runs = [_confirmed(ManifoldAgent(llm=LLMClient()).run(code, path=src.name))
                       for _ in range(args.runs)]
        online = online_runs[0]

        off_keys = {(r[0], r[1]) for r in offline}
        on_keys = {(r[0], r[1]) for r in online}
        det_same = off_keys == on_keys

        # ranking: confidence order over confirmed (compare offline vs online)
        off_rank = [(r[0], r[1]) for r in sorted(offline, key=lambda r: -r[5])]
        on_rank = [(r[0], r[1]) for r in sorted(online, key=lambda r: -r[5])]
        rank_same = off_rank == on_rank

        # interpretation: CWE per confirmed (online vs offline)
        cwe_off = {k: r[2] for r in offline for k in [(r[0], r[1])]}
        cwe_on = {k: r[2] for r in online for k in [(r[0], r[1])]}
        cwe_diff = {k for k in on_keys & off_keys if cwe_on.get(k) != cwe_off.get(k)}

        # reporting: title/description presence + specificity
        off_titles = [r[3] for r in offline if r[3]]
        on_titles = [r[3] for r in online if r[3]]
        off_desc = [r[4] for r in offline if r[4]]
        on_desc = [r[4] for r in online if r[4]]

        # inter-online-run stability (LLM nondeterminism)
        run_keys = [{(r[0], r[1]) for r in run} for run in online_runs]
        runs_stable = all(k == run_keys[0] for k in run_keys) if run_keys else True

        rows.append({
            "file": src.name,
            "n_conf_offline": len(offline),
            "n_conf_online": len(online),
            "detection_same": det_same,
            "ranking_same": rank_same,
            "cwe_changed": sorted(cwe_diff),
            "offline_cwe": sorted({r[2] for r in offline}),
            "online_cwe": sorted({r[2] for r in online}),
            "title_len_off": sum(len(t) for t in off_titles),
            "title_len_on": sum(len(t) for t in on_titles),
            "desc_present_off": len(off_desc),
            "desc_present_on": len(on_desc),
            "runs_stable": runs_stable,
        })
        print(f"{src.name:24} conf off/on={len(offline)}/{len(online)} det_same={det_same} "
              f"rank_same={rank_same} cwe_changed={len(cwe_diff)}")

    n = len(rows)
    det_agree = sum(1 for r in rows if r["detection_same"]) / n if n else 0.0
    rank_agree = sum(1 for r in rows if r["ranking_same"]) / n if n else 0.0
    runs_stable = sum(1 for r in rows if r["runs_stable"]) / n if n else 0.0
    n_conf = sum(r["n_conf_offline"] for r in rows)
    cwe_changed_total = sum(len(r["cwe_changed"]) for r in rows)
    cwe_change_rate = cwe_changed_total / n_conf if n_conf else 0.0
    title_len_off = sum(r["title_len_off"] for r in rows)
    title_len_on = sum(r["title_len_on"] for r in rows)
    desc_off = sum(r["desc_present_off"] for r in rows)
    desc_on = sum(r["desc_present_on"] for r in rows)

    summary = {
        "live": live,
        "n_files": n,
        "n_confirmed": n_conf,
        "detection_agreement": det_agree,
        "ranking_agreement": rank_agree,
        "runs_stable": runs_stable,
        "cwe_change_rate": cwe_change_rate,
        "cwe_changed_total": cwe_changed_total,
        "title_len_offline": title_len_off,
        "title_len_online": title_len_on,
        "desc_present_offline": desc_off,
        "desc_present_online": desc_on,
    }
    print("\n== summary ==")
    for k, v in summary.items():
        print(f"  {k}: {v}")

    out = Path(args.out) if args.out else ROOT / "benchmarks" / "llm_ablation.json"
    out.write_text(json.dumps({"summary": summary, "rows": rows}, indent=2))
    print(f"results -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

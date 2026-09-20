"""LLM ablation: compare the heuristic agent against the LiteLLM-backed agent.

    # offline (heuristic only)
    python benchmarks/run_llm.py

    # with the local LiteLLM proxy (~/litellm):
    set -a; . ~/litellm/.env; set +a
    MANIFOLD_LLM_MODEL=openai/flash \
    MANIFOLD_LLM_BASE_URL=http://127.0.0.1:4000 \
    MANIFOLD_LLM_API_KEY=$LITELLM_MASTER_KEY \
    python benchmarks/run_llm.py

Writes benchmarks/llm_results.json.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.agent import ManifoldAgent
from agent.llm import LLMClient

EXAMPLES = ROOT / "examples" / "python"


class OfflineLLM:
    """A no-op client so the agent falls back to the heuristic hypothesizer."""

    available = False

    def complete(self, messages):  # pragma: no cover - trivial
        return None


def _entries(report):
    return [
        {"status": e.status, "cwe": e.cwe, "title": e.title, "signal": e.signal, "source": e.source}
        for e in report.entries
    ]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=1, help="LLM runs per example (for stability)")
    args = ap.parse_args()

    live = bool(os.environ.get("MANIFOLD_LLM_MODEL") and os.environ.get("MANIFOLD_LLM_BASE_URL"))
    print(f"LLM configured: {live}  (model={os.environ.get('MANIFOLD_LLM_MODEL','-')} "
          f"base={os.environ.get('MANIFOLD_LLM_BASE_URL','-')})")

    results = []
    for source in sorted(EXAMPLES.glob("*.py")):
        code = source.read_text()
        offline = _entries(ManifoldAgent(llm=OfflineLLM()).run(code, path=source.name))
        online_runs = []
        for _ in range(args.runs):
            online_runs.append(_entries(ManifoldAgent(llm=LLMClient()).run(code, path=source.name)))

        online = online_runs[0]
        llm_entries = [e for e in online if e["source"] == "llm"]
        # stability: titles per run for confirmed entries
        titles_per_run = [[e["title"] for e in run if e["status"] == "confirmed"] for run in online_runs]
        stable = all(t == titles_per_run[0] for t in titles_per_run) if titles_per_run else True

        results.append({
            "file": source.name,
            "offline": offline,
            "online": online,
            "llm_generated": len(llm_entries),
            "confirmed_offline": sum(1 for e in offline if e["status"] == "confirmed"),
            "confirmed_online": sum(1 for e in online if e["status"] == "confirmed"),
            "stable": stable,
        })
        print(f"{source.name:22} confirmed off/on = {results[-1]['confirmed_offline']}/{results[-1]['confirmed_online']}"
              f"  llm_entries={len(llm_entries)}  stable={stable}")
        if llm_entries:
            print(f"    LLM: {llm_entries[0]['cwe']} {llm_entries[0]['title'][:60]}")

    out = ROOT / "benchmarks" / "llm_results.json"
    out.write_text(json.dumps({"live": live, "results": results}, indent=2))
    print(f"results -> {out.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

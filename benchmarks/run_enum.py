"""Enumeration benchmark: run gobuster/ffuf (stealth-aware) and ingest output.

By default it parses the bundled fixtures; pass ``--base-url`` and
``--authorize`` to actually run gobuster/ffuf against an authorized target, or
``--gobuster/--ffuf`` to ingest your own tool output. Writes
benchmarks/enum_results.json.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from valen.redteam.enum import enum_to_graph, parse_ffuf_json, parse_gobuster, shadow_endpoints  # noqa: E402
from valen.redteam.wordlists import default_wordlist  # noqa: E402

GOBUSTER_FIX = ROOT / "examples" / "recon" / "gobuster.txt"
FFUF_FIX = ROOT / "examples" / "recon" / "ffuf.jsonl"
SPEC = ROOT / "examples" / "api" / "crapi-openapi-spec.json"


def run_gobuster(base_url: str, wordlist: Path) -> str:
    proc = subprocess.run(
        ["gobuster", "dir", "-u", base_url, "-w", str(wordlist),
         "--no-color", "-q"],
        capture_output=True, text=True, timeout=180,
    )
    return proc.stdout


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", type=str, default="")
    ap.add_argument("--authorize", action="store_true", help="actually run the tools")
    ap.add_argument("--wordlist", type=str, default="")
    ap.add_argument("--gobuster", type=str, default=str(GOBUSTER_FIX))
    ap.add_argument("--ffuf", type=str, default=str(FFUF_FIX))
    args = ap.parse_args()

    records = parse_gobuster(Path(args.gobuster).read_text())
    records += parse_ffuf_json(Path(args.ffuf).read_text())

    if args.base_url and args.authorize:
        wl = Path(args.wordlist) if args.wordlist else _write_wordlist()
        records += parse_gobuster(run_gobuster(args.base_url, wl))

    spec = json.loads(SPEC.read_text())
    spec_paths = list(spec.get("paths", {}).keys())
    shadow = shadow_endpoints(records, spec_paths)

    graph = enum_to_graph(records)
    out = {
        "n": len(records),
        "records": records,
        "shadow_endpoints": shadow,
        "graph_nodes": graph.node_count,
    }
    print(f"== VALEN enumeration ({len(records)} discoveries) ==")
    print(f"  shadow endpoints (not in OpenAPI spec): {shadow}")
    out_p = ROOT / "benchmarks" / "enum_results.json"
    out_p.write_text(json.dumps(out, indent=2))
    print(f"  results -> {out_p.relative_to(ROOT)}")
    return 0


def _write_wordlist() -> Path:
    p = ROOT / "benchmarks" / "wordlist.tmp.txt"
    p.write_text("\n".join(default_wordlist()))
    return p


if __name__ == "__main__":
    raise SystemExit(main())

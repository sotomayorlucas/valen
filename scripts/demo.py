#!/usr/bin/env python3
"""End-to-end demo: run MANIFOLD over every example program and emit HTML maps.

Usage:
    python scripts/demo.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.agent import ManifoldAgent
from manifold.analysis.math_core import run_core
from manifold.ingest import analyze, infer_adapter
from manifold.ingest.python import PythonIngest
from manifold.viz import write_html

EXAMPLES = ROOT / "examples"
OUT = ROOT / "viz" / "out"


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    summary = []

    for source in sorted(EXAMPLES.rglob("*")):
        if not source.is_file():
            continue
        if source.suffix not in (".py", ".json", ".asm"):
            continue
        code = source.read_text()
        adapter = infer_adapter(code, source.name)
        result = analyze(code, path=source.name, adapter=adapter)

        if adapter == "python":
            report = ManifoldAgent().run(code, path=source.name)
            confirmed = len(report.confirmed)
            candidates = len(report.entries) - confirmed
        else:
            report = None
            confirmed = len(result.findings)
            candidates = 0

        try:
            math = run_core(result.graph)
        except Exception:
            math = None

        rel = source.relative_to(EXAMPLES)
        out = OUT / rel.with_suffix(".html")
        out.parent.mkdir(parents=True, exist_ok=True)
        write_html(
            result.graph,
            str(out),
            math=math,
            report=report,
            subtitle=f"{rel} ({adapter})",
        )
        summary.append(
            {
                "file": str(rel),
                "adapter": adapter,
                "nodes": result.graph.node_count,
                "edges": result.graph.edge_count,
                "taint": len(result.findings),
                "confirmed": confirmed,
                "candidates": candidates,
            }
        )
        print(
            f"{rel} [{adapter}]: {confirmed} confirmed, "
            f"{candidates} candidates -> {out.relative_to(ROOT)}"
        )

    (OUT / "summary.json").write_text(json.dumps(summary, indent=2))
    print(f"summary -> {(OUT / 'summary.json').relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

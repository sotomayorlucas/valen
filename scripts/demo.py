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
from manifold.ingest.python import PythonIngest
from manifold.viz import write_html

EXAMPLES = ROOT / "examples" / "python"
OUT = ROOT / "viz" / "out"


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    summary = []

    for source in sorted(EXAMPLES.glob("*.py")):
        code = source.read_text()
        result = PythonIngest().analyze(code, path=source.name)
        report = ManifoldAgent().run(code, path=source.name)
        try:
            math = run_core(result.graph)
        except Exception:
            math = None

        out = OUT / f"{source.stem}.html"
        write_html(
            result.graph,
            str(out),
            math=math,
            report=report,
            subtitle=f"{source.name}",
        )
        candidates = len(report.entries) - len(report.confirmed)
        summary.append(
            {
                "file": source.name,
                "nodes": result.graph.node_count,
                "edges": result.graph.edge_count,
                "taint": len(result.findings),
                "confirmed": len(report.confirmed),
                "candidates": candidates,
            }
        )
        print(
            f"{source.name}: {len(report.confirmed)} confirmed, "
            f"{candidates} candidates -> {out.relative_to(ROOT)}"
        )

    (OUT / "summary.json").write_text(json.dumps(summary, indent=2))
    print(f"summary -> {(OUT / 'summary.json').relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

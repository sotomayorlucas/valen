"""Command-line interface for the VALEN pipeline."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .analysis.verifier import verify
from .ingest import analyze, infer_adapter


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="valen", description="Analyze a target for vulnerabilities.")
    parser.add_argument("target", help="source file / OpenAPI JSON / agent JSON / disassembly to analyze")
    parser.add_argument("--adapter", help="adapter: python, binary, angr-binary, web, llm-agent (inferred if omitted)")
    parser.add_argument("--json", action="store_true", help="emit the IR graph as JSON")
    parser.add_argument("--verify", action="store_true", help="formally verify taint flows (Z3, python only)")
    parser.add_argument("--agent", action="store_true", help="run the autonomous agent (python only)")
    parser.add_argument("--viz", metavar="FILE.html", help="render the vulnerability valen to a self-contained HTML file")
    args = parser.parse_args(argv)

    path = Path(args.target)
    if not path.exists():
        print(f"error: {path} does not exist", file=sys.stderr)
        return 1

    adapter = args.adapter
    if adapter == "angr-binary":
        code = ""
    else:
        try:
            code = path.read_text()
        except UnicodeDecodeError:
            print("error: binary file detected; use --adapter angr-binary", file=sys.stderr)
            return 1
    if adapter is None:
        adapter = infer_adapter(code, str(path))
    try:
        result = analyze(code, path=str(path), adapter=adapter)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(result.graph.to_dict(), indent=2))
        return 0

    print(f"== {path} ({adapter}) -> {result.graph.node_count} nodes, "
          f"{result.graph.edge_count} edges")
    for finding in result.findings:
        print(f"  [{finding.severity:>8}] {finding.title}")
        print(f"      line {finding.line}: {finding.sink_name} <- {finding.source_names}")
    if not result.findings:
        print("  (no taint findings)")

    if args.verify and adapter == "python":
        print("== formal verification (Z3) ==")
        verifications = verify(code, path=str(path))
        for v in verifications:
            print(f"  [{v.severity:>8}] {v.category} via {v.sink_name} (line {v.line})")
            if v.witness:
                print(f"      witness: {v.witness}")
        if not verifications:
            print("  (no flows confirmed)")

    if args.agent and adapter == "python":
        from agent.agent import ValenAgent

        print("== autonomous agent report ==")
        report = ValenAgent().run(code, path=str(path))
        for e in report.entries:
            print(f"  [{e.status:>9}] {e.cwe:>8} {e.title}")
            print(f"      signal={e.signal} region={e.region} (line {e.line})")
            if e.evidence:
                print(f"      evidence: {e.evidence}")
        if not report.entries:
            print("  (no findings)")

    if args.viz:
        from .analysis.math_core import run_core
        from .viz import write_html

        try:
            math = run_core(result.graph)
        except Exception:
            math = None
        write_html(
            result.graph,
            args.viz,
            math=math,
            report=None,
            title="VALEN",
            subtitle=f"{path} ({adapter}) — {result.graph.node_count} nodes, {result.graph.edge_count} edges",
        )
        print(f"== valen written to {args.viz}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

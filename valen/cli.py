"""Command-line interface for the VALEN pipeline."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .analysis.verifier import verify
from .ingest import analyze, infer_adapter


def _pentest_main(argv: list[str]) -> int:
    from .redteam.challenges import CHALLENGES
    from .redteam.executor import AutonomousAgent

    parser = argparse.ArgumentParser(prog="valen pentest", description="Autonomous red-team engagement.")
    parser.add_argument("--scope", required=True, help="target base URL (authorized scope)")
    parser.add_argument("--goal", default="all", help="challenge id, or 'all'")
    parser.add_argument("--authorize", action="store_true", help="execute intrusive operators")
    parser.add_argument("--profile", default="sneaky", help="stealth profile")
    parser.add_argument("--max-requests", type=int, default=40)
    args = parser.parse_args(argv)

    ids = [args.goal] if args.goal != "all" else list(CHALLENGES)
    results = []
    for cid in ids:
        c = dict(CHALLENGES[cid]); c["id"] = cid
        agent = AutonomousAgent(args.scope, authorize=args.authorize,
                                max_steps=args.max_requests)
        r = agent.solve(c)
        results.append(r)
        print(f"  [{cid:<22}] {'SOLVED' if r['solved'] else 'not solved'} "
              f"({r['requests']} req)")
    solved = sum(1 for r in results if r["solved"])
    print(f"\n== VALEN autonomous pentest: {solved}/{len(results)} challenges solved ==")
    return 0


def _analyze_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="valen", description="Analyze a target for vulnerabilities.")
    parser.add_argument("target", help="source / OpenAPI JSON / agent JSON / disassembly to analyze")
    parser.add_argument("--adapter",
                        help="adapter: python, java, java-interproc, c, cpp, rust, csharp, "
                             "go, php, ruby, javascript, binary, angr-binary, web, llm-agent, iam")
    parser.add_argument("--json", action="store_true", help="emit the IR graph as JSON")
    parser.add_argument("--verify", action="store_true", help="formally verify taint flows (Z3)")
    parser.add_argument("--agent", action="store_true", help="run the autonomous agent (python only)")
    parser.add_argument("--viz", metavar="FILE.html", help="render the vulnerability valen to HTML")
    parser.add_argument("--dynamic", action="store_true",
                        help="execute the target in a sandbox and triangulate runtime trace vs static IR (python)")
    parser.add_argument("--argv", nargs="*", default=None,
                        help="arguments passed to the target as sys.argv[1:] (dynamic)")
    parser.add_argument("--timeout", type=float, default=30.0,
                        help="dynamic run timeout in seconds")
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

    if args.dynamic:
        if adapter != "python":
            print("error: --dynamic is only supported for python targets", file=sys.stderr)
            return 1
        from .dynamic import run_module, triangulate

        print("== dynamic analysis (sandboxed execution) ==")
        try:
            dyn = run_module(str(path), argv=args.argv, timeout=args.timeout)
        except Exception as exc:  # noqa: BLE001
            print(f"error: dynamic run failed: {exc}", file=sys.stderr)
            return 1
        report = triangulate(result, dyn)
        cov = report["coverage"]
        print(f"  exit_code={report['exit_code']} timed_out={report['timed_out']} "
              f"coverage={cov['nodes']}/{cov['total_nodes']} nodes "
              f"({cov['ratio']:.0%}) · {cov['lines']} lines")
        for a in report["agreement"]:
            tag = {"confirmed": "CONFIRMED", "hit": "HIT", "unexecuted": "UNEXECUTED"}[a["dynamic"]]
            print(f"  [{tag:>10}] line {a['line']}: {a['sink_name']}")
            if a["matched_value"]:
                print(f"      value: {a['matched_value']}")
        if not report["agreement"]:
            print("  (no static sinks to triangulate)")
        if report["dynamic_only_sinks"]:
            print("  dynamic-only sinks (static missed):")
            for s in report["dynamic_only_sinks"]:
                print(f"      line {s['line']}: {s['name']} ({s['category']})")
        if args.json:
            print(json.dumps(report, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if argv and argv[0] == "pentest":
        return _pentest_main(argv[1:])
    return _analyze_main(argv)


if __name__ == "__main__":
    raise SystemExit(main())

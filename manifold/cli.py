"""Minimal command-line interface for the F1 SAST pipeline."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .analysis.verifier import verify
from .ingest import LANGUAGE_TO_INGEST


def _language_for(path: Path) -> str:
    ext = path.suffix.lower().lstrip(".")
    mapping = {
        "py": "python",
        "js": "javascript",
        "mjs": "javascript",
    }
    return mapping.get(ext, ext)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="manifold", description="Analyze a target for vulnerabilities.")
    parser.add_argument("target", help="source file to analyze")
    parser.add_argument("--json", action="store_true", help="emit the IR graph as JSON")
    parser.add_argument("--verify", action="store_true", help="formally verify taint flows (Z3)")
    parser.add_argument("--language", help="override language detection")
    args = parser.parse_args(argv)

    path = Path(args.target)
    if not path.exists():
        print(f"error: {path} does not exist", file=sys.stderr)
        return 1

    language = args.language or _language_for(path)
    if language not in LANGUAGE_TO_INGEST:
        print(f"error: unsupported language {language!r}", file=sys.stderr)
        return 1

    code = path.read_text()
    ingest_cls = LANGUAGE_TO_INGEST[language]
    result = ingest_cls().analyze(code, path=str(path))

    if args.json:
        print(json.dumps(result.graph.to_dict(), indent=2))
        return 0

    print(f"== {path} ({language}) -> {result.graph.node_count} nodes, "
          f"{result.graph.edge_count} edges")
    for finding in result.findings:
        print(f"  [{finding.severity:>8}] {finding.title}")
        print(f"      line {finding.line}: {finding.sink_name} <- {finding.source_names}")
    if not result.findings:
        print("  (no taint findings)")

    if args.verify and language == "python":
        print("== formal verification (Z3) ==")
        verifications = verify(code, path=str(path))
        for v in verifications:
            print(f"  [{v.severity:>8}] {v.category} via {v.sink_name} (line {v.line})")
            if v.witness:
                print(f"      witness: {v.witness}")
        if not verifications:
            print("  (no flows confirmed)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

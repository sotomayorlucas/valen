"""Run the benchmark against an external corpus (manifest or directory).

Usage:
    python benchmarks/run_external.py <corpus.json | corpus_dir> [--adapter python]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from manifold.benchmark import evaluate_report
from manifold.corpus import adapter_detector, load_corpus


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark against an external corpus.")
    parser.add_argument("corpus", help="JSON manifest or directory of labeled files")
    parser.add_argument("--adapter", default="python", help="ingest adapter (default: python)")
    args = parser.parse_args()

    if not Path(args.corpus).exists():
        print(f"error: {args.corpus} does not exist", file=sys.stderr)
        return 1

    cases = load_corpus(args.corpus)
    if not cases:
        print("no cases loaded", file=sys.stderr)
        return 1

    print(f"== corpus: {args.corpus} ({len(cases)} cases, adapter={args.adapter}) ==")
    print(evaluate_report(cases, adapter_detector(args.adapter)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

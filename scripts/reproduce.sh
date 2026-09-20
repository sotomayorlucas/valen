#!/usr/bin/env bash
# Reproduce every figure and table in the paper, from scratch.
#
#   ./scripts/reproduce.sh [--fetch-owasp]
#
# Prerequisites: python3, cargo, gcc, git, and tectonic (or a TeX toolchain).
# The OWASP Benchmark corpus is large; pass --fetch-owasp to download it.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

VENV=".venv"
OWASP_DIR="/tmp/opencode/BenchmarkJava"
CSV="/tmp/opencode/expectedresults-1.2.csv"

echo "== 0. environment =="
if [ ! -d "$VENV" ]; then python3 -m venv "$VENV"; fi
"$VENV/bin/pip" install -q -r requirements.txt

echo "== 1. build the Rust core =="
cargo build --release --manifest-path core/Cargo.toml

echo "== 1b. scalability benchmark (curves) =="
cargo run --release --manifest-path core/Cargo.toml --bin scale 2>/dev/null \
  | grep -E "^[a-z_]+," | grep -v "^kernel," > benchmarks/scale_results.csv
echo "wrote benchmarks/scale_results.csv"

echo "== 2. unit tests =="
"$VENV/bin/python" -m pytest tests/ -q -p no:cacheprovider

if [ "${1:-}" = "--fetch-owasp" ]; then
  echo "== 3. fetch OWASP Benchmark 1.2 =="
  curl -sL -o "$CSV" \
    https://raw.githubusercontent.com/OWASP-Benchmark/BenchmarkJava/master/expectedresults-1.2.csv
  rm -rf "$OWASP_DIR"
  git clone --depth 1 --filter=blob:none --sparse \
    https://github.com/OWASP-Benchmark/BenchmarkJava.git "$OWASP_DIR"
  git -C "$OWASP_DIR" sparse-checkout set src/main/java/org/owasp/benchmark/testcode
fi

if [ -f "$CSV" ] && [ -d "$OWASP_DIR/src/main/java/org/owasp/benchmark/testcode" ]; then
  echo "== 4. OWASP Benchmark: precision/recall =="
  "$VENV/bin/python" benchmarks/run_owasp.py \
    --testcode "$OWASP_DIR/src/main/java/org/owasp/benchmark/testcode" --csv "$CSV" \
    | tee benchmarks/results/owasp.txt

  echo "== 4b. OWASP Benchmark with the Java Z3 verifier =="
  "$VENV/bin/python" benchmarks/run_owasp.py \
    --testcode "$OWASP_DIR/src/main/java/org/owasp/benchmark/testcode" --csv "$CSV" --verify \
    | tee benchmarks/results/owasp_z3.txt

  echo "== 5. prioritization oracle (main experiment) =="
  "$VENV/bin/python" benchmarks/run_oracle.py \
    --testcode "$OWASP_DIR/src/main/java/org/owasp/benchmark/testcode" --csv "$CSV" \
    --budget 6 --seeds 20 | tee benchmarks/results/oracle.txt

  echo "== 6. regenerate figures/tables =="
  "$VENV/bin/python" scripts/make_figures.py
else
  echo "!! OWASP corpus not found; skipping steps 4-6 (use --fetch-owasp)."
fi

echo "== 7. demos (toy corpora) =="
"$VENV/bin/python" scripts/demo.py
"$VENV/bin/python" benchmarks/run.py | tee benchmarks/results/toy.txt

echo "== 8. compile the paper and slides =="
if command -v tectonic >/dev/null 2>&1; then
  for lang in en es; do
    (cd "docs/$lang" && tectonic whitepaper.tex >/dev/null && tectonic slides.tex >/dev/null)
  done
  echo "PDFs up to date under docs/{en,es}/."
fi

echo "done."

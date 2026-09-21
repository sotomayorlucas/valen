#!/usr/bin/env bash
# Verify the mechanized formal core (Lean 4). Skips if Lean is not installed.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/.elan/bin:$PATH"
if ! command -v lean >/dev/null 2>&1; then
  echo "lean not found (install via https://leanprover-community.github.io/); skipping"; exit 0
fi
lean "$ROOT/formal/Valen.lean"
echo "formal core verified: prop1_soundness, no_auth_bounded"

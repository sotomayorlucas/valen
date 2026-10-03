#!/usr/bin/env bash
# VALEN demo — Black Hat Arsenal / DEF CON style, authorized lab only.
#
#   ./scripts/demo.sh
#
# Does, best-effort and in order:
#   1. install the package (editable) if `valen` is not on PATH
#   2. start the team server with an initial admin (prints its password)
#   3. bring up the crAPI lab (Docker) + the LLM shim (skippable)
#   4. multi-language SAST demo
#   5. Active Directory attack-graph demo (chokepoints / synthesis / PCFG)
#   6. autonomous pentest (18/18) — only if the lab came up
#   7. generate the report (HTML/MD/JSON/SARIF)
#
# Every offensive step targets the local 127.0.0.1 crAPI lab, with --authorize.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PY=".venv/bin/python"
SCOPE="${SCOPE:-http://127.0.0.1:8888}"
PORT="${PORT:-8000}"
COMPOSE_DIR="${CRAPI_COMPOSE:-/tmp/opencode/crapi/deploy/docker}"

say() { printf '\n\033[1;34m== %s ==\033[0m\n' "$*"; }

# 0. install ----------------------------------------------------------------
if ! command -v valen >/dev/null 2>&1 && [ ! -x .venv/bin/valen ]; then
  say "installing VALEN (editable)"
  python3 -m venv .venv
  .venv/bin/pip install -q -e ".[dev]" || .venv/bin/pip install -q -e .
fi

# 1. team server ------------------------------------------------------------
say "team server"
if ! curl -s -o /dev/null "http://127.0.0.1:$PORT/api/health"; then
  rm -rf /tmp/valen-demo-data
  nohup "$PY" -m valen.server --port "$PORT" --data-dir /tmp/valen-demo-data \
    --create-admin admin > /tmp/valen-demo-server.log 2>&1 &
  sleep 3
fi
ADMIN_PW="$(grep -oP 'password: \K.*' /tmp/valen-demo-server.log | head -1 || true)"
echo "  server: http://127.0.0.1:$PORT   admin / ${ADMIN_PW:-<see log>}"

# 2. crAPI lab (best-effort) -------------------------------------------------
say "crAPI lab"
if command -v docker >/dev/null 2>&1; then
  if [ -d "$COMPOSE_DIR" ]; then
    docker compose -f "$COMPOSE_DIR/docker-compose.yml" \
      -f "$ROOT/examples/lab/crapi-chatbot-litellm.yml" up -d >/dev/null 2>&1 || \
      docker compose -f "$COMPOSE_DIR/docker-compose.yml" up -d >/dev/null 2>&1 || true
  fi
  (nohup "$PY" "$ROOT/examples/lab/openai_shim.py" --port 8055 \
    >/tmp/valen-demo-shim.log 2>&1 &) 2>/dev/null || true
  sleep 2
fi

# 3. multi-language SAST -----------------------------------------------------
say "multi-language SAST"
"$PY" -m valen.cli analyze examples/c/command_injection.c 2>&1 | head -6 || true
"$PY" -m valen.cli analyze examples/rust/command_injection.rs 2>&1 | head -4 || true

# 4. Active Directory attack graph ------------------------------------------
say "Active Directory attack graph"
"$PY" -m valen.cli ad --data tests/fixtures/ad_sharphound.json --entries ALICE,BOB \
  | "$PY" -c 'import sys,json; d=json.load(sys.stdin)
print("  chokepoints:", d["chokepoints"])
print("  hitting:", d["hitting"])
print("  synthesized:", [(p["target"], p["cost"]) for p in d["synthesized_plans"]])'

# 5. autonomous pentest -----------------------------------------------------
if curl -s -o /dev/null "$SCOPE/health"; then
  say "autonomous pentest (authorized, $SCOPE)"
  "$PY" -m valen.cli pentest --scope "$SCOPE" --goal all --authorize 2>&1 | tail -5
else
  say "pentest skipped (lab not reachable at $SCOPE)"
fi

# 6. report -----------------------------------------------------------------
say "report"
"$PY" -m valen.redteam.report --format all --client "VALEN demo" \
  --scope "$SCOPE" --author "VALEN" 2>&1 | tail -5

say "done"
echo "  report: benchmarks/report.{html,md,json,sarif,pdf}"
echo "  UI:     http://127.0.0.1:$PORT  (admin / ${ADMIN_PW:-see /tmp/valen-demo-server.log})"

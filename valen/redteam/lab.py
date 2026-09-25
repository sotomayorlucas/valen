"""crAPI lab lifecycle: reset (down -v + up -d) with the LiteLLM chatbot override.

Used by ``valen pentest --reset`` and ``POST /api/lab/reset`` so an operator can
re-run an engagement against a clean lab without leaving the UI. The override
file (``examples/lab/crapi-chatbot-litellm.yml``) is applied when the LiteLLM
master key is discoverable (env ``LITELLM_MASTER_KEY`` or ``~/litellm/.env``),
so the chatbot challenges (16-18) keep working after a reset.
"""

from __future__ import annotations

import os
import subprocess
import time
import urllib.request
from pathlib import Path
from typing import Dict, Optional

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_COMPOSE = "/tmp/opencode/crapi/deploy/docker"
OVERRIDE = ROOT / "examples" / "lab" / "crapi-chatbot-litellm.yml"


def _litellm_key() -> str:
    key = os.environ.get("LITELLM_MASTER_KEY", "").strip()
    if key:
        return key
    env = Path.home() / "litellm" / ".env"
    if env.exists():
        for line in env.read_text().splitlines():
            if line.startswith("LITELLM_MASTER_KEY="):
                return line.split("=", 1)[1].strip()
    return ""


def wait_healthy(scope: str, timeout: int = 200) -> bool:
    """Poll ``{scope}/health`` until 200 or timeout."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"{scope}/health", timeout=3) as r:
                if r.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(3)
    return False


def reset_lab(compose: Optional[str] = None, scope: str = "http://127.0.0.1:8888",
              timeout: int = 200) -> Dict:
    """``docker compose down -v`` then ``up -d`` at ``compose``; wait for health."""
    cdir = Path(compose or os.environ.get("VALEN_CRAPI_COMPOSE", DEFAULT_COMPOSE))
    if not (cdir / "docker-compose.yml").exists():
        return {"ok": False, "error": f"docker-compose.yml not found in {cdir}",
                "hint": "clone crAPI and pass the compose dir, e.g. "
                        "--compose /tmp/opencode/crapi/deploy/docker"}

    log = []
    try:
        down = subprocess.run(["docker", "compose", "down", "-v"], cwd=cdir,
                              capture_output=True, text=True, timeout=180)
        log.append(f"down: rc={down.returncode}")
    except FileNotFoundError:
        return {"ok": False, "error": "docker not found on PATH"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "docker compose down timed out"}

    env = dict(os.environ)
    key = _litellm_key()
    cmd = ["docker", "compose"]
    if OVERRIDE.exists() and key:
        cmd += ["-f", "docker-compose.yml", "-f", str(OVERRIDE)]
        env["LITELLM_MASTER_KEY"] = key
        log.append("override: crapi-chatbot-litellm.yml (LiteLLM key found)")
    else:
        log.append("override: not applied (no LiteLLM key) — chatbot challenges may fail")
    try:
        up = subprocess.run(cmd + ["up", "-d"], cwd=cdir, capture_output=True,
                            text=True, timeout=420, env=env)
        log.append(f"up: rc={up.returncode}")
        if up.returncode != 0:
            log.append((up.stderr or up.stdout)[-400:])
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "docker compose up timed out", "log": log}

    ok = wait_healthy(scope, timeout)
    log.append(f"health: {'OK' if ok else 'timeout'} ({scope}/health)")
    return {"ok": ok, "compose": str(cdir), "scope": scope, "log": log}

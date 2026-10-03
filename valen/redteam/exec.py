"""Safe execution of external red-team tools.

A deliberately narrow wrapper: only binaries on an explicit allowlist may run,
never through a shell, always with a timeout and output caps. Everything that
touches a target is gated one level up by the engagement ``--allow-exec`` flag
and the operator approval queue.
"""

from __future__ import annotations

import shutil
import subprocess
from typing import Dict, List, Optional

ALLOWED = frozenset({
    "nmap", "masscan", "gobuster", "ffuf", "nuclei", "sqlmap", "nikto",
    "sliver-client", "impacket-GetUserSPNs", "impacket-GetNPUsers",
    "kerbrute", "hashcat", "john", "msfvenom", "bloodhound-python", "ldapsearch",
})

_MAX_STDOUT = 20000
_MAX_STDERR = 4000


def available(binary: str) -> bool:
    return shutil.which(binary) is not None


def installed() -> Dict[str, bool]:
    return {b: available(b) for b in sorted(ALLOWED)}


def install_hint(binary: str) -> str:
    from .tools import TOOLS  # local import: tools.py holds the install methods

    t = TOOLS.get(binary)
    if t:
        return " ; ".join(t.get("install", []))
    return f"install {binary} (not in the bootstrap table)"


def run(cmd: List[str], *, timeout: int = 120, cwd: Optional[str] = None) -> Dict:
    """Run an allowlisted command (no shell). Returns a JSON-able result."""
    if not cmd:
        return {"error": "empty command"}
    exe = cmd[0]
    if exe not in ALLOWED:
        return {"error": f"refused: {exe!r} is not on the execution allowlist",
                "command": cmd}
    if not available(exe):
        return {"error": f"{exe} not installed", "installed": False,
                "command": cmd, "hint": install_hint(exe)}
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           cwd=cwd)
        return {
            "ok": p.returncode == 0, "code": p.returncode,
            "stdout": (p.stdout or "")[-_MAX_STDOUT:],
            "stderr": (p.stderr or "")[-_MAX_STDERR:],
            "command": cmd,
        }
    except subprocess.TimeoutExpired:
        return {"error": "timeout", "timeout": timeout, "command": cmd}
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc), "command": cmd}

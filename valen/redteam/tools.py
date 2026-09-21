"""Kali tool inventory and bootstrap.

VALEN's red-team layer wraps Kali reconnaissance tools. This module (1) reports
which tools are installed, (2) generates the install commands to fetch the
missing ones, and (3) can run the install (dry-run by default).

For authorized engagements only.
"""

from __future__ import annotations

import shutil
import subprocess
from typing import Dict, List

# name -> (executable, apt package, description)
TOOLS: Dict[str, tuple] = {
    "nmap": ("nmap", "nmap", "port and service discovery"),
    "masscan": ("masscan", "masscan", "fast port scanning"),
    "gobuster": ("gobuster", "gobuster", "directory / vhost brute-force"),
    "ffuf": ("ffuf", "ffuf", "fast fuzzing"),
    "theHarvester": ("theHarvester", "theharvester", "OSINT email/domain recon"),
    "amass": ("amass", "amass", "subdomain enumeration"),
    "subfinder": ("subfinder", "subfinder", "subdomain discovery"),
    "nuclei": ("nuclei", "nuclei", "template-based vulnerability scanning"),
    "sqlmap": ("sqlmap", "sqlmap", "SQL injection exploitation"),
    "nikto": ("nikto", "nikto", "web server scanning"),
}


def tool_status() -> Dict[str, Dict]:
    """Return per-tool ``{installed, path, pkg, description}``."""
    out = {}
    for name, (exe, pkg, desc) in TOOLS.items():
        path = shutil.which(exe)
        out[name] = {
            "installed": path is not None,
            "path": path or "",
            "pkg": pkg,
            "description": desc,
        }
    return out


def missing_tools() -> List[str]:
    return [name for name, s in tool_status().items() if not s["installed"]]


def bootstrap_commands() -> List[str]:
    """apt commands to install the missing tools."""
    missing = missing_tools()
    if not missing:
        return []
    pkgs = " ".join(TOOLS[name][1] for name in missing)
    return [
        "sudo apt-get update",
        f"sudo apt-get install -y {pkgs}",
    ]


def bootstrap(dry_run: bool = True) -> Dict:
    """Install missing tools. Returns the commands and (unless dry-run) exit codes."""
    cmds = bootstrap_commands()
    results = []
    if not dry_run and cmds:
        for c in cmds:
            proc = subprocess.run(c, shell=True, capture_output=True, text=True)
            results.append({"command": c, "returncode": proc.returncode,
                            "stderr": proc.stderr[-200:]})
    else:
        results = [{"command": c, "returncode": None} for c in cmds]
    return {"dry_run": dry_run, "missing": missing_tools(), "results": results}

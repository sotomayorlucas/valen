"""Kali tool inventory and bootstrap.

VALEN's red-team layer wraps Kali reconnaissance tools. This module (1) reports
which tools are installed, (2) generates the *correct* install command per tool
(apt vs pipx vs ``go install``), and (3) can run the install (dry-run by default).

Not every Kali tool ships in Ubuntu's apt repositories: theHarvester is a Python
package (pipx), and amass / subfinder / nuclei are Go binaries (``go install``).
The bootstrap emits the right command per tool plus the prerequisite (Go / pipx)
only when needed.

For authorized engagements only.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Dict, List

# name -> {exe, method, install (list of shell commands), pkg, description}
TOOLS: Dict[str, dict] = {
    "nmap":         {"exe": "nmap", "method": "apt", "pkg": "nmap",
                     "install": ["sudo apt-get install -y nmap"],
                     "description": "port and service discovery"},
    "masscan":      {"exe": "masscan", "method": "apt", "pkg": "masscan",
                     "install": ["sudo apt-get install -y masscan"],
                     "description": "fast port scanning"},
    "gobuster":     {"exe": "gobuster", "method": "apt", "pkg": "gobuster",
                     "install": ["sudo apt-get install -y gobuster"],
                     "description": "directory / vhost brute-force"},
    "ffuf":         {"exe": "ffuf", "method": "apt", "pkg": "ffuf",
                     "install": ["sudo apt-get install -y ffuf"],
                     "description": "fast fuzzing"},
    "sqlmap":       {"exe": "sqlmap", "method": "apt", "pkg": "sqlmap",
                     "install": ["sudo apt-get install -y sqlmap"],
                     "description": "SQL injection exploitation"},
    "nikto":        {"exe": "nikto", "method": "apt", "pkg": "nikto",
                     "install": ["sudo apt-get install -y nikto"],
                     "description": "web server scanning"},
    "theHarvester": {"exe": "theHarvester", "method": "uv", "pkg": "github.com/laramies/theHarvester",
                     "install": [
                         "git clone --depth 1 https://github.com/laramies/theHarvester.git ~/theHarvester",
                         "curl -LsSf https://astral.sh/uv/install.sh | sh",
                         "cd ~/theHarvester && uv sync",
                     ],
                     "run": "cd ~/theHarvester && uv run theHarvester -d DOMAIN -b crtsh,certspotter",
                     "description": "OSINT email/domain recon (needs uv; run: uv run theHarvester)"},
    "amass":        {"exe": "amass", "method": "go", "pkg": "github.com/owasp-amass/amass/v4",
                     "install": ["go install -v github.com/owasp-amass/amass/v4/...@master"],
                     "description": "subdomain enumeration"},
    "subfinder":    {"exe": "subfinder", "method": "go", "pkg": "github.com/projectdiscovery/subfinder/v2",
                     "install": ["go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"],
                     "description": "subdomain discovery"},
    "nuclei":       {"exe": "nuclei", "method": "go", "pkg": "github.com/projectdiscovery/nuclei/v3",
                     "install": ["go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"],
                     "description": "template-based vulnerability scanning"},
}


def _gopath() -> Path:
    try:
        out = subprocess.run(["go", "env", "GOPATH"], capture_output=True, text=True)
        if out.returncode == 0 and out.stdout.strip():
            return Path(out.stdout.strip())
    except Exception:
        pass
    return Path.home() / "go"


def _detect(t: dict) -> str:
    """Locate a tool's executable, including non-PATH installs (git/go)."""
    on_path = shutil.which(t["exe"])
    if on_path:
        return on_path
    method = t["method"]
    home = Path.home()
    if method == "uv" and t["exe"] == "theHarvester":
        # installed only after `uv sync` creates the project .venv entry point
        entry = home / "theHarvester" / ".venv" / "bin" / "theHarvester"
        if entry.exists():
            return str(entry)
    if method == "go":
        gopath = _gopath()
        for candidate in (gopath / "bin" / t["exe"], home / "go" / "bin" / t["exe"]):
            if candidate.exists():
                return str(candidate)
    return ""


def tool_status() -> Dict[str, Dict]:
    """Return per-tool ``{installed, path, method, pkg, description, install}``."""
    out = {}
    for name, t in TOOLS.items():
        path = _detect(t)
        out[name] = {
            "installed": bool(path),
            "path": path,
            "method": t["method"],
            "pkg": t["pkg"],
            "description": t["description"],
            "install": t["install"],
        }
    return out


def missing_tools() -> List[str]:
    return [name for name, s in tool_status().items() if not s["installed"]]


def bootstrap_commands() -> List[str]:
    """Shell commands to install the missing tools, with prerequisites first."""
    missing = missing_tools()
    if not missing:
        return []

    apt_tools = [n for n in missing if TOOLS[n]["method"] == "apt"]
    go_tools = [n for n in missing if TOOLS[n]["method"] == "go"]
    other_tools = [n for n in missing if TOOLS[n]["method"] not in ("apt", "go")]

    cmds: List[str] = []
    prereqs: List[str] = []
    if apt_tools:
        cmds.append("sudo apt-get update")
        cmds.append("sudo apt-get install -y " + " ".join(TOOLS[n]["pkg"] for n in apt_tools))
    if go_tools:
        prereqs.append("golang-go")

    if prereqs:
        cmds.append("sudo apt-get install -y " + " ".join(prereqs))

    for n in other_tools:
        cmds.extend(TOOLS[n]["install"])
    for n in go_tools:
        cmds.extend(TOOLS[n]["install"])
    if go_tools:
        cmds.append("export PATH=\"$PATH:$(go env GOPATH)/bin\"")
    return cmds


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

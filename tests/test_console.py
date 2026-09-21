"""Tests for the VALEN red-team console, tool bootstrap, and server routes."""

import json
import subprocess
import sys
import threading
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

from valen.console import build_console, collect
from valen.redteam.tools import bootstrap_commands, missing_tools, tool_status
from valen.server import Handler

ROOT = Path(__file__).resolve().parent.parent


def test_tool_status_inventory():
    status = tool_status()
    assert "nmap" in status and "masscan" in status
    assert set(status["nmap"]) >= {"installed", "path", "method", "pkg", "description"}
    assert isinstance(missing_tools(), list)
    # non-apt tools carry the right install method
    assert status["theHarvester"]["method"] == "git"
    assert status["amass"]["method"] == "go"
    assert status["subfinder"]["method"] == "go"
    assert status["nuclei"]["method"] == "go"


def test_bootstrap_commands_use_correct_method_per_tool():
    cmds = bootstrap_commands()
    if not cmds:
        return
    joined = "\n".join(cmds)
    assert "apt-get install" in joined
    if "theHarvester" in missing_tools():
        assert "git clone" in joined and "laramies/theHarvester" in joined
    if "amass" in missing_tools():
        assert "go install" in joined
        assert "golang-go" in joined
        assert "GOPATH" in joined


def test_build_console_embeds_all_panels():
    html = build_console()
    assert "VALEN" in html and "Red Team Console" in html
    for marker in ("Toolkit", "Attack Plan (kill-chain)", "Proof-of-Concepts",
                   "BOLA / IDOR (crAPI)", "Neuro-symbolic"):
        assert marker in html
    # the embedded JSON is valid and carries the plan
    assert "cve_hypotheses" in html or "recon" in html


def test_collect_has_redteam_artifacts():
    data = collect()
    assert "tools" in data and "recon" in data and "plan" in data and "pocs" in data
    assert "bola" in data


def test_console_cli_writes_file(tmp_path):
    out = tmp_path / "c.html"
    subprocess.run([sys.executable, "-m", "valen.console", "--out", str(out)],
                   cwd=ROOT, capture_output=True, text=True, check=True)
    assert out.exists()
    assert "Red Team Console" in out.read_text()


def test_server_redteam_routes_ephemeral_port():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/console") as r:
            assert r.status == 200
            assert b"Red Team Console" in r.read()

        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/redteam") as r:
            data = json.loads(r.read())
        assert "tools" in data and "plan" in data and "pocs" in data

        # recon endpoint builds (but does not run) the stealth commands
        body = json.dumps({"targets": ["10.0.0.0/24"], "profile": "paranoid"}).encode()
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/recon", data=body,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req) as r:
            recon = json.loads(r.read())
        assert recon["profile"] == "paranoid"
        assert "-T0" in recon["nmap"]
    finally:
        httpd.shutdown()
        httpd.server_close()

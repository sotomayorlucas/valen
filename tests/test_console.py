"""Tests for the VALEN red-team console, tool bootstrap, and server routes."""

import json
import re
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
    assert status["theHarvester"]["method"] == "uv"
    assert status["amass"]["method"] == "go"
    assert status["subfinder"]["method"] == "go"
    assert status["nuclei"]["method"] == "go"


def test_bootstrap_commands_use_correct_method_per_tool():
    cmds = bootstrap_commands()
    if not cmds:
        return
    joined = "\n".join(cmds)
    missing = set(missing_tools())
    if missing & {"nmap", "masscan", "gobuster", "ffuf", "sqlmap", "nikto"}:
        assert "apt-get install" in joined
    if "theHarvester" in missing:
        assert "uv" in joined and "laramies/theHarvester" in joined
    if missing & {"amass", "subfinder", "nuclei"}:
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


# ---------------------------------------------------------------------------
# Regression: the console's inline JS must parse and render.
# ---------------------------------------------------------------------------
def _main_script(html: str) -> str:
    scripts = re.findall(r"<script>(.*?)</script>", html, re.S)
    assert scripts, "console must embed a script"
    return scripts[-1]


def test_console_js_has_no_raw_newline_in_join():
    # ``_PAGE`` must be a raw string: a Python-interpreted \n in the JS template
    # (e.g. join('\n')) breaks the whole script with a syntax error.
    html = build_console()
    assert "join('\\n')" in html, "the backslash-n sequence must survive as two chars"


def test_console_data_script_precedes_main_script():
    # The main script reads document.getElementById('data'); the data island
    # must therefore appear before it, or the page renders nothing.
    html = build_console()
    i_data = html.find('id="data"')
    i_main = html.find("<script>", html.find("</style>"))
    assert 0 <= i_data < i_main, "data island must come before the main script"


def test_console_cards_reference_app_div():
    html = build_console()
    assert 'id="app"' in html
    assert "document.getElementById('app').innerHTML" in html
    assert "toolsCard()" in html and "pocsCard()" in html


def test_console_report_buttons_use_dl():
    html = build_console()
    for fmt in ("html", "md", "json", "sarif", "pdf"):
        assert f"dl('{fmt}')" in html


def test_console_file_protocol_fallback_present():
    html = build_console()
    assert "location.protocol === 'file:'" in html


def test_console_js_parses_with_node(tmp_path):
    """If node is available, syntax-check the embedded script."""
    import shutil
    if not shutil.which("node"):
        return
    script = _main_script(build_console())
    f = tmp_path / "console.js"
    f.write_text(script)
    proc = subprocess.run(["node", "--check", str(f)],
                          capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr

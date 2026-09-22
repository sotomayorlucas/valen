"""Tests for enumeration parsing and shadow-API detection."""

import json
import subprocess
import sys
from pathlib import Path

from valen.redteam.enum import (
    enum_to_graph,
    parse_amass_json,
    parse_ffuf_json,
    parse_gobuster,
    parse_harvester,
    shadow_endpoints,
)
from valen.redteam.wordlists import default_wordlist

ROOT = Path(__file__).resolve().parent.parent


def test_parse_gobuster():
    text = "/admin (Status: 200) [Size: 1234]\n/login (Status: 200) [Size: 900]\n"
    records = parse_gobuster(text)
    assert len(records) == 2
    assert records[0]["path"] == "/admin" and records[0]["status"] == 200


def test_parse_ffuf_json():
    text = '{"url":"http://x/admin","status":200,"length":1234}\n'
    assert parse_ffuf_json(text)[0]["path"] == "x/admin"


def test_parse_amass_and_harvester():
    amass = '{"name":"api.example.com","addresses":[{"ip":"10.0.0.1"}]}\n'
    assert parse_amass_json(amass)[0]["path"] == "api.example.com"
    harv = "victim@example.com\napi.example.com\n"
    recs = parse_harvester(harv)
    assert any(r["path"] == "victim@example.com" for r in recs)


def test_shadow_endpoints():
    recs = parse_gobuster("/admin (Status: 200) [Size: 1]\n/identity/api/v2/user (Status: 200) [Size: 1]\n")
    spec = ["/identity/api/v2/user/dashboard"]
    shadow = shadow_endpoints(recs, spec)
    assert "/admin" in shadow
    assert "/identity/api/v2/user" not in shadow  # prefix of a spec path


def test_enum_to_graph():
    recs = parse_gobuster("/admin (Status: 200) [Size: 1]\n")
    g = enum_to_graph(recs)
    assert g.meta["language"] == "enum"
    assert g.node_count == 2  # target + one discovery


def test_default_wordlist():
    wl = default_wordlist()
    assert len(wl) > 30
    assert "admin" in wl and "api" in wl


def test_run_enum_generation():
    subprocess.run(
        [sys.executable, str(ROOT / "benchmarks" / "run_enum.py")],
        capture_output=True, text=True, check=True,
    )
    data = json.loads((ROOT / "benchmarks" / "enum_results.json").read_text())
    assert data["n"] > 0
    # /admin and /internal are not in the crAPI OpenAPI spec -> shadow endpoints
    assert "/admin" in data["shadow_endpoints"]
    assert "/internal" in data["shadow_endpoints"]

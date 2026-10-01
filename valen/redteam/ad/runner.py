"""Optional live AD credential-attack driver (behind --allow-exec).

Wraps the command builders with the safe executor so an approved action can run
``impacket``/``kerbrute``/``hashcat`` for real when the operator enables it.
Absent tools degrade to an install hint rather than failing hard.
"""

from __future__ import annotations

from typing import Any, Dict

from ..exec import install_hint, installed, run
from .attacks import asrep_command, crack_command, kerberoast_command, spray_command


class ADRunner:
    def __init__(self, timeout: int = 600) -> None:
        self.timeout = timeout

    def tools(self) -> Dict[str, bool]:
        all_tools = installed()
        return {k: v for k, v in all_tools.items()
                if k in ("impacket-GetUserSPNs", "impacket-GetNPUsers",
                         "kerbrute", "hashcat", "john")}

    def _maybe(self, cmd, execute: bool) -> Dict[str, Any]:
        if not execute:
            return {"command": cmd, "note": "dry-run (pass execute=true and --allow-exec)"}
        return run(cmd, timeout=self.timeout)

    def kerberoast(self, domain: str, dc: str, user: str, password: str,
                   execute: bool = False) -> Dict[str, Any]:
        return self._maybe(kerberoast_command(domain, dc, user, password), execute)

    def asrep(self, domain: str, dc: str, users_file: str = "users.txt",
              execute: bool = False) -> Dict[str, Any]:
        return self._maybe(asrep_command(domain, dc, users_file), execute)

    def spray(self, domain: str, dc: str, users_file: str, password: str,
              execute: bool = False) -> Dict[str, Any]:
        return self._maybe(spray_command(domain, dc, users_file, password), execute)

    def crack(self, hashes_file: str, wordlist: str, mode: str = "13100",
              execute: bool = False) -> Dict[str, Any]:
        return self._maybe(crack_command(hashes_file, wordlist, mode), execute)


__all__ = ["ADRunner", "install_hint"]

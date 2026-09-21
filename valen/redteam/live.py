"""Active validation: replay a BOLA/IDOR finding against a live target.

VALEN's static witnesses show *satisfiability*; this layer shows *impact* by
actually sending the request and checking the response. A red team points it at
a reachable host with a low-privilege credential, and it confirms (or refutes)
the leak without needing source code.
"""

from __future__ import annotations

from typing import Dict, Optional

import requests

from .poc import build_url


class LiveValidator:
    def __init__(self, base_url: str, timeout: float = 5.0, verify_tls: bool = False):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.verify_tls = verify_tls

    def check(
        self,
        method: str,
        path: str,
        id_params: list,
        victim_id: str,
        token: str,
        leak_hint: str = "",
    ) -> Dict:
        url = self.base_url + build_url(path, id_params, victim_id)
        headers = {"Authorization": f"Bearer {token}"}
        try:
            r = requests.request(
                method, url, headers=headers,
                timeout=self.timeout, verify=self.verify_tls,
            )
            body = r.text
            leaked = (r.status_code == 200) and (leak_hint in body if leak_hint else bool(body))
            return {
                "url": url,
                "status": r.status_code,
                "leaked": leaked,
                "evidence": body[:400],
            }
        except requests.RequestException as exc:
            return {"url": url, "status": None, "leaked": False,
                    "evidence": str(exc)[:200], "error": str(exc)[:200]}

    def validate(self, plan: dict, victim_id: str, token: str) -> Dict:
        """Validate one generated PoC plan (from ``valen.redteam.poc``)."""
        return self.check(
            plan["method"], plan["path"], plan.get("id_params", []),
            victim_id, token, plan.get("leak_hint", ""),
        )

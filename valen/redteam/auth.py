"""crAPI client: signup, login, token handling, and authenticated requests.

A thin wrapper over ``requests`` for the crAPI identity flow. Two users are
seeded so BOLA/IDOR can be demonstrated (attacker reads the victim's resources).

For authorized engagements only (point at the local lab, not arbitrary hosts).
"""

from __future__ import annotations

from typing import Dict, List, Optional

import requests


class CrApiClient:
    def __init__(self, base_url: str = "http://127.0.0.1:8888",
                 timeout: float = 10.0, verify_tls: bool = False):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.session = requests.Session()

    def signup(self, name: str, email: str, number: str, password: str) -> Dict:
        r = self.session.post(
            f"{self.base_url}/identity/api/auth/signup",
            json={"name": name, "email": email, "number": number, "password": password},
            timeout=self.timeout, verify=self.verify_tls,
        )
        return {"status": r.status_code, "body": r.json() if r.content else {}}

    def login(self, email: str, password: str) -> Dict:
        r = self.session.post(
            f"{self.base_url}/identity/api/auth/login",
            json={"email": email, "password": password},
            timeout=self.timeout, verify=self.verify_tls,
        )
        body = r.json() if r.content else {}
        token = body.get("token") if isinstance(body, dict) else None
        return {"status": r.status_code, "body": body, "token": token}

    def get(self, path: str, token: str) -> Dict:
        r = self.session.get(
            f"{self.base_url}{path}",
            headers={"Authorization": f"Bearer {token}"},
            timeout=self.timeout, verify=self.verify_tls,
        )
        return {"status": r.status_code, "body": r.text, "json": self._safe_json(r)}

    def put(self, path: str, token: str, json_body: Optional[Dict] = None) -> Dict:
        r = self.session.put(
            f"{self.base_url}{path}",
            headers={"Authorization": f"Bearer {token}"},
            json=json_body or {}, timeout=self.timeout, verify=self.verify_tls,
        )
        return {"status": r.status_code, "body": r.text, "json": self._safe_json(r)}

    @staticmethod
    def _safe_json(r) -> Optional[dict]:
        try:
            return r.json()
        except Exception:
            return None

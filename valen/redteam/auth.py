"""crAPI client: signup, login, token handling, and authenticated requests.

A thin wrapper over ``requests`` for the crAPI identity flow. Two users are
seeded so BOLA/IDOR can be demonstrated (attacker reads the victim's resources).

For authorized engagements only (point at the local lab, not arbitrary hosts).
"""

from __future__ import annotations

from typing import Dict, List, Optional
from urllib.parse import urlsplit, urlunsplit

import requests

DEFAULT_SCOPE = "http://127.0.0.1:8888"


def normalize_scope(url: str) -> str:
    """Reduce a target URL to its origin (``scheme://host[:port]``).

    Operators often paste a deep link from the browser (e.g.
    ``http://127.0.0.1:8888/login``); the pentest agent appends API paths to the
    scope, so any path/query/fragment must be dropped or every request is
    prefixed with the wrong path. Raises ``ValueError`` if it is not an
    ``http(s)`` origin.
    """
    parts = urlsplit((url or "").strip())
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise ValueError(f"invalid scope {url!r} (need http(s)://host[:port])")
    return urlunsplit((parts.scheme, parts.netloc, "", "", ""))


class CrApiClient:
    def __init__(self, base_url: str = DEFAULT_SCOPE,
                 timeout: float = 10.0, verify_tls: bool = False):
        try:
            self.base_url = normalize_scope(base_url)
        except ValueError:
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

    def post(self, path: str, token: str, json_body: Optional[Dict] = None) -> Dict:
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        r = self.session.post(
            f"{self.base_url}{path}", headers=headers,
            json=json_body or {}, timeout=self.timeout, verify=self.verify_tls,
        )
        return {"status": r.status_code, "body": r.text, "json": self._safe_json(r)}

    def delete(self, path: str, token: str) -> Dict:
        r = self.session.delete(
            f"{self.base_url}{path}",
            headers={"Authorization": f"Bearer {token}"},
            timeout=self.timeout, verify=self.verify_tls,
        )
        return {"status": r.status_code, "body": r.text, "json": self._safe_json(r)}

    @staticmethod
    def _safe_json(r) -> Optional[dict]:
        try:
            return r.json()
        except Exception:
            return None

"""Authentication and authorization for the VALEN team server.

Users, roles and sessions live in the same SQLite database as the history store
(``~/.local/share/valen/valen.db``), so a team server is a single file to back up.

Roles (least → most privileged): ``viewer`` < ``operator`` < ``admin``.
Passwords use PBKDF2-HMAC-SHA256 (stdlib); session tokens are random and stored
hashed, so a DB leak does not yield usable tokens.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from .store import Store, default_data_dir

ROLES = ("viewer", "operator", "admin")

# capability -> roles allowed
PERMISSIONS: Dict[str, set] = {
    "read": {"viewer", "operator", "admin"},
    "write": {"operator", "admin"},          # create engagements / record runs
    "execute": {"operator", "admin"},         # scans, pentest, dynamic, lab reset
    "manage_engagement": {"operator", "admin"},
    "manage_users": {"admin"},
}


def role_can(role: str, capability: str) -> bool:
    return role in PERMISSIONS.get(capability, set())


_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'operator',
    created_at REAL NOT NULL,
    disabled INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
"""

_ITERATIONS = 200_000


def _hash_password(password: str, salt_hex: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), _ITERATIONS
    ).hex()


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class Authz:
    """User + session store backed by the shared SQLite database."""

    def __init__(self, path: Optional[str] = None) -> None:
        self.dir = Path(path) if path else default_data_dir()
        self.dir.mkdir(parents=True, exist_ok=True)
        self.db = self.dir / "valen.db"
        self._init()

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        c = sqlite3.connect(self.db, timeout=10)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA foreign_keys = ON")
        try:
            yield c
            c.commit()
        finally:
            c.close()

    def _init(self) -> None:
        with self._conn() as c:
            c.executescript(_SCHEMA)

    # -- users -------------------------------------------------------------
    def has_users(self) -> bool:
        with self._conn() as c:
            return c.execute("SELECT COUNT(*) FROM users").fetchone()[0] > 0

    def create_user(self, username: str, password: str,
                    role: str = "operator") -> Dict[str, Any]:
        username = (username or "").strip()
        if not username:
            raise ValueError("username required")
        if role not in ROLES:
            raise ValueError(f"role must be one of {ROLES}")
        if len(password or "") < 8:
            raise ValueError("password must be at least 8 characters")
        salt = os.urandom(16).hex()
        ph = _hash_password(password, salt)
        with self._conn() as c:
            try:
                cur = c.execute(
                    "INSERT INTO users(username, password_hash, salt, role, created_at)"
                    " VALUES(?,?,?,?,?)",
                    (username, ph, salt, role, time.time()),
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError(f"user {username!r} already exists") from exc
            row = c.execute("SELECT * FROM users WHERE id=?", (cur.lastrowid,)).fetchone()
        return self._public(row)

    @staticmethod
    def _public(row: sqlite3.Row) -> Dict[str, Any]:
        if row is None:
            return {}
        d = dict(row)
        d.pop("password_hash", None)
        d.pop("salt", None)
        d["disabled"] = bool(d.get("disabled"))
        return d

    def list_users(self) -> List[Dict[str, Any]]:
        with self._conn() as c:
            rows = c.execute("SELECT * FROM users ORDER BY id").fetchall()
        return [self._public(r) for r in rows]

    def get_user(self, user_id: int) -> Optional[Dict[str, Any]]:
        with self._conn() as c:
            row = c.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        return self._public(row) if row else None

    def set_role(self, user_id: int, role: str) -> None:
        if role not in ROLES:
            raise ValueError(f"role must be one of {ROLES}")
        with self._conn() as c:
            c.execute("UPDATE users SET role=? WHERE id=?", (role, user_id))

    def set_password(self, user_id: int, password: str) -> None:
        if len(password or "") < 8:
            raise ValueError("password must be at least 8 characters")
        salt = os.urandom(16).hex()
        with self._conn() as c:
            c.execute("UPDATE users SET password_hash=?, salt=? WHERE id=?",
                      (_hash_password(password, salt), salt, user_id))

    def set_disabled(self, user_id: int, disabled: bool) -> None:
        with self._conn() as c:
            c.execute("UPDATE users SET disabled=? WHERE id=?",
                      (1 if disabled else 0, user_id))

    def delete_user(self, user_id: int) -> None:
        with self._conn() as c:
            c.execute("DELETE FROM users WHERE id=?", (user_id,))

    def count(self) -> int:
        with self._conn() as c:
            return c.execute("SELECT COUNT(*) FROM users").fetchone()[0]

    # -- authentication ----------------------------------------------------
    def authenticate(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        with self._conn() as c:
            row = c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if row is None or row["disabled"]:
            # constant-time-ish: still do a dummy hash to avoid trivial timing leaks
            _hash_password(password or "", os.urandom(16).hex())
            return None
        expected = row["password_hash"]
        got = _hash_password(password or "", row["salt"])
        if not secrets.compare_digest(expected, got):
            return None
        return self._public(row)

    # -- sessions ----------------------------------------------------------
    def create_session(self, user_id: int, ttl: float = 12 * 3600) -> str:
        token = secrets.token_urlsafe(32)
        now = time.time()
        with self._conn() as c:
            c.execute(
                "INSERT INTO sessions(token_hash, user_id, created_at, expires_at)"
                " VALUES(?,?,?,?)",
                (_hash_token(token), user_id, now, now + ttl),
            )
        return token

    def resolve(self, token: str) -> Optional[Dict[str, Any]]:
        if not token:
            return None
        th = _hash_token(token)
        with self._conn() as c:
            row = c.execute("SELECT * FROM sessions WHERE token_hash=?", (th,)).fetchone()
            if row is None:
                return None
            if row["expires_at"] < time.time():
                c.execute("DELETE FROM sessions WHERE token_hash=?", (th,))
                return None
            user = c.execute("SELECT * FROM users WHERE id=?", (row["user_id"],)).fetchone()
        if user is None or user["disabled"]:
            return None
        return self._public(user)

    def revoke(self, token: str) -> None:
        with self._conn() as c:
            c.execute("DELETE FROM sessions WHERE token_hash=?", (_hash_token(token),))

    def purge_expired(self) -> int:
        with self._conn() as c:
            cur = c.execute("DELETE FROM sessions WHERE expires_at < ?", (time.time(),))
            return cur.rowcount


def bootstrap_admin(authz: Authz, username: str = "admin",
                    password: Optional[str] = None) -> Dict[str, Any]:
    """Create the initial admin. Generates a password if none is given."""
    if authz.has_users():
        raise ValueError("an admin already exists")
    pw = password or secrets.token_urlsafe(12)
    user = authz.create_user(username, pw, role="admin")
    user["generated_password"] = None if password else pw
    return user


def open_shared_store(path: Optional[str] = None) -> Store:
    """Open the history ``Store`` against the same DB file as :class:`Authz`."""
    return Store(path)

"""Persistent store for engagements and analysis/pentest runs (stdlib sqlite3).

Single-operator MVP: a local SQLite database under ``VALEN_DATA_DIR`` (default
``~/.local/share/valen``) holds engagements and the runs attached to them, so the
web UI can show history across server restarts.

Thread-safety: ``sqlite3`` connections are not shared across threads, and the
server is threaded, so every operation opens a short-lived connection.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional


def default_data_dir() -> Path:
    env = os.environ.get("VALEN_DATA_DIR")
    if env:
        return Path(env)
    xdg = os.environ.get("XDG_DATA_HOME")
    base = Path(xdg) if xdg else Path.home() / ".local" / "share"
    return base / "valen"


_SCHEMA = """
CREATE TABLE IF NOT EXISTS engagements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    client TEXT DEFAULT '',
    scope TEXT DEFAULT '',
    notes TEXT DEFAULT '',
    owner_id INTEGER,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS engagement_members (
    engagement_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    role TEXT NOT NULL DEFAULT 'operator',   -- operator | viewer
    created_at REAL NOT NULL,
    PRIMARY KEY (engagement_id, user_id),
    FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER,
    kind TEXT NOT NULL,             -- analyze | compare | dynamic | pentest | report
    name TEXT DEFAULT '',
    adapter TEXT DEFAULT '',
    path TEXT DEFAULT '',
    summary TEXT DEFAULT '',
    payload TEXT NOT NULL,          -- JSON
    created_at REAL NOT NULL,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_runs_engagement ON runs(engagement_id);
CREATE INDEX IF NOT EXISTS idx_runs_created ON runs(created_at);
CREATE INDEX IF NOT EXISTS idx_members_user ON engagement_members(user_id);
"""


class Store:
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
            # migrate pre-multi-user databases (engagements.owner_id added in 0.2)
            cols = {r["name"] for r in c.execute("PRAGMA table_info(engagements)")}
            if "owner_id" not in cols:
                c.execute("ALTER TABLE engagements ADD COLUMN owner_id INTEGER")

    # -- engagements -------------------------------------------------------
    def create_engagement(self, name: str, client: str = "", scope: str = "",
                          notes: str = "", owner_id: Optional[int] = None) -> Dict[str, Any]:
        with self._conn() as c:
            cur = c.execute(
                "INSERT INTO engagements(name, client, scope, notes, owner_id, created_at)"
                " VALUES(?,?,?,?,?,?)",
                (name, client, scope, notes, owner_id, time.time()),
            )
            row = c.execute("SELECT * FROM engagements WHERE id=?",
                            (cur.lastrowid,)).fetchone()
        eng = dict(row) if row else {}
        eng["runs"] = []
        return eng

    def list_engagements(self, user_id: Optional[int] = None) -> List[Dict[str, Any]]:
        with self._conn() as c:
            base = (
                "SELECT e.*, (SELECT COUNT(*) FROM runs r WHERE r.engagement_id=e.id)"
                " AS run_count FROM engagements e"
            )
            if user_id is None:
                rows = c.execute(base + " ORDER BY e.created_at DESC").fetchall()
            else:
                rows = c.execute(
                    base + " WHERE e.owner_id=? OR e.id IN"
                    " (SELECT engagement_id FROM engagement_members WHERE user_id=?)"
                    " ORDER BY e.created_at DESC",
                    (user_id, user_id),
                ).fetchall()
        return [dict(r) for r in rows]

    def get_engagement(self, eid: int) -> Optional[Dict[str, Any]]:
        with self._conn() as c:
            row = c.execute("SELECT * FROM engagements WHERE id=?", (eid,)).fetchone()
            if row is None:
                return None
            eng = dict(row)
            eng["runs"] = [self._row_to_run(r) for r in c.execute(
                "SELECT * FROM runs WHERE engagement_id=? ORDER BY created_at DESC", (eid,)
            ).fetchall()]
        return eng

    def delete_engagement(self, eid: int) -> None:
        with self._conn() as c:
            c.execute("DELETE FROM runs WHERE engagement_id=?", (eid,))
            c.execute("DELETE FROM engagement_members WHERE engagement_id=?", (eid,))
            c.execute("DELETE FROM engagements WHERE id=?", (eid,))

    # -- membership / access ----------------------------------------------
    def add_member(self, eid: int, user_id: int, role: str = "operator") -> None:
        with self._conn() as c:
            c.execute(
                "INSERT OR REPLACE INTO engagement_members"
                "(engagement_id, user_id, role, created_at) VALUES(?,?,?,?)",
                (eid, user_id, role, time.time()),
            )

    def remove_member(self, eid: int, user_id: int) -> None:
        with self._conn() as c:
            c.execute("DELETE FROM engagement_members WHERE engagement_id=? AND user_id=?",
                      (eid, user_id))

    def list_members(self, eid: int) -> List[Dict[str, Any]]:
        with self._conn() as c:
            return [dict(r) for r in c.execute(
                "SELECT * FROM engagement_members WHERE engagement_id=?", (eid,)
            ).fetchall()]

    def member_role(self, eid: int, user_id: int) -> Optional[str]:
        with self._conn() as c:
            row = c.execute(
                "SELECT role FROM engagement_members WHERE engagement_id=? AND user_id=?",
                (eid, user_id),
            ).fetchone()
        return row["role"] if row else None

    def can_access(self, eid: int, user: Dict[str, Any]) -> bool:
        """Admins see everything; others need to own or be a member."""
        if not user:
            return False
        if user.get("role") == "admin":
            return True
        with self._conn() as c:
            row = c.execute("SELECT owner_id FROM engagements WHERE id=?", (eid,)).fetchone()
            if row is None:
                return False
            if row["owner_id"] == user.get("id"):
                return True
            return self.member_role(eid, user.get("id")) is not None

    # -- runs --------------------------------------------------------------
    @staticmethod
    def _row_to_run(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        try:
            d["payload"] = json.loads(d.get("payload") or "{}")
        except Exception:
            d["payload"] = {}
        return d

    def record(self, kind: str, payload: Any, *, engagement_id: Optional[int] = None,
               name: str = "", adapter: str = "", path: str = "",
               summary: str = "") -> Dict[str, Any]:
        with self._conn() as c:
            cur = c.execute(
                "INSERT INTO runs(engagement_id, kind, name, adapter, path, summary,"
                " payload, created_at) VALUES(?,?,?,?,?,?,?,?)",
                (engagement_id, kind, name, adapter, path, summary,
                 json.dumps(payload), time.time()),
            )
            rid = cur.lastrowid
        return {"id": rid, "kind": kind, "name": name}

    def get_run(self, rid: int) -> Optional[Dict[str, Any]]:
        with self._conn() as c:
            row = c.execute("SELECT * FROM runs WHERE id=?", (rid,)).fetchone()
        return self._row_to_run(row) if row else None

    def recent_runs(self, limit: int = 50, kind: Optional[str] = None) -> List[Dict[str, Any]]:
        q = "SELECT id, engagement_id, kind, name, adapter, path, summary, created_at FROM runs"
        args: List[Any] = []
        if kind:
            q += " WHERE kind=?"
            args.append(kind)
        q += " ORDER BY created_at DESC LIMIT ?"
        args.append(limit)
        with self._conn() as c:
            rows = c.execute(q, args).fetchall()
        return [dict(r) for r in rows]

    def count(self) -> Dict[str, int]:
        with self._conn() as c:
            eng = c.execute("SELECT COUNT(*) FROM engagements").fetchone()[0]
            runs = c.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
        return {"engagements": eng, "runs": runs}

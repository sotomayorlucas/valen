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
    created_at REAL NOT NULL
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

    # -- engagements -------------------------------------------------------
    def create_engagement(self, name: str, client: str = "", scope: str = "",
                          notes: str = "") -> Dict[str, Any]:
        with self._conn() as c:
            cur = c.execute(
                "INSERT INTO engagements(name, client, scope, notes, created_at)"
                " VALUES(?,?,?,?,?)",
                (name, client, scope, notes, time.time()),
            )
            row = c.execute("SELECT * FROM engagements WHERE id=?",
                            (cur.lastrowid,)).fetchone()
        eng = dict(row) if row else {}
        eng["runs"] = []
        return eng

    def list_engagements(self) -> List[Dict[str, Any]]:
        with self._conn() as c:
            rows = c.execute(
                "SELECT e.*, (SELECT COUNT(*) FROM runs r WHERE r.engagement_id=e.id)"
                " AS run_count FROM engagements e ORDER BY e.created_at DESC"
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
            c.execute("DELETE FROM engagements WHERE id=?", (eid,))

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

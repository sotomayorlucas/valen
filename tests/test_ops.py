"""Tests for the operation board (kill-chain mapping)."""

import json
import threading
import urllib.request
from http.server import ThreadingHTTPServer

from valen.ops import board_from_store, build_board
from valen.server import Handler, ServerConfig
from valen.store import Store


def test_build_board_maps_kinds_to_tactics():
    runs = [
        {"kind": "analyze", "name": "sqli.py", "adapter": "python", "summary": "1 finding",
         "engagement_id": 1, "created_at": 1.0},
        {"kind": "pentest", "name": "crAPI", "adapter": "", "summary": "18/18",
         "engagement_id": 1, "created_at": 2.0},
        {"kind": "dynamic", "name": "t.py", "adapter": "python", "summary": "exit=0",
         "engagement_id": 1, "created_at": 3.0},
    ]
    board = build_board(runs, engagement_id=1)
    tids = [p["tactic_id"] for p in board["phases"]]
    assert tids == ["TA0007", "TA0002", "TA0009"]  # kill-chain order
    assert board["total_runs"] == 3
    assert "T1213" in board["techniques"]
    # engagement filter
    assert build_board(runs, engagement_id=99)["total_runs"] == 0


def test_board_from_store(tmp_path):
    s = Store(str(tmp_path / "d"))
    e = s.create_engagement("e1", owner_id=1)
    s.record("analyze", {"x": 1}, engagement_id=e["id"], name="a.py", summary="1 finding")
    s.record("pentest", {"solved": 18}, engagement_id=e["id"], name="crapi", summary="18/18")
    board = board_from_store(s, engagement_id=e["id"])
    assert board["total_runs"] == 2
    assert {p["tactic_id"] for p in board["phases"]} == {"TA0007", "TA0009"}


def test_operations_endpoint(tmp_path):
    store = Store(str(tmp_path / "d"))
    e = store.create_engagement("e1")
    store.record("pentest", {"solved": 18}, engagement_id=e["id"], name="crapi", summary="18/18")
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    httpd.cfg = ServerConfig(store=store)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        port = httpd.server_address[1]
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/operations?engagement_id={e['id']}") as r:
            board = json.loads(r.read())
        assert board["total_runs"] == 1
        assert board["phases"][0]["tactic_id"] == "TA0009"
    finally:
        httpd.shutdown()
        httpd.server_close()

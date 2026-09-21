"""Tests for the red-team assistance layer (PoC generation + live validation)."""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from valen.redteam.live import LiveValidator
from valen.redteam.poc import build_url, generate_pocs, render_poc

ROOT = Path(__file__).resolve().parent.parent
SPEC = ROOT / "examples" / "api" / "crapi-openapi-spec.json"
LABELS = ROOT / "examples" / "api" / "crapi_bola_labels.json"


# ---- a tiny mock target: one vulnerable endpoint, one fixed -----------------
class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if "location-fixed" in self.path:
            # fixed: only the owner (id == "self") gets the resource
            if self.path.split("/")[-2] != "self":
                self.send_response(403)
                self.end_headers()
                return
        # vulnerable endpoint leaks the victim's data regardless of token
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"full_name": "victim", "latitude": 1.0, "longitude": 2.0}')

    def log_message(self, *a):
        pass


def _server():
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, f"http://127.0.0.1:{srv.server_port}"


def test_render_poc_is_valid_python_and_points_at_target():
    poc = render_poc("GET", "/identity/api/v2/vehicle/{vehicleId}/location",
                     [], leak_hint="full_name", base_url="http://x")
    compile(poc, "<poc>", "exec")  # must be valid Python
    assert "/identity/api/v2/vehicle/{VICTIM_ID}/location" in poc
    assert "full_name" in poc


def test_build_url_substitutes_path_and_query_ids():
    assert build_url("/api/videos/{video_id}", [], "42") == "/api/videos/42"
    assert build_url("/api/report", ["report_id"], "7") == "/api/report?report_id=7"


def test_live_validator_detects_vulnerable_and_fixed():
    srv, base = _server()
    try:
        v = LiveValidator(base)
        vuln = v.check("GET", "/identity/api/v2/vehicle/{vehicleId}/location",
                       [], victim_id="victim-1", token="attacker", leak_hint="full_name")
        fixed = v.check("GET", "/identity/api/v2/vehicle/{vehicleId}/location-fixed",
                        [], victim_id="victim-1", token="attacker", leak_hint="full_name")
        assert vuln["leaked"] is True and vuln["status"] == 200
        assert fixed["leaked"] is False and fixed["status"] == 403
    finally:
        srv.shutdown()


def test_generate_pocs_covers_all_documented_bola_endpoints():
    spec = json.loads(SPEC.read_text())
    labels = json.loads(LABELS.read_text())
    pocs = generate_pocs(spec, labels, leak_hints={"GET /identity/api/v2/vehicle/{vehicleId}/location": "full_name"})
    got = {f"{p['method']} {p['path']}" for p in pocs}
    assert got == set(labels["vulnerable"])
    assert len(pocs) == 9
    for p in pocs:
        compile(p["poc"], "<poc>", "exec")  # raises if any PoC is invalid

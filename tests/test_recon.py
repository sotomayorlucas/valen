"""Tests for Kali recon ingestion and stealth profiles (hermetic, no scanning)."""

import random
import subprocess
import sys
from pathlib import Path

from valen.redteam.recon import (
    hypothesis_for,
    network_topology_graph,
    parse_masscan_json,
    parse_nmap_xml,
    recon_to_graph,
)
from valen.redteam.stealth import PRESETS, StealthProfile, build_masscan_args, build_nmap_args

ROOT = Path(__file__).resolve().parent.parent
NMAP = (ROOT / "examples" / "recon" / "nmap.xml").read_text()
MASSCAN = (ROOT / "examples" / "recon" / "masscan.json").read_text()


def test_parse_nmap_xml():
    hosts = parse_nmap_xml(NMAP)
    assert len(hosts) == 3
    web = next(h for h in hosts if h["ip"] == "10.0.0.5")
    assert {s["port"] for s in web["services"]} == {80, 443}
    assert web["services"][0]["product"] == "Apache httpd"


def test_parse_nmap_xml_ignores_closed_ports():
    xml = """<nmaprun><host><address addr="10.0.0.9" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22"><state state="closed"/><service name="ssh"/></port>
      <port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
    </ports></host></nmaprun>"""
    hosts = parse_nmap_xml(xml)
    assert [s["port"] for s in hosts[0]["services"]] == [80]


def test_parse_masscan_json():
    hosts = parse_masscan_json(MASSCAN)
    assert len(hosts) == 3
    assert any(h["ip"] == "10.0.0.12" for h in hosts)


def test_recon_to_graph():
    graph = recon_to_graph(parse_nmap_xml(NMAP))
    assert graph.meta["language"] == "recon"
    assert graph.node_count == 3 + 4  # 3 hosts + 4 services (22, 80, 443, 21)
    assert any(n.attrs.get("kind") == "service" for n in graph.nodes)


def test_network_topology_adds_gateway_edges():
    hosts = parse_nmap_xml(NMAP)
    graph = network_topology_graph(hosts, gateway="10.0.0.1")
    # gateway <-> every other host (2 hosts), so +4 route edges
    routes = [e for e in graph.edges() if e.attrs.get("relation") == "route"]
    assert len(routes) == 4
    assert any(e.src == "10.0.0.1" and e.dst == "10.0.0.5" for e in routes)


def test_cve_hypothesis_mapping():
    assert hypothesis_for("Apache httpd 2.4.49") == "CVE-2021-41773 (path traversal)"
    assert hypothesis_for("vsftpd 2.3.4") == "CVE-2011-2523 (backdoor)"
    assert hypothesis_for("nginx 1.18") is None


def test_stealth_nmap_args():
    profile = PRESETS["sneaky"]
    args = build_nmap_args(profile, ["10.0.0.0/24"], "1-1000")
    assert args[0] == "nmap" and "-oX" in args
    assert "-T2" in args and "--max-rate" in args and "25" in args
    assert "--randomize-hosts" in args and "--data-length" in args
    assert "--host-timeout" in args


def test_stealth_paranoid_is_quietest():
    paranoid = PRESETS["paranoid"]
    assert paranoid.timing == "T0"
    # paranoid is quieter than sneaky; "active" means unlimited (rate 0)
    assert paranoid.max_rate < PRESETS["sneaky"].max_rate
    assert PRESETS["active"].max_rate == 0


def test_masscan_args_has_rate_and_json():
    args = build_masscan_args(PRESETS["sneaky"], ["10.0.0.0/24"], "1-1000")
    assert args[0] == "masscan" and "--rate" in args and "-oJ" in args


def test_jitter_sleep_within_range(monkeypatch):
    slept = []
    monkeypatch.setattr("valen.redteam.stealth.time.sleep", lambda s: slept.append(s))
    profile = StealthProfile(jitter_ms=(100, 500))
    from valen.redteam.stealth import jitter_sleep
    delay = jitter_sleep(profile, rng=random.Random(0))
    assert 0.1 <= delay <= 0.5
    assert slept and 0.1 <= slept[0] <= 0.5


def test_recon_plan_generation():
    subprocess.run(
        [sys.executable, str(ROOT / "benchmarks" / "run_recon_plan.py")],
        capture_output=True, text=True, check=True,
    )
    import json
    data = json.loads((ROOT / "benchmarks" / "recon_plan.json").read_text())
    assert len(data["hosts"]) == 6
    # the three illustrative CVE hypotheses are present
    assert len(data["cve_hypotheses"]) >= 3
    assert data["profile"] == "sneaky"


def test_network_map_generation():
    subprocess.run(
        [sys.executable, str(ROOT / "benchmarks" / "run_network_map.py"),
         "--nmap", str(ROOT / "examples" / "recon" / "nmap.xml"), "--gateway", "10.0.0.1"],
        capture_output=True, text=True, check=True,
    )
    import json
    data = json.loads((ROOT / "benchmarks" / "network_map.json").read_text())
    assert data["n_hosts"] == 3
    assert data["gateway"] == "10.0.0.1"
    # the gateway surfaces among the trust bridges (it is the routing hub)
    assert any("gw" in f"{b['src_label']}{b['dst_label']}" for b in data["trust_bridges"])

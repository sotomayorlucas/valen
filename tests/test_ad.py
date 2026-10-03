"""Tests for the Active Directory attack-graph module."""

import json
from pathlib import Path

import pytest

from valen.redteam.ad import (
    asrep_roastable,
    attack_paths,
    betweenness_ranking,
    decrypt_cpassword,
    gpp_from_xml,
    high_value_targets,
    kerberoastable,
    node_id,
    parse_sharphound,
)

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "ad_sharphound.json"


def _ad():
    return parse_sharphound(json.loads(FIXTURE.read_text()))


def test_graph_builds_nodes_and_edges():
    ad = _ad()
    assert ad.graph.node_count >= 8
    # ALICE --GenericAll--> DOMAIN ADMINS
    assert ad.graph.has_node(node_id("group", "DOMAIN ADMINS@CORP.LOCAL"))
    assert ad.graph.has_node(node_id("domain", "CORP.LOCAL"))
    rels = {e.attrs.get("ad_relation") for e in ad.graph.edges()}
    assert {"MemberOf", "GenericAll", "AdminTo", "HasSession", "TrustedBy", "DCSync"} <= rels


def test_kerberoastable_and_asrep():
    ad = _ad()
    spn = {u["name"] for u in kerberoastable(ad)}
    assert spn == {"ALICE@CORP.LOCAL", "SVC_SQL@CORP.LOCAL"}
    asrep = {u["name"] for u in asrep_roastable(ad)}
    assert asrep == {"BOB@CORP.LOCAL"}


def test_high_value_targets():
    ad = _ad()
    targets = high_value_targets(ad)
    assert node_id("group", "DOMAIN ADMINS@CORP.LOCAL") in targets
    assert node_id("domain", "CORP.LOCAL") in targets


def test_attack_paths_to_domain_admins():
    ad = _ad()
    paths = attack_paths(ad, entries=["ALICE"])
    assert paths, "expected at least one path"
    # shortest: ALICE --GenericAll--> DOMAIN ADMINS
    top = paths[0]
    assert top["entry"].startswith("user:ALICE")
    assert top["target"] == node_id("group", "DOMAIN ADMINS@CORP.LOCAL")
    assert top["steps"][0]["technique"] == "T1098"
    assert top["z3"]["reachable"] is True


def test_attack_paths_two_hop_via_group():
    ad = _ad()
    paths = attack_paths(ad, entries=["BOB"])
    # BOB --MemberOf--> IT --GenericAll--> DOMAIN ADMINS (or DCSync to domain)
    assert any(p["length"] >= 2 for p in paths)
    assert all(p["z3"]["reachable"] for p in paths)


def test_betweenness_identifies_bridge():
    ad = _ad()
    bridges = betweenness_ranking(ad)
    assert bridges, "IT should be a structural bridge"
    assert any("IT" in b["label"].upper() for b in bridges)


def test_gpp_cpassword_roundtrip():
    pytest.importorskip("Crypto")
    from Crypto.Cipher import AES
    import base64

    from valen.redteam.ad.attacks import _GPP_KEY

    secret = "Sup3rSecret!"
    data = secret.encode("utf-16-le")
    data += b"\x00" * ((16 - len(data) % 16) % 16)
    ct = AES.new(_GPP_KEY, AES.MODE_CBC, b"\x00" * 16).encrypt(data)
    cpassword = base64.b64encode(ct).decode()
    assert decrypt_cpassword(cpassword) == secret


def test_gpp_from_xml():
    pytest.importorskip("Crypto")
    from Crypto.Cipher import AES
    import base64

    from valen.redteam.ad.attacks import _GPP_KEY

    secret = "GppPass1"
    data = secret.encode("utf-16-le")
    data += b"\x00" * ((16 - len(data) % 16) % 16)
    cp = base64.b64encode(AES.new(_GPP_KEY, AES.MODE_CBC, b"\x00" * 16).encrypt(data)).decode()
    xml = f'<Groups><User userName="svc-gpp" cpassword="{cp}" /></Groups>'
    out = gpp_from_xml(xml)
    assert out and out[0]["user"] == "svc-gpp" and out[0]["plaintext"] == secret


def test_ad_plan_endpoint():
    from valen.server import _ad_plan

    data = json.loads(FIXTURE.read_text())
    out = _ad_plan({"data": data, "entries": ["ALICE"]})
    assert out["kerberoastable"]
    assert out["paths"]
    assert out["stats"]["nodes"] >= 8
    # string input accepted
    out2 = _ad_plan({"data": FIXTURE.read_text()})
    assert out2["stats"]["users"] == 4
    # missing data
    assert "error" in _ad_plan({})


def test_ad_command_builders():
    from valen.redteam.ad import asrep_command, crack_command, kerberoast_command, spray_command

    assert "impacket-GetUserSPNs" in kerberoast_command("CORP.LOCAL", "10.0.0.1", "u", "p")[0]
    assert "-request" in kerberoast_command("C", "d", "u", "p")
    assert asrep_command("CORP.LOCAL", "10.0.0.1")[0] == "impacket-GetNPUsers"
    assert spray_command("C", "d", "users.txt", "Passw0rd!")[0] == "kerbrute"
    assert crack_command("h.txt")[0] == "hashcat"


def test_bloodhound_command_builder_and_parse_dir(tmp_path):
    from valen.redteam.ad import bloodhound_command, kerberoastable, parse_collection_dir

    cmd = bloodhound_command("CORP.LOCAL", "10.0.0.1", "u", "p")
    assert cmd[0] == "bloodhound-python" and "-c" in cmd

    # split the fixture into per-key files (bloodhound-python output layout)
    data = json.loads(FIXTURE.read_text())
    for key, items in data.items():
        (tmp_path / f"20240901_{key}.json").write_text(json.dumps({key: items}))

    ad = parse_collection_dir(str(tmp_path))
    assert ad.graph.node_count >= 8
    assert {u["name"] for u in kerberoastable(ad)} == {"ALICE@CORP.LOCAL", "SVC_SQL@CORP.LOCAL"}


def test_ad_collect_endpoint_dry_run():
    from valen.server import _ad_collect

    out = _ad_collect({"domain": "CORP.LOCAL", "dc": "10.0.0.1", "user": "u", "password": "p"})
    assert out.get("command") and out.get("note") == "dry-run (pass execute=true and --allow-exec)"
    assert "error" in _ad_collect({})


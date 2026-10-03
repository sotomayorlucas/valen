"""Phishing / delivery (GoPhish integration, planning only).

Builds the GoPhish API payloads (targets, email template, landing page,
campaign) and the matching ``curl`` calls. Nothing is sent: the operator runs it
against their own GoPhish instance. Also parses a GoPhish campaign report into
the usual funnel metrics (sent / opened / clicked / submitted / reported).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


def group_payload(name: str, targets: List[Dict[str, str]]) -> Dict[str, Any]:
    """GoPhish ``groups`` payload. ``targets``: [{email, first_name?, last_name?}]."""
    tgt = [{"email": t["email"], "first_name": t.get("first_name", ""),
            "last_name": t.get("last_name", ""),
            "position": t.get("position", "")} for t in targets]
    return {"name": name, "targets": tgt}


def template_payload(name, subject, html, text="", sender=None) -> Dict[str, Any]:
    p = {"name": name, "subject": subject, "html": html, "text": text}
    if sender:
        p["from_address"] = sender
    return p


def page_payload(name, html, capture_credentials=True, capture_passwords=True,
                 redirect_url: Optional[str] = None) -> Dict[str, Any]:
    p = {"name": name, "html": html,
         "capture_credentials": capture_credentials,
         "capture_passwords": capture_passwords}
    if redirect_url:
        p["redirect_url"] = redirect_url
    return p


def campaign_payload(name, template_name, page_name, group_name,
                     smtp_name: str = "Local SMTP", url: str = "http://127.0.0.1") -> Dict[str, Any]:
    return {
        "name": name,
        "template": {"name": template_name},
        "page": {"name": page_name},
        "smtp": {"name": smtp_name},
        "launch_date": "2006-01-02T15:04:05+00:00",
        "groups": [{"name": group_name}],
        "url": url,
    }


def api_command(base_url: str, api_key: str, resource: str, payload: Dict[str, Any]) -> List[str]:
    """A ready-to-run curl call against the GoPhish API (does not run)."""
    import json

    return ["curl", "-sS", "-X", "POST",
            f"{base_url.rstrip('/')}/api/{resource}/",
            "-H", f"Authorization: {api_key}",
            "-H", "Content-Type: application/json",
            "-d", json.dumps(payload)]


def campaign_plan(base_url: str, api_key: str, *,
                  name: str, senders: List[Dict[str, str]],
                  subject: str, body_html: str,
                  landing_html: str, landing_url: str,
                  smtp_name: str = "Local SMTP") -> Dict[str, Any]:
    """Full delivery plan: group + template + page + campaign + curl calls."""
    group = group_payload(f"{name}-targets", senders)
    template = template_payload(f"{name}-email", subject, body_html)
    page = page_payload(f"{name}-page", landing_html, redirect_url=landing_url)
    campaign = campaign_payload(f"{name}", template["name"], page["name"], group["name"],
                                smtp_name=smtp_name, url=landing_url)
    return {
        "group": group, "template": template, "page": page, "campaign": campaign,
        "calls": [
            api_command(base_url, api_key, "groups", group),
            api_command(base_url, api_key, "templates", template),
            api_command(base_url, api_key, "pages", page),
            api_command(base_url, api_key, "campaigns", campaign),
        ],
        "warning": "authorized engagements only; do not send to anyone outside scope",
    }


def parse_results(report: Dict[str, Any]) -> Dict[str, Any]:
    """Turn a GoPhish campaign report into funnel metrics."""
    stats = report.get("stats", {}) if isinstance(report, dict) else {}
    sent = int(stats.get("sent", 0) or 0)
    opened = int(stats.get("opened", 0) or 0)
    clicked = int(stats.get("clicked", 0) or 0)
    submitted = int(stats.get("submitted_data", 0) or 0)
    reported = int(stats.get("email_reported", 0) or 0)
    def pct(n: int) -> float:
        return round(n / sent, 4) if sent else 0.0
    return {
        "sent": sent, "opened": opened, "clicked": clicked,
        "submitted": submitted, "reported": reported,
        "open_rate": pct(opened), "click_rate": pct(clicked),
        "submit_rate": pct(submitted), "report_rate": pct(reported),
    }

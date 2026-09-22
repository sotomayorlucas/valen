"""Built-in enumeration wordlists (compact, so gobuster/ffuf run offline).

The system image has no SecLists/dirb; this ships a small, opinionated list for
API + web discovery. Pass ``--wordlist`` to override with your own file.
"""

from __future__ import annotations

from typing import List

API_WORDLIST: List[str] = [
    "admin", "api", "v1", "v2", "v3", "login", "signup", "register",
    "auth", "token", "users", "user", "account", "profile", "settings",
    "dashboard", "health", "status", "metrics", "actuator", "swagger",
    "openapi.json", "docs", "internal", "debug", "console", "upload",
    "download", "export", "import", "report", "reports", "graphql",
    "backup", "config", "env", "secret", "keys", "logs", "search",
    "orders", "order", "vehicles", "vehicle", "videos", "video", "payments",
    "checkout", "cart", "basket", "coupons", "coupon", "reset", "password",
    "verify", "invite", "webhook", "webhooks", "files", "static", "assets",
]

WEB_WORDLIST: List[str] = [
    ".git", ".git/HEAD", ".env", ".htaccess", "robots.txt", "sitemap.xml",
    "index.php", "index.html", "wp-admin", "wp-login.php", "phpinfo.php",
    "server-status", "trace", "crossdomain.xml", "favicon.ico",
]


def default_wordlist() -> List[str]:
    return sorted(set(API_WORDLIST + WEB_WORDLIST))

"""User configuration (``~/.config/valen/config.toml``).

Optional. Provides defaults for the server (host/port/token/allow_* /data_dir)
and the red-team scope, so an operator does not repeat flags every run. Uses
``tomllib`` on Python 3.11+ and a minimal fallback parser otherwise.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Dict

try:  # Python 3.11+
    import tomllib as _toml  # type: ignore
except Exception:  # pragma: no cover
    _toml = None

DEFAULTS: Dict[str, Any] = {
    "server": {
        "host": "127.0.0.1",
        "port": 8000,
        "token": "",
        "allow_host": False,
        "allow_exec": False,
        "data_dir": "",
    },
    "engagement": {
        "scope": "http://127.0.0.1:8888",
        "client": "",
    },
}


def config_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME")
    root = Path(base) if base else Path.home() / ".config"
    return root / "valen"


def config_path() -> Path:
    return config_dir() / "config.toml"


def _parse_minimal(text: str) -> Dict[str, Any]:
    """Very small TOML subset: [section] + key = value (str/int/bool)."""
    out: Dict[str, Any] = {}
    section = None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line.strip("[]").strip()
            out.setdefault(section, {})
            continue
        if "=" not in line:
            continue
        key, val = (x.strip() for x in line.split("=", 1))
        if val.lower() in ("true", "false"):
            parsed: Any = val.lower() == "true"
        elif (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
            parsed = val[1:-1]
        else:
            try:
                parsed = int(val)
            except ValueError:
                parsed = val
        (out.setdefault(section, {}) if section else out)[key] = parsed
    return out


def load_config() -> Dict[str, Any]:
    """Return the merged config (defaults <- file). Missing file → defaults."""
    cfg = {k: dict(v) for k, v in DEFAULTS.items()}
    path = config_path()
    if not path.exists():
        return cfg
    text = path.read_text(encoding="utf-8")
    if _toml is not None:
        try:
            data = _toml.loads(text)
        except Exception:
            data = _parse_minimal(text)
    else:
        data = _parse_minimal(text)
    for section, values in (data or {}).items():
        if isinstance(values, dict):
            cfg.setdefault(section, {}).update(values)
    return cfg


def get(section: str, key: str, default: Any = None) -> Any:
    return load_config().get(section, {}).get(key, default)


def write_default(path: Path | None = None, *, force: bool = False) -> Path:
    """Write a commented default config if none exists (or ``force``)."""
    p = path or config_path()
    if p.exists() and not force:
        return p
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        "# VALEN user configuration\n"
        "[server]\n"
        'host = "127.0.0.1"\n'
        "port = 8000\n"
        'token = ""            # require this bearer token on /api/*\n'
        "allow_host = false   # allow non-loopback pentest targets (SSRF guard)\n"
        "allow_exec = false   # enable /api/dynamic and /api/lab/reset\n"
        'data_dir = ""         # history store dir (default ~/.local/share/valen)\n'
        "\n"
        "[engagement]\n"
        'scope = "http://127.0.0.1:8888"\n'
        'client = ""\n',
        encoding="utf-8",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    import argparse
    import json

    ap = argparse.ArgumentParser(prog="valen config", description="VALEN configuration.")
    ap.add_argument("--init", action="store_true", help="write a default config file")
    ap.add_argument("--force", action="store_true", help="overwrite an existing file")
    args = ap.parse_args(argv or [])
    if args.init:
        p = write_default(force=args.force)
        print(f"wrote {p}")
        return 0
    print(f"# {config_path()}  ({'exists' if config_path().exists() else 'not created'})")
    print(json.dumps(load_config(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

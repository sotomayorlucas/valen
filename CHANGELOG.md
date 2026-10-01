# Changelog

All notable changes to VALEN. Format based on [Keep a Changelog](https://keepachangelog.com/);
this project aims to follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added — MVP track (packaging · hardening · product · quality)
- **Packaging**: installable `valen` package — all 9 tree-sitter grammars declared,
  the `agent` package included, `valen` console entry point, `LICENSE` (MIT),
  `valen --version`, `valen analyze` alias.
- **Numeric core**: pure-Python fallback (`valen.analysis.math_core_py`) so
  `pip install valen` works without a Rust toolchain; same JSON schema as the
  Rust `valen-core`; `run_core` prefers the binary, falls back automatically
  (`VALEN_NO_CORE=1` to force).
- **Hardening**: `ServerConfig` trust boundary — `--token` (or `VALEN_TOKEN`) on
  `/api/*`, loopback-only pentest/validate targets (`--allow-host` to opt out),
  `--allow-exec` gate for `/api/dynamic` and `/api/lab/reset`, request body
  limits, access logging, and a clear bind-error message.
- **Product**: persistent SQLite store for engagements and runs
  (`~/.local/share/valen/valen.db`) with a **History** tab in the SPA; engagement
  selector attaches runs; `valen config` + `~/.config/valen/config.toml`; product
  quickstart in the README.
- **Quality**: GitHub Actions CI (ruff + pytest + wheel build), `ruff`/`pytest-cov`
  config, coverage reporting (~72%), `CHANGELOG.md`.

### Added — Red-team kit
- Multi-format pentest reports: HTML, Markdown, JSON and **SARIF 2.1.0** (+ PDF),
  with engagement metadata, risk matrix, kill-chain, PoCs, CVE/KEV/EPSS enrichment
  and a dynamic remediation plan; `valen report`, `POST /api/report`,
  `GET /api/report/download`.
- **CVSS 3.1** (base + temporal + environmental) and **CVSS 4.0** (base) calculator
  (`valen cvss`, interactive SPA tab, `POST /api/cvss`).
- **CVE intelligence** offline snapshot (CISA KEV + FIRST EPSS + product hints) with
  `just cve-sync`; `GET /api/cve`.
- Canonical category registry (`valen/categories.py`): CWE, OWASP Top-10, CVSS
  defaults, MITRE tactic and remediation per finding category.

### Added — Multi-language SAST
- Adapters for C, C++, Rust, C#, Go, PHP, Ruby and JavaScript/TypeScript
  (plus the existing Python/Java), driven by per-language taint profiles and a
  generic C-like taint engine.
- Server parity with the CLI: `/api/dynamic` (sandboxed run + triangulation),
  `/api/pentest`, `/api/viz`, `/api/adapters`, `/api/challenges`.

### Added — Autonomous red-team
- crAPI 18/18 challenges solved autonomously (incl. 3 LLM chatbot challenges);
  `valen pentest` with `--authorize`, `--reset` (lab reset) and scope
  normalization.

### Fixed
- Web console JS now parses (raw-string template) and the data island precedes the
  main script; unhandled GET errors no longer drop the connection
  ("Failed to fetch"); report/CVE-hint rendering; scope deep links (`/login`)
  reduce to their origin.

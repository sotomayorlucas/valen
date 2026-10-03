# VALEN — Black Hat Arsenal / DEF CON Demo Kit

> **One-command demo of a neuro-symbolic, mathematics-driven red-team platform.**
> Authorized engagements only.

---

## Elevator pitch (30 seconds)

VALEN is a verifier and an autonomous red-team platform over **one typed graph**.
Its defensive side answers *where structural invariants of program graphs carry
security information* with a measured boundary (taint wins on injections; only
structure sees BOLA/IDOR and destructive cycles). Its offensive side turns the
same graph into **attack-graph mathematics**: Menger min-cut *chokepoints*,
min-cost flow *plans*, absorbing Markov-chain *hitting probabilities*,
Z3-Optimize *exploit synthesis*, and a PCFG *password prior* — and drives an
agent that solves **18/18 crAPI challenges autonomously**, including three LLM
prompt-injection challenges.

The demo shows, in order: (1) multi-language SAST, (2) the autonomous pentest,
(3) the Active Directory attack graph, (4) the generated report.

---

## What is genuinely novel (for the reviewers)

| Claim | Where to see it |
|---|---|
| A *falsifiable boundary* on structural priors (permutation test, $p=5\times10^{-5}$) | `valen oracle` / `docs/en/valen_full_paper.pdf` §3.1 |
| GLMY directed homology beats symmetrized ($0.97$ vs $0.065$) | `valen solidity` / paper §3.3 |
| Authorization as a mechanized invariant (Lean 4) + Z3 ownership witness | `valen verify` / paper §3.2 |
| Attack-graph **mathematics**: chokepoints, min-cost flow, hitting probability, synthesis, PCFG | `valen ad` / paper §6 |
| Autonomous agent solving 18/18 (incl. 3 LLM) | `valen pentest` |
| Multi-user team server with RBAC + live collaboration (SSE) | `valen serve` |

---

## Requirements

- Linux with Docker (for the crAPI lab) and Python ≥ 3.10.
- Optional: `just` (Makefile fallback provided), a LiteLLM proxy for the 3 LLM
  challenges (skippable — 15/18 solve without it).

```bash
git clone https://github.com/anomalyco/valen && cd valen
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"          # or: pip install valen
```

---

## The 5-minute demo

### 0. One command

```bash
./scripts/demo.sh
```

This builds the package, starts the team server, brings up the crAPI lab, runs
the 18-challenge pentest, and renders the report. The step-by-step version:

### 1. Team server (multi-user, RBAC)

```bash
valen serve --create-admin admin      # prints a generated password
# open http://127.0.0.1:8000  -> log in -> tabs: Analyze · Pentest · AD · Operations · History
```

*Talking points:* roles (viewer/operator/admin), SSE live activity, engagements
persisted in SQLite, per-route RBAC, `--allow-exec`/`--allow-host` gating.

### 2. Multi-language SAST

```bash
valen analyze examples/c/command_injection.c
valen analyze examples/rust/command_injection.rs --verify
valen cvss "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
```

*Talking point:* nine languages, one generic taint engine; findings carry CWE +
OWASP + CVSS 3.1/4.0 + MITRE.

### 3. Autonomous pentest (18/18)

```bash
docker compose -f deploy/docker/docker-compose.yml up -d            # crAPI lab
python examples/lab/openai_shim.py --port 8055 &                    # LLM shim
valen pentest --scope http://127.0.0.1:8888 --goal all --authorize
```

*Talking point:* the agent solves all 18 documented challenges — BOLA/BFLA, mass
assignment, SSRF, NoSQL/SQLi, JWT forgery, and three LLM prompt-injection
challenges — with an audit trail per challenge.

### 4. Active Directory attack graph

```bash
valen ad --data tests/fixtures/ad_sharphound.json --entries BOB
```

*Talking points:* ingest BloodHound/SharpHound, then show **chokepoints**
(Menger min-cut), **hitting probability** (Markov), **least-cost plans**
(Dijkstra), and **synthesized exploits** (Z3 Optimize) — each a question
reachability cannot answer.

### 5. Report

```bash
valen report --format all --client "Demo" --scope http://127.0.0.1:8888
# -> benchmarks/report.{html,md,json,sarif,pdf}
```

---

## Live-lab cheat sheet (crAPI + LLM)

```bash
# clone crAPI (compose files only; images pull from Docker Hub)
git clone --depth 1 https://github.com/OWASP/crAPI /tmp/crapi
cd /tmp/crapi/deploy/docker
docker compose -f docker-compose.yml -f /path/to/valen/examples/lab/crapi-chatbot-litellm.yml up -d

# LLM shim (for ch16-18); points at a local LiteLLM proxy
python /path/to/valen/examples/lab/openai_shim.py --port 8055 &
```

The chatbot challenges (16–18) need `LITELLM_MASTER_KEY` and the shim; without
them the remaining 15 still solve.

---

## Safety & ethics (say this out loud)

- Every offensive module requires an explicit scope and `--authorize`;
  intrusive actions need operator approval; the server binds `127.0.0.1` and
  executes nothing without `--allow-exec`.
- The demo target is the **local crAPI lab**; do not point VALEN at systems you
  do not own or are not authorized to test.

---

## Artifacts

- Paper (IEEE format, with proofs): `docs/en/valen_full_paper.pdf`
- Slides: `docs/en/valen_full_slides.pdf`
- Release: `just publish-wheel` (PyPI), `just docker-push` (registry).

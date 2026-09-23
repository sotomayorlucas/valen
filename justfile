# VALEN — comandos de desarrollo, benchmarks y red-team.
#   just <recipe>            lista -> just --list

set shell := ["bash", "-uc"]

VENV := ".venv/bin"
PY := VENV / "python"
SCOPE := env_var_or_default("SCOPE", "http://127.0.0.1:8888")

# --- análisis estático -----------------------------------------------------

analyze file:      # analizar un archivo (adapter auto)  e.g. just analyze examples/python/sqli.py
    {{PY}} -m valen.cli {{file}}

verify file:       # verificar flujos de taint con Z3 (witness)
    {{PY}} -m valen.cli {{file}} --verify

viz file out="valen.html":  # render del grafo de vulnerabilidad
    {{PY}} -m valen.cli {{file}} --viz {{out}}

agent file:        # agente autónomo sobre un archivo python
    {{PY}} -m valen.cli {{file}} --agent

# --- web UI / console ------------------------------------------------------

serve port="8000": # servidor web (UI + /console + /api/redteam)
    {{PY}} -m valen.server --port {{port}}

dashboard:         # dashboard estático + abrir en el browser
    {{PY}} -m valen.dashboard --out dashboard.html

console:           # consola red-team autocontenida (valen_console.html)
    {{PY}} -m valen.console

# --- red-team / pentest ----------------------------------------------------

pentest goal="all": # pentest autónomo (crAPI 18 challenges)
    {{PY}} -m valen.cli pentest --scope {{SCOPE}} --goal {{goal}} --authorize

autopentest:       # benchmark 18 challenges (lab en docker)
    {{PY}} benchmarks/run_autopentest.py --compose /tmp/opencode/crapi/deploy/docker --authorize

exploit:           # JWT forge -> account takeover + IDOR (crAPI vivo)
    {{PY}} benchmarks/run_exploit.py --base-url {{SCOPE}} --authorize

report:            # report.html + report.pdf (CVSS 3.1)
    {{PY}} -m valen.redteam.report

# --- benchmarks ------------------------------------------------------------

bench-owasp:       # OWASP Benchmark 1.2 (resultado negativo: taint MRR 0.894)
    {{PY}} benchmarks/run_owasp.py

bench-bola:        # BOLA/IDOR corpus (F1 0.837; taint = 0)
    {{PY}} benchmarks/run_bola.py

bench-crapi:       # BOLA real crAPI (recall 1.0 / precisión 0.90)
    {{PY}} benchmarks/run_crapi_bola.py

bench-state:       # homología dirigida GLMY en grafos de estado
    {{PY}} benchmarks/run_state_glmy.py

bench-solidity:    # reentrancy SmartBugs via GLMY
    {{PY}} benchmarks/run_solidity_glmy.py --smartbugs ~/.cache/valen/smartbugs-curated

bench-spec:        # spec-mining (0.5 recall, 0 alucinación)
    {{PY}} benchmarks/run_spec_mining.py

bench-ablation:    # ablación del LLM
    {{PY}} benchmarks/run_llm_ablation.py

# --- lab (chatbot LLM ch16-18) ---------------------------------------------

lab-shim:          # shim openai-compatible (embeddings cero + chat -> LiteLLM)
    {{PY}} examples/lab/openai_shim.py --port 8055

lab-chatbot:       # recrear crapi-chatbot con el override LiteLLM
    cd /tmp/opencode/crapi/deploy/docker && LITELLM_MASTER_KEY="$$(grep LITELLM_MASTER_KEY ~/litellm/.env | cut -d= -f2)" docker compose -f docker-compose.yml -f {{justfile_directory()}}/examples/lab/crapi-chatbot-litellm.yml up -d crapi-chatbot

# --- tests / core ----------------------------------------------------------

test:              # suite completa
    {{PY}} -m pytest -q

test-agent:        # solo el harness de pentest
    {{PY}} -m pytest tests/test_autopentest.py -q

build-core:        # compilar el núcleo Rust (centralidad espectral/geométrica)
    cargo build --release --manifest-path core/Cargo.toml

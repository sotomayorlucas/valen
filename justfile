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

dynamic file *args:  # ejecuta el target en sandbox y triangula traza vs estático
    {{PY}} -m valen.cli {{file}} --dynamic --argv {{args}}

agent file:        # agente autónomo sobre un archivo python
    {{PY}} -m valen.cli {{file}} --agent

# --- web UI / console ------------------------------------------------------

serve port="8000": # servidor web (team server + UI + /console + API)
    {{PY}} -m valen.server --port {{port}}

serve-admin port="8000" user="admin": # arranca el team server creando el admin inicial
    {{PY}} -m valen.server --port {{port}} --create-admin {{user}}

dashboard:         # dashboard estático + abrir en el browser
    {{PY}} -m valen.dashboard --out dashboard.html

console:           # consola red-team autocontenida (valen_console.html)
    {{PY}} -m valen.console

# --- red-team / pentest ----------------------------------------------------

pentest goal="all": # pentest autónomo (crAPI 18 challenges)
    {{PY}} -m valen.cli pentest --scope {{SCOPE}} --goal {{goal}} --authorize

lab-reset:         # reinicia el lab crAPI (docker compose down -v + up -d, con override LLM)
    {{PY}} -m valen.cli pentest --scope {{SCOPE}} --reset --goal ch14_unauthenticated

autopentest:       # benchmark 18 challenges (lab en docker)
    {{PY}} benchmarks/run_autopentest.py --compose /tmp/opencode/crapi/deploy/docker --authorize

exploit:           # JWT forge -> account takeover + IDOR (crAPI vivo)
    {{PY}} benchmarks/run_exploit.py --base-url {{SCOPE}} --authorize

report format="all": # reporte pentest (all = html+md+json+sarif)  e.g. just report md
    {{PY}} -m valen.redteam.report --format {{format}}

report-info client="" scope="" author="": # reporte con metadata de engagement
    {{PY}} -m valen.redteam.report --format all --client "{{client}}" --scope "{{scope}}" --author "{{author}}"

cvss vector="": # score de un vector CVSS (3.1/4.0) o --category NAME
    {{PY}} -m valen.cli cvss {{vector}}

cve-sync:       # refresca el snapshot KEV/EPSS/NVD (requiere red)
    {{PY}} benchmarks/cve_intel/build_snapshot.py

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

lint:              # ruff (correctness) sobre el repo
    {{PY}} -m ruff check .

cov:               # tests con cobertura
    {{PY}} -m pytest --cov=valen --cov=agent --cov-report=term-missing

config:            # crea/muestra ~/.config/valen/config.toml
    {{PY}} -m valen.cli config

# --- docker ----------------------------------------------------------------

docker-build:      # construye la imagen del servidor (Rust core + runtime)
    docker build -f Dockerfile.server -t valen .

docker-up:         # levanta el servidor en http://127.0.0.1:8000
    docker compose up -d --build

docker-down:       # detiene y borra el contenedor
    docker compose down

# --- release ---------------------------------------------------------------

publish-wheel:     # sdist+wheel y upload a PyPI (TWINE_USERNAME/TWINE_PASSWORD)
    {{PY}} -m build
    {{PY}} -m twine upload dist/*

docker-push tag="latest": # sube la imagen a un registry (set REGISTRY)
    docker tag valen:latest {{REGISTRY}}/valen:{{tag}}
    docker push {{REGISTRY}}/valen:{{tag}}

test-agent:        # solo el harness de pentest
    {{PY}} -m pytest tests/test_autopentest.py -q

build-core:        # compilar el núcleo Rust (centralidad espectral/geométrica)
    cargo build --release --manifest-path core/Cargo.toml

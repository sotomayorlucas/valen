# MANIFOLD

Un motor matemático para **mapear vulnerabilidades** de forma intuitiva y
**asistir a un agente LLM autónomo** a encontrarlas y verificarlas.

A mathematical engine for **mapping vulnerabilities** intuitively and **assisting
an autonomous LLM agent** to find and verify them.

## Idea central / Core idea

Un artefacto (código fuente, binario, API web, agente LLM) se transforma en un
**objeto matemático unificado**: un grafo tipado (IR) enriquecido con estructura
**algebraica, espectral, topológica y geométrica**. Sobre él se computa un campo
escalar de vulnerabilidad `V(x)`; un agente LLM navega ese "manifold", formula
hipótesis y las **verifica formalmente** (Z3 / ejecución simbólica / taint).

A target (source code, binary, web API, LLM agent) becomes a unified mathematical
object: a typed graph (IR) enriched with **algebraic, spectral, topological and
geometric** structure. A vulnerability scalar field `V(x)` is computed over it;
an LLM agent navigates that "manifold", hypothesizes, and **formally verifies**
(Z3 / symbolic execution / taint).

## Estado / Status

- [x] **F0** — Whitepaper (es/en) y arquitectura
- [x] **F1** — IR + ingesta SAST (Python, tree-sitter) + taint intraprocedural
- [x] **F2** — Núcleo espectral (Fiedler) + geométrico (Ricci) (Rust)
- [x] **F3** — Topología (homología persistente H0/H1, Mapper) (Rust)
- [x] **F4** — Verificación formal (retículo de taint + sanitizers, verificador simbólico Z3, auth gates/L4)
- [x] **F5** — Agente LLM autónomo (LiteLLM, fallback offline)
- [x] **F6** — Visualización (HTML autocontenido) + demo end-to-end
- [ ] **F7** — Adaptadores binario / web / LLM

## Estructura / Layout

```
manifold/          # núcleo Python: IR, ingesta, análisis
  ir.py            #   grafo tipado (Node/Edge/Graph, serializable)
  ingest/          #   adaptadores (tree-sitter, perfiles source/sink)
  analysis/        #   taint engine + findings
core/              # núcleo numérico Rust (espectral, topología, álgebra)
agent/             # agente LLM autónomo (LiteLLM)  [F5]
viz/               # visualización del manifold     [F6]
examples/python/   # programas vulnerables de juguete
docs/es, docs/en/  # whitepaper en español e inglés
```

## Uso rápido / Quick start

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"

# Analiza un archivo y emite hallazgos + grafo IR como JSON
.venv/bin/python -m manifold.cli examples/python/sqli.py
```

Para el núcleo Rust:

```bash
cd core && cargo test
```

## Documentación / Docs

- Whitepaper (español): [`docs/es/whitepaper.md`](docs/es/whitepaper.md) · [PDF](docs/es/whitepaper.pdf)
- Whitepaper (English): [`docs/en/whitepaper.md`](docs/en/whitepaper.md) · [PDF](docs/en/whitepaper.pdf)
- Fuente LaTeX: `docs/es/whitepaper.tex`, `docs/en/whitepaper.tex` (compilar con `tectonic`)

## Núcleo numérico (F2)

```bash
cd core && cargo test && cargo build --release
# El binario lee el IR (JSON) por stdin y emite señales espectrales/geométricas.
```
El puente Python está en `manifold/analysis/math_core.py` (`run_core`, `fiedler_ranking`).

Núcleo incluye además: **Laplaciano dirigido de Chung** (`directed_laplacian`) y
**Ollivier–Ricci aproximado vía Sinkhorn** (`ollivier_ricci_sinkhorn`).

## Agente autónomo (F5)

```bash
.venv/bin/python -m manifold.cli examples/python/sqli.py --agent
```

Funciona **offline** (hipótesis heurísticas deterministas) por defecto. Para usar
un LLM vía LiteLLM, define las variables de entorno y se activa automáticamente:

```bash
export MANIFOLD_LLM_MODEL="gpt-4o-mini"      # o claude-3-5-sonnet-*, ollama/llama3, ...
export MANIFOLD_LLM_API_KEY="..."             # opcional para endpoints locales
export MANIFOLD_LLM_BASE_URL="http://localhost:11434/v1"  # opcional (Ollama/vLLM)
```

## Visualización y demo (F6)

```bash
# Renderiza el manifold (grafo IR + señales + findings) a un HTML autocontenido
.venv/bin/python -m manifold.cli examples/python/sqli.py --viz /tmp/sqli.html

# Demo end-to-end: analiza todos los ejemplos y genera HTML + summary.json
.venv/bin/python scripts/demo.py   # escribe en viz/out/
```

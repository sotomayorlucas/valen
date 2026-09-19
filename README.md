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
- [ ] **F2** — Núcleo espectral + geométrico (Rust)
- [ ] **F3** — Topología (homología persistente, Mapper)
- [ ] **F4** — Verificación formal (lattice de taint, Z3, angr)
- [ ] **F5** — Agente LLM autónomo (LiteLLM)
- [ ] **F6** — Visualización + demo end-to-end
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

- Whitepaper (español): [`docs/es/whitepaper.md`](docs/es/whitepaper.md)
- Whitepaper (English): [`docs/en/whitepaper.md`](docs/en/whitepaper.md)

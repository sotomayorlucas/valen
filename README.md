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
- [x] **F7** — Adaptadores multi-dominio (binario / OpenAPI / agente LLM)

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
- Slides de conferencia: [es](docs/es/slides.pdf) · [en](docs/en/slides.pdf) (Beamer)
- Fuente LaTeX: `docs/{es,en}/whitepaper.tex`, `docs/{es,en}/slides.tex` (compilar con `tectonic`)

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

## Multi-dominio (F7)

```bash
.venv/bin/python -m manifold.cli examples/binary/vuln.asm      # binario (objdump)
.venv/bin/python -m manifold.cli examples/web/api.json         # OpenAPI
.venv/bin/python -m manifold.cli examples/llm_agent/agent.json # agente LLM
.venv/bin/python -m manifold.cli Foo.java --adapter java        # Java (SAST)

# Binario con angr (CFGFast real + taint interprocedural); requiere: pip install ".[angr]"
gcc -o /tmp/vuln /tmp/vuln.c
.venv/bin/python -m manifold.cli /tmp/vuln --adapter angr-binary
```
Los adaptadores producen el mismo IR tipado, así que el núcleo espectral /
topológico / geométrico y el verificador se aplican sin cambios.

## Reproducibilidad (artefacto)

```bash
./scripts/reproduce.sh                 # build + tests + demo + figuras + PDFs
./scripts/reproduce.sh --fetch-owasp   # además descarga y corre OWASP Benchmark
```

- **Docker**: `docker build -t manifold . && docker run --rm manifold`
- Versiones fijadas en `requirements.txt` y `core/Cargo.lock`; semillas fijas en el
  oráculo (20 semillas) y en el calibrador; TODAS las figuras/tablas del paper se
  regeneran con `scripts/make_figures.py` desde `benchmarks/oracle_results.json`.

### Experimento principal: oráculo de priorización

```bash
.venv/bin/python benchmarks/run_oracle.py --testcode <dir> --csv <csv>
```

Ranking de sinks candidatos (902 casos vulnerables) y AUC por señal. Resultado
central: **el taint domina (MRR 0.894, AUC 0.895); las señales espectral (AUC
0.496), topológica (0.500) y geométrica (0.376) no discriminan** — un resultado
negativo honesto que el whitepaper reporta (L1/L2/L5 no soportadas en OWASP).

## Benchmark y calibración

```bash
.venv/bin/python benchmarks/run.py
# Corpus externo (manifest JSON o directorio vulnerable|safe, bad|good):
.venv/bin/python benchmarks/run_external.py benchmarks/fixtures --adapter python
```
Evalúa precisión/recall/F1 (taint crudo vs verificado Z3) y **calibra los pesos
αᵢ** del campo V(x) con regresión logística pura-Python (validación leave-one-out).

### OWASP Benchmark 1.2 (corpus real, 2740 casos Java)

```bash
pip install tree-sitter-java
# descarga: https://github.com/OWASP-Benchmark/BenchmarkJava (testcode/ + expectedresults-1.2.csv)
.venv/bin/python benchmarks/run_owasp.py \
    --testcode .../src/main/java/org/owasp/benchmark/testcode \
    --csv .../expectedresults-1.2.csv
```

Resultados del adaptador Java (corpus completo):

| scope | precisión | recall | F1 |
|---|---|---|---|
| categorías de taint (7, 1698 casos) | 0.549 | 0.834 | 0.662 |
| todas las categorías (11, 2740 casos) | 0.572 | 0.842 | 0.681 |

**Verificación Z3 para Java** (`manifold/analysis/java_verifier.py`): con
`--verify` el verificador simbólico (branches con merge, strings, sanitizadores
como contratos, witness concreto) reproduce exactamente la precisión del
adaptador (P=0.549, R=0.834, J=+0.057) — **aporta prueba, no precisión**: los
errores residuales son casos adversariales del benchmark, no caminos espurios.

Mejoras sobre el baseline naive inicial (0.515/0.426/0.466 en taint), todas
genéricas: **taint con conciencia de ramas** (join de entornos), **taint del
receptor/estado** (objetos y colecciones) y **restricción de sinks XSS al writer
de respuesta** (`System.out.println` no es XSS). Ablación en el whitepaper.

El whitepaper incluye además una tabla comparativa con las métricas oficiales de
OWASP Benchmark (índice de Youden $J=\mathrm{TPR}-\mathrm{FPR}$) frente a
SonarQube y CodeQL, notas metodológicas (hardware, versiones, timeout Z3 de 5 s)
y el objetivo neuro-simbólico proyectado ($V(x)+$Z3). El adaptador medido alcanza
$J=+0.168$ (all-categories).

Categorías taint: sqli/cmdi/pathtraver/xss/ldapi/xpathi/trustbound. Las categorías
por-patrón `crypto`/`hash` se configuran vía `.properties`; `weakrand`/`securecookie`
son detectables por fuente. **SARD**: el cargador (`load_directory`, convención
`good`/`bad`) está listo; el corpus completo (Juliet) es una descarga de gran
tamaño y mayormente C/C++/Java.

# MANIFOLD

**¿Aportan información las invariantes geométricas/topológicas de los grafos de
programa por encima del análisis semántico clásico (taint)?** MANIFOLD es el
instrumento para responderlo de forma **falsable**: convierte un artefacto en un
grafo tipado (IR), computa un campo *pre-verificación* `V_prior(x)` con señales
baratas, y deja que un ciclo neuro-simbólico (LLM + Z3) actúe sobre las regiones
priorizadas.

**Do geometric/topological invariants of program graphs add information over
classic semantic analysis (taint)?** MANIFOLD is the instrument to answer this
**falsifiably**: it turns an artifact into a typed graph (IR), computes a
*pre-verification* field `V_prior(x)` from cheap signals, and lets a
neuro-symbolic loop (LLM + Z3) act on the prioritized regions.

> **Resultado principal (honesto):** en OWASP Benchmark 1.2, el taint crudo
> ordena mejor el sink vulnerable (MRR 0.894, AUC 0.895) y supera al campo
> fusionado con **p=0.000**; las señales espectral (AUC 0.496) y topológica
> (0.500) están en el azar y la curvatura (0.376) por debajo. El campo
> estructural solo ayuda en el extremo superior de una cola global (P@10 0.8 vs
> 0.6). Las hipótesis H1/H2/H5 quedan **no soportadas**.

## Idea central / Core idea

Un artefacto (código fuente, binario, API web, agente LLM) se transforma en un
grafo tipado (IR) enriquecido con estructura **algebraica, espectral, topológica
y geométrica**. Sobre él se computan dos campos: `V_prior` (señales baratas,
pre-verificación, sin la señal formal → sin circularidad) y `V_post` (incorpora
Z3). Un agente LLM navega ese espacio, formula hipótesis y las **verifica
formalmente** (Z3 / ejecución simbólica / taint), produciendo *witnesses*
verificables por máquina bajo la semántica modelada.

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

## Interfaz web (sin CLI)

```bash
.venv/bin/python -m manifold.server --port 8000
# abrir http://127.0.0.1:8000
```

SPA autocontenida (servidor `http.server` de la stdlib, sin dependencias) con 3
pestañas:

- **Analyze** — pegá código, elegí un ejemplo del repo o fijá un `path`; elegí el
  adaptador (auto/python/java/binary/angr-binary/web/llm-agent) y corré el
  análisis. Muestra hallazgos, **ranking de V(x)**, manifold force-directed,
  verificaciones Z3 (con witness) y el reporte del agente. `POST /api/analyze`.
- **Experiments** — oráculo de priorización (curva de costo + AUC), OWASP
  Benchmark, ablación y escalabilidad. `GET /api/results`.
- **Methodology** — pipeline, capas→señal→evidencia (con su AUC), protocolo de
  evaluación y leyes de mapeo con estado medido.

La API es estática (tree-sitter + Z3 + el núcleo Rust); **nunca ejecuta tu código**.

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
**Ollivier–Ricci aproximado vía Sinkhorn** (`ollivier_ricci_sinkhorn`). La capa
topológica tiene dos invariantes: homología **no dirigida** (`homology`) y
**homología de caminos dirigida GLMY** (`path_homology`, H0/H1 + generadores) — sobre
`reentrancy.py` dan β1=1 y β1=0 respectivamente (la dirección cambia el veredicto).

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

# Dashboard: todos los experimentos + metodología + explorador del manifold
.venv/bin/python -m manifold.dashboard --out dashboard.html
```

El dashboard (autocontenido) muestra las **metodologías** (pipeline, capas→señal→
evidencia con su AUC, leyes de mapeo con estado, protocolo de evaluación), la tabla
del oráculo de priorización, OWASP Benchmark, la ablación, la escalabilidad, un
explorador del manifold de los ejemplos y recetas de uso con los datos de los
experimentos.

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
- **Núcleo formal mecanizado** (Lean 4, sin Mathlib): `bash scripts/check_formal.sh`
  verifica `formal/Manifold.lean` (`prop1_soundness`, `no_auth_bounded`).
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

**Oráculo (priorización)**: `taint` MRR 0.894 vs campo `V_prior` 0.872; test
pareado **+0.0225, p=0.000**. **Cola global** (todos seguros+vulnerables): AP
taint 0.489, `V_prior` 0.434, DFS 0.286, random 0.216; P@10 `V_prior` 0.8 vs
taint 0.6 (el campo ayuda solo en el extremo superior).

**Verificación Z3 para Java** (`manifold/analysis/java_verifier.py`): con
`--verify` el verificador simbólico (branches con merge, strings, sanitizadores
como contratos, witness concreto) reproduce exactamente la precisión del
adaptador (P=0.549, R=0.834, J=+0.057) — **aporta prueba, no precisión**: los
errores residuales son casos adversariales del benchmark, no caminos espurios.

**Juliet Java** (`benchmarks/run_juliet.py`, `manifold/corpus.py::load_juliet`):
264 casos de 5 CWEs; el adaptador ajustado en OWASP transfiere mal
(P=0.333, R=0.562) porque Juliet separa fuente/sumidero entre clases
(`_a`/`_base`/`_bad`) y exige taint **interprocedural** — evidencia para el
siguiente paso de sistemas y amenaza a la validez externa.

**Taint interprocedural** (`manifold/ingest/java_interproc.py`, adaptador
`java-interproc`): punto fijo insensible al contexto (parámetro manchado si un
call site le pasa taint; llamada manchada si el callee devuelve taint). En
**Juliet**: R 0.562→0.750, F1 0.419→0.490 (CWE78/CWE90 de 0.000→0.750). En
**OWASP** empeora levemente (F1 de taint 0.662→0.637) por insensibilidad al
contexto → necesario pero no suficiente; el siguiente paso son summaries
sensibles al contexto.

**Escalabilidad** (`core/src/bin/scale.rs`, `benchmarks/scale_results.csv`):
Forman–Ricci y Mapper casi lineales ($10^3\to10^5$ aristas en $<0.2$ s);
homología superlineal (123 s @ $10^5$); Sinkhorn/Ollivier cuadráticos;
Laplacianos densos cúbicos (tope práctico ~$1200$ nodos sin solver disperso).

**CVEs reales** (`benchmarks/run_cves.py`): 22 CVEs de OSV/GitHub Advisories, 46
archivos fuente; **3 resueltos** (ambos `eval` injection: `senaite.core`
CVE-2026-54569, `xinference` CVE-2026-61539). Los SQLi internos del ORM de Django
son flujos indirectos → 0 detecciones (misma frontera que Juliet: falta análisis
interprocedural). El arnés reconstruye el "before" aplicando el diff inverso (sin
cuota de API).

**Ablación del LLM** (`benchmarks/run_llm.py`, LiteLLM local en `:4000`):
```bash
set -a; . ~/litellm/.env; set +a
MANIFOLD_LLM_MODEL=openai/flash MANIFOLD_LLM_BASE_URL=http://127.0.0.1:4000 \
MANIFOLD_LLM_API_KEY=$LITELLM_MASTER_KEY .venv/bin/python benchmarks/run_llm.py --runs 2
```
Resultado: los **confirmados son idénticos** offline vs LLM (el verificador Z3 es
el árbitro); el LLM cambia la interpretación (CWE/título más ricos, p.ej. CWE-674
para el ciclo). El conjunto confirmado es estable entre corridas.

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

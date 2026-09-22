# VALEN

> **VALEN** = *Verification And Active Logic Engine, Neuro-symbolic* (Verificación
> y Lógica Activa, Neuro-simbólica).

**VALEN es un *verificador neuro-simbólico de invariantes estructurales*:** un
agente autónomo que extrae especificaciones de seguridad (invariantes de
autorización, ciclos de máquinas de estado, precondiciones de taint) con un LLM y
las descarga con métodos formales (Z3, homología dirigida GLMY, un núcleo
mecanizado en Lean 4), emitiendo solo *witnesses verificables por máquina bajo la
semántica modelada*. Este trabajo plantea una única pregunta integral — *¿dónde
aportan las invariantes estructurales de los grafos de programa información de
seguridad, y dónde no?* — y la responde con una frontera de dos caras: en las
fallas de inyección lineal los priors estructurales no aportan sobre el taint, y
en las fallas de confianza y lógica (**BOLA/IDOR, autorización ausente, ciclos de
estado**) son la única señal, porque ahí el dato es legítimo y el taint es ciego.

**VALEN is a *neuro-symbolic structural-invariant verifier*:** an autonomous
agent that mines security specifications (authorization invariants, state-machine
cycles, taint preconditions) from code with an LLM and discharges them with
formal methods (Z3, GLMY directed homology, a mechanized Lean 4 core), emitting
only *machine-checkable witnesses under the modeled semantics*. This work asks one
integral question — *where do structural invariants of program graphs carry
security information, and where do they not?* — and answers it with a two-sided
boundary: on linear injection flaws structural priors add nothing over taint, and
on trust & logic flaws (**BOLA/IDOR, missing authorization, state cycles**) they
are the only signal, because there the data is legitimate and taint is blind.

> **Un estudio integral: ¿dónde aportan las invariantes estructurales información
> de seguridad, y dónde no?** La respuesta es una frontera con dos caras.
> **Lado negativo:** en inyecciones lineales (OWASP Benchmark 1.2) el taint crudo
> ordena mejor el sink vulnerable (MRR 0.894, AUC 0.895, supera al campo fusionado
> con **$p=5\times10^{-5}$**); espectral (0.496) y topológica (0.500) están en el
> azar y la curvatura (0.376) por debajo. H1/H2/H3/H5 quedan **no soportadas** —
> porque un servlet plano y casi acíclico no tiene esa estructura, y el taint ya
> es casi óptimo allí. **Lado positivo:** en las fallas de confianza y lógica el
> dato es legítimo y el taint es ciego, así que la estructura es la única señal:
> el detector estructural de **autorización ausente / BOLA** alcanza **recall 1.0
> / precisión 0.72 / F1 0.837** en un corpus curado de 39 casos
> (`examples/python/bola/`, `examples/python/bola_corpus/`,
> `benchmarks/run_bola.py`) — el taint puntúa **0** en esos casos; sus 7 falsos
> positivos son el límite de sobre-aproximación documentado. La homología dirigida
> **GLMY** (evaluada en 12 grafos de estado, `benchmarks/run_state_glmy.py`)
> domina al simetrizado: recall 1.0 / precisión 0.75 vs 0.5/0.5. **Datos reales**
> (OWASP crAPI, `examples/api/`, `benchmarks/run_crapi_bola.py`): la señal de
> referencia-a-objeto recupera los 9 BOLA/BFLA documentados con recall 1.0 /
> precisión 0.90, donde el chequeo de auth-ausente puntúa 0 (todo BOLA **está**
> autenticado). El **witness de
> ownership en Z3** (`bola_verifier.py`) separa autorización de objeto de mera
> autenticación (`login_required` NO bloquea BOLA). Además: detección de
> **auth-gap OpenAPI** (CWE-862), **puentes de privilegio IAM** vía Fiedler/Forman-Ricci
> (`examples/iam/demo.json`), y **spec-mining** (0.5 recall, 0 alucinación, n=8).
> La ablación del LLM sobre 38 archivos (29 hallazgos
> confirmados) da invariancia de detección/ranking en 37/38 (acuerdo 0.974; la
> única excepción es una hipótesis no determinista de `compile`), con 28% de
> cambio en CWE (interpretación) y títulos más concisos.
> Ver *Structural invariants across domains* en el whitepaper.

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
valen/          # núcleo Python: IR, ingesta, análisis
  ir.py            #   grafo tipado (Node/Edge/Graph, serializable)
  ingest/          #   adaptadores (tree-sitter, perfiles source/sink)
  analysis/        #   taint engine + findings
core/              # núcleo numérico Rust (espectral, topología, álgebra)
agent/             # agente LLM autónomo (LiteLLM)  [F5]
viz/               # visualización del valen     [F6]
examples/python/   # programas vulnerables de juguete
docs/es, docs/en/  # whitepaper en español e inglés
```

## Interfaz web (sin CLI)

```bash
.venv/bin/python -m valen.server --port 8000
# abrir http://127.0.0.1:8000
```

SPA autocontenida (servidor `http.server` de la stdlib, sin dependencias) con 3
pestañas:

- **Analyze** — pegá código, elegí un ejemplo del repo o fijá un `path`; elegí el
  adaptador (auto/python/java/binary/angr-binary/web/llm-agent) y corré el
  análisis. Muestra hallazgos, **ranking de V(x)**, valen force-directed,
  verificaciones Z3 (con witness) y el reporte del agente. `POST /api/analyze`.
- **Experiments** — oráculo de priorización (curva de costo + AUC), OWASP
  Benchmark, ablación y escalabilidad. `GET /api/results`.
- **Methodology** — pipeline, capas→señal→evidencia (con su AUC), protocolo de
  evaluación y leyes de mapeo con estado medido.

La API es estática (tree-sitter + Z3 + el núcleo Rust); **nunca ejecuta tu código**.

## Consola red-team + bootstrap de herramientas

```bash
.venv/bin/python -m valen.console            # escribe valen_console.html (consola autocontenida)
.venv/bin/python -m valen.console --bootstrap  # imprime el apt install de las tools faltantes
.venv/bin/python -m valen.server --port 8000
# abrir http://127.0.0.1:8000/console   y   GET /api/redteam
```

La consola integra el flujo red-team: **estado del toolkit** (nmap/masscan/...),
**recon** de Kali (`-oX`/`-oJ` → IR, hipótesis CVE, perfil de sigilo `-T0..-T2`),
**plan de ataque kill-chain** (MITRE + cadenas IAM con confirmación Z3), **PoCs
BOLA/IDOR** (witness → `requests`) y resultados medidos (crAPI, neuro-simbólico).
`POST /api/recon` construye los comandos sigilosos (no los ejecuta); `POST
/api/validate` replayea un PoC contra un target vivo. Solo para engagements
autorizados.

## Enumeración, explotación activa y reporte

```bash
# Lab crAPI (imágenes prebuilt, no hace falta JDK/Maven/Node):
#   git clone https://github.com/OWASP/crAPI /tmp/opencode/crapi
#   cd /tmp/opencode/crapi/deploy/docker && docker compose up -d   # web en http://127.0.0.1:8888

.venv/bin/python benchmarks/run_enum.py                    # gobuster/ffuf/amass -> IR + shadow endpoints
.venv/bin/python benchmarks/run_exploit.py --base-url http://127.0.0.1:8888 --authorize  # JWT forge -> takeover + IDOR
.venv/bin/python -m valen.redteam.report                    # report.html + report.pdf (CVSS 3.1, Chrome headless)
```

- **Enumeración** (`valen/redteam/enum.py`): parsea gobuster/ffuf/amass/theHarvester,
  detecta *shadow endpoints* (descubiertos pero ausentes del OpenAPI) y alimenta el IR.
- **Explotación activa** (`valen/redteam/{auth,jwt,idor}.py`): signup/login crAPI,
  forja de JWT con **stdlib** (`kid` path-traversal, `alg=none`, firma inválida) →
  **account takeover validado**, y enumeración activa de ids → **BOLA/IDOR confirmado**
  con evidencia request/response. Dry-run por defecto.
- **Reporte** (`valen/redteam/report.py`): resumen ejecutivo, hallazgos con **CVSS 3.1**,
  reproducción, evidencia y remediación, en HTML + PDF.

## Agente autónomo de pentest + smart contracts

```bash
# Agente autónomo: plan -> actuar -> observar -> re-planear, sobre los 18 challenges de crAPI
.venv/bin/python -m valen.cli pentest --scope http://127.0.0.1:8888 --goal all --authorize
.venv/bin/python benchmarks/run_autopentest.py --compose /tmp/opencode/crapi/deploy/docker --authorize

# Smart contracts: reentrancy via homología dirigida (GLMY) sobre SmartBugs-curated
.venv/bin/python benchmarks/run_solidity_glmy.py --smartbugs /path/to/smartbugs-curated
```

- **Agente autónomo** (`valen/redteam/{operators,executor,challenges}.py`): operadores por
  tiers (passive/bounded/intrusive), planner+executor con presupuesto y audit log, fallback
  LLM (LiteLLM). Resuelve **12/18** challenges de crAPI de forma autónoma (BOLA/IDOR,
  mass-assignment, BFLA, JWT forge, exposición, NoSQLi, acceso no autenticado); el resto
  (SSRF, SQLi, brute OTP, chatbot LLM) son recetas pendientes honestamente reportadas.
  Chatbot (16-18) se cablea a LiteLLM con `examples/lab/crapi-chatbot-litellm.yml`.
- **Smart contracts** (`valen/ingest/solidity.py`, `valen/analysis/reentrancy.py`): parsea
  `.sol` (tree-sitter-solidity) y detecta reentrancy por orden checks-effects-interactions +
  ciclo dirigido GLMY. Sobre SmartBugs-curated (31 pos / 112 neg): **orden P=0.72/R=0.90/F1=0.80**,
  GLMY R=0.97 (el 2-ciclo de reentrancy), y **simetrizada R=0.065** (colapsa el ciclo).

## Uso rápido / Quick start

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"

# Analiza un archivo y emite hallazgos + grafo IR como JSON
.venv/bin/python -m valen.cli examples/python/sqli.py
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
El puente Python está en `valen/analysis/math_core.py` (`run_core`, `fiedler_ranking`).

Núcleo incluye además: **Laplaciano dirigido de Chung** (`directed_laplacian`) y
**Ollivier–Ricci aproximado vía Sinkhorn** (`ollivier_ricci_sinkhorn`). La capa
topológica tiene dos invariantes: homología **no dirigida** (`homology`) y
**homología de caminos dirigida GLMY** (`path_homology`, H0/H1 + generadores) — sobre
`reentrancy.py` dan β1=1 y β1=0 respectivamente (la dirección cambia el veredicto).

## Agente autónomo (F5)

```bash
.venv/bin/python -m valen.cli examples/python/sqli.py --agent
```

Funciona **offline** (hipótesis heurísticas deterministas) por defecto. Para usar
un LLM vía LiteLLM, define las variables de entorno y se activa automáticamente:

```bash
export VALEN_LLM_MODEL="gpt-4o-mini"      # o claude-3-5-sonnet-*, ollama/llama3, ...
export VALEN_LLM_API_KEY="..."             # opcional para endpoints locales
export VALEN_LLM_BASE_URL="http://localhost:11434/v1"  # opcional (Ollama/vLLM)
```

## Visualización y demo (F6)

```bash
# Renderiza el valen (grafo IR + señales + findings) a un HTML autocontenido
.venv/bin/python -m valen.cli examples/python/sqli.py --viz /tmp/sqli.html

# Demo end-to-end: analiza todos los ejemplos y genera HTML + summary.json
.venv/bin/python scripts/demo.py   # escribe en viz/out/

# Dashboard: todos los experimentos + metodología + explorador del valen
.venv/bin/python -m valen.dashboard --out dashboard.html
```

El dashboard (autocontenido) muestra las **metodologías** (pipeline, capas→señal→
evidencia con su AUC, leyes de mapeo con estado, protocolo de evaluación), la tabla
del oráculo de priorización, OWASP Benchmark, la ablación, la escalabilidad, un
explorador del valen de los ejemplos y recetas de uso con los datos de los
experimentos.

## Multi-dominio (F7)

```bash
.venv/bin/python -m valen.cli examples/binary/vuln.asm      # binario (objdump)
.venv/bin/python -m valen.cli examples/web/api.json         # OpenAPI
.venv/bin/python -m valen.cli examples/llm_agent/agent.json # agente LLM
.venv/bin/python -m valen.cli Foo.java --adapter java        # Java (SAST)

# Binario con angr (CFGFast real + taint interprocedural); requiere: pip install ".[angr]"
gcc -o /tmp/vuln /tmp/vuln.c
.venv/bin/python -m valen.cli /tmp/vuln --adapter angr-binary
```
Los adaptadores producen el mismo IR tipado, así que el núcleo espectral /
topológico / geométrico y el verificador se aplican sin cambios.

## Reproducibilidad (artefacto)

```bash
./scripts/reproduce.sh                 # build + tests + demo + figuras + PDFs
./scripts/reproduce.sh --fetch-owasp   # además descarga y corre OWASP Benchmark
```

- **Docker**: `docker build -t valen . && docker run --rm valen`
- **Núcleo formal mecanizado** (Lean 4, sin Mathlib): `bash scripts/check_formal.sh`
  verifica `formal/Valen.lean` (`prop1_soundness`, `no_auth_bounded`).
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
pareado **+0.0225, $p=5\times10^{-5}$** (add-one, 20000 permutaciones). **Cola
global** (todos seguros+vulnerables): AP taint 0.489, `V_prior` 0.434, DFS 0.286,
random 0.216; P@10 `V_prior` 0.8 vs taint 0.6 (el campo ayuda solo en el extremo
superior; la diferencia es pequeña en absoluto y no se reporta como significativa).

**Verificación Z3 para Java** (`valen/analysis/java_verifier.py`): con
`--verify` el verificador simbólico (branches con merge, strings, sanitizadores
como contratos, witness concreto) reproduce exactamente la precisión del
adaptador (P=0.549, R=0.834, J=+0.057) — **aporta prueba, no precisión**: los
errores residuales son casos adversariales del benchmark, no caminos espurios.

**Juliet Java** (`benchmarks/run_juliet.py`, `valen/corpus.py::load_juliet`):
264 casos de 5 CWEs; el adaptador ajustado en OWASP transfiere mal
(P=0.333, R=0.562) porque Juliet separa fuente/sumidero entre clases
(`_a`/`_base`/`_bad`) y exige taint **interprocedural** — evidencia para el
siguiente paso de sistemas y amenaza a la validez externa.

**Taint interprocedural** (`valen/ingest/java_interproc.py`, adaptador
`java-interproc`): punto fijo insensible al contexto (parámetro manchado si un
call site le pasa taint; llamada manchada si el callee devuelve taint). En
**Juliet**: R 0.562→0.750, F1 0.419→0.490 (CWE78/CWE90 de 0.000→0.750). En
**OWASP** empeora levemente (F1 de taint 0.662→0.637) por insensibilidad al
contexto → necesario pero no suficiente; el siguiente paso son summaries
sensibles al contexto. **Summaries de frameworks**: fuentes por atributo (`request.GET`/`request.args`) y sinks de ORM/SSTI (Django `raw`/`RawSQL`, Flask `render_template_string`, JPA `createQuery`) que capturan flujos a nivel aplicación.

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
VALEN_LLM_MODEL=openai/flash VALEN_LLM_BASE_URL=http://127.0.0.1:4000 \
VALEN_LLM_API_KEY=$LITELLM_MASTER_KEY .venv/bin/python benchmarks/run_llm.py --runs 2
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

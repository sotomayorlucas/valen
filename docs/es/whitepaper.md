# VALEN — Priorizar Qué Verificar: un Pipeline Neuro-Simbólico Reproducible

**Whitepaper v0.3 (rev 8)** · *Borrador de trabajo — no revisado por pares*

> *"Mapear el programa como un espacio — y probar si la estructura realmente ayuda. Cuando la geometría falla, el fallo también es información."*

---

## Resumen

VALEN es un **verificador neuro-simbólico de confianza y lógica**: un agente
autónomo que extrae especificaciones de seguridad (invariantes de autorización,
ciclos de máquinas de estado, precondiciones de taint) desde el código con un LLM
y las descarga con métodos formales (Z3, homología dirigida GLMY, un núcleo
mecanizado en Lean 4), emitiendo solo witnesses verificables por máquina bajo la
semántica modelada. Su tesis: los defectos de mayor impacto del software moderno
— **BOLA/IDOR (CWE-639), autorización ausente (CWE-862) y ciclos de estado
destructivos (reentrancia, deadlocks)** — son *estructurales*: el dato es
legítimo, el taint es ciego ante ellos y solo la forma de fronteras de privilegio
y transiciones de estado los delata.

Esta cuenta integral se apoya en un resultado **negativo** riguroso sobre SAST de inyección
lineal (**OWASP Benchmark 1.2**, 2740 casos): el taint crudo ordena mejor (MRR
0.894, AUC 0.895, $p=5\times10^{-5}$ sobre el campo fusionado); espectral (0.496)
y topológica (0.500) están en el azar y la curvatura por debajo (0.376); H1/H2/H3/H5
quedan **no soportadas** — porque un servlet plano y casi acíclico no tiene esa
estructura. La misma maquinaria rinde donde la estructura *sí* es la señal: un
detector estructural de autorización ausente/BOLA recupera casos que el taint
omite por completo (0 hallazgos de taint) con recall 1.0 / precisión 0.72 / F1 0.837 en un
corpus curado de 39 casos, y la homología dirigida GLMY extrae el generador β₁ concreto
de un ciclo de estado que la simetrización borra.

## 1. Motivación

Los SAST clásicos enumeran patrones sintácticos: frágiles y ruidosos. En OWASP
Benchmark 1.2, herramientas desplegadas colapsan en el **índice de Youden**
$J = \mathrm{TPR}-\mathrm{FPR}$ (SonarQube $J\approx+0.01$; CodeQL $J\approx+0.22$).
Faltan: (i) una **representación unificada y cuantitativa**, y (ii) un **ciclo de
razonamiento** que convierta sospecha en prueba.

## 2. La idea central

```
artefacto → IR (grafo tipado) → capas matemáticas → V(x) → agente LLM → verificador formal
                     ↑__________________ re-embebe __________________|
```

Modelamos a los *candidatos* a vulnerabilidad como violaciones de invariantes de
programa en vez de patrones puramente sintácticos (invariante de autorización
rota, ciclo persistente, cuello de botella de curvatura negativa, flujo de taint
que cruza un corte de confianza).

## 3. La Representación Intermedia (IR)

**Definición 1 (Grafo de programa).** $G = (V, E, \tau_V, \tau_E, \omega)$ donde
los nodos llevan un tipo (módulo, función, bloque, sentencia, llamada, asignación,
variable, parámetro, fuente, sumidero, gate), las aristas un tipo (control, dato,
llamada, taint, confianza, auth) y $\omega$ un peso no negativo. La IR es la única
fuente de verdad, serializable a JSON, compartida entre las capas Python y Rust.

## 4. Capas matemáticas

### 4.1 Espectral
$L_t = D_t - A_t$; $\lambda_2$ (conectividad algebraica), vector de Fiedler,
embedding espectral y cota de Cheeger. **Señal:** anomalía espectral.

### 4.2 Topológica (TDA)
Homología persistente de una filtración; $\beta_0$ componentes, $\beta_1$ ciclos
independientes; diagramas de persistencia; Mapper construye el nervio navegable.
**Señal:** outliers de persistencia / generadores de $H_1$ de larga vida.

### 4.3 Geométrica
Ollivier–Ricci $\kappa(u,v) = 1 - W_1(m_u,m_v)/d(u,v)$ (PL exacto o aproximación
entrópica de Sinkhorn); Forman–Ricci $\kappa_F = 4 - \deg(u) - \deg(v)$.
**Señal:** cuellos de botella por curvatura.

### 4.4 Algebraica
El retículo de taint $\mathbb{T} = \{\bot = \text{limpio} \sqsubseteq \top = \text{manchado}\}$
y una conexión de Galois $(\alpha, \gamma)$. La **función de nivel de privilegio**
$F: V \to \mathbb{N}$ asigna un nivel a cada punto; una arista $(u,v)$ es *arista
auth* si y solo si $F(u) < F(v)$. **Proposición (violación de la invariante de
autorización):** un flujo de taint viola la invariante si y solo si su camino cruza
una arista `auth` sin un sanitizador — la regla operacional H4/§8 (prueba en el PDF,
§4.6; la parte de no-escalada está mecanizada en Lean 4). No se reclama ninguna
transformación natural
categórica.

### 4.5 Formal
La ejecución simbólica calcula una condición de camino $\Phi$; un solver SMT
comprueba $\mathrm{SAT}(\phi_{\text{malo}})$; la alcanzabilidad es la fórmula CTL
$\mathbf{EF}\,\phi_{\text{malo}}$; el taint es un autómata finito.

## 5. El campo escalar de vulnerabilidad

$$V(x) = \sigma\!\Big(\sum_i \alpha_i\, s_i(x)\Big).$$

Las señales se normalizan por capa; en el prototipo los pesos son **uniformes**
($\alpha_i = 1/N$) y $V$ se reporta como el puntaje fusionado crudo; la calibración
se hace por regresión logística sobre datos etiquetados (§11.1).

## 6. Hipótesis de mapeo

| # | Rasgo | Clase |
|---|-------|-------|
| H1 | cuello de botella $\kappa \ll 0$ | escalada de privilegios |
| H2 | generador de $H_1$ persistente | reentrancia / recursión |
| H3 | corte de Fiedler | inyección cruzando confianza |
| H4 | taint que cruza arista `auth` | violación de la invariante de autorización |
| H5 | outlier de persistencia | real vs. espurio |
| H6 | $\mathrm{SAT}(\phi_{\text{malo}})$ | witness (semántica codificada) |

Son *hipótesis falsables*, no leyes; H1/H2/H3/H5 no se sostienen en los corpus
evaluados.

## 7. El agente LLM autónomo

Ciclo cerrado: **mapea → ordena → hipotetiza → verifica → refina → reporta**. El
valen aporta una spec estructurada `(sink, fuente, línea, categoría)`; el LLM
aporta la interpretación (CWE, descripción); el verificador consume la spec —nunca
la prosa del LLM. Capa de proveedor vía **LiteLLM** (OpenAI/Anthropic/local), con
fallback offline determinista.

## 8. Desafíos de diseño y mitigaciones

* **C1 — Paradoja del cuello de botella.** La curvatura negativa marca chokepoints
  defensivos legítimos; se discriminan por rol / destino `auth`.
* **C2 — Simetrización.** La dirección se preserva con el Laplaciano dirigido de
  Chung sobre la SCC mayor (Perron por iteración estilo PageRank); los DAG se
  delegan a retículos/alcanzabilidad.
* **C3 — Coste del transporte.** Forman–Ricci por defecto ($O(|E|)$);
  Ollivier–Ricci con Sinkhorn como alternativa rápida.
* **C4 — Operacionalización de H4.** Un flujo de taint que cruza una arista `auth`
  es violación de la invariante de autorización (alcanzabilidad sobre `dato ∪ taint ∪ auth`).
* **C5 — Puente valen→verificador.** Gramática de verificación fija; el LLM
  nunca emite SMT-LIB.

## 9. Un ejemplo resuelto

```python
def search(db, query_param):
    sql = "SELECT * FROM users WHERE name = '" + query_param + "'"
    cursor = db.cursor()
    cursor.execute(sql)
```

El pipeline produce un nodo `source` (`param:query_param`), un nodo `sink`
(`cursor.execute`, categoría `sql`) y una arista `taint`; $V(x)$ se dispara en el
sink; Z3 devuelve `SAT` con un witness bajo la semántica codificada (no un exploit
end-to-end). La variante parametrizada se
excluye correctamente, y un decorador `@login_required` eleva el hallazgo a
violación de la invariante de autorización H4.

## 10. Estado de implementación

F0 whitepaper · F1 IR + SAST Python + taint · F2 espectral/geométrico (Rust) ·
F3 TDA · F4 verificador Z3 + retículo de taint + H4 · F5 agente LLM autónomo ·
F6 visualización + demo · F7 adaptadores multi-dominio (binario objdump/angr,
OpenAPI, agente LLM, Java). Además: arnés de benchmark, calibración de pesos y el
estudio OWASP.

## 11. Validación y estudio empírico

**Etapa 1 (completa):** micro-benchmarks de juguete; toda vulnerabilidad sembrada
se confirma, todo falso positivo por sanitizador / query parametrizada / argv se
excluye.

**Etapa 2 (en curso):** corpus etiquetados.

### 11.1 Estudio empírico sobre OWASP Benchmark 1.2

Perfilando el corpus completo se corrigieron tres carencias *generalizables*: (i)
**taint con conciencia de ramas** (join de entornos — supremo del retículo), (ii)
**taint del receptor/estado** (sinks como `statement.execute()` llevan el taint en
el objeto; los mutadores manchan su receptor), (iii) **restricción del
response-writer** para XSS (`System.out.println` no es XSS). Ablación (categorías
de taint, 1698 casos):

| Variante | P | R | F1 |
|---|---|---|---|
| adaptador naive inicial | 0.515 | 0.426 | 0.466 |
| + branch-join, receptor/estado, cobertura | 0.530 | 0.856 | 0.655 |
| + restricción XSS (final) | **0.549** | **0.834** | **0.662** |
| final, sin branch-join | 0.515 | 0.555 | 0.535 |

### 11.2 Comparación y objetivo neuro-simbólico

| Herramienta | TPR | FPR | Prec. | F1 | J |
|---|---|---|---|---|---|
| SonarQube (reportado) | 0.956 | 0.946 | 0.330 | 0.490 | +0.010 |
| CodeQL (reportado) | 0.902 | 0.682 | 0.603 | 0.744 | +0.220 |
| **VALEN adaptador (medido)** | 0.842 | 0.674 | 0.572 | 0.681 | **+0.168** |
| VALEN adaptador + Z3 (medido, taint) | 0.834 | 0.776 | 0.549 | 0.662 | +0.057 |

*Las filas externas son números reportados en evaluaciones públicas; el adaptador
VALEN es medido (once categorías); las dos últimas filas son el objetivo
**proyectado** de la Etapa 2, no medido (Z3 con timeout de 5 s por consulta; ante
timeout el caso se marca desconocido/conservador, nunca como detección).*

### 11.3 Backend binario dual

Dos backends intercambiables emiten la misma IR: una ruta de texto `objdump` sin
dependencias y un backend `angr` opcional (`CFGFast` + taint interprocedural).

## 12. Uso responsable

VALEN es una herramienta de defensa / pruebas autorizadas; se libera bajo el
supuesto de uso autorizado y divulgación coordinada.

## 13. Referencias

1. Fiedler (1973), *Algebraic connectivity of graphs.*
2. Chung (1997), *Spectral Graph Theory*; (2005) *Laplacians for directed graphs.*
3. Edelsbrunner, Letscher, Zomorodian (2002), *Topological persistence.*
4. Singh, Mémoli, Carlsson (2007), *Mapper.*
5. Ollivier (2009), *Ricci curvature of Markov chains.*
6. Cousot & Cousot (1977), *Abstract interpretation.*
7. King (1976), *Symbolic execution.*
8. Clarke et al. (1986), *Model checking.*
9. Cuturi (2013), *Sinkhorn distances.*
10. OWASP Benchmark Project, v1.2 (2024).

## 12. Invariantes estructurales a través de dominios

El resultado negativo de OWASP es un diagnóstico del terreno, no un fallo de la
maquinaria: un servlet plano no tiene curvatura ni topología persistente, y el
taint ya es casi óptimo allí. VALEN se reposiciona como un **motor formal de
invariantes estructurales y lógica de negocio**, apuntando a cuatro dominios
donde el análisis estático convencional es ciego:

| Capa formal / matemática | Objeto modelado | Vulnerabilidad mapeada |
|---|---|---|
| Invariante auth (Lean 4) | endpoints, decoradores, recursos de API | **BOLA / IDOR / BFLA** |
| Homología dirigida (GLMY) | grafo de transiciones de estado y llamadas asíncronas | **reentrancia, desincronización de estado, deadlocks** |
| Espectral (Fiedler) | topologías de red, K8s RBAC, IAM | **ruptura de segmentación de confianza, movimiento lateral** |
| Curvatura discreta (Ricci) | grafos de microservicios e identidad | **puntos únicos de fallo, puentes de escalada de privilegios** |
| Verificador simbólico (Z3) | restricciones de camino en la lógica de negocio | **contraejemplos ejecutables (witnesses)** |

Sustrato ya en el repo: el **detector BOLA/IDOR**
(`valen.analysis.authorization.bola_idor_candidates`, corpus
`examples/python/bola/` + `bola_corpus/`, eval `benchmarks/run_bola.py`, recall 1.0 / precisión 0.72 / F1 0.837 con
**0 hallazgos de taint** en los casos vulnerables); el **witness de ownership en
Z3** (`valen.analysis.bola_verifier`) que separa autorización de objeto de
mera autenticación; el **adaptador OpenAPI**
(`valen.ingest.web`) que emite aristas `auth` desde esquemas de seguridad y
marca operaciones con sink y sin esquema (CWE-862); la
**homología dirigida GLMY** (`core/src/path_homology.rs`, evaluada en R 1.0 /
P 0.75 vs no dirigida 0.5/0.5, `benchmarks/run_state_glmy.py`); el **adaptador
IAM** (`valen.ingest.iam` + `valen.analysis.trust`) para puentes de
privilegio vía Fiedler/Forman-Ricci (`examples/iam/demo.json`); la
**spec-mining** (`benchmarks/run_spec_mining.py`, 0.5 recall / 0 alucinación); y
una **evaluación en datos reales sobre OWASP crAPI**
(`valen.analysis.api_bola`, `benchmarks/run_crapi_bola.py`) que recupera los 9
endpoints BOLA/BFLA documentados con recall 1.0 / precisión 0.90, donde el
chequeo de auth-ausente puntúa 0 porque todo endpoint BOLA está autenticado. El
**adaptador de agentes LLM**
(`valen.ingest.llm_agent`) para confused-deputy / inyección indirecta de
prompt. Abandona la competencia estéril con Semgrep/CodeQL en SQLi/XSS locales y
ataca las fallas arquitectónicas donde las reglas sintácticas callan.

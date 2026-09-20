# MANIFOLD — Un Motor Matemático para Mapear Vulnerabilidades

**Whitepaper v0.1** · *Borrador de trabajo — no revisado por pares*

> *"Mapea el código como un espacio; deja que la geometría de ese espacio revele la falla."*

---

## Resumen

MANIFOLD trata un artefacto de software no como un conjunto de reglas a emparejar,
sino como un **objeto matemático**: un grafo tipado y ponderado enriquecido con
estructura **algebraica**, **espectral**, **topológica** y **geométrica**. Sobre ese
objeto se computa un campo escalar de **potencial de vulnerabilidad** $V(x)$, que
hace emerger las regiones anómalas como *rasgos* geométricos/topológicos/espectrales
en lugar de coincidencias literales de cadenas. Un **agente LLM autónomo** navega el
"manifold" resultante, formula hipótesis sobre esas regiones y despacha
**verificadores formales** (SMT, ejecución simbólica, interpretación abstracta) que
confirman o refutan cada hipótesis — cerrando el ciclo entre intuición estadística y
prueba matemática.

Este documento define la representación intermedia, formaliza cada capa matemática,
enuncia las leyes de mapeo que conectan rasgos matemáticos con clases de
vulnerabilidad, y especifica la arquitectura del agente y la hoja de ruta.

---

## 1. Motivación

Los escáneres tradicionales (SAST/DAST) enumeran patrones sintácticos. Son frágiles:
pasan por alto vulnerabilidades novedosas y ahogan al analista en falsos positivos.
Faltan dos capacidades:

1. Una **representación unificada y cuantitativa** de la "estructura del programa"
   sobre la cual proyectar y fusionar muchas señales *independientes*.
2. Un **ciclo de razonamiento** que convierta "región sospechosa" en "vulnerabilidad
   probada": el LLM aporta la intuición, la matemática aporta la prueba.

MANIFOLD proporciona ambas.

## 2. La idea central

```
artefacto ──► IR (grafo tipado) ──► capas matemáticas ──► campo escalar V(x)
                                        │                        │
                                        └── embeddings/persistencia/curvatura
                                                               │
                                                  AGENTE LLM  ◄─┘  (navega, hipotetiza)
                                                               │
                                                  verificadores formales (prueban/refutan)
```

Una vulnerabilidad **no** es un patrón; es una *violación de una invariante
estructural* (una condición de naturalidad rota, un ciclo persistente, un cuello de
botella de curvatura negativa, un flujo de taint que cruza un corte espectral de
confianza). Cada capa detecta un *tipo* distinto de violación de invariante, y el
campo fusionado $V(x)$ ordena las regiones para que el agente las inspeccione.

## 3. La Representación Intermedia (IR)

### Definición 1 (Grafo de programa)

Un **grafo de programa** es una tupla

$$
G = (V, E, \tau_V, \tau_E, \omega)
$$

donde

* $V$ es un conjunto finito de **nodos** (módulos, funciones, bloques, sentencias,
  llamadas, variables, fuentes, sumideros);
* $E \subseteq V \times V$ es un conjunto de **aristas** dirigidas;
* $\tau_V : V \to \mathbb{N}_K$ asigna a cada nodo un **tipo** de un conjunto fijo
  $K = \{\text{módulo, función, bloque, sentencia, llamada, asignación, variable, parámetro, fuente, sumidero}\}$;
* $\tau_E : E \to \mathcal{T}$ asigna a cada arista un **tipo**
  $\mathcal{T} = \{\text{control, dato, llamada, taint, confianza, auth}\}$;
* $\omega : E \to \mathbb{R}_{\ge 0}$ asigna a cada arista un **peso** no negativo
  (por defecto $1$; se usa luego para curvatura y persistencia).

La IR es la única fuente de verdad. Cada adaptador (código fuente, binario, API web,
agente LLM) debe producir un grafo de programa; cada análisis lo consume. El esquema
es agnóstico al lenguaje y serializable a JSON (las capas Python y Rust comparten el
mismo esquema).

## 4. Capas matemáticas

Para cada capa fijamos un subgrafo por tipo de arista $\tau_E$, y luego computamos
estructura.

### 4.1 Capa espectral (teoría algebraica de grafos)

Para un tipo de arista $t$, definimos la **adyacencia** simétrica $A_t$ y el **grado**
$D_t$, y el **Laplaciano combinatorio**

$$
L_t = D_t - A_t.
$$

$L_t$ es semidefinido positivo; su espectro $0 = \lambda_1 \le \lambda_2 \le \cdots$
codifica la estructura global:

* $\lambda_2$ es la **conectividad algebraica** (valor de Fiedler). Su autovector
  $f_2$ — el **vector de Fiedler** — induce un corte canónico $S^+ = \{v : f_2(v) \ge 0\}$.
* El **embedding espectral** $\Phi^{(d)}(v) = (f_2(v), f_3(v), \dots, f_{d+1}(v))$ mapea
  nodos a $\mathbb{R}^d$ de modo que la distancia en el grafo sea aproximadamente la
  distancia euclídea.
* La desigualdad de Cheeger acota el **cociente de cuello de botella** $h(G)$ por
  $\frac{\lambda_2}{2} \le h(G) \le \sqrt{2\,d_{\max}\lambda_2}$.

**Señal 1 (anomalía espectral).** El *error de reconstrucción* de un nodo bajo una
reconstrucción de eigenmap de bajo rango, y su distancia al corte de Fiedler, se usan
como puntajes de anomalía: los nodos que "no encajan" en el esqueleto de baja
dimensión son candidatos a inspección.

### 4.2 Capa topológica (homología persistente)

Del grafo de programa construimos una **filtración** de complejos simpliciales — p. ej.
un complejo de Vietoris–Rips o de bandera (clique) sobre la métrica de caminos más
cortos, o una filtración guiada por el peso $\omega$. Aplicando homología persistente
se obtiene, para cada dimensión $k$, un **diagrama de persistencia** $\mathrm{Dgm}_k$ de
pares nacimiento–muerte.

* $\beta_0$ cuenta componentes conexas (módulos, islas inalcanzables).
* $\beta_1$ cuenta **ciclos independientes** — bucles en el grafo de llamadas/flujo de datos.
* Los puntos de $\mathrm{Dgm}_k$ lejos de la diagonal tienen alta **persistencia**
  $\mathrm{muerte} - \mathrm{nacimiento}$ y representan rasgos robustos; los puntos
  cercanos a la diagonal son ruido topológico.

**Señal 2 (outliers de persistencia).** Los generadores de $H_1$ de larga vida y los
puntos de alta persistencia se ordenan como estructuralmente significativos.

El algoritmo **Mapper** (Singh–Mémoli–Carlsson) produce un mapa *visual*: se elige una
función filtro $f : V \to \mathbb{R}$ (p. ej. el propio campo de vulnerabilidad, o la
centralidad de nodo), se cubre su imagen con intervalos solapados, se agrupa cada fibra
y se construye el **nervio** (un grafo cuyos nodos son los clústeres). Mapper produce el
"manifold" navegable que da nombre al proyecto.

### 4.3 Capa geométrica (curvatura discreta)

La **curvatura de Ollivier–Ricci** de una arista $(u,v)$ es

$$
\kappa(u,v) = 1 - \frac{W_1(m_u, m_v)}{d(u,v)},
$$

donde $m_u, m_v$ son medidas de probabilidad concentradas alrededor de $u,v$ (p. ej.
medidas de paseo aleatorio perezoso) y $W_1$ es la distancia de Wasserstein-1. La
curvatura negativa significa que hay que mover *más* masa que la propia longitud de la
arista — es decir, la arista es un **embudo** por el que pasan muchos caminos más cortos.

Para artefactos jerárquicos (grafos de llamadas, de dependencias) además embebemos el
grafo en un espacio **hiperbólico** (bola de Poincaré) y medimos $\delta$-hiperbolicidad;
los árboles tienen $\delta = 0$.

**Señal 3 (cuellos de botella por curvatura).** La curvatura $\kappa$ fuertemente
negativa marca cuellos de botella — funciones únicas por las que debe pasar el
privilegio o el dato — la ubicación natural de los bugs de escalada de privilegios y
de autorización.

### 4.4 Capa algebraica (retículos y teoría de categorías)

*Interpretación abstracta.* Un programa es un mapa monótono sobre un retículo de
valores abstractos. El **retículo de taint** es

$$
\mathbb{T} = \{\bot = \text{limpio} \sqsubseteq \top = \text{manchado}\}
$$

(instanciado por etiqueta de taint, dando un retículo producto sobre las etiquetas).
Las fuentes asignan $\top$; las funciones de transferencia lo propagan; un sumidero
alcanzado por $\top$ es una violación. Esto es una **conexión de Galois**
$(\alpha, \gamma)$ entre la semántica recolectora concreta y el dominio abstracto de
taint, garantizando solidez (no se pierden flujos) a costa de precisión (posibles
falsos positivos).

*Teoría de categorías.* Considera el programa como una categoría $\mathbf{Prog}$: los
objetos son puntos de programa / tipos de valores, los morfismos son computaciones, y la
composición es el encadenamiento. Los efectos (E/S, entorno) son **mónadas**; la
autorización es un funtor $F : \mathbf{Prog} \to \mathbf{Auth}$ que compone de forma
segura solo a lo largo de caminos confiables.

**Ley de diseño (naturalidad del taint).** Un **flujo de taint** es un morfismo
$s \xrightarrow{\,t\,} k$ de una fuente a un sumidero. Los programas *seguros* preservan
la naturalidad del funtor de autorización: aplicar $F$ a una composición es igual a
componer las imágenes. Una vulnerabilidad es un flujo de taint que rompe el cuadrado de
naturalidad — el taint alcanza un sumidero "como si" se hubiera aplicado autorización
cuando no se ha hecho.

### 4.5 Capa formal (ejecución simbólica y model checking)

* La ejecución simbólica calcula una condición de camino $\Phi$ y un estado simbólico
  $\sigma$; un estado malo es un $\sigma$ donde un sumidero consume un símbolo marcado
  como manchado.
* Un solucionador SMT comprueba $\mathrm{SAT}\left(\Phi \wedge \text{taint\_alcanza\_sumidero}\right)$ —
  un *modelo* es un exploit concreto.
* La alcanzabilidad de un estado malo es la fórmula CTL $\mathbf{EF}\,\mathrm{malo}$.
* La propagación de taint es un **autómata finito**: las fuentes son estados iniciales,
  los sumideros estados aceptores; el lenguaje aceptado es exactamente el conjunto de
  caminos fuente→sumidero.

**Señal 4 (verdad formal de base).** A diferencia de las capas anteriores (que son
*rasgos heurísticos*), la capa formal produce *pruebas*. Es el árbitro que convierte las
hipótesis del agente en hallazgos confirmados.

## 5. El campo escalar de vulnerabilidad

Cada capa produce un puntaje a nivel de nodo o de arista. Los **fusionamos** en un campo

$$
V(x) = \sigma\!\Big(\sum_i \alpha_i \, s_i(x)\Big),
$$

donde $s_i$ son las señales normalizadas de cada capa (anomalía espectral, outlier de
persistencia, curvatura, altura de retículo, alcanzabilidad formal) y $\alpha_i$ son
pesos aprendibles (o ajustados a mano), con $\sigma$ una compresión logística. $V$ es:

* un **ranking** para el agente (inspeccionar primero el mayor $V$),
* una **función filtro** para Mapper,
* un **campo de costos** sobre el que el agente planifica la navegación.

## 6. Leyes de mapeo (rasgo → clase de vulnerabilidad)

Son *hipótesis de diseño* a validar empíricamente; cada una se enuncia con el objeto
matemático que la sustenta.

| # | Ley | Objeto matemático | Clase de vulnerabilidad |
|---|-----|-------------------|-------------------------|
| L1 | Cuello de botella | $\kappa(u,v) \ll 0$ | escalada de privilegios, bypass de auth |
| L2 | Ciclo | generador de $H_1$ (persistente) | reentrancia, recursión infinita, deadlock |
| L3 | Corte de confianza | corte de Fiedler del grafo control+dato | inyección que cruza la frontera de confianza |
| L4 | Ruptura de naturalidad | flujo de taint que viola la naturalidad de $F$ | violación arbitraria de taint |
| L5 | Persistencia | puntos lejos de la diagonal en $\mathrm{Dgm}_k$ | separación de rasgo *real* vs. espurio |
| L6 | Alcanzabilidad | $\mathrm{SAT}(\Phi \wedge \text{malo})$ | camino de exploit concreto |

## 7. El agente LLM autónomo

El agente es un ciclo cerrado con anclaje matemático explícito:

1. **Ingesta** — analizar el artefacto hacia la IR.
2. **Embebir y mapear** — computar $V(x)$, embedding espectral, diagramas de
   persistencia, curvatura; construir el manifold de Mapper.
3. **Hipotetizar** — el LLM, dado el manifold (regiones top, su código y los *rasgos*
   que las marcaron), propone vulnerabilidades candidatas.
4. **Verificar** — la capa formal (SMT / ejecución simbólica / interpretación
   abstracta) prueba o refuta cada candidato.
5. **Refinar** — los hallazgos confirmados añaden/ponderan aristas de taint/confianza y
   se re-embeben; las hipótesis refutadas se registran como ejemplos negativos.
6. **Reportar** — un informe legible por humanos y máquinas que cita, para cada
   hallazgo, el *rasgo matemático* que lo hizo emerger y la *prueba* que lo confirmó.

**Capa de proveedor LLM.** El agente apunta a cualquier endpoint compatible con
OpenAI mediante **LiteLLM**, de modo que funciona sin cambios contra modelos "cyber" de
OpenAI/Anthropic o modelos locales (Ollama, etc.).

**Por qué el LLM no hace detección cruda.** Los LLM son *clasificadores* poco fiables
pero *razonadores* fuertes. MANIFOLD divide responsabilidades: la matemática propone
*regiones* (barato, aproximadamente sólido, sin alucinación), el LLM propone
*hipótesis* (ricas, contextuales), la capa formal propone *pruebas* (sólidas). Cada
componente hace lo que se le da bien.

## 8. Arquitectura del sistema

```
ingest/  (Python)         core/  (Rust)             agent/  (Python)        viz/  (TS)
├─ AST tree-sitter        ├─ grafo (serde)          ├─ proveedor LiteLLM      ├─ mapa del manifold
├─ CFG/DFG/grafo de llamadas ├─ espectral (Laplaciano) ├─ generador de hipótesis  ├─ diagrama de persistencia
├─ perfiles source/sink   ├─ topología (F3)         ├─ puente verificador     ├─ gráficos espectrales
└─ pase de taint  ───────►└─ geometría (F2) ──────►└─ memoria/reflexión ────►└─ panel de hallazgos
        │                        │
        └──── JSON IR (esquema compartido) ────┘
```

El JSON de la IR es el contrato entre Python y Rust (ambos consumen/producen el mismo
esquema; el lado Rust se verifica con `cargo test`).

## 9. Estado de implementación

| Fase | Entregable | Estado |
|------|------------|--------|
| F0 | Whitepaper (es/en), arquitectura | ✅ este documento |
| F1 | IR + ingesta SAST Python (tree-sitter) + taint intraprocedural | ✅ implementado, testeado |
| F2 | Núcleos espectral + geométrico (Rust, vector de Fiedler, Ricci, embedding hiperbólico) | ✅ implementado, testeado |
| F3 | TDA (homología persistente H0/H1, Mapper) | ✅ implementado, testeado |
| F4 | Verificación formal (retículo de taint, Z3, angr) | ⬜ |
| F5 | Agente LLM autónomo (LiteLLM) | ⬜ |
| F6 | Visualización + demo end-to-end | ⬜ |
| F7 | Adaptadores binario / web / LLM (multi-dominio) | ⬜ |

## 10. Plan de validación

* **Micro-benchmarks**: programas vulnerables de juguete (SQLi, inyección de comandos,
  ejecución de código, reentrancia) con verdad de referencia conocida; afirmar que la
  señal de cada capa está presente y correctamente localizada.
* **Precisión/recall**: comparar contra un corpus etiquetado (p. ej. OWASP Benchmark,
  SARD) una vez que F4 aterrice; reportar la tasa de falsos positivos del campo
  fusionado frente al pase de taint crudo.
* **Eficacia del agente**: medir la tasa de hipótesis→confirmación y la cobertura de
  vulnerabilidades sembradas en repos sintéticos.

## 11. Uso responsable

MANIFOLD es una herramienta de defensa/pruebas autorizadas. La misma geometría que
revela vulnerabilidades a un defensor se las revela a un atacante; la liberamos bajo el
supuesto de uso autorizado y alentamos la divulgación coordinada.

## 12. Referencias

1. Fiedler, M. (1973). *Algebraic connectivity of graphs.*
2. Chung, F. (1997). *Spectral Graph Theory.*
3. Edelsbrunner, Letscher, Zomorodian (2002). *Topological persistence and simplification.*
4. Singh, Mémoli, Carlsson (2007). *Topological Methods for the Analysis of High Dimensional Data Sets and 3D Object Recognition.*
5. Ollivier, Y. (2009). *Ricci curvature of Markov chains on metric spaces.*
6. Cousot, P. & Cousot, R. (1977). *Abstract interpretation: a unified lattice model.*
7. Mac Lane, S. (1971). *Categories for the Working Mathematician.*
8. King, J. (1976). *Symbolic execution and program testing.*
9. Clarke, E. M. et al. (1986). *Automatic verification of finite-state concurrent systems.*

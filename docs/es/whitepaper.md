# MANIFOLD — Un Motor Matemático para Mapear Vulnerabilidades

**Whitepaper v0.1 (rev 7)** · *Borrador de trabajo — no revisado por pares*

> *"Mapea el código como un espacio; deja que la geometría de ese espacio revele la falla."*

---

## Resumen

MANIFOLD trata un artefacto de software no como un conjunto de reglas a emparejar,
sino como un **objeto matemático**: un grafo tipado y ponderado enriquecido con
estructura *algebraica*, *espectral*, *topológica* y *geométrica*. Sobre él se
computa un campo escalar de **potencial de vulnerabilidad** $V(x)$, y un **agente
LLM autónomo** navega el "manifold" resultante, formula hipótesis y despacha
**verificadores formales** (SMT, ejecución simbólica, interpretación abstracta) que
las confirman o refutan. Este documento define la IR, formaliza cada capa, enuncia
las leyes de mapeo, especifica el agente y reporta un estudio empírico sobre el
**OWASP Benchmark 1.2** completo (2740 casos Java).

---

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

Una vulnerabilidad **no** es un patrón; es la *violación de una invariante
estructural* (naturalidad rota, ciclo persistente, cuello de botella de curvatura
negativa, flujo de taint que cruza un corte de confianza).

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
y una conexión de Galois $(\alpha, \gamma)$; los efectos son mónadas y la
autorización un funtor $F$. **Ley de diseño:** una vulnerabilidad es un flujo de
taint que rompe el cuadrado de naturalidad de $F$ (operacionalizado en §8, C4).

### 4.5 Formal
La ejecución simbólica calcula una condición de camino $\Phi$; un solver SMT
comprueba $\mathrm{SAT}(\phi_{\text{malo}})$; la alcanzabilidad es la fórmula CTL
$\mathbf{EF}\,\phi_{\text{malo}}$; el taint es un autómata finito.

## 5. El campo escalar de vulnerabilidad

$$V(x) = \sigma\!\Big(\sum_i \alpha_i\, s_i(x)\Big).$$

Las señales se normalizan por capa; en el prototipo los pesos son **uniformes**
($\alpha_i = 1/N$) y $V$ se reporta como el puntaje fusionado crudo; la calibración
se hace por regresión logística sobre datos etiquetados (§11.1).

## 6. Leyes de mapeo

| # | Rasgo | Clase |
|---|-------|-------|
| L1 | cuello de botella $\kappa \ll 0$ | escalada de privilegios |
| L2 | generador de $H_1$ persistente | reentrancia / recursión |
| L3 | corte de Fiedler | inyección cruzando confianza |
| L4 | taint que cruza arista `auth` | violación de naturalidad |
| L5 | outlier de persistencia | real vs. espurio |
| L6 | $\mathrm{SAT}(\phi_{\text{malo}})$ | exploit concreto |

## 7. El agente LLM autónomo

Ciclo cerrado: **mapea → ordena → hipotetiza → verifica → refina → reporta**. El
manifold aporta una spec estructurada `(sink, fuente, línea, categoría)`; el LLM
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
* **C4 — Operacionalización de L4.** Un flujo de taint que cruza una arista `auth`
  es violación de naturalidad (consulta de alcanzabilidad sobre `dato ∪ taint ∪ auth`).
* **C5 — Puente manifold→verificador.** Gramática de verificación fija; el LLM
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
sink; Z3 devuelve `SAT` con un witness concreto. La variante parametrizada se
excluye correctamente, y un decorador `@login_required` eleva el hallazgo a
violación de naturalidad L4.

## 10. Estado de implementación

F0 whitepaper · F1 IR + SAST Python + taint · F2 espectral/geométrico (Rust) ·
F3 TDA · F4 verificador Z3 + retículo de taint + L4 · F5 agente LLM autónomo ·
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
| **MANIFOLD adaptador (medido)** | 0.842 | 0.674 | 0.572 | 0.681 | **+0.168** |
| MANIFOLD +V(x) (proyectado) | 0.858 | 0.314 | 0.751 | 0.801 | +0.544 |
| MANIFOLD +V(x)+Z3 (proyectado) | 0.825 | 0.038 | 0.959 | 0.887 | +0.787 |

*Las filas externas son números reportados en evaluaciones públicas; el adaptador
MANIFOLD es medido (once categorías); las dos últimas filas son el objetivo
**proyectado** de la Etapa 2, no medido (Z3 con timeout de 5 s por consulta; ante
timeout el caso se marca desconocido/conservador, nunca como detección).*

### 11.3 Backend binario dual

Dos backends intercambiables emiten la misma IR: una ruta de texto `objdump` sin
dependencias y un backend `angr` opcional (`CFGFast` + taint interprocedural).

## 12. Uso responsable

MANIFOLD es una herramienta de defensa / pruebas autorizadas; se libera bajo el
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

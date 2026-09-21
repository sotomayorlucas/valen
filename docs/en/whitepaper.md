# MANIFOLD — Prioritizing What to Verify: a Reproducible Neuro-Symbolic Vulnerability Pipeline

**Whitepaper v0.3 (rev 8)** · *Working draft — not peer reviewed*

> *"Map the code as a space; let the geometry of that space reveal the flaw."*

---

## Abstract

The bottleneck of static analysis is not *detecting* sinks but *deciding which one
to verify*. MANIFOLD turns an artifact into a typed graph (IR), computes a
vulnerability scalar field $V(x)$, and lets a neuro-symbolic loop (LLM + Z3 with
witnesses) act on prioritized regions. Contributions: (1) a prioritization-oracle
harness (MRR/R@1/NDCG@k, cost curve, baselines); (2) an end-to-end Java pipeline
(SAST + Z3 verifier) and a reproducible artifact; (3) a measurement study on
**OWASP Benchmark 1.2** (2740 cases) and a Juliet transfer. Headline (negative)
result: raw taint ranks best (MRR 0.894, AUC 0.895); spectral (0.496) and
topological (0.500) are at chance and curvature is below chance (0.376); Z3 adds
proof, not precision; OWASP→Juliet transfers poorly (P=0.333, R=0.562), exposing
the need for interprocedural taint.

## 1. Motivation

Classic SAST enumerates syntactic patterns: brittle, noisy. On OWASP Benchmark
1.2, deployed tools collapse on the **Youden index** $J = \mathrm{TPR}-\mathrm{FPR}$
(SonarQube $J\approx+0.01$; CodeQL $J\approx+0.22$). Two capabilities are
missing: (i) a **unified, quantitative representation**, and (ii) a **reasoning
loop** turning suspicion into proof.

## 2. The core idea

```
artifact → IR (typed graph) → mathematical layers → V(x) → LLM agent → formal verifier
                     ↑__________________ re-embed __________________|
```

We model vulnerability *candidates* as violations of program invariants rather
than purely syntactic patterns (a broken authorization invariant, a persistent
cycle, a negative curvature chokepoint, a taint flow across a trust cut).

## 3. The Intermediate Representation (IR)

**Definition 1 (Program graph).** $G = (V, E, \tau_V, \tau_E, \omega)$ where
nodes carry a kind (module, function, block, statement, call, assign, variable,
parameter, source, sink, gate), edges carry a type (control, data, call, taint,
trust, auth), and $\omega$ is a non-negative weight. The IR is the single source
of truth, JSON-serializable, shared verbatim between the Python and Rust layers.

## 4. Mathematical layers

### 4.1 Spectral
$L_t = D_t - A_t$; $\lambda_2$ (algebraic connectivity), the Fiedler vector, the
spectral embedding and the Cheeger bound. **Signal:** spectral anomaly.

### 4.2 Topological (TDA)
Persistent homology of a filtration; $\beta_0$ components, $\beta_1$ independent
cycles; persistence diagrams; Mapper builds the navigable nerve. **Signal:**
persistence outliers / long-lived $H_1$ generators.

### 4.3 Geometric
Ollivier–Ricci $\kappa(u,v) = 1 - W_1(m_u,m_v)/d(u,v)$ (exact LP, or Sinkhorn
entropic approximation); Forman–Ricci $\kappa_F = 4 - \deg(u) - \deg(v)$.
**Signal:** curvature chokepoints.

### 4.4 Algebraic
The taint lattice $\mathbb{T} = \{\bot = \text{clean} \sqsubseteq \top = \text{tainted}\}$
and a Galois connection $(\alpha, \gamma)$. The **privilege-level function**
$F: V \to \mathbb{N}$ assigns each point a level; an edge $(u,v)$ is an *auth edge*
iff $F(u) < F(v)$. **Proposition (authorization-invariant violation):** a taint flow
violates the invariant iff its path crosses an `auth` edge without a sanitizer —
the operational rule H4/§8 (proof in the PDF, §4.6; the no-auth part is
mechanized in Lean 4). No
category-theoretic natural transformation is claimed.

### 4.5 Formal
Symbolic execution computes a path condition $\Phi$; an SMT solver checks
$\mathrm{SAT}(\phi_{\text{bad}})$; reachability is the CTL formula
$\mathbf{EF}\,\phi_{\text{bad}}$; taint is a finite automaton.

## 5. The vulnerability scalar field

$$V(x) = \sigma\!\Big(\sum_i \alpha_i\, s_i(x)\Big).$$

Signals are normalized per layer; in the prototype the weights are **uniform**
($\alpha_i = 1/N$) and $V$ is reported as the raw fused score; calibration is
done by logistic regression over labeled data (§11.1).

## 6. Mapping hypotheses

| # | Feature | Class |
|---|---------|-------|
| H1 | $\kappa \ll 0$ chokepoint | privilege escalation |
| H2 | persistent $H_1$ generator | reentrancy / recursion |
| H3 | Fiedler cut | injection across trust |
| H4 | taint crossing an `auth` edge | authorization-invariant violation |
| H5 | persistence outlier | real vs. spurious |
| H6 | $\mathrm{SAT}(\phi_{\text{bad}})$ | model witness (encoded semantics) |

These are *falsifiable hypotheses*, not laws; H1/H2/H3/H5 are not supported on the
evaluated corpora.

## 7. The autonomous LLM agent

Closed loop: **map → rank → hypothesize → verify → refine → report**. The
manifold supplies a structured spec `(sink, source, line, category)`; the LLM
supplies the interpretation (CWE, description); the verifier consumes the spec —
never the LLM prose. Provider layer via **LiteLLM** (OpenAI/Anthropic/local), with
a deterministic offline fallback.

## 8. Design challenges and mitigations

* **C1 — Bottleneck paradox.** Negative curvature flags legitimate defensive
  chokepoints; we discriminate them by role / `auth` target.
* **C2 — Symmetrization.** Direction is preserved via Chung's directed Laplacian
  over the largest SCC (Perron vector by PageRank-style iteration); DAGs are
  handed to the lattice/reachability layers.
* **C3 — Transport cost.** Forman–Ricci is the default ($O(|E|)$); Ollivier–Ricci
  with Sinkhorn is the fast alternative.
* **C4 — H4 operationalization.** A taint flow crossing an `auth` edge is an
  authorization-invariant violation (reachability over `data ∪ taint ∪ auth`).
* **C5 — Manifold→verifier bridge.** Fixed verification grammar; the LLM never
  emits SMT-LIB.

## 9. A worked example

```python
def search(db, query_param):
    sql = "SELECT * FROM users WHERE name = '" + query_param + "'"
    cursor = db.cursor()
    cursor.execute(sql)
```

The pipeline yields a `source` node (`param:query_param`), a `sink` node
(`cursor.execute`, category `sql`) and a `taint` edge; $V(x)$ spikes at the sink;
Z3 returns `SAT` with a model witness under the encoded semantics (not an
end-to-end exploit). The parameterized variant is correctly not flagged, and an
`@login_required` gate upgrades the finding to an H4 authorization violation.

## 10. Implementation status

F0 whitepaper · F1 IR + Python SAST + taint · F2 spectral/geometric (Rust) ·
F3 TDA · F4 Z3 verifier + taint lattice + H4 · F5 autonomous LLM agent ·
F6 visualization + demo · F7 multi-domain adapters (binary objdump/angr, OpenAPI,
LLM-agent, Java). Plus benchmark harness, weight calibration, and the OWASP study.

## 11. Validation and empirical study

**Stage 1 (complete):** toy micro-benchmarks; every seeded vulnerability confirmed,
every sanitizer / parameterized-query / argv-form false positive excluded.

**Stage 2 (in progress):** labeled corpora.

### 11.1 Empirical study on OWASP Benchmark 1.2

Profiling the full corpus, three *generalizable* gaps were fixed: (i) **branch-aware
taint** (join of branch environments — the lattice least-upper-bound), (ii)
**receiver/state taint** (sinks like `statement.execute()` carry taint in the
object; mutators taint their receiver), (iii) **response-writer restriction** for
XSS (`System.out.println` is not XSS). Ablation (taint categories, 1698 cases):

| Variant | P | R | F1 |
|---|---|---|---|
| initial naive adapter | 0.515 | 0.426 | 0.466 |
| + branch-join, receiver/state, sink coverage | 0.530 | 0.856 | 0.655 |
| + XSS writer restriction (final) | **0.549** | **0.834** | **0.662** |
| final, without branch-join | 0.515 | 0.555 | 0.535 |

### 11.2 Comparison and the neuro-symbolic target

| Tool | TPR | FPR | Prec. | F1 | J |
|---|---|---|---|---|---|
| SonarQube (reported) | 0.956 | 0.946 | 0.330 | 0.490 | +0.010 |
| CodeQL (reported) | 0.902 | 0.682 | 0.603 | 0.744 | +0.220 |
| **MANIFOLD adapter (measured)** | 0.842 | 0.674 | 0.572 | 0.681 | **+0.168** |
| MANIFOLD adapter + Z3 (measured, taint) | 0.834 | 0.776 | 0.549 | 0.662 | +0.057 |

*External rows are reported in public evaluations; MANIFOLD adapter is measured
(all eleven categories); the last two rows are the **projected** Stage-2 target,
not measured (Z3 with a 5 s per-query timeout; on timeout the case is marked
unknown/conservative, never counted as a detection).*

### 11.3 Dual binary backend

Two interchangeable backends emit the same IR: a zero-dependency `objdump`-text
path and an optional `angr` backend (`CFGFast` + interprocedural taint).

## 12. Responsible use

MANIFOLD is a defensive / authorized-testing tool; released under the assumption
of authorized use and coordinated disclosure.

## 13. References

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

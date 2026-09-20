# MANIFOLD — A Mathematical Engine for Mapping Vulnerabilities

**Whitepaper v0.1** · *Working draft — not peer reviewed*

> *"Map the code as a space; let the geometry of that space reveal the flaw."*

---

## Abstract

MANIFOLD treats a software artifact not as a bag of rules to match, but as a
**mathematical object**: a typed, weighted graph enriched with *algebraic*,
*spectral*, *topological* and *geometric* structure. Over this object we compute
a scalar field of **vulnerability potential** $V(x)$, which surfaces anomalous
regions as geometric/topological/spectral *features* rather than as literal
string matches. An **autonomous LLM agent** navigates the resulting "manifold",
formulates hypotheses about those regions, and dispatches **formal verifiers**
(SMT, symbolic execution, abstract interpretation) that confirm or refute each
hypothesis — closing the loop between statistical intuition and mathematical
proof.

This document defines the intermediate representation, formalizes each
mathematical layer, states the mapping laws that connect mathematical features
to vulnerability classes, and specifies the agent architecture and roadmap.

---

## 1. Motivation

Traditional scanners (SAST/DAST) enumerate syntactic patterns. They are
brittle: they miss novel vulnerabilities and drown analysts in false positives.
Two capabilities are missing:

1. **A unified, quantitative representation** of "program structure" onto which
   many *independent* signals can be projected and fused.
2. **A reasoning loop** that converts "suspicious region" into "proven
   vulnerability" — the LLM supplies the intuition, mathematics supplies the
   proof.

MANIFOLD provides both.

## 2. The core idea

```
artifact ──► IR (typed graph) ──► mathematical layers ──► scalar field V(x)
                                        │                        │
                                        └── embeddings/persistence/curvature
                                                               │
                                                  AGENT LLM  ◄─┘  (navigate, hypothesize)
                                                               │
                                                  formal verifiers (prove/refute)
```

A vulnerability is **not** a pattern; it is a *violation of a structural
invariant* (a broken naturality condition, a persistent cycle, a negative
curvature chokepoint, a taint flow across a spectral trust cut). Each layer
detects a different *kind* of invariant violation, and the fused field $V(x)$
ranks regions for the agent to inspect.

## 3. The Intermediate Representation (IR)

### Definition 1 (Program graph)

A **program graph** is a tuple

$$
G = (V, E, \tau_V, \tau_E, \omega)
$$

where

* $V$ is a finite set of **nodes** (modules, functions, blocks, statements,
  calls, variables, sources, sinks);
* $E \subseteq V \times V$ is a set of directed **edges**;
* $\tau_V : V \to \mathbb{N}_K$ assigns each node a **kind** from a fixed set
  $K = \{\text{module, function, block, statement, call, assign, variable, parameter, source, sink}\}$;
* $\tau_E : E \to \mathcal{T}$ assigns each edge a **type**
  $\mathcal{T} = \{\text{control, data, call, taint, trust, auth}\}$;
* $\omega : E \to \mathbb{R}_{\ge 0}$ assigns each edge a non-negative **weight**
  (default $1$; used later for curvature and persistence).

The IR is the single source of truth. Every adapter (source code, binary, web
API, LLM agent) must produce a program graph; every analysis consumes it. The
schema is language-agnostic and JSON-serializable (the Python and Rust layers
share the identical schema).

## 4. Mathematical layers

For each layer we fix a subgraph by edge type $\tau_E$, then compute structure.

### 4.1 Spectral layer (algebraic graph theory)

For an edge type $t$, define the symmetric **adjacency** $A_t$ and **degree**
$D_t$, and the **combinatorial Laplacian**

$$
L_t = D_t - A_t.
$$

$L_t$ is positive semidefinite; its spectrum $0 = \lambda_1 \le \lambda_2 \le \cdots$ encodes
global structure:

* $\lambda_2$ is the **algebraic connectivity** (Fiedler value). Its eigenvector
  $f_2$ — the **Fiedler vector** — induces a canonical cut $S^+ = \{v : f_2(v) \ge 0\}$.
* The **spectral embedding** $\Phi^{(d)}(v) = (f_2(v), f_3(v), \dots, f_{d+1}(v))$ maps
  nodes into $\mathbb{R}^d$ so that graph distance is approximately Euclidean distance.
* The Cheeger inequality bounds the **bottleneck ratio** $h(G)$ by
  $\frac{\lambda_2}{2} \le h(G) \le \sqrt{2\,d_{\max}\lambda_2}$.

**Signal 1 (spectral anomaly).** The *reconstruction error* of a node under a
low-rank eigenmap reconstruction, and its distance from the Fiedler cut, are
used as anomaly scores: nodes that "don't fit" the low-dimensional skeleton are
candidates for inspection.

### 4.2 Topological layer (persistent homology)

From the program graph we build a **filtration** of simplicial complexes — e.g. a
Vietoris–Rips or flag (clique) complex over the shortest-path metric, or a
filtration driven by the edge weight $\omega$. Applying persistent homology
yields, for each dimension $k$, a **persistence diagram** $\mathrm{Dgm}_k$ of
birth–death pairs.

* $\beta_0$ counts connected components (modules, unreachable islands).
* $\beta_1$ counts **independent cycles** — loops in the call/data-flow graph.
* Points in $\mathrm{Dgm}_k$ far from the diagonal have high **persistence**
  $\mathrm{death} - \mathrm{birth}$ and represent robust features; near-diagonal
  points are topological noise.

**Signal 2 (persistence outliers).** Long-lived $H_1$ generators and high-persistence
points are ranked as structurally significant.

The **Mapper** algorithm (Singh–Mémoli–Carlsson) produces a *visual* map: choose a
filter function $f : V \to \mathbb{R}$ (e.g. the vulnerability field itself, or node
centrality), cover its image by overlapping intervals, cluster each fiber, and
build the **nerve** (a graph whose nodes are clusters). Mapper yields the
navigable "manifold" that gives the project its name.

### 4.3 Geometric layer (discrete curvature)

The **Ollivier–Ricci curvature** of an edge $(u,v)$ is

$$
\kappa(u,v) = 1 - \frac{W_1(m_u, m_v)}{d(u,v)},
$$

where $m_u, m_v$ are probability measures concentrated around $u,v$ (e.g. lazy
random-walk measures) and $W_1$ is the Wasserstein-1 distance. Negative
curvature means *more* mass must be moved than the edge's own length — i.e. the
edge is a **funnel** through which many shortest paths pass.

For hierarchical artifacts (call graphs, dependency graphs) we additionally embed
the graph into a **hyperbolic** space (Poincaré ball) and measure
$\delta$-hyperbolicity; trees have $\delta = 0$.

**Signal 3 (curvature chokepoints).** Strongly negative $\kappa$ marks chokepoints —
single functions through which privilege or data must pass — the natural location
of privilege-escalation and authorization bugs.

### 4.4 Algebraic layer (lattices & category theory)

*Abstract interpretation.* A program is a monotone map over a lattice of abstract
values. The **taint lattice** is

$$
\mathbb{T} = \{\bot = \text{clean} \sqsubseteq \top = \text{tainted}\}
$$

(instantiated per taint tag, giving a product lattice over tags). Sources assign
$\top$; transfer functions propagate it; a sink reached by $\top$ is a violation.
This is a **Galois connection** $(\alpha, \gamma)$ between the concrete collecting
semantics and the abstract taint domain, guaranteeing soundness
(no missed flows) at the cost of precision (possible false positives).

*Category theory.* Regard the program as a category $\mathbf{Prog}$: objects are
program points / value types, morphisms are computations, and composition is
sequencing. Effects (I/O, environment) are **monads**; authorization is a functor
$F : \mathbf{Prog} \to \mathbf{Auth}$ that composes safely only along trusted paths.

**Design law (naturality of taint).** A **taint flow** is a morphism
$s \xrightarrow{\,t\,} k$ from a source to a sink. *Safe* programs preserve
naturality of the authorization functor: applying $F$ to a composition equals
composing the images. A vulnerability is a taint flow that breaks the
naturality square — the taint reaches a sink "as if" authorization had been
applied when it has not.

### 4.5 Formal layer (symbolic execution & model checking)

* Symbolic execution computes a path condition $\Phi$ and symbolic state $\sigma$;
  a bad state is $\sigma$ where a sink consumes a symbol marked tainted.
* An SMT solver checks $\mathrm{SAT}\left(\Phi \wedge \text{taint\_reaches\_sink}\right)$ —
  a *model* is a concrete exploit.
* Reachability of a bad state is the CTL formula $\mathbf{EF}\,\mathrm{bad}$.
* Taint propagation is a **finite automaton**: sources are initial states, sinks
  accepting states; the accepted language is exactly the set of source→sink paths.

**Signal 4 (formal ground truth).** Unlike the previous layers (which are
*heuristic features*), the formal layer produces *proofs*. It is the arbiter
that turns agent hypotheses into confirmed findings.

## 5. The vulnerability scalar field

Each layer yields a node-level or edge-level score. We **fuse** them into a field

$$
V(x) = \sigma\!\Big(\sum_i \alpha_i \, s_i(x)\Big),
$$

where $s_i$ are the normalized layer signals (spectral anomaly, persistence
outlier, curvature, lattice height, formal reachability) and $\alpha_i$ are
learnable (or hand-tuned) weights, with $\sigma$ a logistic squeeze. $V$ is:

* a **ranking** for the agent (inspect highest $V$ first),
* a **filter function** for Mapper,
* a **cost field** over which the agent plans navigation.

## 6. Mapping laws (feature → vulnerability class)

These are *design hypotheses* to be validated empirically; each is stated with
the mathematical object that supports it.

| # | Law | Mathematical object | Vulnerability class |
|---|-----|---------------------|---------------------|
| L1 | Chokepoint | $\kappa(u,v) \ll 0$ | privilege escalation, auth bypass |
| L2 | Cycle | generator of $H_1$ (persistent) | reentrancy, infinite recursion, deadlock |
| L3 | Trust cut | Fiedler cut of control+data graph | injection crossing trust boundary |
| L4 | Naturality break | taint flow violating $F$-naturality | arbitrary taint violation |
| L5 | Persistence | far-from-diagonal $\mathrm{Dgm}_k$ points | *real* vs. spurious feature separation |
| L6 | Reachability | $\mathrm{SAT}(\Phi \wedge \text{bad})$ | concrete exploit path |

## 7. The autonomous LLM agent

The agent is a closed loop with explicit mathematical grounding:

1. **Ingest** — parse the artifact into the IR.
2. **Embed & map** — compute $V(x)$, spectral embedding, persistence diagrams,
   curvature; build the Mapper manifold.
3. **Hypothesize** — the LLM, given the manifold (top regions, their code, and
   the *features* that flagged them), proposes candidate vulnerabilities.
4. **Verify** — the formal layer (SMT / symbolic execution / abstract
   interpretation) proves or refutes each candidate.
5. **Refine** — confirmed findings add/weight taint/trust edges and are
   re-embedded; refuted hypotheses are recorded as negative examples.
6. **Report** — a human- and machine-readable report citing, for each finding,
   the *mathematical feature* that surfaced it and the *proof* that confirmed it.

**LLM provider layer.** The agent targets any OpenAI-compatible endpoint through
**LiteLLM**, so it runs unchanged against OpenAI/Anthropic "cyber" models or
local models (Ollama, etc.).

**Why the LLM does not do raw detection.** LLMs are unreliable *classifiers* but
strong *reasoners*. MANIFOLD splits responsibilities: the mathematics proposes
*regions* (cheap, sound-ish, no hallucination), the LLM proposes *hypotheses*
(rich, contextual), the formal layer proposes *proofs* (sound). Each component
does what it is good at.

## 8. System architecture

```
ingest/  (Python)         core/  (Rust)             agent/  (Python)        viz/  (TS)
├─ tree-sitter AST        ├─ graph (serde)          ├─ LiteLLM provider      ├─ manifold map
├─ CFG/DFG/call graph     ├─ spectral (Laplacian)   ├─ hypothesis generator  ├─ persistence diag
├─ source/sink profiles   ├─ topology (F3)          ├─ verifier bridge       ├─ spectral plots
└─ taint pass  ─────────► └─ geometry (F2) ───────► └─ memory/reflection ──► └─ findings panel
        │                        │
        └──── JSON IR (shared schema) ────┘
```

The IR JSON is the contract between Python and Rust (both consume/produce the
identical schema; the Rust side is verified by `cargo test`).

## 9. Implementation status

| Phase | Deliverable | Status |
|-------|-------------|--------|
| F0 | Whitepaper (en/es), architecture | ✅ this document |
| F1 | IR + Python SAST ingest (tree-sitter) + intraprocedural taint | ✅ implemented, tested |
| F2 | Spectral + geometric kernels (Rust, Fiedler vector, Ricci, hyperbolic embedding) | ✅ implemented, tested |
| F3 | TDA (persistent homology H0/H1, Mapper) | ✅ implemented, tested |
| F4 | Formal verification (taint lattice + sanitizers, Z3 symbolic verifier) | ✅ implemented, tested |
| F5 | Autonomous LLM agent (LiteLLM, offline fallback) | ✅ implemented, tested |
| F6 | Visualization (self-contained HTML) + end-to-end demo | ✅ implemented, tested |
| F7 | Binary / web / LLM adapters (multi-domain) | ✅ implemented, tested |

## 10. Validation plan

* **Micro-benchmarks**: toy vulnerable programs (SQLi, command injection,
  code execution, reentrancy) with known ground truth; assert each layer's
  signal is present and correctly located.
* **Precision/recall**: compare against a labeled corpus (e.g. OWASP Benchmark,
  SARD) once F4 lands; report false-positive rate of the fused field vs. the
  raw taint pass.
* **Agent efficacy**: measure hypothesis-to-confirmation rate and coverage of
  seeded vulnerabilities in synthetic repos.

## 11. Responsible use

MANIFOLD is a defensive/authorized-testing tool. The same geometry that reveals
vulnerabilities to a defender reveals them to an attacker; we release under the
assumption of authorized use and encourage coordinated disclosure.

## 12. References

1. Fiedler, M. (1973). *Algebraic connectivity of graphs.*
2. Chung, F. (1997). *Spectral Graph Theory.*
3. Edelsbrunner, Letscher, Zomorodian (2002). *Topological persistence and simplification.*
4. Singh, Mémoli, Carlsson (2007). *Topological Methods for the Analysis of High Dimensional Data Sets and 3D Object Recognition.*
5. Ollivier, Y. (2009). *Ricci curvature of Markov chains on metric spaces.*
6. Cousot, P. & Cousot, R. (1977). *Abstract interpretation: a unified lattice model.*
7. Mac Lane, S. (1971). *Categories for the Working Mathematician.*
8. King, J. (1976). *Symbolic execution and program testing.*
9. Clarke, E. M. et al. (1986). *Automatic verification of finite-state concurrent systems.*

"""The prioritization-oracle experiment (the paper's centrepiece).

For each labeled test case we enumerate *all* sink calls (candidates) and rank
them with the vulnerability field $V(x)$. The metric is the rank at which a
ground-truth-vulnerable sink appears, compared against baselines (DFS order, raw
taint order, random). We also report the *cost curve*: cumulative fraction of
vulnerable sinks reached as a function of verification queries.

The verification oracle is the ground-truth label here; a real Z3 backend can
replace it behind the same interface.
"""

from __future__ import annotations

import math as _math
import random
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from .analysis.field import signal_fields, vulnerability_field
from .analysis.math_core import run_core
from .ingest.java import JavaIngest, enumerate_sinks

BASELINES = ("field", "taint", "dfs", "random")
SIGNALS = ("taint", "formal", "spectral", "topological", "geometric")


@dataclass
class Candidate:
    line: int
    name: str
    category: str
    tainted: bool = False
    score: float = 0.0
    signals: Dict[str, float] = field(default_factory=dict)


def _sink_node_index(graph) -> Dict[tuple, str]:
    idx: Dict[tuple, str] = {}
    for n in graph.nodes:
        if n.kind.value == "sink":
            idx[(n.line, n.label, n.attrs.get("category"))] = n.id
    return idx


def analyze_case(code: str) -> List[Candidate]:
    """Analyze once: candidates with taint flag and V(x) score."""
    sinks = [Candidate(**s) for s in enumerate_sinks(code)]
    result = JavaIngest().analyze(code)
    tainted = {(f.category, f.line) for f in result.findings}
    for c in sinks:
        c.tainted = (c.category, c.line) in tainted
    try:
        math = run_core(result.graph)
        field_map = vulnerability_field(result.graph, math=math, findings=result.findings)
        signals = signal_fields(result.graph, math=math, findings=result.findings)
    except Exception:
        field_map, signals = {}, {}
    idx = _sink_node_index(result.graph)
    for c in sinks:
        sid = idx.get((c.line, c.name, c.category))
        c.score = field_map.get(sid, 0.0) if sid else 0.0
        c.signals = {k: (signals.get(k, {}).get(sid, 0.0) if sid else 0.0) for k in SIGNALS}
    return sinks


def order_signal(sinks: Sequence[Candidate], signal: str) -> List[Candidate]:
    """Rank candidates by a single field signal (per-signal ablation)."""
    return sorted(sinks, key=lambda c: (-c.signals.get(signal, 0.0), c.line))


def order(sinks: Sequence[Candidate], method: str, seed: int = 0) -> List[Candidate]:
    if method == "dfs":
        return sorted(sinks, key=lambda c: c.line)
    if method == "taint":
        return sorted(sinks, key=lambda c: (not c.tainted, c.line))
    if method == "random":
        out = list(sinks)
        random.Random(seed).shuffle(out)
        return out
    if method == "field":
        return sorted(sinks, key=lambda c: (-c.score, c.line))
    raise ValueError(f"unknown method {method!r}")


def rank_of_target(ranking: Sequence[Candidate], category: str) -> int:
    for i, c in enumerate(ranking, 1):
        if c.category == category:
            return i
    return len(ranking) + 1


def _ndcg_at_k(rank: int, k: int) -> float:
    return 1.0 / _math.log2(rank + 1) if rank <= k else 0.0


@dataclass
class RankingMetrics:
    n: int = 0
    mrr: float = 0.0
    recall_at_1: float = 0.0
    mean_rank: float = 0.0
    ndcg_at_5: float = 0.0
    ranks: List[int] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "n": self.n,
            "mrr": round(self.mrr, 4),
            "recall@1": round(self.recall_at_1, 4),
            "mean_rank": round(self.mean_rank, 3),
            "ndcg@5": round(self.ndcg_at_5, 4),
        }


def _metrics(ranks: List[int]) -> RankingMetrics:
    m = RankingMetrics(n=len(ranks), ranks=ranks)
    if ranks:
        m.mrr = sum(1.0 / r for r in ranks) / len(ranks)
        m.recall_at_1 = sum(1 for r in ranks if r == 1) / len(ranks)
        m.mean_rank = sum(ranks) / len(ranks)
        m.ndcg_at_5 = sum(_ndcg_at_k(r, 5) for r in ranks) / len(ranks)
    return m


def evaluate_cached(cache: Sequence[Tuple[List[Candidate], str]], method: str, seed: int = 0) -> RankingMetrics:
    """``cache`` is a list of (candidates, target_category)."""
    ranks = [rank_of_target(order(cands, method, seed), cat) for cands, cat in cache]
    return _metrics(ranks)


def evaluate_signal_cached(cache: Sequence[Tuple[List[Candidate], str]], signal: str) -> RankingMetrics:
    """Per-signal ranking ablation: rank by a single field signal."""
    ranks = [rank_of_target(order_signal(cands, signal), cat) for cands, cat in cache]
    return _metrics(ranks)


def cost_curve(ranks: Sequence[int], budget: int) -> List[float]:
    n = len(ranks)
    if n == 0:
        return [0.0] * budget
    return [sum(1 for r in ranks if r <= b) / n for b in range(1, budget + 1)]


def reciprocal_ranks(cache: Sequence[Tuple[List[Candidate], str]], method: str, seed: int = 0) -> List[float]:
    return [1.0 / rank_of_target(order(c, method, seed), cat) for c, cat in cache]


def paired_permutation(a: Sequence[float], b: Sequence[float], iters: int = 20000, seed: int = 0) -> dict:
    """Paired permutation test on the difference of means.

    Returns the observed mean difference, a 95\\% bootstrap CI and a two-sided
    permutation p-value. Used to test ``taint`` vs the fused field.

    The p-value uses the standard add-one estimator ``(b + 1) / (N + 1)`` so it
    is never reported as exactly zero.
    """
    rnd = random.Random(seed)
    n = min(len(a), len(b))
    diffs = [a[i] - b[i] for i in range(n)]
    obs = sum(diffs) / n if n else 0.0

    # bootstrap CI of the mean difference
    boots = []
    for _ in range(2000):
        s = sum(diffs[rnd.randrange(n)] for _ in range(n)) / n if n else 0.0
        boots.append(s)
    boots.sort()
    lo = boots[int(0.025 * len(boots))]
    hi = boots[int(0.975 * len(boots)) - 1]

    # two-sided permutation: flip each pair's sign at random
    ge = 0
    for _ in range(iters):
        stat = sum(diffs[i] if rnd.random() < 0.5 else -diffs[i] for i in range(n)) / n if n else 0.0
        if abs(stat) >= abs(obs):
            ge += 1
    p = (ge + 1) / (iters + 1)
    return {"mean_diff": obs, "ci95": [lo, hi], "p_value": p, "n": n, "iters": iters}


def global_metrics(
    entries: Sequence[Tuple[List[Candidate], str, bool]],
    method: str = "taint",
    seed: int = 0,
    ks: Sequence[int] = (10, 50, 100),
) -> dict:
    """Global-pool ranking over *all* candidates (safe and vulnerable cases).

    ``entries`` is a list of ``(candidates, target_category, vulnerable)``. A
    candidate is *relevant* iff its case is truly vulnerable and its category is
    the target. Returns precision@k, recall@k, average precision (PR-AUC) and the
    number of queries needed to reach 90% recall.
    """
    pool: List[Tuple[float, bool]] = []  # (key, relevant)
    for cands, cat, vuln in entries:
        for c in cands:
            relevant = bool(vuln and c.category == cat)
            if method == "random":
                key = 0.0
            elif method == "dfs":
                key = (c.line,)
            elif method == "taint":
                key = (not c.tainted, c.line)
            else:  # field (V_prior): tainted first, then structural score
                key = (not c.tainted, -c.score, c.line)
            pool.append((key, relevant))

    if method == "random":
        rnd = random.Random(seed)
        rnd.shuffle(pool)
    else:
        pool.sort(key=lambda p: p[0])

    relevant_flags = [rel for _, rel in pool]
    total_rel = sum(1 for r in relevant_flags if r)
    running = 0
    precisions: List[float] = []
    recalls: List[float] = []
    queries_90 = None
    for i, rel in enumerate(relevant_flags, 1):
        running += 1 if rel else 0
        precisions.append(running / i)
        rec = running / total_rel if total_rel else 0.0
        recalls.append(rec)
        if queries_90 is None and rec >= 0.9:
            queries_90 = i
    ap = sum(precisions[i] for i in range(len(relevant_flags)) if relevant_flags[i]) / total_rel if total_rel else 0.0
    out = {
        "candidates": len(pool),
        "relevant": total_rel,
        "average_precision": round(ap, 4),
        "queries_to_90_recall": queries_90,
    }
    for k in ks:
        out[f"precision@{k}"] = round(sum(1 for r in relevant_flags[:k] if r) / k, 4) if k <= len(relevant_flags) else None
        out[f"recall@{k}"] = round(sum(1 for r in relevant_flags[:k] if r) / total_rel, 4) if total_rel else 0.0
    return out


def _auc(points: Sequence[Tuple[float, int]]) -> float:
    """Rank-based AUC (Mann-Whitney) for (score, label) points."""
    pos = [s for s, l in points if l == 1]
    neg = [s for s, l in points if l == 0]
    if not pos or not neg:
        return 0.5
    ranked = sorted(points, key=lambda p: p[0])
    # average ranks for ties
    ranks = [0.0] * len(ranked)
    i = 0
    while i < len(ranked):
        j = i
        while j + 1 < len(ranked) and ranked[j + 1][0] == ranked[i][0]:
            j += 1
        avg = (i + j) / 2.0 + 1.0
        for k in range(i, j + 1):
            ranks[k] = avg
        i = j + 1
    rank_sum_pos = sum(ranks[k] for k in range(len(ranked)) if ranked[k][1] == 1)
    n_pos, n_neg = len(pos), len(neg)
    return (rank_sum_pos - n_pos * (n_pos + 1) / 2.0) / (n_pos * n_neg)


def signal_aucs(
    cache: Sequence[Tuple[List[Candidate], str]],
    seed: int = 0,
    iters: int = 200,
) -> Dict[str, dict]:
    """AUC of each signal for predicting `candidate is the ground-truth sink`."""
    rnd = random.Random(seed)
    data: Dict[str, List[Tuple[float, int]]] = {k: [] for k in SIGNALS}
    for cands, target in cache:
        for c in cands:
            label = 1 if c.category == target else 0
            for k in SIGNALS:
                data[k].append((c.signals.get(k, 0.0), label))

    out: Dict[str, dict] = {}
    for k, pts in data.items():
        base = _auc(pts)
        boots = []
        for _ in range(iters):
            sample = [pts[rnd.randrange(len(pts))] for _ in range(len(pts))]
            boots.append(_auc(sample))
        boots.sort()
        lo = boots[int(0.025 * len(boots))]
        hi = boots[int(0.975 * len(boots)) - 1]
        out[k] = {"auc": round(base, 3), "ci95": [round(lo, 3), round(hi, 3)]}
    return out

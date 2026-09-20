r"""Calibration of the vulnerability field weights.

The field $V(x) = \sigma(\sum_i \alpha_i s_i(x))$ needs its weights
``alpha_i``. Here they are learned from a labeled benchmark with a small
pure-Python logistic regression over the *cheap* per-layer signals (taint,
spectral, topological, geometric) --- deliberately excluding the expensive
``formal`` (Z3) signal, so the calibrated detector approximates the verifier's
precision at a fraction of the cost.
"""

from __future__ import annotations

import math
from typing import Callable, Dict, List, Sequence, Tuple

from .field import signal_fields
from .math_core import run_core
from ..ingest.python import PythonIngest

# The cheap signals used as features (the formal/Z3 signal is the expensive one
# we want to *approximate*, not consume).
FEATURE_KEYS: Tuple[str, ...] = ("taint", "spectral", "topological", "geometric")


def extract_features(code: str) -> Dict[str, float]:
    """Aggregate each cheap signal into a single scalar (max over nodes)."""
    result = PythonIngest().analyze(code)
    try:
        math = run_core(result.graph)
    except Exception:
        math = None
    signals = signal_fields(result.graph, math=math, findings=result.findings)
    features: Dict[str, float] = {}
    for k in FEATURE_KEYS:
        vals = signals.get(k, {})
        features[k] = max(vals.values()) if vals else 0.0
    return features


def feature_vector(code: str) -> List[float]:
    feats = extract_features(code)
    return [feats[k] for k in FEATURE_KEYS]


def sigmoid(z: float) -> float:
    return 1.0 / (1.0 + math.exp(-max(-50.0, min(50.0, z))))


def logistic_regression(
    X: Sequence[Sequence[float]],
    y: Sequence[int],
    lr: float = 0.5,
    iters: int = 1000,
) -> Tuple[List[float], float]:
    """Gradient-descent logistic regression (pure Python). Returns (w, b)."""
    n = len(X)
    d = len(X[0])
    w = [0.0] * d
    b = 0.0
    for _ in range(iters):
        gw = [0.0] * d
        gb = 0.0
        for i in range(n):
            z = b + sum(w[j] * X[i][j] for j in range(d))
            err = sigmoid(z) - y[i]
            gb += err
            for j in range(d):
                gw[j] += err * X[i][j]
        for j in range(d):
            w[j] -= lr * gw[j] / n
        b -= lr * gb / n
    return w, b


def calibrate(
    codes: Sequence[str],
    labels: Sequence[int],
    lr: float = 0.5,
    iters: int = 1000,
) -> Tuple[List[float], float]:
    """Fit ``(weights, bias)`` from labeled source code."""
    X = [feature_vector(c) for c in codes]
    return logistic_regression(X, labels, lr=lr, iters=iters)


def calibrated_detector(weights: Sequence[float], bias: float) -> Callable[[str], bool]:
    """Return a ``code -> bool`` detector using the learned field weights."""

    def detector(code: str) -> bool:
        x = feature_vector(code)
        z = bias + sum(w * v for w, v in zip(weights, x))
        return sigmoid(z) > 0.5

    return detector

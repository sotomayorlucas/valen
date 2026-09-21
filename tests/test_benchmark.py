"""Tests for the benchmark harness and calibration."""

from valen.analysis.calibration import (
    FEATURE_KEYS,
    calibrated_detector,
    logistic_regression,
    sigmoid,
)
from valen.benchmark import Case, Metrics, evaluate, taint_detector, verified_detector


def test_metrics_counts():
    cases = [
        Case("tp", "def f(x):\n    return eval(x)\n", True),
        Case("fp", "def add(a, b):\n    return a + b\n", False),
    ]
    m = evaluate(cases, taint_detector)
    # tp predicted vuln, fp predicted safe
    assert (m.tp, m.fp, m.fn, m.tn) == (1, 0, 0, 1)
    assert m.precision == 1.0 and m.recall == 1.0


def test_taint_and_verified_detect_sqli():
    code = "def f(q):\n    db.execute('SELECT ' + q)\n"
    assert taint_detector(code)
    assert verified_detector(code)


def test_logistic_regression_separates():
    X = [[0.0, 0.0], [0.0, 1.0], [1.0, 0.0], [1.0, 1.0], [2.0, 0.0]]
    y = [0, 1, 1, 1, 1]
    w, b = logistic_regression(X, y, lr=0.5, iters=3000)
    for xi, yi in zip(X, y):
        p = sigmoid(b + sum(w[j] * xi[j] for j in range(2)))
        assert (p > 0.5) == bool(yi)


def test_calibrated_detector_uses_features():
    # A code snippet whose only signal is taint.
    code = "def f(q):\n    db.execute('SELECT ' + q)\n"
    w = {k: 0.0 for k in FEATURE_KEYS}
    w["taint"] = 5.0
    b = -1.0
    weights = [w[k] for k in FEATURE_KEYS]
    det = calibrated_detector(weights, b)
    assert det(code)  # taint feature fires

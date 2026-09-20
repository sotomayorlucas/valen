"""Benchmark harness: precision/recall evaluation of vulnerability detectors.

A *detector* is a callable ``code -> bool`` (does the program contain a
vulnerability?). The harness evaluates a detector against a labeled corpus and
reports precision, recall, F1 and the confusion matrix. The bundled detectors
are the raw taint pass, the Z3-verified taint pass, and (once calibrated) the
field-based detector.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, List

from .analysis.verifier import verify
from .ingest.python import PythonIngest

Detector = Callable[[str], bool]


@dataclass
class Case:
    name: str
    code: str
    vulnerable: bool


@dataclass
class Metrics:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.fn + self.tn

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 1.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def accuracy(self) -> float:
        return (self.tp + self.tn) / self.total if self.total else 1.0

    def as_dict(self) -> dict:
        return {
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "tn": self.tn,
            "precision": round(self.precision, 3),
            "recall": round(self.recall, 3),
            "f1": round(self.f1, 3),
            "accuracy": round(self.accuracy, 3),
        }

    def __repr__(self) -> str:
        return (
            f"Metrics(tp={self.tp}, fp={self.fp}, fn={self.fn}, tn={self.tn}, "
            f"precision={self.precision:.3f}, recall={self.recall:.3f}, f1={self.f1:.3f})"
        )


def taint_detector(code: str) -> bool:
    """Raw taint pass: any taint finding counts as vulnerable."""
    return bool(PythonIngest().analyze(code).findings)


def verified_detector(code: str) -> bool:
    """Formal layer: a Z3-confirmed flow counts as vulnerable."""
    return bool(verify(code))


def evaluate(cases: List[Case], detector: Detector) -> Metrics:
    m = Metrics()
    for case in cases:
        predicted = detector(case.code)
        if case.vulnerable and predicted:
            m.tp += 1
        elif case.vulnerable and not predicted:
            m.fn += 1
        elif not case.vulnerable and predicted:
            m.fp += 1
        else:
            m.tn += 1
    return m


def evaluate_report(cases: List[Case], detector: Detector) -> str:
    """Return a human-readable per-case + summary report."""
    lines = []
    for case in cases:
        predicted = detector(case.code)
        truth = "VULN" if case.vulnerable else "safe"
        pred = "VULN" if predicted else "safe"
        mark = "ok " if predicted == case.vulnerable else "MISS"
        lines.append(f"  [{mark}] {case.name:<28} truth={truth:<4} predicted={pred}")
    m = evaluate(cases, detector)
    lines.append("")
    lines.append(f"  precision={m.precision:.3f}  recall={m.recall:.3f}  f1={m.f1:.3f}")
    lines.append(f"  TP={m.tp} FP={m.fp} FN={m.fn} TN={m.tn}")
    return "\n".join(lines)

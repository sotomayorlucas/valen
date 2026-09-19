"""Ingest adapters: turn target artifacts into the unified IR."""

from __future__ import annotations

from .python import PythonIngest

__all__ = ["PythonIngest", "LANGUAGE_TO_INGEST"]


LANGUAGE_TO_INGEST = {
    "python": PythonIngest,
}

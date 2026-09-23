"""Dynamic analysis for Python source.

The pipeline mirrors VALEN's static/symbolic layers but produces *concrete*
evidence: it executes the target in an isolated child process under a trace
recorder, then triangulates the runtime trace against the static IR (coverage +
agreement). See ``trace.py``, ``runner.py`` and ``triangulate.py``.
"""

from .runner import DynamicResult, run_module
from .triangulate import triangulate

__all__ = ["DynamicResult", "run_module", "triangulate"]

"""Isolated, reproducible execution of a Python module under a trace recorder.

The runner launches a **fresh** child interpreter, so the target's code runs
completely out of the analyzer's process. Isolation is portable (no Docker
required) and best-effort:

* **resource limits** via ``resource.setrlimit`` (CPU seconds, address space,
  output file size, number of files) so a runaway target cannot wedge the host;
* **clean environment** -- only ``PYTHONPATH`` and a couple of safe vars survive;
* **clean cwd** -- a fresh temp directory (so the target cannot read the repo's
  files by relative path);
* **hard timeout** -- SIGKILL if the child overruns;
* **evidence** -- sha256 of the target source and of every input, plus the
  full trace JSON, so a run is reproducible.

Everything is deterministic: no randomness, no wall-clock in the trace (only a
coarse duration for the report).
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..ingest.sources_sinks import PYTHON

_TRACE_MAIN = str(Path(__file__).resolve().parent / "trace.py")
_REPO_ROOT = str(Path(__file__).resolve().parents[2])


@dataclass
class DynamicResult:
    """The outcome of one dynamic run: concrete runtime evidence."""

    target: str
    exit_code: int
    trace: Dict[str, Any]
    stdout: str
    stderr: str
    timed_out: bool = False
    evidence: Dict[str, str] = field(default_factory=dict)

    @property
    def coverage(self) -> List[Dict[str, Any]]:
        return self.trace.get("coverage", [])

    @property
    def covered_lines(self) -> set:
        return {(c["file"], c["line"]) for c in self.coverage}

    @property
    def sinks(self) -> List[Dict[str, Any]]:
        return self.trace.get("sinks", [])

    @property
    def sources(self) -> List[Dict[str, Any]]:
        return self.trace.get("sources", [])


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


def _preexec() -> None:
    """Best-effort sandboxing, applied before exec in the child."""
    try:
        import resource

        # CPU seconds (soft/hard), address space (bytes), file size (bytes),
        # number of open files.
        resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
        resource.setrlimit(resource.RLIMIT_AS, (2 * 1024 ** 3, 2 * 1024 ** 3))
        resource.setrlimit(resource.RLIMIT_FSIZE, (256 * 1024 ** 2, 256 * 1024 ** 2))
        resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
    except Exception:  # noqa: BLE001
        pass  # limits are best-effort on non-POSIX or when unavailable


def run_module(
    target: str,
    *,
    target_files: Optional[List[str]] = None,
    argv: Optional[List[str]] = None,
    timeout: float = 30.0,
) -> DynamicResult:
    """Execute ``target`` (a ``.py`` file) under the trace recorder.

    ``target_files`` is the set of files whose frames count as "the program"
    for coverage filtering; defaults to the target itself. ``argv`` becomes the
    target's ``sys.argv`` (argv[0] is the target path).
    """
    target_path = Path(target).resolve()
    if not target_path.exists():
        raise FileNotFoundError(target)

    files = target_files or [str(target_path)]
    trace_out = tempfile.mkstemp(suffix=".json", prefix="valen-trace-")[1]

    env = {
        "PYTHONPATH": _REPO_ROOT,
        "PYTHONUNBUFFERED": "1",
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "VALEN_TRACE_OUT": trace_out,
        "VALEN_SINKS": json.dumps(PYTHON.sinks),
        "VALEN_SOURCES": json.dumps(PYTHON.sources),
        "VALEN_ARGV": json.dumps([str(target_path)] + list(argv or [])),
    }

    cmd = [sys.executable, _TRACE_MAIN, str(target_path)] + [
        f"--target={f}" for f in files
    ]

    evidence = {
        "sha256_target": _sha256(target_path.read_bytes()),
        "target": str(target_path),
    }
    for i, a in enumerate(argv or []):
        evidence[f"sha256_argv_{i}"] = _sha256(a.encode())

    with tempfile.TemporaryDirectory(prefix="valen-dyn-") as cwd:
        try:
            proc = subprocess.run(
                cmd,
                cwd=cwd,
                env=env,
                capture_output=True,
                text=True,
                timeout=timeout,
                preexec_fn=_preexec,
            )
            exit_code = proc.returncode
            stdout, stderr = proc.stdout, proc.stderr
            timed_out = False
        except subprocess.TimeoutExpired:
            exit_code = -9
            stdout, stderr = "", "dynamic run timed out"
            timed_out = True

    trace: Dict[str, Any] = {}
    try:
        with open(trace_out, "r", encoding="utf-8") as f:
            trace = json.load(f)
    except Exception:  # noqa: BLE001
        trace = {"coverage": [], "calls": [], "sinks": [], "sources": []}
    finally:
        try:
            os.unlink(trace_out)
        except OSError:
            pass

    trace.setdefault("exit_code", exit_code)
    trace.setdefault("timed_out", timed_out)
    trace.setdefault("stdout_tail", stdout[-4000:])
    trace.setdefault("stderr_tail", stderr[-4000:])

    return DynamicResult(
        target=str(target_path),
        exit_code=exit_code,
        trace=trace,
        stdout=stdout,
        stderr=stderr,
        timed_out=timed_out,
        evidence=evidence,
    )

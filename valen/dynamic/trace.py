"""Runtime trace recorder for Python dynamic analysis.

This module runs *inside* the sandboxed child process (see ``runner.py``). It
records concrete runtime evidence without touching the target's code:

* **line coverage** via ``sys.settrace`` -- the ``(file, line)`` pairs executed;
* **sink / source hits** via ``sys.setprofile`` -- every call is inspected,
  including **C functions** (``c_call``), which is what lets us see dangerous
  stdlib operations like ``cursor.execute``/``os.system`` that ``settrace``
  silently skips. For each hit we capture the *caller's* locals as the concrete
  argument values that reached the dangerous operation;
* **call graph** -- concrete ``(caller, callee)`` pairs for the target's frames.

Everything is deterministic (sets/sorted lists, a coarse duration only). The
result is written to ``VALEN_TRACE_OUT`` as JSON. Self-contained: stdlib + a
plain-dict profile passed through env vars.
"""

from __future__ import annotations

import json
import os
import sys
import time
from typing import Dict, List, Optional, Set, Tuple


def _resolve_profile_name(name: str, mod: str, profile: Dict[str, str]) -> Optional[str]:
    """Match a call to a profile key (sink/source). Returns the profile key.

    Tries: ``module.name``, then ``name`` as a bare key, then ``name`` against
    the last component of every profile key. First hit wins.
    """
    if mod and f"{mod}.{name}" in profile:
        return f"{mod}.{name}"
    if name in profile:
        return name
    for key in profile:
        if key.rsplit(".", 1)[-1] == name:
            return key
    return None


def _call_name(arg, frame) -> str:
    """Best-effort function name for a profile 'call'/'c_call' event."""
    if isinstance(arg, type):
        return arg.__name__
    name = getattr(arg, "__name__", None)
    if name:
        return name
    # fall back to the frame's code name
    return frame.f_code.co_name


def _module_name(arg) -> str:
    for attr in ("__self__", "__module__"):
        obj = getattr(arg, attr, None)
        if obj is None:
            continue
        mod = getattr(obj, "__module__", None)
        if mod:
            return mod
        cls = getattr(obj, "__class__", None)
        if cls is not None:
            return getattr(cls, "__module__", "") or ""
    return ""


class TraceRecorder:
    """Collects runtime evidence. One instance per child process."""

    def __init__(
        self,
        target_files: List[str],
        sinks: Dict[str, str],
        sources: Dict[str, str],
        max_value_len: int = 200,
    ) -> None:
        self._prefixes = [os.path.abspath(f) for f in target_files]
        self._sinks = sinks
        self._sources = sources
        self._max_value_len = max_value_len

        self.lines: Set[Tuple[str, int]] = set()
        self.calls: List[Dict] = []
        self.sink_hits: List[Dict] = []
        self.source_hits: List[Dict] = []
        self._start = time.monotonic()

    # -- helpers -----------------------------------------------------------
    def _is_target(self, filename: str) -> bool:
        if not filename or filename.startswith("<"):
            return False
        f = os.path.abspath(filename)
        return any(f == p or f.startswith(p + os.sep) for p in self._prefixes)

    def _snapshot(self, frame, names: List[str]) -> Dict[str, str]:
        """Repr the named locals (no evaluation)."""
        out: Dict[str, str] = {}
        for n in names:
            if n in frame.f_locals:
                try:
                    s = repr(frame.f_locals[n])
                except Exception:  # noqa: BLE001
                    s = "<unrepr>"
                if len(s) > self._max_value_len:
                    s = s[: self._max_value_len] + "…"
                out[n] = s
        return out

    def _record_call(self, arg, frame) -> None:
        """Handle a 'call' (Python) or 'c_call' (C) profile event."""
        name = _call_name(arg, frame)
        mod = _module_name(arg)

        # 'call': frame is the callee; caller is frame.f_back.
        # 'c_call': frame is the caller; the C function has no Python frame.
        is_c = self._profile_event == "c_call"
        caller_frame = frame if is_c else frame.f_back
        caller_line = caller_frame.f_lineno if caller_frame else frame.f_lineno

        # Only sinks/sources reached from the *target's* code are meaningful;
        # the interpreter's own import/bootstrap machinery (os.remove,
        # pickle.loads, os.environ.get during import) is noise.
        caller_in_target = (
            caller_frame is not None
            and self._is_target(caller_frame.f_code.co_filename)
        )

        if caller_in_target:
            sink_key = _resolve_profile_name(name, mod, self._sinks)
            if sink_key:
                code = caller_frame.f_code
                varnames = list(code.co_varnames)
                self.sink_hits.append({
                    "name": sink_key,
                    "category": self._sinks[sink_key],
                    "callee": name,
                    "line": caller_line,
                    "args": self._snapshot(caller_frame, varnames),
                })

            src_key = _resolve_profile_name(name, mod, self._sources)
            if src_key:
                code = caller_frame.f_code
                varnames = list(code.co_varnames)
                self.source_hits.append({
                    "name": src_key,
                    "callee": name,
                    "line": caller_line,
                    "args": self._snapshot(caller_frame, varnames),
                })

        # call graph: only for the target's own Python frames
        if not is_c and caller_frame is not None and self._is_target(caller_frame.f_code.co_filename):
            caller_name = caller_frame.f_code.co_name
            self.calls.append({
                "caller": caller_name,
                "callee": name,
                "module": mod,
                "line": caller_line,
            })

    # -- profile hook (calls, incl. C) ------------------------------------
    def _profile(self, frame, event, arg):
        if event == "call" or event == "c_call":
            self._profile_event = event
            self._record_call(arg, frame)
        return self._profile

    # -- trace hook (line coverage only) -----------------------------------
    def _trace(self, frame, event, arg):
        if event == "line" and self._is_target(frame.f_code.co_filename):
            self.lines.add((frame.f_code.co_filename, frame.f_lineno))
        return self._trace

    def install(self) -> None:
        sys.setprofile(self._profile)
        sys.settrace(self._trace)

    def uninstall(self) -> None:
        sys.setprofile(None)
        sys.settrace(None)

    # -- serialization -----------------------------------------------------
    def to_dict(self) -> Dict:
        return {
            "duration_ms": round((time.monotonic() - self._start) * 1000.0, 3),
            "coverage": [{"file": f, "line": ln} for f, ln in sorted(self.lines)],
            "calls": self.calls,
            "sinks": self.sink_hits,
            "sources": self.source_hits,
        }


def _main() -> int:
    """Child bootstrap: run the target module under the recorder.

    ``sys.argv[1]`` is the module path; ``--target=FILE`` (repeatable) limits
    coverage to those files; ``VALEN_ARGV`` (JSON list) becomes ``sys.argv``;
    ``VALEN_SINKS``/``VALEN_SOURCES`` carry the taint profile; the trace JSON is
    written to ``VALEN_TRACE_OUT``.
    """
    module_path = sys.argv[1]
    target_files = [a[len("--target="):] for a in sys.argv if a.startswith("--target=")]
    if not target_files:
        target_files = [module_path]

    argv = json.loads(os.environ.get("VALEN_ARGV", "null"))
    if argv is not None:
        sys.argv = argv

    sinks = json.loads(os.environ.get("VALEN_SINKS", "{}"))
    sources = json.loads(os.environ.get("VALEN_SOURCES", "{}"))

    rec = TraceRecorder(target_files, sinks, sources)
    rec.install()
    try:
        import runpy
        runpy.run_path(module_path, run_name="__main__")
    finally:
        rec.uninstall()
        out = os.environ.get("VALEN_TRACE_OUT")
        if out:
            with open(out, "w", encoding="utf-8") as f:
                json.dump(rec.to_dict(), f, sort_keys=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())

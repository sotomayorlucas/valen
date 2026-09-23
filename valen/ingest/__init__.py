"""Ingest adapters: turn target artifacts into the unified IR."""

from __future__ import annotations

from .angr_binary import AngrBinaryIngest
from .binary import BinaryIngest
from .clike import CLikeIngest
from .iam import IAMIgest
from .java import JavaIngest
from .java_interproc import JavaInterproceduralIngest
from .llm_agent import LLMAgentIngest
from .python import PythonIngest
from .web import WebIngest

__all__ = [
    "PythonIngest",
    "JavaIngest",
    "JavaInterproceduralIngest",
    "BinaryIngest",
    "AngrBinaryIngest",
    "WebIngest",
    "LLMAgentIngest",
    "IAMIgest",
    "CLikeIngest",
    "LANGUAGE_TO_INGEST",
    "analyze",
]


LANGUAGE_TO_INGEST = {
    "python": PythonIngest,
    "java": JavaIngest,
    "java-interproc": JavaInterproceduralIngest,
    "binary": BinaryIngest,
    "angr-binary": AngrBinaryIngest,
    "web": WebIngest,
    "llm-agent": LLMAgentIngest,
    "iam": IAMIgest,
}

_EXT_TO_ADAPTER = {
    ".py": "python",
    ".java": "java",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "javascript",
    ".tsx": "javascript",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".hh": "cpp",
    ".hxx": "cpp",
    ".rs": "rust",
    ".cs": "csharp",
    ".go": "go",
    ".php": "php",
    ".rb": "ruby",
    ".asm": "binary",
    ".s": "binary",
    ".json": None,  # ambiguous: web (OpenAPI) vs llm-agent
    ".yaml": "web",
    ".yml": "web",
}


def _make_clike(profile_name: str):
    from .sources_sinks import PROFILES

    class _Adapter(CLikeIngest):
        def __init__(self):
            super().__init__(PROFILES[profile_name])

    _Adapter.__name__ = f"{profile_name.title()}Ingest"
    return _Adapter


# C-like language adapters built from their taint profiles.
LANGUAGE_TO_INGEST.update({
    name: _make_clike(name)
    for name in ("c", "cpp", "rust", "csharp", "go", "php", "ruby", "javascript")
})


def analyze(source: str, path: str = "<stdin>", adapter: str | None = None):
    """Dispatch to the right ingest adapter.

    ``source`` is code/JSON/disassembly text. ``adapter`` may be ``python``,
    ``binary``, ``web`` or ``llm-agent``; if omitted it is inferred from the path
    extension (``.json`` defaults to OpenAPI).
    """
    if adapter is None:
        adapter = infer_adapter(source, path)
    ingest_cls = LANGUAGE_TO_INGEST.get(adapter)
    if ingest_cls is None:
        raise ValueError(f"unsupported adapter {adapter!r}")
    if adapter == "angr-binary":
        return ingest_cls().analyze(path, path=path)
    return ingest_cls().analyze(source, path=path)


def infer_adapter(source: str, path: str) -> str:
    import os

    ext = os.path.splitext(path)[1].lower()
    if ext == ".json":
        # Distinguish an agent spec (has "tools") from an OpenAPI spec (has "paths").
        import json

        try:
            data = json.loads(source)
        except Exception:
            return "web"
        if "tools" in data:
            return "llm-agent"
        if "nodes" in data and "edges" in data:
            return "iam"
        return "web"
    return _EXT_TO_ADAPTER.get(ext, "python")

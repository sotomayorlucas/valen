"""Ingest adapters: turn target artifacts into the unified IR."""

from __future__ import annotations

from .angr_binary import AngrBinaryIngest
from .binary import BinaryIngest
from .java import JavaIngest
from .llm_agent import LLMAgentIngest
from .python import PythonIngest
from .web import WebIngest

__all__ = [
    "PythonIngest",
    "JavaIngest",
    "BinaryIngest",
    "AngrBinaryIngest",
    "WebIngest",
    "LLMAgentIngest",
    "LANGUAGE_TO_INGEST",
    "analyze",
]


LANGUAGE_TO_INGEST = {
    "python": PythonIngest,
    "java": JavaIngest,
    "binary": BinaryIngest,
    "angr-binary": AngrBinaryIngest,
    "web": WebIngest,
    "llm-agent": LLMAgentIngest,
}

_EXT_TO_ADAPTER = {
    ".py": "python",
    ".js": "python",
    ".mjs": "python",
    ".asm": "binary",
    ".s": "binary",
    ".json": None,  # ambiguous: web (OpenAPI) vs llm-agent
    ".yaml": "web",
    ".yml": "web",
}


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
        return "llm-agent" if "tools" in data else "web"
    return _EXT_TO_ADAPTER.get(ext, "python")

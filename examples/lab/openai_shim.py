"""OpenAI-compatible shim: forward chat/completions to LiteLLM, fake embeddings.

crAPI's chatbot needs an OpenAI-compatible endpoint that also serves
``/embeddings`` (its RAG layer calls ``add_to_chroma_collection`` after every
reply, and a 400 there would discard the reply). The local LiteLLM proxy has no
embeddings model, so this shim sits in front of it:

* POST /chat/completions  -> forward to LiteLLM (127.0.0.1:4000)
* POST /v1/chat/completions -> forward to LiteLLM
* POST /embeddings        -> return deterministic zero vectors (dim 1536)
* POST /v1/embeddings     -> same
* GET  /models, /v1/models -> list {flash, pro, kimi, glm, text-embedding-3-large}

Usage:
    python examples/lab/openai_shim.py --port 8055 [--upstream http://127.0.0.1:4000]
"""

from __future__ import annotations

import argparse
import json
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DIM = 1536
MODELS = ["flash", "pro", "kimi", "glm", "text-embedding-3-large"]

UPSTREAM = "http://127.0.0.1:4000"


def _embedding_response(model: str, count: int) -> dict:
    return {
        "object": "list",
        "data": [
            {"object": "embedding", "index": i, "embedding": [0.0] * DIM}
            for i in range(count)
        ],
        "model": model,
        "usage": {"prompt_tokens": count, "total_tokens": count},
    }


def _models_response() -> dict:
    return {"object": "list", "data": [{"id": m, "object": "model", "owned_by": "shim"} for m in MODELS]}


def _forward(path: str, body: bytes, headers: dict) -> tuple[int, bytes, str]:
    url = UPSTREAM + path
    req = urllib.request.Request(url, data=body, method="POST")
    for k, v in headers.items():
        if k.lower() in ("authorization", "content-type"):
            req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=300) as resp:
            return resp.status, resp.read(), resp.headers.get("Content-Type", "application/json")
    except urllib.error.HTTPError as e:
        return e.code, e.read(), "application/json"
    except Exception as e:  # noqa: BLE001
        return 502, json.dumps({"error": str(e)}).encode(), "application/json"


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, obj: dict | bytes, ctype: str = "application/json"):
        if isinstance(obj, dict):
            body = json.dumps(obj).encode()
        else:
            body = obj
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read(self) -> bytes:
        length = int(self.headers.get("Content-Length", 0) or 0)
        return self.rfile.read(length) if length else b""

    def do_GET(self):  # noqa: N802
        if self.path.rstrip("/") in ("/models", "/v1/models"):
            self._send(200, _models_response())
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):  # noqa: N802
        body = self._read()
        path = self.path
        if path.rstrip("/") in ("/embeddings", "/v1/embeddings"):
            try:
                payload = json.loads(body or b"{}")
            except Exception:  # noqa: BLE001
                payload = {}
            model = payload.get("model", "text-embedding-3-large")
            inp = payload.get("input", [])
            count = len(inp) if isinstance(inp, list) else (1 if inp else 0)
            self._send(200, _embedding_response(model, count))
        elif path.rstrip("/") in ("/chat/completions", "/v1/chat/completions"):
            code, resp, ctype = _forward("/v1/chat/completions", body, dict(self.headers))
            self._send(code, resp, ctype)
        else:
            self._send(404, {"error": f"unsupported {path}"})

    def log_message(self, fmt, *args):  # quiet
        return


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8055)
    ap.add_argument("--upstream", default="http://127.0.0.1:4000")
    args = ap.parse_args()
    global UPSTREAM
    UPSTREAM = args.upstream
    server = ThreadingHTTPServer(("0.0.0.0", args.port), Handler)
    print(f"openai_shim listening on 0.0.0.0:{args.port} -> {UPSTREAM}")
    server.serve_forever()


if __name__ == "__main__":
    main()

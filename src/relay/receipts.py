"""Ed25519-signed action receipts with offline public verification."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import os
import re
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

RECEIPT_SCHEMA_VERSION = "agenthub.action-receipt.v1"
RECEIPT_ALGORITHM = "EdDSA"
_PRIVATE_KEY_ENV = "AGENTHUB_MCP_RECEIPT_PRIVATE_KEY_B64"
_ENVELOPE_FIELDS = frozenset({"schema_version", "alg", "kid", "payload", "signature"})
_JWK_FIELDS = frozenset({"kty", "crv", "x", "kid"})
_URLSAFE_B64_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_STANDARD_B64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")


def _validate_json(value: Any, *, path: str = "$") -> None:
    if value is None or isinstance(value, (bool, str, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"non-finite JSON number at {path}")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json(item, path=f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"JSON object key at {path} must be a string")
            _validate_json(item, path=f"{path}.{key}")
        return
    raise ValueError(f"unsupported JSON value at {path}: {type(value).__name__}")


def canonical_json_bytes(value: Any) -> bytes:
    """Return deterministic UTF-8 JSON after rejecting non-JSON and non-finite values."""
    _validate_json(value)
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        return encoded.encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ValueError("value cannot be encoded as canonical JSON") from exc


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _decode_private_seed(value: str) -> bytes:
    encoded = value.strip()
    if not encoded:
        raise ValueError(f"{_PRIVATE_KEY_ENV} must not be empty")
    if ("-" in encoded or "_" in encoded) and ("+" in encoded or "/" in encoded):
        raise ValueError(f"{_PRIVATE_KEY_ENV} uses mixed base64 alphabets")
    if "-" in encoded or "_" in encoded:
        if "=" in encoded or _URLSAFE_B64_RE.fullmatch(encoded) is None:
            raise ValueError(f"{_PRIVATE_KEY_ENV} must be valid unpadded base64url")
        altchars: bytes | None = b"-_"
    else:
        if _STANDARD_B64_RE.fullmatch(encoded) is None:
            raise ValueError(f"{_PRIVATE_KEY_ENV} must be valid base64")
        altchars = None
    padded = encoded + "=" * ((4 - len(encoded) % 4) % 4)
    try:
        seed = base64.b64decode(padded, altchars=altchars, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError(f"{_PRIVATE_KEY_ENV} must be valid base64") from exc
    if len(seed) != 32:
        raise ValueError(f"{_PRIVATE_KEY_ENV} must decode to a 32-byte Ed25519 seed")
    return seed


def _b64url_decode(value: Any, *, field: str, expected_length: int) -> bytes:
    if not isinstance(value, str) or not value or "=" in value:
        raise ValueError(f"{field} must be unpadded base64url")
    if _URLSAFE_B64_RE.fullmatch(value) is None:
        raise ValueError(f"{field} must be unpadded base64url")
    padded = value + "=" * ((4 - len(value) % 4) % 4)
    try:
        decoded = base64.b64decode(padded, altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError(f"{field} must be unpadded base64url") from exc
    if len(decoded) != expected_length:
        raise ValueError(f"{field} must decode to {expected_length} bytes")
    return decoded


def _private_key() -> Ed25519PrivateKey:
    raw = os.getenv(_PRIVATE_KEY_ENV)
    if raw is None:
        raise RuntimeError(f"{_PRIVATE_KEY_ENV} is required")
    try:
        seed = _decode_private_seed(raw)
    except ValueError as exc:
        raise RuntimeError(str(exc)) from exc
    return Ed25519PrivateKey.from_private_bytes(seed)


def _public_key_bytes(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _key_id(public_key_bytes: bytes) -> str:
    return f"ed25519-{_b64url_encode(hashlib.sha256(public_key_bytes).digest())}"


def validate_receipt_configuration() -> None:
    """Fail closed unless the configured private seed is a usable Ed25519 key."""
    _private_key()


def receipt_public_jwk() -> dict[str, str]:
    """Return the public JWK corresponding to the configured receipt signer."""
    public_bytes = _public_key_bytes(_private_key().public_key())
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": _b64url_encode(public_bytes),
        "kid": _key_id(public_bytes),
    }


def _unsigned_envelope(payload: Any, *, kid: str) -> dict[str, Any]:
    return {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "alg": RECEIPT_ALGORITHM,
        "kid": kid,
        "payload": payload,
    }


def sign_receipt(payload: Any) -> dict[str, Any]:
    """Sign an action receipt payload and bind all envelope metadata."""
    canonical_json_bytes(payload)
    private_key = _private_key()
    public_bytes = _public_key_bytes(private_key.public_key())
    unsigned = _unsigned_envelope(payload, kid=_key_id(public_bytes))
    signature = private_key.sign(canonical_json_bytes(unsigned))
    return {**unsigned, "signature": _b64url_encode(signature)}


def _invalid(reason: str) -> dict[str, Any]:
    return {"valid": False, "reason": reason}


def verify_receipt(envelope: Any, public_jwk: Any) -> dict[str, Any]:
    """Verify a receipt with public material only, returning a stable result."""
    if not isinstance(envelope, dict) or set(envelope) != _ENVELOPE_FIELDS:
        return _invalid("invalid receipt envelope")
    if envelope.get("schema_version") != RECEIPT_SCHEMA_VERSION:
        return _invalid("unknown receipt schema version")
    if envelope.get("alg") != RECEIPT_ALGORITHM:
        return _invalid("unsupported receipt algorithm")
    if not isinstance(public_jwk, dict) or not _JWK_FIELDS.issubset(public_jwk):
        return _invalid("invalid public JWK")
    if public_jwk.get("kty") != "OKP" or public_jwk.get("crv") != "Ed25519":
        return _invalid("invalid public JWK")

    try:
        public_bytes = _b64url_decode(
            public_jwk.get("x"), field="public JWK x", expected_length=32
        )
    except ValueError as exc:
        return _invalid(str(exc))

    expected_kid = _key_id(public_bytes)
    if public_jwk.get("kid") != expected_kid:
        return _invalid("public JWK kid does not match its key")
    if envelope.get("kid") != expected_kid:
        return _invalid("unknown receipt key id")

    try:
        signature = _b64url_decode(
            envelope.get("signature"), field="receipt signature", expected_length=64
        )
        unsigned = _unsigned_envelope(envelope.get("payload"), kid=expected_kid)
        signed_bytes = canonical_json_bytes(unsigned)
        public_key = Ed25519PublicKey.from_public_bytes(public_bytes)
        public_key.verify(signature, signed_bytes)
    except InvalidSignature:
        return _invalid("invalid receipt signature")
    except (TypeError, ValueError) as exc:
        return _invalid(str(exc) or "invalid receipt")

    return {"valid": True, "reason": "ok"}

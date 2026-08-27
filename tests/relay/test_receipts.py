from __future__ import annotations

import base64
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any

import pytest

from src.relay.receipts import (
    RECEIPT_ALGORITHM,
    RECEIPT_SCHEMA_VERSION,
    canonical_json_bytes,
    receipt_public_jwk,
    sign_receipt,
    validate_receipt_configuration,
    verify_receipt,
)

ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / "tools" / "relay" / "verify_receipt.py"
PRIVATE_KEY_ENV = "AGENTHUB_MCP_RECEIPT_PRIVATE_KEY_B64"
SEED = bytes(range(32))


@pytest.fixture(autouse=True)
def receipt_signing_key(monkeypatch: pytest.MonkeyPatch) -> None:
    encoded = base64.urlsafe_b64encode(SEED).decode("ascii").rstrip("=")
    monkeypatch.setenv(PRIVATE_KEY_ENV, encoded)


def _payload() -> dict[str, Any]:
    return {
        "invocation_id": "inv-167",
        "outcome": "succeeded",
        "tenant_id": "tenant-a",
        "input_digest": "sha256:input",
        "output_digest": "sha256:output",
        "cost_usd": "0.001200",
        "attempt_count": 1,
        "network_started": True,
    }


def test_canonical_json_is_deterministic_utf8_and_compact() -> None:
    first = {"z": [3, {"b": True, "a": None}], "a": "caf\u00e9"}
    second = {"a": "caf\u00e9", "z": [3, {"a": None, "b": True}]}

    expected = '{"a":"caf\u00e9","z":[3,{"a":null,"b":true}]}'.encode()
    assert canonical_json_bytes(first) == expected
    assert canonical_json_bytes(second) == expected


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_canonical_json_rejects_non_finite_numbers(value: float) -> None:
    with pytest.raises(ValueError, match="non-finite JSON number"):
        canonical_json_bytes({"nested": [value]})


@pytest.mark.parametrize(
    "value",
    [
        {1: "non-string-key"},
        {"tuple": (1, 2)},
        {"bytes": b"secret"},
        {"set": {1, 2}},
    ],
)
def test_canonical_json_rejects_values_outside_strict_json(value: Any) -> None:
    with pytest.raises(ValueError):
        canonical_json_bytes(value)


def test_sign_and_verify_round_trip_with_public_jwk_only() -> None:
    envelope = sign_receipt(_payload())
    public_jwk = receipt_public_jwk()

    assert set(envelope) == {
        "schema_version",
        "alg",
        "kid",
        "payload",
        "signature",
    }
    assert envelope["schema_version"] == RECEIPT_SCHEMA_VERSION
    assert envelope["alg"] == RECEIPT_ALGORITHM
    assert envelope["kid"] == public_jwk["kid"]
    assert set(public_jwk) == {"kty", "crv", "x", "kid"}
    assert public_jwk["kty"] == "OKP"
    assert public_jwk["crv"] == "Ed25519"

    os.environ.pop(PRIVATE_KEY_ENV)
    assert verify_receipt(envelope, public_jwk) == {"valid": True, "reason": "ok"}


def test_standard_and_unpadded_base64url_seeds_resolve_same_public_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    url_jwk = receipt_public_jwk()
    monkeypatch.setenv(PRIVATE_KEY_ENV, base64.b64encode(SEED).decode("ascii"))
    standard_jwk = receipt_public_jwk()
    assert standard_jwk == url_jwk


@pytest.mark.parametrize(
    ("configured", "message"),
    [
        (None, "is required"),
        ("", "must not be empty"),
        ("not!base64", "must be valid base64"),
        (base64.b64encode(b"short").decode(), "32-byte Ed25519 seed"),
        ("abcd-_+/", "mixed base64 alphabets"),
    ],
)
def test_validate_configuration_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    configured: str | None,
    message: str,
) -> None:
    if configured is None:
        monkeypatch.delenv(PRIVATE_KEY_ENV, raising=False)
    else:
        monkeypatch.setenv(PRIVATE_KEY_ENV, configured)
    with pytest.raises(RuntimeError, match=message):
        validate_receipt_configuration()


def test_validate_configuration_accepts_valid_seed() -> None:
    assert validate_receipt_configuration() is None


@pytest.mark.parametrize(
    ("field", "replacement", "reason"),
    [
        (
            "schema_version",
            "agenthub.action-receipt.v999",
            "unknown receipt schema version",
        ),
        ("alg", "HS256", "unsupported receipt algorithm"),
        ("kid", "ed25519-unknown", "unknown receipt key id"),
    ],
)
def test_unknown_envelope_authority_is_rejected(
    field: str,
    replacement: str,
    reason: str,
) -> None:
    envelope = sign_receipt(_payload())
    envelope[field] = replacement
    assert verify_receipt(envelope, receipt_public_jwk()) == {
        "valid": False,
        "reason": reason,
    }


@pytest.mark.parametrize(
    "mutation",
    [
        lambda envelope: envelope["payload"].update({"outcome": "failed"}),
        lambda envelope: envelope["payload"].update({"tenant_id": "tenant-b"}),
        lambda envelope: envelope["payload"].update({"cost_usd": "1000.00"}),
        lambda envelope: envelope["payload"].update({"network_started": False}),
    ],
)
def test_payload_tampering_invalidates_signature(mutation: Any) -> None:
    envelope = sign_receipt(_payload())
    mutation(envelope)
    assert verify_receipt(envelope, receipt_public_jwk()) == {
        "valid": False,
        "reason": "invalid receipt signature",
    }


def test_signature_and_jwk_base64_are_strict() -> None:
    envelope = sign_receipt(_payload())
    jwk = receipt_public_jwk()

    malformed_signature = {**envelope, "signature": "not+base64"}
    assert verify_receipt(malformed_signature, jwk)["reason"] == (
        "receipt signature must be unpadded base64url"
    )

    padded_signature = {**envelope, "signature": f"{envelope['signature']}="}
    assert verify_receipt(padded_signature, jwk)["reason"] == (
        "receipt signature must be unpadded base64url"
    )

    malformed_jwk = {**jwk, "x": "not+base64"}
    assert verify_receipt(envelope, malformed_jwk)["reason"] == (
        "public JWK x must be unpadded base64url"
    )


def test_wrong_public_key_and_tampered_jwk_kid_are_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    envelope = sign_receipt(_payload())
    jwk = receipt_public_jwk()

    tampered_kid = {**jwk, "kid": "ed25519-forged"}
    assert verify_receipt(envelope, tampered_kid)["reason"] == (
        "public JWK kid does not match its key"
    )

    other_seed = bytes(reversed(range(32)))
    monkeypatch.setenv(
        PRIVATE_KEY_ENV,
        base64.urlsafe_b64encode(other_seed).decode("ascii").rstrip("="),
    )
    other_jwk = receipt_public_jwk()
    assert verify_receipt(envelope, other_jwk)["reason"] == "unknown receipt key id"


def test_envelope_shape_and_non_finite_payload_fail_closed() -> None:
    envelope = sign_receipt(_payload())
    jwk = receipt_public_jwk()
    assert verify_receipt({**envelope, "unexpected": True}, jwk)["reason"] == (
        "invalid receipt envelope"
    )

    invalid_payload = copy.deepcopy(envelope)
    invalid_payload["payload"]["cost"] = float("nan")
    result = verify_receipt(invalid_payload, jwk)
    assert result["valid"] is False
    assert "non-finite JSON number" in result["reason"]


def test_offline_cli_accepts_valid_receipt_without_private_key(
    tmp_path: Path,
) -> None:
    receipt_path = tmp_path / "receipt.json"
    jwk_path = tmp_path / "receipt-public.jwk.json"
    receipt_path.write_text(json.dumps(sign_receipt(_payload())), encoding="utf-8")
    jwk_path.write_text(json.dumps(receipt_public_jwk()), encoding="utf-8")
    environment = {**os.environ}
    environment.pop(PRIVATE_KEY_ENV, None)

    result = subprocess.run(
        [sys.executable, str(CLI), str(receipt_path), str(jwk_path)],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"valid": True, "reason": "ok"}


def test_offline_cli_exits_nonzero_for_tampered_or_malformed_receipt(
    tmp_path: Path,
) -> None:
    receipt_path = tmp_path / "receipt.json"
    jwk_path = tmp_path / "receipt-public.jwk.json"
    envelope = sign_receipt(_payload())
    envelope["payload"]["outcome"] = "indeterminate"
    receipt_path.write_text(json.dumps(envelope), encoding="utf-8")
    jwk_path.write_text(json.dumps(receipt_public_jwk()), encoding="utf-8")

    tampered = subprocess.run(
        [sys.executable, str(CLI), str(receipt_path), str(jwk_path)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert tampered.returncode != 0
    assert json.loads(tampered.stdout)["valid"] is False

    receipt_path.write_text("{not-json", encoding="utf-8")
    malformed = subprocess.run(
        [sys.executable, str(CLI), str(receipt_path), str(jwk_path)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert malformed.returncode != 0
    assert json.loads(malformed.stdout)["valid"] is False

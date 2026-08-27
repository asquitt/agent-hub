from __future__ import annotations

import base64

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from src.api.routes import relay
from src.relay.receipts import sign_receipt


def test_receipt_public_key_unavailable_is_a_stable_503(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unavailable() -> dict[str, str]:
        raise RuntimeError("signing key missing")

    monkeypatch.setattr(relay, "receipt_public_jwk", unavailable)

    with pytest.raises(HTTPException) as exc_info:
        relay.get_receipt_public_key()

    assert exc_info.value.status_code == 503
    assert exc_info.value.detail == {
        "code": "relay.receipt_key_unavailable",
        "message": "relay receipt verification key is unavailable",
    }


def test_api_verifier_rejects_caller_keys_and_uses_configured_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current_seed = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("=")
    attacker_seed = (
        base64.urlsafe_b64encode(bytes(reversed(range(32)))).decode().rstrip("=")
    )
    monkeypatch.setenv("AGENTHUB_MCP_RECEIPT_PRIVATE_KEY_B64", attacker_seed)
    forged = sign_receipt({"outcome": "succeeded", "owner": "victim"})
    monkeypatch.setenv("AGENTHUB_MCP_RECEIPT_PRIVATE_KEY_B64", current_seed)

    result = relay.verify_relay_receipt(
        relay.ReceiptVerificationRequest(receipt=forged)
    )
    assert result == {"valid": False, "reason": "unknown receipt key id"}

    with pytest.raises(ValidationError):
        relay.ReceiptVerificationRequest.model_validate(
            {"receipt": forged, "public_jwk": {"kty": "OKP"}}
        )


def test_budget_request_rejects_overflow_to_infinity() -> None:
    with pytest.raises(ValidationError):
        relay.RelayBudgetRequest.model_validate_json('{"max_budget_usd":1e999}')

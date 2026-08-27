from __future__ import annotations

import json
import os
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.idempotency import storage as idempotency_storage  # noqa: E402


TEST_API_KEYS = {
    "dev-owner-key": "owner-dev",
    "partner-owner-key": "owner-partner",
    "platform-owner-key": "owner-platform",
    "test-key": "owner-dev",
    "test-key-001": "test-owner",
}

TEST_ENV_DEFAULTS = {
    "AGENTHUB_ACCESS_ENFORCEMENT_MODE": "enforce",
    "AGENTHUB_AUTH_TOKEN_SECRET": "test-global-auth-secret",
    "AGENTHUB_CORS_ORIGINS": "http://localhost:3000,https://app.example.com",
    "AGENTHUB_FEDERATION_DOMAIN_TOKENS_JSON": json.dumps(
        {
            "partner-east": "east-token-001",
            "partner-west": "west-token-001",
            "test-domain": "test-token",
            "test.local": "tok",
        },
        sort_keys=True,
    ),
    "AGENTHUB_IDENTITY_SIGNING_SECRET": "test-global-identity-secret",
    "AGENTHUB_ENABLE_UNSAFE_FINANCIAL_MUTATIONS": "true",
    "AGENTHUB_PROVENANCE_SIGNING_SECRET": "test-global-provenance-secret",
    "AGENTHUB_POLICY_SIGNING_SECRET": "test-global-policy-secret",
    "AGENTHUB_VAULT_KEY": "test-global-vault-key",
    "AGENTHUB_RATE_LIMIT_DEFAULT": "10000/minute",
}


def pytest_configure() -> None:
    """Install one deterministic baseline before test modules are imported."""
    os.environ["AGENTHUB_API_KEYS_JSON"] = json.dumps(TEST_API_KEYS, sort_keys=True)
    for name, value in TEST_ENV_DEFAULTS.items():
        os.environ[name] = value


@pytest.fixture(autouse=True)
def isolate_idempotency_storage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[None]:
    from src.api.middleware import limiter

    db_path = tmp_path / "idempotency.db"
    monkeypatch.setenv("AGENTHUB_IDEMPOTENCY_DB_PATH", str(db_path))
    idempotency_storage.reset_for_tests(db_path=db_path)
    limiter.reset()
    yield
    limiter.reset()

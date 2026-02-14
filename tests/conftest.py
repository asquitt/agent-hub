from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.idempotency import storage as idempotency_storage


@pytest.fixture(autouse=True)
def isolate_idempotency_storage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTHUB_ACCESS_ENFORCEMENT_MODE", "enforce")
    monkeypatch.setenv(
        "AGENTHUB_API_KEYS_JSON",
        '{"dev-owner-key":"owner-dev","partner-owner-key":"owner-partner","platform-owner-key":"owner-platform"}',
    )
    monkeypatch.setenv("AGENTHUB_AUTH_TOKEN_SECRET", "test-global-auth-secret")
    monkeypatch.setenv(
        "AGENTHUB_FEDERATION_DOMAIN_TOKENS_JSON",
        '{"partner-east":"fed-partner-east-token","partner-west":"fed-partner-west-token"}',
    )
    monkeypatch.setenv("AGENTHUB_PROVENANCE_SIGNING_SECRET", "test-global-provenance-secret")
    monkeypatch.setenv("AGENTHUB_POLICY_SIGNING_SECRET", "test-global-policy-secret")
    db_path = tmp_path / "idempotency.db"
    monkeypatch.setenv("AGENTHUB_IDEMPOTENCY_DB_PATH", str(db_path))
    idempotency_storage.reset_for_tests(db_path=db_path)

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_playwright_server_declares_every_required_startup_secret() -> None:
    config = (ROOT / "playwright.config.js").read_text(encoding="utf-8")

    for variable in (
        "AGENTHUB_API_KEYS_JSON",
        "AGENTHUB_AUTH_TOKEN_SECRET",
        "AGENTHUB_FEDERATION_DOMAIN_TOKENS_JSON",
        "AGENTHUB_IDENTITY_SIGNING_SECRET",
        "AGENTHUB_POLICY_SIGNING_SECRET",
        "AGENTHUB_PROVENANCE_SIGNING_SECRET",
        "AGENTHUB_VAULT_KEY",
    ):
        assert f"{variable}:" in config


def test_playwright_operator_diagnostics_use_the_runtime_sandbox() -> None:
    config = (ROOT / "playwright.config.js").read_text(encoding="utf-8")

    assert 'AGENTHUB_OPERATOR_DIAGNOSTICS_DB_PATH: runtimePath("operator-diagnostics.db")' in config

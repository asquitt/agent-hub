from __future__ import annotations

import base64
from collections.abc import Iterator
from contextlib import contextmanager
import json
from pathlib import Path
import socket
import subprocess
import sys
import time
from typing import Any
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from src.api.app import app
from src.api.auth import AuthContext
from src.identity import storage as identity_storage
from src.relay.config import load_mcp_relay_target
from src.relay.defaults import OfficialMCPRelayTransport
from src.relay.receipts import receipt_public_jwk, verify_receipt
from src.relay.service import (
    RelayCrashAfterRemoteResult,
    RelayService,
    RelayServiceError,
)
from src.relay.storage import RELAY_STORAGE, RelayStorage

FIXTURE_SERVER = Path(__file__).parent / "fixtures" / "official_readonly_server.py"


def _free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


@contextmanager
def _official_server(tmp_path: Path) -> Iterator[tuple[int, Path]]:
    port = _free_port()
    counter = tmp_path / "upstream-calls.txt"
    counter.write_text("0", encoding="utf-8")
    log = (tmp_path / "upstream.log").open("w", encoding="utf-8")
    process = subprocess.Popen(  # noqa: S603
        [
            sys.executable,
            str(FIXTURE_SERVER),
            "--port",
            str(port),
            "--counter",
            str(counter),
        ],
        stdout=log,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if process.poll() is not None:
                log.flush()
                raise RuntimeError(
                    (tmp_path / "upstream.log").read_text(encoding="utf-8")
                )
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.05)
        else:
            raise TimeoutError("official MCP fixture did not become ready")
        yield port, counter
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        log.close()


def _seed() -> str:
    return base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("=")


def _target_json(port: int) -> str:
    return json.dumps(
        [
            {
                "target_id": "catalog",
                "tenant_id": "tenant-a",
                "endpoint_url": f"http://127.0.0.1:{port}/mcp",
                "tool_name": "lookup",
                "auth": "none",
                "operator_attests_read_only": True,
                "max_call_cost_usd": 0.25,
            }
        ]
    )


def _headers(
    *,
    api_key: str | None = None,
    credential: str | None = None,
    idempotency_key: str | None = None,
) -> dict[str, str]:
    headers = {"X-Tenant-ID": "tenant-a"}
    if api_key is not None:
        headers["X-API-Key"] = api_key
    if credential is not None:
        headers["Authorization"] = f"AgentCredential {credential}"
    if idempotency_key is not None:
        headers["Idempotency-Key"] = idempotency_key
    return headers


@pytest.fixture()
def relay_api_runtime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTHUB_ACCESS_ENFORCEMENT_MODE", "enforce")
    monkeypatch.setenv(
        "AGENTHUB_API_KEYS_JSON",
        json.dumps(
            {
                "owner-a-key": {
                    "owner": "owner-a",
                    "scopes": ["*"],
                    "roles": ["admin"],
                },
                "owner-b-key": {
                    "owner": "owner-b",
                    "scopes": ["*"],
                    "roles": ["admin"],
                },
            }
        ),
    )
    monkeypatch.setenv(
        "AGENTHUB_OWNER_TENANTS_JSON",
        json.dumps({"owner-a": ["tenant-a"], "owner-b": ["tenant-a"]}),
    )
    monkeypatch.setenv("AGENTHUB_IDENTITY_SIGNING_SECRET", "s167-identity-secret")
    monkeypatch.setenv("AGENTHUB_MCP_RECEIPT_PRIVATE_KEY_B64", _seed())
    monkeypatch.setenv("AGENTHUB_MCP_RELAY_ALLOW_LOOPBACK_HTTP", "true")
    identity_db = tmp_path / "identity.db"
    relay_db = tmp_path / "relay.db"
    monkeypatch.setenv("AGENTHUB_IDENTITY_DB_PATH", str(identity_db))
    monkeypatch.setenv("AGENTHUB_RELAY_DB_PATH", str(relay_db))
    identity_storage.reset_for_tests(identity_db)
    RELAY_STORAGE.reset_for_tests(relay_db)


def test_api_dispatches_once_and_revocation_blocks_next_network_call(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    relay_api_runtime: None,
) -> None:
    with _official_server(tmp_path) as (port, counter):
        monkeypatch.setenv("AGENTHUB_MCP_RELAY_TARGETS_JSON", _target_json(port))
        with TestClient(app) as client:
            admin = _headers(api_key="owner-a-key", idempotency_key=uuid4().hex)
            registered = client.post(
                "/v1/identity/agents",
                json={"agent_id": "agent-a"},
                headers=admin,
            )
            assert registered.status_code == 200, registered.text
            issued_credential = client.post(
                "/v1/identity/agents/agent-a/credentials",
                json={
                    "scopes": ["relay.call", "relay.read", "mcp.tools.lookup.invoke"],
                    "ttl_seconds": 3600,
                },
                headers=_headers(api_key="owner-a-key", idempotency_key=uuid4().hex),
            )
            assert issued_credential.status_code == 200, issued_credential.text
            credential = str(issued_credential.json()["secret"])

            issued_capability = client.post(
                "/v1/identity/capability-tokens/issue",
                json={
                    "issuer_agent_id": "agent-a",
                    "subject_agent_id": "agent-a",
                    "scopes": ["mcp.tools.lookup.invoke"],
                    "ttl_seconds": 3600,
                    "audience": "agenthub://mcp-relay",
                    "resource": "urn:agenthub:mcp-relay:catalog:lookup",
                },
                headers=_headers(api_key="owner-a-key", idempotency_key=uuid4().hex),
            )
            assert issued_capability.status_code == 200, issued_capability.text
            capability = issued_capability.json()

            imported = client.post(
                "/v1/relay/mcp/import",
                json={"target_id": "catalog"},
                headers=_headers(api_key="owner-a-key", idempotency_key=uuid4().hex),
            )
            assert imported.status_code == 200, imported.text
            budget = client.put(
                f"/v1/relay/budgets/{capability['token_id']}",
                json={"max_budget_usd": 1.0},
                headers=_headers(api_key="owner-a-key", idempotency_key=uuid4().hex),
            )
            assert budget.status_code == 200, budget.text

            call_key = uuid4().hex
            called = client.post(
                "/v1/relay/mcp/call",
                json={
                    "target_id": "catalog",
                    "capability_token": capability,
                    "arguments": {"q": "invoice"},
                },
                headers=_headers(credential=credential, idempotency_key=call_key),
            )
            assert called.status_code == 200, called.text
            record = called.json()
            assert record["status"] == "succeeded"
            assert record["result"] == {"answer": "found:invoice"}
            assert counter.read_text(encoding="utf-8") == "1"

            public_jwk = client.get("/v1/relay/receipt-keys/current").json()
            verification = client.post(
                "/v1/relay/receipts/verify",
                json={"receipt": record["receipt"]},
            )
            assert verification.status_code == 200, verification.text
            assert verification.json() == {"valid": True, "reason": "ok"}
            assert verify_receipt(record["receipt"], public_jwk)["valid"] is True

            cross_owner = client.get(
                f"/v1/relay/mcp/calls/{record['invocation_id']}",
                headers=_headers(api_key="owner-b-key"),
            )
            assert cross_owner.status_code == 404

            revoked = client.post(
                f"/v1/identity/capability-tokens/{capability['token_id']}/revoke",
                json={"reason": "test revocation"},
                headers=_headers(api_key="owner-a-key", idempotency_key=uuid4().hex),
            )
            assert revoked.status_code == 200, revoked.text
            denied = client.post(
                "/v1/relay/mcp/call",
                json={
                    "target_id": "catalog",
                    "capability_token": capability,
                    "arguments": {"q": "second"},
                },
                headers=_headers(credential=credential, idempotency_key=uuid4().hex),
            )
            assert denied.status_code == 403, denied.text
            assert denied.json()["detail"]["code"] == "relay.policy_denied"
            assert counter.read_text(encoding="utf-8") == "1"


@pytest.mark.anyio
async def test_process_result_crash_recovers_indeterminate_without_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTHUB_MCP_RECEIPT_PRIVATE_KEY_B64", _seed())
    monkeypatch.setenv("AGENTHUB_MCP_RELAY_ALLOW_LOOPBACK_HTTP", "true")
    with _official_server(tmp_path) as (port, counter):
        monkeypatch.setenv("AGENTHUB_MCP_RELAY_TARGETS_JSON", _target_json(port))
        target = load_mcp_relay_target()
        storage = RelayStorage()
        storage.reset_for_tests(tmp_path / "crash-relay.db")
        context = AuthContext(
            "owner-a",
            scopes=["relay.call"],
            roles=["member"],
            tenant_id="tenant-a",
            auth_method="agent_credential",
            agent_id="agent-a",
        )
        capability = {
            "valid": True,
            "token_id": "cap-crash",
            "issuer": "agent-a",
            "subject": "agent-a",
            "audience": "agenthub://mcp-relay",
            "resource": "urn:agenthub:mcp-relay:catalog:lookup",
            "effective_scopes": ["mcp.tools.lookup.invoke"],
        }
        monkeypatch.setattr(
            "src.relay.service.verify_capability_token",
            lambda *_args, **_kwargs: dict(capability),
        )

        def crash(_result: dict[str, Any]) -> None:
            raise RelayCrashAfterRemoteResult()

        service = RelayService(
            transport=OfficialMCPRelayTransport(),
            config_loader=lambda _target_id: target,
            storage=storage,
            after_remote_result=crash,
        )
        admin = AuthContext(
            "owner-a",
            scopes=["*"],
            roles=["admin"],
            tenant_id="tenant-a",
            auth_method="api_key",
        )
        await service.import_target("catalog", actor=admin)
        storage.set_budget(
            owner="owner-a",
            tenant_id="tenant-a",
            capability_token_id="cap-crash",
            max_budget_usd=1.0,
        )
        with pytest.raises(RelayCrashAfterRemoteResult):
            await service.invoke(
                target_id="catalog",
                capability_token=capability,
                arguments={"q": "crash"},
                idempotency_key="crash-after-result",
                source_ip="127.0.0.1",
                reauthenticate=lambda: context,
            )
        assert counter.read_text(encoding="utf-8") == "1"

        recovered_service = RelayService(
            transport=OfficialMCPRelayTransport(),
            config_loader=lambda _target_id: target,
            storage=storage,
        )
        recovered = recovered_service.reconcile_abandoned()
        assert recovered[0]["status"] == "indeterminate"
        assert verify_receipt(recovered[0]["receipt"], receipt_public_jwk())["valid"]
        with pytest.raises(RelayServiceError, match="cannot be replayed"):
            await recovered_service.invoke(
                target_id="catalog",
                capability_token=capability,
                arguments={"q": "crash"},
                idempotency_key="crash-after-result",
                source_ip="127.0.0.1",
                reauthenticate=lambda: context,
            )
        assert counter.read_text(encoding="utf-8") == "1"

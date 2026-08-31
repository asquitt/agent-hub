from __future__ import annotations

import base64
from collections.abc import Iterator
from contextlib import contextmanager
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
from typing import Any
from uuid import uuid4

import httpx
import pytest
from fastapi.testclient import TestClient

from src.api.access_policy import requires_idempotency
from src.api.app import app
from src.api.auth import AuthContext
from src.identity import storage as identity_storage
from src.protocol.mcp_client import (
    MCPResponseTooLargeError,
    MCPToolListingError,
    call_tool,
    inspect_target,
)
from src.relay.config import load_mcp_relay_target, parse_mcp_relay_targets_json
from src.relay.defaults import OfficialMCPRelayTransport
from src.relay.receipts import receipt_public_jwk, verify_receipt
from src.relay.service import (
    RelayCrashAfterRemoteResult,
    RelayService,
    RelayServiceError,
)
from src.relay.storage import RELAY_STORAGE, RelayStorage
import src.relay.service as relay_service_module

FIXTURE_SERVER = Path(__file__).parent / "fixtures" / "official_readonly_server.py"
REPEATING_CURSOR_SERVER = (
    Path(__file__).parent / "fixtures" / "repeating_cursor_server.py"
)
ROOT = Path(__file__).resolve().parents[2]
CRASH_ONCE_APP = "tests.relay.fixtures.crash_once_app:app"
CRASH_EXIT_CODE = 91


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


@contextmanager
def _repeating_cursor_server(tmp_path: Path) -> Iterator[tuple[int, Path, Path]]:
    port = _free_port()
    list_counter = tmp_path / "upstream-list-calls.txt"
    call_counter = tmp_path / "upstream-tool-calls.txt"
    list_counter.write_text("0", encoding="utf-8")
    call_counter.write_text("0", encoding="utf-8")
    log = (tmp_path / "repeating-cursor.log").open("w", encoding="utf-8")
    process = subprocess.Popen(  # noqa: S603
        [
            sys.executable,
            str(REPEATING_CURSOR_SERVER),
            "--port",
            str(port),
            "--list-counter",
            str(list_counter),
            "--call-counter",
            str(call_counter),
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
                    (tmp_path / "repeating-cursor.log").read_text(encoding="utf-8")
                )
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.05)
        else:
            raise TimeoutError("repeating-cursor MCP fixture did not become ready")
        yield port, list_counter, call_counter
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


def _target_json(port: int, *, tool_name: str = "lookup") -> str:
    return json.dumps(
        [
            {
                "target_id": "catalog",
                "tenant_id": "tenant-a",
                "endpoint_url": f"http://127.0.0.1:{port}/mcp",
                "tool_name": tool_name,
                "auth": "none",
                "operator_attests_read_only": True,
                "max_call_cost_usd": 0.25,
            }
        ]
    )


def _api_process_env(tmp_path: Path, *, upstream_port: int) -> dict[str, str]:
    env = {
        name: value
        for name, value in os.environ.items()
        if not name.startswith("AGENTHUB_")
    }
    env.update(
        {
            "PYTHONPATH": str(ROOT),
            "AGENTHUB_ACCESS_ENFORCEMENT_MODE": "enforce",
            "AGENTHUB_API_KEYS_JSON": json.dumps(
                {
                    "owner-a-key": {
                        "owner": "owner-a",
                        "scopes": ["*"],
                        "roles": ["admin"],
                    }
                }
            ),
            "AGENTHUB_OWNER_TENANTS_JSON": json.dumps({"owner-a": ["tenant-a"]}),
            "AGENTHUB_AUTH_TOKEN_SECRET": "s167-auth-secret",
            "AGENTHUB_IDENTITY_SIGNING_SECRET": "s167-identity-secret",
            "AGENTHUB_POLICY_SIGNING_SECRET": "s167-policy-secret",
            "AGENTHUB_PROVENANCE_SIGNING_SECRET": "s167-provenance-secret",
            "AGENTHUB_FEDERATION_DOMAIN_TOKENS_JSON": json.dumps(
                {"test-domain": "test-token"}
            ),
            "AGENTHUB_VAULT_KEY": "s167-vault-key",
            "AGENTHUB_MCP_RECEIPT_PRIVATE_KEY_B64": _seed(),
            "AGENTHUB_MCP_RELAY_ALLOW_LOOPBACK_HTTP": "true",
            "AGENTHUB_MCP_RELAY_TARGETS_JSON": _target_json(upstream_port),
            "AGENTHUB_RELAY_CRASH_ONCE_MARKER": str(tmp_path / "crashed.marker"),
            "AGENTHUB_SINGLETON_LOCK_PATH": str(tmp_path / "agenthub.lock"),
            "AGENTHUB_API_WORKERS": "1",
            "WEB_CONCURRENCY": "1",
            "AGENTHUB_API_REPLICAS": "1",
            "AGENTHUB_REPLICAS": "1",
            "AGENTHUB_RATE_LIMIT_DEFAULT": "10000/minute",
        }
    )
    for store in (
        "billing",
        "compliance",
        "cost",
        "delegation",
        "devhub",
        "eval",
        "federation",
        "idempotency",
        "identity",
        "knowledge",
        "lease",
        "marketplace",
        "operator_diagnostics",
        "procurement",
        "registry",
        "relay",
        "runtime",
        "trust",
    ):
        env[f"AGENTHUB_{store.upper()}_DB_PATH"] = str(tmp_path / f"{store}.db")
    return env


@contextmanager
def _agenthub_api_process(
    tmp_path: Path,
    *,
    upstream_port: int,
    instance_name: str,
) -> Iterator[tuple[httpx.Client, subprocess.Popen[str]]]:
    port = _free_port()
    log_path = tmp_path / f"agenthub-{instance_name}.log"
    log = log_path.open("w", encoding="utf-8")
    process = subprocess.Popen(  # noqa: S603
        [
            sys.executable,
            "-m",
            "uvicorn",
            CRASH_ONCE_APP,
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--log-level",
            "warning",
        ],
        cwd=ROOT,
        env=_api_process_env(tmp_path, upstream_port=upstream_port),
        stdout=log,
        stderr=subprocess.STDOUT,
        text=True,
    )
    client = httpx.Client(
        base_url=f"http://127.0.0.1:{port}", timeout=5.0, trust_env=False
    )
    try:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if process.poll() is not None:
                log.flush()
                raise RuntimeError(log_path.read_text(encoding="utf-8"))
            try:
                if client.get("/healthz").status_code == 200:
                    break
            except httpx.HTTPError:
                time.sleep(0.05)
        else:
            raise TimeoutError("AgentHub API fixture did not become ready")
        yield client, process
    finally:
        client.close()
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        log.close()


@pytest.mark.anyio
async def test_official_server_oversized_text_with_small_structured_output_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTHUB_MCP_RELAY_ALLOW_LOOPBACK_HTTP", "true")
    with _official_server(tmp_path) as (port, counter):
        monkeypatch.setenv(
            "AGENTHUB_MCP_RELAY_TARGETS_JSON",
            _target_json(port, tool_name="oversized_lookup"),
        )
        target = load_mcp_relay_target()
        inspection = await inspect_target(target)

        with pytest.raises(MCPResponseTooLargeError, match="response exceeds"):
            await call_tool(
                target,
                arguments={"q": "bounded"},
                before_dispatch=lambda: None,
                expected_schema_digest=inspection.tool.schema_digest,
                expected_server_name=inspection.server.name,
                expected_server_version=inspection.server.version,
                expected_protocol_version=inspection.protocol_version,
            )

        assert counter.read_text(encoding="utf-8") == "1"


@pytest.mark.anyio
async def test_official_server_repeated_cursor_preserves_stable_listing_error(
    tmp_path: Path,
) -> None:
    with _repeating_cursor_server(tmp_path) as (port, list_counter, call_counter):
        target = parse_mcp_relay_targets_json(
            _target_json(port), allow_loopback_http=True
        )
        admission_calls = 0

        def before_dispatch() -> None:
            nonlocal admission_calls
            admission_calls += 1

        with pytest.raises(MCPToolListingError) as exc_info:
            await call_tool(
                target,
                arguments={"q": "must-not-dispatch"},
                before_dispatch=before_dispatch,
                expected_schema_digest="unused-before-listing-rejection",
                expected_server_name="repeating-cursor",
                expected_server_version="1.0.0",
                expected_protocol_version="2025-11-25",
                timeout_seconds=5,
            )

        assert exc_info.value.code == "relay.upstream_tool_listing_invalid"
        assert "opaque-repeat" not in str(exc_info.value)
        assert list_counter.read_text(encoding="utf-8") == "2"
        assert call_counter.read_text(encoding="utf-8") == "0"
        assert admission_calls == 0


@pytest.mark.anyio
async def test_official_transport_preserves_final_admission_revocation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTHUB_MCP_RECEIPT_PRIVATE_KEY_B64", _seed())
    monkeypatch.setenv("AGENTHUB_POLICY_SIGNING_SECRET", "s167-policy-secret")
    with _official_server(tmp_path) as (port, counter):
        target = parse_mcp_relay_targets_json(
            _target_json(port), allow_loopback_http=True
        )
        store = RelayStorage()
        store.reset_for_tests(tmp_path / "relay-revocation.db")
        service = RelayService(
            transport=OfficialMCPRelayTransport(),
            config_loader=lambda _target_id: target,
            storage=store,
        )

        def context(*, admin: bool = False) -> AuthContext:
            return AuthContext(
                "owner-a",
                scopes=["*" if admin else "relay.call"],
                roles=["admin" if admin else "member"],
                tenant_id="tenant-a",
                auth_method="api_key" if admin else "agent_credential",
                agent_id=None if admin else "agent-a",
            )

        await service.import_target("catalog", actor=context(admin=True))
        store.set_budget(
            owner="owner-a",
            tenant_id="tenant-a",
            capability_token_id="cap-a",
            max_budget_usd=1,
        )
        capability = {
            "valid": True,
            "token_id": "cap-a",
            "issuer": "agent-a",
            "subject": "agent-a",
            "audience": "agenthub://mcp-relay",
            "resource": "urn:agenthub:mcp-relay:catalog:lookup",
            "effective_scopes": ["mcp.tools.lookup.invoke"],
        }
        monkeypatch.setattr(
            relay_service_module,
            "verify_capability_token",
            lambda *_args, **_kwargs: dict(capability),
        )
        reauthentication_calls = 0

        def reauthenticate() -> AuthContext:
            nonlocal reauthentication_calls
            reauthentication_calls += 1
            if reauthentication_calls == 3:
                raise PermissionError("revoked at final dispatch admission")
            return context()

        with pytest.raises(RelayServiceError) as exc_info:
            await service.invoke(
                target_id="catalog",
                capability_token=capability,
                arguments={"q": "must-not-dispatch"},
                idempotency_key="real-runtime-revocation",
                source_ip="127.0.0.1",
                reauthenticate=reauthenticate,
            )

        assert exc_info.value.code == "relay.authority_revoked"
        assert exc_info.value.status_code == 403
        assert exc_info.value.record is not None
        assert exc_info.value.record["status"] == "failed"
        assert exc_info.value.record["network_started_at"] is None
        assert exc_info.value.record["charged_cost_usd"] == 0
        assert counter.read_text(encoding="utf-8") == "0"
        budget = store.get_budget(
            owner="owner-a", tenant_id="tenant-a", capability_token_id="cap-a"
        )
        assert budget["reserved_usd"] == 0
        assert reauthentication_calls == 3


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

            assert requires_idempotency("POST", "/v1/relay/mcp/call") is False
            missing_key = client.post(
                "/v1/relay/mcp/call",
                json={
                    "target_id": "catalog",
                    "capability_token": capability,
                    "arguments": {"q": "missing-key"},
                },
                headers=_headers(credential=credential),
            )
            assert missing_key.status_code == 400, missing_key.text
            assert missing_key.json()["detail"]["code"] == (
                "relay.idempotency_required"
            )
            assert counter.read_text(encoding="utf-8") == "0"

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

            replayed = client.post(
                "/v1/relay/mcp/call",
                json={
                    "target_id": "catalog",
                    "capability_token": capability,
                    "arguments": {"q": "invoice"},
                },
                headers=_headers(credential=credential, idempotency_key=call_key),
            )
            assert replayed.status_code == 200, replayed.text
            assert replayed.json()["idempotent_replay"] is True
            assert "X-AgentHub-Idempotent-Replay" not in replayed.headers
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


def test_api_restart_exposes_recovered_domain_outcome_without_replay(
    tmp_path: Path,
) -> None:
    with _official_server(tmp_path) as (port, counter):
        with _agenthub_api_process(
            tmp_path, upstream_port=port, instance_name="initial"
        ) as (client, process):
            registered = client.post(
                "/v1/identity/agents",
                json={"agent_id": "agent-crash"},
                headers=_headers(api_key="owner-a-key", idempotency_key=uuid4().hex),
            )
            assert registered.status_code == 200, registered.text
            issued_credential = client.post(
                "/v1/identity/agents/agent-crash/credentials",
                json={
                    "scopes": [
                        "relay.call",
                        "relay.read",
                        "mcp.tools.lookup.invoke",
                    ],
                    "ttl_seconds": 3600,
                },
                headers=_headers(api_key="owner-a-key", idempotency_key=uuid4().hex),
            )
            assert issued_credential.status_code == 200, issued_credential.text
            credential = str(issued_credential.json()["secret"])
            issued_capability = client.post(
                "/v1/identity/capability-tokens/issue",
                json={
                    "issuer_agent_id": "agent-crash",
                    "subject_agent_id": "agent-crash",
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
            with pytest.raises(httpx.HTTPError):
                client.post(
                    "/v1/relay/mcp/call",
                    json={
                        "target_id": "catalog",
                        "capability_token": capability,
                        "arguments": {"q": "crash-through-api"},
                    },
                    headers=_headers(credential=credential, idempotency_key=call_key),
                )
            assert process.wait(timeout=5) == CRASH_EXIT_CODE

        assert counter.read_text(encoding="utf-8") == "1"
        with _agenthub_api_process(
            tmp_path, upstream_port=port, instance_name="restarted"
        ) as (restarted, process):
            replay = restarted.post(
                "/v1/relay/mcp/call",
                json={
                    "target_id": "catalog",
                    "capability_token": capability,
                    "arguments": {"q": "crash-through-api"},
                },
                headers=_headers(credential=credential, idempotency_key=call_key),
            )
            assert replay.status_code == 409, replay.text
            assert replay.json()["detail"]["code"] == "relay.replay_blocked"
            recovered = replay.json()["detail"]["invocation"]
            assert recovered["status"] == "indeterminate"
            verification = restarted.post(
                "/v1/relay/receipts/verify", json={"receipt": recovered["receipt"]}
            )
            assert verification.status_code == 200, verification.text
            assert verification.json() == {"valid": True, "reason": "ok"}
            assert process.poll() is None
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

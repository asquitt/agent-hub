from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
from urllib.error import URLError
from urllib.request import urlopen

import pytest


ROOT = Path(__file__).resolve().parents[2]
CLIENT_SCRIPT = Path(__file__).with_name("official_mcp_sdk_client_s164.py")


def _available_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_for_server(process: subprocess.Popen[str], health_url: str) -> None:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if process.poll() is not None:
            output = process.stdout.read() if process.stdout is not None else ""
            pytest.fail(f"MCP test server exited during startup:\n{output}")
        try:
            with urlopen(health_url, timeout=1) as response:  # noqa: S310 - local test server only
                if response.status == 200:
                    return
        except (OSError, URLError):
            time.sleep(0.1)
    pytest.fail("MCP test server did not become healthy")


def test_official_mcp_sdk_runs_streamable_http_lifecycle(tmp_path: Path) -> None:
    client_python_raw = os.getenv("AGENTHUB_OFFICIAL_MCP_PYTHON", "").strip()
    if not client_python_raw:
        pytest.skip("set AGENTHUB_OFFICIAL_MCP_PYTHON to the isolated official MCP SDK interpreter")
    client_python = Path(client_python_raw)
    if not client_python.is_file():
        pytest.fail("AGENTHUB_OFFICIAL_MCP_PYTHON does not identify a file")

    port = _available_port()
    base_url = f"http://127.0.0.1:{port}"
    api_key = "official-mcp-client-key"
    server_env = os.environ.copy()
    server_env.update(
        {
            "AGENTHUB_ACCESS_ENFORCEMENT_MODE": "enforce",
            "AGENTHUB_BASE_URL": base_url,
            "AGENTHUB_API_KEYS_JSON": json.dumps(
                {
                    api_key: {
                        "owner": "official-mcp-client",
                        "scopes": ["discovery.read", "discovery.search"],
                        "roles": ["member"],
                    }
                }
            ),
            "AGENTHUB_OWNER_TENANTS_JSON": json.dumps(
                {"official-mcp-client": ["tenant-default"]}
            ),
            "AGENTHUB_AUTH_TOKEN_SECRET": "official-mcp-auth-secret-at-least-32-bytes",
            "AGENTHUB_IDENTITY_SIGNING_SECRET": "official-mcp-identity-secret-at-least-32-bytes",
            "AGENTHUB_POLICY_SIGNING_SECRET": "official-mcp-policy-secret-at-least-32-bytes",
            "AGENTHUB_PROVENANCE_SIGNING_SECRET": "official-mcp-provenance-secret-at-least-32-bytes",
            "AGENTHUB_VAULT_KEY": "official-mcp-vault-key-at-least-32-bytes",
            "AGENTHUB_FEDERATION_DOMAIN_TOKENS_JSON": json.dumps(
                {"test.local": "official-mcp-federation-token"}
            ),
            "AGENTHUB_REGISTRY_DB_PATH": str(tmp_path / "registry.db"),
            "AGENTHUB_IDENTITY_DB_PATH": str(tmp_path / "identity.db"),
            "AGENTHUB_RUNTIME_DB_PATH": str(tmp_path / "runtime.db"),
            "AGENTHUB_DELEGATION_DB_PATH": str(tmp_path / "delegation.db"),
            "AGENTHUB_IDEMPOTENCY_DB_PATH": str(tmp_path / "idempotency.db"),
            "AGENTHUB_BILLING_DB_PATH": str(tmp_path / "billing.db"),
            "AGENTHUB_COST_EVENTS_PATH": str(tmp_path / "cost-events.json"),
            "AGENTHUB_AUDIT_STREAM_PATH": str(tmp_path / "audit-events.jsonl"),
            "AGENTHUB_RATE_LIMIT_DEFAULT": "10000/minute",
            "PYTHONPATH": str(ROOT),
        }
    )
    server = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "src.api.app:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        cwd=ROOT,
        env=server_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        _wait_for_server(server, f"{base_url}/healthz")
        completed = subprocess.run(
            [str(client_python), str(CLIENT_SCRIPT), f"{base_url}/mcp"],
            cwd=ROOT,
            env={**os.environ, "AGENTHUB_OFFICIAL_MCP_API_KEY": api_key},
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        result = json.loads(completed.stdout)
        assert result == {
            "is_error": False,
            "protocol_version": "2025-11-25",
            "result_count": 4,
            "sdk_version": "2.1.1",
            "server_name": "agenthub-discovery",
            "tool_names": ["check_compatibility", "get_agent_manifest", "search_capabilities"],
        }
    finally:
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=5)

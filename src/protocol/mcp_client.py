from __future__ import annotations

import hashlib
import json
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from copy import deepcopy
from dataclasses import dataclass
from typing import Any, cast

import httpx2
from mcp.client.client import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.types import CallToolResult, Tool

from src.relay.config import MCPRelayTarget

DEFAULT_TIMEOUT_SECONDS = 30.0
MAX_MCP_RESPONSE_BYTES = 65_536


class MCPRelayClientError(RuntimeError):
    """Base error for a configured MCP relay operation."""


class MCPToolNotFoundError(MCPRelayClientError):
    code = "relay.tool_not_found"
    definite_failure = True


class MCPToolContractDriftError(MCPRelayClientError):
    code = "relay.schema_drift"
    definite_failure = True


class MCPServerIdentityDriftError(MCPRelayClientError):
    code = "relay.server_identity_drift"
    definite_failure = True


class MCPPreDispatchError(MCPRelayClientError):
    code = "relay.upstream_pre_dispatch_failed"
    definite_failure = True


class MCPResponseTooLargeError(MCPRelayClientError, httpx2.StreamError):
    code = "relay.upstream_response_too_large"


class _BoundedResponseStream(httpx2.AsyncByteStream):
    def __init__(self, stream: httpx2.AsyncByteStream, *, max_bytes: int) -> None:
        self._stream = stream
        self._max_bytes = max_bytes
        self._observed_bytes = 0

    async def __aiter__(self) -> AsyncIterator[bytes]:
        async for chunk in self._stream:
            self._observed_bytes += len(chunk)
            if self._observed_bytes > self._max_bytes:
                await self._stream.aclose()
                raise MCPResponseTooLargeError(
                    f"MCP response exceeds {self._max_bytes} bytes"
                )
            yield chunk

    async def aclose(self) -> None:
        await self._stream.aclose()


class _BoundedHTTPTransport(httpx2.AsyncBaseTransport):
    def __init__(self, transport: httpx2.AsyncBaseTransport, *, max_bytes: int) -> None:
        self._transport = transport
        self._max_bytes = max_bytes

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        request.headers["Accept-Encoding"] = "identity"
        response = await self._transport.handle_async_request(request)
        declared_encodings = response.headers.get_list("content-encoding")
        if declared_encodings:
            encodings = [
                token.strip().lower()
                for value in declared_encodings
                for token in value.split(",")
            ]
            if not encodings or any(encoding != "identity" for encoding in encodings):
                await response.aclose()
                raise MCPResponseTooLargeError(
                    "MCP response Content-Encoding must be identity"
                )
        declared_lengths = response.headers.get_list("content-length")
        if declared_lengths:
            normalized = {value.strip() for value in declared_lengths}
            if len(normalized) != 1 or not next(iter(normalized)).isdigit():
                await response.aclose()
                raise MCPResponseTooLargeError(
                    "MCP response has an invalid Content-Length"
                )
            if int(next(iter(normalized))) > self._max_bytes:
                await response.aclose()
                raise MCPResponseTooLargeError(
                    f"MCP response exceeds {self._max_bytes} bytes"
                )
        response.stream = _BoundedResponseStream(
            cast(httpx2.AsyncByteStream, response.stream),
            max_bytes=self._max_bytes,
        )
        return response

    async def aclose(self) -> None:
        await self._transport.aclose()


def _find_response_too_large(
    exc: BaseException,
) -> MCPResponseTooLargeError | None:
    if isinstance(exc, MCPResponseTooLargeError):
        return exc
    if isinstance(exc, BaseExceptionGroup):
        matched_error: MCPResponseTooLargeError | None = None
        for nested in exc.exceptions:
            matched = _find_response_too_large(nested)
            if matched is None:
                return None
            matched_error = matched
        return matched_error
    return None


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


def _json_dict(value: Mapping[str, Any] | None) -> dict[str, Any]:
    return deepcopy(dict(value or {}))


def tool_contract_digest(
    *,
    name: str,
    input_schema: Mapping[str, Any],
    output_schema: Mapping[str, Any] | None,
    annotations: Mapping[str, Any] | None,
) -> str:
    """Hash every advertised field that can change safe call semantics."""
    contract = {
        "name": name,
        "input_schema": _json_dict(input_schema),
        "output_schema": None if output_schema is None else _json_dict(output_schema),
        "annotations": None if annotations is None else _json_dict(annotations),
    }
    return hashlib.sha256(_canonical_json(contract).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class MCPServerIdentity:
    name: str
    version: str
    details: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return deepcopy(self.details)


@dataclass(frozen=True, slots=True)
class MCPToolContract:
    name: str
    description: str | None
    input_schema: dict[str, Any]
    output_schema: dict[str, Any] | None
    annotations: dict[str, Any] | None
    schema_digest: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": deepcopy(self.input_schema),
            "output_schema": deepcopy(self.output_schema),
            "annotations": deepcopy(self.annotations),
            "schema_digest": self.schema_digest,
        }


@dataclass(frozen=True, slots=True)
class MCPInspection:
    target_id: str
    tenant_id: str
    endpoint_digest: str
    policy_revision: str
    max_call_cost_usd: float
    protocol_version: str
    server: MCPServerIdentity
    tool: MCPToolContract

    def as_dict(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "tenant_id": self.tenant_id,
            "endpoint_digest": self.endpoint_digest,
            "policy_revision": self.policy_revision,
            "max_call_cost_usd": self.max_call_cost_usd,
            "protocol_version": self.protocol_version,
            "server": self.server.as_dict(),
            "tool": self.tool.as_dict(),
        }

    def as_target_record(self, target: MCPRelayTarget) -> dict[str, Any]:
        if target.target_id != self.target_id or target.tenant_id != self.tenant_id:
            raise ValueError("inspection and configured target identities do not match")
        return {
            "target_id": self.target_id,
            "tenant_id": self.tenant_id,
            "endpoint_url": target.endpoint_url,
            "endpoint_digest": self.endpoint_digest,
            "tool_name": self.tool.name,
            "server_name": self.server.name,
            "server_version": self.server.version,
            "protocol_version": self.protocol_version,
            "input_schema": deepcopy(self.tool.input_schema),
            "output_schema": deepcopy(self.tool.output_schema),
            "schema_digest": self.tool.schema_digest,
            "annotations": deepcopy(self.tool.annotations),
            "max_call_cost_usd": self.max_call_cost_usd,
            "policy_revision": self.policy_revision,
        }


@dataclass(frozen=True, slots=True)
class MCPCallOutcome:
    inspection: MCPInspection
    content: list[dict[str, Any]]
    structured_content: dict[str, Any] | None
    is_error: bool
    meta: dict[str, Any] | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "inspection": self.inspection.as_dict(),
            "content": deepcopy(self.content),
            "structured_content": deepcopy(self.structured_content),
            "is_error": self.is_error,
            "meta": deepcopy(self.meta),
        }


def _tool_contract(tool: Tool) -> MCPToolContract:
    payload = tool.model_dump(mode="json", by_alias=True, exclude_none=False)
    input_schema = _json_dict(payload["inputSchema"])
    output_payload = payload.get("outputSchema")
    output_schema = None if output_payload is None else _json_dict(output_payload)
    annotation_payload = payload.get("annotations")
    annotations = None if annotation_payload is None else _json_dict(annotation_payload)
    return MCPToolContract(
        name=tool.name,
        description=tool.description,
        input_schema=input_schema,
        output_schema=output_schema,
        annotations=annotations,
        schema_digest=tool_contract_digest(
            name=tool.name,
            input_schema=input_schema,
            output_schema=output_schema,
            annotations=annotations,
        ),
    )


async def _fresh_exact_tool(client: Client, tool_name: str) -> MCPToolContract:
    matches: list[Tool] = []
    cursor: str | None = None
    while True:
        page = await client.list_tools(cursor=cursor, cache_mode="refresh")
        matches.extend(tool for tool in page.tools if tool.name == tool_name)
        cursor = page.next_cursor
        if cursor is None:
            break
    if not matches:
        raise MCPToolNotFoundError(f"configured MCP tool not found: {tool_name}")
    if len(matches) != 1:
        raise MCPRelayClientError(
            f"configured MCP tool is advertised more than once: {tool_name}"
        )
    return _tool_contract(matches[0])


def _server_identity(client: Client) -> MCPServerIdentity:
    server_info = client.server_info
    if server_info is None:
        raise MCPRelayClientError("initialized MCP server did not provide an identity")
    details = server_info.model_dump(mode="json", by_alias=True, exclude_none=False)
    return MCPServerIdentity(
        name=server_info.name,
        version=server_info.version,
        details=_json_dict(details),
    )


async def _inspect_connected(client: Client, target: MCPRelayTarget) -> MCPInspection:
    tool = await _fresh_exact_tool(client, target.tool_name)
    return MCPInspection(
        target_id=target.target_id,
        tenant_id=target.tenant_id,
        endpoint_digest=target.endpoint_digest,
        policy_revision=target.policy_revision,
        max_call_cost_usd=target.max_call_cost_usd,
        protocol_version=client.protocol_version,
        server=_server_identity(client),
        tool=tool,
    )


@asynccontextmanager
async def _configured_client(
    target: MCPRelayTarget,
    *,
    timeout_seconds: float,
) -> AsyncIterator[Client]:
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be greater than zero")
    http_transport = _BoundedHTTPTransport(
        httpx2.AsyncHTTPTransport(retries=0),
        max_bytes=MAX_MCP_RESPONSE_BYTES,
    )
    async with httpx2.AsyncClient(
        follow_redirects=False,
        timeout=httpx2.Timeout(timeout_seconds),
        transport=http_transport,
        trust_env=False,
    ) as http_client:
        transport = streamable_http_client(
            target.endpoint_url,
            http_client=http_client,
            terminate_on_close=True,
        )
        async with Client(
            transport,
            mode="legacy",
            cache=None,
            input_required_max_rounds=0,
            read_timeout_seconds=timeout_seconds,
        ) as client:
            yield client


async def inspect_target(
    target: MCPRelayTarget,
    *,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
) -> MCPInspection:
    """Initialize the configured server and inspect its exact allowlisted tool."""
    async with _configured_client(target, timeout_seconds=timeout_seconds) as client:
        return await _inspect_connected(client, target)


async def call_tool(
    target: MCPRelayTarget,
    *,
    arguments: Mapping[str, Any],
    expected_schema_digest: str,
    expected_server_name: str,
    expected_server_version: str,
    expected_protocol_version: str,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
) -> MCPCallOutcome:
    """Freshly inspect, compare, then issue exactly one configured tools/call."""
    if not isinstance(arguments, Mapping):
        raise TypeError("arguments must be a mapping")
    if not isinstance(expected_schema_digest, str) or not expected_schema_digest:
        raise ValueError("expected_schema_digest is required")

    tool_call_started = False
    try:
        async with _configured_client(
            target, timeout_seconds=timeout_seconds
        ) as client:
            inspection = await _inspect_connected(client, target)
            observed_identity = (
                inspection.server.name,
                inspection.server.version,
                inspection.protocol_version,
            )
            expected_identity = (
                expected_server_name,
                expected_server_version,
                expected_protocol_version,
            )
            if observed_identity != expected_identity:
                raise MCPServerIdentityDriftError(
                    "configured MCP server identity changed before invocation"
                )
            observed_digest = inspection.tool.schema_digest
            if observed_digest != expected_schema_digest:
                raise MCPToolContractDriftError(
                    "configured MCP tool contract changed before invocation: "
                    f"expected {expected_schema_digest}, observed {observed_digest}"
                )

            tool_call_started = True
            result = await client.session.call_tool(
                target.tool_name,
                deepcopy(dict(arguments)),
                read_timeout_seconds=timeout_seconds,
                allow_input_required=False,
                allow_claimed=False,
            )
            if not isinstance(result, CallToolResult):
                raise MCPRelayClientError(
                    f"unexpected MCP tools/call result type: {type(result).__name__}"
                )
            serialized_result = result.model_dump_json(
                by_alias=True,
                exclude_none=False,
            )
            if len(serialized_result.encode("utf-8")) > MAX_MCP_RESPONSE_BYTES:
                raise MCPResponseTooLargeError(
                    f"MCP tools/call result exceeds {MAX_MCP_RESPONSE_BYTES} bytes"
                )
            payload = json.loads(serialized_result)
            if not isinstance(payload, dict):  # pragma: no cover - pydantic contract
                raise MCPRelayClientError("MCP tools/call result is not an object")
            return MCPCallOutcome(
                inspection=inspection,
                content=payload["content"],
                structured_content=payload.get("structuredContent"),
                is_error=bool(payload.get("isError", False)),
                meta=payload.get("_meta"),
            )
    except (
        MCPToolNotFoundError,
        MCPToolContractDriftError,
        MCPServerIdentityDriftError,
        MCPPreDispatchError,
    ):
        raise
    except Exception as exc:
        if tool_call_started:
            oversized = _find_response_too_large(exc)
            if oversized is not None:
                raise oversized from exc
            raise
        raise MCPPreDispatchError(
            "MCP connection or discovery failed before tools/call"
        ) from exc

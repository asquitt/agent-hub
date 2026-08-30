from __future__ import annotations

import asyncio
import gzip
import hashlib
import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from types import SimpleNamespace
from typing import Any, Self

import pytest
from mcp.types import CallToolResult, Implementation, TextContent, Tool

from src.protocol import mcp_client
from src.protocol.mcp_client import (
    MAX_MCP_RESPONSE_BYTES,
    MCPPreDispatchError,
    MCPResponseTooLargeError,
    MCPServerIdentityDriftError,
    MCPToolContractDriftError,
    _BoundedHTTPTransport,
    _tool_contract,
    call_tool,
    inspect_target,
    tool_contract_digest,
)
from src.relay.config import (
    ALLOW_LOOPBACK_HTTP_ENV,
    TARGETS_ENV,
    MCPRelayConfigError,
    endpoint_digest,
    load_mcp_relay_target,
    parse_mcp_relay_targets_json,
    target_policy_revision,
)


def _target(**overrides: object) -> dict[str, object]:
    target: dict[str, object] = {
        "target_id": "readonly-upstream",
        "tenant_id": "tenant-alpha",
        "endpoint_url": "https://mcp.example.test/mcp",
        "tool_name": "catalog.lookup",
        "auth": "none",
        "operator_attests_read_only": True,
        "max_call_cost_usd": 0.0125,
    }
    target.update(overrides)
    return target


def _raw(*targets: dict[str, object]) -> str:
    return json.dumps(list(targets))


def test_parses_exact_single_auth_none_target_and_computes_digests() -> None:
    source = _target()
    target = parse_mcp_relay_targets_json(_raw(source))

    assert target.allowlist_dict() == source
    assert (
        target.endpoint_digest
        == hashlib.sha256(str(source["endpoint_url"]).encode("utf-8")).hexdigest()
    )
    assert target.policy_revision == target_policy_revision(source)
    assert target.as_dict() == {
        **source,
        "endpoint_digest": target.endpoint_digest,
        "policy_revision": target.policy_revision,
    }


@pytest.mark.parametrize(
    "document", [[], [_target(), _target(target_id="second")], _target()]
)
def test_requires_a_one_element_json_array(document: object) -> None:
    with pytest.raises(MCPRelayConfigError, match="exactly one target"):
        parse_mcp_relay_targets_json(json.dumps(document))


@pytest.mark.parametrize(
    "mutation",
    [
        lambda target: target.pop("tenant_id"),
        lambda target: target.update({"url": target["endpoint_url"]}),
    ],
)
def test_rejects_missing_or_unknown_target_fields(mutation: object) -> None:
    target = _target()
    mutation(target)  # type: ignore[operator]
    with pytest.raises(MCPRelayConfigError, match="exactly the required fields"):
        parse_mcp_relay_targets_json(_raw(target))


def test_rejects_duplicate_json_fields() -> None:
    raw = _raw(_target()).replace(
        '"target_id": "readonly-upstream",',
        '"target_id": "shadow", "target_id": "readonly-upstream",',
    )
    with pytest.raises(MCPRelayConfigError, match="duplicate JSON field"):
        parse_mcp_relay_targets_json(raw)


@pytest.mark.parametrize("auth", ["bearer", "None", "", None, {"type": "none"}])
def test_rejects_every_auth_mode_except_exact_none(auth: object) -> None:
    with pytest.raises(MCPRelayConfigError, match="auth must be exactly 'none'"):
        parse_mcp_relay_targets_json(_raw(_target(auth=auth)))


@pytest.mark.parametrize("attestation", [False, None, "true", 1])
def test_requires_exact_operator_read_only_attestation(attestation: object) -> None:
    with pytest.raises(
        MCPRelayConfigError, match="operator_attests_read_only must be exactly true"
    ):
        parse_mcp_relay_targets_json(
            _raw(_target(operator_attests_read_only=attestation))
        )


@pytest.mark.parametrize(
    ("endpoint", "message"),
    [
        ("https://user:secret@mcp.example.test/mcp", "credentials"),
        ("https://mcp.example.test/mcp?tenant=other", "query"),
        ("https://mcp.example.test/mcp?", "query"),
        ("https://mcp.example.test/mcp#tool", "fragment"),
        ("https://mcp.example.test/mcp#", "fragment"),
        ("http://mcp.example.test/mcp", "HTTPS"),
    ],
)
def test_rejects_credentialed_ambiguous_or_public_http_urls(
    endpoint: str, message: str
) -> None:
    with pytest.raises(MCPRelayConfigError, match=message):
        parse_mcp_relay_targets_json(_raw(_target(endpoint_url=endpoint)))


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://localhost:8765/mcp",
        "http://127.0.0.1:8765/mcp",
        "http://[::1]:8765/mcp",
    ],
)
def test_loopback_http_requires_exact_opt_in(endpoint: str) -> None:
    raw = _raw(_target(endpoint_url=endpoint))
    with pytest.raises(MCPRelayConfigError, match="loopback HTTP requires"):
        parse_mcp_relay_targets_json(raw)

    target = load_mcp_relay_target({TARGETS_ENV: raw, ALLOW_LOOPBACK_HTTP_ENV: "true"})
    assert target.endpoint_url == endpoint


def test_loopback_opt_in_does_not_allow_public_http() -> None:
    with pytest.raises(MCPRelayConfigError, match="HTTPS"):
        parse_mcp_relay_targets_json(
            _raw(_target(endpoint_url="http://mcp.example.test/mcp")),
            allow_loopback_http=True,
        )


@pytest.mark.parametrize("flag", ["TRUE", "1", "yes", " true "])
def test_loopback_environment_flag_is_exact(flag: str) -> None:
    with pytest.raises(MCPRelayConfigError, match="exactly 'true' or 'false'"):
        load_mcp_relay_target(
            {TARGETS_ENV: _raw(_target()), ALLOW_LOOPBACK_HTTP_ENV: flag}
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("target_id", ""),
        ("tenant_id", " tenant-alpha"),
        ("tool_name", ""),
        ("tool_name", "catalog.lookup "),
    ],
)
def test_requires_exact_target_tool_and_tenant_values(
    field: str, value: object
) -> None:
    with pytest.raises(MCPRelayConfigError):
        parse_mcp_relay_targets_json(_raw(_target(**{field: value})))


@pytest.mark.parametrize("cost", [True, -0.01, float("inf"), float("nan"), "0.01"])
def test_rejects_invalid_call_costs(cost: object) -> None:
    with pytest.raises(MCPRelayConfigError, match="finite non-negative number"):
        parse_mcp_relay_targets_json(_raw(_target(max_call_cost_usd=cost)))


def test_endpoint_and_policy_digests_are_exact_and_deterministic() -> None:
    first = _target()
    reordered = dict(reversed(list(first.items())))

    assert endpoint_digest(str(first["endpoint_url"])) != endpoint_digest(
        "https://mcp.example.test/mcp/"
    )
    assert target_policy_revision(first) == target_policy_revision(reordered)
    assert target_policy_revision(first) != target_policy_revision(
        {**first, "tool_name": "catalog.other"}
    )


def test_tool_contract_digest_canonicalizes_keys_and_detects_semantic_drift() -> None:
    input_schema = {
        "type": "object",
        "properties": {"query": {"type": "string"}},
        "required": ["query"],
    }
    reordered_input = dict(reversed(list(input_schema.items())))
    annotations = {"readOnlyHint": True, "idempotentHint": True}

    baseline = tool_contract_digest(
        name="catalog.lookup",
        input_schema=input_schema,
        output_schema={"type": "object"},
        annotations=annotations,
    )
    assert baseline == tool_contract_digest(
        name="catalog.lookup",
        input_schema=reordered_input,
        output_schema={"type": "object"},
        annotations=dict(reversed(list(annotations.items()))),
    )
    assert baseline != tool_contract_digest(
        name="catalog.lookup",
        input_schema=input_schema,
        output_schema={"type": "object"},
        annotations={**annotations, "readOnlyHint": False},
    )


def test_official_tool_conversion_preserves_schemas_and_annotations() -> None:
    tool = Tool.model_validate(
        {
            "name": "catalog.lookup",
            "description": "Read one catalog entry",
            "inputSchema": {
                "type": "object",
                "properties": {"id": {"type": "string"}},
                "required": ["id"],
            },
            "outputSchema": {
                "type": "object",
                "properties": {"title": {"type": "string"}},
            },
            "annotations": {
                "title": "Catalog lookup",
                "readOnlyHint": True,
                "idempotentHint": True,
                "openWorldHint": False,
            },
        }
    )

    contract = _tool_contract(tool)
    payload = tool.model_dump(mode="json", by_alias=True, exclude_none=False)

    assert contract.input_schema == payload["inputSchema"]
    assert contract.output_schema == payload["outputSchema"]
    assert contract.annotations == payload["annotations"]
    assert contract.as_dict()["schema_digest"] == contract.schema_digest


class _FakeSession:
    def __init__(self) -> None:
        self.call_count = 0

    async def call_tool(
        self, name: str, arguments: dict[str, object], **_: object
    ) -> CallToolResult:
        self.call_count += 1
        assert name == "catalog.lookup"
        assert arguments == {"id": "item-1"}
        return CallToolResult(
            content=[TextContent(type="text", text="found")],
            structured_content={"title": "Example"},
            is_error=False,
        )


class _OversizedFakeSession(_FakeSession):
    async def call_tool(
        self, name: str, arguments: dict[str, object], **kwargs: object
    ) -> CallToolResult:
        result = await super().call_tool(name, arguments, **kwargs)
        return result.model_copy(
            update={
                "content": [
                    TextContent(
                        type="text",
                        text="x" * (MAX_MCP_RESPONSE_BYTES + 1),
                    )
                ],
                "structured_content": {"title": "small"},
            }
        )


class _FakeClient:
    protocol_version = "2025-06-18"
    server_info = Implementation(
        name="upstream-catalog",
        title="Upstream Catalog",
        version="1.4.2",
    )

    def __init__(self, tool: Tool) -> None:
        self.tool = tool
        self.list_count = 0
        self.session = _FakeSession()

    async def list_tools(self, **_: object) -> SimpleNamespace:
        self.list_count += 1
        return SimpleNamespace(tools=[self.tool], next_cursor=None)


def _fake_tool(*, read_only: bool = True) -> Tool:
    return Tool.model_validate(
        {
            "name": "catalog.lookup",
            "description": "Read one catalog entry",
            "inputSchema": {
                "type": "object",
                "properties": {"id": {"type": "string"}},
                "required": ["id"],
            },
            "outputSchema": {
                "type": "object",
                "properties": {"title": {"type": "string"}},
            },
            "annotations": {
                "readOnlyHint": read_only,
                "idempotentHint": True,
                "openWorldHint": False,
            },
        }
    )


def _install_fake_client(monkeypatch: pytest.MonkeyPatch, fake: _FakeClient) -> None:
    @asynccontextmanager
    async def configured_client(*_: object, **__: object) -> AsyncIterator[_FakeClient]:
        yield fake

    monkeypatch.setattr(mcp_client, "_configured_client", configured_client)


def test_inspect_preserves_server_protocol_and_exact_tool_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = parse_mcp_relay_targets_json(_raw(_target()))
    fake = _FakeClient(_fake_tool())
    _install_fake_client(monkeypatch, fake)

    inspection = asyncio.run(inspect_target(target))

    assert fake.list_count == 1
    assert inspection.protocol_version == "2025-06-18"
    assert inspection.server.as_dict() == {
        "name": "upstream-catalog",
        "title": "Upstream Catalog",
        "version": "1.4.2",
        "description": None,
        "websiteUrl": None,
        "icons": None,
    }
    assert inspection.tool.input_schema["required"] == ["id"]
    assert inspection.tool.output_schema == {
        "type": "object",
        "properties": {"title": {"type": "string"}},
    }
    assert inspection.tool.annotations is not None
    assert inspection.tool.annotations["readOnlyHint"] is True


def test_call_freshly_lists_and_invokes_exactly_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = parse_mcp_relay_targets_json(_raw(_target()))
    fake = _FakeClient(_fake_tool())
    _install_fake_client(monkeypatch, fake)
    expected = _tool_contract(fake.tool).schema_digest

    outcome = asyncio.run(
        call_tool(
            target,
            arguments={"id": "item-1"},
            expected_schema_digest=expected,
            expected_server_name="upstream-catalog",
            expected_server_version="1.4.2",
            expected_protocol_version="2025-06-18",
        )
    )

    assert fake.list_count == 1
    assert fake.session.call_count == 1
    assert outcome.structured_content == {"title": "Example"}
    assert outcome.is_error is False


def test_call_bounds_complete_result_before_application_copies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = parse_mcp_relay_targets_json(_raw(_target()))
    fake = _FakeClient(_fake_tool())
    fake.session = _OversizedFakeSession()
    _install_fake_client(monkeypatch, fake)

    with pytest.raises(MCPResponseTooLargeError, match="result exceeds"):
        asyncio.run(
            call_tool(
                target,
                arguments={"id": "item-1"},
                expected_schema_digest=_tool_contract(fake.tool).schema_digest,
                expected_server_name="upstream-catalog",
                expected_server_version="1.4.2",
                expected_protocol_version="2025-06-18",
            )
        )

    assert fake.session.call_count == 1


def test_call_blocks_fresh_schema_drift_before_remote_invocation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = parse_mcp_relay_targets_json(_raw(_target()))
    expected = _tool_contract(_fake_tool(read_only=True)).schema_digest
    fake = _FakeClient(_fake_tool(read_only=False))
    _install_fake_client(monkeypatch, fake)

    with pytest.raises(MCPToolContractDriftError, match="contract changed"):
        asyncio.run(
            call_tool(
                target,
                arguments={"id": "item-1"},
                expected_schema_digest=expected,
                expected_server_name="upstream-catalog",
                expected_server_version="1.4.2",
                expected_protocol_version="2025-06-18",
            )
        )

    assert fake.list_count == 1
    assert fake.session.call_count == 0


def test_call_blocks_server_identity_drift_before_remote_invocation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = parse_mcp_relay_targets_json(_raw(_target()))
    fake = _FakeClient(_fake_tool())
    _install_fake_client(monkeypatch, fake)

    with pytest.raises(MCPServerIdentityDriftError, match="identity changed"):
        asyncio.run(
            call_tool(
                target,
                arguments={"id": "item-1"},
                expected_schema_digest=_tool_contract(fake.tool).schema_digest,
                expected_server_name="different-server",
                expected_server_version="1.4.2",
                expected_protocol_version="2025-06-18",
            )
        )

    assert fake.list_count == 1
    assert fake.session.call_count == 0


def test_connection_failure_before_tools_call_is_definite_and_uncharged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = parse_mcp_relay_targets_json(_raw(_target()))

    @asynccontextmanager
    async def unavailable(*_: object, **__: object) -> AsyncIterator[_FakeClient]:
        raise TimeoutError("connect failed")
        yield _FakeClient(_fake_tool())  # pragma: no cover

    monkeypatch.setattr(mcp_client, "_configured_client", unavailable)
    with pytest.raises(MCPPreDispatchError, match="before tools/call") as exc_info:
        asyncio.run(
            call_tool(
                target,
                arguments={"id": "item-1"},
                expected_schema_digest="schema-digest",
                expected_server_name="upstream-catalog",
                expected_server_version="1.4.2",
                expected_protocol_version="2025-06-18",
            )
        )
    assert exc_info.value.definite_failure is True


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"content-length": "1"},
        {"content-encoding": "Identity"},
    ],
)
def test_bounded_transport_counts_streamed_bytes_when_length_is_missing_or_false(
    headers: dict[str, str],
) -> None:
    class ChunkStream(mcp_client.httpx2.AsyncByteStream):
        def __init__(self) -> None:
            self.closed = False

        async def __aiter__(self) -> AsyncIterator[bytes]:
            yield b"a" * MAX_MCP_RESPONSE_BYTES
            yield b"b"

        async def aclose(self) -> None:
            self.closed = True

    stream = ChunkStream()

    class InnerTransport(mcp_client.httpx2.AsyncBaseTransport):
        async def handle_async_request(
            self, request: mcp_client.httpx2.Request
        ) -> mcp_client.httpx2.Response:
            return mcp_client.httpx2.Response(
                200,
                headers=headers,
                stream=stream,
                request=request,
            )

    async def read_response() -> None:
        transport = _BoundedHTTPTransport(
            InnerTransport(), max_bytes=MAX_MCP_RESPONSE_BYTES
        )
        request = mcp_client.httpx2.Request("POST", "https://mcp.example.test")
        response = await transport.handle_async_request(request)
        with pytest.raises(MCPResponseTooLargeError, match="response exceeds"):
            await response.aread()

    asyncio.run(read_response())
    assert stream.closed is True


@pytest.mark.parametrize("content_type", ["application/json", "text/event-stream"])
@pytest.mark.parametrize(
    "content_encoding",
    ["gzip", "deflate", "br", "zstd", "gzip, identity", ""],
)
def test_bounded_transport_rejects_encoded_expansion_before_decoding(
    content_type: str,
    content_encoding: str,
) -> None:
    decoded = b"x" * (MAX_MCP_RESPONSE_BYTES * 4)
    encoded = gzip.compress(decoded)
    observed_request_headers: dict[str, str] = {}

    class EncodedStream(mcp_client.httpx2.AsyncByteStream):
        def __init__(self) -> None:
            self.closed = False
            self.iterated = False

        async def __aiter__(self) -> AsyncIterator[bytes]:
            self.iterated = True
            yield encoded

        async def aclose(self) -> None:
            self.closed = True

    stream = EncodedStream()

    class InnerTransport(mcp_client.httpx2.AsyncBaseTransport):
        async def handle_async_request(
            self, request: mcp_client.httpx2.Request
        ) -> mcp_client.httpx2.Response:
            observed_request_headers.update(dict(request.headers))
            return mcp_client.httpx2.Response(
                200,
                headers={
                    "content-encoding": content_encoding,
                    "content-length": str(len(encoded)),
                    "content-type": content_type,
                },
                stream=stream,
                request=request,
            )

    async def read_response() -> None:
        transport = _BoundedHTTPTransport(
            InnerTransport(), max_bytes=MAX_MCP_RESPONSE_BYTES
        )
        async with mcp_client.httpx2.AsyncClient(transport=transport) as client:
            with pytest.raises(
                MCPResponseTooLargeError, match="Content-Encoding must be identity"
            ):
                await client.get("https://mcp.example.test")

    assert len(encoded) < MAX_MCP_RESPONSE_BYTES
    assert len(decoded) > MAX_MCP_RESPONSE_BYTES
    asyncio.run(read_response())
    assert observed_request_headers["accept-encoding"] == "identity"
    assert stream.iterated is False
    assert stream.closed is True


@pytest.mark.parametrize(
    "content_length",
    [str(MAX_MCP_RESPONSE_BYTES + 1), "not-a-number", "10, 11"],
)
def test_bounded_transport_rejects_invalid_or_oversized_declared_length(
    content_length: str,
) -> None:
    class EmptyStream(mcp_client.httpx2.AsyncByteStream):
        def __init__(self) -> None:
            self.closed = False

        async def __aiter__(self) -> AsyncIterator[bytes]:
            if False:  # pragma: no cover
                yield b""

        async def aclose(self) -> None:
            self.closed = True

    stream = EmptyStream()

    class InnerTransport(mcp_client.httpx2.AsyncBaseTransport):
        async def handle_async_request(
            self, request: mcp_client.httpx2.Request
        ) -> mcp_client.httpx2.Response:
            return mcp_client.httpx2.Response(
                200,
                headers={"content-length": content_length},
                stream=stream,
                request=request,
            )

    async def open_response() -> None:
        transport = _BoundedHTTPTransport(
            InnerTransport(), max_bytes=MAX_MCP_RESPONSE_BYTES
        )
        request = mcp_client.httpx2.Request("POST", "https://mcp.example.test")
        with pytest.raises(MCPResponseTooLargeError):
            await transport.handle_async_request(request)

    asyncio.run(open_response())
    assert stream.closed is True


def test_transport_uses_official_stream_client_without_redirects_or_retries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = parse_mcp_relay_targets_json(_raw(_target()))
    observed: dict[str, Any] = {}

    class FakeHTTPTransport:
        def __init__(self, *, retries: int) -> None:
            observed["retries"] = retries

    class FakeHTTPClient:
        def __init__(self, **kwargs: object) -> None:
            observed["http_client"] = self
            observed["http_client_kwargs"] = kwargs

        async def __aenter__(self) -> Self:
            return self

        async def __aexit__(self, *_: object) -> None:
            return None

    stream_transport = object()

    def fake_streamable_http_client(url: str, **kwargs: object) -> object:
        observed["stream_url"] = url
        observed["stream_kwargs"] = kwargs
        return stream_transport

    class FakeOfficialClient:
        def __init__(self, server: object, **kwargs: object) -> None:
            observed["client_server"] = server
            observed["client_kwargs"] = kwargs

        async def __aenter__(self) -> Self:
            return self

        async def __aexit__(self, *_: object) -> None:
            return None

    monkeypatch.setattr(mcp_client.httpx2, "AsyncHTTPTransport", FakeHTTPTransport)
    monkeypatch.setattr(mcp_client.httpx2, "AsyncClient", FakeHTTPClient)
    monkeypatch.setattr(
        mcp_client, "streamable_http_client", fake_streamable_http_client
    )
    monkeypatch.setattr(mcp_client, "Client", FakeOfficialClient)

    async def open_client() -> None:
        async with mcp_client._configured_client(target, timeout_seconds=7.0):
            pass

    asyncio.run(open_client())

    assert observed["retries"] == 0
    http_client_kwargs = observed["http_client_kwargs"]
    assert http_client_kwargs["follow_redirects"] is False
    assert str(http_client_kwargs["timeout"]) == str(mcp_client.httpx2.Timeout(7.0))
    bounded_transport = http_client_kwargs["transport"]
    assert isinstance(bounded_transport, _BoundedHTTPTransport)
    assert isinstance(bounded_transport._transport, FakeHTTPTransport)
    assert bounded_transport._max_bytes == MAX_MCP_RESPONSE_BYTES
    assert http_client_kwargs["trust_env"] is False
    assert observed["stream_url"] == target.endpoint_url
    assert observed["stream_kwargs"]["http_client"] is observed["http_client"]
    assert observed["stream_kwargs"]["terminate_on_close"] is True
    assert observed["client_server"] is stream_transport
    assert observed["client_kwargs"] == {
        "mode": "legacy",
        "cache": None,
        "input_required_max_rounds": 0,
        "read_timeout_seconds": 7.0,
    }

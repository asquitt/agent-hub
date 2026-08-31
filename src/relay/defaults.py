from __future__ import annotations

from collections.abc import Callable
from typing import Any

from src.protocol.mcp_client import call_tool, inspect_target
from src.relay.config import MCPRelayTarget, load_mcp_relay_target
from src.relay.service import RelayService


def configured_target(target_id: str) -> MCPRelayTarget:
    target = load_mcp_relay_target()
    if target.target_id != target_id:
        raise KeyError(f"relay target not found: {target_id}")
    return target


def _target(value: dict[str, Any]) -> MCPRelayTarget:
    fields = {
        "target_id",
        "tenant_id",
        "endpoint_url",
        "tool_name",
        "auth",
        "operator_attests_read_only",
        "max_call_cost_usd",
        "endpoint_digest",
        "policy_revision",
    }
    return MCPRelayTarget(**{key: value[key] for key in fields})


class OfficialMCPRelayTransport:
    async def inspect(self, target: dict[str, Any]) -> dict[str, Any]:
        inspection = await inspect_target(_target(target))
        return {
            "server_name": inspection.server.name,
            "server_version": inspection.server.version,
            "protocol_version": inspection.protocol_version,
            "tool": inspection.tool.as_dict(),
        }

    async def call(
        self,
        target: dict[str, Any],
        *,
        arguments: dict[str, Any],
        before_dispatch: Callable[[], None],
        expected_schema_digest: str,
    ) -> dict[str, Any]:
        outcome = await call_tool(
            _target(target),
            arguments=arguments,
            before_dispatch=before_dispatch,
            expected_schema_digest=expected_schema_digest,
            expected_server_name=str(target["server_name"]),
            expected_server_version=str(target["server_version"]),
            expected_protocol_version=str(target["protocol_version"]),
        )
        return {
            "schema_digest": outcome.inspection.tool.schema_digest,
            "content": outcome.content,
            "structured_content": outcome.structured_content,
            "is_error": outcome.is_error,
            "meta": outcome.meta,
        }


RELAY_SERVICE = RelayService(
    transport=OfficialMCPRelayTransport(),
    config_loader=configured_target,
)

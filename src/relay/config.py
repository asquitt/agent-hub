from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

TARGETS_ENV = "AGENTHUB_MCP_RELAY_TARGETS_JSON"
ALLOW_LOOPBACK_HTTP_ENV = "AGENTHUB_MCP_RELAY_ALLOW_LOOPBACK_HTTP"

_TARGET_FIELDS = frozenset(
    {
        "target_id",
        "tenant_id",
        "endpoint_url",
        "tool_name",
        "auth",
        "operator_attests_read_only",
        "max_call_cost_usd",
    }
)
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class MCPRelayConfigError(ValueError):
    """Raised when the operator-owned MCP relay allowlist is invalid."""


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _reject_duplicate_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise MCPRelayConfigError(f"duplicate JSON field is not allowed: {key}")
        result[key] = value
    return result


def _required_identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER_RE.fullmatch(value):
        raise MCPRelayConfigError(
            f"{field} must be a non-empty identifier of at most 128 characters"
        )
    return value


def _required_exact_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise MCPRelayConfigError(
            f"{field} must be a non-empty string without surrounding whitespace"
        )
    if any(ord(character) < 0x20 for character in value):
        raise MCPRelayConfigError(f"{field} must not contain control characters")
    return value


def _is_loopback_host(hostname: str) -> bool:
    if hostname.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def _validate_endpoint(value: Any, *, allow_loopback_http: bool) -> str:
    endpoint = _required_exact_string(value, "endpoint_url")
    if any(character in endpoint for character in ("\r", "\n", "\t")):
        raise MCPRelayConfigError("endpoint_url must not contain control characters")

    try:
        parsed = urlsplit(endpoint)
        _ = parsed.port
    except ValueError as exc:
        raise MCPRelayConfigError("endpoint_url is not a valid URL") from exc

    if not parsed.hostname:
        raise MCPRelayConfigError("endpoint_url must include a hostname")
    if parsed.username is not None or parsed.password is not None:
        raise MCPRelayConfigError("endpoint_url must not include credentials")
    if "?" in endpoint:
        raise MCPRelayConfigError("endpoint_url must not include a query")
    if "#" in endpoint:
        raise MCPRelayConfigError("endpoint_url must not include a fragment")

    if parsed.scheme == "https":
        return endpoint
    if (
        parsed.scheme == "http"
        and allow_loopback_http
        and _is_loopback_host(parsed.hostname)
    ):
        return endpoint
    raise MCPRelayConfigError(
        "endpoint_url must use HTTPS; loopback HTTP requires "
        f"{ALLOW_LOOPBACK_HTTP_ENV}=true"
    )


def _validate_cost(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise MCPRelayConfigError(
            "max_call_cost_usd must be a finite non-negative number"
        )
    cost = float(value)
    if not math.isfinite(cost) or cost < 0:
        raise MCPRelayConfigError(
            "max_call_cost_usd must be a finite non-negative number"
        )
    return cost


@dataclass(frozen=True, slots=True)
class MCPRelayTarget:
    target_id: str
    tenant_id: str
    endpoint_url: str
    tool_name: str
    auth: str
    operator_attests_read_only: bool
    max_call_cost_usd: float
    endpoint_digest: str
    policy_revision: str

    def allowlist_dict(self) -> dict[str, Any]:
        """Return only the exact operator-authored allowlist fields."""
        return {
            "target_id": self.target_id,
            "tenant_id": self.tenant_id,
            "endpoint_url": self.endpoint_url,
            "tool_name": self.tool_name,
            "auth": self.auth,
            "operator_attests_read_only": self.operator_attests_read_only,
            "max_call_cost_usd": self.max_call_cost_usd,
        }

    def as_dict(self) -> dict[str, Any]:
        return {
            **self.allowlist_dict(),
            "endpoint_digest": self.endpoint_digest,
            "policy_revision": self.policy_revision,
        }


def endpoint_digest(endpoint_url: str) -> str:
    """Hash the exact configured endpoint without normalization."""
    return _sha256_text(endpoint_url)


def target_policy_revision(target: Mapping[str, Any]) -> str:
    """Hash the canonical allowlist contract, including policy-relevant limits."""
    return _sha256_text(_canonical_json(dict(target)))


def parse_mcp_relay_targets_json(
    raw: str,
    *,
    allow_loopback_http: bool = False,
) -> MCPRelayTarget:
    """Parse the fail-closed, exactly-one-target relay allowlist."""
    if not isinstance(raw, str) or not raw.strip():
        raise MCPRelayConfigError(f"{TARGETS_ENV} must contain a JSON array")
    try:
        document = json.loads(raw, object_pairs_hook=_reject_duplicate_fields)
    except json.JSONDecodeError as exc:
        raise MCPRelayConfigError(f"{TARGETS_ENV} must contain valid JSON") from exc

    if not isinstance(document, list) or len(document) != 1:
        raise MCPRelayConfigError(f"{TARGETS_ENV} must contain exactly one target")
    source = document[0]
    if not isinstance(source, dict):
        raise MCPRelayConfigError("the relay target must be a JSON object")

    actual_fields = frozenset(source)
    if actual_fields != _TARGET_FIELDS:
        missing = sorted(_TARGET_FIELDS - actual_fields)
        unknown = sorted(actual_fields - _TARGET_FIELDS)
        details = []
        if missing:
            details.append(f"missing={missing}")
        if unknown:
            details.append(f"unknown={unknown}")
        raise MCPRelayConfigError(
            "the relay target must contain exactly the required fields"
            + (f" ({', '.join(details)})" if details else "")
        )

    target_id = _required_identifier(source["target_id"], "target_id")
    tenant_id = _required_identifier(source["tenant_id"], "tenant_id")
    endpoint_url = _validate_endpoint(
        source["endpoint_url"], allow_loopback_http=allow_loopback_http
    )
    tool_name = _required_exact_string(source["tool_name"], "tool_name")
    if source["auth"] != "none":
        raise MCPRelayConfigError("auth must be exactly 'none'")
    if source["operator_attests_read_only"] is not True:
        raise MCPRelayConfigError("operator_attests_read_only must be exactly true")
    max_call_cost_usd = _validate_cost(source["max_call_cost_usd"])

    allowlist = {
        "target_id": target_id,
        "tenant_id": tenant_id,
        "endpoint_url": endpoint_url,
        "tool_name": tool_name,
        "auth": "none",
        "operator_attests_read_only": True,
        "max_call_cost_usd": max_call_cost_usd,
    }
    return MCPRelayTarget(
        **allowlist,
        endpoint_digest=endpoint_digest(endpoint_url),
        policy_revision=target_policy_revision(allowlist),
    )


def _parse_loopback_http_flag(value: str | None) -> bool:
    if value is None or value == "false":
        return False
    if value == "true":
        return True
    raise MCPRelayConfigError(
        f"{ALLOW_LOOPBACK_HTTP_ENV} must be exactly 'true' or 'false'"
    )


def load_mcp_relay_target(
    environ: Mapping[str, str] | None = None,
) -> MCPRelayTarget:
    """Load the sole operator-owned target; callers cannot supply an endpoint."""
    values = os.environ if environ is None else environ
    raw = values.get(TARGETS_ENV)
    if raw is None:
        raise MCPRelayConfigError(f"{TARGETS_ENV} is required")
    return parse_mcp_relay_targets_json(
        raw,
        allow_loopback_http=_parse_loopback_http_flag(
            values.get(ALLOW_LOOPBACK_HTTP_ENV)
        ),
    )

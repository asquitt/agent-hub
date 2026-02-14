"""Delegation chain middleware — enforces scope attenuation at every hop.

When a request carries an X-Delegation-Token header, this middleware:
1. Validates the full delegation chain
2. Verifies scopes cover the requested operation
3. Enforces that each hop attenuates scopes (child ⊂ parent)
4. Sets request.state.delegation_context for downstream handlers
"""
from __future__ import annotations

import logging
import re
from typing import Any

from fastapi import Request
from starlette.types import ASGIApp, Receive, Scope, Send

from src.api.route_helpers import stable_error

_log = logging.getLogger("agenthub.delegation_chain")

# Route → required scope mapping for delegation-based access control.
# Routes not listed here don't require specific delegation scopes.
ROUTE_SCOPE_MAP: list[tuple[re.Pattern[str], str]] = [
    # Read operations
    (re.compile(r"^GET /v1/agents"), "read"),
    (re.compile(r"^GET /v1/discovery"), "discovery.search"),
    (re.compile(r"^GET /v1/identity"), "read"),
    (re.compile(r"^GET /v1/capabilities"), "read"),
    # Write operations
    (re.compile(r"^POST /v1/agents"), "write"),
    (re.compile(r"^PUT /v1/agents"), "write"),
    (re.compile(r"^DELETE /v1/agents"), "write"),
    (re.compile(r"^POST /v1/identity"), "write"),
    (re.compile(r"^PUT /v1/identity"), "write"),
    # Delegation operations
    (re.compile(r"^POST /v1/delegations"), "delegation.create"),
    (re.compile(r"^POST /v1/identity/delegation-tokens"), "delegation.create"),
    # Runtime operations
    (re.compile(r"^POST /v1/runtime/sandboxes"), "runtime.execute"),
    (re.compile(r"^POST /v1/runtime/sandboxes/[^/]+/execute"), "runtime.execute"),
    # Discovery
    (re.compile(r"^POST /v1/discovery/search"), "discovery.search"),
    (re.compile(r"^POST /v1/discovery/contract-match"), "discovery.search"),
]


def required_scope_for_route(method: str, path: str) -> str | None:
    """Determine the required delegation scope for a given route."""
    key = f"{method.upper()} {path}"
    for pattern, scope in ROUTE_SCOPE_MAP:
        if pattern.match(key):
            return scope
    return None


def _verify_scope_attenuation(chain: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Verify that each hop in the delegation chain attenuates scopes.

    Returns an error dict if attenuation is violated, None if valid.
    """
    if len(chain) < 2:
        return None

    for i in range(1, len(chain)):
        parent_scopes = set(chain[i - 1].get("delegated_scopes", []))
        child_scopes = set(chain[i].get("delegated_scopes", []))

        # Wildcard parent allows any child scopes
        if "*" in parent_scopes:
            continue

        # Child scopes must be a subset of parent scopes
        excess = child_scopes - parent_scopes
        if excess:
            return {
                "hop": i,
                "parent_token": chain[i - 1].get("token_id", ""),
                "child_token": chain[i].get("token_id", ""),
                "excess_scopes": sorted(excess),
            }

    return None


class DelegationChainMiddleware:
    """ASGI middleware enforcing delegation scope attenuation."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope)
        delegation_token = request.headers.get("x-delegation-token")

        if not delegation_token:
            await self.app(scope, receive, send)
            return

        method = request.method.upper()
        path = request.url.path

        # Verify the delegation token
        try:
            from src.identity.delegation_tokens import (
                get_delegation_chain,
                verify_delegation_token,
            )

            token_result = verify_delegation_token(delegation_token)
        except PermissionError as exc:
            response = stable_error(
                401, "delegation.invalid", f"delegation token validation failed: {exc}"
            )
            await response(scope, receive, send)
            return

        # Verify scope attenuation across the chain
        try:
            chain_result = get_delegation_chain(token_result["token_id"])
            chain_hops = chain_result.get("chain", [])
        except KeyError:
            chain_hops = []

        if chain_hops:
            attenuation_error = _verify_scope_attenuation(chain_hops)
            if attenuation_error is not None:
                hop = attenuation_error["hop"]
                excess = attenuation_error["excess_scopes"]
                _log.warning(
                    "delegation scope attenuation violated at hop %d: excess scopes %s",
                    hop,
                    excess,
                )
                response = stable_error(
                    403,
                    "delegation.scope_escalation",
                    f"scope attenuation violated at hop {hop}: excess scopes {excess}",
                )
                await response(scope, receive, send)
                return

        # Check if the delegation's scopes cover the required scope for this route
        required = required_scope_for_route(method, path)
        if required is not None:
            delegated_scopes = set(token_result.get("delegated_scopes", []))
            if "*" not in delegated_scopes and required not in delegated_scopes:
                response = stable_error(
                    403,
                    "delegation.insufficient_scope",
                    f"delegation token missing required scope: {required}",
                )
                await response(scope, receive, send)
                return

        # Set delegation context on request state for downstream handlers
        scope.setdefault("state", {})
        scope["state"]["delegation_context"] = {
            "token_id": token_result["token_id"],
            "issuer_agent_id": token_result["issuer_agent_id"],
            "subject_agent_id": token_result["subject_agent_id"],
            "delegated_scopes": token_result["delegated_scopes"],
            "chain_depth": token_result["chain_depth"],
        }

        await self.app(scope, receive, send)

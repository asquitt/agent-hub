"""A2A Agent Card generation from AgentHub registry data.

Transforms AgentHub agent manifests into Google A2A protocol
agent cards following the mapping rules in docs/spec/a2a-mapping.md.
"""
from __future__ import annotations

import os
from typing import Any


def _base_url() -> str:
    return os.getenv("AGENTHUB_BASE_URL", "https://localhost:8000").rstrip("/")


def build_registry_agent_card() -> dict[str, Any]:
    """Build the A2A agent card for the AgentHub registry service itself."""
    base = _base_url()
    return {
        "id": "agenthub-registry",
        "name": "AgentHub Registry Service",
        "description": "IAM layer for autonomous systems — agent identity, delegation, and discovery.",
        "version": "0.1.0",
        "url": base,
        "provider": {"organization": "AgentHub", "url": base},
        "capabilities": {
            "streaming": False,
            "pushNotifications": False,
        },
        "authentication": {
            "schemes": ["bearer", "apiKey"],
            "credentials": None,
        },
        "skills": [
            {
                "id": "agent_identity",
                "name": "Agent Identity",
                "description": "Register and manage agent identities with credential lifecycle.",
            },
            {
                "id": "delegation",
                "name": "Delegated Authority",
                "description": "Create scoped delegation chains with budget controls.",
            },
            {
                "id": "discovery",
                "name": "Capability Discovery",
                "description": "Search and match agent capabilities with trust-aware ranking.",
            },
        ],
        "defaultInputModes": ["application/json"],
        "defaultOutputModes": ["application/json"],
    }


def build_agent_card(
    *,
    agent_id: str,
    manifest: dict[str, Any],
    trust_score: float | None = None,
) -> dict[str, Any]:
    """Build an A2A agent card from an AgentHub agent manifest.

    Follows the A2A-to-AgentHub mapping rules from docs/spec/a2a-mapping.md.
    """
    identity = manifest.get("identity", {})
    base = _base_url()

    # Extract A2A endpoint from interfaces if available
    interfaces = manifest.get("interfaces", [])
    a2a_url = None
    for iface in interfaces if isinstance(interfaces, list) else []:
        if isinstance(iface, dict) and iface.get("protocol", "").upper() == "A2A":
            a2a_url = iface.get("endpoint")
            break
    if not a2a_url:
        a2a_url = f"{base}/v1/a2a/agent-card/{agent_id}"

    # Build skills from capabilities
    capabilities = manifest.get("capabilities", [])
    skills: list[dict[str, Any]] = []
    for cap in capabilities if isinstance(capabilities, list) else []:
        if not isinstance(cap, dict):
            continue
        skill: dict[str, Any] = {
            "id": cap.get("id", "unknown"),
            "name": cap.get("name", cap.get("id", "unknown")),
            "description": cap.get("description", ""),
        }
        if cap.get("input_schema"):
            skill["inputModes"] = ["application/json"]
        if cap.get("output_schema"):
            skill["outputModes"] = ["application/json"]
        skills.append(skill)

    # Build trust/security section
    trust_config = manifest.get("trust", {})
    security: dict[str, Any] = {}
    min_trust = trust_config.get("minimum_trust_score")
    if min_trust is not None:
        security["minimum_trust_score"] = min_trust
    allowed_sources = trust_config.get("allowed_trust_sources")
    if allowed_sources:
        security["allowed_sources"] = allowed_sources

    card: dict[str, Any] = {
        "id": agent_id,
        "name": identity.get("name", agent_id),
        "description": identity.get("description", ""),
        "version": identity.get("version", "0.1.0"),
        "url": a2a_url,
        "provider": {"organization": "AgentHub", "url": base},
        "capabilities": {
            "streaming": False,
            "pushNotifications": False,
        },
        "authentication": {
            "schemes": ["bearer"],
            "credentials": None,
        },
        "skills": skills,
        "defaultInputModes": ["application/json"],
        "defaultOutputModes": ["application/json"],
    }

    if trust_score is not None:
        card["trustScore"] = trust_score
    if security:
        card["security"] = security

    return card

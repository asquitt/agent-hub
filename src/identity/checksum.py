"""Configuration Checksum — compute and verify agent config integrity.

Provides deterministic checksums for agent manifests/configurations
to detect drift between registered and deployed agent configs.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from src.identity.storage import IDENTITY_STORAGE


def compute_config_checksum(manifest: dict[str, Any]) -> str:
    """Compute a SHA-256 checksum of a canonical JSON-serialized manifest.

    The manifest is serialized with sorted keys and no whitespace to ensure
    deterministic output regardless of key ordering.
    """
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def verify_config_integrity(
    *,
    agent_id: str,
    manifest: dict[str, Any],
) -> dict[str, Any]:
    """Verify that a manifest matches the stored configuration checksum.

    Returns a verification result with computed vs stored checksum comparison.
    Raises KeyError if agent_id is not found.
    """
    identity = IDENTITY_STORAGE.get_identity(agent_id)
    stored = identity.get("configuration_checksum")
    computed = compute_config_checksum(manifest)

    if stored is None:
        return {
            "agent_id": agent_id,
            "valid": False,
            "reason": "no_checksum",
            "message": "agent has no stored configuration checksum",
            "computed_checksum": computed,
        }

    return {
        "agent_id": agent_id,
        "valid": stored == computed,
        "stored_checksum": stored,
        "computed_checksum": computed,
    }

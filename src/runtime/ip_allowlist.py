"""IP Allowlisting (S158).

Per-agent IP restrictions with CIDR support, allowlists/denylists,
and access logging.
"""
from __future__ import annotations

import ipaddress
import logging
import time
import uuid
from typing import Any

_log = logging.getLogger("agenthub.ip_allowlist")

_MAX_RECORDS = 10_000
_rules: dict[str, dict[str, Any]] = {}  # rule_id -> rule
_access_log: list[dict[str, Any]] = []


def create_rule(
    *,
    agent_id: str,
    name: str,
    rule_type: str,
    cidrs: list[str],
    description: str = "",
) -> dict[str, Any]:
    """Create an IP allowlist/denylist rule."""
    if rule_type not in ("allow", "deny"):
        raise ValueError("rule_type must be 'allow' or 'deny'")

    # Validate CIDRs
    for cidr in cidrs:
        try:
            ipaddress.ip_network(cidr, strict=False)
        except ValueError as exc:
            raise ValueError(f"invalid CIDR '{cidr}': {exc}") from exc

    rid = f"ipr-{uuid.uuid4().hex[:12]}"
    now = time.time()

    rule: dict[str, Any] = {
        "rule_id": rid,
        "agent_id": agent_id,
        "name": name,
        "rule_type": rule_type,
        "cidrs": cidrs,
        "description": description,
        "enabled": True,
        "created_at": now,
    }
    _rules[rid] = rule

    if len(_rules) > _MAX_RECORDS:
        oldest = sorted(_rules, key=lambda k: _rules[k]["created_at"])
        for k in oldest[: len(oldest) - _MAX_RECORDS]:
            del _rules[k]

    return rule


def get_rule(rule_id: str) -> dict[str, Any]:
    """Get an IP rule by ID."""
    rule = _rules.get(rule_id)
    if not rule:
        raise KeyError(f"IP rule not found: {rule_id}")
    return rule


def list_rules(
    *,
    agent_id: str | None = None,
    rule_type: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """List IP rules with optional filters."""
    results: list[dict[str, Any]] = []
    for r in sorted(_rules.values(), key=lambda x: x["created_at"], reverse=True):
        if agent_id and r["agent_id"] != agent_id:
            continue
        if rule_type and r["rule_type"] != rule_type:
            continue
        results.append(r)
        if len(results) >= limit:
            break
    return results


def check_ip(
    *,
    agent_id: str,
    ip_address: str,
) -> dict[str, Any]:
    """Check if an IP is allowed for an agent."""
    try:
        addr = ipaddress.ip_address(ip_address)
    except ValueError as exc:
        raise ValueError(f"invalid IP address '{ip_address}': {exc}") from exc

    agent_rules = [r for r in _rules.values() if r["agent_id"] == agent_id and r["enabled"]]
    if not agent_rules:
        result: dict[str, Any] = {
            "allowed": True,
            "reason": "no_rules",
            "agent_id": agent_id,
            "ip_address": ip_address,
        }
        _log_access(result)
        return result

    # Check deny rules first (deny takes precedence)
    for rule in agent_rules:
        if rule["rule_type"] == "deny":
            for cidr in rule["cidrs"]:
                net = ipaddress.ip_network(cidr, strict=False)
                if addr in net:
                    result = {
                        "allowed": False,
                        "reason": "denied",
                        "rule_id": rule["rule_id"],
                        "matched_cidr": cidr,
                        "agent_id": agent_id,
                        "ip_address": ip_address,
                    }
                    _log_access(result)
                    return result

    # Check allow rules (if any allow rules exist, IP must match at least one)
    allow_rules = [r for r in agent_rules if r["rule_type"] == "allow"]
    if allow_rules:
        for rule in allow_rules:
            for cidr in rule["cidrs"]:
                net = ipaddress.ip_network(cidr, strict=False)
                if addr in net:
                    result = {
                        "allowed": True,
                        "reason": "allowed",
                        "rule_id": rule["rule_id"],
                        "matched_cidr": cidr,
                        "agent_id": agent_id,
                        "ip_address": ip_address,
                    }
                    _log_access(result)
                    return result

        # IP not in any allow rule
        result = {
            "allowed": False,
            "reason": "not_in_allowlist",
            "agent_id": agent_id,
            "ip_address": ip_address,
        }
        _log_access(result)
        return result

    # Only deny rules exist, and none matched — allow
    result = {
        "allowed": True,
        "reason": "not_denied",
        "agent_id": agent_id,
        "ip_address": ip_address,
    }
    _log_access(result)
    return result


def disable_rule(rule_id: str) -> dict[str, Any]:
    """Disable an IP rule."""
    rule = _rules.get(rule_id)
    if not rule:
        raise KeyError(f"IP rule not found: {rule_id}")
    rule["enabled"] = False
    return rule


def get_access_log(
    *,
    agent_id: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Get IP access check log."""
    results: list[dict[str, Any]] = []
    for entry in reversed(_access_log):
        if agent_id and entry["agent_id"] != agent_id:
            continue
        results.append(entry)
        if len(results) >= limit:
            break
    return results


def get_ip_stats() -> dict[str, Any]:
    """Get IP allowlist statistics."""
    total_rules = len(_rules)
    enabled = sum(1 for r in _rules.values() if r["enabled"])
    allow_rules = sum(1 for r in _rules.values() if r["rule_type"] == "allow")
    deny_rules = sum(1 for r in _rules.values() if r["rule_type"] == "deny")
    total_checks = len(_access_log)
    allowed_checks = sum(1 for e in _access_log if e["allowed"])

    return {
        "total_rules": total_rules,
        "enabled_rules": enabled,
        "allow_rules": allow_rules,
        "deny_rules": deny_rules,
        "total_checks": total_checks,
        "allowed_checks": allowed_checks,
        "denied_checks": total_checks - allowed_checks,
    }


# ── Internal helpers ─────────────────────────────────────────────────

def _log_access(result: dict[str, Any]) -> None:
    """Log an access check result."""
    entry = {**result, "checked_at": time.time()}
    _access_log.append(entry)
    if len(_access_log) > _MAX_RECORDS:
        _access_log[:] = _access_log[-_MAX_RECORDS:]


def reset_for_tests() -> None:
    """Clear all IP allowlist data for testing."""
    _rules.clear()
    _access_log.clear()

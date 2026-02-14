"""Threat Intelligence Integration — STIX/TAXII IOC matching for agents.

Provides threat indicator management with agent risk assessment:
- IOC (Indicator of Compromise) ingestion and storage
- Pattern matching against agent activity (IPs, domains, hashes, agent IDs)
- Risk scoring based on matched indicators
- Feed management for STIX/TAXII-compatible sources
"""
from __future__ import annotations

import logging
import time
import uuid
from typing import Any

_log = logging.getLogger("agenthub.threat_intel")

# Indicator types (STIX cyber observable types)
INDICATOR_TYPE_IP = "ipv4-addr"
INDICATOR_TYPE_DOMAIN = "domain-name"
INDICATOR_TYPE_HASH = "file:hashes.'SHA-256'"
INDICATOR_TYPE_AGENT_ID = "x-agenthub-agent-id"
INDICATOR_TYPE_URL = "url"
VALID_INDICATOR_TYPES = {
    INDICATOR_TYPE_IP, INDICATOR_TYPE_DOMAIN, INDICATOR_TYPE_HASH,
    INDICATOR_TYPE_AGENT_ID, INDICATOR_TYPE_URL,
}

# Severity levels
SEVERITY_LOW = "low"
SEVERITY_MEDIUM = "medium"
SEVERITY_HIGH = "high"
SEVERITY_CRITICAL = "critical"

# In-memory stores
_MAX_RECORDS = 10_000
_indicators: dict[str, dict[str, Any]] = {}  # indicator_id -> indicator
_feeds: dict[str, dict[str, Any]] = {}  # feed_id -> feed metadata
_matches: list[dict[str, Any]] = []  # match history


def add_indicator(
    *,
    indicator_type: str,
    value: str,
    severity: str = SEVERITY_MEDIUM,
    description: str = "",
    source_feed: str | None = None,
    ttl_seconds: int = 86400 * 30,
    tags: list[str] | None = None,
) -> dict[str, Any]:
    """Add a threat indicator (IOC)."""
    if indicator_type not in VALID_INDICATOR_TYPES:
        raise ValueError(f"invalid indicator type: {indicator_type}, valid: {sorted(VALID_INDICATOR_TYPES)}")
    if severity not in {SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_CRITICAL}:
        raise ValueError(f"invalid severity: {severity}")

    now = time.time()
    indicator_id = f"ioc-{uuid.uuid4().hex[:12]}"

    indicator: dict[str, Any] = {
        "indicator_id": indicator_id,
        "indicator_type": indicator_type,
        "value": value,
        "severity": severity,
        "description": description,
        "source_feed": source_feed,
        "tags": tags or [],
        "created_at": now,
        "expires_at": now + ttl_seconds,
        "active": True,
        "match_count": 0,
    }

    _indicators[indicator_id] = indicator
    _log.info("indicator added: id=%s type=%s severity=%s", indicator_id, indicator_type, severity)
    return indicator


def check_indicator(
    *,
    indicator_type: str,
    value: str,
    agent_id: str | None = None,
    context: str = "",
) -> dict[str, Any]:
    """Check if a value matches any active threat indicators."""
    now = time.time()
    matched: list[dict[str, Any]] = []

    for ind in _indicators.values():
        if not ind["active"]:
            continue
        if now > ind["expires_at"]:
            continue
        if ind["indicator_type"] != indicator_type:
            continue
        if ind["value"].lower() == value.lower():
            ind["match_count"] += 1
            matched.append({
                "indicator_id": ind["indicator_id"],
                "severity": ind["severity"],
                "description": ind["description"],
                "source_feed": ind["source_feed"],
                "tags": ind["tags"],
            })

    is_threat = len(matched) > 0

    if is_threat:
        match_record: dict[str, Any] = {
            "match_id": f"tm-{uuid.uuid4().hex[:12]}",
            "indicator_type": indicator_type,
            "value": value,
            "agent_id": agent_id,
            "context": context,
            "matched_indicators": matched,
            "max_severity": max((m["severity"] for m in matched), key=lambda s: ["low", "medium", "high", "critical"].index(s)),
            "detected_at": now,
        }
        _matches.append(match_record)
        if len(_matches) > _MAX_RECORDS:
            _matches[:] = _matches[-_MAX_RECORDS:]
        _log.warning("threat match: type=%s value=%s agent=%s severity=%s", indicator_type, value, agent_id, match_record["max_severity"])

    return {
        "is_threat": is_threat,
        "indicator_type": indicator_type,
        "value": value,
        "match_count": len(matched),
        "matches": matched,
        "max_severity": matched[0]["severity"] if matched else None,
    }


def get_agent_threat_assessment(agent_id: str) -> dict[str, Any]:
    """Get a threat assessment for an agent based on matched indicators."""
    agent_matches = [m for m in _matches if m.get("agent_id") == agent_id]

    if not agent_matches:
        return {
            "agent_id": agent_id,
            "risk_level": "clean",
            "total_matches": 0,
            "indicators": [],
        }

    severity_scores = {"low": 10, "medium": 30, "high": 60, "critical": 100}
    total_score = 0
    for m in agent_matches:
        total_score += severity_scores.get(m.get("max_severity", "low"), 10)

    risk_score = min(100, total_score)
    if risk_score >= 80:
        risk_level = "critical"
    elif risk_score >= 50:
        risk_level = "high"
    elif risk_score >= 20:
        risk_level = "medium"
    else:
        risk_level = "low"

    return {
        "agent_id": agent_id,
        "risk_level": risk_level,
        "risk_score": risk_score,
        "total_matches": len(agent_matches),
        "recent_matches": agent_matches[-10:],
    }


def register_feed(
    *,
    feed_name: str,
    feed_url: str = "",
    feed_type: str = "stix-taxii",
    description: str = "",
) -> dict[str, Any]:
    """Register a threat intelligence feed source."""
    feed_id = f"feed-{uuid.uuid4().hex[:12]}"
    now = time.time()

    feed: dict[str, Any] = {
        "feed_id": feed_id,
        "feed_name": feed_name,
        "feed_url": feed_url,
        "feed_type": feed_type,
        "description": description,
        "registered_at": now,
        "last_sync": None,
        "indicator_count": 0,
        "status": "active",
    }
    _feeds[feed_id] = feed
    _log.info("feed registered: id=%s name=%s", feed_id, feed_name)
    return feed


def list_feeds() -> list[dict[str, Any]]:
    """List registered threat intelligence feeds."""
    return list(_feeds.values())


def list_indicators(
    *,
    indicator_type: str | None = None,
    severity: str | None = None,
    active_only: bool = True,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """List threat indicators with optional filters."""
    now = time.time()
    results: list[dict[str, Any]] = []
    for ind in _indicators.values():
        if active_only and (not ind["active"] or now > ind["expires_at"]):
            continue
        if indicator_type and ind["indicator_type"] != indicator_type:
            continue
        if severity and ind["severity"] != severity:
            continue
        results.append(ind)
        if len(results) >= limit:
            break
    return results


def get_match_history(
    *,
    agent_id: str | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Get threat match history."""
    results = _matches
    if agent_id:
        results = [m for m in results if m.get("agent_id") == agent_id]
    return list(reversed(results[-limit:]))


def get_threat_summary() -> dict[str, Any]:
    """Get threat intelligence summary."""
    now = time.time()
    active_indicators = sum(1 for i in _indicators.values() if i["active"] and now <= i["expires_at"])
    severity_dist: dict[str, int] = {}
    for ind in _indicators.values():
        if ind["active"] and now <= ind["expires_at"]:
            s = ind["severity"]
            severity_dist[s] = severity_dist.get(s, 0) + 1

    return {
        "total_indicators": len(_indicators),
        "active_indicators": active_indicators,
        "total_feeds": len(_feeds),
        "total_matches": len(_matches),
        "severity_distribution": severity_dist,
    }


def reset_for_tests() -> None:
    """Clear all threat intelligence data."""
    _indicators.clear()
    _feeds.clear()
    _matches.clear()

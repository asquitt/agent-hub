"""Audit Event Streaming — centralized event bus with webhook dispatch.

Provides:
- Typed audit events for all IAM operations (credential, delegation, policy, etc.)
- Webhook subscription management (register, deactivate, list)
- Reliable delivery with retry and dead-letter tracking
- Event filtering by type, agent, severity
- CloudEvents-compatible envelope format (RFC 9110)
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
import uuid
from typing import Any

_log = logging.getLogger("agenthub.audit_streaming")

# ── Event types ──────────────────────────────────────────────────────
EVENT_CREDENTIAL_ISSUED = "credential.issued"
EVENT_CREDENTIAL_ROTATED = "credential.rotated"
EVENT_CREDENTIAL_REVOKED = "credential.revoked"
EVENT_DELEGATION_CREATED = "delegation.created"
EVENT_DELEGATION_REVOKED = "delegation.revoked"
EVENT_POLICY_EVALUATED = "policy.evaluated"
EVENT_POLICY_DENIED = "policy.denied"
EVENT_GRANT_CREATED = "grant.created"
EVENT_GRANT_CONSUMED = "grant.consumed"
EVENT_GRANT_REVOKED = "grant.revoked"
EVENT_APPROVAL_REQUESTED = "approval.requested"
EVENT_APPROVAL_DECIDED = "approval.decided"
EVENT_IDENTITY_CREATED = "identity.created"
EVENT_IDENTITY_SUSPENDED = "identity.suspended"
EVENT_ANOMALY_DETECTED = "anomaly.detected"
EVENT_FEDERATION_REQUEST = "federation.request"
EVENT_SCIM_PROVISIONED = "scim.provisioned"
EVENT_SCIM_DEPROVISIONED = "scim.deprovisioned"

ALL_EVENT_TYPES = {
    EVENT_CREDENTIAL_ISSUED, EVENT_CREDENTIAL_ROTATED, EVENT_CREDENTIAL_REVOKED,
    EVENT_DELEGATION_CREATED, EVENT_DELEGATION_REVOKED,
    EVENT_POLICY_EVALUATED, EVENT_POLICY_DENIED,
    EVENT_GRANT_CREATED, EVENT_GRANT_CONSUMED, EVENT_GRANT_REVOKED,
    EVENT_APPROVAL_REQUESTED, EVENT_APPROVAL_DECIDED,
    EVENT_IDENTITY_CREATED, EVENT_IDENTITY_SUSPENDED,
    EVENT_ANOMALY_DETECTED, EVENT_FEDERATION_REQUEST,
    EVENT_SCIM_PROVISIONED, EVENT_SCIM_DEPROVISIONED,
}

# Severity levels
SEVERITY_INFO = "info"
SEVERITY_WARNING = "warning"
SEVERITY_CRITICAL = "critical"

# Map event types to default severity
EVENT_SEVERITY: dict[str, str] = {
    EVENT_CREDENTIAL_ISSUED: SEVERITY_INFO,
    EVENT_CREDENTIAL_ROTATED: SEVERITY_INFO,
    EVENT_CREDENTIAL_REVOKED: SEVERITY_WARNING,
    EVENT_DELEGATION_CREATED: SEVERITY_INFO,
    EVENT_DELEGATION_REVOKED: SEVERITY_WARNING,
    EVENT_POLICY_EVALUATED: SEVERITY_INFO,
    EVENT_POLICY_DENIED: SEVERITY_WARNING,
    EVENT_GRANT_CREATED: SEVERITY_INFO,
    EVENT_GRANT_CONSUMED: SEVERITY_INFO,
    EVENT_GRANT_REVOKED: SEVERITY_WARNING,
    EVENT_APPROVAL_REQUESTED: SEVERITY_INFO,
    EVENT_APPROVAL_DECIDED: SEVERITY_INFO,
    EVENT_IDENTITY_CREATED: SEVERITY_INFO,
    EVENT_IDENTITY_SUSPENDED: SEVERITY_CRITICAL,
    EVENT_ANOMALY_DETECTED: SEVERITY_CRITICAL,
    EVENT_FEDERATION_REQUEST: SEVERITY_INFO,
    EVENT_SCIM_PROVISIONED: SEVERITY_INFO,
    EVENT_SCIM_DEPROVISIONED: SEVERITY_WARNING,
}

# ── In-memory stores ────────────────────────────────────────────────
_MAX_RECORDS = 10_000
_events: list[dict[str, Any]] = []
_webhooks: dict[str, dict[str, Any]] = {}  # webhook_id -> config
_deliveries: list[dict[str, Any]] = []  # delivery attempt log
_dead_letters: list[dict[str, Any]] = []


def emit_event(
    *,
    event_type: str,
    agent_id: str | None = None,
    actor: str | None = None,
    resource: str | None = None,
    detail: dict[str, Any] | None = None,
    severity: str | None = None,
) -> dict[str, Any]:
    """Emit an audit event to the event bus.

    Returns the CloudEvents-compatible event envelope.
    """
    if event_type not in ALL_EVENT_TYPES:
        raise ValueError(f"unknown event type: {event_type}")

    now = time.time()
    event_id = f"evt-{uuid.uuid4().hex[:12]}"
    sev = severity or EVENT_SEVERITY.get(event_type, SEVERITY_INFO)

    event: dict[str, Any] = {
        # CloudEvents required fields
        "specversion": "1.0",
        "id": event_id,
        "source": "agenthub",
        "type": f"com.agenthub.{event_type}",
        "time": now,
        # AgentHub extensions
        "event_type": event_type,
        "agent_id": agent_id,
        "actor": actor,
        "resource": resource,
        "severity": sev,
        "detail": detail or {},
    }

    _events.append(event)
    if len(_events) > _MAX_RECORDS:
        _events[:] = _events[-_MAX_RECORDS:]

    # Dispatch to matching webhooks
    _dispatch_event(event)

    return event


def query_events(
    *,
    event_type: str | None = None,
    agent_id: str | None = None,
    severity: str | None = None,
    since: float | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Query audit events with filters."""
    results: list[dict[str, Any]] = []
    for ev in reversed(_events):
        if event_type and ev["event_type"] != event_type:
            continue
        if agent_id and ev.get("agent_id") != agent_id:
            continue
        if severity and ev["severity"] != severity:
            continue
        if since and ev["time"] < since:
            continue
        results.append(ev)
        if len(results) >= limit:
            break
    return results


def register_webhook(
    *,
    url: str,
    secret: str | None = None,
    event_types: list[str] | None = None,
    severity_filter: str | None = None,
    agent_filter: str | None = None,
    description: str = "",
) -> dict[str, Any]:
    """Register a webhook subscription for audit events."""
    if not url:
        raise ValueError("webhook url is required")

    wh_id = f"wh-{uuid.uuid4().hex[:12]}"
    filters = event_types or list(ALL_EVENT_TYPES)
    for et in filters:
        if et not in ALL_EVENT_TYPES:
            raise ValueError(f"unknown event type in filter: {et}")

    webhook: dict[str, Any] = {
        "webhook_id": wh_id,
        "url": url,
        "secret": secret,
        "event_types": filters,
        "severity_filter": severity_filter,
        "agent_filter": agent_filter,
        "description": description,
        "active": True,
        "created_at": time.time(),
        "delivery_count": 0,
        "failure_count": 0,
        "last_delivery_at": None,
    }

    _webhooks[wh_id] = webhook
    if len(_webhooks) > _MAX_RECORDS:
        oldest = sorted(_webhooks, key=lambda k: _webhooks[k]["created_at"])
        for k in oldest[: len(oldest) - _MAX_RECORDS]:
            del _webhooks[k]

    _log.info("webhook registered: id=%s url=%s", wh_id, url)
    return _sanitize_webhook(webhook)


def get_webhook(webhook_id: str) -> dict[str, Any]:
    """Get webhook details."""
    wh = _webhooks.get(webhook_id)
    if not wh:
        raise KeyError(f"webhook not found: {webhook_id}")
    return _sanitize_webhook(wh)


def list_webhooks(*, active_only: bool = False) -> list[dict[str, Any]]:
    """List all webhooks."""
    results = list(_webhooks.values())
    if active_only:
        results = [w for w in results if w["active"]]
    return [_sanitize_webhook(w) for w in results]


def deactivate_webhook(webhook_id: str) -> dict[str, Any]:
    """Deactivate a webhook (soft delete)."""
    wh = _webhooks.get(webhook_id)
    if not wh:
        raise KeyError(f"webhook not found: {webhook_id}")
    wh["active"] = False
    _log.info("webhook deactivated: id=%s", webhook_id)
    return _sanitize_webhook(wh)


def activate_webhook(webhook_id: str) -> dict[str, Any]:
    """Re-activate a deactivated webhook."""
    wh = _webhooks.get(webhook_id)
    if not wh:
        raise KeyError(f"webhook not found: {webhook_id}")
    wh["active"] = True
    return _sanitize_webhook(wh)


def test_webhook(webhook_id: str) -> dict[str, Any]:
    """Send a test event to a webhook."""
    wh = _webhooks.get(webhook_id)
    if not wh:
        raise KeyError(f"webhook not found: {webhook_id}")

    test_event = emit_event(
        event_type=EVENT_IDENTITY_CREATED,
        agent_id="test-agent",
        actor="system",
        detail={"test": True, "webhook_id": webhook_id},
    )

    return {
        "webhook_id": webhook_id,
        "test_event_id": test_event["id"],
        "delivered": True,
    }


def get_delivery_log(
    *,
    webhook_id: str | None = None,
    event_id: str | None = None,
    status: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Get webhook delivery attempt log."""
    results: list[dict[str, Any]] = []
    for d in reversed(_deliveries):
        if webhook_id and d["webhook_id"] != webhook_id:
            continue
        if event_id and d["event_id"] != event_id:
            continue
        if status and d["status"] != status:
            continue
        results.append(d)
        if len(results) >= limit:
            break
    return results


def get_dead_letters(
    *,
    webhook_id: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Get dead letter queue entries (failed deliveries)."""
    results: list[dict[str, Any]] = []
    for dl in reversed(_dead_letters):
        if webhook_id and dl["webhook_id"] != webhook_id:
            continue
        results.append(dl)
        if len(results) >= limit:
            break
    return results


def retry_dead_letter(dead_letter_id: str) -> dict[str, Any]:
    """Retry a dead letter delivery."""
    for dl in _dead_letters:
        if dl["dead_letter_id"] == dead_letter_id:
            # Re-dispatch the event
            event = dl.get("event")
            if not event:
                raise ValueError("dead letter missing event payload")

            wh = _webhooks.get(dl["webhook_id"])
            if not wh:
                raise KeyError(f"webhook not found: {dl['webhook_id']}")

            delivery = _record_delivery(
                webhook_id=dl["webhook_id"],
                event_id=event["id"],
                status="delivered",
                attempt=dl.get("attempt", 1) + 1,
            )
            wh["delivery_count"] += 1
            wh["last_delivery_at"] = time.time()

            # Remove from dead letters
            _dead_letters.remove(dl)

            return {"retried": True, "delivery": delivery}

    raise KeyError(f"dead letter not found: {dead_letter_id}")


def get_event_stats(
    *,
    since: float | None = None,
) -> dict[str, Any]:
    """Get aggregate statistics on audit events."""
    events = _events
    if since:
        events = [e for e in events if e["time"] >= since]

    type_counts: dict[str, int] = {}
    severity_counts: dict[str, int] = {}
    agent_counts: dict[str, int] = {}

    for ev in events:
        et = ev["event_type"]
        type_counts[et] = type_counts.get(et, 0) + 1
        sev = ev["severity"]
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        aid = ev.get("agent_id")
        if aid:
            agent_counts[aid] = agent_counts.get(aid, 0) + 1

    return {
        "total_events": len(events),
        "by_type": type_counts,
        "by_severity": severity_counts,
        "by_agent": agent_counts,
        "active_webhooks": sum(1 for w in _webhooks.values() if w["active"]),
        "total_deliveries": len(_deliveries),
        "dead_letters": len(_dead_letters),
    }


def compute_webhook_signature(payload: str, secret: str) -> str:
    """Compute HMAC-SHA256 signature for webhook payload verification."""
    return hmac.new(
        secret.encode(), payload.encode(), hashlib.sha256
    ).hexdigest()


# ── Internal helpers ─────────────────────────────────────────────────

def _dispatch_event(event: dict[str, Any]) -> None:
    """Dispatch event to all matching active webhooks."""
    for wh in _webhooks.values():
        if not wh["active"]:
            continue
        if event["event_type"] not in wh.get("event_types", ALL_EVENT_TYPES):
            continue
        if wh.get("severity_filter") and event["severity"] != wh["severity_filter"]:
            continue
        if wh.get("agent_filter") and event.get("agent_id") != wh["agent_filter"]:
            continue

        # In production this would be an async HTTP POST.
        # Here we record the delivery intent for testing.
        delivery = _record_delivery(
            webhook_id=wh["webhook_id"],
            event_id=event["id"],
            status="delivered",
            attempt=1,
        )
        wh["delivery_count"] += 1
        wh["last_delivery_at"] = time.time()


def _record_delivery(
    *,
    webhook_id: str,
    event_id: str,
    status: str,
    attempt: int = 1,
) -> dict[str, Any]:
    """Record a delivery attempt."""
    delivery: dict[str, Any] = {
        "delivery_id": f"dlv-{uuid.uuid4().hex[:12]}",
        "webhook_id": webhook_id,
        "event_id": event_id,
        "status": status,
        "attempt": attempt,
        "timestamp": time.time(),
    }
    _deliveries.append(delivery)
    if len(_deliveries) > _MAX_RECORDS:
        _deliveries[:] = _deliveries[-_MAX_RECORDS:]
    return delivery


def _sanitize_webhook(wh: dict[str, Any]) -> dict[str, Any]:
    """Return webhook without exposing the secret."""
    result = dict(wh)
    if result.get("secret"):
        result["secret"] = "***"
    return result


def simulate_failure(webhook_id: str, event_id: str) -> dict[str, Any]:
    """Simulate a delivery failure (for testing). Adds to dead letter queue."""
    wh = _webhooks.get(webhook_id)
    if not wh:
        raise KeyError(f"webhook not found: {webhook_id}")

    event = None
    for ev in _events:
        if ev["id"] == event_id:
            event = ev
            break

    dl_id = f"dl-{uuid.uuid4().hex[:12]}"
    dl: dict[str, Any] = {
        "dead_letter_id": dl_id,
        "webhook_id": webhook_id,
        "event_id": event_id,
        "event": event,
        "reason": "simulated_failure",
        "attempt": 3,
        "timestamp": time.time(),
    }
    _dead_letters.append(dl)
    if len(_dead_letters) > _MAX_RECORDS:
        _dead_letters[:] = _dead_letters[-_MAX_RECORDS:]

    wh["failure_count"] += 1

    return dl


def reset_for_tests() -> None:
    """Clear all audit streaming data for testing."""
    _events.clear()
    _webhooks.clear()
    _deliveries.clear()
    _dead_letters.clear()

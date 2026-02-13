from __future__ import annotations

import hashlib
import uuid
from typing import Any

from src.common.time import iso_from_epoch, utc_now_epoch
from . import storage as knowledge_storage

POISON_PATTERNS = [
    "ignore previous instructions",
    "system prompt",
    "exfiltrate",
    "bypass policy",
]


def _now_epoch() -> int:
    return utc_now_epoch()


def _iso(epoch: int) -> str:
    return iso_from_epoch(epoch)


def _content_hash(title: str, content: str, source_uri: str) -> str:
    payload = f"{title}|{content}|{source_uri}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _detect_poisoning(content: str) -> str | None:
    lowered = content.lower()
    if len(content) > 5000:
        return "content too large"
    for pattern in POISON_PATTERNS:
        if pattern in lowered:
            return f"suspicious pattern detected: {pattern}"
    return None


def _confidence(record: dict[str, Any], now_epoch: int | None = None) -> float:
    now = _now_epoch() if now_epoch is None else now_epoch
    age_days = max(0.0, (now - int(record["created_at_epoch"])) / 86400)
    decay_factor = max(0.35, 1.0 - (age_days * 0.03))

    positive = sum(1 for row in record["validations"] if row["verdict"] is True)
    negative = sum(1 for row in record["validations"] if row["verdict"] is False)

    score = float(record["base_confidence"]) * decay_factor
    score += min(0.25, positive * 0.05)
    score -= min(0.35, negative * 0.1)
    return round(max(0.0, min(1.0, score)), 4)


def contribute_entry(
    owner: str,
    title: str,
    content: str,
    tags: list[str],
    source_uri: str,
    contributor: str,
    base_confidence: float = 0.65,
) -> dict[str, Any]:
    poison_error = _detect_poisoning(content)
    if poison_error:
        raise ValueError(poison_error)

    now = _now_epoch()
    entry_id = str(uuid.uuid4())
    row = {
        "entry_id": entry_id,
        "owner": owner,
        "title": title,
        "content": content,
        "tags": sorted({tag.strip().lower() for tag in tags if tag.strip()}),
        "source_uri": source_uri,
        "contributor": contributor,
        "provenance_hash": _content_hash(title=title, content=content, source_uri=source_uri),
        "base_confidence": max(0.0, min(1.0, base_confidence)),
        "validations": [],
        "created_at": _iso(now),
        "created_at_epoch": now,
        "updated_at": _iso(now),
    }
    entries = knowledge_storage.load_entries()
    entries[entry_id] = row
    knowledge_storage.save_entries(entries)
    out = row.copy()
    out["confidence"] = _confidence(row, now_epoch=now)
    return out


def query_entries(query: str, limit: int = 10) -> list[dict[str, Any]]:
    terms = [term for term in query.lower().split(" ") if term]
    rows: list[dict[str, Any]] = []
    now = _now_epoch()

    entries = knowledge_storage.load_entries()
    for row in entries.values():
        text = " ".join([row["title"], row["content"], " ".join(row["tags"])]).lower()
        if terms and not all(term in text for term in terms):
            continue
        payload = row.copy()
        payload["confidence"] = _confidence(row, now_epoch=now)
        rows.append(payload)

    rows.sort(key=lambda item: item["confidence"], reverse=True)
    return rows[:limit]


def validate_entry(entry_id: str, validator: str, verdict: bool, rationale: str) -> dict[str, Any]:
    entries = knowledge_storage.load_entries()
    if entry_id not in entries:
        raise KeyError("entry not found")
    row = entries[entry_id]
    now = _now_epoch()

    row["validations"].append(
        {
            "validator": validator,
            "verdict": bool(verdict),
            "rationale": rationale,
            "timestamp": _iso(now),
        }
    )
    row["updated_at"] = _iso(now)
    entries[entry_id] = row
    knowledge_storage.save_entries(entries)

    out = row.copy()
    out["confidence"] = _confidence(row, now_epoch=now)
    return out


def reset_state_for_tests() -> None:
    knowledge_storage.reset_for_tests()

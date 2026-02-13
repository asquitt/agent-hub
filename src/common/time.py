from __future__ import annotations

from datetime import UTC, datetime


def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


def utc_now_epoch() -> int:
    return int(datetime.now(UTC).timestamp())


def iso_from_epoch(epoch: int) -> str:
    return datetime.fromtimestamp(int(epoch), tz=UTC).isoformat()

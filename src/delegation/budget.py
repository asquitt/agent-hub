"""Per-delegation budget enforcement with 80/100/120 threshold model.

Tracks cost events per delegation token and enforces budget limits:
- 80% soft alert: warning header added
- 100% reauthorization: requires explicit re-auth
- 120% hard stop: request rejected
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from pathlib import Path
from typing import Any

from src.persistence import apply_scope_migrations

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DB = ROOT / "data" / "delegation" / "delegation.db"


def _db_path() -> Path:
    return Path(os.getenv("AGENTHUB_DELEGATION_DB_PATH", str(DEFAULT_DB)))


class DelegationBudgetStore:
    """SQLite-backed per-delegation budget tracking."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._conn: sqlite3.Connection | None = None
        self._db_path: str | None = None

    def _connect(self, db_path: Path) -> sqlite3.Connection:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        return conn

    def _ensure_ready(self) -> None:
        with self._lock:
            desired = str(_db_path())
            if self._conn is not None and self._db_path == desired:
                return
            if self._conn is not None:
                self._conn.close()
            self._conn = self._connect(Path(desired))
            apply_scope_migrations(self._conn, "delegation")
            self._db_path = desired

    def set_budget_limit(
        self,
        *,
        token_id: str,
        max_budget_usd: float,
        tenant_id: str = "tenant-default",
        soft_alert_pct: float = 80.0,
        reauth_pct: float = 100.0,
        hard_stop_pct: float = 120.0,
    ) -> dict[str, Any]:
        """Set or update the budget limit for a delegation token."""
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            with self._conn:
                self._conn.execute(
                    """
                    INSERT OR REPLACE INTO delegation_budget_limits
                        (token_id, tenant_id, max_budget_usd, soft_alert_pct, reauth_pct, hard_stop_pct)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (token_id, tenant_id, max_budget_usd, soft_alert_pct, reauth_pct, hard_stop_pct),
                )
            return {
                "token_id": token_id,
                "max_budget_usd": max_budget_usd,
                "soft_alert_pct": soft_alert_pct,
                "reauth_pct": reauth_pct,
                "hard_stop_pct": hard_stop_pct,
            }

    def record_cost_event(
        self,
        *,
        token_id: str,
        cost_usd: float,
        actor: str,
        description: str = "",
        tenant_id: str = "tenant-default",
    ) -> dict[str, Any]:
        """Record a cost event against a delegation token's budget."""
        self._ensure_ready()
        event_id = str(uuid.uuid4())
        with self._lock:
            assert self._conn is not None
            with self._conn:
                self._conn.execute(
                    """
                    INSERT INTO delegation_budget_events
                        (event_id, token_id, tenant_id, actor, cost_usd, description)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (event_id, token_id, tenant_id, actor, cost_usd, description),
                )
        return {"event_id": event_id, "token_id": token_id, "cost_usd": cost_usd}

    def get_total_spend(self, token_id: str) -> float:
        """Get total spend for a delegation token."""
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            row = self._conn.execute(
                "SELECT COALESCE(SUM(cost_usd), 0.0) as total FROM delegation_budget_events WHERE token_id = ?",
                (token_id,),
            ).fetchone()
            return float(row["total"]) if row else 0.0

    def check_budget(self, token_id: str) -> dict[str, Any]:
        """Check budget status for a delegation token.

        Returns state: 'ok', 'soft_alert', 'reauth_required', 'hard_stop', or 'no_limit'.
        """
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            limit_row = self._conn.execute(
                "SELECT * FROM delegation_budget_limits WHERE token_id = ?",
                (token_id,),
            ).fetchone()

            if limit_row is None:
                return {
                    "token_id": token_id,
                    "state": "no_limit",
                    "total_spend_usd": self.get_total_spend(token_id),
                }

            max_budget = float(limit_row["max_budget_usd"])
            soft_pct = float(limit_row["soft_alert_pct"])
            reauth_pct = float(limit_row["reauth_pct"])
            hard_pct = float(limit_row["hard_stop_pct"])

            total = self.get_total_spend(token_id)
            ratio = (total / max_budget * 100.0) if max_budget > 0 else 0.0

            if ratio >= hard_pct:
                state = "hard_stop"
            elif ratio >= reauth_pct:
                state = "reauth_required"
            elif ratio >= soft_pct:
                state = "soft_alert"
            else:
                state = "ok"

            return {
                "token_id": token_id,
                "state": state,
                "total_spend_usd": total,
                "max_budget_usd": max_budget,
                "ratio_pct": round(ratio, 2),
                "thresholds": {
                    "soft_alert_pct": soft_pct,
                    "reauth_pct": reauth_pct,
                    "hard_stop_pct": hard_pct,
                },
            }

    def enforce_budget(self, token_id: str) -> dict[str, Any]:
        """Enforce budget — raises ValueError if hard_stop, returns status otherwise."""
        status = self.check_budget(token_id)
        if status["state"] == "hard_stop":
            raise ValueError(
                f"delegation budget exceeded hard stop: "
                f"${status['total_spend_usd']:.2f} / ${status['max_budget_usd']:.2f} "
                f"({status['ratio_pct']:.1f}%)"
            )
        return status

    def reset_for_tests(self) -> None:
        """Reset budget tables for testing."""
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            with self._conn:
                for table in ["delegation_budget_events", "delegation_budget_limits"]:
                    try:
                        self._conn.execute(f"DELETE FROM {table}")  # noqa: S608
                    except sqlite3.Error:
                        pass


BUDGET_STORE = DelegationBudgetStore()

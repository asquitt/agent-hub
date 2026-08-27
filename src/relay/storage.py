from __future__ import annotations

import json
import math
import os
from pathlib import Path
import sqlite3
import threading
from typing import Any
from uuid import uuid4

from src.persistence import apply_scope_migrations

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DB = ROOT / "data" / "relay" / "relay.db"


class RelayConflictError(RuntimeError):
    pass


class RelayStateError(RuntimeError):
    pass


class RelayBudgetError(RuntimeError):
    def __init__(
        self, code: str, message: str, budget: dict[str, Any] | None = None
    ) -> None:
        super().__init__(message)
        self.code = code
        self.budget = budget or {}


def _db_path() -> Path:
    return Path(os.getenv("AGENTHUB_RELAY_DB_PATH", str(DEFAULT_DB)))


def _json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _round_cost(value: float) -> float:
    return round(float(value), 6)


class RelayStorage:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._conn: sqlite3.Connection | None = None
        self._path: str | None = None

    def _connect(self, path: Path) -> sqlite3.Connection:
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = FULL")
        return conn

    def _ensure_ready(self) -> None:
        with self._lock:
            desired = str(_db_path())
            if self._conn is not None and self._path == desired:
                return
            self._reconfigure_locked(Path(desired))

    def _reconfigure_locked(self, path: Path) -> None:
        if self._conn is not None:
            self._conn.close()
        self._conn = self._connect(path)
        apply_scope_migrations(self._conn, "relay")
        self._path = str(path)

    def reconfigure(self, db_path: str | Path | None = None) -> None:
        if db_path is not None:
            os.environ["AGENTHUB_RELAY_DB_PATH"] = str(Path(db_path))
        with self._lock:
            self._reconfigure_locked(_db_path())

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                self._conn.close()
            self._conn = None
            self._path = None

    def reset_for_tests(self, db_path: str | Path | None = None) -> None:
        self.reconfigure(db_path)
        with self._lock:
            assert self._conn is not None
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._conn.execute("DELETE FROM relay_invocations")
                self._conn.execute("DELETE FROM relay_budget_accounts")
                self._conn.execute("DELETE FROM relay_targets")
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

    def upsert_target(self, target: dict[str, Any]) -> dict[str, Any]:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            with self._conn:
                self._conn.execute(
                    """
                    INSERT INTO relay_targets(
                        target_id, tenant_id, endpoint_url, endpoint_digest, tool_name,
                        server_name, server_version, protocol_version, input_schema_json,
                        output_schema_json, schema_digest, annotations_json,
                        operator_attests_read_only, max_call_cost_usd,
                        policy_revision, enabled
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                    ON CONFLICT(target_id) DO UPDATE SET
                        tenant_id = excluded.tenant_id,
                        endpoint_url = excluded.endpoint_url,
                        endpoint_digest = excluded.endpoint_digest,
                        tool_name = excluded.tool_name,
                        server_name = excluded.server_name,
                        server_version = excluded.server_version,
                        protocol_version = excluded.protocol_version,
                        input_schema_json = excluded.input_schema_json,
                        output_schema_json = excluded.output_schema_json,
                        schema_digest = excluded.schema_digest,
                        annotations_json = excluded.annotations_json,
                        operator_attests_read_only = excluded.operator_attests_read_only,
                        max_call_cost_usd = excluded.max_call_cost_usd,
                        policy_revision = excluded.policy_revision,
                        enabled = 1,
                        updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                    """,
                    (
                        target["target_id"],
                        target["tenant_id"],
                        target["endpoint_url"],
                        target["endpoint_digest"],
                        target["tool_name"],
                        target["server_name"],
                        target["server_version"],
                        target["protocol_version"],
                        _json(target["input_schema"]),
                        _json(target["output_schema"]),
                        target["schema_digest"],
                        _json(target["annotations"]),
                        1 if target["operator_attests_read_only"] else 0,
                        _round_cost(target["max_call_cost_usd"]),
                        target["policy_revision"],
                    ),
                )
        return self.get_target(str(target["target_id"]))

    def get_target(self, target_id: str) -> dict[str, Any]:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            row = self._conn.execute(
                "SELECT * FROM relay_targets WHERE target_id = ?", (target_id,)
            ).fetchone()
            if row is None:
                raise KeyError(f"relay target not found: {target_id}")
            return self._target_row(row)

    def set_target_enabled(self, target_id: str, enabled: bool) -> dict[str, Any]:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            with self._conn:
                result = self._conn.execute(
                    """
                    UPDATE relay_targets
                    SET enabled = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                    WHERE target_id = ?
                    """,
                    (1 if enabled else 0, target_id),
                )
            if result.rowcount != 1:
                raise KeyError(f"relay target not found: {target_id}")
        return self.get_target(target_id)

    def set_budget(
        self,
        *,
        owner: str,
        tenant_id: str,
        capability_token_id: str,
        max_budget_usd: float,
    ) -> dict[str, Any]:
        maximum = _round_cost(max_budget_usd)
        if not math.isfinite(maximum) or maximum <= 0:
            raise ValueError("max_budget_usd must be finite and greater than zero")
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            with self._conn:
                self._conn.execute(
                    """
                    INSERT INTO relay_budget_accounts(
                        owner, tenant_id, capability_token_id, max_budget_usd
                    ) VALUES (?, ?, ?, ?)
                    ON CONFLICT(owner, tenant_id, capability_token_id) DO UPDATE SET
                        max_budget_usd = excluded.max_budget_usd,
                        updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                    """,
                    (owner, tenant_id, capability_token_id, maximum),
                )
        return self.get_budget(
            owner=owner, tenant_id=tenant_id, capability_token_id=capability_token_id
        )

    def get_budget(
        self, *, owner: str, tenant_id: str, capability_token_id: str
    ) -> dict[str, Any]:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            row = self._conn.execute(
                """
                SELECT * FROM relay_budget_accounts
                WHERE owner = ? AND tenant_id = ? AND capability_token_id = ?
                """,
                (owner, tenant_id, capability_token_id),
            ).fetchone()
            if row is None:
                raise KeyError("relay budget not found")
            return dict(row)

    def reserve_invocation(
        self,
        *,
        owner: str,
        tenant_id: str,
        agent_id: str,
        idempotency_key: str,
        request_hash: str,
        target_id: str,
        capability_token_id: str,
        input_hash: str,
    ) -> tuple[dict[str, Any], bool]:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            invocation_id = f"rly-{uuid4().hex[:20]}"
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                existing = self._conn.execute(
                    """
                    SELECT * FROM relay_invocations
                    WHERE owner = ? AND tenant_id = ? AND idempotency_key = ?
                    """,
                    (owner, tenant_id, idempotency_key),
                ).fetchone()
                if existing is not None:
                    if str(existing["request_hash"]) != request_hash:
                        raise RelayConflictError(
                            "idempotency key reused with a different request"
                        )
                    self._conn.commit()
                    return self._invocation_row(existing), False
                self._conn.execute(
                    """
                    INSERT INTO relay_invocations(
                        invocation_id, owner, tenant_id, agent_id, idempotency_key,
                        request_hash, target_id, capability_token_id, status, input_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)
                    """,
                    (
                        invocation_id,
                        owner,
                        tenant_id,
                        agent_id,
                        idempotency_key,
                        request_hash,
                        target_id,
                        capability_token_id,
                        input_hash,
                    ),
                )
                row = self._conn.execute(
                    "SELECT * FROM relay_invocations WHERE invocation_id = ?",
                    (invocation_id,),
                ).fetchone()
                self._conn.commit()
                assert row is not None
                return self._invocation_row(row), True
            except Exception:
                self._conn.rollback()
                raise

    def reserve_budget(
        self,
        *,
        invocation_id: str,
        policy: dict[str, Any],
        cost_usd: float,
    ) -> dict[str, Any]:
        cost = _round_cost(cost_usd)
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                invocation = self._pending_locked(invocation_id)
                account = self._conn.execute(
                    """
                    SELECT * FROM relay_budget_accounts
                    WHERE owner = ? AND tenant_id = ? AND capability_token_id = ?
                    """,
                    (
                        invocation["owner"],
                        invocation["tenant_id"],
                        invocation["capability_token_id"],
                    ),
                ).fetchone()
                if account is None:
                    raise RelayBudgetError("budget.missing", "relay budget is required")
                maximum = float(account["max_budget_usd"])
                spent = float(account["spent_usd"])
                reserved = float(account["reserved_usd"])
                projected = _round_cost(spent + reserved + cost)
                ratio = (projected / maximum * 100.0) if maximum else 120.0
                state = (
                    "hard_stop"
                    if ratio >= 120.0
                    else "reauthorization_required"
                    if ratio >= 100.0
                    else "soft_alert"
                    if ratio >= 80.0
                    else "ok"
                )
                budget = {
                    "max_budget_usd": maximum,
                    "spent_before_usd": spent,
                    "reserved_before_usd": reserved,
                    "reserved_cost_usd": cost,
                    "projected_usd": projected,
                    "projected_ratio_pct": round(ratio, 2),
                    "state": state,
                    "thresholds": {
                        "soft_alert_pct": 80,
                        "reauth_pct": 100,
                        "hard_stop_pct": 120,
                    },
                }
                if state in {"reauthorization_required", "hard_stop"}:
                    code = (
                        "budget.hard_stop"
                        if state == "hard_stop"
                        else "budget.reauthorization_required"
                    )
                    raise RelayBudgetError(
                        code, "relay budget does not authorize this call", budget
                    )
                self._conn.execute(
                    """
                    UPDATE relay_budget_accounts
                    SET reserved_usd = reserved_usd + ?,
                        updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                    WHERE owner = ? AND tenant_id = ? AND capability_token_id = ?
                    """,
                    (
                        cost,
                        invocation["owner"],
                        invocation["tenant_id"],
                        invocation["capability_token_id"],
                    ),
                )
                self._conn.execute(
                    """
                    UPDATE relay_invocations
                    SET reserved_cost_usd = ?, policy_json = ?, budget_json = ?,
                        updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                    WHERE invocation_id = ? AND status = 'pending'
                    """,
                    (cost, _json(policy), _json(budget), invocation_id),
                )
                self._conn.commit()
                return budget
            except Exception:
                self._conn.rollback()
                raise

    def mark_network_started(
        self, invocation_id: str, *, target_snapshot: dict[str, Any]
    ) -> dict[str, Any]:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            with self._conn:
                result = self._conn.execute(
                    """
                    UPDATE relay_invocations
                    SET network_started_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                        attempt_count = 1, target_snapshot_json = ?,
                        updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                    WHERE invocation_id = ? AND status = 'pending'
                      AND network_started_at IS NULL AND policy_json IS NOT NULL
                    """,
                    (_json(target_snapshot), invocation_id),
                )
            if result.rowcount != 1:
                raise RelayStateError("relay invocation cannot enter network state")
        return self.get_invocation_unscoped(invocation_id)

    def finalize(
        self,
        *,
        invocation_id: str,
        status: str,
        output_hash: str | None,
        result: dict[str, Any] | None,
        error_code: str | None,
        error_message: str | None,
        receipt: dict[str, Any],
        remote_result_observed: bool,
        charge_reserved: bool,
    ) -> dict[str, Any]:
        if status not in {"succeeded", "failed", "indeterminate"}:
            raise ValueError("invalid final relay status")
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                invocation = self._pending_locked(invocation_id)
                reserved = float(invocation["reserved_cost_usd"])
                charge = reserved if charge_reserved else 0.0
                if reserved:
                    self._conn.execute(
                        """
                        UPDATE relay_budget_accounts
                        SET reserved_usd = MAX(0, reserved_usd - ?),
                            spent_usd = spent_usd + ?,
                            updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                        WHERE owner = ? AND tenant_id = ? AND capability_token_id = ?
                        """,
                        (
                            reserved,
                            charge,
                            invocation["owner"],
                            invocation["tenant_id"],
                            invocation["capability_token_id"],
                        ),
                    )
                self._conn.execute(
                    """
                    UPDATE relay_invocations
                    SET status = ?, output_hash = ?, result_json = ?, error_code = ?,
                        error_message = ?, receipt_json = ?, charged_cost_usd = ?,
                        remote_result_observed = ?,
                        completed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                        updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                    WHERE invocation_id = ? AND status = 'pending'
                    """,
                    (
                        status,
                        output_hash,
                        _json(result) if result is not None else None,
                        error_code,
                        error_message,
                        _json(receipt),
                        charge,
                        1 if remote_result_observed else 0,
                        invocation_id,
                    ),
                )
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
        return self.get_invocation_unscoped(invocation_id)

    def fail_before_dispatch(
        self,
        *,
        invocation_id: str,
        error_code: str,
        error_message: str,
        receipt: dict[str, Any] | None = None,
        policy: dict[str, Any] | None = None,
        budget: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                invocation = self._pending_locked(invocation_id)
                reserved = float(invocation["reserved_cost_usd"])
                if reserved:
                    self._conn.execute(
                        """
                        UPDATE relay_budget_accounts
                        SET reserved_usd = MAX(0, reserved_usd - ?),
                            updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                        WHERE owner = ? AND tenant_id = ? AND capability_token_id = ?
                        """,
                        (
                            reserved,
                            invocation["owner"],
                            invocation["tenant_id"],
                            invocation["capability_token_id"],
                        ),
                    )
                self._conn.execute(
                    """
                    UPDATE relay_invocations
                    SET status = 'failed', error_code = ?, error_message = ?,
                        policy_json = COALESCE(?, policy_json),
                        budget_json = COALESCE(?, budget_json),
                        receipt_json = ?, completed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                        updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                    WHERE invocation_id = ? AND status = 'pending'
                    """,
                    (
                        error_code,
                        error_message,
                        _json(policy) if policy is not None else None,
                        _json(budget) if budget is not None else None,
                        _json(receipt) if receipt is not None else None,
                        invocation_id,
                    ),
                )
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
        return self.get_invocation_unscoped(invocation_id)

    def recover_abandoned(self) -> list[dict[str, Any]]:
        """Close abandoned calls and return terminal rows missing a receipt."""
        self._ensure_ready()
        recovered: list[dict[str, Any]] = []
        with self._lock:
            assert self._conn is not None
            ids = [
                str(row["invocation_id"])
                for row in self._conn.execute(
                    "SELECT invocation_id FROM relay_invocations WHERE status = 'pending'"
                ).fetchall()
            ]
            for invocation_id in ids:
                invocation = self.get_invocation_unscoped(invocation_id)
                if invocation["network_started_at"] is None:
                    recovered.append(
                        self.fail_before_dispatch(
                            invocation_id=invocation_id,
                            error_code="relay.recovered_before_dispatch",
                            error_message="abandoned before remote dispatch",
                        )
                    )
                    continue
                if not isinstance(invocation.get("target_snapshot"), dict):
                    raise RelayStateError(
                        "dispatched relay invocation lacks an immutable target snapshot"
                    )
                recovered.append(
                    self.finalize(
                        invocation_id=invocation_id,
                        status="indeterminate",
                        output_hash=None,
                        result=None,
                        error_code="relay.recovered_ambiguous",
                        error_message="remote completion could not be proven after recovery",
                        receipt={},
                        remote_result_observed=False,
                        charge_reserved=True,
                    )
                )
            recovered_ids = {str(row["invocation_id"]) for row in recovered}
            receiptless_ids = [
                str(row["invocation_id"])
                for row in self._conn.execute(
                    """
                    SELECT invocation_id FROM relay_invocations
                    WHERE status != 'pending'
                      AND (receipt_json IS NULL OR receipt_json = '{}')
                    """
                ).fetchall()
            ]
            for invocation_id in receiptless_ids:
                if invocation_id not in recovered_ids:
                    recovered.append(self.get_invocation_unscoped(invocation_id))
        return recovered

    def get_invocation(
        self, invocation_id: str, *, owner: str, tenant_id: str
    ) -> dict[str, Any]:
        row = self.get_invocation_unscoped(invocation_id)
        if row["owner"] != owner or row["tenant_id"] != tenant_id:
            raise KeyError(f"relay invocation not found: {invocation_id}")
        return row

    def attach_receipt(
        self, invocation_id: str, receipt: dict[str, Any]
    ) -> dict[str, Any]:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            with self._conn:
                result = self._conn.execute(
                    """
                    UPDATE relay_invocations
                    SET receipt_json = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                    WHERE invocation_id = ? AND status != 'pending'
                      AND (receipt_json IS NULL OR receipt_json = '{}')
                    """,
                    (_json(receipt), invocation_id),
                )
            if result.rowcount != 1:
                raise RelayStateError("relay receipt cannot be attached")
        return self.get_invocation_unscoped(invocation_id)

    def get_invocation_unscoped(self, invocation_id: str) -> dict[str, Any]:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            row = self._conn.execute(
                "SELECT * FROM relay_invocations WHERE invocation_id = ?",
                (invocation_id,),
            ).fetchone()
            if row is None:
                raise KeyError(f"relay invocation not found: {invocation_id}")
            return self._invocation_row(row)

    def _pending_locked(self, invocation_id: str) -> sqlite3.Row:
        assert self._conn is not None
        row = self._conn.execute(
            "SELECT * FROM relay_invocations WHERE invocation_id = ?", (invocation_id,)
        ).fetchone()
        if row is None:
            raise KeyError(f"relay invocation not found: {invocation_id}")
        if row["status"] != "pending":
            raise RelayStateError("relay invocation is already finalized")
        return row

    @staticmethod
    def _target_row(row: sqlite3.Row) -> dict[str, Any]:
        out = dict(row)
        out["enabled"] = bool(out["enabled"])
        out["operator_attests_read_only"] = bool(out["operator_attests_read_only"])
        out["input_schema"] = json.loads(out.pop("input_schema_json"))
        out["output_schema"] = json.loads(out.pop("output_schema_json"))
        out["annotations"] = json.loads(out.pop("annotations_json"))
        return out

    @staticmethod
    def _invocation_row(row: sqlite3.Row) -> dict[str, Any]:
        out = dict(row)
        for source, target in (
            ("result_json", "result"),
            ("policy_json", "policy"),
            ("budget_json", "budget"),
            ("receipt_json", "receipt"),
            ("target_snapshot_json", "target_snapshot"),
        ):
            raw = out.pop(source)
            out[target] = json.loads(raw) if raw else None
        out["remote_result_observed"] = bool(out["remote_result_observed"])
        return out


RELAY_STORAGE = RelayStorage()

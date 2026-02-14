"""Network Egress Allowlists — per-agent outbound connection policies.

Restricts which domains/IPs an agent can connect to during sandboxed execution.
Supports allowlist (whitelist) and denylist (blocklist) modes.
"""
from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
import threading
import uuid
from pathlib import Path
from typing import Any

from src.persistence import apply_scope_migrations

_log = logging.getLogger("agenthub.egress_policy")

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DB = ROOT / "data" / "runtime" / "runtime.db"


def _db_path() -> Path:
    return Path(os.getenv("AGENTHUB_RUNTIME_DB_PATH", str(DEFAULT_DB)))


# Default denylist — always blocked regardless of per-agent policy
DEFAULT_DENYLIST = [
    "169.254.169.254",   # AWS metadata service
    "metadata.google.internal",  # GCP metadata
    "100.100.100.200",   # Azure metadata
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
]


class EgressPolicyStore:
    """SQLite-backed egress policy management."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._conn: sqlite3.Connection | None = None
        self._db_path: str | None = None

    def _ensure_ready(self) -> None:
        with self._lock:
            desired = str(_db_path())
            if self._conn is not None and self._db_path == desired:
                return
            if self._conn is not None:
                self._conn.close()
            db = Path(desired)
            db.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(str(db), check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode = WAL")
            self._conn.execute("PRAGMA synchronous = NORMAL")
            self._init_tables()
            self._db_path = desired

    def _init_tables(self) -> None:
        assert self._conn is not None
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS egress_policies (
                policy_id TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL DEFAULT 'tenant-default',
                mode TEXT NOT NULL DEFAULT 'allowlist',
                domains_json TEXT NOT NULL DEFAULT '[]',
                ports_json TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
            );
            CREATE INDEX IF NOT EXISTS idx_egress_policies_agent
                ON egress_policies(agent_id);
        """)

    def set_policy(
        self,
        *,
        agent_id: str,
        mode: str = "allowlist",
        domains: list[str] | None = None,
        ports: list[int] | None = None,
        tenant_id: str = "tenant-default",
    ) -> dict[str, Any]:
        """Set or update an egress policy for an agent."""
        if mode not in ("allowlist", "denylist"):
            raise ValueError(f"invalid mode: {mode}, must be 'allowlist' or 'denylist'")
        self._ensure_ready()
        policy_id = f"egress-{agent_id}-{uuid.uuid4().hex[:8]}"
        effective_domains = domains or []
        effective_ports = ports or [443, 80]  # Default: HTTPS + HTTP only

        with self._lock:
            assert self._conn is not None
            # Remove existing policy for this agent
            with self._conn:
                self._conn.execute("DELETE FROM egress_policies WHERE agent_id = ?", (agent_id,))
                self._conn.execute(
                    """
                    INSERT INTO egress_policies (policy_id, agent_id, tenant_id, mode, domains_json, ports_json)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (policy_id, agent_id, tenant_id, mode,
                     json.dumps(effective_domains), json.dumps(effective_ports)),
                )
        return {
            "policy_id": policy_id,
            "agent_id": agent_id,
            "mode": mode,
            "domains": effective_domains,
            "ports": effective_ports,
        }

    def get_policy(self, agent_id: str) -> dict[str, Any] | None:
        """Get the egress policy for an agent."""
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            row = self._conn.execute(
                "SELECT * FROM egress_policies WHERE agent_id = ? ORDER BY created_at DESC LIMIT 1",
                (agent_id,),
            ).fetchone()
            if row is None:
                return None
            return {
                "policy_id": str(row["policy_id"]),
                "agent_id": str(row["agent_id"]),
                "mode": str(row["mode"]),
                "domains": json.loads(row["domains_json"]),
                "ports": json.loads(row["ports_json"]),
            }

    def check_egress(
        self,
        *,
        agent_id: str,
        target_host: str,
        target_port: int = 443,
    ) -> dict[str, Any]:
        """Check if an agent is allowed to connect to a target.

        Returns a dict with 'allowed' (bool) and 'reason'.
        """
        # Always deny default denylist targets
        normalized = target_host.lower().strip()
        if normalized in DEFAULT_DENYLIST:
            return {
                "allowed": False,
                "reason": "default_denylist",
                "target_host": target_host,
                "target_port": target_port,
            }

        policy = self.get_policy(agent_id)
        if policy is None:
            # No policy → allow all (open by default for backward compat)
            return {
                "allowed": True,
                "reason": "no_policy",
                "target_host": target_host,
                "target_port": target_port,
            }

        domains = [d.lower().strip() for d in policy["domains"]]
        ports = policy["ports"]
        mode = policy["mode"]

        # Check port
        if ports and target_port not in ports:
            return {
                "allowed": False,
                "reason": "port_not_allowed",
                "target_host": target_host,
                "target_port": target_port,
                "allowed_ports": ports,
            }

        # Check domain
        domain_match = _matches_domain(normalized, domains)

        if mode == "allowlist":
            allowed = domain_match
            reason = "allowlist_match" if allowed else "not_in_allowlist"
        else:  # denylist
            allowed = not domain_match
            reason = "denylist_match" if not allowed else "not_in_denylist"

        return {
            "allowed": allowed,
            "reason": reason,
            "target_host": target_host,
            "target_port": target_port,
        }

    def reset_for_tests(self) -> None:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            with self._conn:
                self._conn.execute("DELETE FROM egress_policies")


def _matches_domain(target: str, patterns: list[str]) -> bool:
    """Check if target matches any domain pattern (supports wildcard *.example.com)."""
    for pattern in patterns:
        if pattern == target:
            return True
        if pattern.startswith("*."):
            suffix = pattern[1:]  # .example.com
            if target.endswith(suffix) or target == pattern[2:]:
                return True
    return False


EGRESS_STORE = EgressPolicyStore()

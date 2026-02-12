from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.api.store import STORE

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ADAPTER_CATALOG = ROOT / "tests" / "capability_search" / "fixtures" / "mock_capabilities.json"


@dataclass(frozen=True)
class CapabilityRow:
    agent_id: str
    capability_id: str
    capability_name: str
    description: str
    tags: list[str]
    category: str
    protocols: list[str]
    permissions: list[str]
    trust_score: float
    usage_30d: int
    p95_latency_ms: int
    estimated_cost_usd: float
    freshness_days: int
    input_required: list[str]
    output_fields: list[str]
    source: str


class LiveCapabilityIndex:
    def __init__(self, refresh_interval_seconds: int = 5) -> None:
        self.refresh_interval_seconds = refresh_interval_seconds
        self._lock = threading.RLock()
        self._rows: list[CapabilityRow] = []
        self._refreshed_at: float = 0.0
        self._adapter_catalog_path = Path(str(Path(os.getenv("AGENTHUB_ADAPTER_CATALOG_PATH", str(DEFAULT_ADAPTER_CATALOG)))))

    def _normalize_row(self, row: dict[str, Any], source: str) -> CapabilityRow:
        return CapabilityRow(
            agent_id=str(row.get("agent_id", "")).strip(),
            capability_id=str(row.get("capability_id", "")).strip(),
            capability_name=str(row.get("capability_name", "")).strip(),
            description=str(row.get("description", "")).strip(),
            tags=[str(tag) for tag in row.get("tags", []) if str(tag).strip()],
            category=str(row.get("category", "general")).strip(),
            protocols=[str(protocol) for protocol in row.get("protocols", []) if str(protocol).strip()],
            permissions=[str(perm) for perm in row.get("permissions", []) if str(perm).strip()],
            trust_score=round(float(row.get("trust_score", 0.75)), 6),
            usage_30d=int(row.get("usage_30d", 0)),
            p95_latency_ms=int(row.get("p95_latency_ms", 200)),
            estimated_cost_usd=round(float(row.get("estimated_cost_usd", 0.05)), 6),
            freshness_days=int(row.get("freshness_days", 0)),
            input_required=[str(value) for value in row.get("input_required", []) if str(value).strip()],
            output_fields=[str(value) for value in row.get("output_fields", []) if str(value).strip()],
            source=source,
        )

    def _adapter_rows(self) -> list[CapabilityRow]:
        if not self._adapter_catalog_path.exists():
            return []
        try:
            raw = json.loads(self._adapter_catalog_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return []
        if not isinstance(raw, list):
            return []
        rows: list[CapabilityRow] = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            normalized = self._normalize_row(item, source="adapter")
            if normalized.agent_id and normalized.capability_id:
                rows.append(normalized)
        return rows

    def _registry_rows(self) -> list[CapabilityRow]:
        rows: list[CapabilityRow] = []
        for agent in STORE.list_agents():
            if not agent.versions:
                continue
            latest_manifest = agent.versions[-1].manifest
            for cap in latest_manifest.get("capabilities", []):
                if not isinstance(cap, dict):
                    continue
                normalized = self._normalize_row(
                    {
                        "agent_id": agent.slug,
                        "capability_id": cap.get("id"),
                        "capability_name": cap.get("name"),
                        "description": cap.get("description", ""),
                        "tags": cap.get("tags", []),
                        "category": cap.get("category", "general"),
                        "protocols": cap.get("protocols", []),
                        "permissions": cap.get("permissions", []),
                        "trust_score": 0.75,
                        "usage_30d": 0,
                        "p95_latency_ms": cap.get("p95_latency_ms", 150),
                        "estimated_cost_usd": cap.get("estimated_cost_usd", 0.05),
                        "freshness_days": 0,
                        "input_required": cap.get("input_schema", {}).get("required", []),
                        "output_fields": cap.get("output_schema", {}).get("required", []),
                    },
                    source="registry",
                )
                if normalized.agent_id and normalized.capability_id:
                    rows.append(normalized)
        return rows

    def refresh(self, force: bool = False) -> None:
        with self._lock:
            now = time.time()
            if not force and self._rows and (now - self._refreshed_at) < self.refresh_interval_seconds:
                return
            adapter_rows = self._adapter_rows()
            registry_rows = self._registry_rows()
            merged: dict[tuple[str, str], CapabilityRow] = {}

            for row in adapter_rows:
                merged[(row.agent_id, row.capability_id)] = row
            # Registry rows override adapter rows for same agent+capability ids.
            for row in registry_rows:
                merged[(row.agent_id, row.capability_id)] = row

            self._rows = sorted(merged.values(), key=lambda row: (row.agent_id, row.capability_id))
            self._refreshed_at = now

    def snapshot(self) -> dict[str, Any]:
        self.refresh(force=False)
        with self._lock:
            source_counts = {"adapter": 0, "registry": 0}
            for row in self._rows:
                source_counts[row.source] = source_counts.get(row.source, 0) + 1
            return {
                "rows": list(self._rows),
                "refreshed_at_epoch": self._refreshed_at,
                "source_counts": source_counts,
            }


LIVE_CAPABILITY_INDEX = LiveCapabilityIndex(refresh_interval_seconds=5)

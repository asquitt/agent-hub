from __future__ import annotations

from src.api.store import STORE
from src.api.store import AgentRecord


def list_tenant_ids() -> list[str]:
    return STORE.list_tenant_ids()


def list_agents_for_tenant(tenant_id: str) -> list[AgentRecord]:
    return STORE.list_agents(tenant_id=tenant_id)

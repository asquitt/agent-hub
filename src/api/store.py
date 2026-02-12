from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class VersionRecord:
    version: str
    manifest: dict[str, Any]
    eval_summary: dict[str, Any] = field(default_factory=lambda: {"tier1": "pending", "tier2": "pending", "tier3": "pending"})


@dataclass
class AgentRecord:
    agent_id: str
    namespace: str
    slug: str
    owner: str
    status: str = "active"
    versions: list[VersionRecord] = field(default_factory=list)


class RegistryStore:
    def __init__(self) -> None:
        self.namespaces: dict[str, str] = {}
        self.agents: dict[str, AgentRecord] = {}
        self.idempotency_cache: dict[tuple[str, str], Any] = {}

    def reserve_namespace(self, namespace: str, owner: str) -> None:
        if namespace not in self.namespaces:
            self.namespaces[namespace] = owner
            return
        if self.namespaces[namespace] != owner:
            raise PermissionError("namespace already reserved by another owner")

    def register_agent(self, namespace: str, manifest: dict[str, Any], owner: str) -> AgentRecord:
        slug = manifest["identity"]["id"]
        agent_id = f"{namespace}:{slug}"
        if agent_id in self.agents:
            raise ValueError("agent already exists")

        record = AgentRecord(agent_id=agent_id, namespace=namespace, slug=slug, owner=owner)
        record.versions.append(VersionRecord(version=manifest["identity"]["version"], manifest=manifest))
        self.agents[agent_id] = record
        return record

    def list_agents(self, namespace: str | None = None, status: str | None = None) -> list[AgentRecord]:
        items = list(self.agents.values())
        if namespace:
            items = [a for a in items if a.namespace == namespace]
        if status:
            items = [a for a in items if a.status == status]
        items.sort(key=lambda a: a.agent_id)
        return items

    def get_agent(self, agent_id: str) -> AgentRecord:
        if agent_id not in self.agents:
            raise KeyError("agent not found")
        return self.agents[agent_id]

    def update_agent(self, agent_id: str, manifest: dict[str, Any], owner: str) -> AgentRecord:
        agent = self.get_agent(agent_id)
        if agent.owner != owner:
            raise PermissionError("owner mismatch")

        version = manifest["identity"]["version"]
        if any(v.version == version for v in agent.versions):
            raise ValueError("version already exists")

        agent.versions.append(VersionRecord(version=version, manifest=manifest))
        agent.status = "active"
        return agent

    def delete_agent(self, agent_id: str, owner: str) -> AgentRecord:
        agent = self.get_agent(agent_id)
        if agent.owner != owner:
            raise PermissionError("owner mismatch")
        agent.status = "deprecated"
        return agent

    def list_versions(self, agent_id: str) -> list[VersionRecord]:
        return self.get_agent(agent_id).versions

    def get_version(self, agent_id: str, version: str) -> VersionRecord:
        agent = self.get_agent(agent_id)
        for item in agent.versions:
            if item.version == version:
                return item
        raise KeyError("version not found")


STORE = RegistryStore()

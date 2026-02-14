"""Kubernetes Sandbox Operator Interface — CRD definitions and pod spec generation.

Generates Kubernetes manifests for agent sandbox execution:
- Custom Resource Definitions (CRDs) for AgentSandbox
- Pod spec generation with security contexts
- NetworkPolicy generation for sandbox isolation
- Resource quota enforcement
"""
from __future__ import annotations

import hashlib
import logging
import time
import uuid
from typing import Any

_log = logging.getLogger("agenthub.k8s_operator")

# Default resource limits
DEFAULT_CPU_LIMIT = "500m"
DEFAULT_MEMORY_LIMIT = "256Mi"
DEFAULT_CPU_REQUEST = "100m"
DEFAULT_MEMORY_REQUEST = "64Mi"

# In-memory store for generated manifests
_generated_manifests: list[dict[str, Any]] = []


def generate_pod_spec(
    *,
    sandbox_id: str,
    agent_id: str,
    image: str = "agenthub/sandbox:latest",
    cpu_limit: str = DEFAULT_CPU_LIMIT,
    memory_limit: str = DEFAULT_MEMORY_LIMIT,
    env_vars: dict[str, str] | None = None,
    network_mode: str = "none",
) -> dict[str, Any]:
    """Generate a Kubernetes Pod specification for a sandbox."""
    labels = {
        "app": "agenthub-sandbox",
        "sandbox-id": sandbox_id,
        "agent-id": agent_id,
    }

    env_list: list[dict[str, str]] = [
        {"name": "SANDBOX_ID", "value": sandbox_id},
        {"name": "AGENT_ID", "value": agent_id},
    ]
    if env_vars:
        for k, v in env_vars.items():
            env_list.append({"name": k, "value": v})

    pod_spec: dict[str, Any] = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": f"sandbox-{sandbox_id[:24]}",
            "namespace": "agenthub-sandboxes",
            "labels": labels,
        },
        "spec": {
            "containers": [{
                "name": "sandbox",
                "image": image,
                "env": env_list,
                "resources": {
                    "limits": {"cpu": cpu_limit, "memory": memory_limit},
                    "requests": {"cpu": DEFAULT_CPU_REQUEST, "memory": DEFAULT_MEMORY_REQUEST},
                },
                "securityContext": {
                    "runAsNonRoot": True,
                    "runAsUser": 1000,
                    "readOnlyRootFilesystem": True,
                    "allowPrivilegeEscalation": False,
                    "capabilities": {"drop": ["ALL"]},
                },
            }],
            "restartPolicy": "Never",
            "serviceAccountName": "sandbox-runner",
            "automountServiceAccountToken": False,
        },
    }

    record: dict[str, Any] = {
        "manifest_id": f"k8s-{uuid.uuid4().hex[:12]}",
        "manifest_type": "pod",
        "sandbox_id": sandbox_id,
        "agent_id": agent_id,
        "manifest": pod_spec,
        "generated_at": time.time(),
    }
    _generated_manifests.append(record)
    return record


def generate_network_policy(
    *,
    sandbox_id: str,
    agent_id: str,
    allow_egress: bool = False,
    allowed_egress_cidrs: list[str] | None = None,
) -> dict[str, Any]:
    """Generate a Kubernetes NetworkPolicy for sandbox isolation."""
    labels = {"sandbox-id": sandbox_id, "agent-id": agent_id}

    egress_rules: list[dict[str, Any]] = []
    if allow_egress and allowed_egress_cidrs:
        egress_rules.append({
            "to": [{"ipBlock": {"cidr": cidr}} for cidr in allowed_egress_cidrs],
        })

    policy: dict[str, Any] = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "name": f"sandbox-netpol-{sandbox_id[:24]}",
            "namespace": "agenthub-sandboxes",
        },
        "spec": {
            "podSelector": {"matchLabels": labels},
            "policyTypes": ["Ingress", "Egress"],
            "ingress": [],  # Deny all ingress
            "egress": egress_rules,
        },
    }

    record: dict[str, Any] = {
        "manifest_id": f"k8s-{uuid.uuid4().hex[:12]}",
        "manifest_type": "network_policy",
        "sandbox_id": sandbox_id,
        "agent_id": agent_id,
        "manifest": policy,
        "generated_at": time.time(),
    }
    _generated_manifests.append(record)
    return record


def generate_crd() -> dict[str, Any]:
    """Generate the AgentSandbox Custom Resource Definition."""
    crd: dict[str, Any] = {
        "apiVersion": "apiextensions.k8s.io/v1",
        "kind": "CustomResourceDefinition",
        "metadata": {"name": "agentsandboxes.agenthub.dev"},
        "spec": {
            "group": "agenthub.dev",
            "versions": [{
                "name": "v1",
                "served": True,
                "storage": True,
                "schema": {
                    "openAPIV3Schema": {
                        "type": "object",
                        "properties": {
                            "spec": {
                                "type": "object",
                                "properties": {
                                    "agentId": {"type": "string"},
                                    "sandboxId": {"type": "string"},
                                    "image": {"type": "string"},
                                    "cpuLimit": {"type": "string", "default": DEFAULT_CPU_LIMIT},
                                    "memoryLimit": {"type": "string", "default": DEFAULT_MEMORY_LIMIT},
                                    "networkMode": {"type": "string", "enum": ["none", "restricted", "full"]},
                                },
                                "required": ["agentId", "sandboxId"],
                            },
                            "status": {
                                "type": "object",
                                "properties": {
                                    "phase": {"type": "string"},
                                    "podName": {"type": "string"},
                                    "startTime": {"type": "string", "format": "date-time"},
                                },
                            },
                        },
                    },
                },
            }],
            "scope": "Namespaced",
            "names": {
                "plural": "agentsandboxes",
                "singular": "agentsandbox",
                "kind": "AgentSandbox",
                "shortNames": ["asb"],
            },
        },
    }
    return {"manifest_type": "crd", "manifest": crd, "generated_at": time.time()}


def list_generated_manifests(
    *,
    sandbox_id: str | None = None,
    manifest_type: str | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """List generated K8s manifests."""
    results = _generated_manifests
    if sandbox_id:
        results = [m for m in results if m.get("sandbox_id") == sandbox_id]
    if manifest_type:
        results = [m for m in results if m["manifest_type"] == manifest_type]
    return list(reversed(results[-limit:]))


def reset_for_tests() -> None:
    """Clear generated manifests."""
    _generated_manifests.clear()

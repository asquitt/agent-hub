"""A2A Protocol Adapter — canonical contract ↔ Google A2A protocol translation.

Translates between AgentHub's canonical internal contract format
and the Google Agent-to-Agent (A2A) protocol format.
"""
from __future__ import annotations

import json
import uuid
from typing import Any

from src.protocol.types import CanonicalCapability, CanonicalToolCall, CanonicalToolResult


def capability_to_a2a_skill(capability: CanonicalCapability) -> dict[str, Any]:
    """Convert a canonical capability to an A2A skill definition."""
    skill: dict[str, Any] = {
        "id": capability.get("id", "unknown"),
        "name": capability.get("name", capability.get("id", "unknown")),
        "description": capability.get("description", ""),
    }

    input_schema = capability.get("input_schema")
    if input_schema:
        skill["inputModes"] = ["application/json"]
    output_schema = capability.get("output_schema")
    if output_schema:
        skill["outputModes"] = ["application/json"]

    return skill


def a2a_skill_to_capability(skill: dict[str, Any]) -> CanonicalCapability:
    """Convert an A2A skill to a canonical capability."""
    cap: CanonicalCapability = {
        "id": str(skill.get("id", "unknown")),
        "name": str(skill.get("name", skill.get("id", "unknown"))),
        "description": str(skill.get("description", "")),
        "category": "skill",
        "protocols": ["A2A"],
        "idempotency_key_required": False,
        "side_effect_level": "unknown",
    }
    return cap


def to_a2a_task(canonical_call: CanonicalToolCall) -> dict[str, Any]:
    """Convert a canonical tool call to an A2A Task.

    A2A Task: { id, sessionId, status, message }
    """
    task_id = canonical_call.get("idempotency_key", str(uuid.uuid4()))
    return {
        "id": task_id,
        "sessionId": canonical_call.get("sandbox_id", ""),
        "status": {"state": "submitted"},
        "message": {
            "role": "user",
            "parts": [
                {
                    "type": "text",
                    "text": json.dumps({
                        "tool": canonical_call.get("tool_name", ""),
                        "input": canonical_call.get("tool_input", {}),
                    }),
                }
            ],
        },
    }


def from_a2a_task(task: dict[str, Any]) -> CanonicalToolCall:
    """Convert an A2A Task to a canonical tool call."""
    message = task.get("message", {})
    parts = message.get("parts", [])

    tool_name = ""
    tool_input: dict[str, Any] = {}

    for part in parts if isinstance(parts, list) else []:
        if isinstance(part, dict) and part.get("type") == "text":
            text = part.get("text", "")
            try:
                parsed = json.loads(text)
                if isinstance(parsed, dict):
                    tool_name = str(parsed.get("tool", ""))
                    tool_input = parsed.get("input", {})
            except (json.JSONDecodeError, TypeError):
                tool_name = text

    call: CanonicalToolCall = {
        "tool_name": tool_name,
        "tool_input": tool_input,
    }

    task_id = task.get("id")
    if task_id:
        call["idempotency_key"] = str(task_id)

    session_id = task.get("sessionId")
    if session_id:
        call["sandbox_id"] = str(session_id)

    return call


def to_a2a_task_result(
    canonical_result: CanonicalToolResult,
    task_id: str = "",
) -> dict[str, Any]:
    """Convert a canonical tool result to an A2A Task result."""
    parts: list[dict[str, Any]] = []

    output = canonical_result.get("output")
    if output is not None:
        if isinstance(output, str):
            parts.append({"type": "text", "text": output})
        else:
            parts.append({"type": "text", "text": json.dumps(output)})

    error = canonical_result.get("error")
    is_error = canonical_result.get("is_error", False)

    if is_error and error:
        state = "failed"
        parts.append({"type": "text", "text": f"Error: {error}"})
    else:
        state = "completed"

    return {
        "id": task_id,
        "status": {"state": state},
        "artifacts": [
            {
                "name": canonical_result.get("tool_name", "result"),
                "parts": parts,
            }
        ] if parts else [],
    }


def from_a2a_task_result(task_result: dict[str, Any]) -> CanonicalToolResult:
    """Convert an A2A Task result to a canonical tool result."""
    status = task_result.get("status", {})
    state = status.get("state", "unknown")
    is_error = state == "failed"

    text_parts: list[str] = []
    artifacts = task_result.get("artifacts", [])
    for artifact in artifacts if isinstance(artifacts, list) else []:
        if isinstance(artifact, dict):
            for part in artifact.get("parts", []):
                if isinstance(part, dict) and part.get("type") == "text":
                    text_parts.append(str(part.get("text", "")))

    output_text = "\n".join(text_parts)
    output: Any = output_text
    try:
        output = json.loads(output_text)
    except (json.JSONDecodeError, TypeError):
        pass

    result: CanonicalToolResult = {
        "tool_name": "",
        "output": output,
        "is_error": is_error,
        "error": output_text if is_error else None,
        "metadata": {"task_id": task_result.get("id", "")},
    }

    return result

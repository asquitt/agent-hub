from __future__ import annotations

from typing import Any

SIDE_EFFECT_ORDER = {"none": 0, "low": 1, "high": 2}


def _required_fields(schema: dict[str, Any]) -> set[str]:
    required = schema.get("required", [])
    if not isinstance(required, list):
        return set()
    return {str(item) for item in required}


def _index_capabilities(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    capabilities = manifest.get("capabilities", [])
    if not isinstance(capabilities, list):
        return {}
    indexed: dict[str, dict[str, Any]] = {}
    for capability in capabilities:
        if not isinstance(capability, dict):
            continue
        cid = capability.get("id")
        if isinstance(cid, str):
            indexed[cid] = capability
    return indexed


def _risk_level(score: int) -> str:
    if score >= 6:
        return "high"
    if score >= 3:
        return "medium"
    return "low"


def compute_behavioral_diff(base_manifest: dict[str, Any], target_manifest: dict[str, Any]) -> dict[str, Any]:
    base_caps = _index_capabilities(base_manifest)
    target_caps = _index_capabilities(target_manifest)

    added_capabilities = sorted(set(target_caps) - set(base_caps))
    removed_capabilities = sorted(set(base_caps) - set(target_caps))
    shared_capabilities = sorted(set(base_caps) & set(target_caps))

    breaking_changes: list[dict[str, Any]] = []
    non_breaking_changes: list[dict[str, Any]] = []
    modified_capabilities: list[str] = []

    for capability_id in shared_capabilities:
        before = base_caps[capability_id]
        after = target_caps[capability_id]

        before_input_required = _required_fields(before.get("input_schema", {}))
        after_input_required = _required_fields(after.get("input_schema", {}))
        input_required_added = sorted(after_input_required - before_input_required)
        input_required_removed = sorted(before_input_required - after_input_required)

        before_output_required = _required_fields(before.get("output_schema", {}))
        after_output_required = _required_fields(after.get("output_schema", {}))
        output_required_removed = sorted(before_output_required - after_output_required)
        output_required_added = sorted(after_output_required - before_output_required)

        before_protocols = set(before.get("protocols", []))
        after_protocols = set(after.get("protocols", []))
        protocols_removed = sorted(before_protocols - after_protocols)
        protocols_added = sorted(after_protocols - before_protocols)

        before_side_effect = str(before.get("side_effect_level", "none"))
        after_side_effect = str(after.get("side_effect_level", "none"))
        side_effect_escalated = SIDE_EFFECT_ORDER.get(after_side_effect, 0) > SIDE_EFFECT_ORDER.get(before_side_effect, 0)

        changed = any(
            [
                input_required_added,
                input_required_removed,
                output_required_removed,
                output_required_added,
                protocols_removed,
                protocols_added,
                side_effect_escalated,
            ]
        )
        if changed:
            modified_capabilities.append(capability_id)

        if input_required_added:
            breaking_changes.append(
                {
                    "capability_id": capability_id,
                    "type": "input_required_added",
                    "fields": input_required_added,
                }
            )

        if output_required_removed:
            breaking_changes.append(
                {
                    "capability_id": capability_id,
                    "type": "output_required_removed",
                    "fields": output_required_removed,
                }
            )

        if protocols_removed:
            breaking_changes.append(
                {
                    "capability_id": capability_id,
                    "type": "protocols_removed",
                    "protocols": protocols_removed,
                }
            )

        if side_effect_escalated:
            breaking_changes.append(
                {
                    "capability_id": capability_id,
                    "type": "side_effect_escalated",
                    "from": before_side_effect,
                    "to": after_side_effect,
                }
            )

        if input_required_removed:
            non_breaking_changes.append(
                {
                    "capability_id": capability_id,
                    "type": "input_required_removed",
                    "fields": input_required_removed,
                }
            )

        if output_required_added:
            non_breaking_changes.append(
                {
                    "capability_id": capability_id,
                    "type": "output_required_added",
                    "fields": output_required_added,
                }
            )

        if protocols_added:
            non_breaking_changes.append(
                {
                    "capability_id": capability_id,
                    "type": "protocols_added",
                    "protocols": protocols_added,
                }
            )

    if added_capabilities:
        non_breaking_changes.append(
            {
                "type": "capabilities_added",
                "capability_ids": added_capabilities,
            }
        )
    if removed_capabilities:
        breaking_changes.append(
            {
                "type": "capabilities_removed",
                "capability_ids": removed_capabilities,
            }
        )

    score = len(breaking_changes) * 2 + len(non_breaking_changes)
    compatibility = "backward_compatible" if not breaking_changes else "breaking"

    return {
        "compatibility": compatibility,
        "risk_level": _risk_level(score),
        "regression_risk_score": score,
        "capability_delta": {
            "added": added_capabilities,
            "removed": removed_capabilities,
            "modified": modified_capabilities,
        },
        "breaking_changes": breaking_changes,
        "non_breaking_changes": non_breaking_changes,
    }

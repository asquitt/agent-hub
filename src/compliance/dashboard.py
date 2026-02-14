"""Compliance Dashboard — unified compliance posture view.

Aggregates compliance data from OWASP mapping, SOC2 evidence, and
identity analytics into a single dashboard view with overall scores.
"""
from __future__ import annotations

import time
from typing import Any

from src.compliance.owasp_agentic import get_gap_analysis, get_owasp_mapping
from src.compliance.soc2_evidence import get_compliance_summary


def get_dashboard() -> dict[str, Any]:
    """Get the unified compliance dashboard."""
    now = time.time()

    # OWASP Agentic coverage
    owasp = get_owasp_mapping()
    owasp_gaps = get_gap_analysis()
    owasp_score = owasp.get("coverage_percentage", 0)

    # SOC2 evidence coverage
    soc2 = get_compliance_summary()
    soc2_criteria = soc2.get("criteria_coverage", {})
    criteria_with_evidence = sum(1 for c in soc2_criteria.values() if c.get("has_recent_evidence"))
    soc2_score = round(criteria_with_evidence / max(len(soc2_criteria), 1) * 100)

    # Overall score (weighted average)
    overall_score = round(owasp_score * 0.6 + soc2_score * 0.4)

    if overall_score >= 80:
        posture = "strong"
    elif overall_score >= 60:
        posture = "adequate"
    elif overall_score >= 40:
        posture = "needs_improvement"
    else:
        posture = "critical"

    return {
        "overall_score": overall_score,
        "posture": posture,
        "owasp_agentic": {
            "score": owasp_score,
            "total_controls": owasp.get("total_controls", 0),
            "categories_covered": owasp.get("categories_covered", 0),
            "gap_count": owasp_gaps.get("total_gaps", 0),
        },
        "soc2": {
            "score": soc2_score,
            "total_evidence": soc2.get("total_evidence", 0),
            "criteria_with_recent_evidence": criteria_with_evidence,
            "criteria_total": len(soc2_criteria),
        },
        "recommendations": _generate_recommendations(owasp_gaps, soc2),
        "computed_at": now,
    }


def _generate_recommendations(
    owasp_gaps: dict[str, Any],
    soc2: dict[str, Any],
) -> list[dict[str, str]]:
    """Generate actionable compliance recommendations."""
    recs: list[dict[str, str]] = []

    # OWASP gaps
    gaps = owasp_gaps.get("gaps", [])
    for gap in gaps[:3]:
        recs.append({
            "priority": "high",
            "area": "owasp_agentic",
            "recommendation": f"Address gap in {gap.get('category', 'unknown')}: {gap.get('description', '')}",
        })

    # SOC2 criteria without recent evidence
    criteria = soc2.get("criteria_coverage", {})
    for name, data in criteria.items():
        if not data.get("has_recent_evidence"):
            recs.append({
                "priority": "medium",
                "area": "soc2",
                "recommendation": f"Collect recent evidence for SOC2 criteria {name}",
            })

    return recs

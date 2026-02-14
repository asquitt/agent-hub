"""OWASP Agentic Top 10 Mapping — control mapping and gap analysis.

Maps AgentHub security controls to the OWASP Top 10 for Agentic Applications,
identifies coverage, and produces gap analysis reports.
"""
from __future__ import annotations

from typing import Any

# OWASP Agentic Top 10 categories (2025 draft)
OWASP_CATEGORIES: list[dict[str, str]] = [
    {
        "id": "OWASP-AG-01",
        "name": "Prompt Injection",
        "description": "Attacker manipulates agent behavior through crafted inputs.",
    },
    {
        "id": "OWASP-AG-02",
        "name": "Insufficient Access Control",
        "description": "Agent operates with excessive privileges or missing authorization.",
    },
    {
        "id": "OWASP-AG-03",
        "name": "Tool Misuse",
        "description": "Agent uses tools in unintended or harmful ways.",
    },
    {
        "id": "OWASP-AG-04",
        "name": "Insecure Output Handling",
        "description": "Agent outputs are used unsafely by downstream systems.",
    },
    {
        "id": "OWASP-AG-05",
        "name": "Excessive Agency",
        "description": "Agent has too much autonomy without human oversight.",
    },
    {
        "id": "OWASP-AG-06",
        "name": "Data Leakage",
        "description": "Sensitive information exposed through agent actions or outputs.",
    },
    {
        "id": "OWASP-AG-07",
        "name": "Insufficient Monitoring",
        "description": "Lack of observability into agent actions and decisions.",
    },
    {
        "id": "OWASP-AG-08",
        "name": "Insecure Credential Management",
        "description": "Agent credentials are poorly managed, stored, or rotated.",
    },
    {
        "id": "OWASP-AG-09",
        "name": "Supply Chain Vulnerabilities",
        "description": "Compromised tools, plugins, or dependencies used by agents.",
    },
    {
        "id": "OWASP-AG-10",
        "name": "Denial of Service",
        "description": "Agent resources exhausted through abuse or runaway behavior.",
    },
]

# AgentHub control-to-OWASP mapping
CONTROL_MAPPING: list[dict[str, Any]] = [
    # OWASP-AG-01: Prompt Injection
    {
        "owasp_id": "OWASP-AG-01",
        "control_id": "CTL-INJ-001",
        "control_name": "I/O Injection Detection",
        "module": "src/runtime/io_validation.py",
        "function": "detect_injection",
        "coverage": "full",
        "description": "Pattern-based prompt injection detection on all tool inputs.",
    },
    {
        "owasp_id": "OWASP-AG-01",
        "control_id": "CTL-INJ-002",
        "control_name": "Input Schema Validation",
        "module": "src/runtime/io_validation.py",
        "function": "validate_schema",
        "coverage": "full",
        "description": "JSON schema validation on tool inputs to restrict structure.",
    },
    # OWASP-AG-02: Insufficient Access Control
    {
        "owasp_id": "OWASP-AG-02",
        "control_id": "CTL-ACC-001",
        "control_name": "Scope-Based Access Control",
        "module": "src/api/access_policy.py",
        "function": "evaluate_access",
        "coverage": "full",
        "description": "Route classification with public/authenticated/tenant/admin scopes.",
    },
    {
        "owasp_id": "OWASP-AG-02",
        "control_id": "CTL-ACC-002",
        "control_name": "Delegation Scope Attenuation",
        "module": "src/api/middleware_delegation.py",
        "function": "DelegationChainMiddleware",
        "coverage": "full",
        "description": "Middleware enforcing scope attenuation at every delegation hop.",
    },
    {
        "owasp_id": "OWASP-AG-02",
        "control_id": "CTL-ACC-003",
        "control_name": "JWT-Based Bearer Auth",
        "module": "src/identity/jwt_tokens.py",
        "function": "verify_jwt",
        "coverage": "full",
        "description": "AAP-compliant JWT tokens with scoped claims.",
    },
    # OWASP-AG-03: Tool Misuse
    {
        "owasp_id": "OWASP-AG-03",
        "control_id": "CTL-TOOL-001",
        "control_name": "I/O Validation Hooks",
        "module": "src/runtime/io_validation.py",
        "function": "validate_input",
        "coverage": "full",
        "description": "Full input validation with schema, PII, and injection checks.",
    },
    {
        "owasp_id": "OWASP-AG-03",
        "control_id": "CTL-TOOL-002",
        "control_name": "Output Validation",
        "module": "src/runtime/io_validation.py",
        "function": "validate_output",
        "coverage": "full",
        "description": "Output validation with schema and PII checks.",
    },
    # OWASP-AG-04: Insecure Output Handling
    {
        "owasp_id": "OWASP-AG-04",
        "control_id": "CTL-OUT-001",
        "control_name": "PII Detection in Outputs",
        "module": "src/runtime/io_validation.py",
        "function": "detect_pii",
        "coverage": "full",
        "description": "PII pattern detection on tool outputs.",
    },
    # OWASP-AG-05: Excessive Agency
    {
        "owasp_id": "OWASP-AG-05",
        "control_id": "CTL-AGN-001",
        "control_name": "Oversight Levels",
        "module": "src/identity/jwt_tokens.py",
        "function": "issue_jwt (oversight_level claim)",
        "coverage": "full",
        "description": "JWT oversight_level claim: none/notify/approve/full.",
    },
    {
        "owasp_id": "OWASP-AG-05",
        "control_id": "CTL-AGN-002",
        "control_name": "Sub-Agent Spawn Controls",
        "module": "src/runtime/spawn_controls.py",
        "function": "check_spawn_allowed",
        "coverage": "full",
        "description": "Spawn depth, concurrent, and total limits per agent.",
    },
    {
        "owasp_id": "OWASP-AG-05",
        "control_id": "CTL-AGN-003",
        "control_name": "Delegation Budget Enforcement",
        "module": "src/delegation/budget.py",
        "function": "enforce_budget",
        "coverage": "full",
        "description": "80/100/120 budget thresholds with hard stop.",
    },
    # OWASP-AG-06: Data Leakage
    {
        "owasp_id": "OWASP-AG-06",
        "control_id": "CTL-DLP-001",
        "control_name": "PII Detection",
        "module": "src/runtime/io_validation.py",
        "function": "detect_pii",
        "coverage": "full",
        "description": "Multi-pattern PII detection on inputs and outputs.",
    },
    {
        "owasp_id": "OWASP-AG-06",
        "control_id": "CTL-DLP-002",
        "control_name": "Network Egress Allowlists",
        "module": "src/runtime/egress_policy.py",
        "function": "check_egress",
        "coverage": "full",
        "description": "Per-agent network egress restrictions with domain allowlists.",
    },
    # OWASP-AG-07: Insufficient Monitoring
    {
        "owasp_id": "OWASP-AG-07",
        "control_id": "CTL-MON-001",
        "control_name": "Request Logging Middleware",
        "module": "src/api/middleware.py",
        "function": "RequestLoggingMiddleware",
        "coverage": "full",
        "description": "Structured request/response logging with X-Request-ID.",
    },
    {
        "owasp_id": "OWASP-AG-07",
        "control_id": "CTL-MON-002",
        "control_name": "Provenance Tracking",
        "module": "src/provenance/service.py",
        "function": "sign_manifest",
        "coverage": "full",
        "description": "Artifact signing and manifest verification for audit trails.",
    },
    # OWASP-AG-08: Insecure Credential Management
    {
        "owasp_id": "OWASP-AG-08",
        "control_id": "CTL-CRED-001",
        "control_name": "JIT Credential Binding",
        "module": "src/runtime/jit_credentials.py",
        "function": "issue_jit_credential",
        "coverage": "full",
        "description": "Auto-issue/revoke credentials bound to sandbox lifecycle.",
    },
    {
        "owasp_id": "OWASP-AG-08",
        "control_id": "CTL-CRED-002",
        "control_name": "Credential Rotation",
        "module": "src/identity/credentials.py",
        "function": "rotate_credential",
        "coverage": "full",
        "description": "Automatic credential rotation with parent chain tracking.",
    },
    {
        "owasp_id": "OWASP-AG-08",
        "control_id": "CTL-CRED-003",
        "control_name": "Cascade Revocation",
        "module": "src/identity/revocation.py",
        "function": "revoke_credential",
        "coverage": "full",
        "description": "Revoking a credential cascades to all downstream tokens.",
    },
    # OWASP-AG-09: Supply Chain Vulnerabilities
    {
        "owasp_id": "OWASP-AG-09",
        "control_id": "CTL-SC-001",
        "control_name": "Configuration Checksums",
        "module": "src/identity/checksum.py",
        "function": "verify_config_integrity",
        "coverage": "partial",
        "description": "SHA-256 checksums for agent configurations to detect drift.",
    },
    {
        "owasp_id": "OWASP-AG-09",
        "control_id": "CTL-SC-002",
        "control_name": "Provenance Verification",
        "module": "src/provenance/service.py",
        "function": "verify_manifest",
        "coverage": "partial",
        "description": "Manifest signature verification for supply chain integrity.",
    },
    # OWASP-AG-10: Denial of Service
    {
        "owasp_id": "OWASP-AG-10",
        "control_id": "CTL-DOS-001",
        "control_name": "Rate Limiting",
        "module": "src/api/middleware.py",
        "function": "limiter",
        "coverage": "full",
        "description": "SlowAPI-based rate limiting on all endpoints.",
    },
    {
        "owasp_id": "OWASP-AG-10",
        "control_id": "CTL-DOS-002",
        "control_name": "Payload Size Limits",
        "module": "src/runtime/io_validation.py",
        "function": "validate_size",
        "coverage": "full",
        "description": "1MB input / 10MB output payload size enforcement.",
    },
    {
        "owasp_id": "OWASP-AG-10",
        "control_id": "CTL-DOS-003",
        "control_name": "Budget Hard Stop",
        "module": "src/delegation/budget.py",
        "function": "enforce_budget",
        "coverage": "full",
        "description": "120% budget hard stop prevents runaway cost.",
    },
]


def get_owasp_mapping() -> dict[str, Any]:
    """Get the full OWASP Agentic Top 10 control mapping."""
    return {
        "framework": "OWASP Agentic Top 10",
        "version": "2025-draft",
        "categories": OWASP_CATEGORIES,
        "total_controls": len(CONTROL_MAPPING),
        "controls": CONTROL_MAPPING,
    }


def get_gap_analysis() -> dict[str, Any]:
    """Analyze coverage gaps across OWASP categories."""
    category_ids = {c["id"] for c in OWASP_CATEGORIES}
    covered_ids = {c["owasp_id"] for c in CONTROL_MAPPING}
    controls_by_category: dict[str, list[dict[str, Any]]] = {}

    for control in CONTROL_MAPPING:
        cat_id = control["owasp_id"]
        if cat_id not in controls_by_category:
            controls_by_category[cat_id] = []
        controls_by_category[cat_id].append(control)

    analysis: list[dict[str, Any]] = []
    for category in OWASP_CATEGORIES:
        cat_id = category["id"]
        controls = controls_by_category.get(cat_id, [])
        full_coverage = [c for c in controls if c["coverage"] == "full"]
        partial_coverage = [c for c in controls if c["coverage"] == "partial"]

        if not controls:
            status = "gap"
        elif partial_coverage and not full_coverage:
            status = "partial"
        elif full_coverage:
            status = "covered"
        else:
            status = "partial"

        analysis.append({
            "owasp_id": cat_id,
            "category_name": category["name"],
            "status": status,
            "control_count": len(controls),
            "full_coverage_count": len(full_coverage),
            "partial_coverage_count": len(partial_coverage),
        })

    uncovered = category_ids - covered_ids
    return {
        "total_categories": len(OWASP_CATEGORIES),
        "covered_categories": len(covered_ids),
        "gap_categories": len(uncovered),
        "coverage_pct": round(len(covered_ids) / len(category_ids) * 100, 1),
        "analysis": analysis,
    }

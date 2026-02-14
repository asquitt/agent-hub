"""I/O Validation Hooks — schema validation, PII detection, prompt injection detection.

Validates tool inputs and outputs against schemas, detects PII in payloads,
and flags potential prompt injection attempts.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from src.runtime.io_constants import (
    INJECTION_MARKERS,
    MAX_INPUT_SIZE_BYTES,
    MAX_OUTPUT_SIZE_BYTES,
    PII_PATTERNS,
    SEVERITY_CRITICAL,
    SEVERITY_INFO,
    SEVERITY_WARNING,
)

_log = logging.getLogger("agenthub.io_validation")


class ValidationFinding:
    """A single validation finding."""

    __slots__ = ("category", "severity", "message", "details")

    def __init__(
        self,
        *,
        category: str,
        severity: str,
        message: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.category = category
        self.severity = severity
        self.message = message
        self.details = details or {}

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "category": self.category,
            "severity": self.severity,
            "message": self.message,
        }
        if self.details:
            result["details"] = self.details
        return result


class ValidationResult:
    """Result of an I/O validation pass."""

    def __init__(self) -> None:
        self.findings: list[ValidationFinding] = []

    @property
    def valid(self) -> bool:
        return not any(f.severity == SEVERITY_CRITICAL for f in self.findings)

    @property
    def has_warnings(self) -> bool:
        return any(f.severity == SEVERITY_WARNING for f in self.findings)

    def add(self, finding: ValidationFinding) -> None:
        self.findings.append(finding)

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "finding_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
        }


def _extract_text(data: Any, max_depth: int = 5) -> str:
    """Extract all text content from a nested data structure."""
    if max_depth <= 0:
        return ""
    if isinstance(data, str):
        return data
    if isinstance(data, dict):
        parts = []
        for v in data.values():
            parts.append(_extract_text(v, max_depth - 1))
        return " ".join(parts)
    if isinstance(data, list):
        parts = []
        for item in data:
            parts.append(_extract_text(item, max_depth - 1))
        return " ".join(parts)
    return str(data) if data is not None else ""


def detect_pii(data: Any) -> list[ValidationFinding]:
    """Scan data for PII patterns."""
    text = _extract_text(data)
    findings: list[ValidationFinding] = []
    for pii_type, pattern in PII_PATTERNS:
        matches = pattern.findall(text)
        if matches:
            findings.append(ValidationFinding(
                category="pii",
                severity=SEVERITY_WARNING,
                message=f"potential {pii_type} detected ({len(matches)} occurrence(s))",
                details={"pii_type": pii_type, "count": len(matches)},
            ))
    return findings


def detect_injection(data: Any) -> list[ValidationFinding]:
    """Scan data for prompt injection markers."""
    text = _extract_text(data)
    findings: list[ValidationFinding] = []
    for pattern in INJECTION_MARKERS:
        match = pattern.search(text)
        if match:
            findings.append(ValidationFinding(
                category="injection",
                severity=SEVERITY_CRITICAL,
                message=f"potential prompt injection detected: '{match.group()}'",
                details={"matched_text": match.group()},
            ))
    return findings


def validate_size(
    data: Any,
    *,
    direction: str = "input",
) -> list[ValidationFinding]:
    """Validate payload size constraints."""
    findings: list[ValidationFinding] = []
    try:
        serialized = json.dumps(data, default=str)
        size = len(serialized.encode("utf-8"))
    except (TypeError, ValueError):
        size = 0

    max_size = MAX_INPUT_SIZE_BYTES if direction == "input" else MAX_OUTPUT_SIZE_BYTES
    if size > max_size:
        findings.append(ValidationFinding(
            category="size",
            severity=SEVERITY_CRITICAL,
            message=f"{direction} payload exceeds maximum size ({size} > {max_size} bytes)",
            details={"size_bytes": size, "max_bytes": max_size},
        ))
    return findings


def validate_schema(
    data: Any,
    schema: dict[str, Any] | None,
) -> list[ValidationFinding]:
    """Validate data against a JSON schema (basic type checking)."""
    findings: list[ValidationFinding] = []
    if schema is None:
        return findings

    expected_type = schema.get("type")
    if expected_type == "object" and not isinstance(data, dict):
        findings.append(ValidationFinding(
            category="schema",
            severity=SEVERITY_CRITICAL,
            message=f"expected object, got {type(data).__name__}",
        ))
    elif expected_type == "array" and not isinstance(data, list):
        findings.append(ValidationFinding(
            category="schema",
            severity=SEVERITY_CRITICAL,
            message=f"expected array, got {type(data).__name__}",
        ))
    elif expected_type == "string" and not isinstance(data, str):
        findings.append(ValidationFinding(
            category="schema",
            severity=SEVERITY_CRITICAL,
            message=f"expected string, got {type(data).__name__}",
        ))

    # Check required properties for objects
    if isinstance(data, dict) and expected_type == "object":
        required = schema.get("required", [])
        for field in required:
            if field not in data:
                findings.append(ValidationFinding(
                    category="schema",
                    severity=SEVERITY_CRITICAL,
                    message=f"missing required field: {field}",
                    details={"field": field},
                ))

    return findings


def validate_input(
    data: Any,
    *,
    schema: dict[str, Any] | None = None,
    check_pii: bool = True,
    check_injection: bool = True,
) -> ValidationResult:
    """Full input validation: size, schema, PII, injection."""
    result = ValidationResult()

    for f in validate_size(data, direction="input"):
        result.add(f)
    if schema:
        for f in validate_schema(data, schema):
            result.add(f)
    if check_pii:
        for f in detect_pii(data):
            result.add(f)
    if check_injection:
        for f in detect_injection(data):
            result.add(f)

    return result


def validate_output(
    data: Any,
    *,
    schema: dict[str, Any] | None = None,
    check_pii: bool = True,
) -> ValidationResult:
    """Full output validation: size, schema, PII (no injection check on output)."""
    result = ValidationResult()

    for f in validate_size(data, direction="output"):
        result.add(f)
    if schema:
        for f in validate_schema(data, schema):
            result.add(f)
    if check_pii:
        for f in detect_pii(data):
            result.add(f)

    return result

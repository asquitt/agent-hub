"""Constants for I/O validation — PII patterns, thresholds, injection markers."""
from __future__ import annotations

import re

# PII detection patterns (conservative — minimize false positives)
PII_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("email", re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", re.IGNORECASE)),
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("credit_card", re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b")),
    ("phone_us", re.compile(r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")),
    ("ip_address", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
]

# Prompt injection detection markers
INJECTION_MARKERS: list[re.Pattern[str]] = [
    re.compile(r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(?:a|an|in)\s+", re.IGNORECASE),
    re.compile(r"system\s*prompt\s*:", re.IGNORECASE),
    re.compile(r"<\s*(?:system|admin|root)\s*>", re.IGNORECASE),
    re.compile(r"(?:override|bypass)\s+(?:safety|security|restrictions)", re.IGNORECASE),
    re.compile(r"(?:reveal|show|print)\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions)", re.IGNORECASE),
]

# Validation severity levels
SEVERITY_INFO = "info"
SEVERITY_WARNING = "warning"
SEVERITY_CRITICAL = "critical"

# Maximum payload sizes
MAX_INPUT_SIZE_BYTES = 1_048_576   # 1 MB
MAX_OUTPUT_SIZE_BYTES = 10_485_760  # 10 MB

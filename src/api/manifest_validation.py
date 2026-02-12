from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator, FormatChecker

ROOT_DIR = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT_DIR / "specs" / "manifest" / "agent-manifest-spec-v0.1.yaml"
_SECRET_KEY_PATTERN = re.compile(r"(secret|token|password|api[_-]?key|private[_-]?key)", re.IGNORECASE)
_ALLOWED_SECRET_KEYS = {"secret_ref", "token_ref", "credential_ref", "password_ref", "api_key_ref", "private_key_ref"}


def _format_path(path: list[Any]) -> str:
    if not path:
        return "$"
    parts = []
    for part in path:
        if isinstance(part, int):
            parts.append(f"[{part}]")
        else:
            parts.append(f".{part}")
    return "$" + "".join(parts)


def _iter_inline_secret_violations(value: Any, path: list[Any]) -> list[str]:
    violations: list[str] = []

    if isinstance(value, dict):
        for key, child in value.items():
            child_path = path + [key]
            key_lc = str(key).lower()
            has_secret_name = bool(_SECRET_KEY_PATTERN.search(key_lc))
            is_reference_key = key_lc.endswith("_ref") or key_lc in _ALLOWED_SECRET_KEYS

            if has_secret_name and not is_reference_key and isinstance(child, (str, int, float, bool)):
                violations.append(
                    f"{_format_path(child_path)} has inline secret-like value; use *_ref (env://, vault://, kms://)"
                )

            violations.extend(_iter_inline_secret_violations(child, child_path))

    elif isinstance(value, list):
        for idx, child in enumerate(value):
            violations.extend(_iter_inline_secret_violations(child, path + [idx]))

    return violations


def validate_manifest_object(manifest: dict[str, Any]) -> list[str]:
    schema = yaml.safe_load(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema, format_checker=FormatChecker())

    errors: list[str] = []
    for err in sorted(validator.iter_errors(manifest), key=lambda item: list(item.absolute_path)):
        location = _format_path(list(err.absolute_path))
        errors.append(f"{location}: {err.message}")

    errors.extend(_iter_inline_secret_violations(manifest, []))
    return errors

#!/usr/bin/env python3
"""Validate AgentHub manifest files against schema + policy checks."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator, FormatChecker

ROOT_DIR = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT_DIR / "specs" / "manifest" / "agent-manifest-spec-v0.1.yaml"
_SECRET_KEY_PATTERN = re.compile(r"(secret|token|password|api[_-]?key|private[_-]?key)", re.IGNORECASE)
_ALLOWED_SECRET_KEYS = {"secret_ref", "token_ref", "credential_ref", "password_ref", "api_key_ref", "private_key_ref"}


class ValidationFailure(Exception):
    pass


def _read_yaml(path: Path) -> dict[str, Any]:
    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ValidationFailure(f"YAML parse error in {path}: {exc}") from exc

    if not isinstance(loaded, dict):
        raise ValidationFailure(f"Manifest root must be an object: {path}")

    return loaded


def _load_schema() -> dict[str, Any]:
    if not SCHEMA_PATH.exists():
        raise ValidationFailure(f"Schema not found: {SCHEMA_PATH}")
    return _read_yaml(SCHEMA_PATH)


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


def validate_manifest(path: Path) -> list[str]:
    schema = _load_schema()
    manifest = _read_yaml(path)

    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors: list[str] = []

    for err in sorted(validator.iter_errors(manifest), key=lambda item: list(item.absolute_path)):
        location = _format_path(list(err.absolute_path))
        errors.append(f"{location}: {err.message}")

    errors.extend(_iter_inline_secret_violations(manifest, []))
    return errors


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="agenthub manifest validate",
        description="Validate an AgentHub manifest file.",
    )
    parser.add_argument("manifest", help="Path to agent manifest YAML")
    return parser.parse_args(argv)


def _normalize_cli(argv: list[str]) -> list[str]:
    if len(argv) >= 3 and argv[0] == "manifest" and argv[1] == "validate":
        return argv[2:]
    return argv


def main(argv: list[str] | None = None) -> int:
    incoming = list(sys.argv[1:] if argv is None else argv)
    normalized = _normalize_cli(incoming)

    try:
        args = _parse_args(normalized)
    except SystemExit:
        return 2

    manifest_path = Path(args.manifest)
    if not manifest_path.exists():
        print(f"ERROR: manifest not found: {manifest_path}", file=sys.stderr)
        return 2

    try:
        failures = validate_manifest(manifest_path)
    except ValidationFailure as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if failures:
        print(f"INVALID: {manifest_path}")
        for idx, failure in enumerate(failures, start=1):
            print(f"{idx}. {failure}")
        return 1

    print(f"VALID: {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

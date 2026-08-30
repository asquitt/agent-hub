#!/usr/bin/env python3
"""Offline verifier for AgentHub Ed25519 action receipts."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.relay.receipts import verify_receipt  # noqa: E402


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read JSON from {path}: {exc}") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify an AgentHub action receipt using an Ed25519 public JWK."
    )
    parser.add_argument("receipt", type=Path, help="path to the receipt envelope JSON")
    parser.add_argument("public_jwk", type=Path, help="path to the public JWK JSON")
    args = parser.parse_args(argv)

    try:
        envelope = _read_json(args.receipt)
        public_jwk = _read_json(args.public_jwk)
        result = verify_receipt(envelope, public_jwk)
    except ValueError as exc:
        result = {"valid": False, "reason": str(exc)}

    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = ROOT / "tools" / "manifest" / "validate_manifest.py"
EXAMPLES = ROOT / "specs" / "manifest" / "examples"

sys.path.insert(0, str(ROOT / "tools" / "manifest"))
from validate_manifest import validate_manifest  # noqa: E402


VALID_EXAMPLES = [
    EXAMPLES / "simple-tool-agent.yaml",
    EXAMPLES / "multi-capability-agent.yaml",
    EXAMPLES / "pipeline-agent.yaml",
]


def test_schema_accepts_canonical_examples() -> None:
    for manifest_path in VALID_EXAMPLES:
        errors = validate_manifest(manifest_path)
        assert errors == [], f"expected valid manifest, got errors for {manifest_path}: {errors}"


def test_cli_accepts_canonical_example() -> None:
    result = subprocess.run(
        [sys.executable, str(VALIDATOR), "manifest", "validate", str(VALID_EXAMPLES[0])],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "VALID:" in result.stdout

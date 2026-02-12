from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
INVALID_DIR = ROOT / "tests" / "manifest" / "fixtures" / "invalid"
VALIDATOR = ROOT / "tools" / "manifest" / "validate_manifest.py"

sys.path.insert(0, str(ROOT / "tools" / "manifest"))
from validate_manifest import validate_manifest  # noqa: E402


@pytest.mark.parametrize(
    "fixture,expected_snippet",
    [
        ("missing-identity-version.yaml", "identity: 'version' is a required property"),
        ("invalid-semver.yaml", "identity.version"),
        ("privileged-interface-missing-permissions.yaml", "interfaces[0]"),
        ("missing-trust-policy.yaml", "trust: 'policy' is a required property"),
        ("inline-secret-value.yaml", "inline secret-like value"),
        ("invalid-budget-thresholds.yaml", "budget_guardrails"),
    ],
)
def test_schema_rejects_invalid_fixtures_with_actionable_errors(fixture: str, expected_snippet: str) -> None:
    fixture_path = INVALID_DIR / fixture
    errors = validate_manifest(fixture_path)
    assert errors, f"expected validation errors for {fixture_path}"
    combined = "\n".join(errors)
    assert expected_snippet in combined, f"missing expected error fragment: {expected_snippet}\n{combined}"


def test_cli_rejects_invalid_manifest() -> None:
    fixture_path = INVALID_DIR / "invalid-semver.yaml"
    result = subprocess.run(
        [sys.executable, str(VALIDATOR), str(fixture_path)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1, result.stdout + result.stderr
    assert "INVALID:" in result.stdout

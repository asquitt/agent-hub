from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from src.api.app import app
from src.api.store import STORE
from src.provenance.service import (
    sign_artifact,
    sign_manifest,
    verify_artifact_signature,
    verify_manifest_signature,
)

ROOT = Path(__file__).resolve().parents[2]
MANIFEST_FIXTURE = ROOT / "specs" / "manifest" / "examples" / "simple-tool-agent.yaml"


@pytest.fixture(autouse=True)
def isolate_registry_and_signing_secret(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    registry_db = tmp_path / "registry.db"
    monkeypatch.setenv("AGENTHUB_REGISTRY_DB_PATH", str(registry_db))
    monkeypatch.setenv("AGENTHUB_PROVENANCE_SIGNING_SECRET", "s40-test-secret")
    STORE.reset_for_tests(db_path=registry_db)


def _manifest() -> dict:
    return yaml.safe_load(MANIFEST_FIXTURE.read_text(encoding="utf-8"))


def test_manifest_signing_roundtrip_and_tamper_detection() -> None:
    manifest = _manifest()
    envelope = sign_manifest(manifest=manifest, signer="owner-dev", artifact_hashes=["abc123"])
    verified = verify_manifest_signature(manifest=manifest, envelope=envelope)
    assert verified["valid"] is True

    tampered = dict(manifest)
    tampered = yaml.safe_load(yaml.safe_dump(tampered))
    tampered["identity"]["name"] = "tampered-name"
    tampered_result = verify_manifest_signature(manifest=tampered, envelope=envelope)
    assert tampered_result["valid"] is False
    assert tampered_result["reason"] == "manifest hash mismatch"


def test_artifact_signing_roundtrip_and_tamper_detection() -> None:
    artifact_payload = {"artifact_type": "container", "digest": "sha256:abcd", "metadata": {"region": "us-east-1"}}
    envelope = sign_artifact(artifact_id="artifact-s40-1", artifact_payload=artifact_payload, signer="owner-dev")
    verified = verify_artifact_signature(artifact_id="artifact-s40-1", artifact_payload=artifact_payload, envelope=envelope)
    assert verified["valid"] is True

    tampered_payload = {"artifact_type": "container", "digest": "sha256:efgh", "metadata": {"region": "us-east-1"}}
    tampered_result = verify_artifact_signature(
        artifact_id="artifact-s40-1",
        artifact_payload=tampered_payload,
        envelope=envelope,
    )
    assert tampered_result["valid"] is False
    assert tampered_result["reason"] == "artifact hash mismatch"


def test_provenance_api_sign_verify_and_signer_boundary() -> None:
    manifest = _manifest()
    artifact_payload = {"artifact_type": "bundle", "checksum": "v1"}
    with TestClient(app) as client:
        blocked = client.post(
            "/v1/provenance/manifests/sign",
            json={"manifest": manifest, "signer": "owner-partner", "artifact_hashes": []},
            headers={"X-API-Key": "dev-owner-key"},
        )
        assert blocked.status_code == 403

        sign_manifest_response = client.post(
            "/v1/provenance/manifests/sign",
            json={"manifest": manifest, "signer": "owner-dev", "artifact_hashes": ["abc123"]},
            headers={"X-API-Key": "dev-owner-key"},
        )
        assert sign_manifest_response.status_code == 200
        manifest_envelope = sign_manifest_response.json()["envelope"]

        verify_manifest_response = client.post(
            "/v1/provenance/manifests/verify",
            json={"manifest": manifest, "envelope": manifest_envelope},
            headers={"X-API-Key": "dev-owner-key"},
        )
        assert verify_manifest_response.status_code == 200
        assert verify_manifest_response.json()["verification"]["valid"] is True

        sign_artifact_response = client.post(
            "/v1/provenance/artifacts/sign",
            json={"artifact_id": "artifact-s40-api", "artifact_payload": artifact_payload, "signer": "owner-dev"},
            headers={"X-API-Key": "dev-owner-key"},
        )
        assert sign_artifact_response.status_code == 200
        artifact_envelope = sign_artifact_response.json()["envelope"]

        verify_artifact_response = client.post(
            "/v1/provenance/artifacts/verify",
            json={"artifact_id": "artifact-s40-api", "artifact_payload": artifact_payload, "envelope": artifact_envelope},
            headers={"X-API-Key": "dev-owner-key"},
        )
        assert verify_artifact_response.status_code == 200
        assert verify_artifact_response.json()["verification"]["valid"] is True

        tampered_artifact_verify = client.post(
            "/v1/provenance/artifacts/verify",
            json={
                "artifact_id": "artifact-s40-api",
                "artifact_payload": {"artifact_type": "bundle", "checksum": "v2"},
                "envelope": artifact_envelope,
            },
            headers={"X-API-Key": "dev-owner-key"},
        )
        assert tampered_artifact_verify.status_code == 200
        assert tampered_artifact_verify.json()["verification"]["valid"] is False

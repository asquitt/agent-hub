from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import Any

from src.common.time import utc_now_iso

PROVENANCE_VERSION = "provenance-v1"
SIGNATURE_ALGORITHM = "hmac-sha256"


def _canonical_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _hash_payload(payload: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def _signing_secret() -> bytes:
    secret = os.getenv("AGENTHUB_PROVENANCE_SIGNING_SECRET", "agenthub-provenance-secret")
    return secret.encode("utf-8")


def _sign(payload: dict[str, Any]) -> str:
    body = _canonical_json(payload).encode("utf-8")
    return hmac.new(_signing_secret(), body, hashlib.sha256).hexdigest()


def manifest_hash(manifest: dict[str, Any]) -> str:
    return _hash_payload(manifest)


def artifact_hash(artifact_payload: dict[str, Any]) -> str:
    return _hash_payload(artifact_payload)


def _manifest_envelope_payload(*, subject_hash: str, signer: str, artifact_hashes: list[str], issued_at: str) -> dict[str, Any]:
    return {
        "version": PROVENANCE_VERSION,
        "subject_type": "manifest",
        "subject_hash": subject_hash,
        "artifact_hashes": sorted(str(item) for item in artifact_hashes),
        "signer": signer,
        "issued_at": issued_at,
        "signature_algorithm": SIGNATURE_ALGORITHM,
    }


def sign_manifest(manifest: dict[str, Any], signer: str, artifact_hashes: list[str] | None = None) -> dict[str, Any]:
    payload = _manifest_envelope_payload(
        subject_hash=manifest_hash(manifest),
        signer=signer,
        artifact_hashes=list(artifact_hashes or []),
        issued_at=utc_now_iso(),
    )
    signature = _sign(payload)
    return {**payload, "signature": signature}


def verify_manifest_signature(manifest: dict[str, Any], envelope: dict[str, Any]) -> dict[str, Any]:
    observed_hash = manifest_hash(manifest)
    declared_hash = str(envelope.get("subject_hash", ""))
    if observed_hash != declared_hash:
        return {
            "valid": False,
            "reason": "manifest hash mismatch",
            "observed_hash": observed_hash,
            "declared_hash": declared_hash,
        }

    payload = _manifest_envelope_payload(
        subject_hash=declared_hash,
        signer=str(envelope.get("signer", "")),
        artifact_hashes=[str(item) for item in envelope.get("artifact_hashes", []) if isinstance(item, (str, int, float))],
        issued_at=str(envelope.get("issued_at", "")),
    )
    if str(envelope.get("signature_algorithm", "")) != SIGNATURE_ALGORITHM:
        return {"valid": False, "reason": "unsupported signature algorithm"}

    expected = _sign(payload)
    provided = str(envelope.get("signature", ""))
    valid = hmac.compare_digest(provided, expected)
    return {
        "valid": valid,
        "reason": "ok" if valid else "invalid signature",
        "observed_hash": observed_hash,
        "declared_hash": declared_hash,
    }


def _artifact_envelope_payload(*, artifact_id: str, artifact_digest: str, signer: str, issued_at: str) -> dict[str, Any]:
    return {
        "version": PROVENANCE_VERSION,
        "subject_type": "artifact",
        "artifact_id": artifact_id,
        "artifact_hash": artifact_digest,
        "signer": signer,
        "issued_at": issued_at,
        "signature_algorithm": SIGNATURE_ALGORITHM,
    }


def sign_artifact(artifact_id: str, artifact_payload: dict[str, Any], signer: str) -> dict[str, Any]:
    payload = _artifact_envelope_payload(
        artifact_id=artifact_id,
        artifact_digest=artifact_hash(artifact_payload),
        signer=signer,
        issued_at=utc_now_iso(),
    )
    signature = _sign(payload)
    return {**payload, "signature": signature}


def verify_artifact_signature(artifact_id: str, artifact_payload: dict[str, Any], envelope: dict[str, Any]) -> dict[str, Any]:
    observed_hash = artifact_hash(artifact_payload)
    declared_hash = str(envelope.get("artifact_hash", ""))
    declared_id = str(envelope.get("artifact_id", ""))
    if artifact_id != declared_id:
        return {"valid": False, "reason": "artifact id mismatch", "artifact_id": artifact_id, "declared_id": declared_id}
    if observed_hash != declared_hash:
        return {
            "valid": False,
            "reason": "artifact hash mismatch",
            "observed_hash": observed_hash,
            "declared_hash": declared_hash,
        }

    payload = _artifact_envelope_payload(
        artifact_id=declared_id,
        artifact_digest=declared_hash,
        signer=str(envelope.get("signer", "")),
        issued_at=str(envelope.get("issued_at", "")),
    )
    if str(envelope.get("signature_algorithm", "")) != SIGNATURE_ALGORITHM:
        return {"valid": False, "reason": "unsupported signature algorithm"}
    expected = _sign(payload)
    provided = str(envelope.get("signature", ""))
    valid = hmac.compare_digest(provided, expected)
    return {
        "valid": valid,
        "reason": "ok" if valid else "invalid signature",
        "artifact_id": artifact_id,
        "observed_hash": observed_hash,
        "declared_hash": declared_hash,
    }

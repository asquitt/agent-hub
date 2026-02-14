"""Quantum-Resistant Credentials — hybrid classical+PQ signature scheme.

Implements a post-quantum cryptography (PQC) interface for agent credentials:
- Hybrid signature scheme: classical (ECDSA/HMAC) + PQ (CRYSTALS-Dilithium stub)
- Key pair generation (classical + PQ components)
- Dual signing: both classical and PQ signatures required
- Verification: both signatures must be valid
- Migration path from classical-only to hybrid

Note: PQ algorithms are stubs pending standardized library availability.
Production deployment requires NIST PQC winner implementations.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from typing import Any

_log = logging.getLogger("agenthub.pqc")

# PQC algorithm identifiers
ALG_DILITHIUM3 = "dilithium3"  # CRYSTALS-Dilithium (NIST PQC winner)
ALG_HYBRID_HMAC_DILITHIUM = "hybrid-hmac-dilithium3"
ALG_CLASSICAL_HMAC = "hmac-sha256"
VALID_PQC_ALGORITHMS = {ALG_DILITHIUM3, ALG_HYBRID_HMAC_DILITHIUM, ALG_CLASSICAL_HMAC}

# In-memory stores
_MAX_SIGNATURES = 10_000
_pqc_keypairs: dict[str, dict[str, Any]] = {}  # agent_id -> keypair
_pqc_signatures: list[dict[str, Any]] = []  # signature records


def _signing_secret() -> bytes:
    secret = os.getenv("AGENTHUB_IDENTITY_SIGNING_SECRET", "")
    if not secret:
        raise PermissionError("AGENTHUB_IDENTITY_SIGNING_SECRET is required")
    return secret.encode("utf-8")


def _hmac_sign(data: bytes) -> str:
    """Classical HMAC-SHA256 signature."""
    return hmac.new(_signing_secret(), data, hashlib.sha256).hexdigest()


def _pq_sign_stub(data: bytes, private_key: str) -> str:
    """Stub PQ signature (CRYSTALS-Dilithium).

    In production, this would use a real PQC library (e.g., liboqs).
    For now, simulates PQ signing with HMAC using the PQ private key.
    """
    combined = private_key.encode("utf-8") + data
    return hashlib.sha3_256(combined).hexdigest()


def _pq_verify_stub(data: bytes, signature: str, public_key: str) -> bool:
    """Stub PQ verification."""
    # In production, verify with real PQ algorithm
    # Stub uses the same derivation path for deterministic verification
    private_key = public_key.replace("pub-", "priv-")
    expected = _pq_sign_stub(data, private_key)
    return hmac.compare_digest(expected, signature)


def generate_keypair(
    *,
    agent_id: str,
    algorithm: str = ALG_HYBRID_HMAC_DILITHIUM,
) -> dict[str, Any]:
    """Generate a hybrid classical+PQ key pair for an agent."""
    if algorithm not in VALID_PQC_ALGORITHMS:
        raise ValueError(f"invalid algorithm: {algorithm}, valid: {sorted(VALID_PQC_ALGORITHMS)}")

    now = time.time()
    key_id = f"pqc-{uuid.uuid4().hex[:12]}"

    # Generate classical component
    classical_key_material = hashlib.sha256(f"{agent_id}|{key_id}|classical".encode()).hexdigest()

    # Generate PQ component (stub)
    pq_private = f"priv-{hashlib.sha3_256(f'{agent_id}|{key_id}|pq'.encode()).hexdigest()[:32]}"
    pq_public = f"pub-{hashlib.sha3_256(f'{agent_id}|{key_id}|pq'.encode()).hexdigest()[:32]}"

    keypair: dict[str, Any] = {
        "key_id": key_id,
        "agent_id": agent_id,
        "algorithm": algorithm,
        "classical": {
            "algorithm": ALG_CLASSICAL_HMAC,
            "key_fingerprint": classical_key_material[:16],
        },
        "post_quantum": {
            "algorithm": ALG_DILITHIUM3,
            "public_key": pq_public,
            "key_size_bits": 2592,  # Dilithium3 public key size
        },
        "created_at": now,
        "status": "active",
    }

    # Store with private components (not exposed in API response)
    _pqc_keypairs[agent_id] = {
        **keypair,
        "_pq_private": pq_private,
        "_classical_material": classical_key_material,
    }

    _log.info("PQC keypair generated: agent=%s algorithm=%s", agent_id, algorithm)
    return keypair


def sign_data(
    *,
    agent_id: str,
    data: dict[str, Any],
) -> dict[str, Any]:
    """Sign data with hybrid classical+PQ signature."""
    keypair = _pqc_keypairs.get(agent_id)
    if keypair is None:
        raise KeyError(f"no PQC keypair for agent: {agent_id}")

    canonical = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")

    # Classical signature
    classical_sig = _hmac_sign(canonical)

    # PQ signature
    pq_sig = _pq_sign_stub(canonical, keypair["_pq_private"])

    now = time.time()
    sig_record: dict[str, Any] = {
        "signature_id": f"sig-{uuid.uuid4().hex[:12]}",
        "agent_id": agent_id,
        "algorithm": keypair["algorithm"],
        "classical_signature": classical_sig,
        "pq_signature": pq_sig,
        "data_hash": hashlib.sha256(canonical).hexdigest(),
        "signed_at": now,
    }

    _pqc_signatures.append(sig_record)
    if len(_pqc_signatures) > _MAX_SIGNATURES:
        _pqc_signatures[:] = _pqc_signatures[-_MAX_SIGNATURES:]
    return sig_record


def verify_signature(
    *,
    agent_id: str,
    data: dict[str, Any],
    classical_signature: str,
    pq_signature: str,
) -> dict[str, Any]:
    """Verify a hybrid signature (both classical and PQ must be valid)."""
    keypair = _pqc_keypairs.get(agent_id)
    if keypair is None:
        raise KeyError(f"no PQC keypair for agent: {agent_id}")

    canonical = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")

    # Verify classical
    expected_classical = _hmac_sign(canonical)
    classical_valid = hmac.compare_digest(expected_classical, classical_signature)

    # Verify PQ
    pq_public = keypair["post_quantum"]["public_key"]
    pq_valid = _pq_verify_stub(canonical, pq_signature, pq_public)

    # Both must be valid for hybrid scheme
    valid = classical_valid and pq_valid

    return {
        "valid": valid,
        "classical_valid": classical_valid,
        "pq_valid": pq_valid,
        "algorithm": keypair["algorithm"],
        "agent_id": agent_id,
    }


def get_keypair_info(agent_id: str) -> dict[str, Any]:
    """Get public key info for an agent (no private keys)."""
    keypair = _pqc_keypairs.get(agent_id)
    if keypair is None:
        raise KeyError(f"no PQC keypair for agent: {agent_id}")

    return {
        "key_id": keypair["key_id"],
        "agent_id": keypair["agent_id"],
        "algorithm": keypair["algorithm"],
        "classical": keypair["classical"],
        "post_quantum": keypair["post_quantum"],
        "created_at": keypair["created_at"],
        "status": keypair["status"],
    }


def list_keypairs() -> list[dict[str, Any]]:
    """List all PQC keypairs (public info only)."""
    return [
        {
            "key_id": kp["key_id"],
            "agent_id": kp["agent_id"],
            "algorithm": kp["algorithm"],
            "status": kp["status"],
            "created_at": kp["created_at"],
        }
        for kp in _pqc_keypairs.values()
    ]


def reset_for_tests() -> None:
    """Clear all PQC data."""
    _pqc_keypairs.clear()
    _pqc_signatures.clear()

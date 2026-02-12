# Provenance Signing Pipeline (S40)

## Scope
S40 introduces manifest/artifact provenance signing and verification with tamper detection.

## Cryptographic Model
- Canonicalization: stable JSON with sorted keys and compact separators.
- Digest: SHA-256 hash of canonical payload.
- Signature: HMAC-SHA256 over canonical envelope payload.
- Secret source: `AGENTHUB_PROVENANCE_SIGNING_SECRET`.

## Envelope Versions
- `version`: `provenance-v1`
- `signature_algorithm`: `hmac-sha256`

## Manifest Endpoints
- `POST /v1/provenance/manifests/sign`
- `POST /v1/provenance/manifests/verify`

`sign` returns:
- `manifest_hash`
- signed envelope (`subject_hash`, `artifact_hashes`, `signer`, `issued_at`, `signature`)

`verify` returns:
- `verification.valid`
- reason + observed/declared hashes

## Artifact Endpoints
- `POST /v1/provenance/artifacts/sign`
- `POST /v1/provenance/artifacts/verify`

`sign` returns:
- `artifact_hash`
- signed envelope (`artifact_id`, `artifact_hash`, `signer`, `issued_at`, `signature`)

`verify` returns:
- `verification.valid`
- reason + observed/declared hashes

## Security Boundaries
- Signing requires authenticated owner; `signer` must equal authenticated principal.
- Verification endpoints are authenticated and deterministic.
- Tampering either payload hash or envelope signature invalidates verification.

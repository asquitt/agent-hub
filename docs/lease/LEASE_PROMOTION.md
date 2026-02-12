# D14 Lease-First Capability Acquisition

## Scope Implemented (S13)
- `POST /v1/capabilities/lease`: acquire temporary capability access with TTL.
- `GET /v1/capabilities/leases/{lease_id}`: inspect lease status (active/expired/promoted).
- `POST /v1/capabilities/leases/{lease_id}/promote`: promote lease to install when policy and attestation checks pass.

## Controls Enforced
- Lease ownership boundary: only creating owner can read/promote the lease.
- TTL expiry: expired leases cannot be promoted.
- Explicit policy gate: `policy_approved=true` required for promotion.
- Attestation check:
  - hash must match lease attestation hash.
  - signature must match deterministic local format: `sig:{attestation_hash}:{owner}`.

## Promotion Output
- `status=promoted`
- `promotion.installed_ref` to indicate installed capability mapping
- `promotion.attestation_hash` captured for auditability

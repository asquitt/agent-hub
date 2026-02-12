# Federation Enterprise Pack (S46)

## Scope
S46 adds enterprise federation controls for:
- data residency policy enforcement,
- private-connect boundary enforcement for designated domains,
- attestation export for compliance review.

## Domain Enterprise Profiles
`GET /v1/federation/domains`

Federated domains now expose profile metadata:
- `residency_region`
- `private_connect_required`
- `network_pattern`

These profiles drive runtime boundary checks and compliance reporting.

## Execution Boundary Controls
`POST /v1/federation/execute`

Extended request fields:
- `requested_residency_region` (optional)
- `connection_mode` (`private_connect` or `public_internet`)

Runtime controls:
1. Domain authentication must pass.
2. If residency is requested, it must match the domain enterprise profile.
3. If domain requires private connectivity, execution is denied unless `connection_mode=private_connect`.
4. Existing policy, secret, and budget checks remain enforced.

Attestation and audit records now include residency and connectivity fields.

## Compliance Export
`GET /v1/federation/attestations/export`

Admin-only export endpoint returns:
- signed-style deterministic `bundle_hash`,
- export manifest (record count, regions, private-connect record count),
- normalized attestation/audit records for compliance evidence workflows.

## Verification Themes
- Federation boundary tests:
  - private-connect required domain rejects public path.
  - residency mismatch is denied.
- Compliance tests:
  - export endpoint is admin-scoped.
  - export bundle includes deterministic hash and residency/connectivity metadata.

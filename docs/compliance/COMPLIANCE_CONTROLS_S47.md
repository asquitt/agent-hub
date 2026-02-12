# Compliance Controls (S47)

## Scope
S47 adds an automated compliance evidence layer for SOC2 and ISO27001 controls.

## New API Endpoints
- `GET /v1/compliance/controls`
- `POST /v1/compliance/evidence/export`
- `GET /v1/compliance/evidence`

## Automated Control Checks
Evidence export currently validates:
1. Billing ledger chain + double-entry integrity.
2. Metering event schema integrity.
3. Federation audit completeness.
4. Procurement audit completeness.
5. Provenance signature verification and tamper detection.

## Framework Mapping
Control catalog maps checks to:
- SOC2 controls (CC6/CC7/CC8 coverage),
- ISO27001 controls (A.5/A.8 coverage).

Each control result includes:
- status (`pass`/`fail`),
- check key,
- checked timestamp,
- structured evidence payload.

## Access Boundaries
- Control catalog: authenticated access.
- Evidence export/list: admin-only (`owner-dev`, `owner-platform`).

## Persistence
Generated evidence reports are persisted to:
- `AGENTHUB_COMPLIANCE_EVIDENCE_PATH`
- default: `data/compliance/evidence_reports.json`

## Validation Goals
- Deterministic evidence bundle generation per framework.
- Explicit failure visibility when evidence controls are malformed or missing required fields.

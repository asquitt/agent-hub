# Procurement Controls (S45)

## Scope
S45 introduces enterprise procurement controls that bind marketplace purchases to:
- budget policy packs,
- manual approval workflow,
- explicit exception workflow,
- auditable procurement decision traces.

## Procurement Policy Pack
`POST /v1/procurement/policy-packs`

Policy packs are configured per buyer and define:
- `auto_approve_limit_usd`: purchases at or below this amount auto-allow.
- `hard_stop_limit_usd`: purchases above this amount are denied unless exception extends the limit.
- `allowed_sellers`: optional allowlist of seller owners.

Only admin actors (`owner-dev`, `owner-platform`) can create/update packs.

## Approval Workflow
- `POST /v1/procurement/approvals`: create pending approval request for a buyer purchase request.
- `POST /v1/procurement/approvals/{approval_id}/decision`: approve/reject approval request.

Approval decisions are admin-only and can provide `approved_max_total_usd`.

## Exception Workflow
`POST /v1/procurement/exceptions`

Admin-only exceptions can temporarily:
- raise hard-stop ceilings (`override_hard_stop_limit_usd`),
- allow an otherwise disallowed seller (`allow_seller_id`).

Exceptions can include optional expiry (`expires_at`).

## Marketplace Enforcement
`POST /v1/marketplace/purchase` now accepts:
- `procurement_approval_id` (optional)
- `procurement_exception_id` (optional)

Purchase evaluation order:
1. Validate seller boundary against pack allowlist (or exception seller override).
2. Enforce hard-stop budget (or exception hard-stop override).
3. Require approved procurement approval when spend exceeds auto-approve limit.
4. Persist `procurement_decision` with reason codes into contract records.

## Audit and Visibility
- `GET /v1/procurement/audit`
- `GET /v1/procurement/policy-packs`
- `GET /v1/procurement/approvals`
- `GET /v1/procurement/exceptions`

All procurement policy/approval/exception/purchase-evaluation actions are recorded in an immutable-style audit stream for operator review.

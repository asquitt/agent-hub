# Marketplace Finance v2 (S44)

## Scope
S44 extends marketplace alpha with:
- dispute lifecycle,
- payout workflow,
- settlement-to-payout integrity rules.

## New API Endpoints
- `POST /v1/marketplace/contracts/{contract_id}/disputes`
- `GET /v1/marketplace/contracts/{contract_id}/disputes`
- `POST /v1/marketplace/disputes/{dispute_id}/resolve`
- `POST /v1/marketplace/contracts/{contract_id}/payout`
- `GET /v1/marketplace/contracts/{contract_id}/payouts`

## Dispute Rules
- Buyers/sellers can file disputes.
- Only `owner-platform` can resolve disputes.
- Resolutions:
  - `rejected`
  - `approved_partial`
  - `approved_full`
- Open disputes block payout execution.

## Payout Rules
- Contract must be fully settled before payout.
- Payout is blocked if any dispute is open.
- Net payout is computed as:
  - `gross_amount_settled - approved_dispute_adjustments`.
- Payout execution is limited to platform/admin actors.

## Integrity Properties
- Dispute adjustments are bounded by settled contract amount.
- Payout records include gross, adjustment, and net values for auditability.
- Duplicate payout requests for the same contract return the existing payout record.

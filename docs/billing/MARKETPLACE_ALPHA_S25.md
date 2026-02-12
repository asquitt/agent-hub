# Marketplace Alpha (S25)

## API Surface
- `POST /v1/marketplace/listings`
- `GET /v1/marketplace/listings`
- `POST /v1/marketplace/purchase`
- `GET /v1/marketplace/contracts/{contract_id}`
- `POST /v1/marketplace/contracts/{contract_id}/settle`

## Policy-Scoped Procurement Rules
- Purchase requires `policy_approved=true`.
- Purchase blocked when:
  - requested units exceed listing max units per purchase
  - estimated total exceeds listing `policy_purchase_limit_usd`
  - estimated total exceeds buyer `max_total_usd`

## Settlement Integrity
- Settlement cannot exceed purchased units.
- Only buyer, seller, or platform admin can settle.
- Contract status transitions to `settled` only when all purchased units are settled.

## Fraud/Abuse Smoke Defenses
- Invalid units and settlement overruns are rejected.
- Contract/listing lookup is strict and deterministic.

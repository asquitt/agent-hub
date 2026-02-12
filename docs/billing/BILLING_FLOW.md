# D16 Billing + Settlement Activation

## Scope Implemented (S15)
- `POST /v1/billing/subscriptions`
- `POST /v1/billing/usage`
- `POST /v1/billing/invoices/generate`
- `GET /v1/billing/invoices/{invoice_id}`
- `POST /v1/billing/invoices/{invoice_id}/reconcile`
- `POST /v1/billing/invoices/{invoice_id}/refund`

## Capabilities
- Subscription + metered usage event recording.
- Invoice generation with line items and due/refund tracking.
- Reconciliation check for subtotal correctness (`matched` + `delta_usd`).
- Admin-only refund path (`owner-platform`).

## Verification Focus
- Metering accuracy (usage * unit price + subscription fee).
- Invoice reconciliation correctness.
- Refund permission boundary and over-refund protection.

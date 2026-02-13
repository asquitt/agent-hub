const { test, expect } = require("@playwright/test");
const { api, expectStatus, uniqueId } = require("./support/agenthub");

test.describe("S56 Commercial Flow E2E", () => {
  test("full marketplace + procurement + billing lifecycle", async ({ request }) => {
    const accountId = `acct-${uniqueId("full").slice(0, 24)}`;

    const listingResult = await api(request, "POST", "/v1/marketplace/listings", {
      apiKey: "dev-owner-key",
      data: {
        capability_ref: "@seed:data-normalizer/normalize-records",
        unit_price_usd: 0.75,
        max_units_per_purchase: 10,
        policy_purchase_limit_usd: 10.0,
      },
    });
    const listing = await expectStatus(listingResult, 200, "create listing");

    const packResult = await api(request, "POST", "/v1/procurement/policy-packs", {
      apiKey: "platform-owner-key",
      data: {
        buyer: "owner-partner",
        auto_approve_limit_usd: 1.0,
        hard_stop_limit_usd: 5.0,
        allowed_sellers: ["owner-dev"],
      },
    });
    const pack = await expectStatus(packResult, 200, "upsert policy pack");
    expect(pack.buyer).toBe("owner-partner");

    const approvalResult = await api(request, "POST", "/v1/procurement/approvals", {
      apiKey: "partner-owner-key",
      data: {
        buyer: "owner-partner",
        listing_id: listing.listing_id,
        units: 4,
        estimated_total_usd: 3.0,
        note: "S56 full-flow approval",
      },
    });
    const approval = await expectStatus(approvalResult, 200, "request approval");

    const decisionResult = await api(request, "POST", `/v1/procurement/approvals/${approval.approval_id}/decision`, {
      apiKey: "platform-owner-key",
      data: {
        decision: "approve",
        approved_max_total_usd: 3.2,
        note: "Approved for S56 full-flow",
      },
    });
    const decision = await expectStatus(decisionResult, 200, "approval decision");
    expect(decision.status).toBe("approved");

    const purchaseResult = await api(request, "POST", "/v1/marketplace/purchase", {
      apiKey: "partner-owner-key",
      data: {
        listing_id: listing.listing_id,
        units: 4,
        max_total_usd: 10.0,
        policy_approved: true,
        procurement_approval_id: approval.approval_id,
      },
    });
    const purchase = await expectStatus(purchaseResult, 200, "purchase listing");

    const settleResult = await api(request, "POST", `/v1/marketplace/contracts/${purchase.contract_id}/settle`, {
      apiKey: "partner-owner-key",
      data: { units_used: 4 },
    });
    const settled = await expectStatus(settleResult, 200, "settle contract");
    expect(settled.status).toBe("settled");
    expect(settled.amount_settled_usd).toBe(3.0);

    const disputeResult = await api(request, "POST", `/v1/marketplace/contracts/${purchase.contract_id}/disputes`, {
      apiKey: "partner-owner-key",
      data: {
        reason: "quality issue",
        requested_amount_usd: 0.6,
      },
    });
    const dispute = await expectStatus(disputeResult, 200, "create dispute");

    const resolveResult = await api(request, "POST", `/v1/marketplace/disputes/${dispute.dispute_id}/resolve`, {
      apiKey: "platform-owner-key",
      data: {
        resolution: "approved_partial",
        approved_amount_usd: 0.2,
      },
    });
    const resolved = await expectStatus(resolveResult, 200, "resolve dispute");
    expect(resolved.status).toBe("resolved_approved_partial");

    const payoutResult = await api(request, "POST", `/v1/marketplace/contracts/${purchase.contract_id}/payout`, {
      apiKey: "platform-owner-key",
    });
    const payout = await expectStatus(payoutResult, 200, "create payout");
    expect(payout.gross_amount_usd).toBe(3.0);
    expect(payout.dispute_adjustment_usd).toBe(0.2);
    expect(payout.net_payout_usd).toBe(2.8);

    const subscriptionResult = await api(request, "POST", "/v1/billing/subscriptions", {
      apiKey: "dev-owner-key",
      data: {
        account_id: accountId,
        plan_id: "s56-pro",
        monthly_fee_usd: 20.0,
        included_units: 100,
      },
    });
    await expectStatus(subscriptionResult, 200, "create subscription");

    const usageAResult = await api(request, "POST", "/v1/billing/usage", {
      apiKey: "dev-owner-key",
      data: {
        account_id: accountId,
        meter: "delegation_calls",
        quantity: 5,
        unit_price_usd: 0.4,
      },
    });
    await expectStatus(usageAResult, 200, "record usage A");

    const usageBResult = await api(request, "POST", "/v1/billing/usage", {
      apiKey: "dev-owner-key",
      data: {
        account_id: accountId,
        meter: "eval_runs",
        quantity: 2,
        unit_price_usd: 0.5,
      },
    });
    await expectStatus(usageBResult, 200, "record usage B");

    const invoiceResult = await api(request, "POST", "/v1/billing/invoices/generate", {
      apiKey: "dev-owner-key",
      data: { account_id: accountId },
    });
    const invoice = await expectStatus(invoiceResult, 200, "generate invoice");
    expect(invoice.subtotal_usd).toBe(23.0);

    const reconcileResult = await api(request, "POST", `/v1/billing/invoices/${invoice.invoice_id}/reconcile`, {
      apiKey: "dev-owner-key",
    });
    const reconciled = await expectStatus(reconcileResult, 200, "reconcile invoice");
    expect(reconciled.matched).toBe(true);
    expect(reconciled.double_entry_balanced).toBe(true);

    const refundResult = await api(request, "POST", `/v1/billing/invoices/${invoice.invoice_id}/refund`, {
      apiKey: "platform-owner-key",
      data: {
        amount_usd: 1.5,
        reason: "S56 quality credit",
      },
    });
    const refunded = await expectStatus(refundResult, 200, "refund invoice");
    expect(refunded.due_usd).toBe(21.5);
  });

  test("hard stop requires exception path", async ({ request }) => {
    const listingResult = await api(request, "POST", "/v1/marketplace/listings", {
      apiKey: "dev-owner-key",
      data: {
        capability_ref: "@seed:data-normalizer/normalize-records",
        unit_price_usd: 1.0,
        max_units_per_purchase: 10,
        policy_purchase_limit_usd: 10.0,
      },
    });
    const listing = await expectStatus(listingResult, 200, "create listing hard-stop");

    await expectStatus(
      await api(request, "POST", "/v1/procurement/policy-packs", {
        apiKey: "platform-owner-key",
        data: {
          buyer: "owner-partner",
          auto_approve_limit_usd: 1.0,
          hard_stop_limit_usd: 2.0,
          allowed_sellers: ["owner-dev"],
        },
      }),
      200,
      "configure hard-stop policy"
    );

    const approval = await expectStatus(
      await api(request, "POST", "/v1/procurement/approvals", {
        apiKey: "partner-owner-key",
        data: {
          buyer: "owner-partner",
          listing_id: listing.listing_id,
          units: 3,
          estimated_total_usd: 3.0,
        },
      }),
      200,
      "request approval hard-stop"
    );

    await expectStatus(
      await api(request, "POST", `/v1/procurement/approvals/${approval.approval_id}/decision`, {
        apiKey: "platform-owner-key",
        data: {
          decision: "approve",
          approved_max_total_usd: 4.0,
        },
      }),
      200,
      "approve above hard-stop request"
    );

    const denied = await api(request, "POST", "/v1/marketplace/purchase", {
      apiKey: "partner-owner-key",
      data: {
        listing_id: listing.listing_id,
        units: 3,
        max_total_usd: 10.0,
        policy_approved: true,
        procurement_approval_id: approval.approval_id,
      },
    });
    expect(denied.status, JSON.stringify(denied.payload)).toBe(403);
    expect(String(denied.payload.detail)).toContain("hard stop");

    const createdException = await expectStatus(
      await api(request, "POST", "/v1/procurement/exceptions", {
        apiKey: "platform-owner-key",
        data: {
          buyer: "owner-partner",
          reason: "temporary extension",
          override_hard_stop_limit_usd: 3.5,
        },
      }),
      200,
      "create procurement exception"
    );

    const allowed = await expectStatus(
      await api(request, "POST", "/v1/marketplace/purchase", {
        apiKey: "partner-owner-key",
        data: {
          listing_id: listing.listing_id,
          units: 3,
          max_total_usd: 10.0,
          policy_approved: true,
          procurement_approval_id: approval.approval_id,
          procurement_exception_id: createdException.exception_id,
        },
      }),
      200,
      "purchase with exception"
    );
    expect(allowed.procurement_decision.exception_id).toBe(createdException.exception_id);
  });

  test("idempotency replay returns original purchase response", async ({ request }) => {
    const listing = await expectStatus(
      await api(request, "POST", "/v1/marketplace/listings", {
        apiKey: "dev-owner-key",
        data: {
          capability_ref: "@seed:data-normalizer/normalize-records",
          unit_price_usd: 0.4,
          max_units_per_purchase: 10,
          policy_purchase_limit_usd: 5.0,
        },
      }),
      200,
      "create listing for idempotency"
    );

    await expectStatus(
      await api(request, "POST", "/v1/procurement/policy-packs", {
        apiKey: "platform-owner-key",
        data: {
          buyer: "owner-partner",
          auto_approve_limit_usd: 5.0,
          hard_stop_limit_usd: 10.0,
          allowed_sellers: ["owner-dev"],
        },
      }),
      200,
      "configure auto-approve policy"
    );

    const replayKey = uniqueId("purchase-replay");
    const purchasePayload = {
      listing_id: listing.listing_id,
      units: 2,
      max_total_usd: 2.0,
      policy_approved: true,
    };

    const first = await api(request, "POST", "/v1/marketplace/purchase", {
      apiKey: "partner-owner-key",
      headers: { "Idempotency-Key": replayKey },
      data: purchasePayload,
    });
    const firstPayload = await expectStatus(first, 200, "first purchase request");

    const replayed = await api(request, "POST", "/v1/marketplace/purchase", {
      apiKey: "partner-owner-key",
      headers: { "Idempotency-Key": replayKey },
      data: purchasePayload,
    });
    const replayedPayload = await expectStatus(replayed, 200, "replayed purchase request");
    expect(replayedPayload.contract_id).toBe(firstPayload.contract_id);
    expect(replayed.headers["x-agenthub-idempotent-replay"]).toBe("true");

    const mismatch = await api(request, "POST", "/v1/marketplace/purchase", {
      apiKey: "partner-owner-key",
      headers: { "Idempotency-Key": replayKey },
      data: {
        ...purchasePayload,
        units: 3,
      },
    });
    expect(mismatch.status, JSON.stringify(mismatch.payload)).toBe(409);
    expect(mismatch.payload.detail.code).toBe("idempotency.key_reused_with_different_payload");
  });
});

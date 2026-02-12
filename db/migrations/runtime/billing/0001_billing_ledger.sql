CREATE TABLE IF NOT EXISTS billing_subscriptions (
  account_id TEXT PRIMARY KEY,
  plan_id TEXT NOT NULL,
  owner TEXT NOT NULL,
  monthly_fee_usd REAL NOT NULL,
  included_units INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS billing_usage_events (
  event_id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  owner TEXT NOT NULL,
  meter TEXT NOT NULL,
  quantity REAL NOT NULL,
  unit_price_usd REAL NOT NULL,
  cost_usd REAL NOT NULL,
  timestamp TEXT NOT NULL,
  timestamp_epoch INTEGER NOT NULL,
  invoice_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_billing_usage_account_invoiced
  ON billing_usage_events(account_id, invoice_id, timestamp_epoch);

CREATE TABLE IF NOT EXISTS billing_invoices (
  invoice_id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  owner TEXT NOT NULL,
  created_at TEXT NOT NULL,
  payload_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS billing_ledger_entries (
  sequence_id INTEGER PRIMARY KEY AUTOINCREMENT,
  entry_id TEXT NOT NULL UNIQUE,
  tx_id TEXT NOT NULL,
  entry_order INTEGER NOT NULL,
  account_id TEXT NOT NULL,
  source_type TEXT NOT NULL,
  source_id TEXT NOT NULL,
  ledger_account TEXT NOT NULL,
  debit_usd REAL NOT NULL DEFAULT 0,
  credit_usd REAL NOT NULL DEFAULT 0,
  currency TEXT NOT NULL DEFAULT 'USD',
  metadata_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  entry_hash TEXT NOT NULL,
  CHECK (debit_usd >= 0.0),
  CHECK (credit_usd >= 0.0),
  CHECK ((debit_usd = 0.0) <> (credit_usd = 0.0))
);

CREATE INDEX IF NOT EXISTS idx_billing_ledger_tx
  ON billing_ledger_entries(tx_id, entry_order);

CREATE INDEX IF NOT EXISTS idx_billing_ledger_source
  ON billing_ledger_entries(source_type, source_id, sequence_id);

CREATE INDEX IF NOT EXISTS idx_billing_ledger_account
  ON billing_ledger_entries(account_id, ledger_account, sequence_id);

CREATE TRIGGER IF NOT EXISTS trg_billing_ledger_entries_no_update
BEFORE UPDATE ON billing_ledger_entries
BEGIN
  SELECT RAISE(ABORT, 'billing_ledger_entries are immutable');
END;

CREATE TRIGGER IF NOT EXISTS trg_billing_ledger_entries_no_delete
BEFORE DELETE ON billing_ledger_entries
BEGIN
  SELECT RAISE(ABORT, 'billing_ledger_entries are immutable');
END;

CREATE TRIGGER IF NOT EXISTS trg_billing_ledger_no_update
BEFORE UPDATE ON billing_ledger_entries
BEGIN
  SELECT RAISE(ABORT, 'immutable ledger: updates are not allowed');
END;

CREATE TRIGGER IF NOT EXISTS trg_billing_ledger_no_delete
BEFORE DELETE ON billing_ledger_entries
BEGIN
  SELECT RAISE(ABORT, 'immutable ledger: deletes are not allowed');
END;

CREATE TABLE IF NOT EXISTS billing_metering_events (
  event_id TEXT PRIMARY KEY,
  timestamp TEXT NOT NULL,
  actor TEXT NOT NULL,
  operation TEXT NOT NULL,
  cost_usd REAL NOT NULL,
  metadata_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_billing_metering_timestamp
  ON billing_metering_events(timestamp);

CREATE TABLE IF NOT EXISTS devhub_release_reviews (
  review_id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL,
  version TEXT NOT NULL,
  requested_by TEXT NOT NULL,
  status TEXT NOT NULL,
  approvals_required INTEGER NOT NULL,
  approvals_count INTEGER NOT NULL DEFAULT 0,
  rejections_count INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  payload_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS devhub_release_decisions (
  decision_id INTEGER PRIMARY KEY AUTOINCREMENT,
  review_id TEXT NOT NULL,
  actor TEXT NOT NULL,
  decision TEXT NOT NULL,
  note TEXT,
  created_at TEXT NOT NULL,
  UNIQUE(review_id, actor),
  FOREIGN KEY(review_id) REFERENCES devhub_release_reviews(review_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS devhub_promotions (
  promotion_id TEXT PRIMARY KEY,
  review_id TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  version TEXT NOT NULL,
  promoted_by TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  FOREIGN KEY(review_id) REFERENCES devhub_release_reviews(review_id) ON DELETE CASCADE
);

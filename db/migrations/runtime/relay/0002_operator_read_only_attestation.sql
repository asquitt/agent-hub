ALTER TABLE relay_targets
ADD COLUMN operator_attests_read_only INTEGER NOT NULL DEFAULT 0
CHECK (operator_attests_read_only IN (0, 1));

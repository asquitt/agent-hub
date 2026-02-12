PYTHON ?= python3

.PHONY: dev test lint migrate eval trust gate discovery-load cli-test operator-test versioning-test compose-up compose-down

dev:
	uvicorn src.api.main:app --reload --host 0.0.0.0 --port 8000

test:
	pytest -q

lint:
	$(PYTHON) -m py_compile agenthub/*.py src/api/*.py src/delegation/*.py src/discovery/*.py src/eval/*.py src/gate/*.py src/trust/*.py src/versioning/*.py tools/manifest/*.py tools/capability_search/*.py tools/eval/*.py tools/gate/*.py tools/trust/*.py

migrate:
	@echo "Apply migrations with your Postgres DSN"
	@echo "psql $$DATABASE_URL -f db/migrations/0001_initial_schema.sql"
	@echo "psql $$DATABASE_URL -f db/migrations/0002_retention_indexes.sql"

eval:
	$(PYTHON) tools/eval/agenthub_eval.py eval --manifest specs/manifest/examples/simple-tool-agent.yaml --agent-id @local:manifest-eval

trust:
	$(PYTHON) tools/trust/recompute_trust.py --agent-id @demo:invoice-summarizer --owner owner-dev

gate:
	$(PYTHON) tools/gate/review_gate.py --metrics data/gate/pilot_metrics.json --out docs/gate/S10_GATE_REVIEW.json

discovery-load:
	pytest tests/discovery/test_load_sla.py -q

cli-test:
	pytest tests/cli/test_agenthub_cli.py -q

operator-test:
	pytest tests/operator/test_operator_ui.py -q

versioning-test:
	pytest tests/versioning/test_behavioral_diff.py -q

compose-up:
	docker compose up --build -d

compose-down:
	docker compose down

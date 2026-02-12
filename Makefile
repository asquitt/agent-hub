PYTHON ?= python3

.PHONY: dev test lint migrate eval compose-up compose-down

dev:
	uvicorn src.api.main:app --reload --host 0.0.0.0 --port 8000

test:
	pytest -q

lint:
	$(PYTHON) -m py_compile src/api/*.py tools/manifest/*.py tools/capability_search/*.py

migrate:
	@echo "Apply migrations with your Postgres DSN"
	@echo "psql $$DATABASE_URL -f db/migrations/0001_initial_schema.sql"
	@echo "psql $$DATABASE_URL -f db/migrations/0002_retention_indexes.sql"

eval:
	$(PYTHON) tools/eval/agenthub_eval.py eval --manifest specs/manifest/examples/simple-tool-agent.yaml --agent-id @local:manifest-eval

compose-up:
	docker compose up --build -d

compose-down:
	docker compose down

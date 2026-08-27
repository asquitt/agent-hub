PYTHON ?= python3

.PHONY: install-runtime install-dev dev test lint package-build packaging-test deployment-test migrate eval trust gate launch-check discovery-load cli-test operator-test versioning-test lease-test knowledge-test billing-test launch-test e2e-install e2e-test compose-up compose-down

install-runtime:
	$(PYTHON) -m pip install -r requirements-runtime.txt

install-dev:
	$(PYTHON) -m pip install -r requirements.txt

dev:
	uvicorn src.api.main:app --reload --host 0.0.0.0 --port 8000

test:
	$(PYTHON) -m pytest -q

lint:
	$(PYTHON) -m py_compile agenthub/*.py src/api/*.py src/billing/*.py src/delegation/*.py src/discovery/*.py src/eval/*.py src/gate/*.py src/knowledge/*.py src/launch/*.py src/lease/*.py src/trust/*.py src/versioning/*.py tools/manifest/*.py tools/capability_search/*.py tools/eval/*.py tools/gate/*.py tools/launch/*.py tools/trust/*.py

package-build:
	$(PYTHON) -m pip wheel --no-deps --wheel-dir dist .

packaging-test:
	$(PYTHON) -m pytest tests/packaging/test_p0_wheel_packaging.py -q

deployment-test:
	$(PYTHON) -m pytest tests/deployment/test_p0_sqlite_deployment_containment.py -q

migrate:
	@echo "SQLite scope migrations run during application startup."
	@echo "Postgres migrations are not active until the application has a Postgres persistence adapter."

eval:
	$(PYTHON) tools/eval/agenthub_eval.py eval --manifest specs/manifest/examples/simple-tool-agent.yaml --agent-id @local:manifest-eval

trust:
	$(PYTHON) tools/trust/recompute_trust.py --agent-id @demo:invoice-summarizer --owner owner-dev

gate:
	$(PYTHON) tools/gate/review_gate.py --metrics data/gate/pilot_metrics.json --out docs/gate/S10_GATE_REVIEW.json

launch-check:
	$(PYTHON) tools/launch/check_launch_readiness.py --metrics data/launch/onboarding_metrics.json --manifest specs/manifest/examples/simple-tool-agent.yaml --out docs/launch/S16_READINESS.json

discovery-load:
	pytest tests/discovery/test_load_sla.py -q

cli-test:
	pytest tests/cli/test_agenthub_cli.py -q

operator-test:
	pytest tests/operator/test_operator_ui.py -q

versioning-test:
	pytest tests/versioning/test_behavioral_diff.py -q

lease-test:
	pytest tests/lease/test_lease_api.py -q

knowledge-test:
	pytest tests/knowledge/test_knowledge_api.py -q

billing-test:
	pytest tests/billing/test_billing_api.py -q

launch-test:
	pytest tests/launch/test_launch_readiness.py -q

e2e-install:
	npm install
	npx playwright install chromium

e2e-test:
	npm run e2e

compose-up:
	docker compose up --build -d

compose-down:
	docker compose down

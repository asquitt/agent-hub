# AgentHub

AgentHub is a reliability-first interoperability and runtime infrastructure layer for autonomous agents.

## What We Are Building
AgentHub is designed as two connected layers:

- Layer 1: Agent DevHub (human-facing)
  - Registry, versioning, trust/evals, and developer collaboration workflows.
- Layer 2: Agent Runtime Infrastructure (agent-native)
  - Programmatic capability discovery, delegation, and controlled capability acquisition.

Core strategy: prioritize reliability, policy control, and unit economics before full marketplace expansion.

## Build Strategy
Delivery is segmented (S01-S16) with strict completion rules per segment:

1. Implement in-scope artifacts.
2. Run required tests.
3. Record verification evidence.
4. Update segment tracker.
5. Update master plan progress notes.

No segment is considered complete without passing tests and evidence.

## Scope and Gates
Build-first scope (V1): D01, D02, D03, D04, D05, D09, D11, D12, D13, D08 (minimum), D17 (minimum)

Deferred until gate criteria pass: D07 full, D06, D10, D14 full promotion path, D15, D16, D18

Gate criteria:
- Reliability target met in pilot workloads
- Positive design-partner ROI evidence
- Sustainable unit economics under real multi-agent load

## Current Progress
- S01 / D01 completed
  - Canonical manifest schema (`specs/manifest/agent-manifest-spec-v0.1.yaml`)
  - A2A and MCP mapping docs (`docs/spec/`)
  - Manifest validator (`tools/manifest/validate_manifest.py`)
  - Passing tests (`pytest tests/manifest -q`)
  - Evidence recorded (`docs/evidence/S01.md`)
- Segment status tracker: `docs/DELIVERABLE_LOG.md`

## Repository Layout
- `docs/session-packets/`: execution packets for S01-S16
- `docs/evidence/`: evidence per segment
- `docs/spec/`: human-readable specs and mapping docs
- `specs/manifest/`: canonical schema and example manifests
- `tools/manifest/`: validation tooling
- `tests/manifest/`: schema and CLI tests
- `docs/agenthub-master-plan-v1.2.docx`: master build plan

## Quick Start
```bash
cd /Users/demarioasquitt/Desktop/Projects/Entrepreneurial/agent-hub
python3 -m pip install -U pip
python3 -m pip install pyyaml jsonschema pytest

python3 tools/manifest/validate_manifest.py specs/manifest/examples/simple-tool-agent.yaml
python3 tools/manifest/validate_manifest.py specs/manifest/examples/multi-capability-agent.yaml
python3 tools/manifest/validate_manifest.py specs/manifest/examples/pipeline-agent.yaml

pytest tests/manifest -q
```

## Reference Docs
- Master plan: `docs/agenthub-master-plan-v1.2.docx`
- Deliverable map: `docs/DELIVERABLE_LOG.md`
- Research inputs: `docs/RESEARCH_INSIGHTS.md`

## License
Proprietary/Confidential unless explicitly stated otherwise.

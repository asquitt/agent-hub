# AgentHub

AgentHub is a reliability-first interoperability and runtime infrastructure layer for autonomous agents.

It is being delivered in strict, evidence-backed segments and tracked through repository docs.

## Project Status
- Active phased build (S01-S16)
- S01 (`D01`) completed with artifacts, tests, and evidence
- Remaining segments tracked in `/Users/demarioasquitt/Desktop/Projects/Entrepreneurial/agent-hub/docs/DELIVERABLE_LOG.md`

## Repository Structure
- `/Users/demarioasquitt/Desktop/Projects/Entrepreneurial/agent-hub/docs/session-packets/`: per-segment execution packets (S01-S16)
- `/Users/demarioasquitt/Desktop/Projects/Entrepreneurial/agent-hub/docs/evidence/`: verification evidence per segment
- `/Users/demarioasquitt/Desktop/Projects/Entrepreneurial/agent-hub/docs/spec/`: human-readable technical specs and mappings
- `/Users/demarioasquitt/Desktop/Projects/Entrepreneurial/agent-hub/specs/manifest/`: canonical manifest schema and examples
- `/Users/demarioasquitt/Desktop/Projects/Entrepreneurial/agent-hub/tools/manifest/`: validation tooling
- `/Users/demarioasquitt/Desktop/Projects/Entrepreneurial/agent-hub/tests/manifest/`: schema and CLI tests

## Quick Start
```bash
cd /Users/demarioasquitt/Desktop/Projects/Entrepreneurial/agent-hub
python3 -m pip install -U pip
python3 -m pip install pyyaml jsonschema pytest

# Validate manifests
python3 tools/manifest/validate_manifest.py specs/manifest/examples/simple-tool-agent.yaml
python3 tools/manifest/validate_manifest.py specs/manifest/examples/multi-capability-agent.yaml
python3 tools/manifest/validate_manifest.py specs/manifest/examples/pipeline-agent.yaml

# Run tests
pytest tests/manifest -q
```

## Segment Execution Contract
For each segment, complete all of the following before moving on:
1. Implement in-scope artifacts only
2. Run required tests
3. Record evidence in the matching `/docs/evidence/Sxx.md`
4. Update `/docs/DELIVERABLE_LOG.md`
5. Update `/docs/agenthub-master-plan-v1.2.docx`

## Governance
- Do not mark a segment complete without passing tests and recorded evidence.
- Use research-backed architecture decisions only.
- Treat all tool inputs/outputs as untrusted and enforce least privilege.

## Current Canonical Spec (S01)
- Schema: `/Users/demarioasquitt/Desktop/Projects/Entrepreneurial/agent-hub/specs/manifest/agent-manifest-spec-v0.1.yaml`
- Spec doc: `/Users/demarioasquitt/Desktop/Projects/Entrepreneurial/agent-hub/docs/spec/SPEC.md`
- A2A mapping: `/Users/demarioasquitt/Desktop/Projects/Entrepreneurial/agent-hub/docs/spec/a2a-mapping.md`
- MCP mapping: `/Users/demarioasquitt/Desktop/Projects/Entrepreneurial/agent-hub/docs/spec/mcp-mapping.md`
- Validator: `/Users/demarioasquitt/Desktop/Projects/Entrepreneurial/agent-hub/tools/manifest/validate_manifest.py`

## License
Proprietary/Confidential unless explicitly stated otherwise.

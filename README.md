# AgentHub

Identity, permissions, and signed audit receipts for AI agent tool calls.

`Python` `FastAPI` `SQLite` `MCP` `Ed25519`

> One of four projects on running AI agents safely: **AgentHub** · [AgentGuard](https://github.com/asquitt/agent-guard) · [AgentTrace](https://github.com/asquitt/agent-trace) · [SynthArena](https://github.com/asquitt/synth-arena)

## Overview

Getting an AI agent to call a tool is easy. The hard part is everything around the call: who is the agent, what is it allowed to do, was that permission revoked a second ago, and what happens if the call times out halfway through?

AgentHub is a FastAPI service that answers those questions. It gives each agent an identity, lets agents hand off limited authority to each other, checks policy before every call, and forwards approved calls to an MCP tool. Every call ends with a signed receipt.

## Features

- **Agent identity.** Each agent gets its own credentials, and those credentials can be revoked. See [`src/identity/`](src/identity/).
- **Scoped delegation.** An agent can pass part of its authority to another agent, but never more than it holds.
- **Policy-aware discovery.** Capability search drops tools the caller isn't allowed to use *before* ranking results. See [`src/discovery/`](src/discovery/).
- **Governed MCP relay.** Identity, scope, budget, and revocation are all checked right before dispatch. Every call needs an `Idempotency-Key`. See [`src/relay/service.py`](src/relay/service.py).
- **Crash-safe calls.** Idempotency and budget state are saved to disk. If a crash leaves a call's outcome unknown, AgentHub marks it as unknown instead of retrying it automatically. See [`src/relay/storage.py`](src/relay/storage.py).
- **Signed receipts.** Each call outcome gets an Ed25519-signed receipt that you can check offline with [`tools/relay/verify_receipt.py`](tools/relay/verify_receipt.py).

## How it works

```mermaid
flowchart LR
    A[Agent credential] --> B[Identity and scope checks]
    B --> C[Policy and budget checks]
    C --> D[Save idempotency record]
    D --> E[Final revocation check]
    E --> F[MCP tool]
    F --> G[Signed receipt]
```

A call only reaches the tool if every step passes. The revocation check runs again at the last moment, so a credential revoked mid-flight can't slip through. The relay never accepts a target URL from the caller, and it doesn't follow redirects or retry on its own.

## Quick start

Requires Python 3.11+.

```bash
git clone https://github.com/asquitt/agent-hub.git
cd agent-hub
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

The server won't start without these settings. The values below are placeholders for local use only:

```bash
export AGENTHUB_API_KEYS_JSON='{"local-dev-key": "owner-dev"}'
export AGENTHUB_FEDERATION_DOMAIN_TOKENS_JSON='{"local.test": "local-federation-token"}'
export AGENTHUB_AUTH_TOKEN_SECRET=local-auth-secret
export AGENTHUB_IDENTITY_SIGNING_SECRET=local-identity-secret
export AGENTHUB_POLICY_SIGNING_SECRET=local-policy-secret
export AGENTHUB_PROVENANCE_SIGNING_SECRET=local-provenance-secret
export AGENTHUB_VAULT_KEY=local-vault-key

uvicorn src.api.main:app --host 127.0.0.1 --port 8000
```

Then open the [API docs](http://127.0.0.1:8000/docs) or the [operator console](http://127.0.0.1:8000/operator), or make a request:

```bash
curl -H "X-API-Key: local-dev-key" http://127.0.0.1:8000/v1/agents
```

## Running tests

```bash
python -m pytest tests/relay/test_policy.py tests/relay/test_storage.py tests/relay/test_receipts.py -q
```

[`tests/relay/`](tests/relay/) also has integration tests that start separate local processes and cover crash recovery.

## Project structure

```text
src/identity/     credentials, delegation, revocation
src/discovery/    capability search
src/policy/       authorization rules
src/relay/        MCP relay, durable call state, signed receipts
src/api/          FastAPI app and routes
specs/            schemas and protocol contracts
tests/            unit, integration, and failure-recovery tests
tools/relay/      offline receipt verifier
```

## Status

- AgentHub is a local prototype, not a production service. It runs as a single process on SQLite. Postgres and Redis are not connected or included.
- The only remote execution path is one operator-attested, server-declared read-only/idempotent MCP tool with no upstream authentication. MCP annotations are untrusted hints, so the read-only guarantee comes from the operator's attestation, not from technical enforcement.
- Delegation, federation, and the Runtime State Simulator record lifecycle state only. They don't run remote workloads.

## Author

Built by [Demario Asquitt](https://github.com/asquitt). Bug reports with a small failing test are welcome, especially for revocation races and MCP compatibility.

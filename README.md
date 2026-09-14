# AgentHub

### Identity, scoped authority, and accountable tool calls for AI agents.

An agent finding a tool is easy. Deciding whether it may call that tool, whether its authority has been revoked, and what happened after a timeout is the harder systems problem.

AgentHub explores that boundary with a Python control plane: agent identities, policy-aware capability discovery, short-lived delegation, and a narrowly scoped MCP relay with signed execution receipts.

**Start with:** [relay implementation](src/relay/service.py) · [authorization policy](src/policy/mcp_relay.py) · [failure-path tests](tests/relay/) · [architecture](architecture.md)

## The interesting engineering

| Problem | Approach | Read the code |
| --- | --- | --- |
| Delegation must not create more authority | Scoped credentials and attenuated delegation chains | [Identity](src/identity/) |
| A previously valid credential may be revoked before dispatch | Recheck authority at the network boundary | [Relay service](src/relay/service.py) |
| A crash can leave the outcome of a remote call unknown | Persist idempotency and budget state; retain an indeterminate outcome without automatic replay | [Relay storage](src/relay/storage.py) |
| An execution record needs verifiable provenance | Ed25519-signed receipts and an offline verifier | [Receipts](src/relay/receipts.py) · [Verifier](tools/relay/verify_receipt.py) |
| Discovery must respect policy before ranking | Filter capabilities against the caller's constraints | [Discovery](src/discovery/) |

## One tool call, end to end

```mermaid
flowchart LR
    A[Agent credential] --> B[Identity and scope checks]
    B --> C[Policy and budget admission]
    C --> D[Durable idempotency record]
    D --> E[Final revocation check]
    E --> F[Configured MCP tool]
    F --> G[Signed outcome receipt]
```

The relay targets one operator-attested, server-declared read-only/idempotent tool without upstream authentication. It rejects caller-supplied target URLs and disables redirects and automatic retries. Read-only behavior depends on the operator's attestation of the upstream tool; MCP annotations alone cannot enforce it.

This is a local, single-process SQLite implementation. Other runtime, federation, and delegation surfaces include simulations; they should not be mistaken for remote workload execution. General-purpose remote execution and multi-replica coordination are outside this implementation's verified boundary.

## Explore locally

Requires **Python 3.11+**. Use an isolated development environment.

```bash
git clone https://github.com/asquitt/agent-hub.git
cd agent-hub
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pip install -e .
uvicorn src.api.main:app --host 127.0.0.1 --port 8000
```

Open [API documentation](http://127.0.0.1:8000/docs) or the [operator console](http://127.0.0.1:8000/operator). Local development credentials are defined in the source and are for loopback use only.

Run focused relay checks:

```bash
python -m pytest tests/relay/test_policy.py tests/relay/test_storage.py tests/relay/test_receipts.py -q
```

The [relay integration tests](tests/relay/test_official_process_integration.py) exercise separate local processes and crash recovery. Tests using local MCP fixtures establish behavior against those fixtures, not arbitrary provider compatibility.

## Repository map

- [`src/identity/`](src/identity/): credentials, delegation, revocation, and identity storage.
- [`src/discovery/`](src/discovery/) and [`src/policy/`](src/policy/): capability selection and admission rules.
- [`src/relay/`](src/relay/): transport boundary, durable call state, and receipts.
- [`specs/`](specs/): schemas and protocol contracts.
- [`tests/`](tests/): authorization, failure recovery, protocol, and packaging checks.

## Discuss or contribute

Especially interested in minimal reproductions for revocation races, ambiguous remote outcomes, capability attenuation, and MCP interoperability. Open an issue with the expected behavior, observed result, and a small test case.

Built by [Demario Asquitt](https://github.com/asquitt). [More projects](https://github.com/asquitt#selected-work).

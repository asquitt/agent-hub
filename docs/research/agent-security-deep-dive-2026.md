# Agent Security, Sandboxing, and Runtime Isolation: Deep Research Report

**Date:** 2026-02-14
**Scope:** Comprehensive technical research across 6 categories for AgentHub product strategy
**Sources:** 40+ articles, papers, and industry frameworks from 2024-2026

---

## Executive Summary

The agent security landscape has undergone a radical shift between 2024 and early 2026. Key developments include:

1. **OWASP released the Agentic AI Top 10 (2026)** -- the first canonical threat model for autonomous AI systems
2. **Google launched Agent Sandbox** as a CNCF/Kubernetes-native primitive (KubeCon NA 2025)
3. **Microsoft open-sourced FIDES** -- an information-flow control system that deterministically prevents indirect prompt injection
4. **Microsoft open-sourced LiteBox** (Feb 2026) -- a Rust-based Library OS for agent sandboxing with AMD SEV-SNP confidential computing support
5. **Okta introduced Cross App Access (XAA)** for agent delegation chains with OAuth 2.0 Token Exchange
6. **SPIFFE/SPIRE** emerged as the de facto standard for non-human identity (NHI) in agent systems
7. **CoSAI** (Coalition for Secure AI) released "Principles for Secure-by-Design Agentic Systems"

AgentHub is well-positioned with its existing runtime sandbox, identity module, and delegation chain infrastructure. This report identifies 18 actionable features across 6 categories that would strengthen AgentHub's competitive position.

---

## Category 1: Agent Runtime Security

### 1.1 Isolation Technology Landscape

The industry has converged on a three-tier isolation model:

| Technology | Isolation Level | Boot Time | Overhead | Best For |
|------------|----------------|-----------|----------|----------|
| **Firecracker MicroVM** | Hardware (KVM) | ~125ms | <5 MiB memory | Untrusted agent code execution |
| **gVisor** | User-space kernel | ~50ms | 10-30% I/O overhead | Default agent sandboxing |
| **Kata Containers** | Hardware via VMM | ~200ms | ~20 MiB | Kubernetes-orchestrated agents |
| **LiteBox (new)** | Library OS + SEV-SNP | Experimental | Minimal | Confidential agent computing |
| **WebAssembly** | Memory-safe sandbox | <10ms | Variable | Lightweight tool execution |
| **Hardened Containers** | Process namespace | <5ms | Minimal | Trusted agent code only |

**Key finding:** AI agents generate and execute code at runtime based on natural language inputs. This code is treated as trusted even though the LLM is following instructions from untrusted inputs. Without strict sandboxing, this creates a direct path to container escape and remote code execution.

### 1.2 Google Agent Sandbox (CNCF)

Launched at KubeCon NA 2025 as a Kubernetes SIG Apps subproject. Provides:

- **Declarative API** via Custom Resource Definitions (CRDs) for sandbox lifecycle
- **Backend-agnostic** -- supports gVisor (default) and Kata Containers
- **Stable identity** for each sandbox pod (persists across restarts)
- **Persistent storage** with lifecycle management (create, pause, resume, scheduled deletion)
- **Memory sharing** across sandboxes for multi-agent coordination

**AgentHub Integration:** AgentHub's `SandboxInstance` type already tracks `sandbox_id`, `agent_id`, `status`, and resource limits. The Agent Sandbox CRD model maps cleanly to AgentHub's existing data model. AgentHub could expose a Kubernetes operator that translates its sandbox API into Agent Sandbox CRDs, giving customers real container isolation beneath AgentHub's control plane.

**Effort:** Medium (3-4 weeks). Build a Kubernetes operator that watches AgentHub sandbox events and manages Agent Sandbox CRDs.

### 1.3 Microsoft LiteBox (Experimental, Feb 2026)

A Rust-based Library OS that reduces kernel attack surface:

- Runs unmodified Linux programs inside a constrained Library OS
- Supports AMD SEV-SNP for encrypted memory (confidential computing)
- "Platform" abstraction allows plugging into Linux kernel, Windows userland, or hypervisor-protected environments
- Lighter than a VM but with drastically reduced host interface vs. containers
- MIT-licensed, open-source

**AgentHub Integration:** LiteBox would be a future isolation backend for the most security-sensitive agent executions (financial, healthcare). AgentHub could offer a "confidential execution" tier that runs agent code inside LiteBox + SEV-SNP, where even the host operator cannot read agent memory.

**Effort:** High (6-8 weeks, experimental). Wait for stable release, then add as alternative sandbox backend.

### 1.4 NVIDIA's Three Mandatory Controls

NVIDIA's AI Red Team identified three non-negotiable controls for agent sandboxes:

1. **Network Egress Controls** -- Block network access to arbitrary sites; prevent data exfiltration and reverse shells
2. **File System Isolation** -- Block writes outside the workspace; prevent persistence, sandbox escape, and RCE
3. **OS-Level Enforcement** -- Use macOS Seatbelt / Linux seccomp-bpf beneath the application layer; covers subprocesses that application-level controls cannot see

**Critical insight:** Application-level controls are insufficient because tool-using agents write and execute throwaway scripts. Once control passes to a subprocess, the application has no visibility into or control over the subprocess.

**AgentHub Integration:** AgentHub's `network_mode` field (`disabled`, `egress_only`, `full`) already models this. The gap is that AgentHub currently stores these as metadata but does not enforce them at the OS level. Adding OS-level enforcement (seccomp profiles, eBPF policies, or Seatbelt rules) mapped to each `network_mode` would close this gap.

**Effort:** Medium (2-3 weeks). Generate seccomp/AppArmor/Seatbelt profiles from AgentHub's resource limits and apply them to sandbox processes.

### 1.5 Anthropic's Claude Code Sandboxing

Anthropic's approach provides two key lessons:

- **Filesystem isolation** via OS-level primitives (Linux bubblewrap, macOS Seatbelt): read/write access to CWD only, all other paths blocked
- **Network isolation** via a Unix domain socket proxy: all outbound traffic routes through a proxy running outside the sandbox that enforces domain allowlists
- **Result:** 84% reduction in permission prompts while maintaining security guarantees. Even a successful prompt injection is fully contained.

**AgentHub Integration:** The proxy-based network isolation pattern is directly applicable. AgentHub could run a per-sandbox egress proxy that enforces domain allowlists defined in the sandbox profile. This would make `egress_only` mode granular -- not just "can egress" but "can egress to these specific domains."

**Effort:** Low-Medium (1-2 weeks). Add `allowed_egress_domains` to `ResourceLimits` TypedDict and implement a proxy sidecar.

### 1.6 WebAssembly for Lightweight Tool Sandboxing

Key developments:
- **Microsoft Wassette** (Aug 2025): Agents autonomously fetch WebAssembly Components from registries and execute them in Wasmtime
- **LangChain Sandbox** (May 2025): Pyodide + Deno for sandboxed Python execution
- **CVE-2025-68668** (n8n): Critical sandbox escape via Pyodide -- demonstrates that interpreted environments inside Wasm are harder to secure than native Wasm

**AgentHub Integration:** For tool-call execution (not full agent execution), Wasm provides sub-millisecond startup and strong memory isolation. AgentHub could offer a "tool sandbox" tier using Wasm for executing individual tool calls, separate from the full "agent sandbox" for long-running agent processes.

**Effort:** Medium (3-4 weeks). Integrate Wasmtime Python bindings for tool-call execution.

---

## Category 2: Secure Multi-Agent Communication

### 2.1 Protocol Landscape: MCP vs A2A

| Protocol | Purpose | Auth Methods | Status |
|----------|---------|-------------|--------|
| **MCP** (Anthropic, Nov 2024) | Agent-to-Tool | OAuth 2.0, API keys | Production, June 2025 spec update |
| **A2A** (Google, Apr 2025) | Agent-to-Agent | OAuth 2.0, mTLS, API keys, scoped tokens | Production, 50+ partners |

MCP and A2A are complementary. MCP handles agent-to-tool communication; A2A handles agent-to-agent communication. Both support OAuth 2.0 and are built on HTTP/JSON-RPC.

**MCP June 2025 spec update:** Formalizes OAuth Resource Server roles for MCP servers, mandates Resource Indicators (RFC 8707) to prevent token misuse, and requires TLS 1.2+.

**A2A security features:** Supports scoped tokens that limit each agent's capabilities method-specifically. Enterprise-grade authentication parity with OpenAPI's auth schemes.

**AgentHub Integration:** AgentHub should implement both protocols as adapters. The existing delegation token system maps to A2A's scoped token model. AgentHub could serve as the identity and policy layer that sits behind both MCP and A2A protocol endpoints.

**Effort:** Medium-High (4-6 weeks). Build MCP adapter first (more mature), then A2A adapter.

### 2.2 SPIFFE/SPIRE for Agent Identity

SPIFFE (Secure Production Identity Framework for Everyone) is emerging as the standard for non-human identity:

- Every workload gets a **SPIFFE ID** (SVID) -- a URI-format identity bound to X.509 certificates
- **SPIRE** (SPIFFE Runtime Environment) handles attestation: node attestation (cloud metadata, TPM) and workload attestation (Kubernetes service accounts, container image hashes, filesystem paths)
- **HashiCorp Vault 1.21** natively supports SPIFFE authentication, issuing X509-SVIDs to authenticated workloads
- Gartner named NHI (Non-Human Identity) management a 2025 strategic trend

**AgentHub Integration:** AgentHub already supports `CREDENTIAL_TYPE_SPIFFE` in its identity constants. The implementation gap is the actual SPIRE integration. AgentHub should:
1. Run a SPIRE Agent sidecar that issues SVIDs to agent sandboxes
2. Use SPIFFE IDs as the canonical agent identity across federation boundaries
3. Bind credential lifecycle to SVID rotation

**Effort:** High (4-6 weeks). Requires SPIRE deployment infrastructure and integration with the identity storage layer.

### 2.3 mTLS for Agent-to-Agent Communication

mTLS replaces API keys with cryptographic identity verification:

- Both client and server present certificates, ensuring mutual authentication
- Certificates can encode SPIFFE IDs for identity-aware routing
- Eliminates the need for API key distribution and rotation for inter-agent communication

**AgentHub Integration:** AgentHub's federation module (`src/federation/`) already handles cross-domain trust. Adding mTLS as the transport layer for federation calls would eliminate domain token management and provide cryptographic proof of agent identity in transit.

**Effort:** Medium (2-3 weeks). Certificate management infrastructure + mTLS configuration for federation gateway.

### 2.4 Okta Cross App Access (XAA) and ID-JAG

Okta's approach to agent delegation:

- **OAuth 2.0 Token Exchange (RFC 8693):** Agents convert session tokens into short-lived, scoped credentials
- **ID-JAG (Identity Assertion JWT Authorization Grant):** Based on the OAuth Identity and Authorization Chaining specification, tracks delegation lineage for audit
- **Cross App Access (XAA):** Now part of MCP (Nov 2025) under "Enterprise-Managed Authorization"

**Key insight from Okta research:** 97% of non-human identities already carry excessive privileges. Each agent handoff in a delegation chain multiplies access.

**AgentHub Integration:** AgentHub's delegation token system already implements scope attenuation and chain validation. The gap is integration with standard OAuth flows. Adding RFC 8693 Token Exchange support would allow AgentHub to interoperate with enterprise IdPs (Okta, Azure AD, Auth0) and serve as the policy enforcement point in delegation chains.

**Effort:** Medium (3-4 weeks). Implement OAuth 2.0 Token Exchange endpoint in the API.

---

## Category 3: Capability-Based Security for Agents

### 3.1 Object-Capability Model for Agents

A capability is an unforgeable token that both designates a resource and authorizes a specific operation. Key properties:

1. **Unforgeability:** Capabilities cannot be created, modified, or duplicated without proper authorization (enforced via cryptographic signatures)
2. **Attenuation:** You can only give what you have, and you can only give less (Mark Miller's Principle of Least Authority)
3. **No ambient authority:** Agents cannot invoke operations for which they hold no capability, regardless of what downstream agents permit

**Critical quote from research:** "Attenuation isn't policy. It is a consequence of cryptographic derivation."

**AgentHub Integration:** AgentHub's `attenuate_scopes()` function in `src/identity/chain.py` already implements scope attenuation. The gap is that scopes are string-based (`resource.action`) rather than unforgeable capability tokens. Transitioning to cryptographically signed capability tokens (where the token itself encodes both the resource and the permitted operations, signed by the issuer) would make AgentHub's authorization model formally capability-based.

**Effort:** Medium (3-4 weeks). Redesign scope representation as signed capability tokens with cryptographic attenuation.

### 3.2 Delegation Chain Security Vulnerabilities

Recent real-world attacks:

- **Agent Session Smuggling (Nov 2025):** A sub-agent embeds a silent stock trade in a routine response. The parent agent executes it with no prompt and no visibility.
- **Cross-Agent Privilege Escalation (Sept 2025):** One agent rewrites another's config mid-task, triggering a self-reinforcing control loop.

**Defenses required:**
1. **Full chain validation** on every action (not just at delegation time)
2. **Scope reduction enforcement** at every hop (cryptographic, not policy-based)
3. **Consent mechanisms** at delegation boundaries
4. **Time-bounding** -- delegation tokens cannot outlive parent tokens

**AgentHub Integration:** AgentHub already implements chain validation (`_verify_chain_integrity()`) and scope attenuation. The gap is real-time enforcement: AgentHub validates chains at delegation time, but should also validate before every privileged action. Adding a middleware that checks the delegation chain on every API call involving delegated authority would close this gap.

**Effort:** Low (1-2 weeks). Add delegation chain verification to the access policy middleware.

### 3.3 DID/VC for Cross-Domain Agent Identity

Decentralized Identifiers (DIDs) and Verifiable Credentials (VCs) enable:

- Self-sovereign agent identity: agents prove ownership of their DIDs for authentication
- Cross-domain trust via spontaneous exchange of DID-bound VCs
- No central authority required for identity verification
- DIDComm (peer-to-peer communication protocol) for secure transmission

**AgentHub Integration:** AgentHub's federation module could adopt DIDs as the cross-domain identity format. Each agent would have a DID anchored to AgentHub's identity store, and VCs issued by AgentHub would serve as proof of agent capabilities when interacting with external systems.

**Effort:** High (6-8 weeks). Requires DID method implementation, VC issuance infrastructure, and federation gateway updates.

---

## Category 4: Agent Observability & Audit

### 4.1 OWASP Agentic AI Top 10 (2026)

The canonical threat model for agent systems:

| Rank | Risk | Description |
|------|------|-------------|
| ASI01 | Agent Goal Hijack | Attackers redirect agent objectives via manipulated instructions, tool outputs, or external content |
| ASI02 | Tool Misuse and Exploitation | Attackers subvert agent capabilities or their supporting infrastructure |
| ASI03 | Identity and Privilege Abuse | Unauthorized identity escalation or impersonation |
| ASI04 | Unsafe Code Generation | Agent-generated code introduces vulnerabilities |
| ASI05 | Memory and Context Poisoning | Corrupting agent memory or context to alter behavior |
| ASI06 | Cascading Hallucination Attacks | Hallucinations propagate through multi-agent chains |
| ASI07 | Insufficient Guardrails | Missing or weak behavioral boundaries |
| ASI08 | Data Leakage | Unauthorized exposure of sensitive information |
| ASI09 | Human-Agent Trust Exploitation | Manipulating human trust in agent outputs |
| ASI10 | Rogue Agents | Compromised or misaligned agents diverge from intended behavior |

**Core Design Principles:**
- **Least-Agency:** Agents should only be granted the minimum level of autonomy required for their defined task
- **Strong Observability:** Non-negotiable. Detailed logging of goal state, tool-use patterns, and decision pathways is mandatory

**AgentHub Integration:** AgentHub should map its existing controls to each ASI risk and identify gaps. The current runtime module covers ASI04 (sandboxing), ASI03 (identity), and partially ASI07 (resource limits). Major gaps exist in ASI01 (goal hijack detection), ASI05 (memory poisoning), ASI06 (cascading hallucination), and ASI10 (rogue agent detection).

**Effort:** Medium (ongoing). Create a compliance mapping document and implement detection for each risk.

### 4.2 Behavioral Anomaly Detection

Key approaches for detecting anomalous agent behavior:

1. **Behavioral baselines:** Monitor API usage patterns, data access patterns, and task assignment patterns
2. **Runtime signal detection:** Unauthorized access, API misuse, and unexpected privilege escalation
3. **Multi-agent anomalies:** Emerge from complex interactions rather than individual agent failures
4. **Output anomaly detection:** Monte Carlo's 2025 agent observability features monitor agent outputs and trace them back through data lineage

**Detection methods (catches 80%+ of meaningful drift):**
- Statistical deviation from behavioral baselines
- Graph-based analysis of agent interaction patterns
- Correlation with identity posture, permissions, and data access
- Real-time scoring against behavioral models

**AgentHub Integration:** AgentHub's `SandboxMetricSnapshot` already captures CPU, memory, disk I/O, and network bytes per execution. Adding behavioral baselines per agent (average execution time, typical API call patterns, normal resource consumption) and alerting on deviations would provide anomaly detection. The `audit.py` module should be extended with baseline computation and drift scoring.

**Effort:** Medium (3-4 weeks). Build behavioral baseline computation and real-time drift detection.

### 4.3 SOC2/ISO 27001 for Agent Systems

Compliance requirements specific to AI agents:

- **Audit trails** must map to OWASP, NIST, and PCI-DSS frameworks
- **Agent behavior traceability:** Every agent action must have a complete chain of evidence (who authorized it, what identity was used, what data was accessed)
- **ISO 27001:** Security controls must cover AI agent access and data processing
- **SOC 2 Type II:** Agent audit trails must meet evidence requirements auditors expect
- **EU AI Act (enforcement Aug 2026):** Major requirements now rolling out

**AgentHub Integration:** AgentHub's `export_sandbox_evidence()` and `check_sandbox_audit_completeness()` functions provide a foundation. Gaps include:
1. No linkage between sandbox executions and the identity/delegation chain that authorized them
2. No structured evidence format for SOC2 auditors
3. No continuous compliance monitoring (only point-in-time checks)

**Effort:** Medium (2-3 weeks). Add identity chain linkage to audit records and SOC2-formatted evidence export.

### 4.4 AGENTARMOR: Runtime Trace Analysis

Academic research proposes treating an agent's runtime execution trace as a program:

- Abstract runtime traces into **Program Dependence Graphs (PDGs)**
- Apply formal security analysis (information flow, taint tracking) to PDGs
- Detect privilege escalation, data exfiltration, and policy violations through program analysis rather than pattern matching

**AgentHub Integration:** This is a future-looking research direction. AgentHub could record structured execution traces (tool calls, data flows, delegation decisions) and apply PDG analysis post-execution for compliance auditing. This would provide the strongest possible evidence for SOC2 auditors.

**Effort:** High (8-10 weeks). Research-grade implementation, suitable for a differentiated feature.

---

## Category 5: Prompt Injection & Agent Security

### 5.1 Microsoft FIDES: Information-Flow Control

The most significant defensive advance in 2025. FIDES (Flow Integrity Deterministic Enforcement System):

- **Tracks confidentiality and integrity labels** on all messages, actions, tool calls, and results
- **Deterministically enforces security policies** -- no probabilistic defenses
- **Novel primitives** for selectively hiding information from the planner
- **Results:** Stops ALL prompt injection attacks in the AgentDojo benchmark while completing 16% more tasks than a basic planner (with reasoning models)

**How it works:**
1. Every piece of data gets a label (trusted/untrusted, confidential/public)
2. Labels propagate through the system as data flows between components
3. Before executing any consequential action, FIDES checks that the action's data lineage satisfies the security policy
4. Actions with tainted (untrusted) lineage are blocked or flagged

**AgentHub Integration:** This is a transformative feature. AgentHub could implement FIDES-style information-flow labels on:
- Tool call inputs and outputs
- Delegation token payloads
- Agent-to-agent messages
- Sandbox execution I/O

Adding an `integrity_label` and `confidentiality_label` to `SandboxExecution` and propagating labels through the delegation chain would enable deterministic policy enforcement.

**Effort:** High (6-8 weeks). Requires label propagation infrastructure across identity, delegation, and runtime modules.

### 5.2 PALADIN Defense-in-Depth Framework

A five-layer defense framework for prompt injection:

1. **Input validation and sanitization** -- Pre-process all inputs before they reach the LLM
2. **Document provenance verification** -- Track the origin and integrity of all data sources
3. **Session isolation** -- Prevent cross-session data leakage
4. **Anomaly monitoring** -- Detect unusual patterns in agent behavior
5. **Output validation** -- Verify agent outputs before they are acted upon

**Key insight:** No single defensive layer can reliably prevent all attacks due to LLMs' stochastic nature. Only defense-in-depth provides operational resilience.

**AgentHub Integration:** AgentHub should implement this as a pipeline of validation stages:
1. Pre-execution input validation in the sandbox API
2. Data provenance tracking in the identity module (who provided this data, via which delegation chain)
3. Session isolation already exists in the sandbox model
4. Anomaly monitoring (see 4.2)
5. Post-execution output validation before results leave the sandbox

**Effort:** Medium (3-4 weeks for stages 1, 2, and 5; stages 3 and 4 leverage existing infrastructure).

### 5.3 Real-World Attack Vectors (2025-2026)

Documented incidents:

- **GitHub Copilot CVE-2025-53773:** Remote code execution via crafted repository content (CVSS 9.6)
- **ChatGPT Windows License Key Exposure:** Agent leaked sensitive system information
- **RAG Poisoning:** 5 carefully crafted documents can manipulate AI responses 90% of the time
- **Argument Injection:** Security controls validate commands but fail to validate flags/arguments
- **Tool Poisoning via MCP:** Manipulated tool outputs alter agent behavior

**AgentHub Integration:** AgentHub should add:
1. Input hash validation (already exists: `input_hash` on `SandboxExecution`)
2. Output validation hooks (new: validate output against expected schema before returning)
3. Tool output sanitization in the runtime module
4. Argument validation for all tool calls (not just command-level checks)

**Effort:** Low-Medium (2-3 weeks). Extend existing I/O hashing with validation hooks.

---

## Category 6: Emerging Patterns

### 6.1 Just-in-Time (JIT) Credential Provisioning

The paradigm shift from long-lived to ephemeral credentials:

- **JIT provisioning** creates identity profiles for agents at runtime, only when needed, with permissions scoped to the specific task
- **Automatic expiration** -- credentials are destroyed when the task completes
- **Eliminates credential sprawl** -- no thousands of long-lived agent credentials to manage
- **Strata's Maverics** (July 2025): Vendor-agnostic identity orchestration for AI agents with JIT issuance into any cloud or on-premises IDP

**AgentHub Integration:** AgentHub's credential system already supports TTLs (`MIN_CREDENTIAL_TTL_SECONDS` = 300s, `MAX_CREDENTIAL_TTL_SECONDS` = 30 days). The enhancement is to:
1. Auto-issue credentials when a sandbox is provisioned (bind credential lifecycle to sandbox lifecycle)
2. Auto-revoke credentials when the sandbox is terminated
3. Track credential-to-sandbox binding in the identity store

**Effort:** Low (1-2 weeks). Add lifecycle hooks between sandbox and credential modules.

### 6.2 Agent Lifecycle Management

Four-stage lifecycle model:

1. **Registration:** Define the agent, assign its unique identity, map to organizational purpose
2. **Provisioning:** Assign entitlements and policies aligned to role (JIT, context-adaptive)
3. **Runtime:** Continuous monitoring, behavioral baseline enforcement, scope validation on every action
4. **Retirement:** Credential revocation, cascade revocation of delegation tokens, audit trail finalization

**AgentHub Integration:** AgentHub has pieces of all four stages but they are not unified:
- Registration: `src/identity/` (agent identity creation)
- Provisioning: `src/runtime/` (sandbox creation with resource limits)
- Runtime: `src/runtime/` (execution tracking, metrics)
- Retirement: `src/identity/` (revocation, cascade revocation)

The gap is a unified lifecycle API that orchestrates these stages. A single `POST /v1/agents/{agent_id}/lifecycle/provision` endpoint that creates identity + credentials + sandbox + delegation token in one atomic operation would be a significant UX improvement.

**Effort:** Medium (2-3 weeks). Orchestration layer over existing modules.

### 6.3 Cost Guardrails for Agent Fleets

Three-lever cost control model:

1. **Per-agent daily/monthly budgets** -- Hard spending caps per agent identity
2. **Per-tool RPS limits** -- Rate limiting on individual tool invocations
3. **Adaptive throttling** -- Graceful degradation (allow -> throttle -> queue -> deny) based on spend velocity

**Enforcement tiers:**
- **80% soft alert** -- Notify owner
- **100% re-auth** -- Require explicit re-authorization
- **120% hard stop** -- Terminate sandbox immediately

**AgentHub Integration:** AgentHub's cost governance module (`src/cost_governance/`) and metering functions already track costs. The gap is enforcement: metering records costs but does not block execution when budgets are exceeded. Adding budget enforcement to the `evaluate_sandbox_execution_policy()` function would close this loop.

**Effort:** Low-Medium (1-2 weeks). Add budget checks to runtime policy evaluation.

### 6.4 Ephemeral Identity for Short-Lived Agents

Some agents exist for seconds -- spinning up for a micro-task, then dissolving. This requires:

- **Identity-per-task** rather than identity-per-agent
- **Automatic cleanup** -- credentials, delegation tokens, and audit records tied to the task's lifecycle
- **No static entitlements** -- everything is JIT

**AgentHub Integration:** AgentHub could add a `ephemeral` flag to `AgentIdentity` that triggers automatic cleanup after the associated sandbox terminates. This would support the pattern of spawning thousands of micro-agents for parallel task execution.

**Effort:** Low (1 week). Add ephemeral flag and cleanup hooks.

### 6.5 Cross-Cloud Agent Identity Federation

DID/VC-based federation enables:

- Self-sovereign agent identity via Decentralized Identifiers
- Verifiable Credentials for cross-domain trust (AgentHub issues VCs, external systems verify them)
- DIDComm or HTTPS for secure transport
- OIDC (OpenID Connect) integration for enterprise environments
- Decentralized Identity Interop Profile (DIIP): Uses OpenID Federation for agents, wallets, and digital credentials

**AgentHub Integration:** AgentHub's `src/identity/federation.py` handles cross-domain trust via domain tokens. Evolving this to DID-based identity would make AgentHub's federation protocol standards-based and interoperable with other agent platforms.

**Effort:** High (6-8 weeks). Requires DID method implementation and VC issuance.

---

## Architecture Recommendations for AgentHub

### Priority Tier 1: High Impact, Low-Medium Effort (Ship in 4-6 weeks)

| # | Feature | Category | Effort | Impact |
|---|---------|----------|--------|--------|
| 1 | **OS-level sandbox enforcement** (seccomp/AppArmor profiles from resource limits) | Runtime | 2-3 weeks | Closes the gap between policy-as-metadata and actual enforcement |
| 2 | **Egress domain allowlists** (per-sandbox proxy with allowed domains) | Runtime | 1-2 weeks | Granular network control beyond disabled/egress_only/full |
| 3 | **JIT credential binding** (auto-issue/revoke credentials with sandbox lifecycle) | Emerging | 1-2 weeks | Eliminates credential sprawl, simplifies agent provisioning |
| 4 | **Budget enforcement in policy** (block execution when budget exceeded) | Emerging | 1-2 weeks | Prevents runaway agent costs |
| 5 | **Delegation chain middleware** (verify chain on every privileged API call) | Capability | 1-2 weeks | Prevents delegation chain attacks (Agent Session Smuggling) |
| 6 | **Input/output validation hooks** on sandbox execution | Prompt Injection | 2-3 weeks | Defense-in-depth against manipulated tool outputs |

### Priority Tier 2: High Impact, Medium Effort (Ship in 6-12 weeks)

| # | Feature | Category | Effort | Impact |
|---|---------|----------|--------|--------|
| 7 | **Behavioral anomaly detection** (baseline + drift scoring per agent) | Observability | 3-4 weeks | Detects rogue agents and privilege escalation |
| 8 | **Capability tokens** (cryptographically signed, unforgeable scope tokens) | Capability | 3-4 weeks | Formal capability-based security model |
| 9 | **MCP adapter** (serve AgentHub as MCP-compliant tool/resource server) | Communication | 3-4 weeks | Interoperability with Anthropic/Claude ecosystem |
| 10 | **OWASP ASI compliance mapping** (map controls to each risk) | Observability | 2-3 weeks | SOC2/compliance differentiation |
| 11 | **Agent lifecycle orchestration** (unified provision/runtime/retire API) | Emerging | 2-3 weeks | Simplified developer experience |
| 12 | **SOC2-formatted evidence export** with identity chain linkage | Observability | 2-3 weeks | Enterprise compliance readiness |

### Priority Tier 3: Differentiating, High Effort (6-12+ weeks)

| # | Feature | Category | Effort | Impact |
|---|---------|----------|--------|--------|
| 13 | **FIDES-style information-flow labels** (integrity/confidentiality tracking) | Prompt Injection | 6-8 weeks | Deterministic prompt injection prevention |
| 14 | **SPIFFE/SPIRE integration** (SVID-based agent identity) | Communication | 4-6 weeks | Industry-standard NHI |
| 15 | **A2A protocol adapter** (agent-to-agent interoperability) | Communication | 4-6 weeks | Google ecosystem interoperability |
| 16 | **Kubernetes Agent Sandbox operator** (CRD-based real container isolation) | Runtime | 3-4 weeks | Production-grade isolation for Kubernetes deployments |
| 17 | **DID/VC federation** (decentralized cross-domain identity) | Emerging | 6-8 weeks | Standards-based federation, no central authority |
| 18 | **Execution trace PDG analysis** (program-dependence-graph audit) | Observability | 8-10 weeks | Strongest possible compliance evidence |

### Recommended Roadmap

**Phase 1 (Weeks 1-6): Foundation Hardening**
- Items 1-6 from Tier 1
- Focus: Close the gap between policy metadata and actual enforcement

**Phase 2 (Weeks 7-12): Market Differentiation**
- Items 7-12 from Tier 2
- Focus: Features that competitors (Cyata, Strata, Aembit) do not yet offer

**Phase 3 (Weeks 13-24): Standards Leadership**
- Items 13-18 from Tier 3
- Focus: Become the reference implementation for agent security standards

---

## Competitive Analysis

| Feature | AgentHub (Current) | AgentHub (Proposed) | Cyata | Strata | Aembit |
|---------|-------------------|-------------------|-------|--------|--------|
| Runtime Sandbox | Control plane only | OS-level enforcement | Unknown | None | None |
| Delegation Chains | Scope attenuation | Capability tokens + chain verification | None | Partial | None |
| Identity Federation | Domain tokens | SPIFFE + DID/VC | Basic | Maverics | Workload identity |
| Cost Guardrails | Metering only | Metering + enforcement | None | None | None |
| Prompt Injection Defense | None | FIDES-style IFC labels | None | None | None |
| Compliance Evidence | Basic export | SOC2-formatted + OWASP mapping | None | Partial | None |
| Agent Lifecycle | Fragmented | Unified orchestration API | Unknown | JIT provisioning | Basic |

AgentHub's existing delegation chain and sandbox infrastructure provide a significant head start. The proposed enhancements would create a comprehensive agent security platform that no competitor currently offers.

---

## Key Sources

### Runtime Security
- [Northflank: How to Sandbox AI Agents in 2026](https://northflank.com/blog/how-to-sandbox-ai-agents)
- [NVIDIA: Practical Security Guidance for Sandboxing Agentic Workflows](https://developer.nvidia.com/blog/practical-security-guidance-for-sandboxing-agentic-workflows-and-managing-execution-risk)
- [NVIDIA: Sandboxing Agentic AI Workflows with WebAssembly](https://developer.nvidia.com/blog/sandboxing-agentic-ai-workflows-with-webassembly/)
- [Anthropic: Claude Code Sandboxing](https://www.anthropic.com/engineering/claude-code-sandboxing)
- [Microsoft: LiteBox Rust-Based Sandboxing Library OS](https://securityboulevard.com/2026/02/microsoft-unveils-litebox-a-rust-based-approach-to-secure-sandboxing/)
- [Google: Agent Sandbox for Kubernetes](https://opensource.googleblog.com/2025/11/unleashing-autonomous-ai-agents-why-kubernetes-needs-a-new-standard-for-agent-execution.html)
- [Kata Containers + Agent Sandbox Integration](https://katacontainers.io/blog/kata-containers-agent-sandbox-integration/)
- [Blaxel: Container Escape Vulnerabilities for AI Agents](https://blaxel.ai/blog/container-escape)

### Communication & Identity
- [Auth0: MCP vs A2A](https://auth0.com/blog/mcp-vs-a2a/)
- [Semgrep: Security Engineer's Guide to A2A Protocol](https://semgrep.dev/blog/2025/a-security-engineers-guide-to-the-a2a-protocol/)
- [HashiCorp: SPIFFE for Agentic AI Identity](https://www.hashicorp.com/en/blog/spiffe-securing-the-identity-of-agentic-ai-and-non-human-actors)
- [Okta: Fixing AI Agent Delegation](https://www.okta.com/blog/ai/agent-security-delegation-chain/)
- [Okta: Cross App Access (XAA)](https://developer.okta.com/blog/2025/09/03/cross-app-access)
- [ISACA: The Looming Authorization Crisis for Agentic AI](https://www.isaca.org/resources/news-and-trends/industry-news/2025/the-looming-authorization-crisis-why-traditional-iam-fails-agentic-ai)

### Capability Security
- [Niyikiza: Capabilities Are the Only Way to Secure Agent Delegation](https://niyikiza.com/posts/capability-delegation/)
- [Vouchsafe: Zero-Infrastructure Capability Graph Model](https://arxiv.org/html/2601.02254v1)
- [ScaleKit: On-Behalf-Of Authentication for AI Agents](https://www.scalekit.com/blog/delegated-agent-access)
- [arXiv: Novel Zero-Trust Identity Framework for Agentic AI](https://arxiv.org/html/2505.19301v1)
- [arXiv: AI Agents with Decentralized Identifiers and Verifiable Credentials](https://arxiv.org/html/2511.02841v1)

### Observability & Compliance
- [OWASP: Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [Galileo: Real-Time Anomaly Detection for Multi-Agent AI Systems](https://galileo.ai/blog/real-time-anomaly-detection-multi-agent-ai)
- [Zenity: AI Agents Compliance](https://zenity.io/use-cases/business-needs/ai-agents-compliance)
- [Obsidian Security: AI Agent Security Framework](https://www.obsidiansecurity.com/blog/ai-agent-security-framework)
- [Security Boulevard: Anomaly Detection for Non-Human Identities](https://securityboulevard.com/2026/01/anomaly-detection-for-non-human-identities-catching-rogue-workloads-and-ai-agents/)

### Prompt Injection Defense
- [Microsoft: FIDES - Securing AI Agents with Information-Flow Control](https://www.microsoft.com/en-us/research/publication/securing-ai-agents-with-information-flow-control/)
- [Microsoft: How Microsoft Defends Against Indirect Prompt Injection](https://www.microsoft.com/en-us/msrc/blog/2025/07/how-microsoft-defends-against-indirect-prompt-injection-attacks)
- [MDPI: PALADIN - Comprehensive Review of Prompt Injection Defense](https://www.mdpi.com/2078-2489/17/1/54)
- [OpenAI: Understanding Prompt Injections](https://openai.com/index/prompt-injections/)
- [OpenAI: Continuously Hardening Atlas Against Prompt Injection](https://openai.com/index/hardening-atlas-against-prompt-injection/)
- [Lakera: Indirect Prompt Injection - The Hidden Threat](https://www.lakera.ai/blog/indirect-prompt-injection)

### Emerging Patterns
- [Strata: JIT Provisioning for AI Agent Identities](https://www.strata.io/blog/agentic-identity/just-in-time-provisioning-creates-artificial-agent-identities-on-demand-5b/)
- [Strata: AI Agent Identity Management 2026 Guide](https://www.strata.io/glossary/ai-agent-identity-management/)
- [Akeyless: Securing AI Agent Identities](https://www.akeyless.io/press-release/akeyless-unveils-breakthrough-solution-to-secure-ai-agent-identities/)
- [CoSAI: Principles for Secure-by-Design Agentic Systems](https://www.coalitionforsecureai.org/announcing-the-cosai-principles-for-secure-by-design-agentic-systems/)
- [Microsoft: Runtime Risk to Real-Time Defense](https://www.microsoft.com/en-us/security/blog/2026/01/23/runtime-risk-realtime-defense-securing-ai-agents/)
- [arXiv: Taming Privilege Escalation in LLM-Based Agent Systems](https://arxiv.org/html/2601.11893v1)
- [Zenity: AI Detection & Response (AIDR)](https://zenity.io/platform/ai-security-platform/aidr)
- [Cost Guardrails for Agent Fleets](https://medium.com/@Micheal-Lanham/cost-guardrails-for-agent-fleets-how-to-prevent-your-ai-agents-from-burning-through-your-budget-ea68722af3fe)

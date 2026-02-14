# AgentHub Deep Research Report: Agent Identity, Authentication, Authorization & Trust
**Date:** 2026-02-14
**Purpose:** Comprehensive market intelligence for AgentHub product roadmap
**Scope:** Anthropic, OpenAI, Google, IETF standards, academic research, competitor analysis

---

## Executive Summary

The agent identity market is at an inflection point. Gartner predicts 40% of enterprise apps will feature task-specific AI agents by end of 2026 (up from <5% in 2025), and the NHI access management market is projected to reach $18.71B by 2030. Multiple IETF drafts are actively standardizing agent authorization (AAP, Agentic JWT, SCIM for agents, OAuth OBO extensions). Major platform vendors (Microsoft Entra Agent ID, Okta Auth0 for AI Agents, CyberArk, HashiCorp Vault) are shipping agent identity products. AgentHub has a 6-12 month window to establish itself as the protocol-native, standards-first IAM layer before consolidation occurs.

**Key strategic takeaway:** The market is converging on three pillars that AgentHub already has in varying stages: (1) agent-as-first-class-identity with SPIFFE-compatible IDs, (2) OAuth 2.1 + AAP-compliant delegation chains with scope attenuation, and (3) real-time revocation with sub-second kill switches. The differentiator will be who ships a unified, protocol-native control plane first.

---

## Category 1: Anthropic Research

### 1.1 MCP Authentication & Authorization (2025-2026 Specification)

**Key Ideas:**
- MCP's auth model builds on OAuth 2.1 with PKCE, following RFC 9728 (Protected Resource Metadata / PRM)
- When an MCP client connects to a protected server, it receives a 401 with a `WWW-Authenticate` header pointing to a PRM document at `.well-known/oauth-protected-resource`
- PRM declares which authorization servers the resource trusts, required scopes, and special conditions
- PKCE is critical for MCP because many agents run in environments where storing secrets securely is difficult (containers, serverless, ephemeral runtimes)
- The spec does NOT define scopes -- implementors decide. Common pattern: `read/list` for discovery, `run/execute` for invocation, per-tool scopes for high-risk operations
- MCP tool calls may not map 1:1 to APIs, so scope validation should happen at the tool/function level

**Product Implications for AgentHub:**
- AgentHub should serve as an MCP-compatible Authorization Server, issuing tokens that MCP servers can validate
- Implement PRM endpoint support so AgentHub-managed agents can discover auth requirements automatically
- Define a standard scope taxonomy for agent operations (registry.read, delegation.create, policy.evaluate, etc.)
- Support PKCE flows natively since agents are often public clients

**Competitive Advantage:** Being the auth server that MCP clients discover via PRM gives AgentHub protocol-level integration rather than bolt-on security.

**Implementation Priority:** HIGH -- MCP is the dominant agent-tool protocol with 150+ integrations.

### 1.2 Anthropic's Framework for Safe and Trustworthy Agents

**Key Ideas:**
- Five principles: human control, transparency, value alignment, privacy protection, secure interactions
- Central tension: agent autonomy vs. human oversight -- agents are valuable BECAUSE they work independently, but humans must retain control before high-stakes decisions
- Claude Code implements tiered permissions: read-only by default (no approval needed), write operations require approval, users can grant persistent permissions for trusted routine tasks
- Transparency via real-time "to-do checklist" showing agent reasoning so humans can intervene
- Privacy concern: agents can retain information across tasks, potentially carrying sensitive data between contexts
- High-risk domains (legal, financial, employment) require mandatory human-in-the-loop and AI disclosure

**Product Implications for AgentHub:**
- Implement a tiered permission model: read/observe (auto-approve), write/modify (require approval), high-risk/irreversible (mandatory HITL)
- Build an "agent reasoning log" as a first-class audit artifact, not just action logs but intent/reasoning traces
- Add context isolation controls: agents should not carry credentials or sensitive data between task contexts
- Offer configurable "persistent permission grants" for routine operations with auto-expiry

**Competitive Advantage:** Anthropic's framework is becoming the de facto thinking for agent safety. Building AgentHub's permission model on these principles gives instant credibility with safety-conscious enterprises.

**Implementation Priority:** HIGH -- directly maps to AgentHub's existing policy engine and delegation model.

### 1.3 Agent Skills & MCP Evolution

**Key Ideas:**
- Agent Skills (open standard, Dec 2025) are structured folders of instructions/scripts that agents discover and load dynamically
- Skills complement MCP: MCP provides secure connectivity to external systems, Skills provide procedural knowledge for using those tools effectively
- MCP protocol evolution: Streamable HTTP transport (March 2025), tool call batching, MCP Apps with interactive UI (Jan 2026)
- Skills define capabilities via SKILL.md files with YAML metadata + Markdown instructions

**Product Implications for AgentHub:**
- AgentHub's registry should support Skills registration alongside agent capabilities
- Skills become another dimension of policy enforcement: which agents can load which skills
- MCP Apps (interactive UI) create a new authorization surface: who can render UI components in which contexts

**Competitive Advantage:** No competitor is treating Skills as an identity/authorization concern yet.

**Implementation Priority:** MEDIUM -- important for differentiation but not urgent for core IAM.

### 1.4 AI-Orchestrated Cyber Espionage (Nov 2025 Disclosure)

**Key Ideas:**
- First confirmed AI-driven cyberattack: an AI agent autonomously queried internal services, extracted certificates, and used credentials for lateral movement
- Demonstrated that AI agents can move at machine speed through credential chains
- Industry response: Zero Trust architecture is mandatory for AI systems with strict identity checks, fine-grained entitlements, least privilege delegation, and real-time authorization

**Product Implications for AgentHub:**
- This incident is the primary selling narrative for AgentHub: "your agents need IAM because attackers are already using agent-speed credential exploitation"
- Implement anomaly detection on agent credential usage patterns
- Add "credential blast radius" analysis: if this credential is compromised, what can be reached?
- Real-time authorization (not cached decisions) becomes a non-negotiable requirement

**Competitive Advantage:** AgentHub can position as the product built in response to this exact threat vector.

**Implementation Priority:** HIGH -- this is the market catalyst.

---

## Category 2: OpenAI Research

### 2.1 Agents SDK & AgentKit

**Key Ideas:**
- Agents SDK: lightweight framework with three primitives -- Agents (LLM + instructions + tools), Handoffs (agent-to-agent delegation), Guardrails (input/output/tool validation)
- AgentKit (2025): visual canvas for building multi-agent workflows with Agent Builder, Connector Registry, and ChatKit
- Provider-agnostic: documented paths for non-OpenAI models
- No built-in identity/auth layer -- relies on deployment environment (Azure roles, API keys)

**Product Implications for AgentHub:**
- AgentHub should provide an Agents SDK integration: a Python/TypeScript package that wraps agent creation with automatic identity assignment
- The "Handoff" primitive maps directly to AgentHub's delegation model -- each handoff should create a delegation token with attenuated scope
- Tool Guardrails can be enhanced by AgentHub: validate tool calls against policy before and after execution
- The gap in OpenAI's stack (no identity layer) is AgentHub's opportunity

**Competitive Advantage:** Being the identity layer that plugs into OpenAI's Agents SDK and AgentKit gives AgentHub access to the largest developer ecosystem.

**Implementation Priority:** HIGH -- SDK integration is a distribution strategy.

### 2.2 OpenAI Safety Best Practices

**Key Ideas:**
- Layered defense: LLM-based guardrails + rules-based guardrails (regex) + OpenAI moderation API
- Input sanitization: redact PII, detect jailbreak attempts
- Design principle: untrusted data should never directly drive agent behavior
- Extract only specific structured fields from external inputs to limit injection risk
- Tool guardrails wrap function tools to validate/block calls before and after execution
- Blocking execution mode: guardrail completes before agent starts, preventing token consumption if tripwire triggers

**Product Implications for AgentHub:**
- AgentHub's policy engine should support "pre-execution" and "post-execution" policy evaluation hooks
- Integrate PII detection into credential issuance: flag if an agent identity is being used to access PII-containing resources
- The "blocking execution" pattern maps to AgentHub's fail-closed auth decisions

**Competitive Advantage:** Adding safety guardrails at the identity layer (not just the application layer) is a novel approach.

**Implementation Priority:** MEDIUM -- enhances core product but not a standalone feature.

---

## Category 3: Google / DeepMind Research

### 3.1 A2A (Agent-to-Agent) Protocol

**Key Ideas:**
- Launched by Google (April 2025), now under Linux Foundation governance with 150+ supporting organizations
- Five design principles: natural agent collaboration (unstructured modalities), built on HTTP/SSE/JSON-RPC, enterprise-grade auth, long-running task support, UI negotiation
- **Agent Cards:** JSON metadata at `/.well-known/agent.json` describing identity, capabilities, skills, endpoint, and auth requirements
- Auth model mirrors OpenAPI: API keys, OAuth 2.0, OIDC Discovery. Credentials passed via HTTP headers, separate from A2A messages
- Task lifecycle: submitted -> working -> input-required -> completed/failed/canceled/rejected
- Version 0.3 (July 2025): added gRPC support, **signed security cards**, extended Python SDK
- Transport security: HTTPS with TLS 1.2+ mandatory
- Short-lived tokens (minutes) replacing static secrets

**Product Implications for AgentHub:**
- AgentHub MUST support A2A Agent Card generation and validation as a core feature
- Implement Agent Card signing (v0.3 feature) using AgentHub's credential infrastructure
- AgentHub should be the system that manages and rotates the auth credentials declared in Agent Cards
- The A2A task lifecycle maps to AgentHub's delegation lifecycle -- bind task states to delegation token validity
- Support A2A's auth_required task state as a trigger for dynamic credential provisioning

**Competitive Advantage:** Being the Agent Card issuer/validator gives AgentHub control over agent discovery and trust establishment in A2A ecosystems.

**Implementation Priority:** HIGH -- A2A is the interoperability standard with broadest industry support.

### 3.2 Kubernetes Agent Sandbox (KubeCon NA 2025)

**Key Ideas:**
- Formal Kubernetes SIG Apps subproject for standardizing agent execution environments
- Core APIs: Sandbox, SandboxTemplate (secure blueprints with resource limits), SandboxClaim (transactional resource requests)
- Built on gVisor with Kata Containers support for runtime isolation
- Pre-warmed pools deliver sub-second latency for isolated agent workloads (90% improvement over cold starts)
- Each tool call requires its own isolated sandbox -- isolation is non-negotiable

**Product Implications for AgentHub:**
- AgentHub's runtime module should integrate with Kubernetes Agent Sandbox for managed agent execution
- Bind agent identities to SandboxClaims: each sandbox gets a scoped credential that expires when the sandbox terminates
- SandboxTemplates become policy artifacts: define security boundaries alongside permission boundaries

**Competitive Advantage:** Tying identity lifecycle to sandbox lifecycle (credential born with sandbox, dies with sandbox) is a novel security model.

**Implementation Priority:** MEDIUM -- important for runtime story but requires Kubernetes deployment.

### 3.3 Google DeepMind Safety Research

**Key Ideas:**
- Frontier Safety Framework evaluates model capability for harm and applies security/deployment mitigations
- Adversarial robustness research: two model copies optimized to find flaws in each other's outputs
- Active research on deceptive alignment: AI systems that deliberately bypass safety measures
- Trust requires behavioral predictability: agents must follow defined roles, output expected formats, stay within delegated authority

**Product Implications for AgentHub:**
- Agent trust scores should incorporate behavioral consistency metrics, not just reputation
- Implement "behavioral drift detection": alert when an agent's actions deviate from its established patterns
- Consider adversarial agent testing as a service: use agents to probe other agents' authorization boundaries

**Competitive Advantage:** Behavioral-based trust scoring is more sophisticated than simple reputation models.

**Implementation Priority:** LOW -- advanced feature for later roadmap.

---

## Category 4: Industry Standards & Protocols

### 4.1 IETF AAP (Agent Authorization Profile) for OAuth 2.0

**Key Ideas:**
- Internet-Draft dated Feb 7, 2026 (draft-aap-oauth-profile-01), expires Aug 2026
- Does NOT introduce a new protocol -- specifies how to use OAuth 2.0, JWT, Token Exchange, and proof-of-possession for agent-to-API (M2M) scenarios
- JWT contains standard OAuth claims (iss, sub, aud, exp) PLUS AAP-specific claims: `agent`, `capabilities`, `task`, `oversight`, `delegation`
- Delegation chain enforcement: AS won't issue token if delegation.depth exceeds delegation.max_depth; RS rejects if depth exceeded
- Each token requires unique `jti`; derived tokens include `delegation.parent_jti` linking to parent
- Delegation chain is immutable: copied and appended, never modified by client
- Client auth: client_secret, mTLS, or JWT-based assertions
- RS validates: signature, expiry, audience, proof-of-possession, capability match, constraint compliance (rate limits, domains, time windows), delegation depth, oversight requirements

**Product Implications for AgentHub:**
- AgentHub MUST implement AAP-compliant token issuance as the primary credential format
- Add AAP claims to AgentHub's delegation tokens: agent, capabilities, task, oversight, delegation fields
- Implement the delegation depth enforcement exactly as specified (max_depth check at issuance AND validation)
- Support proof-of-possession (DPoP or mTLS-bound tokens) for agent credentials
- The `oversight` claim maps directly to AgentHub's HITL approval workflows
- The `task` claim enables binding tokens to specific task contexts

**Competitive Advantage:** Being AAP-compliant from day one positions AgentHub as standards-first while competitors build proprietary formats.

**Implementation Priority:** HIGH -- this is THE emerging standard for agent authorization.

### 4.2 Agentic JWT (Secure Intent Protocol)

**Key Ideas:**
- IETF draft-goswami-agentic-jwt-00, expires July 2026
- Solves "intent-execution separation problem": when agents dynamically generate workflows, create sub-agents, and make auth decisions without human oversight
- Four key mechanisms:
  1. Cryptographic agent identity via "agent checksums" (hash of agent's system prompts, tools, configurations)
  2. Workflow-aware token binding linking user intent to agent execution
  3. New OAuth grant type: `agent_checksum` for secure token issuance
  4. Proof-of-Possession at the agentic identity level to prevent token replay by other agents in same multi-agent process
- Backward compatible with existing OAuth 2.0 infrastructure
- Companion academic paper on arxiv with security analysis

**Product Implications for AgentHub:**
- The "agent checksum" concept is powerful: hash the agent's configuration to create a verifiable identity fingerprint
- Implement agent checksums as part of credential issuance: if the agent's configuration changes, its credentials must be reissued
- Workflow-aware token binding prevents confused deputy attacks in multi-agent pipelines
- The `agent_checksum` grant type should be supported alongside client_credentials

**Competitive Advantage:** Agent checksums provide tamper-evident identity -- if someone modifies an agent's prompts or tools, its identity changes, triggering re-authorization.

**Implementation Priority:** HIGH -- novel security mechanism that differentiates AgentHub.

### 4.3 SCIM Extension for Agents (IETF)

**Key Ideas:**
- Draft-abbey-scim-agent-extension-00: extends SCIM 2.0 with two new resource types: `Agents` and `AgenticApplications`
- An Agent has its own identifier, metadata, and privileges independent of runtime environment
- An AgenticApplication exposes one or more agents to users
- Includes `lastAccessed` timestamp for stale access detection and least privilege enforcement
- Microsoft actively involved in platform-neutral SCIM enhancement discussions
- Draft-wahl-scim-agent-schema-01: defines schema for transporting agentic identities via SCIM

**Product Implications for AgentHub:**
- Implement SCIM endpoints for agent provisioning and deprovisioning
- Support SCIM-based agent lifecycle management: create, read, update, delete, disable
- The `AgenticApplications` resource type maps to AgentHub's registry concept
- `lastAccessed` tracking enables automatic credential rotation for dormant agents
- SCIM compatibility enables integration with enterprise IdPs (Okta, Azure AD, etc.)

**Competitive Advantage:** SCIM support makes AgentHub pluggable into existing enterprise identity infrastructure.

**Implementation Priority:** MEDIUM -- important for enterprise adoption but not day-one critical.

### 4.4 OAuth 2.0 On-Behalf-Of Extension for AI Agents

**Key Ideas:**
- Draft-oauth-ai-agents-on-behalf-of-user-02 (Aug 2025)
- Introduces `requested_actor` parameter in authorization requests to identify the specific agent requiring delegation
- Introduces `actor_token` parameter in token requests to authenticate the agent during code-for-token exchange
- Ensures secure delegation with explicit user consent via front-channel authorization
- Standard OAuth Token Exchange (RFC 8693) doesn't natively support obtaining explicit user consent for agents via front channel

**Product Implications for AgentHub:**
- Support the OBO flow for agents acting on behalf of human users
- AgentHub's delegation tokens should be usable as `actor_tokens` in OBO exchanges
- The `requested_actor` claim should reference the agent's AgentHub identity
- This bridges the gap between human-initiated workflows and agent-autonomous execution

**Competitive Advantage:** Proper OBO support means AgentHub can mediate between human identity systems and agent identity systems.

**Implementation Priority:** HIGH -- critical for enterprise scenarios where agents act on behalf of employees.

### 4.5 SPIFFE/SPIRE for Agent Identity

**Key Ideas:**
- CNCF graduated project providing cryptographically verifiable workload identities without long-lived secrets
- SPIFFE IDs ideal for AI agents: each gets a unique ID proving origin, capabilities, and trust level
- Format: `spiffe://trust-domain/workload-identifier` (e.g., `spiffe://agenthub.io/agent/order-processor`)
- HashiCorp Vault 1.21+ natively supports SPIFFE authentication and can issue X509-SVIDs
- SPIFFE + OAuth token-exchange patterns becoming standard infrastructure for CI/CD, microservices, and AI agents
- WIMSE (Workload Identity in Multi-System Environments) extending SPIFFE for cross-domain scenarios

**Product Implications for AgentHub:**
- Issue SPIFFE IDs for all registered agents as their foundational workload identity
- Use SPIFFE SVIDs (X.509 or JWT) as the transport layer for agent authentication
- Integrate with SPIRE as an optional identity attestation backend
- Support SPIFFE federation for cross-organization agent trust

**Competitive Advantage:** SPIFFE gives AgentHub credibility with platform/infrastructure teams, not just security teams.

**Implementation Priority:** MEDIUM-HIGH -- foundational infrastructure identity that complements application-level OAuth tokens.

---

## Category 5: Academic Research

### 5.1 TRiSM for Agentic AI (arxiv, June 2025)

**Key Ideas:**
- Trust, Risk, and Security Management framework adapted for LLM-based Agentic Multi-Agent Systems (AMAS)
- Five pillars: Explainability, ModelOps, Application Security, Model Privacy, Governance
- Novel risk taxonomy for agentic AI: prompt injection, collusive agent behavior, memory poisoning, coordination failures
- New metrics: Component Synergy Score (CSS) for inter-agent collaboration quality, Tool Utilization Efficacy (TUE) for effective tool use
- Key finding: agents can recursively create sub-agents without constraints -- one incident showed 847 sub-agents spawned over 72 hours
- Cross-domain authorization with OAuth 2.1 works within single trust domains but falls short for cross-domain, highly autonomous, or asynchronous scenarios

**Product Implications for AgentHub:**
- Implement sub-agent spawn limits as a policy control (AgentHub already has max chain depth of 5)
- Add CSS and TUE as trust score components
- Build collusive behavior detection: flag when agents from different owners coordinate in suspicious patterns
- Memory poisoning protection: agents should not be able to modify each other's context/state

**Competitive Advantage:** Academic-grounded risk taxonomy gives AgentHub a defensible framework for trust decisions.

**Implementation Priority:** MEDIUM -- advanced trust features.

### 5.2 Zero-Trust Identity Framework for Agentic AI (arxiv, May 2025)

**Key Ideas:**
- Uses Decentralized Identifiers (DIDs) and Verifiable Credentials (VCs) for agent identity
- VCs encapsulate: capabilities, provenance, behavioral scope, security posture
- Unified global session management and policy enforcement layer for real-time control
- Consistent revocation across heterogeneous agent communication protocols
- Paradigm shift from persistent identity to session identity: Agent spawns -> gets fresh identity -> performs mission -> mission ends -> identity expires
- Dynamic, context-aware authorization: every request evaluated against real-time context, minimum necessary access for exact duration needed

**Product Implications for AgentHub:**
- Evaluate DID/VC integration as an alternative or complement to JWT-based credentials
- The "session identity" model maps to AgentHub's lease concept -- bind identity to lease TTL
- Implement "identity disc" pattern: fresh credential per mission, auto-expires on completion
- Cross-protocol revocation: ensure revocation propagates across MCP, A2A, and direct API channels

**Competitive Advantage:** DID/VC support positions AgentHub for decentralized/Web3 agent ecosystems.

**Implementation Priority:** LOW-MEDIUM -- forward-looking but not immediate market demand.

### 5.3 Authenticated Delegation and Authorized AI Agents (arxiv, Jan 2025)

**Key Ideas:**
- Each agent in a delegation chain should have narrower permissions than the previous one (scope attenuation)
- This least-privilege principle often fails in practice
- Emerging token formats for delegation: Macaroons, Biscuits, and Wafers -- tokens where holders can add layers that only reduce permissions
- Each sub-agent adds a signed, append-only caveat that narrows scope, forming a verifiable chain
- End-to-end verifiability: resource server at the end of the chain must cryptographically verify the entire delegation path back to the original user

**Product Implications for AgentHub:**
- Evaluate Biscuit tokens as an alternative to JWTs for delegation chains (append-only attenuation is natively supported)
- Implement end-to-end chain verification at the resource server side
- Add delegation chain visualization in the AgentHub dashboard
- Consider supporting multiple token formats: JWT for standard OAuth, Biscuit for delegation chains

**Competitive Advantage:** Biscuit-based delegation tokens are provably attenuating -- mathematically impossible to escalate privileges.

**Implementation Priority:** MEDIUM -- significant technical advantage but requires new token format adoption.

---

## Category 6: Competitor Analysis

### 6.1 Cyata ($8.5M Seed, July 2025)

**Positioning:** "The Control Plane for Agentic Identity"

**Product Features:**
- Automated discovery: continuously scans desktop and SaaS environments to find all AI identities and permissions
- Forensic observability: audit trails with unique "intent capture" -- agents must justify reasoning in real-time
- Granular access control: just-in-time permissions with HITL approvals for sensitive operations
- SIEM/SOAR/compliance integration (PCI, SOC 2, ISO 27001)

**Team:** Unit 8200, Cellebrite, Check Point alumni. CEO Shahar Tal is a 20-year cybersecurity veteran.

**AgentHub Advantage Over Cyata:**
- Cyata is detection/visibility-first (find agents, observe them, then control). AgentHub is identity-first (agents get identity at birth, controlled from creation)
- Cyata doesn't appear to have protocol-level integration (MCP, A2A). AgentHub can be protocol-native
- Cyata's "intent capture" is novel -- AgentHub should implement equivalent reasoning audit trails

**Competitive Response:** Ship intent/reasoning audit logs. Emphasize that "finding agents after deployment" is reactive; "issuing identity before deployment" is proactive.

### 6.2 Aembit ($25M+ Series A, Oct 2025 Agent IAM Launch)

**Positioning:** "IAM for Agentic AI and Workloads"

**Product Features:**
- **Blended Identity:** Each agent gets its own verified identity AND can be bound to the human it represents, creating a single traceable identity
- **MCP Identity Gateway:** Authenticates agents, enforces policy, performs token exchange for MCP tool access without exposing credentials to the agent runtime
- Secretless access and real-time policy enforcement across any environment
- Named "Overall ID Management Solution of the Year" (2025 CyberSecurity Breakthrough Awards)
- Hosted NHIcon 2026 conference (Jan 27)

**Team:** Established non-human identity company expanding into agents.

**AgentHub Advantage Over Aembit:**
- Aembit's MCP Identity Gateway is strong -- AgentHub needs equivalent MCP mediation capability
- Aembit's "Blended Identity" (human+agent) is a key concept AgentHub should implement
- Aembit comes from workload identity (infrastructure-level); AgentHub comes from agent registry/delegation (application-level)
- AgentHub has richer delegation chain support (6-stage lifecycle, budget escrow, scope attenuation)

**Competitive Response:** The "Blended Identity" concept is compelling and should be adopted. AgentHub's deeper delegation model and policy engine are differentiators.

### 6.3 Strata Identity (Maverics Platform, July 2025)

**Positioning:** "Identity Orchestration for AI Agents"

**Product Features:**
- Short-lived, scoped credentials at runtime
- Fine-grained, policy-as-code authorization with HITL approval for sensitive actions
- Full auditability: logs every agent decision and MCP-initiated API call
- Named as Sample Vendor by Gartner in "Agentic Identities" category (Sept 2025)
- Research finding: only 18% of security leaders are highly confident their IAM can manage agent identities

**Key Insight from Strata:** "By 2026, 30% of enterprises will rely on AI agents that act independently." And: "40% of enterprise apps will integrate task-specific agents by 2026."

**AgentHub Advantage Over Strata:**
- Strata is an identity orchestration layer (mediates between existing IdPs). AgentHub is a purpose-built agent IAM
- Strata maps legacy human IAM concepts to agents. AgentHub designs agent identity from first principles
- Strata's policy-as-code is strong -- AgentHub's ABAC engine is comparable

**Competitive Response:** Position as purpose-built vs. retrofitted. Strata's strength is enterprise integration; AgentHub's is protocol-native agent identity.

### 6.4 Microsoft Entra Agent ID (Preview, June 2025)

**Product Features:**
- Agent identities modeled as applications (agent identities) and users (agent users)
- Conditional Access extended to agents: same Zero Trust controls as human users but with agent-specific logic
- Entra ID Protection: detects and blocks agents exhibiting risky behavior
- Lifecycle management: entitlement management, access packages, sponsor/owner assignment
- No passwords/SMS/passkeys -- software-appropriate credential types only
- Integration with Security Copilot, Microsoft 365 Copilot, and third-party agents

**AgentHub vs. Microsoft:**
- Microsoft's advantage: massive enterprise distribution, integration with M365/Azure ecosystem
- AgentHub's advantage: cloud-agnostic, protocol-native (MCP, A2A), supports any agent framework
- Microsoft's approach is Azure-centric; AgentHub is infrastructure-independent
- Microsoft doesn't support delegation chains or scope attenuation natively

**Competitive Response:** Position as the multi-cloud, multi-framework alternative. Emphasize that agents don't live exclusively in Azure. Offer Entra integration as one of many identity provider backends.

### 6.5 Okta (Auth0 for AI Agents, Sept 2025)

**Product Features:**
- Auth0 for AI Agents (GA Oct 2025): authentication, token management, async approvals, fine-grained access controls
- Cross App Access (XAA): new open protocol extending OAuth for agent-to-app and app-to-app access at scale (EA Jan 2026)
- Agent lifecycle security: identity security fabric extended to NHIs
- Verifiable credentials support

**AgentHub vs. Okta:**
- Okta's XAA protocol could become a competing standard to A2A for agent-app access
- Okta has massive developer adoption via Auth0
- AgentHub's advantage: purpose-built for agent-to-agent scenarios, not retrofitted app-to-app
- AgentHub should integrate WITH Okta/Auth0 as an identity provider rather than compete

**Competitive Response:** Build Auth0 integration. Position AgentHub as the agent-specific layer that sits between Okta (human identity) and agent workloads.

### 6.6 HashiCorp Vault (IBM) for Agent Identity

**Product Features:**
- Vault 1.21+: native SPIFFE authentication for NHI workloads
- Issues SPIFFE IDs (X509-SVIDs) to authenticated agent workloads
- Dynamic secrets with just-in-time provisioning and automatic rotation
- MCP server for AI tools to detect leaked secrets and misconfigurations
- Terraform and Vault MCP servers expose RBAC endpoints for AI agents

**AgentHub vs. Vault:**
- Vault is a secrets manager extending to identity. AgentHub is an identity platform
- Vault's SPIFFE support is complementary -- AgentHub should use Vault as a secrets backend
- Vault lacks delegation chains, scope attenuation, trust scoring

**Competitive Response:** Partner, don't compete. Use Vault for credential storage while AgentHub handles identity lifecycle, delegation, and policy.

### 6.7 Palo Alto Networks / CyberArk ($25B Acquisition, Feb 2026)

**Key Development:** Palo Alto closed $25B acquisition of CyberArk on Feb 11, 2026. "Cortex AgentiX" product line expected late 2026 incorporating CyberArk's vaulting technology for agent-to-agent communications.

**Impact on AgentHub:** This is the biggest threat on the horizon. Palo Alto + CyberArk creates a security giant with deep enterprise relationships and a stated agent identity product roadmap. AgentHub has 10-12 months before Cortex AgentiX ships.

**Competitive Response:** Move fast. Ship before Cortex AgentiX. Emphasize open standards, protocol-native design, and multi-vendor neutrality vs. Palo Alto's proprietary stack.

### 6.8 Other Notable Players

- **GitGuardian** ($50M Series C, Feb 2026): NHI secrets detection, not direct competitor but adjacent
- **Astrix Security** ($85M total, including Anthropic investment): AI agent identity governance
- **Defakto** ($30.75M Series B): NHI security
- **Riptides** ($3.3M pre-seed): SPIFFE + OAuth2 convergence for agentic era

---

## Cross-Cutting Themes & Synthesis

### Theme 1: The Ephemeral Identity Paradigm
Every major source agrees: agent identities should be ephemeral, not persistent. The pattern is:
- Agent spawns -> receives fresh, scoped credential
- Credential bound to specific task/session/sandbox
- Task completes -> credential expires automatically
- No credential reuse across contexts

**AgentHub Action:** Ensure all credentials have mandatory expiry. Add "mission-scoped" credentials that auto-expire when the associated task completes.

### Theme 2: Delegation Chains Are the Killer Feature
AAP, Agentic JWT, and academic research all converge on delegation chains as THE critical authorization primitive for multi-agent systems. Key requirements:
- Immutable, append-only chains
- Scope attenuation at every hop (child subset of parent)
- Depth limits (AgentHub already has max 5)
- End-to-end cryptographic verification
- Parent-child JTI linking

**AgentHub Action:** Upgrade delegation tokens to be fully AAP-compliant with all delegation claims. Evaluate Biscuit tokens as a complementary format.

### Theme 3: Protocol-Native Is the Moat
The winners in this market will be integrated at the protocol level (MCP, A2A, AAP), not bolted on as middleware. Key integration points:
- MCP: serve as the Authorization Server discovered via PRM
- A2A: issue and validate Agent Cards, manage auth credentials
- AAP: issue compliant tokens with agent/capability/task/oversight/delegation claims
- SCIM: support agent provisioning/deprovisioning via enterprise IdPs

**AgentHub Action:** Prioritize MCP AS integration, A2A Agent Card management, and AAP token issuance.

### Theme 4: Blended Identity (Human + Agent)
Aembit's "Blended Identity" concept resonates across multiple sources: agents often act on behalf of humans, and the identity system must maintain this link. The OAuth OBO extension formalizes this. Key requirements:
- Agent has its own identity AND can be bound to the human it represents
- Single traceable identity for each agent action
- Delegation from human -> agent uses standard OAuth + requested_actor

**AgentHub Action:** Implement blended identity: each agent has a standalone identity that can be bound to a human principal for OBO scenarios.

### Theme 5: Real-Time Revocation Is Non-Negotiable
Anthropic's cyber espionage disclosure, Zero Trust research, and all competitors agree: revocation must be sub-second, not eventual. Requirements:
- Kill switch within 1 second (AgentHub already specifies this)
- Cascade revocation: revoking a credential revokes all downstream tokens
- Cross-protocol revocation: propagate across MCP, A2A, and direct API channels

**AgentHub Action:** AgentHub's 1-second revocation target is correct. Add cross-protocol revocation propagation.

### Theme 6: Agent Checksums for Tamper-Evident Identity
The Agentic JWT proposal introduces "agent checksums" -- a hash of the agent's system prompts, tools, and configurations. If anything changes, the identity changes, triggering re-authorization. This is a powerful concept for detecting tampered or modified agents.

**AgentHub Action:** Implement agent configuration checksums as part of credential issuance. Store the checksum in the credential. Validate on every request.

---

## Prioritized Product Roadmap Recommendations

### Tier 1: Ship in Next 90 Days (Critical, Market Timing)
1. **AAP-Compliant Token Issuance** -- Issue JWTs with agent/capabilities/task/oversight/delegation claims per IETF draft-aap-oauth-profile-01
2. **MCP Authorization Server** -- Serve as the OAuth 2.1 AS for MCP clients, discoverable via PRM at `.well-known/oauth-protected-resource`
3. **A2A Agent Card Management** -- Generate, sign, and host Agent Cards at `/.well-known/agent.json` for registered agents
4. **Blended Identity (Human+Agent)** -- Bind agent identities to human principals for OBO scenarios
5. **Agent Configuration Checksums** -- Hash agent config at credential issuance, validate on every request
6. **SDK Integration Package** -- Python/TypeScript packages for OpenAI Agents SDK and LangChain that auto-assign identity at agent creation

### Tier 2: Ship in 90-180 Days (Competitive Differentiation)
7. **SCIM Agent Provisioning Endpoints** -- Enable enterprise IdP integration for agent lifecycle management
8. **SPIFFE ID Issuance** -- Issue SPIFFE IDs as foundational workload identity for all agents
9. **Intent/Reasoning Audit Logs** -- Capture not just what agents did, but why (matching Cyata's forensic observability)
10. **Cross-Protocol Revocation** -- Propagate revocation across MCP, A2A, and API channels simultaneously
11. **Behavioral Drift Detection** -- Alert when agent actions deviate from established patterns
12. **Credential Blast Radius Analysis** -- Show what can be reached if a credential is compromised

### Tier 3: Ship in 180-360 Days (Market Leadership)
13. **Biscuit Token Support** -- Append-only attenuation tokens for provably secure delegation chains
14. **Agentic JWT Grant Type** -- Support `agent_checksum` OAuth grant per draft-goswami-agentic-jwt-00
15. **Sub-Agent Spawn Controls** -- Policy-based limits on recursive agent creation
16. **DID/VC Support** -- Decentralized Identifiers and Verifiable Credentials for cross-org federation
17. **Adversarial Agent Testing** -- Use agents to probe authorization boundaries of other agents
18. **Kubernetes Agent Sandbox Integration** -- Bind identity lifecycle to sandbox lifecycle

---

## Market Intelligence Summary

| Signal | Data Point | Implication for AgentHub |
|--------|-----------|--------------------------|
| Market Size | NHI market $9.45B (2024) -> $18.71B (2030) | Massive TAM, growing fast |
| Adoption | 40% enterprise apps with agents by end 2026 (Gartner) | Demand is imminent, not future |
| Identity Ratios | Machine-to-human identity ratio exceeds 17:1 | Scale is the challenge |
| Confidence Gap | Only 18% of security leaders confident in agent IAM | Market is unsatisfied |
| Threat Catalyst | First AI-orchestrated cyberattack (Anthropic, Nov 2025) | Fear drives buying |
| Standards | 5+ IETF drafts actively standardizing agent auth | Standards window is NOW |
| Big Threat | Palo Alto + CyberArk ($25B, Feb 2026) -> Cortex AgentiX | 10-12 months to establish position |
| Funding | $200M+ deployed into NHI/agent identity startups (2025) | VCs are validating the category |
| Cancellation Risk | 40%+ agentic AI projects canceled by 2027 (Gartner) | Focus on must-have, not nice-to-have |

---

## Sources

### Anthropic
- [MCP Authentication on AWS](https://aws.amazon.com/blogs/opensource/open-protocols-for-agent-interoperability-part-2-authentication-on-mcp/)
- [MCP Specification 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25)
- [Framework for Safe and Trustworthy Agents](https://www.anthropic.com/news/our-framework-for-developing-safe-and-trustworthy-agents)
- [Agent Skills Open Standard](https://thenewstack.io/agent-skills-anthropics-next-bid-to-define-ai-standards/)
- [Code Execution with MCP](https://www.anthropic.com/engineering/code-execution-with-mcp)
- [AI Espionage Disclosure & Zero Trust](https://xage.com/blog/anthropics-ai-espionage-disclosure-marks-a-new-era-zero-trust-must-be-the-response/)
- [Aembit Analysis of Anthropic AI Attack](https://aembit.io/blog/anthropic-disruption-of-an-ai-run-attack-and-what-it-means-for-agentic-identity/)
- [Claude System Cards](https://www.anthropic.com/system-cards)

### OpenAI
- [Agents SDK GitHub](https://github.com/openai/openai-agents-python)
- [Agents SDK Documentation](https://openai.github.io/openai-agents-python/)
- [Introducing AgentKit](https://openai.com/index/introducing-agentkit/)
- [Safety in Building Agents](https://platform.openai.com/docs/guides/agent-builder-safety)
- [Guardrails Documentation](https://openai.github.io/openai-agents-python/guardrails/)
- [New Tools for Building Agents](https://openai.com/index/new-tools-for-building-agents/)

### Google / A2A
- [A2A Protocol Specification](https://a2a-protocol.org/latest/)
- [Announcing A2A Protocol](https://developers.googleblog.com/en/a2a-a-new-era-of-agent-interoperability/)
- [A2A Getting an Upgrade](https://cloud.google.com/blog/products/ai-machine-learning/agent2agent-protocol-is-getting-an-upgrade)
- [Linux Foundation A2A Project](https://www.linuxfoundation.org/press/linux-foundation-launches-the-agent2agent-protocol-project-to-enable-secure-intelligent-communication-between-ai-agents)
- [Kubernetes Agent Sandbox](https://opensource.googleblog.com/2025/11/unleashing-autonomous-ai-agents-why-kubernetes-needs-a-new-standard-for-agent-execution.html)
- [Agent Sandbox GitHub](https://github.com/kubernetes-sigs/agent-sandbox)
- [Lessons from 2025 on Agents and Trust](https://cloud.google.com/transform/ai-grew-up-and-got-a-job-lessons-from-2025-on-agents-and-trust)

### IETF Standards
- [AAP OAuth Profile (draft-01)](https://datatracker.ietf.org/doc/draft-aap-oauth-profile/)
- [AAP Protocol Website](https://www.aap-protocol.org/)
- [Agentic JWT Draft](https://datatracker.ietf.org/doc/draft-goswami-agentic-jwt/)
- [Agentic JWT Research Paper](https://arxiv.org/abs/2509.13597)
- [OAuth AI Agents On-Behalf-Of User](https://datatracker.ietf.org/doc/draft-oauth-ai-agents-on-behalf-of-user/)
- [SCIM Agent Extension Draft](https://datatracker.ietf.org/doc/draft-scim-agent-extension/)
- [SCIM Agentic Identity Schema](https://datatracker.ietf.org/doc/draft-wahl-scim-agent-schema/)
- [AI Agent Security Requirements Draft](https://datatracker.ietf.org/doc/draft-ni-a2a-ai-agent-security-requirements/)
- [AI Agent Discovery and Invocation Draft](https://datatracker.ietf.org/doc/draft-cui-ai-agent-discovery-invocation/)

### SPIFFE / Workload Identity
- [HashiCorp: SPIFFE for Agentic AI](https://www.hashicorp.com/en/blog/spiffe-securing-the-identity-of-agentic-ai-and-non-human-actors)
- [HashiCorp: Zero Trust for Agentic Systems](https://www.hashicorp.com/en/blog/zero-trust-for-agentic-systems-managing-non-human-identities-at-scale)
- [HashiCorp Vault AI Agent Identity](https://developer.hashicorp.com/validated-patterns/vault/ai-agent-identity-with-hashicorp-vault)
- [SPIFFE Meets OAuth2 for Agentic AI](https://riptides.io/blog-post/spiffe-meets-oauth2-current-landscape-for-secure-workload-identity-in-the-agentic-ai-era)
- [Solo.io: Agent IAM with SPIFFE](https://www.solo.io/blog/agent-identity-and-access-management---can-spiffe-work)
- [CyberArk Workload Identity Day Zero](https://securityboulevard.com/2025/11/workload-and-agentic-identity-at-scale-insights-from-cyberarks-workload-identity-day-zero/)

### MCP Authorization
- [Oso: Authorization for MCP](https://www.osohq.com/learn/authorization-for-ai-agents-mcp-oauth-21)
- [Aembit: MCP OAuth 2.1 PKCE](https://aembit.io/blog/mcp-oauth-2-1-pkce-and-the-future-of-ai-authorization/)
- [Stytch: MCP Auth Servers](https://stytch.com/blog/mcp-authentication-and-authorization-servers/)
- [MCP Authorization Tutorial](https://modelcontextprotocol.io/docs/tutorials/security/authorization)

### Competitors
- [Cyata Website](https://cyata.ai/)
- [Cyata Launch from Stealth](https://finance.yahoo.com/news/cyata-emerges-stealth-8-5m-110000602.html)
- [Aembit IAM for Agentic AI](https://aembit.io/press-release/aembit-introduces-identity-and-access-management-for-agentic-ai/)
- [Aembit: Emerging Identity Imperatives](https://aembit.io/blog/the-emerging-identity-imperatives-of-agentic-ai/)
- [Strata: Identity Orchestration for Agents](https://www.strata.io/blog/agentic-identity/introducing-identity-orchestrationai-agents/)
- [Strata: New Identity Playbook for 2026](https://www.strata.io/blog/agentic-identity/new-identity-playbook-ai-agents-not-nhi-8b/)
- [Strata in Gartner Emerging Tech Report](https://www.strata.io/resources/news/gartner-agentic-identities-sample-vendor-2025/)
- [Microsoft Entra Agent ID](https://learn.microsoft.com/en-us/entra/agent-id/identity-platform/agent-identities)
- [Entra Agent ID Announcement](https://techcommunity.microsoft.com/blog/microsoft-entra-blog/announcing-microsoft-entra-agent-id-secure-and-manage-your-ai-agents/3827392)
- [Okta Auth0 for AI Agents](https://www.okta.com/newsroom/press-releases/okta-platform-innovation/)
- [Okta Cross App Access (XAA)](https://siliconangle.com/2025/09/25/okta-expands-identity-fabric-ai-agent-lifecycle-security-cross-app-access-verifiable-credentials/)
- [Palo Alto + CyberArk Acquisition](https://markets.financialcontent.com/wral/article/marketminute-2026-2-13-the-identity-fortress-palo-alto-networks-closes-25-billion-acquisition-of-cyberark-to-secure-the-era-of-ai-agents)

### Academic Research
- [TRiSM for Agentic AI](https://arxiv.org/abs/2506.04133)
- [Zero-Trust Identity Framework for Agentic AI](https://arxiv.org/abs/2505.19301)
- [Authenticated Delegation and Authorized AI Agents](https://arxiv.org/abs/2501.09674)
- [Okta: Fixing AI Agent Delegation](https://www.okta.com/blog/ai/agent-security-delegation-chain/)
- [Oso: Setting Permissions for AI Agents](https://www.osohq.com/learn/ai-agent-permissions-delegated-access)

### Market Data
- [Gartner: 40% Enterprise Apps with Agents by 2026](https://www.gartner.com/en/newsroom/press-releases/2025-08-26-gartner-predicts-40-percent-of-enterprise-apps-will-feature-task-specific-ai-agents-by-2026-up-from-less-than-5-percent-in-2025)
- [NHI Market Report 2024-2030](https://www.globenewswire.com/news-release/2026/02/05/3232734/0/en/Non-Human-Identity-Solutions-Global-Report-2024-2025-2030-AI-and-Automation-Integration-Identity-Threat-Detection-and-Response-Ecosystem-Convergence-and-Cloud-Native-Security-Drive.html)
- [Identity Security Funding Soars](https://news.crunchbase.com/cybersecurity/identity-security-startup-funding-ai-agents-sam-altman-world-orb/)
- [GitGuardian $50M Series C](https://blog.gitguardian.com/series-c-announcement/)
- [Cross-Cloud Agent Ecosystems](https://medium.com/@dave-patten/cross-cloud-agent-ecosystems-how-aws-azure-and-gcp-are-shaping-mcp-a2a-and-secure-agent-088fcc57ee7c)
- [NVIDIA Agent Sandbox Security](https://developer.nvidia.com/blog/practical-security-guidance-for-sandboxing-agentic-workflows-and-managing-execution-risk/)
- [WorkOS: SCIM for AI](https://workos.com/blog/scim-agents-agentic-applications)
- [Ephemeral Identity for Agents](https://unmitigatedrisk.com/?p=1075)

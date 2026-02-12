# Research Insights (for AgentHub governance)

Updated: 2026-02-12

## Anthropic
1. Start with simpler, deterministic workflows before adding complex autonomous loops.
2. Multi-agent systems can improve quality substantially on hard tasks but can materially increase token usage/cost.
3. Prompt and tool safety guardrails must be explicit and testable.

Sources:
- https://www.anthropic.com/engineering/building-effective-agents
- https://www.anthropic.com/engineering/built-multi-agent-research-system

## OpenAI docs and blogs
1. Use strict schemas/structured outputs for tool reliability.
2. Tool calling may require explicit handling to avoid duplicates/ordering issues; deterministic validators are required.
3. Eval-driven development is required for production-grade agents.

Sources:
- https://platform.openai.com/docs/guides/function-calling
- https://platform.openai.com/docs/guides/evals
- https://platform.openai.com/docs/guides/agents
- https://openai.com/index/new-tools-for-building-agents/

## OpenAI developer forums
1. Practitioners report occasional duplicate/parallel tool-call edge cases and schema reliability concerns.
2. Robust production systems implement dedupe/idempotency and strict response validation.

Sources:
- https://community.openai.com/t/model-tries-to-call-unknown-function-multi-tool-use/1839912
- https://community.openai.com/t/new-openai-api-tools-and-responses-discussion/1145014
- https://community.openai.com/t/function-calling-returns-empty-arguments-object/1943089
- https://community.openai.com/t/responses-api-generating-multiple-duplicated-function-calls/2484477

## Reddit (anecdotal operator pain points)
1. Local and smaller models can struggle with reliable tool use without strong scaffolding.
2. Tool-calling loops and orchestration bugs are a common production complaint.
3. Teams repeatedly recommend strict schemas, retries with guardrails, and deterministic checks.

Sources:
- https://www.reddit.com/r/openwebui/comments/1mf0h1t/this_whole_tool_calling_loop_does_not_work/
- https://www.reddit.com/r/OpenAI/comments/1f2f74f/building_with_openai_tool_calls_concerns/
- https://www.reddit.com/r/LocalLLaMA/comments/1m2gq23/any_local_models_that_are_really_reliable_for/

## How this research changed our standards
1. Added lease-first acquisition model instead of persistent-by-default installs.
2. Added hard budget guardrails (80/100/120).
3. Added mandatory per-segment evidence and plan/doc updates.
4. Added strict schema and idempotency requirements across all write paths.

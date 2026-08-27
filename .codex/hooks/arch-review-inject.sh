#!/bin/bash

INPUT=$(cat)
PROMPT=$(echo "$INPUT" | jq -r '.user_prompt // .message // empty' 2>/dev/null)

if [ -z "$PROMPT" ]; then
    exit 0
fi

if echo "$PROMPT" | grep -qiE '(implement|add|create|build|fix|refactor|modify|update|review).*(feature|service|agent|task|handler|model|component|module|endpoint|workflow|architecture|codebase)'; then
    cat << 'EOF'
{"additionalContext":"AGENTHUB ARCHITECTURE: Read AGENTS.md, CLAUDE.md, and .github/ai-review/senior-review.md. Search identity, registry, policy, delegation, discovery, lease, federation, provenance, billing, marketplace, and runtime modules. Preserve scope attenuation, revocation-aware verification, policy signing, object authorization, replay safety, and truthful simulated-versus-real execution claims."}
EOF
fi

exit 0

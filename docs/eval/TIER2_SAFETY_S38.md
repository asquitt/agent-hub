# Tier-2 Safety Eval Harness (S38)

## Objective
Provide deterministic regression coverage for high-risk prompt classes before promotion:
- prompt injection,
- secret exfiltration,
- jailbreak attempts.

## Implementation
- Runner entrypoint: `run_tier2_safety_eval` in `src/eval/runner.py`.
- Detection strategy: pattern-based category detectors with fixed corpus and deterministic seed.
- Output contract:
  - `tier = tier2_safety`
  - `suite_id = tier2-safety-v1`
  - structured `findings` per test case,
  - aggregate `safety_category_results`,
  - key metrics including `attack_detection_rate`, `false_positive_count`, `false_negative_count`.

## CLI
Run tier-2 only:
```bash
python3 tools/eval/agenthub_eval.py eval --manifest tests/eval/fixtures/three-capability-agent.yaml --tier tier2
```

Run composite tiers:
```bash
python3 tools/eval/agenthub_eval.py eval --manifest tests/eval/fixtures/three-capability-agent.yaml --tier all
```

## Regression Gates
- Attacks expected to be blocked must remain blocked.
- Benign prompts must not trigger false positives.
- Tier-2 output must persist in eval storage with structured findings.

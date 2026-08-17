## Customer and system impact

What behavior changes, who or what is affected, and which product or operational boundary owns it?

## Scope and exclusions

- In scope:
- Explicitly excluded:
- Unrelated work preserved:

## Exact candidate

- Default branch and base SHA:
- Candidate branch and head SHA:
- Candidate tree SHA:
- Merge strategy: merge commit

## Verification evidence

| Property | Command or probe | Result | Evidence identity |
|---|---|---|---|
| Focused behavior |  |  |  |
| Invalid or failure case |  |  |  |
| Changed-file quality gates |  |  |  |
| Preview or runtime behavior, if required |  |  |  |

## Independent review

- Required for this change: yes / no, with reason
- Exact reviewed base and head:
- Verdict:
- Remaining HIGH findings:
- Remaining MEDIUM findings:

## Release safety

- Data or migration impact:
- Security, tenant, provider, or persistence impact:
- Observability signal and expected steady state:
- Rollback target and procedure:
- Fixture, task, provider, and external-state cleanup:

## AgentHub acceptance

- [ ] OAuth scope attenuation, wildcard authority, revocation, policy signing, and object ownership are covered where applicable.
- [ ] Real execution is distinguished from simulation, and replay or lease behavior is proven for affected paths.

## Readiness checklist

- [ ] This PR contains one coherent customer-impact or operational slice.
- [ ] The remote PR head matches the candidate SHA above.
- [ ] Focused tests cover the changed property and a relevant failure case.
- [ ] Required changed-file gates pass; unavailable evidence is labeled unavailable, not green.
- [ ] Material changes have blocker-free independent review of the exact current base-to-head diff.
- [ ] Required preview, deployment, or public behavior is proven against the named revision.
- [ ] Rollback and cleanup are concrete.
- [ ] No unrelated dirty work or secrets are included.
- [ ] The PR is still draft if any required item above remains unresolved.

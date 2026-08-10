# Experiment Summary

Generated: `2026-08-10T23:44:59.944005+00:00`

## Valid workflows

- Completion: **250/250 (100.0%)**
- Reconstructable with a valid receipt chain: **250/250 (100.0%)**
- Median artifacts / receipts per case: **12.0 / 12.0**

## Invariant-directed fault and mutation tests

| Test | Mapped invariant | Strict block rate | Targeted-ablation admit rate | Collapsed admit rate |
|---|---|---:|---:|---:|
| silent_promotion | I1/I2: typed standing and no implicit promotion | 100.0% | 100.0% | 100.0% |
| self_authorization | I3: no unilateral effect authorization | 100.0% | 100.0% | 100.0% |
| context_replay | I4: context binding | 100.0% | 100.0% | 100.0% |
| policy_outage_fallback | I5: failure non-escalation | 100.0% | 100.0% | 100.0% |
| unapproved_release | I6: communication-release separation | 100.0% | 100.0% | 100.0% |
| in_place_overwrite | I7: successor correction | 100.0% | 100.0% | 100.0% |
| outcome_reentry | I8: outcome re-entry | 100.0% | 100.0% | 100.0% |
| assurance_tamper | I10: assurance independence/integrity | 100.0% | 100.0% | 100.0% |
| expired_authorization | I4 extension: time-bound context | 100.0% | 100.0% | 100.0% |

## Exhaustive abstract-state exploration

- Strict profile: **51 reachable states; 0 reachable bad states**
- Collapsed profile: **6729 reachable states; 9 reachable bad states**
- Every single-control ablation reached exactly its corresponding bad state and no other cataloged bad state.

## Runtime and receipt overhead

| Profile | Median µs/case | P95 µs/case | Receipt bytes/case | Artifacts/case | Receipts/case |
|---|---:|---:|---:|---:|---:|
| Strict | 1430.3 | 1872.8 | 10722.0 | 12.0 | 12.0 |
| Collapsed ablation | 1329.8 | 2001.0 | 9987.0 | 12.0 | 12.0 |

Median runtime ratio (strict / collapsed): **1.076×**

## Interpretation boundary

These results establish constructive feasibility for this implementation and show that the named guards mediate the corresponding synthetic transitions. They do not establish safety, compliance, general security, domain validity, or superiority over production architectures.

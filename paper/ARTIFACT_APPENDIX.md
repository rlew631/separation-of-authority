# Reproducibility Artifact Appendix

## Artifact purpose

This repository is a constructive realization of the paper's separation-of-authority model. It is intentionally a modular monolith: all authorities execute in one process, while artifact standing, state ownership, transition rights, policy authorization, and assurance receipts remain logically distinct.

## Implemented state classes

| Class | Implemented standing | Issuing logical authority |
|---|---|---|
| K | Accepted evidence or assertion | Knowledge authority |
| I | Derived result | Inference authority |
| C | Draft or released communication | Communication authority creates drafts; effect authority realizes consequential release |
| E | Proposed, authorized, or executed effect | Requesting authority proposes; policy authority authorizes; effect authority executes |
| O | Observed external/resulting state | Outcome observer |

## Context binding

Each artifact is bound to a digest over:

- case identifier;
- intended use;
- jurisdiction;
- authority scope;
- affected actor;
- policy version;
- inference method version;
- communication template version;
- effect target/connector version;
- context epoch.

## Receipt fields

Each transition receipt records:

- sequence and transition type;
- source artifact identifiers;
- destination artifact identifier;
- authority scope;
- requester and authorizer/policy identities;
- context and policy identifiers;
- artifact version;
- disposition;
- logical time;
- predecessor/supersession links;
- artifact digest metadata;
- previous receipt hash;
- signer identity and role;
- receipt hash and HMAC signature.

## Implemented invariant mapping

| Paper invariant | Runtime mechanism | Test or analysis |
|---|---|---|
| I1 Typed standing | Artifact class/status and signed producer identity | `silent_promotion` |
| I2 No implicit promotion | Only explicit knowledge acceptance produces governed K | `silent_promotion` |
| I3 No unilateral effect authorization | Policy-signed E:authorized required before execution | `self_authorization` |
| I4 Context binding | Context digest and authorization expiry checked at execution | `context_replay`, `expired_authorization` |
| I5 Failure non-escalation | Missing policy evaluation fails closed | `policy_outage_fallback` |
| I6 Communication-release separation | Draft C requires a separately authorized release effect | `unapproved_release` |
| I7 Successor correction | Corrections create new K with predecessor relation | `in_place_overwrite`; successor unit test |
| I8 Outcome re-entry | O requires explicit knowledge acceptance before becoming K | `outcome_reentry` |
| I9 Explicit write/supersession authority | Logical issuer identity and transition-specific APIs | silent-promotion and overwrite tests |
| I10 Assurance independence | HMAC-authenticated hash chain | `assurance_tamper` |

## Evaluation artifacts

- Controlled implementation trials: `results/experiment.json`
- Compact results table: `results/attack-results.csv`
- Human-readable summary: `results/summary.md`
- Complete receipt trace: `results/sample-ledger.jsonl`
- Complete artifact manifest: `results/sample-artifacts.json`
- Abstract-model counterexample traces: `results/experiment.json` under `abstract_model`

## Limitations

The artifact is not a production security boundary. It does not isolate keys, processes, hosts, or administrative domains. The abstract model is finite, monotonic, and constructed from the proposed transition rules; exhaustive exploration establishes consistency within that model, not correctness of arbitrary implementations. The fault suite is invariant-directed rather than independently discovered. The domain workflow is synthetic and deterministic.

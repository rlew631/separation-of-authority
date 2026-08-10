# Prototype Implementation and Controlled Evaluation

## Research questions

The prototype evaluates three implementation-level questions:

1. Can the proposed K/I/C/E/O state classes, governance roles, and transition receipts be realized in a small single-process system without relying on service decomposition?
2. Do the enabled controls reject invariant-directed mutations and failure paths, and do targeted ablations admit those same paths?
3. What runtime and receipt-storage overhead does the strict profile add relative to an otherwise equivalent profile with the controls disabled?

## Prototype

We implemented a deterministic Python reference kernel using only the standard library. The kernel represents accepted evidence (K), derived results (I), communication artifacts (C), effects (E), and observed outcomes (O) as signed typed artifacts. It binds consequential transitions to a decision-context digest and records each transition in an HMAC-authenticated hash chain. Separate logical principals issue knowledge, inference, communication, policy, effect, outcome, remedy, and assurance records. All principals execute in one process; the prototype therefore tests logical rather than network or microservice separation.

The worked workflow uses a synthetic administrative-benefit rule. It accepts an application record, derives eligibility, renders a draft notice, proposes and authorizes a record-changing effect, executes the effect, separately authorizes release of the notice, observes the resulting state, and explicitly accepts that observation as successor knowledge. A complete successful case emits 12 artifacts and 12 receipts.

## Experimental method

We ran 250 valid-workflow trials under the strict profile. We then defined nine invariant-directed fault or mutation tests. Each test was repeated 250 times over seeded, randomized synthetic application records. For each test we compared: (1) the strict profile; (2) a targeted ablation disabling the named control; and (3) a collapsed profile disabling all evaluated controls. An attempted violation was counted as admitted only when the prohibited transition completed or, for receipt tampering, when verification accepted the modified ledger.

We also encoded the transition rules as a finite monotonic abstract state machine and exhaustively explored its reachable state space. The abstract model contains the valid transition path and one prohibited transition for each evaluated control. This analysis is a consistency check between the stated invariants and the transition relation; it is not a proof about arbitrary implementations.

We additionally measured end-to-end runtime for 2000 cases after 25 warm-up cases. The strict and collapsed profiles execute the same successful 12-artifact workflow; the collapsed profile disables state-class checks, independent authorization, context and expiry checks, fail-closed behavior, release separation, successor and outcome controls, and receipt integrity. Measurements use a single process and should be interpreted as implementation-specific microbenchmarks rather than production capacity estimates.

## Results

All 250 of 250 strict-profile workflows completed, and all 250 produced a valid receipt chain from which all 12 context artifacts and the accepted outcome's transitive lineage could be reconstructed. The exhaustive abstract model reached 51 states under the strict profile with zero cataloged bad states. The collapsed profile reached 6729 states and all 9 cataloged bad states. Each single-control ablation reached exactly one bad state: the state corresponding to the disabled control.

| Test | Mapped invariant | Strict block rate | Targeted-ablation admit rate |
|---|---|---:|---:|
| silent_promotion | I1/I2: typed standing and no implicit promotion | 100.0% | 100.0% |
| self_authorization | I3: no unilateral effect authorization | 100.0% | 100.0% |
| context_replay | I4: context binding | 100.0% | 100.0% |
| policy_outage_fallback | I5: failure non-escalation | 100.0% | 100.0% |
| unapproved_release | I6: communication-release separation | 100.0% | 100.0% |
| in_place_overwrite | I7: successor correction | 100.0% | 100.0% |
| outcome_reentry | I8: outcome re-entry | 100.0% | 100.0% |
| assurance_tamper | I10: assurance independence/integrity | 100.0% | 100.0% |
| expired_authorization | I4 extension: time-bound context | 100.0% | 100.0% |

The strict profile's median end-to-end time was 1430.3 µs per case (P95 1872.8 µs), compared with 1329.8 µs (P95 2001.0 µs) for the collapsed ablation. The median runtime ratio was 1.076×. The strict profile emitted approximately 10722.0 serialized receipt bytes per case in this implementation.

## Interpretation

The results provide constructive evidence that the proposed authority distinctions can be encoded and enforced in a modular monolith. In this implementation, each selected control is necessary to block its corresponding synthetic transition: disabling that control admits the transition it mediates. The evaluation does not show that the architecture prevents unspecified attacks, improves decision accuracy or fairness, satisfies any legal instrument, or outperforms mature production systems. The ablations are intentionally aligned to the stated invariants, and the application rule, actors, policies, and effects are synthetic.

## Threats to validity

- **Construct validity:** each mutation operationalizes one narrow interpretation of an invariant; other violations may not be represented.
- **Internal validity:** the same authors designed the model, implementation, and tests. The targeted-ablation result establishes guard behavior, not independent security validation.
- **External validity:** one deterministic administrative workflow does not establish transfer to stochastic models, distributed systems, physical control, or real institutions.
- **Security validity:** HMAC keys are co-resident in the demonstration process. The artifact does not model hardware roots of trust, remote attestation, compromised hosts, or production identity infrastructure.
- **Performance validity:** Python microbenchmarks on one host are useful only for bounding this artifact's overhead. They are not platform benchmarks.
- **Normative validity:** explicit authority and receipts do not establish that the policy, institution, evidence, or resulting effect is legitimate or correct.

## Reproduction

Run `PYTHONPATH=src python -m unittest discover -s tests -v` and then `PYTHONPATH=src python -m soa.experiment --trials 250 --benchmark-cases 2000 --seed 20260806 --output results`. The machine-readable output is `results/experiment.json`; the per-test table is `results/attack-results.csv`; and `results/sample-ledger.jsonl` contains one complete strict-profile trace.

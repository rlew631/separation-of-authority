# Separation of Authority

A minimal, reproducible implementation of the core claim in **Separating Evidence, Inference, Communication, and Effect in Governed AI Systems**.

The repository demonstrates that logical authority separation can be enforced inside one Python process. It does not rely on microservice boundaries, an LLM, a knowledge graph, or an external policy engine.

## What is implemented

The kernel represents five typed state classes:

- **K — accepted evidence/assertions**
- **I — derived results**
- **C — communication artifacts**
- **E — proposed, authorized, and executed effects**
- **O — observed outcomes that do not automatically re-enter K**

Separate logical principals issue artifacts for knowledge, inference, communication, policy, effect execution, outcome observation, remedy, and assurance. Every artifact is context-bound and HMAC-signed. Every transition emits a hash-chained receipt.

The synthetic administrative workflow performs:

```text
candidate evidence
  -> K accepted
  -> I derived eligibility result
  -> C draft notice
  -> E proposed decision
  -> E policy authorization
  -> E executed record change
  -> E separately authorized notice release
  -> C released notice
  -> O observed result
  -> K accepted successor outcome
```

A successful case emits 12 artifacts and 12 transition receipts.

## Evaluation included

The artifact supplies four forms of evidence:

1. **Executable reference trace.** A valid end-to-end K/I/C/E/O workflow with reconstructable lineage.
2. **Invariant-directed fault and mutation tests.** Nine prohibited transitions are tested under the strict profile, their targeted single-control ablations, and a collapsed profile.
3. **Exhaustive abstract-state exploration.** A finite transition model is explored to a fixed point. The strict profile must contain no cataloged bad state; each single ablation must expose exactly its corresponding bad state.
4. **Runtime and receipt microbenchmark.** The strict and collapsed profiles execute the same successful workflow so the implementation-specific control overhead can be measured.

The tested violations are:

| Test | Control/invariant exercised |
|---|---|
| Silent I → K promotion | Typed standing; no implicit promotion |
| Inference self-authorizes effect | Independent effect authorization |
| Authorization replayed in another context | Context binding |
| Implicit authorization during policy outage | Failure non-escalation |
| Draft communication released without effect authorization | Communication/release separation |
| Accepted evidence overwritten under the same identifier | Successor correction |
| Outcome automatically treated as accepted evidence | Explicit outcome re-entry |
| Prior assurance receipt modified | Assurance integrity |
| Expired authorization executed | Time-bound authorization |

## Run it

Python 3.11 or later is sufficient. There are no runtime dependencies outside the standard library.

```bash
python3 -m venv .venv
source .venv/bin/activate
export PYTHONPATH=src

python -m unittest discover -s tests -v
python -m soa.demo
python -m soa.experiment \
  --trials 250 \
  --benchmark-cases 2000 \
  --seed 20260806 \
  --output results
```

Equivalent Make targets:

```bash
make test
make demo
make experiment
```

To use the installed console scripts instead of source-tree commands:

```bash
python -m pip install .
soa-demo
soa-experiment --trials 250 --benchmark-cases 2000 --seed 20260806 --output results
```

## Outputs

- `results/experiment.json` — machine-readable experiment record
- `results/attack-results.csv` — fault/ablation table
- `results/summary.md` — concise human-readable results
- `results/sample-ledger.jsonl` — one complete receipt chain
- `results/sample-artifacts.json` — artifacts from the same trace
- `paper/METHODS_AND_RESULTS.md` — manuscript-ready methods, results, and limitations section generated from the experiment
- `paper/ARTIFACT_APPENDIX.md` — artifact description for the paper or repository
- `paper/PAPER_REVISION_GUIDE.md` — changes required to frame the manuscript as a research article with a prototype evaluation

## Claim boundary

This reference implementation establishes only that:

- the proposed logical distinctions can be encoded in a modular monolith;
- the implemented guards reject the corresponding tested transitions;
- disabling a guard admits the transition it mediates in the defined fault model;
- the resulting traces can be reconstructed and their integrity checked;
- the implementation has measurable runtime and storage overhead.

It does **not** establish safety, security against unspecified adversaries, legal compliance, model accuracy, fairness, institutional legitimacy, production readiness, or superiority over existing systems. The deterministic rule, policy, identities, effects, and application records are synthetic. HMAC keys are co-resident in one process.

## Repository layout

```text
src/soa/
  model.py           typed artifacts, contexts, roles, enforcement profiles
  ledger.py          hash-chained transition receipts and verification
  core.py            single-process authority kernel and worked workflow
  abstract_model.py  exhaustive finite-state exploration
  experiment.py      fault injection, ablations, benchmark, artifact generation
  demo.py            one readable end-to-end trace

tests/
  test_workflow.py
  test_invariants.py
  test_abstract_model.py

paper/
  METHODS_AND_RESULTS.md
  ARTIFACT_APPENDIX.md
  PAPER_REVISION_GUIDE.md
```

## Research-artifact positioning

The implementation is intended to convert the manuscript from a paper that only argues for an architecture into one that also presents a constructive system, an executable transition model, controlled ablations, and measured results. Whether a submission is accepted by arXiv remains a moderation decision based on the complete manuscript; the presence of code alone is not sufficient.

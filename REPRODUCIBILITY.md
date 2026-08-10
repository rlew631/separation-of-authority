# Reproducibility Record

## Scope

The experiment is deterministic except for host-dependent timing and the UTC generation timestamp. Synthetic records are generated from a fixed pseudorandom seed.

## Reference command

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m soa.experiment \
  --trials 250 \
  --benchmark-cases 2000 \
  --seed 20260806 \
  --output results
```

## Expected logical results

The following should be stable across supported Python versions and hosts:

- every valid strict-profile workflow completes;
- every valid workflow has 12 artifacts and 12 receipts;
- every strict-profile prohibited transition is blocked;
- every targeted single-control ablation admits its mapped transition;
- the collapsed profile admits all cataloged prohibited transitions;
- the strict abstract model reaches no cataloged bad state;
- each single-control abstract-model ablation reaches exactly one mapped bad state;
- the collapsed abstract model reaches all cataloged bad states;
- modified protected receipts fail verification.

Timing values and the strict/collapsed timing ratio will vary by interpreter, host, power state, and background load.

## Output integrity

`results/experiment.json` records:

- experiment schema version;
- seed;
- Python and platform information;
- valid-workflow results;
- per-attack strict, targeted-ablation, and collapsed results;
- exhaustive abstract-state exploration results and counterexample traces;
- benchmark statistics;
- one sample context and lineage.

`results/sample-ledger.jsonl` can be independently parsed as one JSON object per line. Each protected entry includes the prior entry hash, its own hash, signer identity, signer role, and HMAC signature.

## Re-running after code changes

Regenerate every checked-in result after changing transition semantics, artifact fields, signing, ledger logic, attack definitions, or benchmark workflow. Do not retain old result tables with new code.

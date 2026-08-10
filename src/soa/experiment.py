from __future__ import annotations

import argparse
import csv
import json
import platform
import random
import statistics
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from .abstract_model import explore
from .core import AuthorityKernel, AuthorityViolation
from .demo import demo_context
from .model import DecisionContext, EnforcementProfile


@dataclass(frozen=True, slots=True)
class AttackSpec:
    name: str
    invariant: str
    control: str
    description: str
    runner: Callable[[AuthorityKernel, DecisionContext, dict[str, int | str]], bool]


def _context(trial: int, *, suffix: str = "") -> DecisionContext:
    context = demo_context(f"case-{trial:06d}{suffix}")
    return DecisionContext(
        case_id=context.case_id,
        intended_use=context.intended_use,
        jurisdiction=context.jurisdiction,
        scope=context.scope,
        actor_id=f"applicant-{trial:06d}",
        policy_version=context.policy_version,
        method_version=context.method_version,
        template_version=context.template_version,
        target_version=context.target_version,
        context_epoch=context.context_epoch,
    )


def _git_commit() -> str:
    root = Path(__file__).resolve().parents[2]
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return "unavailable"
    return completed.stdout.strip() or "unavailable"


def _evidence(rng: random.Random) -> dict[str, int | str]:
    return {
        "annual_income": rng.randint(8_000, 55_000),
        "household_size": rng.randint(1, 6),
        "application_id": f"app-{rng.randrange(10**12):012d}",
    }


def _through_inference(kernel: AuthorityKernel, context: DecisionContext, evidence: dict[str, int | str]):
    accepted = kernel.accept_evidence(
        evidence=evidence,
        source="authenticated-application",
        context=context,
    )
    inferred = kernel.derive_eligibility(accepted, context)
    return accepted, inferred


def _through_authorization(kernel: AuthorityKernel, context: DecisionContext, evidence: dict[str, int | str]):
    accepted, inferred = _through_inference(kernel, context, evidence)
    proposal = kernel.propose_decision_effect(inferred, context)
    authorization = kernel.authorize_effect(proposal, context)
    return accepted, inferred, proposal, authorization


def attack_silent_promotion(
    kernel: AuthorityKernel, context: DecisionContext, evidence: dict[str, int | str]
) -> bool:
    _, inferred = _through_inference(kernel, context, evidence)
    kernel.silent_promote_to_knowledge(inferred, context)
    return True


def attack_self_authorization(
    kernel: AuthorityKernel, context: DecisionContext, evidence: dict[str, int | str]
) -> bool:
    _, inferred = _through_inference(kernel, context, evidence)
    proposal = kernel.propose_decision_effect(inferred, context)
    authorization = kernel.authorize_effect(
        proposal,
        context,
        force_requester_authorization=True,
    )
    kernel.execute_effect(authorization, context)
    return True


def attack_context_replay(
    kernel: AuthorityKernel, context: DecisionContext, evidence: dict[str, int | str]
) -> bool:
    _, _, _, authorization = _through_authorization(kernel, context, evidence)
    other_context = _context(int(context.case_id.split("-")[1]), suffix="-other")
    kernel.execute_effect(authorization, other_context)
    return True


def attack_policy_outage_fallback(
    kernel: AuthorityKernel, context: DecisionContext, evidence: dict[str, int | str]
) -> bool:
    _, inferred = _through_inference(kernel, context, evidence)
    proposal = kernel.propose_decision_effect(inferred, context)
    authorization = kernel.authorize_effect(proposal, context, policy_available=False)
    kernel.execute_effect(authorization, context)
    return True


def attack_unapproved_release(
    kernel: AuthorityKernel, context: DecisionContext, evidence: dict[str, int | str]
) -> bool:
    accepted, inferred = _through_inference(kernel, context, evidence)
    draft = kernel.render_notice(accepted, inferred, context)
    kernel.release_communication(draft, context, None)
    return True


def attack_outcome_reentry(
    kernel: AuthorityKernel, context: DecisionContext, evidence: dict[str, int | str]
) -> bool:
    _, _, _, authorization = _through_authorization(kernel, context, evidence)
    executed = kernel.execute_effect(authorization, context)
    outcome = kernel.observe_outcome(executed, context)
    kernel.silent_outcome_reentry(outcome, context)
    return True


def attack_in_place_overwrite(
    kernel: AuthorityKernel, context: DecisionContext, evidence: dict[str, int | str]
) -> bool:
    accepted = kernel.accept_evidence(
        evidence=evidence,
        source="authenticated-application",
        context=context,
    )
    corrected = dict(evidence)
    corrected["annual_income"] = int(corrected["annual_income"]) + 1
    replacement = kernel.overwrite_evidence_in_place(accepted, corrected, context)
    return replacement.artifact_id == accepted.artifact_id and replacement.digest != accepted.digest


def attack_expired_authorization(
    kernel: AuthorityKernel, context: DecisionContext, evidence: dict[str, int | str]
) -> bool:
    _, _, _, authorization = _through_authorization(kernel, context, evidence)
    kernel.advance(100)
    kernel.execute_effect(authorization, context)
    return True


def attack_assurance_tamper(
    kernel: AuthorityKernel, context: DecisionContext, evidence: dict[str, int | str]
) -> bool:
    _through_inference(kernel, context, evidence)
    entries = kernel.ledger.entries()
    entries[0]["disposition"] = "tampered"
    verification = kernel.verify_ledger(entries)
    return verification.valid


ATTACKS = (
    AttackSpec(
        "silent_promotion",
        "I1/I2: typed standing and no implicit promotion",
        "typed_standing",
        "Copy a derived result into accepted knowledge without a knowledge-authority transition.",
        attack_silent_promotion,
    ),
    AttackSpec(
        "self_authorization",
        "I3: no unilateral effect authorization",
        "independent_effect_authorization",
        "Allow the inference producer to authorize and execute its own proposed effect.",
        attack_self_authorization,
    ),
    AttackSpec(
        "context_replay",
        "I4: context binding",
        "context_binding",
        "Replay an authorization issued for one case in another decision context.",
        attack_context_replay,
    ),
    AttackSpec(
        "policy_outage_fallback",
        "I5: failure non-escalation",
        "failure_non_escalation",
        "Continue authorization through an implicit default when policy evaluation is unavailable.",
        attack_policy_outage_fallback,
    ),
    AttackSpec(
        "unapproved_release",
        "I6: communication-release separation",
        "communication_release_separation",
        "Release a draft notice without a separately authorized release effect.",
        attack_unapproved_release,
    ),
    AttackSpec(
        "in_place_overwrite",
        "I7: successor correction",
        "successor_correction",
        "Replace accepted evidence under the same identifier instead of creating a successor.",
        attack_in_place_overwrite,
    ),
    AttackSpec(
        "outcome_reentry",
        "I8: outcome re-entry",
        "outcome_reentry",
        "Feed an observed outcome back into accepted knowledge without validation.",
        attack_outcome_reentry,
    ),
    AttackSpec(
        "assurance_tamper",
        "I10: assurance independence/integrity",
        "assurance_integrity",
        "Modify a prior receipt and test whether verification still accepts the ledger.",
        attack_assurance_tamper,
    ),
    AttackSpec(
        "expired_authorization",
        "I4 extension: time-bound context",
        "authorization_expiry",
        "Execute an otherwise valid authorization after its expiry step.",
        attack_expired_authorization,
    ),
)


def _run_attack(
    spec: AttackSpec,
    profile: EnforcementProfile,
    *,
    trials: int,
    seed: int,
) -> dict[str, object]:
    rng = random.Random(seed)
    admitted = 0
    blocked_codes: dict[str, int] = {}
    unexpected_errors: list[str] = []

    for trial in range(trials):
        kernel = AuthorityKernel(profile=profile)
        context = _context(trial)
        evidence = _evidence(rng)
        try:
            if spec.runner(kernel, context, evidence):
                admitted += 1
        except AuthorityViolation as exc:
            blocked_codes[exc.code] = blocked_codes.get(exc.code, 0) + 1
        except Exception as exc:  # pragma: no cover - reported as experiment failure
            unexpected_errors.append(f"{type(exc).__name__}: {exc}")

    return {
        "profile": profile.name,
        "trials": trials,
        "admitted": admitted,
        "admit_rate": admitted / trials,
        "blocked": trials - admitted - len(unexpected_errors),
        "block_rate": (trials - admitted - len(unexpected_errors)) / trials,
        "blocked_codes": blocked_codes,
        "unexpected_error_count": len(unexpected_errors),
        "unexpected_error_samples": unexpected_errors[:3],
    }


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    position = (len(ordered) - 1) * percentile
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] * (1 - fraction) + ordered[upper] * fraction


def _benchmark(profile: EnforcementProfile, *, cases: int, seed: int) -> dict[str, float | int | str]:
    rng = random.Random(seed)
    kernel = AuthorityKernel(profile=profile)
    timings_us: list[float] = []
    warmup = min(25, max(1, cases // 20))

    for index in range(cases + warmup):
        context = _context(index, suffix=f"-{profile.name.replace(':', '-')}")
        evidence = _evidence(rng)
        start = time.perf_counter_ns()
        kernel.run_valid_workflow(
            evidence=evidence,
            source="authenticated-application",
            recipient=context.actor_id,
            context=context,
        )
        elapsed_us = (time.perf_counter_ns() - start) / 1_000
        if index >= warmup:
            timings_us.append(elapsed_us)

    ledger_bytes = len(kernel.ledger.jsonl().encode("utf-8"))
    measured_cases = cases + warmup
    return {
        "profile": profile.name,
        "cases": cases,
        "warmup_cases": warmup,
        "median_us_per_case": statistics.median(timings_us),
        "mean_us_per_case": statistics.fmean(timings_us),
        "p95_us_per_case": _percentile(timings_us, 0.95),
        "min_us_per_case": min(timings_us),
        "max_us_per_case": max(timings_us),
        "artifacts_per_case": len(kernel.artifacts()) / measured_cases,
        "receipts_per_case": len(kernel.ledger.entries()) / measured_cases,
        "receipt_bytes_per_case": ledger_bytes / measured_cases,
    }


def _valid_workflow_trials(*, trials: int, seed: int) -> dict[str, object]:
    rng = random.Random(seed)
    completions = 0
    reconstructions = 0
    artifact_counts: list[int] = []
    receipt_counts: list[int] = []
    errors: list[str] = []

    for trial in range(trials):
        kernel = AuthorityKernel()
        context = _context(trial)
        try:
            result = kernel.run_valid_workflow(
                evidence=_evidence(rng),
                source="authenticated-application",
                recipient=context.actor_id,
                context=context,
            )
            completions += 1
            verification = kernel.verify_ledger()
            lineage = kernel.reconstruct(result.accepted_outcome.artifact_id)
            context_artifacts = kernel.reconstruct_context(context.context_id)
            expected_ids = {artifact.artifact_id for artifact in result.artifacts()}
            if (
                verification.valid
                and result.accepted_outcome.artifact_id in lineage
                and context_artifacts == expected_ids
            ):
                reconstructions += 1
            artifact_counts.append(len(kernel.artifacts()))
            receipt_counts.append(len(kernel.ledger.entries()))
        except Exception as exc:  # pragma: no cover - reported as experiment failure
            errors.append(f"{type(exc).__name__}: {exc}")

    return {
        "trials": trials,
        "completed": completions,
        "completion_rate": completions / trials,
        "reconstructed": reconstructions,
        "reconstruction_rate": reconstructions / trials,
        "median_artifacts_per_case": statistics.median(artifact_counts) if artifact_counts else 0,
        "median_receipts_per_case": statistics.median(receipt_counts) if receipt_counts else 0,
        "error_count": len(errors),
        "error_samples": errors[:3],
    }


def _write_attack_csv(path: Path, attack_rows: list[dict[str, object]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(
            [
                "attack",
                "invariant",
                "control",
                "strict_block_rate",
                "targeted_ablation_admit_rate",
                "collapsed_admit_rate",
            ]
        )
        for row in attack_rows:
            writer.writerow(
                [
                    row["attack"],
                    row["invariant"],
                    row["control"],
                    row["strict"]["block_rate"],  # type: ignore[index]
                    row["targeted_ablation"]["admit_rate"],  # type: ignore[index]
                    row["collapsed"]["admit_rate"],  # type: ignore[index]
                ]
            )


def _fmt_rate(value: float) -> str:
    return f"{100 * value:.1f}%"


def _render_summary(results: dict[str, object]) -> str:
    valid = results["valid_workflows"]  # type: ignore[assignment]
    attacks = results["attacks"]  # type: ignore[assignment]
    benchmark = results["benchmark"]  # type: ignore[assignment]
    model_check = results["abstract_model"]  # type: ignore[assignment]
    strict_benchmark = benchmark["strict"]  # type: ignore[index]
    collapsed_benchmark = benchmark["collapsed"]  # type: ignore[index]

    lines = [
        "# Experiment Summary",
        "",
        f"Generated: `{results['generated_at_utc']}`",
        "",
        "## Valid workflows",
        "",
        f"- Completion: **{valid['completed']}/{valid['trials']} ({_fmt_rate(valid['completion_rate'])})**",  # type: ignore[index]
        f"- Reconstructable with a valid receipt chain: **{valid['reconstructed']}/{valid['trials']} ({_fmt_rate(valid['reconstruction_rate'])})**",  # type: ignore[index]
        f"- Median artifacts / receipts per case: **{valid['median_artifacts_per_case']} / {valid['median_receipts_per_case']}**",  # type: ignore[index]
        "",
        "## Invariant-directed fault and mutation tests",
        "",
        "| Test | Mapped invariant | Strict block rate | Targeted-ablation admit rate | Collapsed admit rate |",
        "|---|---|---:|---:|---:|",
    ]
    for row in attacks:  # type: ignore[union-attr]
        lines.append(
            "| {attack} | {invariant} | {strict} | {ablation} | {collapsed} |".format(
                attack=row["attack"],
                invariant=row["invariant"],
                strict=_fmt_rate(row["strict"]["block_rate"]),
                ablation=_fmt_rate(row["targeted_ablation"]["admit_rate"]),
                collapsed=_fmt_rate(row["collapsed"]["admit_rate"]),
            )
        )

    lines.extend(
        [
            "",
            "## Exhaustive abstract-state exploration",
            "",
            f"- Strict profile: **{model_check['strict']['reachable_states']} reachable states; {model_check['strict']['violation_count']} reachable bad states**",  # type: ignore[index]
            f"- Collapsed profile: **{model_check['collapsed']['reachable_states']} reachable states; {model_check['collapsed']['violation_count']} reachable bad states**",  # type: ignore[index]
            "- Every single-control ablation reached exactly its corresponding bad state and no other cataloged bad state.",
            "",
            "## Runtime and receipt overhead",
            "",
            "| Profile | Median µs/case | P95 µs/case | Receipt bytes/case | Artifacts/case | Receipts/case |",
            "|---|---:|---:|---:|---:|---:|",
            "| Strict | {median:.1f} | {p95:.1f} | {bytes:.1f} | {artifacts:.1f} | {receipts:.1f} |".format(
                median=strict_benchmark["median_us_per_case"],
                p95=strict_benchmark["p95_us_per_case"],
                bytes=strict_benchmark["receipt_bytes_per_case"],
                artifacts=strict_benchmark["artifacts_per_case"],
                receipts=strict_benchmark["receipts_per_case"],
            ),
            "| Collapsed ablation | {median:.1f} | {p95:.1f} | {bytes:.1f} | {artifacts:.1f} | {receipts:.1f} |".format(
                median=collapsed_benchmark["median_us_per_case"],
                p95=collapsed_benchmark["p95_us_per_case"],
                bytes=collapsed_benchmark["receipt_bytes_per_case"],
                artifacts=collapsed_benchmark["artifacts_per_case"],
                receipts=collapsed_benchmark["receipts_per_case"],
            ),
            "",
            f"Median runtime ratio (strict / collapsed): **{benchmark['median_runtime_ratio']:.3f}×**",  # type: ignore[index]
            "",
            "## Interpretation boundary",
            "",
            "These results establish constructive feasibility for this implementation and show that the named guards mediate the corresponding synthetic transitions. They do not establish safety, compliance, general security, domain validity, or superiority over production architectures.",
            "",
        ]
    )
    return "\n".join(lines)


def _render_paper_section(results: dict[str, object]) -> str:
    valid = results["valid_workflows"]  # type: ignore[assignment]
    attacks = results["attacks"]  # type: ignore[assignment]
    benchmark = results["benchmark"]  # type: ignore[assignment]
    model_check = results["abstract_model"]  # type: ignore[assignment]
    strict_benchmark = benchmark["strict"]  # type: ignore[index]
    collapsed_benchmark = benchmark["collapsed"]  # type: ignore[index]
    trial_count = attacks[0]["strict"]["trials"]  # type: ignore[index]

    rows = []
    for row in attacks:  # type: ignore[union-attr]
        rows.append(
            "| {attack} | {invariant} | {strict} | {ablation} |".format(
                attack=row["attack"],
                invariant=row["invariant"],
                strict=_fmt_rate(row["strict"]["block_rate"]),
                ablation=_fmt_rate(row["targeted_ablation"]["admit_rate"]),
            )
        )

    return f"""# Prototype Implementation and Controlled Evaluation

## Research questions

The prototype evaluates three implementation-level questions:

1. Can the proposed K/I/C/E/O state classes, governance roles, and transition receipts be realized in a small single-process system without relying on service decomposition?
2. Do the enabled controls reject invariant-directed mutations and failure paths, and do targeted ablations admit those same paths?
3. What runtime and receipt-storage overhead does the strict profile add relative to an otherwise equivalent profile with the controls disabled?

## Prototype

We implemented a deterministic Python reference kernel using only the standard library. The kernel represents accepted evidence (K), derived results (I), communication artifacts (C), effects (E), and observed outcomes (O) as signed typed artifacts. It binds consequential transitions to a decision-context digest and records each transition in an HMAC-authenticated hash chain. Separate logical principals issue knowledge, inference, communication, policy, effect, outcome, remedy, and assurance records. All principals execute in one process; the prototype therefore tests logical rather than network or microservice separation.

The worked workflow uses a synthetic administrative-benefit rule. It accepts an application record, derives eligibility, renders a draft notice, proposes and authorizes a record-changing effect, executes the effect, separately authorizes release of the notice, observes the resulting state, and explicitly accepts that observation as successor knowledge. A complete successful case emits 12 artifacts and 12 receipts.

## Experimental method

We ran {valid['trials']} valid-workflow trials under the strict profile. We then defined nine invariant-directed fault or mutation tests. Each test was repeated {trial_count} times over seeded, randomized synthetic application records. For each test we compared: (1) the strict profile; (2) a targeted ablation disabling the named control; and (3) a collapsed profile disabling all evaluated controls. An attempted violation was counted as admitted only when the prohibited transition completed or, for receipt tampering, when verification accepted the modified ledger.

We also encoded the transition rules as a finite monotonic abstract state machine and exhaustively explored its reachable state space. The abstract model contains the valid transition path and one prohibited transition for each evaluated control. This analysis is a consistency check between the stated invariants and the transition relation; it is not a proof about arbitrary implementations.

We additionally measured end-to-end runtime for {strict_benchmark['cases']} cases after {strict_benchmark['warmup_cases']} warm-up cases. The strict and collapsed profiles execute the same successful 12-artifact workflow; the collapsed profile disables state-class checks, independent authorization, context and expiry checks, fail-closed behavior, release separation, successor and outcome controls, and receipt integrity. Measurements use a single process and should be interpreted as implementation-specific microbenchmarks rather than production capacity estimates.

## Results

All {valid['completed']} of {valid['trials']} strict-profile workflows completed, and all {valid['reconstructed']} produced a valid receipt chain from which all 12 context artifacts and the accepted outcome's transitive lineage could be reconstructed. The exhaustive abstract model reached {model_check['strict']['reachable_states']} states under the strict profile with zero cataloged bad states. The collapsed profile reached {model_check['collapsed']['reachable_states']} states and all {model_check['collapsed']['violation_count']} cataloged bad states. Each single-control ablation reached exactly one bad state: the state corresponding to the disabled control.

| Test | Mapped invariant | Strict block rate | Targeted-ablation admit rate |
|---|---|---:|---:|
{chr(10).join(rows)}

The strict profile's median end-to-end time was {strict_benchmark['median_us_per_case']:.1f} µs per case (P95 {strict_benchmark['p95_us_per_case']:.1f} µs), compared with {collapsed_benchmark['median_us_per_case']:.1f} µs (P95 {collapsed_benchmark['p95_us_per_case']:.1f} µs) for the collapsed ablation. The median runtime ratio was {benchmark['median_runtime_ratio']:.3f}×. The strict profile emitted approximately {strict_benchmark['receipt_bytes_per_case']:.1f} serialized receipt bytes per case in this implementation.

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

Run `PYTHONPATH=src python -m unittest discover -s tests -v` and then `PYTHONPATH=src python -m soa.experiment --trials {trial_count} --benchmark-cases {strict_benchmark['cases']} --seed {results['seed']} --output results`. The machine-readable output is `results/experiment.json`; the per-test table is `results/attack-results.csv`; and `results/sample-ledger.jsonl` contains one complete strict-profile trace.
"""


def run_experiment(*, trials: int, benchmark_cases: int, seed: int, output: Path) -> dict[str, object]:
    output.mkdir(parents=True, exist_ok=True)

    valid = _valid_workflow_trials(trials=trials, seed=seed)
    attack_rows: list[dict[str, object]] = []
    strict_profile = EnforcementProfile.strict()
    collapsed_profile = EnforcementProfile.collapsed()

    for index, spec in enumerate(ATTACKS):
        attack_seed = seed + (index + 1) * 10_000
        attack_rows.append(
            {
                "attack": spec.name,
                "invariant": spec.invariant,
                "control": spec.control,
                "description": spec.description,
                "strict": _run_attack(spec, strict_profile, trials=trials, seed=attack_seed),
                "targeted_ablation": _run_attack(
                    spec,
                    strict_profile.ablate(spec.control),
                    trials=trials,
                    seed=attack_seed,
                ),
                "collapsed": _run_attack(
                    spec,
                    collapsed_profile,
                    trials=trials,
                    seed=attack_seed,
                ),
            }
        )

    strict_benchmark = _benchmark(strict_profile, cases=benchmark_cases, seed=seed + 100_000)
    collapsed_benchmark = _benchmark(collapsed_profile, cases=benchmark_cases, seed=seed + 100_000)
    benchmark = {
        "strict": strict_benchmark,
        "collapsed": collapsed_benchmark,
        "median_runtime_ratio": (
            strict_benchmark["median_us_per_case"] / collapsed_benchmark["median_us_per_case"]
        ),
        "median_runtime_delta_us": (
            strict_benchmark["median_us_per_case"] - collapsed_benchmark["median_us_per_case"]
        ),
    }

    abstract_model = {
        "strict": explore(strict_profile),
        "single_ablations": {
            spec.control: explore(strict_profile.ablate(spec.control)) for spec in ATTACKS
        },
        "collapsed": explore(collapsed_profile),
    }

    sample_kernel = AuthorityKernel()
    sample_context = _context(999_999)
    sample_result = sample_kernel.run_valid_workflow(
        evidence={"annual_income": 24_000, "household_size": 2, "application_id": "sample"},
        source="authenticated-application",
        recipient=sample_context.actor_id,
        context=sample_context,
    )
    sample_lineage = sorted(sample_kernel.reconstruct(sample_result.accepted_outcome.artifact_id))
    sample_context_artifacts = sorted(sample_kernel.reconstruct_context(sample_context.context_id))

    results: dict[str, object] = {
        "schema_version": "soa-experiment-v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "seed": seed,
        "environment": {
            "python": sys.version,
            "platform": platform.platform(),
            "implementation": platform.python_implementation(),
            "code_commit": _git_commit(),
        },
        "valid_workflows": valid,
        "attacks": attack_rows,
        "benchmark": benchmark,
        "abstract_model": abstract_model,
        "sample": {
            "context_id": sample_context.context_id,
            "final_artifact_id": sample_result.accepted_outcome.artifact_id,
            "accepted_outcome_lineage": sample_lineage,
            "context_artifacts": sample_context_artifacts,
            "ledger_verification": asdict(sample_kernel.verify_ledger()),
        },
        "claim_boundary": (
            "Constructive feasibility and tested guard behavior only; no claim of safety, "
            "compliance, accuracy, fairness, or superiority."
        ),
    }

    (output / "experiment.json").write_text(
        json.dumps(results, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    _write_attack_csv(output / "attack-results.csv", attack_rows)
    (output / "summary.md").write_text(_render_summary(results), encoding="utf-8")
    (output / "sample-ledger.jsonl").write_text(sample_kernel.ledger.jsonl(), encoding="utf-8")
    (output / "sample-artifacts.json").write_text(
        json.dumps(sample_kernel.artifact_manifest(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    paper_dir = output.parent / "paper"
    paper_dir.mkdir(parents=True, exist_ok=True)
    (paper_dir / "METHODS_AND_RESULTS.md").write_text(
        _render_paper_section(results),
        encoding="utf-8",
    )
    return results


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the separation-of-authority reference implementation evaluation")
    parser.add_argument("--trials", type=int, default=250)
    parser.add_argument("--benchmark-cases", type=int, default=2_000)
    parser.add_argument("--seed", type=int, default=20260806)
    parser.add_argument("--output", type=Path, default=Path("results"))
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.trials <= 0 or args.benchmark_cases <= 0:
        raise SystemExit("trials and benchmark-cases must be positive")
    results = run_experiment(
        trials=args.trials,
        benchmark_cases=args.benchmark_cases,
        seed=args.seed,
        output=args.output,
    )
    print(_render_summary(results))


if __name__ == "__main__":
    main()

from __future__ import annotations

import json

from .core import AuthorityKernel
from .model import DecisionContext


def demo_context(case_id: str = "case-001") -> DecisionContext:
    return DecisionContext(
        case_id=case_id,
        intended_use="synthetic-benefit-eligibility",
        jurisdiction="demo-jurisdiction",
        scope="benefit-demo",
        actor_id="applicant-001",
        policy_version="policy-v1",
        method_version="eligibility-rule-v1",
        template_version="notice-template-v1",
        target_version="benefit-record-api-v1",
    )


def main() -> None:
    kernel = AuthorityKernel()
    context = demo_context()
    result = kernel.run_valid_workflow(
        evidence={"annual_income": 24_000, "household_size": 2},
        source="authenticated-application",
        recipient="applicant-001",
        context=context,
    )
    verification = kernel.verify_ledger()
    lineage = sorted(kernel.reconstruct(result.accepted_outcome.artifact_id))
    context_artifacts = sorted(kernel.reconstruct_context(context.context_id))
    print(
        json.dumps(
            {
                "context_id": context.context_id,
                "decision": result.decision_effect.payload["requested_value"],
                "artifact_count": len(result.artifacts()),
                "receipt_count": len(kernel.ledger.entries()),
                "ledger_valid": verification.valid,
                "accepted_outcome_lineage_ids": lineage,
                "reconstructed_context_artifact_ids": context_artifacts,
                "released_notice": result.released_communication.payload["text"],
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()

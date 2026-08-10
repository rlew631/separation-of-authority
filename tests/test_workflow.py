from __future__ import annotations

import unittest

from soa.core import AuthorityKernel
from soa.demo import demo_context
from soa.model import ArtifactClass, Status


class ValidWorkflowTests(unittest.TestCase):
    def test_complete_workflow_is_typed_and_reconstructable(self) -> None:
        kernel = AuthorityKernel()
        context = demo_context("case-valid")
        result = kernel.run_valid_workflow(
            evidence={"annual_income": 24_000, "household_size": 2},
            source="authenticated-application",
            recipient="applicant-valid",
            context=context,
        )

        self.assertEqual(result.evidence.artifact_class, ArtifactClass.KNOWLEDGE)
        self.assertEqual(result.inference.artifact_class, ArtifactClass.INFERENCE)
        self.assertEqual(result.communication_draft.status, Status.DRAFT)
        self.assertEqual(result.decision_authorization.status, Status.AUTHORIZED)
        self.assertEqual(result.decision_effect.status, Status.EXECUTED)
        self.assertEqual(result.released_communication.status, Status.RELEASED)
        self.assertEqual(result.outcome.artifact_class, ArtifactClass.OUTCOME)
        self.assertEqual(result.accepted_outcome.artifact_class, ArtifactClass.KNOWLEDGE)
        self.assertEqual(len(result.artifacts()), 12)
        self.assertEqual(len(kernel.ledger.entries()), 12)

        verification = kernel.verify_ledger()
        self.assertTrue(verification.valid, verification.reason)
        context_artifacts = kernel.reconstruct_context(context.context_id)
        self.assertEqual(context_artifacts, {artifact.artifact_id for artifact in result.artifacts()})
        lineage = kernel.reconstruct(result.accepted_outcome.artifact_id)
        self.assertIn(result.outcome.artifact_id, lineage)
        self.assertIn(result.decision_effect.artifact_id, lineage)
        self.assertIn(result.inference.artifact_id, lineage)
        self.assertIn(result.evidence.artifact_id, lineage)

    def test_correction_creates_successor(self) -> None:
        kernel = AuthorityKernel()
        context = demo_context("case-correct")
        original = kernel.accept_evidence(
            evidence={"annual_income": 30_000, "household_size": 2},
            source="authenticated-application",
            context=context,
        )
        corrected = kernel.correct_evidence(
            original,
            {"annual_income": 20_000, "household_size": 2},
            context,
            reason="validated applicant correction",
        )
        self.assertNotEqual(original.artifact_id, corrected.artifact_id)
        self.assertEqual(corrected.predecessor_ids, (original.artifact_id,))
        self.assertEqual(kernel.get(original.artifact_id).digest, original.digest)


if __name__ == "__main__":
    unittest.main()

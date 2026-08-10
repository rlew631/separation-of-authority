from __future__ import annotations

from dataclasses import replace
import unittest

from soa.core import AuthorityKernel, AuthorityViolation
from soa.demo import demo_context
from soa.model import DecisionContext, sha256_hex


class InvariantTests(unittest.TestCase):
    def setUp(self) -> None:
        self.kernel = AuthorityKernel()
        self.context = demo_context("case-invariant")
        self.evidence = self.kernel.accept_evidence(
            evidence={"annual_income": 24_000, "household_size": 2},
            source="authenticated-application",
            context=self.context,
        )
        self.inference = self.kernel.derive_eligibility(self.evidence, self.context)

    def assert_code(self, code: str, callable_obj, *args, **kwargs) -> None:  # type: ignore[no-untyped-def]
        with self.assertRaises(AuthorityViolation) as raised:
            callable_obj(*args, **kwargs)
        self.assertEqual(raised.exception.code, code)

    def test_no_implicit_promotion(self) -> None:
        self.assert_code(
            "IMPLICIT_PROMOTION",
            self.kernel.silent_promote_to_knowledge,
            self.inference,
            self.context,
        )

    def test_no_self_authorization(self) -> None:
        proposal = self.kernel.propose_decision_effect(self.inference, self.context)
        self.assert_code(
            "SELF_AUTHORIZATION",
            self.kernel.authorize_effect,
            proposal,
            self.context,
            force_requester_authorization=True,
        )

    def test_context_replay_is_rejected(self) -> None:
        proposal = self.kernel.propose_decision_effect(self.inference, self.context)
        authorization = self.kernel.authorize_effect(proposal, self.context)
        other = DecisionContext(
            case_id="case-other",
            intended_use=self.context.intended_use,
            jurisdiction=self.context.jurisdiction,
            scope=self.context.scope,
            actor_id=self.context.actor_id,
            policy_version=self.context.policy_version,
            method_version=self.context.method_version,
            template_version=self.context.template_version,
            target_version=self.context.target_version,
        )
        self.assert_code("CONTEXT_MISMATCH", self.kernel.execute_effect, authorization, other)

    def test_policy_outage_fails_closed(self) -> None:
        proposal = self.kernel.propose_decision_effect(self.inference, self.context)
        self.assert_code(
            "POLICY_UNAVAILABLE",
            self.kernel.authorize_effect,
            proposal,
            self.context,
            policy_available=False,
        )

    def test_release_requires_authorized_effect(self) -> None:
        draft = self.kernel.render_notice(self.evidence, self.inference, self.context)
        self.assert_code(
            "RELEASE_NOT_AUTHORIZED",
            self.kernel.release_communication,
            draft,
            self.context,
            None,
        )

    def test_outcome_cannot_reenter_silently(self) -> None:
        proposal = self.kernel.propose_decision_effect(self.inference, self.context)
        authorization = self.kernel.authorize_effect(proposal, self.context)
        executed = self.kernel.execute_effect(authorization, self.context)
        outcome = self.kernel.observe_outcome(executed, self.context)
        self.assert_code(
            "OUTCOME_REENTRY_REQUIRES_ACCEPTANCE",
            self.kernel.silent_outcome_reentry,
            outcome,
            self.context,
        )

    def test_in_place_overwrite_is_rejected(self) -> None:
        self.assert_code(
            "IN_PLACE_OVERWRITE",
            self.kernel.overwrite_evidence_in_place,
            self.evidence,
            {"annual_income": 20_000, "household_size": 2},
            self.context,
        )

    def test_expired_authorization_is_rejected(self) -> None:
        proposal = self.kernel.propose_decision_effect(self.inference, self.context)
        authorization = self.kernel.authorize_effect(proposal, self.context)
        self.kernel.advance(100)
        self.assert_code(
            "AUTHORIZATION_EXPIRED",
            self.kernel.execute_effect,
            authorization,
            self.context,
        )

    def test_tampered_receipt_is_detected(self) -> None:
        entries = self.kernel.ledger.entries()
        entries[0]["disposition"] = "tampered"
        verification = self.kernel.verify_ledger(entries)
        self.assertFalse(verification.valid)
        self.assertIn("hash", verification.reason)

    def test_receipt_with_mismatched_signer_role_is_rejected(self) -> None:
        entries = self.kernel.ledger.entries()
        entry = entries[0]
        entry["signer_role"] = "effect"
        body = {key: value for key, value in entry.items() if key not in {"entry_hash", "signature"}}
        entry["entry_hash"] = sha256_hex(body)
        entry["signature"] = self.kernel.registry.sign(
            entry["signer_id"],
            {**body, "entry_hash": entry["entry_hash"]},
        )

        verification = self.kernel.verify_ledger(entries)
        self.assertFalse(verification.valid)
        self.assertIn("signer role", verification.reason)

    def test_unknown_artifact_producer_fails_verification(self) -> None:
        forged = replace(self.evidence, producer_id="unknown-producer")
        self.assertFalse(forged.verify(self.kernel.registry))


if __name__ == "__main__":
    unittest.main()

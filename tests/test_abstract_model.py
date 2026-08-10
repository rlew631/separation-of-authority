from __future__ import annotations

import unittest

from soa.abstract_model import BAD_FACTS, explore
from soa.model import EnforcementProfile


CONTROL_TO_BAD = {
    "typed_standing": "bad_silent_promotion",
    "independent_effect_authorization": "bad_self_authorized_effect",
    "context_binding": "bad_context_replay",
    "failure_non_escalation": "bad_policy_outage_fallback",
    "communication_release_separation": "bad_unapproved_release",
    "successor_correction": "bad_in_place_overwrite",
    "outcome_reentry": "bad_outcome_reentry",
    "assurance_integrity": "bad_assurance_tamper",
    "authorization_expiry": "bad_expired_authorization",
}


class AbstractModelTests(unittest.TestCase):
    def test_strict_model_has_no_reachable_bad_state(self) -> None:
        result = explore(EnforcementProfile.strict())
        self.assertEqual(result["violation_count"], 0)

    def test_collapsed_model_reaches_every_cataloged_bad_state(self) -> None:
        result = explore(EnforcementProfile.collapsed())
        self.assertEqual(set(result["violations"]), set(BAD_FACTS))

    def test_each_single_ablation_reaches_its_corresponding_bad_state(self) -> None:
        strict = EnforcementProfile.strict()
        for control, bad_fact in CONTROL_TO_BAD.items():
            with self.subTest(control=control):
                result = explore(strict.ablate(control))
                self.assertIn(bad_fact, result["violations"])
                self.assertEqual(result["violation_count"], 1)


if __name__ == "__main__":
    unittest.main()

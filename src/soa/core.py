from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from .ledger import AssuranceLedger, VerificationResult
from .model import (
    Artifact,
    ArtifactClass,
    AuthorityRegistry,
    DecisionContext,
    EnforcementProfile,
    Role,
    Status,
)


class AuthorityViolation(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


@dataclass(frozen=True, slots=True)
class WorkflowResult:
    evidence: Artifact
    inference: Artifact
    communication_draft: Artifact
    decision_proposal: Artifact
    decision_authorization: Artifact
    decision_effect: Artifact
    release_proposal: Artifact
    release_authorization: Artifact
    release_effect: Artifact
    released_communication: Artifact
    outcome: Artifact
    accepted_outcome: Artifact

    def artifacts(self) -> tuple[Artifact, ...]:
        return (
            self.evidence,
            self.inference,
            self.communication_draft,
            self.decision_proposal,
            self.decision_authorization,
            self.decision_effect,
            self.release_proposal,
            self.release_authorization,
            self.release_effect,
            self.released_communication,
            self.outcome,
            self.accepted_outcome,
        )


class AuthorityKernel:
    """A single-process implementation of logically separated authorities."""

    KNOWLEDGE = "knowledge-authority"
    INFERENCE = "inference-service"
    COMMUNICATION = "communication-service"
    POLICY = "policy-authority"
    EFFECT = "effect-executor"
    OBSERVER = "outcome-observer"
    REMEDY = "remedy-authority"

    def __init__(
        self,
        profile: EnforcementProfile | None = None,
        registry: AuthorityRegistry | None = None,
    ):
        self.profile = profile or EnforcementProfile.strict()
        self.registry = registry or AuthorityRegistry.demo()
        self.ledger = AssuranceLedger(self.registry, protected=self.profile.assurance_integrity)
        self._store: dict[str, Artifact] = {}
        self._clock = 0

    @property
    def logical_time(self) -> int:
        return self._clock

    def advance(self, steps: int = 1) -> int:
        if steps < 0:
            raise ValueError("steps must be nonnegative")
        self._clock += steps
        return self._clock

    def artifacts(self) -> list[Artifact]:
        return list(self._store.values())

    def artifact_manifest(self) -> list[dict[str, Any]]:
        return [artifact.to_dict() for artifact in self._store.values()]

    def get(self, artifact_id: str) -> Artifact:
        try:
            return self._store[artifact_id]
        except KeyError as exc:
            raise AuthorityViolation("UNKNOWN_ARTIFACT", artifact_id) from exc

    def verify_ledger(self, entries: list[dict[str, Any]] | None = None) -> VerificationResult:
        return self.ledger.verify(entries)

    def reconstruct_context(self, context_id: str) -> set[str]:
        """Return every artifact in one context after checking receipt and source integrity."""
        verification = self.verify_ledger()
        if not verification.valid:
            raise AuthorityViolation("LEDGER_INVALID", verification.reason)

        artifact_ids: set[str] = set()
        for entry in self.ledger.entries():
            if entry["context_id"] != context_id:
                continue
            destination_id = entry["destination_artifact_id_or_status"]
            if destination_id not in self._store:
                raise AuthorityViolation("MISSING_DESTINATION", destination_id)
            artifact = self._store[destination_id]
            if artifact.context_id != context_id:
                raise AuthorityViolation("CONTEXT_MISMATCH", destination_id)
            artifact_ids.add(destination_id)
            for source_id in entry["source_artifact_ids"]:
                if source_id not in self._store:
                    raise AuthorityViolation("MISSING_SOURCE", source_id)
                if self._store[source_id].context_id != context_id:
                    raise AuthorityViolation("CONTEXT_MISMATCH", source_id)

        if not artifact_ids:
            raise AuthorityViolation("UNKNOWN_CONTEXT", context_id)
        return artifact_ids

    def reconstruct(self, destination_id: str) -> set[str]:
        """Return the transitive source set for one artifact after verifying receipts."""
        verification = self.verify_ledger()
        if not verification.valid:
            raise AuthorityViolation("LEDGER_INVALID", verification.reason)
        if destination_id not in self._store:
            raise AuthorityViolation("UNKNOWN_ARTIFACT", destination_id)

        found: set[str] = set()
        stack = [destination_id]
        while stack:
            artifact_id = stack.pop()
            if artifact_id in found:
                continue
            found.add(artifact_id)
            artifact = self._store[artifact_id]
            for source_id in artifact.source_ids:
                if source_id not in self._store:
                    raise AuthorityViolation("MISSING_SOURCE", source_id)
                stack.append(source_id)
        return found

    def _tick(self) -> int:
        self._clock += 1
        return self._clock

    def _require_valid(self, artifact: Artifact) -> None:
        stored = self._store.get(artifact.artifact_id)
        if stored is None:
            raise AuthorityViolation("UNKNOWN_ARTIFACT", artifact.artifact_id)
        if stored.digest != artifact.digest:
            raise AuthorityViolation("ARTIFACT_MISMATCH", artifact.artifact_id)
        if not artifact.verify(self.registry):
            raise AuthorityViolation("INVALID_SIGNATURE", artifact.artifact_id)

    def _require_class_status(
        self,
        artifact: Artifact,
        artifact_class: ArtifactClass,
        statuses: Iterable[Status],
    ) -> None:
        self._require_valid(artifact)
        if not self.profile.typed_standing:
            return
        allowed = set(statuses)
        if artifact.artifact_class != artifact_class or artifact.status not in allowed:
            expected = f"{artifact_class.value}/{'|'.join(status.value for status in allowed)}"
            actual = f"{artifact.artifact_class.value}/{artifact.status.value}"
            raise AuthorityViolation("WRONG_STANDING", f"expected {expected}, got {actual}")

    def _require_context(self, context: DecisionContext, *artifacts: Artifact) -> None:
        if not self.profile.context_binding:
            return
        mismatched = [artifact.artifact_id for artifact in artifacts if artifact.context_id != context.context_id]
        if mismatched:
            raise AuthorityViolation("CONTEXT_MISMATCH", ",".join(mismatched))

    def _put(self, artifact: Artifact, *, replace_existing: bool = False) -> None:
        if artifact.artifact_id in self._store and not replace_existing:
            raise AuthorityViolation("DUPLICATE_ARTIFACT", artifact.artifact_id)
        self._store[artifact.artifact_id] = artifact

    def _issue(
        self,
        *,
        artifact_class: ArtifactClass,
        status: Status,
        context: DecisionContext,
        payload: Mapping[str, Any],
        sources: Iterable[Artifact],
        producer_id: str,
        version: str,
        transition_type: str,
        requester_identity: str | None = None,
        authorizer_identity_or_policy: str = "none",
        disposition: str = "created",
        predecessors: Iterable[Artifact] = (),
        metadata: Mapping[str, Any] | None = None,
        forced_artifact_id: str | None = None,
        replace_existing: bool = False,
    ) -> Artifact:
        source_items = tuple(sources)
        predecessor_items = tuple(predecessors)
        logical_time = self._tick()
        artifact = Artifact.issue(
            artifact_class=artifact_class,
            status=status,
            scope=context.scope,
            context_id=context.context_id,
            payload=payload,
            source_ids=(item.artifact_id for item in source_items),
            producer_id=producer_id,
            registry=self.registry,
            version=version,
            predecessor_ids=(item.artifact_id for item in predecessor_items),
            logical_time=logical_time,
            forced_artifact_id=forced_artifact_id,
        )
        self._put(artifact, replace_existing=replace_existing)
        self.ledger.append(
            transition_type=transition_type,
            source_artifact_ids=artifact.source_ids,
            destination_artifact_id_or_status=artifact.artifact_id,
            authority_scope=context.scope,
            requester_identity=requester_identity or producer_id,
            authorizer_identity_or_policy=authorizer_identity_or_policy,
            context_id=context.context_id,
            policy_id=context.policy_version,
            artifact_versions=(artifact.version,),
            disposition=disposition,
            logical_time=logical_time,
            predecessor_or_supersession_links=artifact.predecessor_ids,
            signer_id=producer_id,
            metadata={"artifact_digest": artifact.digest, **dict(metadata or {})},
        )
        return artifact

    def accept_evidence(
        self,
        *,
        evidence: Mapping[str, Any],
        source: str,
        context: DecisionContext,
        limitations: Iterable[str] = (),
    ) -> Artifact:
        return self._issue(
            artifact_class=ArtifactClass.KNOWLEDGE,
            status=Status.ACCEPTED,
            context=context,
            payload={
                "source": source,
                "evidence": dict(evidence),
                "limitations": list(limitations),
                "accepted_for": context.intended_use,
            },
            sources=(),
            producer_id=self.KNOWLEDGE,
            version="knowledge-schema-v1",
            transition_type="accept_evidence",
            authorizer_identity_or_policy=self.KNOWLEDGE,
            disposition="accepted",
        )

    def derive_eligibility(self, evidence: Artifact, context: DecisionContext) -> Artifact:
        self._require_class_status(evidence, ArtifactClass.KNOWLEDGE, (Status.ACCEPTED,))
        self._require_context(context, evidence)
        payload = evidence.payload["evidence"]
        income = int(payload["annual_income"])
        household_size = int(payload["household_size"])
        threshold = 20_000 + max(0, household_size - 1) * 5_000
        eligible = income <= threshold
        return self._issue(
            artifact_class=ArtifactClass.INFERENCE,
            status=Status.DERIVED,
            context=context,
            payload={
                "eligible": eligible,
                "annual_income": income,
                "household_size": household_size,
                "threshold": threshold,
                "rule_path": [
                    "threshold = 20000 + 5000 * max(household_size - 1, 0)",
                    "eligible = annual_income <= threshold",
                ],
                "applicability": "synthetic benefit-eligibility demonstration only",
            },
            sources=(evidence,),
            producer_id=self.INFERENCE,
            version=context.method_version,
            transition_type="derive",
            requester_identity=self.INFERENCE,
            disposition="derived",
        )

    def render_notice(
        self,
        evidence: Artifact,
        inference: Artifact,
        context: DecisionContext,
    ) -> Artifact:
        self._require_class_status(evidence, ArtifactClass.KNOWLEDGE, (Status.ACCEPTED,))
        self._require_class_status(inference, ArtifactClass.INFERENCE, (Status.DERIVED,))
        self._require_context(context, evidence, inference)
        decision = "approved" if inference.payload["eligible"] else "denied"
        text = (
            f"Application {context.case_id} is {decision} under the synthetic rule. "
            f"Recorded income is {inference.payload['annual_income']}; "
            f"the applicable threshold is {inference.payload['threshold']}."
        )
        return self._issue(
            artifact_class=ArtifactClass.COMMUNICATION,
            status=Status.DRAFT,
            context=context,
            payload={
                "audience": "applicant",
                "text": text,
                "presentation_type": "deterministic-template",
                "basis_ids": [evidence.artifact_id, inference.artifact_id],
                "causal_evidence_id": inference.artifact_id,
                "limitations": ["synthetic rule", "not a legal determination"],
            },
            sources=(evidence, inference),
            producer_id=self.COMMUNICATION,
            version=context.template_version,
            transition_type="render",
            disposition="drafted",
        )

    def propose_decision_effect(self, inference: Artifact, context: DecisionContext) -> Artifact:
        self._require_class_status(inference, ArtifactClass.INFERENCE, (Status.DERIVED,))
        self._require_context(context, inference)
        requested_value = "approved" if inference.payload["eligible"] else "denied"
        return self._issue(
            artifact_class=ArtifactClass.EFFECT,
            status=Status.PROPOSED,
            context=context,
            payload={
                "effect_type": "set_benefit_status",
                "target": context.case_id,
                "requested_value": requested_value,
                "basis_result_id": inference.artifact_id,
                "target_version": context.target_version,
            },
            sources=(inference,),
            producer_id=self.INFERENCE,
            version="effect-proposal-v1",
            transition_type="propose_effect",
            disposition="proposed",
        )

    def propose_release_effect(
        self,
        communication: Artifact,
        context: DecisionContext,
        *,
        recipient: str,
    ) -> Artifact:
        self._require_class_status(communication, ArtifactClass.COMMUNICATION, (Status.DRAFT,))
        self._require_context(context, communication)
        return self._issue(
            artifact_class=ArtifactClass.EFFECT,
            status=Status.PROPOSED,
            context=context,
            payload={
                "effect_type": "release_communication",
                "communication_id": communication.artifact_id,
                "recipient": recipient,
                "channel": "synthetic-notice-channel",
            },
            sources=(communication,),
            producer_id=self.COMMUNICATION,
            version="release-proposal-v1",
            transition_type="propose_release",
            disposition="proposed",
        )

    def authorize_effect(
        self,
        proposal: Artifact,
        context: DecisionContext,
        *,
        policy_available: bool = True,
        force_requester_authorization: bool = False,
    ) -> Artifact:
        self._require_class_status(proposal, ArtifactClass.EFFECT, (Status.PROPOSED,))
        self._require_context(context, proposal)

        if not policy_available and self.profile.failure_non_escalation:
            raise AuthorityViolation("POLICY_UNAVAILABLE", "authorization cannot be established")

        effect = proposal.payload
        effect_type = effect.get("effect_type")
        if effect_type not in {"set_benefit_status", "release_communication"}:
            raise AuthorityViolation("POLICY_REJECT", f"unknown effect type: {effect_type}")

        if effect_type == "set_benefit_status":
            basis = self.get(str(effect["basis_result_id"]))
            self._require_class_status(basis, ArtifactClass.INFERENCE, (Status.DERIVED,))
            expected = "approved" if basis.payload["eligible"] else "denied"
            if effect.get("requested_value") != expected:
                raise AuthorityViolation("POLICY_REJECT", "proposal conflicts with bound result")
        else:
            communication = self.get(str(effect["communication_id"]))
            self._require_class_status(communication, ArtifactClass.COMMUNICATION, (Status.DRAFT,))

        requester = proposal.producer_id
        if force_requester_authorization and self.profile.independent_effect_authorization:
            raise AuthorityViolation("SELF_AUTHORIZATION", requester)

        producer_id = (
            requester
            if force_requester_authorization or not self.profile.independent_effect_authorization
            else self.POLICY
        )
        fallback = "implicit-default-policy" if not policy_available else None
        return self._issue(
            artifact_class=ArtifactClass.EFFECT,
            status=Status.AUTHORIZED,
            context=context,
            payload={
                **effect,
                "proposal_id": proposal.artifact_id,
                "proposal_digest": proposal.digest,
                "policy_version": context.policy_version,
                "authorized_by": producer_id,
                "expires_at_step": self.logical_time + 12,
                "fallback": fallback,
            },
            sources=(proposal,),
            producer_id=producer_id,
            version=context.policy_version,
            transition_type="authorize_effect",
            requester_identity=requester,
            authorizer_identity_or_policy=producer_id,
            disposition="authorized",
            metadata={"policy_available": policy_available},
        )

    def execute_effect(self, authorization: Artifact, context: DecisionContext) -> Artifact:
        self._require_class_status(authorization, ArtifactClass.EFFECT, (Status.AUTHORIZED,))
        self._require_context(context, authorization)
        if self.profile.independent_effect_authorization and authorization.producer_role != Role.POLICY:
            raise AuthorityViolation(
                "INVALID_AUTHORIZER",
                f"authorized by {authorization.producer_role.value}, expected policy",
            )
        expires_at = int(authorization.payload["expires_at_step"])
        if self.profile.authorization_expiry and self.logical_time > expires_at:
            raise AuthorityViolation("AUTHORIZATION_EXPIRED", authorization.artifact_id)
        return self._issue(
            artifact_class=ArtifactClass.EFFECT,
            status=Status.EXECUTED,
            context=context,
            payload={
                **authorization.payload,
                "authorization_id": authorization.artifact_id,
                "execution_status": "completed",
                "actual_target_version": context.target_version,
            },
            sources=(authorization,),
            producer_id=self.EFFECT,
            version=context.target_version,
            transition_type="execute_effect",
            requester_identity=authorization.payload["proposal_id"],
            authorizer_identity_or_policy=authorization.producer_id,
            disposition="executed",
        )

    def release_communication(
        self,
        communication: Artifact,
        context: DecisionContext,
        authorization: Artifact | None,
    ) -> tuple[Artifact, Artifact]:
        self._require_class_status(communication, ArtifactClass.COMMUNICATION, (Status.DRAFT,))
        self._require_context(context, communication)

        if authorization is None:
            if self.profile.communication_release_separation:
                raise AuthorityViolation("RELEASE_NOT_AUTHORIZED", communication.artifact_id)
            # Experimental ablation: the communication component promotes its own draft
            # to a released artifact and emits a synthetic completed effect.
            release_effect = self._issue(
                artifact_class=ArtifactClass.EFFECT,
                status=Status.EXECUTED,
                context=context,
                payload={
                    "effect_type": "release_communication",
                    "communication_id": communication.artifact_id,
                    "execution_status": "completed",
                    "authorization_id": None,
                },
                sources=(communication,),
                producer_id=self.COMMUNICATION,
                version="unmediated-release-v1",
                transition_type="release_without_authorization",
                disposition="executed",
            )
        else:
            self._require_class_status(authorization, ArtifactClass.EFFECT, (Status.AUTHORIZED,))
            self._require_context(context, authorization)
            if authorization.payload.get("effect_type") != "release_communication":
                raise AuthorityViolation("WRONG_EFFECT_TYPE", authorization.artifact_id)
            if authorization.payload.get("communication_id") != communication.artifact_id:
                raise AuthorityViolation("WRONG_RELEASE_TARGET", authorization.artifact_id)
            release_effect = self.execute_effect(authorization, context)

        released = self._issue(
            artifact_class=ArtifactClass.COMMUNICATION,
            status=Status.RELEASED,
            context=context,
            payload={
                **communication.payload,
                "release_effect_id": release_effect.artifact_id,
                "delivery_status": "delivered",
            },
            sources=(communication, release_effect),
            producer_id=self.EFFECT,
            version=communication.version,
            transition_type="release_communication",
            requester_identity=communication.producer_id,
            authorizer_identity_or_policy=(
                authorization.producer_id if authorization is not None else communication.producer_id
            ),
            disposition="released",
        )
        return released, release_effect

    def observe_outcome(self, executed_effect: Artifact, context: DecisionContext) -> Artifact:
        self._require_class_status(executed_effect, ArtifactClass.EFFECT, (Status.EXECUTED,))
        self._require_context(context, executed_effect)
        return self._issue(
            artifact_class=ArtifactClass.OUTCOME,
            status=Status.OBSERVED,
            context=context,
            payload={
                "related_effect_id": executed_effect.artifact_id,
                "observed_state": executed_effect.payload.get(
                    "requested_value",
                    executed_effect.payload.get("delivery_status", "completed"),
                ),
                "observation_source": "synthetic-system-of-record-readback",
            },
            sources=(executed_effect,),
            producer_id=self.OBSERVER,
            version="observer-v1",
            transition_type="observe_outcome",
            disposition="observed",
        )

    def accept_outcome(self, outcome: Artifact, context: DecisionContext) -> Artifact:
        self._require_class_status(outcome, ArtifactClass.OUTCOME, (Status.OBSERVED,))
        self._require_context(context, outcome)
        return self._issue(
            artifact_class=ArtifactClass.KNOWLEDGE,
            status=Status.ACCEPTED,
            context=context,
            payload={
                "source": "validated-outcome",
                "evidence": outcome.payload,
                "accepted_for": "post-effect reconstruction",
            },
            sources=(outcome,),
            producer_id=self.KNOWLEDGE,
            version="knowledge-schema-v1",
            transition_type="accept_outcome",
            authorizer_identity_or_policy=self.KNOWLEDGE,
            disposition="accepted",
        )

    def correct_evidence(
        self,
        original: Artifact,
        corrected_evidence: Mapping[str, Any],
        context: DecisionContext,
        *,
        reason: str,
    ) -> Artifact:
        self._require_class_status(original, ArtifactClass.KNOWLEDGE, (Status.ACCEPTED,))
        self._require_context(context, original)
        return self._issue(
            artifact_class=ArtifactClass.KNOWLEDGE,
            status=Status.ACCEPTED,
            context=context,
            payload={
                "source": original.payload.get("source", "corrected-record"),
                "evidence": dict(corrected_evidence),
                "accepted_for": context.intended_use,
                "correction_reason": reason,
            },
            sources=(original,),
            producer_id=self.KNOWLEDGE,
            version="knowledge-schema-v1",
            transition_type="correct_supersede",
            authorizer_identity_or_policy=self.REMEDY,
            disposition="successor-created",
            predecessors=(original,),
        )

    # The following methods exist only to drive controlled negative tests.

    def silent_promote_to_knowledge(self, source: Artifact, context: DecisionContext) -> Artifact:
        self._require_valid(source)
        self._require_context(context, source)
        if self.profile.typed_standing:
            raise AuthorityViolation("IMPLICIT_PROMOTION", source.artifact_id)
        return self._issue(
            artifact_class=ArtifactClass.KNOWLEDGE,
            status=Status.ACCEPTED,
            context=context,
            payload={"source": "silent-copy", "evidence": source.payload},
            sources=(source,),
            producer_id=source.producer_id,
            version=source.version,
            transition_type="silent_promotion",
            disposition="accepted-without-authority-transition",
        )

    def silent_outcome_reentry(self, outcome: Artifact, context: DecisionContext) -> Artifact:
        self._require_valid(outcome)
        self._require_context(context, outcome)
        if self.profile.outcome_reentry:
            raise AuthorityViolation("OUTCOME_REENTRY_REQUIRES_ACCEPTANCE", outcome.artifact_id)
        return self._issue(
            artifact_class=ArtifactClass.KNOWLEDGE,
            status=Status.ACCEPTED,
            context=context,
            payload={"source": "automatic-feedback", "evidence": outcome.payload},
            sources=(outcome,),
            producer_id=outcome.producer_id,
            version=outcome.version,
            transition_type="silent_outcome_reentry",
            disposition="accepted-without-validation",
        )

    def overwrite_evidence_in_place(
        self,
        original: Artifact,
        corrected_evidence: Mapping[str, Any],
        context: DecisionContext,
    ) -> Artifact:
        self._require_valid(original)
        self._require_context(context, original)
        if self.profile.successor_correction:
            raise AuthorityViolation("IN_PLACE_OVERWRITE", original.artifact_id)
        replacement = Artifact.issue(
            artifact_class=ArtifactClass.KNOWLEDGE,
            status=Status.ACCEPTED,
            scope=context.scope,
            context_id=context.context_id,
            payload={
                "source": original.payload.get("source", "overwritten-record"),
                "evidence": dict(corrected_evidence),
                "accepted_for": context.intended_use,
            },
            source_ids=(),
            producer_id=self.KNOWLEDGE,
            registry=self.registry,
            version=original.version,
            predecessor_ids=(),
            logical_time=self._tick(),
            forced_artifact_id=original.artifact_id,
        )
        self._put(replacement, replace_existing=True)
        self.ledger.append(
            transition_type="in_place_overwrite",
            source_artifact_ids=(),
            destination_artifact_id_or_status=original.artifact_id,
            authority_scope=context.scope,
            requester_identity=self.KNOWLEDGE,
            authorizer_identity_or_policy=self.KNOWLEDGE,
            context_id=context.context_id,
            policy_id=context.policy_version,
            artifact_versions=(replacement.version,),
            disposition="overwritten",
            logical_time=replacement.logical_time,
            predecessor_or_supersession_links=(),
            signer_id=self.KNOWLEDGE,
            metadata={"previous_digest_discarded": original.digest},
        )
        return replacement

    def run_valid_workflow(
        self,
        *,
        evidence: Mapping[str, Any],
        source: str,
        recipient: str,
        context: DecisionContext,
    ) -> WorkflowResult:
        accepted = self.accept_evidence(evidence=evidence, source=source, context=context)
        inferred = self.derive_eligibility(accepted, context)
        draft = self.render_notice(accepted, inferred, context)
        decision_proposal = self.propose_decision_effect(inferred, context)
        decision_authorization = self.authorize_effect(decision_proposal, context)
        decision_effect = self.execute_effect(decision_authorization, context)
        release_proposal = self.propose_release_effect(draft, context, recipient=recipient)
        release_authorization = self.authorize_effect(release_proposal, context)
        released, release_effect = self.release_communication(draft, context, release_authorization)
        outcome = self.observe_outcome(decision_effect, context)
        accepted_outcome = self.accept_outcome(outcome, context)
        return WorkflowResult(
            evidence=accepted,
            inference=inferred,
            communication_draft=draft,
            decision_proposal=decision_proposal,
            decision_authorization=decision_authorization,
            decision_effect=decision_effect,
            release_proposal=release_proposal,
            release_authorization=release_authorization,
            release_effect=release_effect,
            released_communication=released,
            outcome=outcome,
            accepted_outcome=accepted_outcome,
        )

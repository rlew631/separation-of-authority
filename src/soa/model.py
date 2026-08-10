from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, replace
from enum import Enum
from typing import Any, Iterable, Mapping


def canonical_json(value: Any) -> str:
    """Return a deterministic JSON representation used for IDs and signatures."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(value: Any) -> str:
    data = value if isinstance(value, str) else canonical_json(value)
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


class ArtifactClass(str, Enum):
    KNOWLEDGE = "K"
    INFERENCE = "I"
    COMMUNICATION = "C"
    EFFECT = "E"
    OUTCOME = "O"


class Role(str, Enum):
    KNOWLEDGE = "knowledge"
    INFERENCE = "inference"
    COMMUNICATION = "communication"
    POLICY = "policy"
    EFFECT = "effect"
    OBSERVER = "observer"
    REMEDY = "remedy"
    ASSURANCE = "assurance"


class Status(str, Enum):
    ACCEPTED = "accepted"
    DERIVED = "derived"
    DRAFT = "draft"
    PROPOSED = "proposed"
    AUTHORIZED = "authorized"
    EXECUTED = "executed"
    FAILED = "failed"
    RELEASED = "released"
    OBSERVED = "observed"
    SUPERSEDED = "superseded"
    REMEDIED = "remedied"


@dataclass(frozen=True, slots=True)
class DecisionContext:
    case_id: str
    intended_use: str
    jurisdiction: str
    scope: str
    actor_id: str
    policy_version: str
    method_version: str
    template_version: str
    target_version: str
    context_epoch: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "intended_use": self.intended_use,
            "jurisdiction": self.jurisdiction,
            "scope": self.scope,
            "actor_id": self.actor_id,
            "policy_version": self.policy_version,
            "method_version": self.method_version,
            "template_version": self.template_version,
            "target_version": self.target_version,
            "context_epoch": self.context_epoch,
        }

    @property
    def context_id(self) -> str:
        return f"ctx-{sha256_hex(self.to_dict())[:24]}"


@dataclass(frozen=True, slots=True)
class Principal:
    principal_id: str
    role: Role
    key: bytes


class AuthorityRegistry:
    """Local role/key registry used to make logical authority machine-checkable.

    The keys are deterministic demo keys. Co-locating them is acceptable for this
    constructive reference implementation but is not a production key-management design.
    """

    def __init__(self, principals: Iterable[Principal]):
        self._principals = {principal.principal_id: principal for principal in principals}
        if not self._principals:
            raise ValueError("at least one principal is required")

    @classmethod
    def demo(cls) -> "AuthorityRegistry":
        rows = (
            ("knowledge-authority", Role.KNOWLEDGE),
            ("inference-service", Role.INFERENCE),
            ("communication-service", Role.COMMUNICATION),
            ("policy-authority", Role.POLICY),
            ("effect-executor", Role.EFFECT),
            ("outcome-observer", Role.OBSERVER),
            ("remedy-authority", Role.REMEDY),
            ("assurance-ledger", Role.ASSURANCE),
        )
        principals = []
        for principal_id, role in rows:
            key = hashlib.sha256(f"soa-demo-key::{principal_id}".encode()).digest()
            principals.append(Principal(principal_id, role, key))
        return cls(principals)

    def role_of(self, principal_id: str) -> Role:
        try:
            return self._principals[principal_id].role
        except KeyError as exc:
            raise KeyError(f"unknown principal: {principal_id}") from exc

    def sign(self, principal_id: str, body: Mapping[str, Any]) -> str:
        principal = self._principals[principal_id]
        message = canonical_json(body).encode("utf-8")
        return hmac.new(principal.key, message, hashlib.sha256).hexdigest()

    def verify(self, principal_id: str, body: Mapping[str, Any], signature: str) -> bool:
        if principal_id not in self._principals:
            return False
        expected = self.sign(principal_id, body)
        return hmac.compare_digest(expected, signature)


@dataclass(frozen=True, slots=True)
class Artifact:
    artifact_id: str
    artifact_class: ArtifactClass
    status: Status
    scope: str
    context_id: str
    payload_json: str
    source_ids: tuple[str, ...]
    producer_id: str
    producer_role: Role
    version: str
    predecessor_ids: tuple[str, ...]
    logical_time: int
    signature: str

    @property
    def payload(self) -> dict[str, Any]:
        loaded = json.loads(self.payload_json)
        if not isinstance(loaded, dict):
            raise TypeError("artifact payload must be a JSON object")
        return loaded

    def unsigned_body(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "artifact_class": self.artifact_class.value,
            "status": self.status.value,
            "scope": self.scope,
            "context_id": self.context_id,
            "payload_json": self.payload_json,
            "source_ids": list(self.source_ids),
            "producer_id": self.producer_id,
            "producer_role": self.producer_role.value,
            "version": self.version,
            "predecessor_ids": list(self.predecessor_ids),
            "logical_time": self.logical_time,
        }

    @property
    def digest(self) -> str:
        return sha256_hex({**self.unsigned_body(), "signature": self.signature})

    def to_dict(self) -> dict[str, Any]:
        return {**self.unsigned_body(), "signature": self.signature, "digest": self.digest}

    def verify(self, registry: AuthorityRegistry) -> bool:
        try:
            producer_role = registry.role_of(self.producer_id)
        except KeyError:
            return False
        if producer_role != self.producer_role:
            return False
        return registry.verify(self.producer_id, self.unsigned_body(), self.signature)

    @classmethod
    def issue(
        cls,
        *,
        artifact_class: ArtifactClass,
        status: Status,
        scope: str,
        context_id: str,
        payload: Mapping[str, Any],
        source_ids: Iterable[str],
        producer_id: str,
        registry: AuthorityRegistry,
        version: str,
        predecessor_ids: Iterable[str] = (),
        logical_time: int,
        forced_artifact_id: str | None = None,
    ) -> "Artifact":
        payload_json = canonical_json(dict(payload))
        role = registry.role_of(producer_id)
        core = {
            "artifact_class": artifact_class.value,
            "status": status.value,
            "scope": scope,
            "context_id": context_id,
            "payload_json": payload_json,
            "source_ids": list(source_ids),
            "producer_id": producer_id,
            "producer_role": role.value,
            "version": version,
            "predecessor_ids": list(predecessor_ids),
            "logical_time": logical_time,
        }
        artifact_id = forced_artifact_id or f"{artifact_class.value}-{sha256_hex(core)[:24]}"
        provisional = cls(
            artifact_id=artifact_id,
            artifact_class=artifact_class,
            status=status,
            scope=scope,
            context_id=context_id,
            payload_json=payload_json,
            source_ids=tuple(core["source_ids"]),
            producer_id=producer_id,
            producer_role=role,
            version=version,
            predecessor_ids=tuple(core["predecessor_ids"]),
            logical_time=logical_time,
            signature="",
        )
        signature = registry.sign(producer_id, provisional.unsigned_body())
        return replace(provisional, signature=signature)


@dataclass(frozen=True, slots=True)
class EnforcementProfile:
    name: str
    typed_standing: bool = True
    independent_effect_authorization: bool = True
    context_binding: bool = True
    failure_non_escalation: bool = True
    communication_release_separation: bool = True
    successor_correction: bool = True
    outcome_reentry: bool = True
    assurance_integrity: bool = True
    authorization_expiry: bool = True

    @classmethod
    def strict(cls) -> "EnforcementProfile":
        return cls(name="strict")

    @classmethod
    def collapsed(cls) -> "EnforcementProfile":
        return cls(
            name="collapsed",
            typed_standing=False,
            independent_effect_authorization=False,
            context_binding=False,
            failure_non_escalation=False,
            communication_release_separation=False,
            successor_correction=False,
            outcome_reentry=False,
            assurance_integrity=False,
            authorization_expiry=False,
        )

    def ablate(self, field_name: str) -> "EnforcementProfile":
        if field_name == "name" or not hasattr(self, field_name):
            raise ValueError(f"unknown enforcement control: {field_name}")
        return replace(self, name=f"ablate:{field_name}", **{field_name: False})

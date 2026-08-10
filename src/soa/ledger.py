from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from .model import AuthorityRegistry, canonical_json, sha256_hex


@dataclass(frozen=True, slots=True)
class VerificationResult:
    valid: bool
    reason: str
    checked_entries: int


class AssuranceLedger:
    """Append-only, hash-chained transition receipts.

    Integrity can be disabled only for the experimental ablation profile.
    """

    GENESIS = "0" * 64

    def __init__(self, registry: AuthorityRegistry, *, protected: bool = True):
        self._registry = registry
        self._protected = protected
        self._entries: list[dict[str, Any]] = []

    @property
    def protected(self) -> bool:
        return self._protected

    def append(
        self,
        *,
        transition_type: str,
        source_artifact_ids: Iterable[str],
        destination_artifact_id_or_status: str,
        authority_scope: str,
        requester_identity: str,
        authorizer_identity_or_policy: str,
        context_id: str,
        policy_id: str,
        artifact_versions: Iterable[str],
        disposition: str,
        logical_time: int,
        predecessor_or_supersession_links: Iterable[str],
        signer_id: str,
        metadata: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        previous_hash = self._entries[-1]["entry_hash"] if self._entries else self.GENESIS
        body = {
            "sequence": len(self._entries) + 1,
            "transition_type": transition_type,
            "source_artifact_ids": list(source_artifact_ids),
            "destination_artifact_id_or_status": destination_artifact_id_or_status,
            "authority_scope": authority_scope,
            "requester_identity": requester_identity,
            "authorizer_identity_or_policy": authorizer_identity_or_policy,
            "context_id": context_id,
            "policy_id": policy_id,
            "artifact_versions": list(artifact_versions),
            "disposition": disposition,
            "logical_time": logical_time,
            "predecessor_or_supersession_links": list(predecessor_or_supersession_links),
            "previous_hash": previous_hash,
            "signer_id": signer_id,
            "signer_role": self._registry.role_of(signer_id).value,
            "metadata": dict(metadata or {}),
        }
        entry_hash = sha256_hex(body)
        signature = self._registry.sign(signer_id, {**body, "entry_hash": entry_hash}) if self._protected else ""
        entry = {**body, "entry_hash": entry_hash, "signature": signature}
        self._entries.append(entry)
        return copy.deepcopy(entry)

    def entries(self) -> list[dict[str, Any]]:
        return copy.deepcopy(self._entries)

    def jsonl(self) -> str:
        return "\n".join(canonical_json(entry) for entry in self._entries) + ("\n" if self._entries else "")

    def verify(self, entries: list[dict[str, Any]] | None = None) -> VerificationResult:
        records = self._entries if entries is None else entries
        if not self._protected:
            return VerificationResult(True, "integrity controls disabled by ablation profile", len(records))

        previous_hash = self.GENESIS
        for index, entry in enumerate(records, start=1):
            if entry.get("sequence") != index:
                return VerificationResult(False, f"sequence mismatch at entry {index}", index - 1)
            if entry.get("previous_hash") != previous_hash:
                return VerificationResult(False, f"hash-chain mismatch at entry {index}", index - 1)

            body = {key: value for key, value in entry.items() if key not in {"entry_hash", "signature"}}
            computed_hash = sha256_hex(body)
            if entry.get("entry_hash") != computed_hash:
                return VerificationResult(False, f"entry hash mismatch at entry {index}", index - 1)

            signer_id = entry.get("signer_id", "")
            try:
                signer_role = self._registry.role_of(signer_id)
            except KeyError:
                return VerificationResult(False, f"unknown signer at entry {index}", index - 1)
            if entry.get("signer_role") != signer_role.value:
                return VerificationResult(False, f"signer role mismatch at entry {index}", index - 1)
            signed_body = {**body, "entry_hash": computed_hash}
            if not self._registry.verify(signer_id, signed_body, entry.get("signature", "")):
                return VerificationResult(False, f"signature mismatch at entry {index}", index - 1)

            previous_hash = computed_hash

        return VerificationResult(True, "ok", len(records))

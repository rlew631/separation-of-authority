from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Callable

from .model import EnforcementProfile


@dataclass(frozen=True, slots=True)
class AbstractState:
    facts: frozenset[str] = frozenset()

    def has(self, *facts: str) -> bool:
        return all(fact in self.facts for fact in facts)

    def add(self, *facts: str) -> "AbstractState":
        return AbstractState(self.facts.union(facts))


@dataclass(frozen=True, slots=True)
class AbstractAction:
    name: str
    apply: Callable[[AbstractState, EnforcementProfile], AbstractState | None]


BAD_FACTS = {
    "bad_silent_promotion": "I1/I2",
    "bad_self_authorized_effect": "I3",
    "bad_context_replay": "I4",
    "bad_policy_outage_fallback": "I5",
    "bad_unapproved_release": "I6",
    "bad_in_place_overwrite": "I7",
    "bad_outcome_reentry": "I8",
    "bad_assurance_tamper": "I10",
    "bad_expired_authorization": "I4-time",
}


def _if_missing(state: AbstractState, fact: str, result: AbstractState) -> AbstractState | None:
    return None if fact in state.facts else result


def _accept(state: AbstractState, _: EnforcementProfile) -> AbstractState | None:
    return _if_missing(state, "k", state.add("k"))


def _derive(state: AbstractState, _: EnforcementProfile) -> AbstractState | None:
    if not state.has("k"):
        return None
    return _if_missing(state, "i", state.add("i"))


def _render(state: AbstractState, _: EnforcementProfile) -> AbstractState | None:
    if not state.has("k", "i"):
        return None
    return _if_missing(state, "c_draft", state.add("c_draft"))


def _propose(state: AbstractState, _: EnforcementProfile) -> AbstractState | None:
    if not state.has("i"):
        return None
    return _if_missing(state, "e_proposed", state.add("e_proposed"))


def _authorize(state: AbstractState, _: EnforcementProfile) -> AbstractState | None:
    if not state.has("e_proposed"):
        return None
    return _if_missing(state, "e_authorized", state.add("e_authorized"))


def _execute(state: AbstractState, _: EnforcementProfile) -> AbstractState | None:
    if not state.has("e_authorized"):
        return None
    return _if_missing(state, "e_executed", state.add("e_executed"))


def _observe(state: AbstractState, _: EnforcementProfile) -> AbstractState | None:
    if not state.has("e_executed"):
        return None
    return _if_missing(state, "o", state.add("o"))


def _accept_outcome(state: AbstractState, _: EnforcementProfile) -> AbstractState | None:
    if not state.has("o"):
        return None
    return _if_missing(state, "k_outcome", state.add("k_outcome"))


def _authorize_release(state: AbstractState, _: EnforcementProfile) -> AbstractState | None:
    if not state.has("c_draft"):
        return None
    return _if_missing(state, "release_authorized", state.add("release_authorized"))


def _release(state: AbstractState, _: EnforcementProfile) -> AbstractState | None:
    if not state.has("c_draft", "release_authorized"):
        return None
    return _if_missing(state, "c_released", state.add("c_released"))


def _correct_successor(state: AbstractState, _: EnforcementProfile) -> AbstractState | None:
    if not state.has("k"):
        return None
    return _if_missing(state, "k_successor", state.add("k_successor"))


def _silent_promotion(state: AbstractState, profile: EnforcementProfile) -> AbstractState | None:
    if profile.typed_standing or not state.has("i"):
        return None
    return _if_missing(state, "bad_silent_promotion", state.add("bad_silent_promotion"))


def _self_authorize(state: AbstractState, profile: EnforcementProfile) -> AbstractState | None:
    if profile.independent_effect_authorization or not state.has("e_proposed"):
        return None
    return _if_missing(
        state,
        "bad_self_authorized_effect",
        state.add("e_authorized", "e_executed", "bad_self_authorized_effect"),
    )


def _context_replay(state: AbstractState, profile: EnforcementProfile) -> AbstractState | None:
    if profile.context_binding or not state.has("e_authorized"):
        return None
    return _if_missing(state, "bad_context_replay", state.add("bad_context_replay"))


def _policy_outage(state: AbstractState, profile: EnforcementProfile) -> AbstractState | None:
    if profile.failure_non_escalation or not state.has("e_proposed"):
        return None
    return _if_missing(
        state,
        "bad_policy_outage_fallback",
        state.add("e_authorized", "bad_policy_outage_fallback"),
    )


def _unapproved_release(state: AbstractState, profile: EnforcementProfile) -> AbstractState | None:
    if profile.communication_release_separation or not state.has("c_draft"):
        return None
    return _if_missing(
        state,
        "bad_unapproved_release",
        state.add("c_released", "bad_unapproved_release"),
    )


def _in_place_overwrite(state: AbstractState, profile: EnforcementProfile) -> AbstractState | None:
    if profile.successor_correction or not state.has("k"):
        return None
    return _if_missing(state, "bad_in_place_overwrite", state.add("bad_in_place_overwrite"))


def _outcome_reentry(state: AbstractState, profile: EnforcementProfile) -> AbstractState | None:
    if profile.outcome_reentry or not state.has("o"):
        return None
    return _if_missing(
        state,
        "bad_outcome_reentry",
        state.add("k_outcome", "bad_outcome_reentry"),
    )


def _assurance_tamper(state: AbstractState, profile: EnforcementProfile) -> AbstractState | None:
    if profile.assurance_integrity or not state.facts:
        return None
    return _if_missing(state, "bad_assurance_tamper", state.add("bad_assurance_tamper"))


def _expired_authorization(state: AbstractState, profile: EnforcementProfile) -> AbstractState | None:
    if profile.authorization_expiry or not state.has("e_authorized"):
        return None
    return _if_missing(
        state,
        "bad_expired_authorization",
        state.add("e_executed", "bad_expired_authorization"),
    )


ACTIONS = (
    AbstractAction("accept_evidence", _accept),
    AbstractAction("derive", _derive),
    AbstractAction("render", _render),
    AbstractAction("propose_effect", _propose),
    AbstractAction("authorize_effect", _authorize),
    AbstractAction("execute_effect", _execute),
    AbstractAction("observe_outcome", _observe),
    AbstractAction("accept_outcome", _accept_outcome),
    AbstractAction("authorize_release", _authorize_release),
    AbstractAction("release_communication", _release),
    AbstractAction("create_successor", _correct_successor),
    AbstractAction("attack_silent_promotion", _silent_promotion),
    AbstractAction("attack_self_authorization", _self_authorize),
    AbstractAction("attack_context_replay", _context_replay),
    AbstractAction("attack_policy_outage", _policy_outage),
    AbstractAction("attack_unapproved_release", _unapproved_release),
    AbstractAction("attack_in_place_overwrite", _in_place_overwrite),
    AbstractAction("attack_outcome_reentry", _outcome_reentry),
    AbstractAction("attack_assurance_tamper", _assurance_tamper),
    AbstractAction("attack_expired_authorization", _expired_authorization),
)


def explore(profile: EnforcementProfile) -> dict[str, object]:
    """Exhaustively explore the finite monotonic transition system."""
    initial = AbstractState()
    queue: deque[AbstractState] = deque([initial])
    seen = {initial}
    predecessor: dict[AbstractState, tuple[AbstractState, str]] = {}
    explored_edges = 0

    while queue:
        state = queue.popleft()
        for action in ACTIONS:
            successor = action.apply(state, profile)
            if successor is None or successor == state:
                continue
            explored_edges += 1
            if successor not in seen:
                seen.add(successor)
                predecessor[successor] = (state, action.name)
                queue.append(successor)

    violations: dict[str, list[str]] = {}
    for bad_fact in BAD_FACTS:
        candidates = [state for state in seen if bad_fact in state.facts]
        if not candidates:
            continue
        target = min(candidates, key=lambda state: len(state.facts))
        trace: list[str] = []
        cursor = target
        while cursor != initial:
            parent, action_name = predecessor[cursor]
            trace.append(action_name)
            cursor = parent
        trace.reverse()
        violations[bad_fact] = trace

    return {
        "profile": profile.name,
        "reachable_states": len(seen),
        "explored_edges": explored_edges,
        "violation_count": len(violations),
        "violations": violations,
        "bad_fact_catalog": BAD_FACTS,
    }

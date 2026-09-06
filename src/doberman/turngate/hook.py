"""Slice TG1.2 — the pre-inference hook seam (``gate_turn``).

The integration point a host calls **before inference**: it captures the turn,
runs the gate, and enforces the verdict before the model spends a token.

* **PASS** → release the turn to the model.
* **AUTH** → run the F7 challenge naming the matched reason; release only on
  approval, otherwise the turn does not reach the model.
* **BLOCK** → never release; remember the turn so a deliberate resubmission gets
  the TG4 escape hatch (a repeat of a recently-blocked turn is challenged, not
  re-blocked, until it locks out).

Two fail-safes define the posture: **graceful absence** (with ``DOBERMAN_TURN_GATE``
off — or a host with no pre-inference surface — the gate is disabled and the
action gate carries everything), and **fail toward the human** (any internal
error becomes AUTH, never a silent pass and never a hard lockout on a bug).

This module is an adapter: it imports engine/auth/storage but never
``doberman.proxy``. The blocking challenge runs inline; a host that calls this on
an event loop should dispatch it off-thread (as ``doberman serve`` does for the
action gate).
"""

import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone

from doberman.auth.challenge import (
    TIMEOUT_METHOD,
    AuthResult,
    Prompter,
    human_answered,
    run_auth_challenge,
)
from doberman.config import load_message_tone
from doberman.engine.decision_engine import TurnGuardrail, decide_turn
from doberman.models import (
    ActionType,
    AuthPath,
    Decision,
    EvalContext,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    TurnObject,
    Verdict,
)
from doberman.turngate import repeat, stylometry
from doberman.turngate.handoff import publish_turn_context
from doberman.turngate.heuristics import Tier1HeuristicGuardrail
from doberman.turngate.log import record_turn_decision
from doberman.turngate.normalize import normalize_turn
from doberman.turngate.raw import RAW_TURN_KEY, STYLE_PVALUE_KEY
from doberman.turngate.signatures import Tier0SignatureGuardrail
from doberman.turngate.task_tokens import record_task_hosts as _record_task_hosts

logger = logging.getLogger("doberman.turngate.hook")

#: Default tier guardrails (module-level so tests/hosts can inject their own).
DEFAULT_TIER0: TurnGuardrail = Tier0SignatureGuardrail()
DEFAULT_TIER1: TurnGuardrail = Tier1HeuristicGuardrail()

_ENV_FLAG = "DOBERMAN_TURN_GATE"
_OFF_VALUES = frozenset({"off", "0", "false", "no", "disabled"})


@dataclass(frozen=True)
class TurnGateOutcome:
    """The result of gating one turn.

    ``released`` is the only operational bit: True means the turn may reach the
    model. ``decision`` is the (turn-shaped) :class:`Decision` for audit.
    """

    released: bool
    verdict: Verdict
    decision: Decision
    note: str


def is_turn_gate_enabled() -> bool:
    """Whether the gate is active (``DOBERMAN_TURN_GATE`` not set to an off value)."""
    return os.environ.get(_ENV_FLAG, "on").strip().lower() not in _OFF_VALUES


def _synthetic_action(turn: TurnObject) -> SecurityObject:
    """A minimal action the F7 challenge can name for a turn (no target)."""
    return SecurityObject(
        id=turn.id,
        ts=turn.ts,
        agent_role="user",
        action_type=ActionType.other,
        tool_name="(turn)",
        target=None,
    )


def _decision_from_result(turn: TurnObject, result: GuardrailResult, when: datetime) -> Decision:
    """Wrap a single GuardrailResult as a turn Decision (for logging)."""
    return Decision(
        action_id=turn.id,
        final_verdict=result.verdict,
        final_risk=result.risk,
        objective=result,
        subjective=None,
        reason_codes=list(result.reason_codes),
        explanation=result.explanation,
        decided_at=when,
    )


def _pass_decision(turn: TurnObject, when: datetime) -> Decision:
    passed = GuardrailResult(verdict=Verdict.PASS, risk=Risk.low)
    return _decision_from_result(turn, passed, when)


def _auth_result_label(result: AuthResult, *, approved: bool) -> str:
    """The ``auth_result`` recorded for a challenge, keeping a silent timeout distinct
    from a human refusal (AN-4a).

    An expired-unanswered challenge is a different operational event from one a human
    declined; collapsing both to ``"denied"`` hides exactly the distinction ADR 0046
    (the wall-clock deadline) exists to record.
    """
    if approved:
        return "approved"
    return "timeout" if result.method == TIMEOUT_METHOD else "denied"


_AUTH_NOTES = {
    "approved": "auth approved",
    "timeout": "auth timed out (auto-denied)",
    "denied": "auth denied",
}


async def _enforce(
    turn: TurnObject,
    decision: Decision,
    *,
    prompter: Prompter | None,
    repo_root: str,
    session_id: str | None,
    entity_id: str,
    when: datetime,
) -> TurnGateOutcome:
    """Act on a fresh turn decision: block (and remember), challenge, or release."""
    if decision.final_verdict is Verdict.BLOCK:
        repeat.register_block(
            entity_id, turn.prompt_fingerprint, decision.reason_codes[0], now=when
        )
        await record_turn_decision(turn, decision, repo_root=repo_root, stage="turn_block")
        return TurnGateOutcome(False, Verdict.BLOCK, decision, "blocked (Tier 0 signature)")

    if decision.final_verdict is Verdict.AUTH:
        result = run_auth_challenge(
            decision,
            _synthetic_action(turn),
            prompter=prompter,
            at=when,
            message_tone=load_message_tone(repo_root),
            repo_root=repo_root,
            session_id=session_id,
        )
        approved = result.approved and result.action_id == turn.id
        label = _auth_result_label(result, approved=approved)
        await record_turn_decision(
            turn,
            decision,
            repo_root=repo_root,
            stage="turn_auth",
            auth_result=label,
            auth_path=AuthPath.turn_gate,
            # Approval alone is not human confirmation: approval memory can
            # satisfy a challenge with nobody present, and it must not be
            # recorded as though somebody was.
            human_confirmed=approved and human_answered(result.method),
        )
        return TurnGateOutcome(approved, Verdict.AUTH, decision, _AUTH_NOTES[label])

    await record_turn_decision(turn, decision, repo_root=repo_root, stage="turn_pass")
    return TurnGateOutcome(True, Verdict.PASS, decision, "released")


async def _handle_repeat(
    turn: TurnObject,
    record: repeat.RepeatRecord,
    *,
    prompter: Prompter | None,
    repo_root: str,
    session_id: str | None,
    entity_id: str,
    when: datetime,
) -> TurnGateOutcome:
    """A resubmission of a recently-blocked turn: challenge, release, or lock out."""
    if repeat.disposition(record) == "lockout":
        blocked = repeat.lockout_block(record.block_reason)
        decision = _decision_from_result(turn, blocked, when)
        await record_turn_decision(turn, decision, repo_root=repo_root, stage="turn_lockout")
        return TurnGateOutcome(False, Verdict.BLOCK, decision, "locked out (repeat)")

    result = repeat.challenge_repeat(
        turn,
        record,
        prompter=prompter,
        at=when,
        message_tone=load_message_tone(repo_root),
        repo_root=repo_root,
        session_id=session_id,
    )
    if result.approved and result.action_id == turn.id:
        repeat.clear_record(entity_id, turn.prompt_fingerprint)  # single-use
        decision = _pass_decision(turn, when)
        await record_turn_decision(
            turn,
            decision,
            repo_root=repo_root,
            stage="turn_repeat_approved",
            auth_result="approved",
            auth_path=AuthPath.turn_gate,
            human_confirmed=human_answered(result.method),
        )
        return TurnGateOutcome(True, Verdict.AUTH, decision, "repeat approved (released)")

    repeat.note_denied(entity_id, turn.prompt_fingerprint, now=when)
    reblock = GuardrailResult(
        verdict=Verdict.BLOCK,
        risk=Risk.high,
        reason_codes=[ReasonCode.repeat_after_block, record.block_reason],
        explanation="Resubmission of a blocked turn was not approved; blocked.",
    )
    decision = _decision_from_result(turn, reblock, when)
    label = _auth_result_label(result, approved=False)
    await record_turn_decision(
        turn,
        decision,
        repo_root=repo_root,
        stage="turn_repeat_denied",
        auth_result=label,
        auth_path=AuthPath.turn_gate,
        # Nothing was approved here, so nobody confirmed anything; `auth_result`
        # still separates a human "denied" from a silent "timeout".
        human_confirmed=False,
    )
    note = "repeat timed out (blocked)" if label == "timeout" else "repeat denied (blocked)"
    return TurnGateOutcome(False, Verdict.BLOCK, decision, note)


def _fail_to_human(turn: TurnObject, when: datetime) -> Decision:
    """The AUTH decision used when the gate itself errs (fail toward the human)."""
    result = GuardrailResult(
        verdict=Verdict.AUTH,
        risk=Risk.high,
        reason_codes=[ReasonCode.turn_gate_error],
        explanation="Turn gate failed to evaluate; deferring to the human (fail upward).",
    )
    return _decision_from_result(turn, result, when)


async def gate_turn(
    prompt: str,
    *,
    entity_id: str,
    segments=None,
    repo_root: str = ".",
    prompter: Prompter | None = None,
    ts: datetime | None = None,
    tier0: TurnGuardrail | None = None,
    tier1: TurnGuardrail | None = None,
    session_id: str | None = None,
) -> TurnGateOutcome:
    """Gate one pre-inference turn and return whether it may reach the model.

    Disabled (env / no host hook) → released with a logged notice. Otherwise:
    normalize → repeat-check → ``decide_turn`` → enforce. Any internal failure
    fails toward the human (AUTH); a denied AUTH/BLOCK is never released.

    ``session_id`` (D2): the harness's own per-conversation session id — the
    same HK.5.1 id the host-hook spine (``hosthooks/spine.py``) already
    extracts and passes to the C3.1 correlator (``apply_correlator``) as
    cross-call decision history's scope. A host wiring this pre-inference hook
    should pass the SAME id it passes to the post-action spine, so a task
    token captured here is visible to that session's own correlator reads.
    ``None`` (no host session concept, or a host that hasn't wired it) simply
    disables task-token capture for this turn — the correlator behaves exactly
    as it did before this feature, unchanged.
    """
    when = ts or datetime.now(timezone.utc)
    tier0 = tier0 if tier0 is not None else DEFAULT_TIER0
    tier1 = tier1 if tier1 is not None else DEFAULT_TIER1

    if not is_turn_gate_enabled():
        logger.info("turn_gate=disabled; releasing the turn to the action gate")
        passed = GuardrailResult(verdict=Verdict.PASS, risk=Risk.low)
        synthetic = TurnObject(
            id="disabled", ts=when, entity_id=entity_id, prompt_fingerprint="hmac:disabled"
        )
        return TurnGateOutcome(
            True, Verdict.PASS, _decision_from_result(synthetic, passed, when), "turn gate disabled"
        )

    try:
        turn, raw = normalize_turn(prompt, entity_id=entity_id, ts=when, segments=segments)
        metadata: dict = {RAW_TURN_KEY: raw}
        # TG3.2: precompute the stylometric p-value (async DB read) so the
        # synchronous Tier 1 guardrail can gate on it — the same pattern the
        # action path uses for the SL4 surprise term. None (immature baseline /
        # failure) ⇒ the key is absent and the stylometric gate abstains.
        style_p = await stylometry.style_pvalue(
            raw.full_text, entity_id=entity_id, repo_root=repo_root
        )
        if style_p is not None:
            metadata[STYLE_PVALUE_KEY] = style_p
        ctx = EvalContext(metadata=metadata)
        record = repeat.lookup(entity_id, turn.prompt_fingerprint, now=when)
        if record is not None:
            outcome = await _handle_repeat(
                turn,
                record,
                prompter=prompter,
                repo_root=repo_root,
                session_id=session_id,
                entity_id=entity_id,
                when=when,
            )
        else:
            decision = decide_turn(turn, tier0, tier1, ctx)
            outcome = await _enforce(
                turn,
                decision,
                prompter=prompter,
                repo_root=repo_root,
                session_id=session_id,
                entity_id=entity_id,
                when=when,
            )
        if outcome.released:
            # Released turns ONLY teach the prompt-style baseline — a blocked
            # or denied turn never teaches "normal" (the SL4 invariant).
            await stylometry.observe_style(
                raw.full_text, entity_id=entity_id, repo_root=repo_root, now=when
            )
            # D2: released turns ONLY contribute task-match tokens — same
            # discipline as the style baseline above and as publish_turn_context
            # below ("a turn that was NOT released publishes nothing"): a
            # turn that never reached the model earns no say in what egress
            # counts as user-justified.
            await _record_task_hosts(raw, repo_root=repo_root, session_id=session_id)
        # TG3.3: a released turn's signals (style p-value + flags) ride along
        # to the action stage as the entity's TurnContext (raise-only there).
        publish_turn_context(
            turn, outcome.decision, style_pvalue=style_p, released=outcome.released
        )
        return outcome
    except Exception:  # noqa: BLE001 — fail toward the human, never silent-pass
        logger.warning("turn gate raised; failing toward the human (AUTH)")
        fallback_turn = TurnObject(
            id="turn-error", ts=when, entity_id=entity_id, prompt_fingerprint="hmac:error"
        )
        decision = _fail_to_human(fallback_turn, when)
        result = run_auth_challenge(
            decision,
            _synthetic_action(fallback_turn),
            prompter=prompter,
            at=when,
            message_tone=load_message_tone(repo_root),
            repo_root=repo_root,
            session_id=session_id,
        )
        approved = result.approved and result.action_id == fallback_turn.id
        return TurnGateOutcome(approved, Verdict.AUTH, decision, "fail-to-human")

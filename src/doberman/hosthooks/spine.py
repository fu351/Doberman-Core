"""Host-generic evaluate/record spine shared by every host-hook adapter (W1.0a).

Every host hook does the same thing between "translated the host's tool call"
and "shaped the host's answer": resolve repo root + strictness mode, extract a
session id, normalize, decide, apply the taint floor, apply the session
correlator (C3.1), resolve the enforcement dial, compute the acted verdict,
and record monitor-softened history. This module owns that flow so a new host
supplies ONLY its tool map, required-field checks, and output shape.

Speed contract (same as the adapters): imports only the light decision path —
NEVER the proxy's tool-execution module or the subjective baseline (their ML
dependencies cost ~2s at module scope on every tool call).

Error contract: :func:`evaluate_action` MAY raise — each host adapter keeps its
own outer try/except converting any failure into ITS fail-closed deny shape.
:func:`record_history` is best-effort and never raises (imports inside the try:
a missing storage backend must not turn an approved AUTH into a deny).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from doberman.config import load_active_role, load_mode, resolve_enforcement_sync
from doberman.engine.correlator import apply_correlator
from doberman.engine.decision_engine import PASS_STUB, decide
from doberman.engine.objective import ObjectiveGuardrail
from doberman.engine.taint_floor import apply_echo_tripwire, apply_taint_floor
from doberman.models import AuthPath, Decision, EvalContext, SecurityObject, Verdict
from doberman.policy.drift import acted_verdict
from doberman.policy.modes import DEFAULT_MODE
from doberman.policy.sources import effective_policy
from doberman.proxy.normalize import challenge_copy, normalize


@dataclass(frozen=True)
class SpineResult:
    """One evaluated host action: the truthful decision plus what to enforce."""

    decision: Decision
    action: SecurityObject
    acted: Verdict
    enforcement: str
    repo_root: str
    session_id: str | None
    #: The action to hand to an AUTH challenge: ``action`` plus the prompt-only
    #: rendering of the raw arguments (``proxy.normalize.challenge_copy``).
    #: Never recorded — history and the dashboard row derive from ``action``.
    challenge_action: SecurityObject


def resolve_root_and_mode(cwd: object) -> tuple[str, str]:
    """Resolve ``(repo_root, strictness_mode)`` from a hook payload's ``cwd``.

    #51: with a valid ``cwd`` read the project's saved mode. With a missing/
    empty/invalid ``cwd`` do NOT fall back to ``load_mode(".")`` (a different
    project's policy, possibly weaker) — use the recommended default mode.
    ``repo_root`` keeps the ``"."`` fallback for storage scoping.
    """
    if isinstance(cwd, str) and cwd:
        return cwd, load_mode(cwd)
    return ".", DEFAULT_MODE.value


def extract_session_id(raw: object) -> str | None:
    """A non-empty string session id, else ``None`` (repo-scope fallback)."""
    return raw if isinstance(raw, str) and raw else None


def is_excluded(cwd: object) -> bool:
    """True if *cwd* resolves into a device-wide excluded project.

    Every host adapter must call this as the very first thing it does with a
    hook payload — before any other check, including the "no identifiable
    action -> fail-closed deny" logic. It is a pure read (see
    :mod:`doberman.storage.exclusions`): no I/O side effect, so an excluded
    project gets a true no-op, not softened enforcement. Any resolution
    failure fails closed (returns ``False`` — protection stays on).
    """
    from doberman.storage.exclusions import is_excluded as _is_excluded

    repo_root, _ = resolve_root_and_mode(cwd)
    return _is_excluded(repo_root)


def evaluate_action(
    canonical: str,
    args: dict[str, Any],
    *,
    cwd: object,
    raw_session_id: object,
) -> SpineResult:
    """Run one translated action through the full shared decision flow."""
    repo_root, mode = resolve_root_and_mode(cwd)
    session_id = extract_session_id(raw_session_id)
    action = normalize(canonical, args, {"repo_root": repo_root})
    # The objective rules inspect the UN-redacted call via metadata['raw_arguments']
    # (in-memory only, never logged). The active role rides along (parity with
    # the proxy's own ctx-build path); no .doberman/role.yaml -> role=None (opt-in).
    metadata: dict[str, Any] = {"raw_arguments": args, "repo_root": repo_root}
    # #147: resolved_policy set ONLY when non-empty -- a repo with no committed
    # doberman.policy.yaml and no registered policy-source plugin is
    # byte-identical to before this seam existed (PolicySourceRule abstains).
    policy = effective_policy(repo_root)
    if not policy.is_empty:
        metadata["resolved_policy"] = policy
    ctx = EvalContext(
        role=load_active_role(repo_root),
        mode=mode,
        metadata=metadata,
    )
    decision = decide(action, ObjectiveGuardrail(), PASS_STUB, ctx)
    decision = apply_taint_floor(action, decision, ctx.mode, repo_root, session_id, args)
    # C1 — the untrusted-value echo tripwire: same scope keying, right after
    # the secret-taint floor for the identical cross-call reason (see
    # engine/taint_floor.py's module docstring).
    decision = apply_echo_tripwire(action, decision, ctx.mode, repo_root, session_id, args)
    # C3.1 session correlator: cross-call PATTERN raise (raise-only), right after
    # the taint floor for the same reason (see doberman.engine.correlator's module
    # docstring). Unlike the pure-MCP proxy's tool-execution chokepoint (no session
    # concept of its own, always passes session_id=None), THIS path already has a
    # real per-session id — the host harness's own session id (HK.5.1), extracted
    # above and already used to scope the taint floor and the decision-history
    # writes below — so the correlator reads real cross-call history here and can
    # actually fire in production.
    decision = apply_correlator(action, decision, ctx.mode, repo_root, session_id)
    enforcement = resolve_enforcement_sync(repo_root)
    acted = acted_verdict(decision, enforcement)
    if (
        acted is Verdict.PASS
        and enforcement == "monitor"
        and decision.final_verdict is not Verdict.PASS
    ):
        # A would-be AUTH/BLOCK softened by MONITOR is history-worthy: record the
        # ORIGINAL (truthful) decision, outcome "executed" (a synthetic allow).
        # `off` softens the same way but is the silent, non-recording state; a
        # genuine PASS is never recorded (hot path — a DB write per pass floods).
        # A synthetic allow: `monitor` softened a real AUTH/BLOCK and nothing
        # asked anyone. Recorded under its own path so an audit can separate
        # "executed because a human approved" from "executed because
        # enforcement was dialled down" — indistinguishable before #505.
        record_history(
            decision,
            action,
            repo_root,
            session_id,
            auth_result="executed",
            auth_path=AuthPath.host_hook_monitor,
            human_confirmed=False,
        )
    return SpineResult(
        decision,
        action,
        acted,
        enforcement,
        repo_root,
        session_id,
        challenge_copy(action, args),
    )


def record_history(
    decision: Decision,
    action: SecurityObject,
    repo_root: str,
    session_id: str | None,
    *,
    auth_result: str,
    auth_path: str = AuthPath.host_hook_objective,
    human_confirmed: bool | None = None,
) -> None:
    """Best-effort: persist one decision row to the local decision log.

    Imports live INSIDE the try (unlike the pre-extraction helper) so even a
    lazy-import failure can never raise into a hook path.

    ``auth_path``/``human_confirmed`` (#505) record WHO resolved the
    authentication. This path is the reason those columns exist: its
    ``auth_result`` vocabulary is only ``executed``/``blocked``, which cannot
    tell "a human approved this" apart from "nothing ever asked a human" — the
    ambiguity #399 turned on. The default is the objective path (no challenge
    ran, no human involved), so only a caller that actually challenged has to
    say otherwise.
    """
    try:
        import asyncio  # lazy — keeps module scope light

        from doberman.storage.log import record_decision

        asyncio.run(
            record_decision(
                decision,
                action,
                repo_root=repo_root,
                auth_result=auth_result,
                session_id=session_id,
                auth_path=auth_path,
                human_confirmed=human_confirmed,
            )
        )
    except Exception:  # noqa: BLE001,S110 — history must never break a hook path
        pass

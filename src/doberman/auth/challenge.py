"""Auth-tier selection and the action-specific challenge (Feature 7, slices 7.1, 7.3).

When the engine returns ``AUTH``, Doberman must prove the action is *deliberate*.
The proof required scales with risk:

* ``soft_confirm`` — a yes/no acknowledgement (minor, unusual-but-allowed).
* ``local_auth`` — local human presence at the CLI.
* ``two_factor`` — local presence **plus** a TOTP code (sensitive / high risk).
* ``role_elevation`` — the action crosses the agent's role boundary; satisfying
  it grants a narrow, temporary elevation (slice 7.4) for that one target.

:func:`select_tier` derives the tier from the **already-final** risk and reason
codes (so a subjective/role escalation correctly bumps the proof required), and
:func:`run_auth_challenge` presents the *specific* action and collects the proof
through the active :class:`~doberman.auth.provider.AuthProvider`.

SECURITY: the challenge always names the exact action and reason — never a
generic "enter 2FA". Any timeout, input error, or denial yields a non-approved
:class:`AuthResult` (fail closed). A hard block (``BLOCK``) never reaches here:
:func:`select_tier` rejects a non-``AUTH`` decision.

That fail-closed guarantee is enforced by :data:`DEFAULT_CHALLENGE_TIMEOUT_S`,
not by exception handling alone. An ``except`` clause only catches a prompter
that *raises*; a prompter that blocks forever — a GUI dialog nobody closes, a
``readline`` on an unattended terminal — never returns and never raises, so no
handler can fire and the agent's tool call hangs indefinitely. **An indefinite
block is not a denial.** :func:`run_auth_challenge` therefore imposes a hard
wall-clock deadline on every challenge and denies when it expires.
"""

import asyncio
import contextvars
import logging
import os
import threading
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from typing import Any, Protocol

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from doberman.models import (
    ActionType,
    Decision,
    EffectSet,
    ReasonCode,
    Risk,
    SecurityObject,
    Verdict,
)

logger = logging.getLogger("doberman.auth.challenge")

#: Hard wall-clock ceiling on ONE challenge, whichever channel it runs on.
#:
#: Ten minutes: an unanswered approval must not sit approvable for longer than
#: that, whichever channels it fell through. Sized above the worst-case
#: *legitimate* pass: the dashboard window (90s, falls through when unanswered)
#: plus ONE human channel — the first open one answers or expires, and its
#: expiry is final (elicitation 180s or GUI 120s; the terminal shares this
#: deadline) — so 270s per pass, run **twice** (540s), because a
#: ``two_factor``/``role_elevation`` tier dispatches the whole chain once for
#: ``confirm()`` and again for ``read_code()``
#: (:meth:`~doberman.auth.provider.LocalAuthProvider._run_tier`) under this one
#: budget. Sizing it for a single pass would let a human who approved the
#: confirm late in the budget be cut off mid-TOTP-entry — manufacturing a denial
#: of an action someone was actively approving, on the highest-risk tiers.
#: It therefore bites only when nobody answers anywhere, where denying is the
#: correct outcome regardless. ``test_the_default_deadline_exceeds_the_worst_case_channel_chain``
#: pins the arithmetic and ``test_an_unanswered_challenge_expires_within_ten_minutes``
#: pins the ceiling, so a channel budget cannot grow past it unnoticed.
DEFAULT_CHALLENGE_TIMEOUT_S = 600.0

#: :attr:`AuthResult.method` (and the decision log's ``auth_result``) when the
#: deadline expired. Deliberately distinct from ``"denied"`` (a human said no)
#: and ``"error"`` (a channel failed): an audit must be able to tell silence
#: apart from refusal, because they call for different operator responses.
TIMEOUT_METHOD = "timeout"

#: Dev/test escape hatch (ADR 0074): when this env var is truthy every AUTH
#: challenge denies immediately, before any approval channel (dashboard, GUI
#: dialog, TTY) opens. Deny-only by construction — there is no approve path —
#: so setting it can only make Doberman stricter; it cannot bypass auth. Meant
#: for unattended dev/test/CI runs; deliberately absent from user-facing docs.
AUTODENY_ENV = "DOBERMAN_AUTODENY_AUTH"

#: :attr:`AuthResult.method` when :data:`AUTODENY_ENV` resolved the challenge.
#: Distinct from ``"denied"``/``"timeout"``/``"error"`` so the audit log never
#: mistakes a dev-switch denial for a human decision or a channel failure.
AUTODENY_METHOD = "autodeny"

MEMORY_METHOD = "soft_confirm+memory"

#: Methods that resolve a challenge with **no human answering anything** (#505).
#: Kept here, beside the constants it names, so the decision log's
#: ``human_confirmed`` column and this module can never drift apart: adding a
#: new machine-resolved method without listing it here would silently start
#: recording it as a human approval, which is the exact misreading the column
#: exists to prevent.
#:
#: ``"denied"`` is deliberately NOT here — a denial is a human answering "no",
#: and ``human_answered`` reports *participation*, not the verdict.
NON_HUMAN_METHODS = frozenset({TIMEOUT_METHOD, AUTODENY_METHOD, MEMORY_METHOD, "error"})


def human_answered(method: str | None) -> bool:
    """Whether ``method`` means a person actually answered a challenge channel.

    This is *participation*, not approval. The decision log's ``human_confirmed``
    column asks the narrower question its name implies — did a person approve —
    so a caller derives it as ``approved and human_answered(method)``; the
    outcome itself stays in ``auth_result``, which already separates a human
    "denied" from "timeout"/"autodeny"/"error".

    Conservative by construction: an unknown or missing method reports False.
    A new machine-resolved path therefore reads as "no human" until it is
    deliberately classified, rather than inflating the human-confirmation
    signal an auditor relies on.
    """
    return bool(method) and method not in NON_HUMAN_METHODS


# A memory hit must never soften destructive, critical, exfiltration, opaque,
# role-boundary, protected-path, history-rewriting, or correlated-destruction work.
APPROVAL_MEMORY_EXCLUSIONS = {
    # File deletion is intrinsically destructive and remains single-use.
    "action_types": frozenset({ActionType.file_delete}),
    # Critical risk is never eligible for a reduced proof.
    "risks": frozenset({Risk.critical}),
    "reason_codes": frozenset(
        {
            ReasonCode.role_out_of_scope,  # Requires its narrow elevation flow.
            ReasonCode.encoded_exfiltration,  # Encoded egress may conceal secret transfer.
            ReasonCode.opaque_command,  # Unparseable effects cannot be safely repeated.
            ReasonCode.protected_path_blocked,  # Protected filesystem targets stay hard-gated.
            ReasonCode.destructive_command,  # Destructive/history-rewriting commands stay full-tier.
            ReasonCode.bulk_operation,  # High-blast filesystem operations stay full-tier.
            ReasonCode.irreversible_high_blast,  # Irreversible broad impact stays full-tier.
            ReasonCode.correlated_destructive_flow,  # Cross-call destructive patterns stay full-tier.
        }
    ),
}


def _autodeny_enabled() -> bool:
    return os.environ.get(AUTODENY_ENV, "").strip().lower() in {"1", "true", "yes"}


def _memory_excluded(decision: Decision, action: SecurityObject) -> bool:
    return (
        action.action_type in APPROVAL_MEMORY_EXCLUSIONS["action_types"]
        or decision.final_risk in APPROVAL_MEMORY_EXCLUSIONS["risks"]
        or bool(set(decision.reason_codes) & APPROVAL_MEMORY_EXCLUSIONS["reason_codes"])
    )


#: Upper bound on one approval-memory storage round-trip from the sync seam.
#: Approval memory is a convenience; a lookup that does not answer in time
#: fails to the stricter full-tier prompt. The bound is a loop *timer*, so it
#: also wakes an event loop whose thread-safe wake-up was lost (seen on the
#: Windows Proactor loop under xdist: the aiosqlite thread had exited and the
#: loop sat in `_poll` forever, a 20-minute CI stall).
_MEMORY_IO_TIMEOUT_S = 5.0


def _run_memory_io(call: Callable[[], Any]) -> Any:
    """Run one async storage call from this synchronous seam, or fail to no-memory."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        try:
            return asyncio.run(asyncio.wait_for(call(), timeout=_MEMORY_IO_TIMEOUT_S))
        except Exception:  # noqa: BLE001 - storage failure/timeout means full-tier prompting
            logger.warning("approval-memory storage unavailable; using full auth tier")
            return None
    logger.warning("approval-memory sync bridge called on an event loop; using full auth tier")
    return None


async def _live_memory_hit(
    repo_root: str, fingerprint_value: str, session_id: str | None, now: datetime
) -> Any:
    from doberman.storage.approval_memory import lookup
    from doberman.storage.taint import entity_scope, read_taint

    scopes = [session_id] if session_id else []
    scopes.append(entity_scope(repo_root))
    for scope in scopes:
        if scope and await read_taint(repo_root, scope):
            return None
    return await lookup(fingerprint_value, repo_root=repo_root, session_id=session_id, now=now)


async def _remember_approval(
    repo_root: str,
    action: SecurityObject,
    session_id: str | None,
    required_tier: "AuthTier",
    result: "AuthResult",
    ttl_seconds: int,
) -> None:
    from doberman.storage.approval_memory import remember

    await remember(
        action.action_fingerprint,
        repo_root=repo_root,
        session_id=session_id,
        required_tier=required_tier.value,
        action_type=action.action_type.value,
        method=result.method,
        approved_at=result.at,
        expires_at=result.at + timedelta(seconds=ttl_seconds),
    )


class AuthTier(StrEnum):
    """The proof an ``AUTH`` requires, weakest → strongest."""

    soft_confirm = "soft_confirm"
    local_auth = "local_auth"
    two_factor = "two_factor"
    role_elevation = "role_elevation"


#: Strength order so "strongest tier wins" is a simple max.
_TIER_ORDER: dict[AuthTier, int] = {
    AuthTier.soft_confirm: 0,
    AuthTier.local_auth: 1,
    AuthTier.two_factor: 2,
    AuthTier.role_elevation: 3,
}

#: Base tier implied by the final risk alone (before reason-specific bumps).
_RISK_TIER: dict[Risk, AuthTier] = {
    Risk.low: AuthTier.soft_confirm,
    Risk.medium: AuthTier.local_auth,
    Risk.high: AuthTier.two_factor,
    Risk.critical: AuthTier.two_factor,
}

#: Minimum tier each reason code warrants. A reason absent here imposes no floor
#: of its own (the risk-derived base still applies). ``role_out_of_scope`` is the
#: one reason that routes to the elevation flow — it is satisfiable by a grant.
_REASON_TIER: dict[ReasonCode, AuthTier] = {
    ReasonCode.role_out_of_scope: AuthTier.role_elevation,
    ReasonCode.policy_source_sensitive: AuthTier.two_factor,
    ReasonCode.sensitive_secret_access: AuthTier.two_factor,
    ReasonCode.opaque_command: AuthTier.two_factor,
    ReasonCode.encoded_exfiltration: AuthTier.two_factor,
    ReasonCode.unknown_external_destination: AuthTier.local_auth,
    ReasonCode.sensitive_path_access: AuthTier.local_auth,
    ReasonCode.bulk_operation: AuthTier.local_auth,
}


def _stronger(a: AuthTier, b: AuthTier) -> AuthTier:
    return a if _TIER_ORDER[a] >= _TIER_ORDER[b] else b


def select_tier(decision: Decision) -> AuthTier:
    """Pick the authentication tier an ``AUTH`` decision requires.

    Strongest-wins across the risk-derived base tier and every reason code's
    minimum, so the result is never weaker than any single signal warrants.

    Raises ``ValueError`` if ``decision`` is not an ``AUTH`` — a ``PASS`` needs
    no challenge and a hard ``BLOCK`` must never be turned into one (the proof
    flow can only *grant*; it can never lift a block).
    """
    if decision.final_verdict is not Verdict.AUTH:
        raise ValueError(f"select_tier requires an AUTH decision, got {decision.final_verdict}")
    tier = _RISK_TIER.get(decision.final_risk, AuthTier.two_factor)
    for reason in decision.reason_codes:
        floor = _REASON_TIER.get(reason)
        if floor is not None:
            tier = _stronger(tier, floor)
    return tier


class Prompter(Protocol):
    """Collects human input for a challenge (injected so tests stay headless).

    Implementations must raise on timeout / no-input so the provider can treat
    it as a denial (fail closed). The default CLI implementation lives in
    :mod:`doberman.auth.provider`.
    """

    def confirm(self, message: str) -> bool: ...

    def read_code(self, message: str) -> str: ...


class AuthResult(BaseModel):
    """The outcome of one challenge (immutable, audit-friendly).

    ``action_id`` ties the approval to exactly one action (no replay onto a
    different call). ``elevation_id`` is set only when a ``role_elevation`` tier
    produced a grant.
    """

    model_config = ConfigDict(frozen=True)

    approved: bool
    tier: AuthTier
    method: str
    at: AwareDatetime
    action_id: str = Field(min_length=1)
    elevation_id: str | None = None


#: The (decision, action, tier) of the challenge currently running on this
#: thread/task, if any — see :func:`current_challenge`.
_current_challenge: contextvars.ContextVar[tuple[Decision, SecurityObject, AuthTier] | None] = (
    contextvars.ContextVar("_current_challenge", default=None)
)


def current_challenge() -> tuple[Decision, SecurityObject, AuthTier] | None:
    """The real ``(decision, action, tier)`` of the challenge in progress here.

    Lets a :class:`Prompter` (e.g. the dashboard's ``DashboardPrompter``) derive
    redaction-safe display fields (risk, reason codes, explanation, path class)
    straight from the typed objects instead of parsing
    :func:`~doberman.auth.provider._challenge_message`'s free-text string, which
    embeds the raw target and is unsafe to persist. ``None`` outside a challenge.

    Set only for the duration of :func:`run_auth_challenge` on the calling
    thread/task; ``asyncio.to_thread`` propagates the current
    ``contextvars.Context`` into its worker thread, so a prompter running there
    (as the proxy's auth challenge does) still sees it.
    """
    return _current_challenge.get()


#: The shared "Blast radius" label every prompter puts in front of
#: format_effect_set()'s string (ADR 0094) — hoisted to one constant so the
#: four hand-written call sites (provider.py's two tones, gui_prompter,
#: dashboard_prompter) cannot drift on the wording (C2 final review, prefix
#: hoist). The technical tone lower-cases it to match its other lower-case
#: field labels; the word choice itself stays identical everywhere.
EFFECT_SET_LABEL = "Blast radius"


def _effect_set_flags_suffix(effects: EffectSet) -> str:
    """ ", includes .git" / ", reaches outside the repo" / both — ASCII only.

    I2 (C2 final review): ``hits_git``/``hits_outside_repo`` were computed and
    carried on ``EffectSet`` but never rendered by this, the ONE formatter
    every prompter uses. Classes, not paths — no location is named.
    """
    flags = []
    if effects.hits_git:
        flags.append("includes .git")
    if effects.hits_outside_repo:
        flags.append("reaches outside the repo")
    return f", {', '.join(flags)}" if flags else ""


def format_effect_set(effects: EffectSet | None) -> str | None:
    """The ONE redaction-safe display string for a delete-class AUTH's
    blast-radius preview (ADR 0094) — every prompter (dashboard, GUI,
    terminal, elicitation, the pending-approval row) must render this exact
    string so the channels cannot drift. ``None`` when there is nothing to
    show — a non-delete-class AUTH, or ``effects`` itself is ``None``.

    Built from counts and booleans only; never a path (there is no path
    field on ``EffectSet`` to leak). The ``hits_git``/``hits_outside_repo``
    flags (I2) are appended, ASCII only, in every shade — known count, cap
    hit, and hard unknown alike.
    """
    if effects is None:
        return None
    flags = _effect_set_flags_suffix(effects)
    if effects.capped:
        if effects.file_count is None:
            return "unknown - count unavailable" + flags
        if effects.dir_count:
            # C2 cleanup (#558): the cap-hit shade now carries the real
            # files/dirs split (see effects.py::_cap_hit) instead of dumping
            # everything under file_count — show the total lower bound (what
            # used to be the whole "N+ files" number) with the split as
            # context, so a mostly-directory delete never renders as an
            # understated "1+ files".
            total = effects.file_count + effects.dir_count
            file_word = "file" if effects.file_count == 1 else "files"
            dir_word = "directory" if effects.dir_count == 1 else "directories"
            return (
                f"{total:,}+ ({effects.file_count:,} {file_word}, "
                f"{effects.dir_count:,} {dir_word})" + flags
            )
        return f"{effects.file_count:,}+ files" + flags
    file_word = "file" if effects.file_count == 1 else "files"
    files = f"{effects.file_count:,} {file_word}"
    if effects.dir_count:
        dir_word = "directory" if effects.dir_count == 1 else "directories"
        return f"{files} in {effects.dir_count:,} {dir_word}" + flags
    return files + flags


def _run_with_deadline(
    call: Callable[[], AuthResult],
    *,
    timeout_s: float,
    on_timeout: Callable[[], AuthResult],
    label: str,
) -> AuthResult:
    """Run ``call`` on a daemon worker; give up and deny after ``timeout_s``.

    The deadline lives here rather than inside each prompter for two reasons.
    First, more than one built-in channel can block without end (``GuiPrompter``'s
    ``mainloop``, ``TtyPrompter``'s ``readline`` on a terminal nobody is at), and a
    guarantee re-implemented per channel is one new channel away from being false.
    Second, both the prompter and the provider are **plugin seams** — anything
    registered through ``doberman.auth_providers`` runs here too, and core cannot
    audit code it never imports. A single deadline at the seam covers all of it.

    Python cannot kill a thread blocked in native code, so the worker is a
    **daemon**: on expiry we abandon it. Its answer is discarded — an approval
    that arrives after the deadline is never honoured — and it can never hold up
    interpreter exit.

    A ``BaseException`` from the worker is re-raised verbatim on the caller's
    thread. :func:`run_auth_challenge` (the sole caller) converts a *non-cooperative*
    one — ``SystemExit`` or any other non-``Exception`` ``BaseException`` a plugin
    provider might raise — into a fail-closed denial there, so it can never escape
    past a caller's ``except Exception``. ``asyncio.CancelledError`` alone still
    propagates (cancellation is cooperative). See ADR 0064.

    One known limit remains, pre-existing and deliberately not widened here: an
    abandoned worker keeps running its channel to completion, so a late answer can
    still touch state the challenge itself no longer reads (notably the TOTP lockout
    counter). It cannot approve the action — the result is discarded here — but it is
    not a clean kill.
    """
    box: dict[str, Any] = {}
    # Copy the caller's context so `_current_challenge` (set just above) reaches
    # the worker: DashboardPrompter reads it and falls back when it is missing.
    ctx = contextvars.copy_context()

    def _worker() -> None:
        try:
            box["result"] = ctx.run(call)
        except BaseException as exc:  # noqa: BLE001 — re-raised on the caller's thread
            box["error"] = exc

    worker = threading.Thread(target=_worker, name=f"doberman-auth-{label}", daemon=True)
    worker.start()
    worker.join(timeout_s)
    if worker.is_alive():
        logger.warning(
            "auth challenge unanswered after %.0fs (action %s); denying (fail closed)",
            timeout_s,
            label,
        )
        return on_timeout()
    if "error" in box:
        raise box["error"]
    return box["result"]


def run_auth_challenge(
    decision: Decision,
    action: SecurityObject,
    *,
    prompter: Prompter | None = None,
    at: AwareDatetime | None = None,
    timeout_s: float = DEFAULT_CHALLENGE_TIMEOUT_S,
    message_tone: str = "human",
    repo_root: str | None = None,
    session_id: str | None = None,
) -> AuthResult:
    """Select the tier and run the challenge through the active provider.

    ``action`` carries the role/target/tool the challenge names to the human
    (the ``Decision`` alone does not). The provider can only *grant or deny* —
    it never alters the decision's verdict or the required tier. With nothing
    installed, the local provider runs (CLI confirm + TOTP). Lazy-imports the
    provider to avoid an import cycle (challenge defines the types it consumes).

    ``message_tone`` (S1) is purely cosmetic — "human" (plain wording, the
    default) or "technical" (the original detailed format) — and is passed
    through as data; this module never reads config/repo state itself, so a
    caller with repo access resolves the tone and hands it in here.

    Returns within ``timeout_s`` no matter what the channel does: an unanswered
    challenge yields a non-approved result with ``method`` set to
    :data:`TIMEOUT_METHOD`. See :func:`_run_with_deadline`.
    """
    from doberman.auth.provider import active_provider

    required_tier = select_tier(decision)
    if _autodeny_enabled():
        # ADR 0074: dev-only fail-closed shortcut — deny before any channel
        # opens. Cannot approve, so it is never an auth bypass.
        logger.info("auth challenge auto-denied by %s (action %s)", AUTODENY_ENV, action.id)
        return AuthResult(
            approved=False,
            tier=required_tier,
            method=AUTODENY_METHOD,
            at=at or datetime.now(timezone.utc),
            action_id=action.id,
        )
    ttl_seconds = 0
    if repo_root is not None:
        from doberman.config import load_approval_memory_seconds

        ttl_seconds = load_approval_memory_seconds(repo_root)

    memory_hit = None
    eligible = required_tier in (AuthTier.local_auth, AuthTier.two_factor)
    if (
        ttl_seconds > 0
        and eligible
        and action.action_fingerprint is not None
        and not _memory_excluded(decision, action)
    ):
        when = at or datetime.now(timezone.utc)
        memory_hit = _run_memory_io(
            lambda: _live_memory_hit(repo_root, action.action_fingerprint, session_id, when)
        )
        # A later TTL reduction is an immediate strengthening: an entry created
        # under a longer old policy cannot outlive the newly configured age.
        if (
            memory_hit is not None
            and memory_hit.approved_at + timedelta(seconds=ttl_seconds) <= when
        ):
            memory_hit = None

    tier = AuthTier.soft_confirm if memory_hit is not None else required_tier
    challenge_action = action
    if memory_hit is not None:
        minutes = max(
            0,
            int(
                ((at or datetime.now(timezone.utc)) - memory_hit.approved_at).total_seconds() // 60
            ),
        )
        challenge_action = action.model_copy(
            update={
                "metadata": {
                    **action.metadata,
                    "approval_memory_notice": (
                        f"You approved this exact action {minutes} min ago - confirm again."
                    ),
                }
            }
        )

    token = _current_challenge.set((decision, challenge_action, tier))
    try:
        result = _run_with_deadline(
            lambda: active_provider().authenticate(
                decision,
                challenge_action,
                tier,
                prompter=prompter,
                at=at,
                message_tone=message_tone,
            ),
            timeout_s=timeout_s,
            on_timeout=lambda: AuthResult(
                approved=False,
                tier=tier,
                method=TIMEOUT_METHOD,
                at=at or datetime.now(timezone.utc),
                action_id=action.id,
            ),
            label=action.id,
        )
        if memory_hit is not None and result.approved and result.action_id == action.id:
            return result.model_copy(
                update={"tier": AuthTier.soft_confirm, "method": MEMORY_METHOD}
            )
        if (
            memory_hit is None
            and ttl_seconds > 0
            and eligible
            and not _memory_excluded(decision, action)
            and action.action_fingerprint is not None
            and result.approved
            and result.action_id == action.id
        ):
            _run_memory_io(
                lambda: _remember_approval(
                    repo_root, action, session_id, required_tier, result, ttl_seconds
                )
            )
        return result
    except asyncio.CancelledError:
        raise  # cooperative cancellation must reach the event loop, never a denial
    except BaseException as exc:  # noqa: BLE001 — fail closed on ANY non-cooperative BaseException
        if isinstance(exc, Exception):
            raise  # a regular error keeps propagating to the caller's own `except Exception`
        # A non-``Exception`` BaseException (``SystemExit``, or a plugin provider's own
        # BaseException subclass) would slip past every caller's ``except Exception`` and
        # escape the fail-closed path entirely. Deny it here, at the one provider seam —
        # tagged ``"error"`` so the audit tells it apart from a timeout or a human "no".
        # ADR 0064; Prime Directive 1 (fail closed) is why this catch is this broad.
        # ponytail: a BaseExceptionGroup wrapping a CancelledError also denies here rather
        # than unwrapping to re-raise — the worker ran on a daemon thread whose result is
        # discarded, so there is no live coroutine to cancel cooperatively; a fail-closed
        # deny is the correct outcome, not an unwrap TODO.
        logger.warning(
            "auth challenge worker raised %s (action %s); denying (fail closed)",
            type(exc).__name__,
            action.id,
        )
        return AuthResult(
            approved=False,
            tier=required_tier,
            method="error",
            at=at or datetime.now(timezone.utc),
            action_id=action.id,
        )
    finally:
        _current_challenge.reset(token)

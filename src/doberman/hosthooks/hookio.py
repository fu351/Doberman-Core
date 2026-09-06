"""Host-generic hook-output shaping + in-process action-bound AUTH challenge.

Extracted from :mod:`doberman.hosthooks.claude_code` (W1.0b) so a second host
adapter (Codex, whose hook protocol mirrors Claude Code's — same
``hookSpecificOutput`` deny shape) can reuse this logic instead of copying it
(issues #65/#67: a host's own yes/no prompt cannot satisfy a 2FA-tier action,
so Doberman runs its own action-bound challenge over a phone→GUI→TTY fallback).

Every function takes the host's hook event name explicitly (``event: str``)
instead of reading a module constant, and :func:`resolve_auth` takes its
``Prompter`` explicitly — each adapter keeps its own module-level
``AUTH_PROMPTER`` injection seam (so tests can still inject a headless fake
there) and passes it in; ``None`` builds the default phone→GUI→TTY fallback lazily.

**Speed.** A host hook runs before or after *every* tool call, so this module
must NEVER import :mod:`doberman.proxy.executor` or the subjective baseline —
those pull ``numpy``/``scipy``/``river`` at module scope. The auth stack
(:mod:`doberman.auth.challenge`, the GUI/TTY prompters, :mod:`doberman.auth.totp`)
is imported lazily, only inside the AUTH branch that actually needs it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from doberman.branding import DOG
from doberman.models import Decision, ReasonCode, SecurityObject

if TYPE_CHECKING:  # annotations only — keeps the hot path free of the auth stack
    from doberman.auth.challenge import Prompter

_REASON = DOG + " Doberman [{verdict}]: {explanation} (reasons: {reasons}; action {action_id})"
FAILSAFE_REASON = DOG + " Doberman: failing closed — could not evaluate this action safely."
#: Default next step on a BLOCK (leemeo3's #70 wording, kept verbatim). Reused as the
#: fallback for any reason without a more specific hint below.
_BLOCK_NEXT_STEP = (
    "Next step: this BLOCK has no in-session override. If this is trusted "
    "administrative recovery work, run it outside the hooked agent session."
)
#: Reason-specific BLOCK next steps (issues #65/#67: adapt the guidance to the actual
#: block). An exfiltration block is not "recovery work to run elsewhere" — it stays
#: blocked in every channel — so it says so. Reasons not listed here use the default.
_BLOCK_NEXT_STEP_BY_REASON: dict[str, str] = {
    ReasonCode.secret_exfiltration.value: (
        "Next step: blocked to stop a credential from leaving — there is no in-session "
        "override; do not route this value to an external destination."
    ),
    ReasonCode.confirmed_exfil.value: (
        "Next step: blocked — an outbound value matches a secret seen earlier this "
        "session. There is no in-session override."
    ),
    ReasonCode.multi_step_exfil.value: (
        "Next step: blocked — a secret entered this session and this call would send it "
        "out. There is no in-session override."
    ),
}


def hook_output(event: str, permission: str, reason: str) -> dict[str, Any]:
    return {
        "hookSpecificOutput": {
            "hookEventName": event,
            "permissionDecision": permission,
            "permissionDecisionReason": reason,
        }
    }


def deny(event: str, reason: str = FAILSAFE_REASON) -> dict[str, Any]:
    return hook_output(event, "deny", reason)


def payload_allows(hook_payload: dict[str, Any]) -> bool:
    """Whether a payload built by :func:`hook_output` lets the call through.

    Fails toward "did not allow" for any shape it does not recognize, so a
    malformed or foreign payload can never be read as an approval.
    """
    specific = hook_payload.get("hookSpecificOutput") if hook_payload else None
    if not isinstance(specific, dict):
        return False
    return specific.get("permissionDecision") == "allow"


def challenge_human_confirmed(hook_payload: dict[str, Any], method: str | None) -> bool:
    """Whether a host-hook challenge was approved *by a person* (#505).

    Both halves are required, and each rules out a different way the decision
    log used to read as a human approval when it was not one: the payload must
    actually allow (a denial is not a confirmation), and the resolving method
    must be one a human answers (which excludes ``timeout``, ``autodeny``,
    approval memory, and a channel ``error``).

    This is the host-hook path's answer to #399, where an ``AUTH`` recorded
    ``auth=executed`` with nobody having seen a dialog. Such a row now records
    ``human_confirmed = 0`` and is greppable.
    """
    from doberman.auth.challenge import human_answered

    return payload_allows(hook_payload) and human_answered(method)


def format_reason(decision: Decision, verdict_label: str) -> str:
    """The redaction-safe reason line (verdict + explanation + reason codes + action
    id). Built only from already-safe decision fields — never a raw argument value."""
    return _REASON.format(
        verdict=verdict_label,
        explanation=(decision.explanation or "").strip() or "no further detail",
        reasons=", ".join(str(rc) for rc in decision.reason_codes) or "unspecified",
        action_id=decision.action_id,
    )


def decision_payload(decision: Decision, *, event: str) -> dict[str, Any]:
    """Build the PreToolUse-style hook output for a BLOCK (deny) verdict.

    AUTH is handled by :func:`resolve_auth` (it runs Doberman's own challenge);
    only a hard BLOCK reaches here, and it always denies.
    """
    reason = format_reason(decision, decision.final_verdict.name)
    return hook_output(event, "deny", f"{reason} {_block_next_step(decision.reason_codes)}")


def _block_next_step(reason_codes: list[ReasonCode]) -> str:
    """The BLOCK next-step for the first reason code with a specific override, else default."""
    for reason in reason_codes:
        specific = _BLOCK_NEXT_STEP_BY_REASON.get(str(reason))
        if specific is not None:
            return specific
    return _BLOCK_NEXT_STEP


def resolve_auth(
    decision: Decision,
    action: SecurityObject,
    *,
    event: str,
    prompter: "Prompter | None",
    message_tone: str = "human",
    repo_root: str | None = None,
    session_id: str | None = None,
) -> dict[str, Any]:
    """Compatibility wrapper returning only the host payload."""
    return resolve_auth_result(
        decision,
        action,
        event=event,
        prompter=prompter,
        message_tone=message_tone,
        repo_root=repo_root,
        session_id=session_id,
    )[0]


def resolve_auth_result(
    decision: Decision,
    action: SecurityObject,
    *,
    event: str,
    prompter: "Prompter | None",
    message_tone: str = "human",
    repo_root: str | None = None,
    session_id: str | None = None,
) -> tuple[dict[str, Any], str]:
    """Run Doberman's tiered challenge for an AUTH and answer the host hook.

    The proxy path (``proxy.executor._handle_auth``) already does this for MCP tools;
    a host hook has no equivalent, so an AUTH here used to defer to the harness's own
    yes/no prompt — which cannot satisfy a 2FA-tier action and left the user with no
    real approve path (issues #65/#67). We now present the action-bound challenge over
    a GUI→TTY fallback (the dialog is a channel the human can actually see even when the
    agent's TUI owns the terminal).

    ``message_tone`` (S1) is cosmetic wording only; the caller resolves it from
    the repo's saved policy (this module stays config-free — see the file's own
    hot-path note) and passes it in as data, same as ``prompter``.

    Approved *and* bound to THIS action id → ``allow`` the one call. A denial, an
    unavailable channel, or any error → ``deny`` (fail closed). The auth stack is
    imported lazily so the common PASS/BLOCK hot path never pays for it.
    """
    # ponytail: no TOCTOU re-decide like the proxy — the hook grants no elevations and
    # holds no state between calls, so there is nothing to re-check; each call is
    # challenged independently.
    try:
        # Imported + built here (not at module scope) so the PASS/BLOCK hot path stays
        # light, and inside the try so a construction failure (e.g. no tkinter) also
        # fails closed with the actionable channel-error message.
        from doberman.auth.challenge import TIMEOUT_METHOD, run_auth_challenge

        active_prompter = prompter if prompter is not None else _default_auth_prompter()
        result = run_auth_challenge(
            decision,
            action,
            prompter=active_prompter,
            message_tone=message_tone,
            repo_root=repo_root,
            session_id=session_id,
        )
    except Exception:  # noqa: BLE001 — any challenge/prompter error is a denial (fail closed)
        return hook_output(
            event, "deny", _auth_denied_reason(decision, channel_error=True)
        ), "error"

    # Approval is bound to THIS action id — never honor a result meant for another call.
    if result.approved and result.action_id == action.id:
        reason = format_reason(decision, "AUTH")
        return (
            hook_output(
                event,
                "allow",
                f"{reason} Approved via Doberman's action-bound authentication ({result.method}).",
            ),
            result.method,
        )
    method = result.method if not result.approved else "denied"
    return (
        hook_output(
            event,
            "deny",
            _auth_denied_reason(
                decision,
                channel_error=result.method == "error",
                timed_out=result.method == TIMEOUT_METHOD,
            ),
        ),
        method,
    )


def _default_auth_prompter() -> "Prompter":
    """The host-hook challenge channel: the phone first, then a topmost GUI dialog,
    then the controlling terminal (no MCP elicitation — a hook has no agent session).
    Built lazily so the common PASS/BLOCK hot path never imports the auth stack.
    """
    from doberman.auth.gui_prompter import FallbackPrompter, GuiPrompter
    from doberman.auth.ntfy import NtfyPrompter
    from doberman.auth.tty_prompter import TtyPrompter

    # ponytail: the phone waits its own `wait_s` before the local dialog opens — a
    # fixed step, not a fan-out race. Upgrade path: first-answer-wins concurrent
    # notify, if a sequential wait proves too slow in practice.
    return FallbackPrompter([NtfyPrompter(), GuiPrompter(), TtyPrompter()])


def _auth_denied_reason(decision: Decision, *, channel_error: bool, timed_out: bool = False) -> str:
    """A denied-AUTH message that names how to actually complete the approval
    (issues #65/#67). Redaction-safe; adds the exact 2FA-enrollment command when an
    un-enrolled 2FA tier is why the action can't be authenticated. A timeout gets its
    own next-step wording so the log/message distinguishes silence from a refusal
    (AN-4a, ADR 0046)."""
    reason = format_reason(decision, "AUTH")
    if channel_error:
        tail = (
            "Next step: Doberman's approval dialog could not be shown (no GUI or "
            "terminal channel). Approve from an interactive session, or run the action "
            "yourself outside the hooked agent session."
        )
    elif timed_out:
        tail = (
            "Next step: the approval request expired with no response (auto-denied "
            "after the deadline) — retry the action to reopen Doberman's approval dialog."
        )
        if _needs_unenrolled_2fa(decision):
            tail += (
                " This action needs 2FA, which isn't set up yet — run "
                "`doberman 2fa setup`, then retry."
            )
    else:
        tail = (
            "Next step: authentication was not completed — retry the action to reopen "
            "Doberman's approval dialog."
        )
        if _needs_unenrolled_2fa(decision):
            tail += (
                " This action needs 2FA, which isn't set up yet — run "
                "`doberman 2fa setup`, then retry."
            )
    return f"{reason} {tail}"


def _needs_unenrolled_2fa(decision: Decision) -> bool:
    """True when the challenge tier requires a TOTP code but none is enrolled — the
    usual reason a high-risk AUTH dead-ends. Best-effort; never raises into the hook."""
    try:
        from doberman.auth import totp
        from doberman.auth.challenge import AuthTier, select_tier

        tier = select_tier(decision)
        return tier in (AuthTier.two_factor, AuthTier.role_elevation) and not totp.is_enrolled()
    except Exception:  # noqa: BLE001 — a messaging aid must never affect the decision
        return False

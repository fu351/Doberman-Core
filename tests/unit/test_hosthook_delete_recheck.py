"""#649 — the delete recheck before execution, on the host-hook path.

Before a risky delete runs, Doberman counts what it would touch, shows that to
the human, and recounts right before execution — denying if the count moved.
That guard (ADR 0094's TOCTOU compare, reason code ``effect_set_diverged``)
existed only in ``proxy/executor.py``, so none of the four supported hosts had
it, even though a host hook is how most agents actually reach a tool.

``hookio.resolve_auth_result`` is the one place every host hook turns an
approval into an execution, so the guard lives there and every adapter that
routes through it inherits it.

What each group proves:

* **The preview exists at all** — a delete-class AUTH now reaches the prompter
  carrying an effect set. Without this there is nothing to recheck against, and
  the host-hook challenge was previously rendering none.
* **Divergence denies** — files appearing or disappearing between approval and
  execution, in either direction, and a known count degrading to unknown.
* **Agreement still allows** — the guard must not deny an unchanged delete, or
  it would make every approved delete unusable.
* **Nothing else pays for it** — a non-delete AUTH performs no filesystem work,
  and the guard never fires where it has no baseline.
* **Redaction and fail-closed** — the deny names the category and no path, and
  a recheck that cannot be computed denies rather than allowing.
"""

import json
from datetime import datetime, timezone

import pytest

from doberman.hosthooks import hookio
from doberman.models import (
    ActionType,
    Decision,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    Verdict,
)

_EVENT = "PreToolUse"


class _Approve:
    """A person who is present and approves."""

    def confirm(self, message):
        return True

    def read_code(self, message):
        return "000000"


def _action(command: str) -> SecurityObject:
    return SecurityObject(
        id="act-649",
        ts=datetime(2026, 6, 7, tzinfo=timezone.utc),
        agent_role="unknown",
        action_type=ActionType.shell_exec,
        tool_name="shell_exec",
        target=command,
    )


def _decision() -> Decision:
    result = GuardrailResult(
        verdict=Verdict.AUTH,
        risk=Risk.medium,
        reason_codes=[ReasonCode.bulk_operation],
        explanation="Bulk delete; authentication required.",
    )
    return Decision(
        action_id="act-649",
        final_verdict=Verdict.AUTH,
        final_risk=Risk.medium,
        objective=result,
        subjective=None,
        reason_codes=[ReasonCode.bulk_operation],
        explanation=result.explanation,
        decided_at=datetime(2026, 6, 7, tzinfo=timezone.utc),
    )


def _resolve(command, repo_root, prompter=None):
    return hookio.resolve_auth_result(
        _decision(),
        _action(command),
        event=_EVENT,
        prompter=prompter or _Approve(),
        repo_root=str(repo_root),
    )


def _permission(payload):
    return (payload.get("hookSpecificOutput") or {}).get("permissionDecision")


def _reason(payload):
    return (payload.get("hookSpecificOutput") or {}).get("permissionDecisionReason")


@pytest.fixture
def target(tmp_path):
    """A directory with three files, the thing the delete would remove."""
    victim = tmp_path / "scratch"
    victim.mkdir()
    for i in range(3):
        (victim / f"f{i}.txt").write_text("x\n", encoding="utf-8")
    return tmp_path


# --- the preview has to exist before anything can be rechecked --------------


def test_a_delete_class_auth_now_carries_a_preview_to_the_prompter(target):
    """The host-hook challenge previously rendered no blast radius at all, so
    the human approved a delete with no idea of its size — and there was no
    baseline a recheck could compare against."""
    seen = {}

    class _Recording:
        def confirm(self, message):
            return True

        def read_code(self, message):
            return "000000"

    def _capture(decision, action, **kwargs):
        seen["effects"] = decision.effects
        from doberman.auth.challenge import AuthResult, AuthTier

        return AuthResult(
            approved=True,
            tier=AuthTier.soft_confirm,
            method="local_auth",
            at=datetime(2026, 6, 7, tzinfo=timezone.utc),
            action_id=action.id,
        )

    import doberman.auth.challenge as challenge_module

    original = challenge_module.run_auth_challenge
    challenge_module.run_auth_challenge = _capture
    try:
        _resolve("rm -rf scratch", target, prompter=_Recording())
    finally:
        challenge_module.run_auth_challenge = original

    assert seen["effects"] is not None, "the challenge saw no blast-radius preview"
    assert seen["effects"].file_count == 3


def test_a_non_delete_auth_gets_no_preview_and_walks_nothing(target, monkeypatch):
    """The early-out matters: a hook runs before every tool call, so a
    non-delete AUTH must never touch the filesystem."""
    import doberman.engine.effects as effects_module

    def _boom(*_a, **_k):
        raise AssertionError("a non-delete AUTH must not walk the filesystem")

    monkeypatch.setattr(effects_module, "compute_delete_effects", _boom)
    out, _method = _resolve("echo hello", target)
    assert _permission(out) == "allow"


# --- divergence denies ------------------------------------------------------


def test_files_appearing_after_approval_denies(target):
    """The classic sneak: approve a small delete, grow it before it runs."""

    class _ApproveThenGrow:
        def confirm(self, message):
            for i in range(5):
                (target / "scratch" / f"extra{i}.txt").write_text("x\n", encoding="utf-8")
            return True

        def read_code(self, message):
            return "000000"

    out, method = _resolve("rm -rf scratch", target, prompter=_ApproveThenGrow())
    assert _permission(out) == "deny"
    assert method == "effect_set_diverged"


def test_files_disappearing_after_approval_also_denies(target):
    """Drift in *either* direction is drift: what the human approved is not
    what would run, and a shrunken set is still not the approved set."""

    class _ApproveThenShrink:
        def confirm(self, message):
            (target / "scratch" / "f0.txt").unlink()
            return True

        def read_code(self, message):
            return "000000"

    out, method = _resolve("rm -rf scratch", target, prompter=_ApproveThenShrink())
    assert _permission(out) == "deny"
    assert method == "effect_set_diverged"


def test_a_known_count_becoming_unknown_denies(target, monkeypatch):
    """A preview the human could read, degrading to a count nobody can
    vouch for, is not agreement — it is the loss of the thing they approved."""
    calls = {"n": 0}
    import doberman.engine.effects as effects_module

    real = effects_module.compute_delete_effects

    def _second_call_is_unknown(operands, repo_root, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            return real(operands, repo_root, **kwargs)
        return effects_module.unknown_effects()

    monkeypatch.setattr(effects_module, "compute_delete_effects", _second_call_is_unknown)
    out, method = _resolve("rm -rf scratch", target)
    assert _permission(out) == "deny"
    assert method == "effect_set_diverged"


def test_a_recheck_that_raises_denies(target, monkeypatch):
    """Fail closed: a guard that cannot verify must not report success."""
    calls = {"n": 0}
    import doberman.engine.effects as effects_module

    real = effects_module.compute_delete_effects

    def _second_call_explodes(operands, repo_root, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            return real(operands, repo_root, **kwargs)
        raise OSError("filesystem went away")

    monkeypatch.setattr(effects_module, "compute_delete_effects", _second_call_explodes)
    out, method = _resolve("rm -rf scratch", target)
    assert _permission(out) == "deny"
    assert method == "effect_set_diverged"


# --- agreement still allows -------------------------------------------------


def test_an_unchanged_delete_is_still_allowed(target):
    """The guard must not break the ordinary approved delete."""
    out, method = _resolve("rm -rf scratch", target)
    assert _permission(out) == "allow"
    assert method != "effect_set_diverged"


def test_a_dynamic_delete_does_not_deny_on_dynamism_alone(target):
    """A delete whose operands include a live substitution is `unknown` at both
    ends. Unknown == unknown is agreement, so it must not re-deny on that
    alone — only a real mismatch denies."""
    out, method = _resolve("rm -rf $(cat targets.txt)", target)
    assert _permission(out) == "allow", "dynamism alone is not divergence"
    assert method != "effect_set_diverged"


def test_no_repo_root_means_no_baseline_and_no_spurious_deny(target):
    """Without a root there is no preview, so there is nothing to compare and
    the guard must stay out of the way rather than invent a divergence."""
    out, _method = hookio.resolve_auth_result(
        _decision(),
        _action("rm -rf scratch"),
        event=_EVENT,
        prompter=_Approve(),
        repo_root=None,
    )
    assert _permission(out) == "allow"


# --- a denial is still a denial ---------------------------------------------


def test_a_declined_challenge_still_denies_without_reaching_the_recheck(target):
    """The recheck sits behind the approval branch: a human "no" denies on its
    own terms, with its own outcome, not as a divergence."""

    class _Decline:
        def confirm(self, message):
            return False

        def read_code(self, message):
            raise AssertionError("not reached")

    out, method = _resolve("rm -rf scratch", target, prompter=_Decline())
    assert _permission(out) == "deny"
    assert method != "effect_set_diverged"


# --- redaction --------------------------------------------------------------


def test_the_divergence_deny_names_the_category_and_no_path(target):
    """Same contract as every other host-visible reason: the class of problem,
    never the operand. This string goes back to the agent harness."""

    class _ApproveThenGrow:
        def confirm(self, message):
            (target / "scratch" / "customer-export-secret.csv").write_text("x\n", encoding="utf-8")
            return True

        def read_code(self, message):
            return "000000"

    out, _method = _resolve("rm -rf scratch", target, prompter=_ApproveThenGrow())
    reason = _reason(out)
    assert ReasonCode.effect_set_diverged.value in reason
    assert "customer-export-secret" not in reason
    assert "scratch" not in reason
    assert str(target) not in reason


def test_the_divergence_deny_is_valid_hook_output(target):
    """The harness has to be able to parse it like any other decision."""

    class _ApproveThenGrow:
        def confirm(self, message):
            (target / "scratch" / "extra.txt").write_text("x\n", encoding="utf-8")
            return True

        def read_code(self, message):
            return "000000"

    out, _ = _resolve("rm -rf scratch", target, prompter=_ApproveThenGrow())
    specific = out["hookSpecificOutput"]
    assert specific["hookEventName"] == _EVENT
    assert specific["permissionDecision"] == "deny"
    assert isinstance(specific["permissionDecisionReason"], str)
    json.dumps(out)  # must be serializable back to the harness

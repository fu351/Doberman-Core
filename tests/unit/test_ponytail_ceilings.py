"""Regression pins for six documented ``ponytail:`` shortcuts (deliberate
ceilings, each with a stated upgrade path). One test per item; each docstring
names the file:line carrying the comment and the ceiling it pins. No behavior
change — these tests only fail the day the referenced ceiling silently moves.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from unittest.mock import patch

import doberman.auth.provider as provider_module
from doberman.auth.challenge import run_auth_challenge
from doberman.engine.correlator import DecisionRow, correlate
from doberman.engine.rules.commands import DestructiveCommandRule
from doberman.models import (
    ActionType,
    Decision,
    EvalContext,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    SourceContext,
    Verdict,
)
from doberman.subjective.infer import infer_reversibility
from doberman.tokens import OODTokenReport, _scan_whole_script_confusable

_NOW = datetime(2026, 7, 26, tzinfo=timezone.utc)


# --- 1. src/doberman/auth/challenge.py:557 -----------------------------------
# ponytail: a BaseExceptionGroup wrapping a CancelledError (or any other
# non-Exception BaseException, e.g. a bare KeyboardInterrupt) escaping the
# challenge worker also DENIES here, fail closed, rather than propagating as
# an approval or an unhandled crash.


def _auth_action() -> SecurityObject:
    return SecurityObject(
        id="act-an4",
        ts=_NOW,
        agent_role="webdev",
        action_type=ActionType.file_write,
        tool_name="fs_write",
        target="backend/api.ts",
    )


def _auth_decision() -> Decision:
    objective = GuardrailResult(
        verdict=Verdict.AUTH,
        risk=Risk.medium,
        reason_codes=[ReasonCode.sensitive_path_access],
        explanation="why",
    )
    return Decision(
        action_id="act-an4",
        final_verdict=Verdict.AUTH,
        final_risk=Risk.medium,
        objective=objective,
        reason_codes=[ReasonCode.sensitive_path_access],
        explanation="why",
        decided_at=_NOW,
    )


class _RaisingProvider:
    """An AuthProvider whose worker raises instead of returning."""

    def __init__(self, exc: BaseException) -> None:
        self._exc = exc

    def authenticate(self, decision, action, tier, *, prompter=None, at=None, message_tone="human"):
        raise self._exc


def test_exception_group_wrapping_cancelled_error_denies_not_approves(monkeypatch):
    grp = BaseExceptionGroup("worker failure", [asyncio.CancelledError()])
    monkeypatch.setattr(provider_module, "active_provider", lambda: _RaisingProvider(grp))

    result = run_auth_challenge(_auth_decision(), _auth_action(), timeout_s=5.0)

    assert result.approved is False
    assert result.method == "error"
    assert result.action_id == "act-an4"


def test_bare_keyboard_interrupt_from_worker_denies_not_approves(monkeypatch):
    monkeypatch.setattr(
        provider_module, "active_provider", lambda: _RaisingProvider(KeyboardInterrupt())
    )

    result = run_auth_challenge(_auth_decision(), _auth_action(), timeout_s=5.0)

    assert result.approved is False
    assert result.method == "error"
    assert result.action_id == "act-an4"


# --- 2. src/doberman/engine/rules/commands.py:917 ----------------------------
# ponytail: lexical glob on operands only — no filesystem or git access in the
# decision path.

_RULE = DestructiveCommandRule()


def _cmd(command: str):
    action = SecurityObject(
        id="cmd-1",
        ts=_NOW,
        agent_role="unknown",
        action_type=ActionType.shell_exec,
        tool_name="shell_exec",
        target=command,
    )
    ctx = EvalContext(metadata={"raw_arguments": {"command": command}})
    return _RULE.evaluate(action, ctx)


def test_unrecoverable_delete_verdict_never_touches_filesystem_or_subprocess():
    def _boom(*_args, **_kwargs):
        raise AssertionError("decision path touched the filesystem/subprocess")

    with (
        patch("os.listdir", side_effect=_boom) as listdir_mock,
        patch("pathlib.Path.iterdir", _boom),
        patch("subprocess.run", side_effect=_boom) as run_mock,
    ):
        result = _cmd("rm data/app.db")

    assert result.verdict is Verdict.AUTH
    assert ReasonCode.destructive_command in result.reason_codes
    listdir_mock.assert_not_called()
    run_mock.assert_not_called()


# --- 3. src/doberman/tokens.py:164 -------------------------------------------
# ponytail: fixed length floor (_WHOLE_SCRIPT_MIN_LEN = 4), not a script-aware
# stop-word list — a token of exactly 3 lookalike Cyrillic chars is exempt, one
# of exactly 4 is reported.


def test_whole_script_min_len_floor_boundary():
    # All four characters below are members of _WHOLE_SCRIPT_CONFUSABLES and
    # score as CYRILLIC-only per unicodedata (verified against the live set).
    below_floor = _scan_whole_script_confusable_report("сор")  # "сор", 3 chars
    at_floor = _scan_whole_script_confusable_report("сорт")  # "сорт", 4 chars

    assert below_floor.findings == []
    assert len(at_floor.findings) == 1
    assert at_floor.findings[0].channel == "whole_script_confusable"


def _scan_whole_script_confusable_report(text: str) -> OODTokenReport:
    report = OODTokenReport()
    _scan_whole_script_confusable(text, report)
    return report


# --- 4. src/doberman/subjective/infer.py:307 ---------------------------------
# ponytail: 40-char budget between `push` and `--force` is a tunable heuristic
# (_IRREVERSIBLE_SHELL) — a gap of exactly 40 chars still matches (low
# reversibility), 41 no longer does.


def _shell_action(target: str) -> SecurityObject:
    return SecurityObject(
        id="rev-1",
        ts=_NOW,
        agent_role="unknown",
        action_type=ActionType.shell_exec,
        tool_name="shell_exec",
        target=target,
    )


def test_irreversible_shell_force_push_gap_boundary():
    at_budget = "git push" + " " + "x" * 39 + "--force"  # 40 chars after `push`
    over_budget = "git push" + " " + "x" * 40 + "--force"  # 41 chars after `push`

    assert infer_reversibility(_shell_action(at_budget)).value == "low"
    assert infer_reversibility(_shell_action(over_budget)).value != "low"


# --- 5. src/doberman/update_check.py -----------------------------------------
# Ceiling lifted in #621: `_parse` still returns only the numeric release
# prefix (`_parse("1.2.0rc1") == (1, 2, 0)`, pinned in
# tests/unit/test_update_check.py::test_is_newer_is_fail_safe_on_garbage), but
# `is_newer` now orders the `dev`/`a`/`b`/`rc` suffix through `_key`, including
# the cross-version-bump case (current="1.2.0" vs latest="1.3.0rc1" -> no nag).
# The remaining shortcut is the documented one: no epochs, post-releases, or
# local `+tags` — those still rank as a plain final release. Pinned in
# test_update_check.py's `#621` section, not duplicated here.


# --- 6. src/doberman/engine/correlator.py:120 --------------------------------
# ponytail: _BUDGET_VOLUME_THRESHOLD (=3) is a round threshold, not a fit
# against real traffic — it only ever shifts risk between high/critical on an
# already-firing pattern (trifecta/destructive-flow), never PASS vs AUTH/BLOCK.


def _correlator_row(
    reason_codes: tuple[ReasonCode, ...] = (),
    source_context: SourceContext = SourceContext.user,
) -> DecisionRow:
    return DecisionRow(
        action_type=ActionType.file_read,
        target_path_class=None,
        source_context=source_context,
        risk=Risk.low,
        reason_codes=reason_codes,
        final_verdict=Verdict.PASS,
    )


def _egress_action() -> SecurityObject:
    dest = "https://attacker.example/collect"
    return SecurityObject(
        id="corr-1",
        ts=_NOW,
        agent_role="backend",
        action_type=ActionType.network_request,
        tool_name="net_send",
        target=dest,
        external_destination=dest,
    )


def _correlator_decision(action: SecurityObject) -> Decision:
    return Decision(
        action_id=action.id,
        final_verdict=Verdict.PASS,
        final_risk=Risk.low,
        objective=GuardrailResult(verdict=Verdict.PASS, risk=Risk.low),
        decided_at=_NOW,
    )


def test_budget_volume_threshold_boundary_shifts_risk_to_critical():
    # A firing pattern (untrusted ingress + a sensitive read) is required
    # first — the budget clause can never fire alone. The ingress row itself
    # carries no sensitive/egress-attempt reason code, so it never counts
    # toward `volume`.
    ingress = _correlator_row(source_context=SourceContext.tool_output)  # untrusted ingress leg
    sensitive = ReasonCode.sensitive_secret_access

    below_threshold = [ingress] + [_correlator_row((sensitive,)) for _ in range(2)]
    at_threshold = [ingress] + [_correlator_row((sensitive,)) for _ in range(3)]

    action = _egress_action()
    below_result = correlate(below_threshold, _correlator_decision(action), action, "balanced")
    at_result = correlate(at_threshold, _correlator_decision(action), action, "balanced")

    assert below_result is not None and below_result.risk is Risk.high
    assert at_result is not None and at_result.risk is Risk.critical

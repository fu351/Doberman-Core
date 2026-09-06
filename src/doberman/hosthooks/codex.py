"""Codex CLI host-hook adapter (W1.1) — Codex's front door onto the shared spine.

Built and tested against **live-captured** Codex 0.146.1 payloads (see
``tests/fixtures/codex/README.md``), not assumptions. What the captures showed:

* Codex's hook payload is snake_case and, for shell, key-compatible with Claude
  Code: ``tool_name": "Bash"`` with a plain-string ``tool_input.command``, plus
  ``session_id`` / ``cwd``. The deny **output** is the same camelCase
  ``hookSpecificOutput`` shape.
* But Codex's catalog is **not** Claude Code's: file edits arrive as
  ``tool_name": "apply_patch"`` whose ``tool_input.command`` is an apply-patch
  **envelope** (the target path lives inside it, e.g. ``*** Add File: note.txt``),
  and reads happen through ``Bash`` (``cat`` / ``rtk read``), not a separate tool.

Because the catalog is only partly documented, this adapter follows the
**gate-by-default** posture of :mod:`doberman.hosthooks.openclaw`, not the
allowlist-abstain of :mod:`doberman.hosthooks.claude_code`: **every** tool call
is normalized and run through :func:`~doberman.hosthooks.spine.evaluate_action`;
a benign / no-target call simply ``PASS``es (→ abstain). Nothing is skipped
without being looked at, so a write under an unforeseen tool name cannot slip
past unmediated. ``apply_patch`` gets its envelope parsed so
:class:`~doberman.engine.rules.paths.ProtectedPathRule` gates the real target(s).

Verdict mapping: ``PASS`` -> abstain (raise-only); ``BLOCK`` -> ``deny``; ``AUTH``
-> Doberman's **own** action-bound GUI->TTY challenge (Codex CLI is interactive,
so — unlike OpenClaw — we do not defer to the host's yes/no flow, which cannot
satisfy a 2FA-tier action; issues #65/#67).

**Fail closed.** A malformed payload, a gated action whose target we cannot see
(a Bash with no command, an apply_patch with no extractable path), or any engine
error denies the call. Same speed contract as the other adapters: only the light
decision path is imported at module scope (the numeric / proxy-executor stack is
never pulled here; the auth stack is imported lazily inside hookio).
"""

from __future__ import annotations

import json
import re
import sys
from typing import TYPE_CHECKING, Any

from doberman.config import load_message_tone
from doberman.hosthooks import claude_code, hookio, spine
from doberman.models import AuthPath, Verdict

if TYPE_CHECKING:  # annotations only — keeps the hot path free of the auth stack
    from doberman.auth.challenge import Prompter

_EVENT = "PreToolUse"

#: Supported Codex CLI version range (inclusive min, exclusive max). ``doberman
#: doctor`` reports an installed Codex outside this range as a
#: WARN, never a critical failure — a newer Codex is not "Doberman may not be
#: protecting you". Verified against 0.146.1; widen the max as the CI canary
#: stays green on newer releases.
SUPPORTED_CODEX_RANGE: tuple[str, str] = ("0.146.0", "1.0.0")

#: Tool names that carry no path/command/network surface and are safe to abstain
#: on *before* execution. Deliberately tiny (gate-by-default): reads on Codex go
#: through ``Bash`` (gated as a command), so there is no benign read tool to list
#: here. Left empty until a genuinely inert Codex tool is confirmed by capture —
#: an empty set means "gate everything", which is the safe default.
_ABSTAIN_TOOLS: frozenset[str] = frozenset()

#: apply_patch envelope path directives (captured): ``*** Add File: <p>`` /
#: ``*** Update File: <p>`` / ``*** Delete File: <p>`` and ``*** Move to: <p>``.
#: Leading whitespace is tolerated so an indented directive can't drop a path out
#: of extraction (a partial extraction on a multi-file patch could otherwise miss a
#: protected target); a trailing ``\r`` from CRLF is stripped by the caller.
_APPLY_PATCH_FILE_RE = re.compile(r"^\s*\*\*\* (?:Add|Update|Delete) File: (.+)$", re.MULTILINE)
_APPLY_PATCH_MOVE_RE = re.compile(r"^\s*\*\*\* Move to: (.+)$", re.MULTILINE)

#: Prompter for the PreToolUse AUTH challenge (test-injection seam, mirrors
#: :data:`doberman.hosthooks.claude_code.AUTH_PROMPTER`). ``None`` -> hookio builds
#: the default GUI->TTY fallback lazily.
AUTH_PROMPTER: Prompter | None = None


def _apply_patch_paths(patch: object) -> list[str]:
    """Extract every target path from an apply_patch envelope. Never raises."""
    if not isinstance(patch, str) or not patch:
        return []
    found = _APPLY_PATCH_FILE_RE.findall(patch) + _APPLY_PATCH_MOVE_RE.findall(patch)
    return [p.strip() for p in found if p.strip()]


def to_normalize_input(
    tool_name: str, tool_input: dict[str, Any] | None
) -> tuple[str, dict[str, Any]]:
    """Translate a Codex tool call into ``normalize()``'s ``(name, args)``. Never raises.

    ``Bash`` -> ``bash`` (command string). ``apply_patch`` -> ``file_write`` with
    the envelope's target path(s) surfaced under ``path`` so the protected-path
    rule gates the real write. Any other name (Claude-Code-style built-ins Codex
    may also emit, or ``mcp__*``) defers to the Claude Code / generic mapping.
    """
    args = dict(tool_input or {})
    if tool_name == "Bash":
        return "bash", args
    if tool_name == "apply_patch":
        paths = _apply_patch_paths(args.get("command"))
        if paths:
            # A list under "path" makes ProtectedPathRule evaluate EVERY touched
            # file and take the worst verdict (a multi-file patch touching one
            # protected path is blocked).
            args["path"] = paths if len(paths) > 1 else paths[0]
            args["raw_paths"] = paths
        return "file_write", args
    return claude_code.to_normalize_input(tool_name, tool_input)


def _required_target_present(
    tool_name: str, tool_input: dict[str, Any], args: dict[str, Any]
) -> bool:
    """Whether a gated tool exposes the field that identifies its action. Fail
    closed (deny) when it doesn't — we cannot gate what we cannot see."""
    if tool_name == "Bash":
        cmd = tool_input.get("command")
        return isinstance(cmd, str) and bool(cmd.strip())
    if tool_name == "apply_patch":
        return bool(args.get("raw_paths"))
    # Claude-Code-style built-ins Codex may emit: reuse their required-field map.
    required = claude_code.REQUIRED_FIELD.get(tool_name)
    if required is None:
        return True  # unknown / mcp tool: no required-field gate (evaluated generically)
    value = tool_input.get(required)
    return isinstance(value, str) and bool(value.strip())


def evaluate_pre(payload: dict[str, Any]) -> dict[str, Any] | None:
    """Decide one Codex ``PreToolUse`` call.

    Gate-by-default: every tool (except the confirmed-inert :data:`_ABSTAIN_TOOLS`)
    is evaluated. Returns the hook-output dict for an AUTH/BLOCK (or a fail-closed
    deny), or ``None`` to abstain (a genuine PASS, or a confirmed-inert tool).
    NEVER raises — any failure becomes a deny.
    """
    try:
        if spine.is_excluded(payload.get("cwd")):
            return None  # device-wide excluded project — full abstain, no I/O

        tool_name = payload.get("tool_name")
        if not isinstance(tool_name, str) or not tool_name:
            return hookio.deny(_EVENT)  # no identifiable action -> refuse
        if tool_name in _ABSTAIN_TOOLS:
            return None  # confirmed-inert tool

        raw_input = payload.get("tool_input")
        tool_input = raw_input if isinstance(raw_input, dict) else {}

        canonical, args = to_normalize_input(tool_name, tool_input)

        # Fail closed: a gated tool whose target field is missing/empty is an
        # action we cannot see — refuse rather than let it through.
        if not _required_target_present(tool_name, tool_input, args):
            return hookio.deny(_EVENT)

        result = spine.evaluate_action(
            canonical, args, cwd=payload.get("cwd"), raw_session_id=payload.get("session_id")
        )
        if result.acted is Verdict.PASS:
            return None  # raise-only; monitor-softened history recorded by the spine
        if result.acted is Verdict.AUTH:
            hook_result, auth_method = hookio.resolve_auth_result(
                result.decision,
                result.challenge_action,
                event=_EVENT,
                prompter=AUTH_PROMPTER,
                message_tone=load_message_tone(result.repo_root),
                repo_root=result.repo_root,
                session_id=result.session_id,
            )
            auth_path = AuthPath.host_hook_challenge
            human_confirmed = hookio.challenge_human_confirmed(hook_result, auth_method)
        else:
            hook_result = hookio.decision_payload(result.decision, event=_EVENT)
            auth_method = "blocked"
            # An objective BLOCK: no challenge ran, so nobody approved anything.
            auth_path = AuthPath.host_hook_objective
            human_confirmed = False
        spine.record_history(
            result.decision,
            result.action,
            result.repo_root,
            result.session_id,
            auth_result=auth_method,
            auth_path=auth_path,
            human_confirmed=human_confirmed,
        )
        return hook_result
    except Exception:  # noqa: BLE001 — fail closed; never surface the payload in an error
        return hookio.deny(_EVENT)


def _auth_result(hook_result: dict[str, Any]) -> str:
    """``"executed"`` if the hook payload allows the call (an approved AUTH), else
    ``"blocked"`` (a denied AUTH, or the BLOCK deny payload itself)."""
    permission = (hook_result.get("hookSpecificOutput") or {}).get("permissionDecision")
    return "executed" if permission == "allow" else "blocked"


def run_codex_pre(stdin_text: str) -> str | None:
    """Parse the hook stdin, evaluate, and return the JSON string to print to
    stdout — or ``None`` to abstain (print nothing).

    A payload that does not parse to a JSON object is denied: an unidentifiable
    call fails closed rather than slipping through.

    **Single-flight (W1.2):** when both install channels are wired, Codex fires
    this hook twice for one tool call. The first invocation records its answer
    under a keyed marker; the second replays it byte-for-byte instead of
    re-evaluating (avoiding a doubled AUTH prompt / history row / taint bump). A
    missing/expired/unavailable marker just means a full evaluation — never a
    skipped one.
    """
    try:
        payload = json.loads(stdin_text)
    except Exception:  # noqa: BLE001 — unparseable input denies the unknown call
        return json.dumps(hookio.deny(_EVENT))
    if not isinstance(payload, dict):
        return json.dumps(hookio.deny(_EVENT))

    from doberman.hosthooks import singleflight

    key = singleflight.event_key(payload)
    prior = singleflight.replay(key)
    if prior is not None:
        return prior or None  # "" -> abstain (print nothing); else replay the JSON

    out = evaluate_pre(payload)
    text = json.dumps(out) if out is not None else None
    singleflight.record(key, text)

    try:  # #239: warn on stderr when Doberman's own registration diverged.
        from doberman.hosthooks.integrity import hook_warning

        cwd = payload.get("cwd")
        if not spine.is_excluded(cwd):
            warning = hook_warning(spine.resolve_root_and_mode(cwd)[0])
            if warning:
                print(warning, file=sys.stderr)
    except Exception:  # noqa: BLE001,S110 — warning-only
        pass

    return text

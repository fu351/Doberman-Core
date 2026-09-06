"""Cursor host-hook adapter — Cursor's front door onto the shared spine (#202).

Decision memo: ``docs/CONNECTOR_MEMO_CURSOR.md`` (#244). Cursor (the IDE and the
``cursor-agent`` CLI) runs command hooks from ``hooks.json``: one JSON document
on stdin, one on stdout (https://cursor.com/docs/hooks). Doberman registers ONE
command, ``doberman hook cursor``, for the gating events and dispatches on the
payload's ``hook_event_name``:

* ``preToolUse`` — every built-in tool (``Shell`` / ``Write`` / ``Read`` /
  ``Delete`` / ``Grep`` / ``Task``) and MCP tools (``MCP:<tool>``). The
  universal chokepoint.
* ``beforeShellExecution`` — the shell command with its ``cwd``.
* ``beforeMCPExecution`` — an MCP tool call (``tool_name``, a JSON-string
  ``tool_input``, ``mcp_server_name``).
* ``beforeReadFile`` — a file read handed over WITH its ``content``: the read is
  gated as a ``file_read`` and, if allowed, the content is scanned exactly like
  Claude Code's ``PostToolUse`` output scan — a credential in the file never
  reaches the model, and the session is tainted + fingerprinted so a later
  egress of that value is a confirmed exfil.
* ``sessionStart`` — acknowledged with ``{}`` and a best-effort liveness
  heartbeat written to ``.doberman/`` (see :func:`record_session_start`), so
  ``doberman doctor`` can tell whether Cursor is actually calling the hook.

Verdict mapping: ``PASS`` -> ``{"permission": "allow"}`` and exit 0. ``BLOCK`` ->
``{"permission": "deny", "user_message": ..., "agent_message": ...}`` AND exit
code 2 — Cursor treats either as a deny, so a lost or mangled document still
blocks. ``AUTH`` -> Doberman's **own** action-bound GUI->TTY challenge inside the
hook, then allow or deny. Never ``ask``: Cursor's approval system ignores a
hook's ``allow``/``ask`` (staff-confirmed), so the human-in-the-loop step has to
be Doberman's.

**Fail closed.** A malformed or non-object payload (a leading UTF-8 BOM, which
``cursor-agent`` on Windows prefixes, is stripped first), a missing or unknown
event, a gated tool whose target we cannot see, an unparseable MCP
``tool_input``, or any engine error denies the call. Cursor's own default is
fail-OPEN on a hook crash or timeout; ``"failClosed": true`` on the
registration closes that, and this module denies before it could ever print a
malformed document.

**Single-flight.** A shell command reaches Doberman twice when both
``preToolUse`` and ``beforeShellExecution`` are registered (same for MCP via
``beforeMCPExecution``, and for a file read via ``preToolUse``/``Read`` +
``beforeReadFile``) — or up to THREE times if the Claude-compat path is also
wired (:func:`respond`'s ``channel`` argument, driven by
``doberman.hosthooks.claude_code``, when Cursor's third-party-hooks setting
fires ``doberman hook pre`` on the same call): compat ``preToolUse``, native
``preToolUse``, native ``before*``. The first call records its answer under a
keyed marker derived from ``(conversation_id, generation_id, translated
action)``; every OTHER call on a different channel replays it — but only the
closing ``before*`` event (never a ``preToolUse`` replay, compat or native)
CONSUMES the marker, so the answer survives until the last of up to three
calls, not just the second. The same channel never replays — a repeated
identical action inside one generation is evaluated (and challenged) again, so
an approval stays single-use. A replayed read still runs the content scan:
only the path decision is shared. Marker security model:
:mod:`doberman.hosthooks.singleflight`.

Speed contract as every adapter: only the light decision path is imported at
module scope (never ``proxy.executor`` / numpy / scipy / river).
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from doberman.config import load_message_tone
from doberman.hosthooks import claude_code, hookio, singleflight, spine
from doberman.models import AuthPath, Verdict

if TYPE_CHECKING:  # annotations only — keeps the hot path free of the auth stack
    from doberman.auth.challenge import Prompter

#: File under `.doberman/` the sessionStart heartbeat writes into (install_cursor
#: imports THIS name to build the doctor-facing path; defined here, not there, so
#: this module never has to import install_cursor).
SESSION_MARKER = "cursor_session"

EVENT_PRE_TOOL = "preToolUse"
EVENT_SHELL = "beforeShellExecution"
EVENT_MCP = "beforeMCPExecution"
EVENT_READ = "beforeReadFile"
EVENT_SESSION_START = "sessionStart"
#: The events this adapter gates. Anything else (missing, unknown, or an
#: observe-only event someone registered us for by mistake) is denied.
GATED_EVENTS: frozenset[str] = frozenset({EVENT_PRE_TOOL, EVENT_SHELL, EVENT_MCP, EVENT_READ})

#: Cursor treats exit code 2 as a deny regardless of stdout.
ALLOW_EXIT_CODE = 0
DENY_EXIT_CODE = 2

#: Label used in the shared reason line (Cursor has no hookEventName echo).
_EVENT_LABEL = "cursor"

#: Cursor's built-in tool -> canonical name for ``normalize()``. ``Shell``'s
#: ``command`` / ``cwd`` fields are staff-confirmed (the docs' own example spells
#: the cwd ``working_directory``); ``Write`` carries ``file_path`` + ``content``
#: (staff-confirmed). ``Read`` / ``Delete`` / ``Grep`` are assumed to share the
#: ``file_path`` spelling, with ``path`` / ``target_file`` accepted as fallbacks.
#: An unrecognised spelling on a path-gated tool fails closed — never waved through.
_BUILTIN: dict[str, str] = {
    "Shell": "bash",
    "Write": "file_write",
    "Read": "file_read",
    "Delete": "file_delete",
    "Grep": "file_read",
}
#: Built-ins that cannot be gated without their target path.
_PATH_REQUIRED: frozenset[str] = frozenset({"Write", "Read", "Delete"})
_PATH_KEYS: tuple[str, ...] = ("file_path", "path", "target_file")
#: ``preToolUse`` names MCP tools ``MCP:<tool>``; the bare name goes to normalize
#: so a filesystem server's ``write_file`` / ``read_file`` maps to the right
#: ``ActionType`` and anything else gets the generic egress/target extraction —
#: the same translation the MCP proxy applies to a wrapped server's tool names.
_MCP_PREFIX = "MCP:"

#: Prompter for the AUTH challenge (test-injection seam, mirrors the other
#: adapters). ``None`` -> hookio builds the default GUI->TTY fallback lazily.
AUTH_PROMPTER: Prompter | None = None


def strip_bom(text: str | bytes) -> str:
    """Decode hook stdin as UTF-8 and drop a leading BOM. ``cursor-agent`` on
    Windows prefixes hook stdin with one, which otherwise turns every hook into a
    JSON parse failure that Cursor fails OPEN on (forum #168407, staff-confirmed,
    no fix ETA). Bytes are decoded here, not by the console: under Windows'
    default cp1252 stdin the BOM arrives as three mojibake characters and a
    non-ASCII path or command is mangled, so the CLI hands over raw bytes."""
    if isinstance(text, bytes):
        return text.decode("utf-8-sig", errors="replace")
    return text.lstrip("\ufeff")


def allow() -> dict[str, Any]:
    return {"permission": "allow"}


def deny(reason: str = hookio.FAILSAFE_REASON) -> dict[str, Any]:
    """Cursor's deny document. ``user_message`` is shown to the human,
    ``agent_message`` to the model — both carry the same redaction-safe reason
    line (verdict, explanation, reason codes, action id, next step)."""
    return {"permission": "deny", "user_message": reason, "agent_message": reason}


def exit_code_for(response: dict[str, Any]) -> int:
    return DENY_EXIT_CODE if response.get("permission") == "deny" else ALLOW_EXIT_CODE


def _first_path(mapping: dict[str, Any]) -> str | None:
    for key in _PATH_KEYS:
        value = mapping.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return None


def _shell_args(mapping: dict[str, Any]) -> dict[str, Any] | None:
    command = mapping.get("command")
    if not isinstance(command, str) or not command.strip():
        return None
    return {"command": command}


def _mcp_args(raw: object) -> dict[str, Any] | None:
    """``tool_input`` for an MCP tool: a dict, or Cursor's JSON-string form.
    ``None`` when the arguments cannot be seen (unparseable / wrong shape). An
    absent ``tool_input`` is a zero-argument tool (``list_allowed_directories``),
    evaluated on its name exactly as the MCP proxy evaluates it — not an
    invisible target."""
    if raw is None:
        return {}
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except Exception:  # noqa: BLE001 — arguments we cannot read -> fail closed
            return None
    return dict(raw) if isinstance(raw, dict) else None


def translate(event: str, payload: dict[str, Any]) -> tuple[str, dict[str, Any]] | None:
    """Translate one gated Cursor event into ``normalize()``'s ``(name, args)``.

    ``None`` means "the target of a gated action is not visible" and the caller
    denies. Gate-by-default: a built-in we have no mapping for (``Task``, a
    future tool) is evaluated generically, never abstained.
    """
    if event == EVENT_SHELL:
        args = _shell_args(payload)
        return ("bash", args) if args else None
    if event == EVENT_READ:
        path = _first_path(payload)
        return ("file_read", {"path": path}) if path else None
    if event == EVENT_MCP:
        name = payload.get("tool_name")
        if not isinstance(name, str) or not name:
            return None
        args = _mcp_args(payload.get("tool_input"))
        return (name, args) if args is not None else None
    # preToolUse
    name = payload.get("tool_name")
    if not isinstance(name, str) or not name:
        return None
    raw = payload.get("tool_input")
    if name.startswith(_MCP_PREFIX):
        bare = name[len(_MCP_PREFIX) :]
        args = _mcp_args(raw)
        return (bare, args) if bare and args is not None else None
    tool_input = raw if isinstance(raw, dict) else {}
    canonical = _BUILTIN.get(name)
    if canonical == "bash":
        args = _shell_args(tool_input)
        return (canonical, args) if args else None
    path = _first_path(tool_input)
    if name in _PATH_REQUIRED and not path:
        return None
    if canonical is not None and path:
        args = {k: v for k, v in tool_input.items() if k not in _PATH_KEYS}
        args["path"] = path
        return canonical, args
    return name, dict(tool_input)  # Grep without a path, Task, anything new: generic


def repo_root_of(payload: dict[str, Any]) -> str | None:
    """``workspace_roots[0]`` (the project Cursor opened), else the payload ``cwd``."""
    roots = payload.get("workspace_roots")
    if isinstance(roots, list):
        for root in roots:
            if isinstance(root, str) and root.strip():
                return root
    cwd = payload.get("cwd")
    return cwd if isinstance(cwd, str) and cwd else None


def record_session_start(project_root: str) -> None:
    """Best-effort liveness record for `doberman doctor`: write the UTC ISO time into
    <root>/.doberman/cursor_session (dir created 0o700). Any OSError is swallowed - a
    heartbeat may never fail a session start."""
    from datetime import datetime, timezone
    from pathlib import Path

    from doberman.storage.db import CONFIG_DIR

    try:
        marker = Path(project_root) / CONFIG_DIR / SESSION_MARKER
        marker.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        marker.write_text(datetime.now(timezone.utc).isoformat(), encoding="utf-8")
    except OSError:
        pass


def _from_host_output(host_out: dict[str, Any]) -> dict[str, Any]:
    """Map the shared ``hookSpecificOutput`` shape onto Cursor's document."""
    hso = host_out.get("hookSpecificOutput") or {}
    if hso.get("permissionDecision") == "allow":
        return allow()
    return deny(hso.get("permissionDecisionReason") or hookio.FAILSAFE_REASON)


def _scan_read_content(
    payload: dict[str, Any], path: str, repo_root: str, session_id: str | None
) -> dict[str, Any]:
    """The Cursor equivalent of Claude Code's PostToolUse output scan.

    ``beforeReadFile`` hands Doberman the file content BEFORE the model sees it,
    so the same scan runs here: a credential in the content denies the read
    (``output-secret-scan``), and the taint ledger + read-vs-send fingerprints are
    recorded so a later egress of that value is a confirmed exfil. A missing
    ``content`` field means there is nothing to scan; the read itself already
    passed the path gate.
    """
    content = payload.get("content")
    if content is None:
        return allow()
    verdict = claude_code.evaluate_post(
        {
            "tool_name": "Read",
            "tool_input": {"file_path": path},
            "tool_response": content,
            "cwd": repo_root,
            "session_id": session_id,
        }
    )
    if verdict is None:
        return allow()
    return deny(verdict.get("reason") or hookio.FAILSAFE_REASON)


def evaluate(payload: dict[str, Any]) -> dict[str, Any]:
    """Decide one Cursor hook payload. Always returns Cursor's response document
    (``allow``, ``deny``, or ``{}`` for a session start). NEVER raises — any
    failure is a deny."""
    try:
        event = payload.get("hook_event_name")
        if event == EVENT_SESSION_START:
            cwd = repo_root_of(payload)
            if cwd and not spine.is_excluded(cwd):
                record_session_start(cwd)
            return {}
        if event not in GATED_EVENTS:
            return deny()  # no identifiable action -> refuse

        cwd = repo_root_of(payload)
        if spine.is_excluded(cwd):
            return allow()  # device-wide excluded project — true no-op

        translated = translate(event, payload)
        if translated is None:
            return deny()  # a gated action whose target we cannot see
        canonical, args = translated

        result = spine.evaluate_action(
            canonical, args, cwd=cwd, raw_session_id=payload.get("conversation_id")
        )
        if result.acted is Verdict.PASS:
            response = allow()  # monitor-softened history recorded by the spine
        else:
            if result.acted is Verdict.AUTH:
                host_out, auth_method = hookio.resolve_auth_result(
                    result.decision,
                    result.challenge_action,
                    event=_EVENT_LABEL,
                    prompter=AUTH_PROMPTER,
                    message_tone=load_message_tone(result.repo_root),
                    repo_root=result.repo_root,
                    session_id=result.session_id,
                )
                auth_path = AuthPath.host_hook_challenge
                human_confirmed = hookio.challenge_human_confirmed(host_out, auth_method)
            else:
                host_out = hookio.decision_payload(result.decision, event=_EVENT_LABEL)
                auth_method = "blocked"
                # An objective BLOCK: no challenge ran, so nobody approved.
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
            response = _from_host_output(host_out)

        if event == EVENT_READ and response.get("permission") == "allow":
            response = _scan_read_content(
                payload, args["path"], result.repo_root, result.session_id
            )
        return response
    except Exception:  # noqa: BLE001 — fail closed; never surface the payload in an error
        return deny()


#: ``preToolUse`` tools that have a second, ``before*`` channel to pair with.
_PAIRED_BUILTINS: frozenset[str] = frozenset({"Shell", "Read"})


def dedupe_key(event: object, payload: dict[str, Any]) -> str | None:
    """A keyed marker for the events Cursor can fire twice for one action — a
    shell command (``preToolUse`` + ``beforeShellExecution``), an MCP call
    (``preToolUse`` + ``beforeMCPExecution``) or a file read (``preToolUse`` +
    ``beforeReadFile``). ``None`` (no dedupe) for every other event, an
    untranslatable payload, or an unavailable HMAC key."""
    if event == EVENT_PRE_TOOL:
        name = payload.get("tool_name")
        if not (
            isinstance(name, str) and (name in _PAIRED_BUILTINS or name.startswith(_MCP_PREFIX))
        ):
            return None
    elif event not in (EVENT_SHELL, EVENT_MCP, EVENT_READ):
        return None
    conv = payload.get("conversation_id")
    gen = payload.get("generation_id")
    if not (isinstance(conv, str) and conv and isinstance(gen, str) and gen):
        return None
    translated = translate(str(event), payload)
    if translated is None:
        return None
    canonical, args = translated
    # A read is paired on its path alone: ``preToolUse``/``Read`` may carry extra
    # fields (offset, limit) that ``beforeReadFile`` does not.
    keyed = {"path": args.get("path")} if canonical == "file_read" else args
    try:
        from doberman.storage.fingerprint import fingerprint  # keyed HMAC, lazy

        body = json.dumps(keyed, sort_keys=True, default=str)
        return fingerprint(f"cursor-event:{conv}:{gen}:{canonical}:{body}")[:32]
    except Exception:  # noqa: BLE001 — no key material -> no dedupe (safe)
        return None


def _replay_for(event: object, prior: str | None) -> dict[str, Any] | None:
    """The other channel's recorded response, or ``None`` to evaluate normally.
    A marker written by THIS channel is ignored so an identical repeated action
    is re-evaluated (approvals stay single-use)."""
    if not prior:
        return None
    try:
        stored = json.loads(prior)
        if stored.get("channel") == event:
            return None
        response = stored.get("response")
        return response if isinstance(response, dict) else None
    except Exception:  # noqa: BLE001 — an unreadable marker just means a full evaluation
        return None


def _scan_after_replay(payload: dict[str, Any]) -> dict[str, Any]:
    """``beforeReadFile`` whose path decision was replayed from ``preToolUse``:
    the content scan is never skipped. Raw ``cwd`` / ``conversation_id`` go to the
    scan the way Claude Code's PostToolUse hook passes its own; any failure
    denies."""
    try:
        path = _first_path(payload)
        cwd = repo_root_of(payload)
        if path is None or cwd is None:
            return deny()
        return _scan_read_content(payload, path, cwd, payload.get("conversation_id"))
    except Exception:  # noqa: BLE001 — fail closed
        return deny()


def _tool_use_dedupe_key(event: object, payload: dict[str, Any]) -> str | None:
    """Fallback dedupe for an unpaired ``preToolUse`` tool (``dedupe_key`` returns
    ``None`` for one, e.g. a file write): keyed on ``tool_use_id`` alone, so a
    duplicated ``preToolUse`` of ANY tool seen by two hook channels (Cursor's own
    ``doberman hook cursor`` and the Claude-compat path in ``hook pre``) collapses
    to one evaluation. ``None`` when the event isn't ``preToolUse``, the payload
    carries no non-empty string ``tool_use_id``, or the HMAC key is unavailable."""
    if event != EVENT_PRE_TOOL:
        return None
    tool_use_id = payload.get("tool_use_id")
    if not (isinstance(tool_use_id, str) and tool_use_id):
        return None
    try:
        from doberman.storage.fingerprint import fingerprint  # keyed HMAC, lazy

        return fingerprint(f"cursor-tool-use:{tool_use_id}")[:32]
    except Exception:  # noqa: BLE001 — no key material -> no dedupe (safe)
        return None


#: Events that are the CLOSING half of a native preToolUse/before* pair — the
#: only replays allowed to consume a shared-flight marker. With BOTH the
#: native ``doberman hook cursor`` install AND the Claude-compat path wired
#: (global Claude Code hooks + Cursor's third-party-hooks setting), a paired
#: action reaches :func:`respond` up to THREE times: compat ``preToolUse``,
#: native ``preToolUse``, native ``before*``. Consuming on the first replay
#: (whichever of the two ``preToolUse`` calls loses the race) would leave no
#: marker for the third call, which would then re-evaluate from scratch and
#: re-run an already-approved AUTH challenge a second time. Only the closing
#: ``before*`` event consumes; a replay by either ``preToolUse`` leaves the
#: marker in place for the ``before*`` call still to come.
_CLOSING_EVENTS: frozenset[str] = frozenset({EVENT_SHELL, EVENT_MCP, EVENT_READ})


def respond(payload: dict[str, Any], *, channel: str | None = None) -> dict[str, Any]:
    """Evaluate one already-parsed Cursor payload, replaying the OTHER channel's
    recorded answer when this action was already decided.

    ``channel`` names the caller for the single-flight "same channel never
    replays" check (see :func:`_replay_for`); ``None`` (the native
    ``doberman hook cursor`` path) uses the payload's own ``hook_event_name``, so
    two different native events pairing the same action (``preToolUse`` +
    ``beforeShellExecution``) keep behaving exactly as before. The Claude-compat
    path (``doberman.hosthooks.claude_code.run_pre_hook``) passes
    ``channel="claudeCompat"`` so it and the native ``preToolUse`` channel share
    one flight regardless of which runs first. A replay only CONSUMES the
    marker when *this* call's own ``hook_event_name`` is a closing ``before*``
    event (see :data:`_CLOSING_EVENTS`) — a ``preToolUse`` replay (native or
    compat) leaves the marker for the ``before*`` call still to come. An
    unpaired ``preToolUse``-only tool (no ``before*`` event ever fires for it)
    never consumes either way; its marker just expires by TTL, which is safe —
    a fresh call gets a fresh ``tool_use_id`` and can never collide with it.
    """
    event = payload.get("hook_event_name")
    key = dedupe_key(event, payload) or _tool_use_dedupe_key(event, payload)
    effective_channel = channel or event
    replayed = _replay_for(effective_channel, singleflight.replay(key))
    if replayed is not None:
        if event in _CLOSING_EVENTS:
            singleflight.consume(key)  # the closing native event: one replay per recorded answer
        if event == EVENT_READ and replayed.get("permission") == "allow":
            replayed = _scan_after_replay(payload)  # the path passed; content still scanned
        return replayed

    response = evaluate(payload)
    singleflight.record(key, json.dumps({"channel": effective_channel, "response": response}))
    return response


def run_cursor(stdin_text: str | bytes) -> tuple[str, int]:
    """Parse the hook stdin (raw UTF-8 bytes preferred; BOM-tolerant), evaluate,
    and return ``(json_document, exit_code)`` for the CLI to emit."""
    try:
        payload = json.loads(strip_bom(stdin_text))
    except Exception:  # noqa: BLE001 — unparseable input denies the unknown call
        response = deny()
        return json.dumps(response), exit_code_for(response)
    if not isinstance(payload, dict):
        response = deny()
        return json.dumps(response), exit_code_for(response)

    response = respond(payload)
    return json.dumps(response), exit_code_for(response)

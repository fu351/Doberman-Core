"""Claude Code host-hook adapter — make Doberman enforce on an agent's tool
calls without the agent opting in.

Claude Code can run a command as a ``PreToolUse`` hook *before* every tool call.
Wired in by ``doberman install-hooks``, the harness invokes ``doberman hook pre``
and hands this adapter the tool call on stdin. We translate it into a
:class:`~doberman.models.SecurityObject`, run the **deterministic objective
floor**, and answer in Claude Code's hook protocol:

* ``PASS``  -> abstain (no output). Doberman is **raise-only**: it never removes
  the harness's own permission prompts, it only *adds* friction.
* ``AUTH``  -> run Doberman's own action-bound challenge (a topmost GUI dialog, else
  the controlling terminal); approved -> ``"allow"`` this one call, otherwise
  ``"deny"`` (fail closed). See :func:`_resolve_auth`.
* ``BLOCK`` -> ``permissionDecision: "deny"`` with a redaction-safe reason.

**Fail closed.** A malformed payload, an engine error, or any unhandled case
denies the call — if we cannot identify an action, we refuse it. The reason text
is built only from ``Decision.explanation`` + ``reason_codes`` (already
redaction-safe); no raw argument value is ever echoed back to the agent.

**PostToolUse hook (HK.2).** After a tool completes, Claude Code delivers the
tool response on stdin. ``doberman hook post`` scans the output for secret
material and records the decision in the local decision history.  If the output
contains credential-like content it returns ``{"decision":"block","reason":"…"}``
(exit 0) so Claude never uses that tainted result.  Non-security-relevant tools
(internal tools such as TodoWrite) return no output (abstain).  The history write
is best-effort and is wrapped in a broad except so it can **never** block or
raise.

**Speed.** A ``PreToolUse``/``PostToolUse`` hook runs before or after *every*
tool call, so this module imports only the light decision path (``normalize`` +
the objective guardrail + ``decide``). It must NEVER import
:mod:`doberman.proxy.executor` or the subjective baseline — those pull
``numpy``/``scipy``/``river`` at module scope (~2s), which would be paid on every
single tool call. The fast, deterministic floor here is the "objective floor"; the
adaptive per-entity layer is a separate, warm-process slice.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from doberman.branding import DOG
from doberman.config import load_active_role, load_message_tone
from doberman.engine.decision_engine import PASS_STUB, decide, max_risk
from doberman.engine.objective import ObjectiveGuardrail
from doberman.engine.taint_floor import UNTRUSTED_READ_TOOLS as _UNTRUSTED_READ_TOOLS
from doberman.hosthooks import hookio, spine
from doberman.models import AuthPath, Decision, EvalContext, Risk, SecurityObject, Verdict
from doberman.proxy.normalize import normalize

if TYPE_CHECKING:  # annotations only — keeps the hot path free of the auth stack
    from doberman.auth.challenge import Prompter

#: Claude Code built-in tools whose *action* we gate before execution. Pure reads
#: (Read / Glob / Grep) are deliberately NOT gated here — a read cannot destroy or
#: exfiltrate on its own; its *output* is the concern, scanned by the PostToolUse
#: hook. Internal tools (TodoWrite, Task, …) are not real-resource
#: actions and abstain too.
GATED_BUILTINS: frozenset[str] = frozenset(
    {"Bash", "Edit", "Write", "NotebookEdit", "WebFetch", "WebSearch"}
)

#: Map a Claude Code built-in to ``(canonical_tool_name, {src_key: dst_key})`` so
#: :func:`doberman.proxy.normalize.normalize` maps it to the right ``ActionType``
#: and finds the target in a key it recognises (``path`` / ``command`` / ``url``).
#: MCP tools (``mcp__server__tool``) are passed through verbatim — normalize's
#: generic egress/target extraction handles their arbitrary, server-defined schemas.
_BUILTIN_TOOL: dict[str, tuple[str, dict[str, str]]] = {
    "Bash": ("bash", {}),  # {command} — already a target key
    "Edit": ("file_write", {"file_path": "path"}),
    "Write": ("file_write", {"file_path": "path"}),
    "NotebookEdit": ("file_write", {"notebook_path": "path"}),
    # Read is NOT in GATED_BUILTINS (reads abstain pre). This mapping is a
    # forward-declaration for the PostToolUse output-scan slice, which WILL gate
    # reads; it is unreached until then.
    "Read": ("read_file", {"file_path": "path"}),
    "WebFetch": ("http_request", {}),  # {url, prompt} — url is a target/egress key
    # WebSearch is intentionally NOT remapped: its `query` is search *content*, not
    # a routable destination. Mapping query->url made normalize treat the query as
    # an external destination and AUTH'd every search (alert fatigue). Passed
    # through, it normalises to a no-destination action whose query is still scanned
    # for secrets.
}

#: A gated built-in must expose the field that identifies its action; if that field
#: is absent or empty we cannot see what we are being asked to gate, so we fail
#: closed (deny) rather than abstain. MCP tools have arbitrary, server-defined
#: schemas and therefore no required-field check — normalize's generic extraction
#: plus the engine handle them.
_REQUIRED_FIELD: dict[str, str] = {
    "Bash": "command",
    "Edit": "file_path",
    "Write": "file_path",
    "NotebookEdit": "notebook_path",
    "WebFetch": "url",
    "WebSearch": "query",
}

#: Public alias. Codex's hook layer is a Claude Code compatibility shim (same tool
#: names + tool_input shape — see tests/fixtures/codex/), so ``hosthooks.codex``
#: reuses this required-field map rather than duplicating it.
REQUIRED_FIELD = _REQUIRED_FIELD

_HOOK_EVENT = "PreToolUse"
_FAILSAFE_REASON = hookio.FAILSAFE_REASON
#: Back-compat re-export: the reason template moved to ``hookio`` with the rest of the
#: hook-output shaping, but ``tests/unit/test_branding.py`` imports it from here.
_REASON = hookio._REASON

#: Prompter for the PreToolUse AUTH challenge. ``None`` ⇒ build the default GUI→TTY
#: fallback lazily (keeps the hot path light; lets tests inject a headless fake, like
#: ``proxy.executor.AUTH_PROMPTER``). Never the MCP elicitation channel — a host hook
#: has no agent session to elicit over.
AUTH_PROMPTER: Prompter | None = None


def to_normalize_input(
    tool_name: str, tool_input: dict[str, Any] | None
) -> tuple[str, dict[str, Any]]:
    """Translate a Claude Code tool call into ``normalize()``'s ``(name, args)``.

    Built-ins are remapped to a canonical name + target key; everything else
    (notably ``mcp__*`` tools) is passed through so normalize's generic handling
    applies. Never raises.
    """
    args = dict(tool_input or {})
    canonical, renames = _BUILTIN_TOOL.get(tool_name, (tool_name, {}))
    for src, dst in renames.items():
        # If dst is already present (agent sent both, e.g. file_path AND path),
        # keep dst and leave src untouched rather than clobbering dst.
        if src in args and dst not in args:
            args[dst] = args.pop(src)
    return canonical, args


def _hook_output(permission: str, reason: str) -> dict[str, Any]:
    return hookio.hook_output(_HOOK_EVENT, permission, reason)


def _resolve_auth(
    decision: Decision, action: SecurityObject, repo_root: str, session_id: str | None = None
) -> tuple[dict[str, Any], str]:
    return hookio.resolve_auth_result(
        decision,
        action,
        event=_HOOK_EVENT,
        prompter=AUTH_PROMPTER,
        message_tone=load_message_tone(repo_root),
        repo_root=repo_root,
        session_id=session_id,
    )


def _decision_payload(decision: Decision) -> dict[str, Any]:
    return hookio.decision_payload(decision, event=_HOOK_EVENT)


def _deny(reason: str = _FAILSAFE_REASON) -> dict[str, Any]:
    return _hook_output("deny", reason)


def _decode_stdin(stdin: str | bytes) -> str:
    """Normalize hook stdin to text, tolerating a leading UTF-8 BOM either way.

    ``cursor-agent`` prefixes every payload with a BOM (forum #168407) — the
    same class of bug ``hosthooks.cursor.strip_bom`` fixed for ``hook cursor``
    (#569). Bytes are decoded ``utf-8-sig`` (strips the BOM, replaces anything
    undecodable rather than raising); a ``str`` already went through the
    console's own text-mode decoding, so only the BOM *character* is stripped.
    A plain local copy, not a call into ``hosthooks.cursor`` — that module
    imports this one, and importing it here would both be a circular import
    and defeat the point: the Claude hot path must not pay for the Cursor
    adapter's weight on every ordinary tool call.
    """
    if isinstance(stdin, bytes):
        return stdin.decode("utf-8-sig", errors="replace")
    return stdin.lstrip("\ufeff")


# Back-compat aliases: the flow moved to hosthooks.spine (W1.0a). The post-hook
# path and existing tests still call these names.
_resolve_root_and_mode = spine.resolve_root_and_mode
_record_history_decision = spine.record_history


def evaluate_pre(payload: dict[str, Any]) -> dict[str, Any] | None:
    """Decide one ``PreToolUse`` call.

    Returns the hook-output dict for an AUTH/BLOCK (or a fail-closed deny), or
    ``None`` to abstain (a PASS, or a tool we don't gate before execution).
    NEVER raises — any failure becomes a deny.
    """
    try:
        if spine.is_excluded(payload.get("cwd")):
            return None  # device-wide excluded project — full abstain, no I/O

        tool_name = payload.get("tool_name")
        if not isinstance(tool_name, str) or not tool_name:
            return _deny()  # no identifiable action -> refuse
        if not tool_name.startswith("mcp__") and tool_name not in GATED_BUILTINS:
            return None  # reads & internal tools: abstain pre (the post-hook owns output)

        raw_input = payload.get("tool_input")
        tool_input = raw_input if isinstance(raw_input, dict) else {}

        # Fail closed: a gated built-in whose required input field is missing/empty
        # is an action we cannot actually see — refuse it rather than abstain.
        required = _REQUIRED_FIELD.get(tool_name)
        if required is not None:
            value = tool_input.get(required)
            if not isinstance(value, str) or not value.strip():
                return _deny()

        canonical, args = to_normalize_input(tool_name, tool_input)
        result = spine.evaluate_action(
            canonical, args, cwd=payload.get("cwd"), raw_session_id=payload.get("session_id")
        )
        if result.acted is Verdict.PASS:
            return None  # raise-only; monitor history already recorded by the spine
        if result.acted is Verdict.AUTH:
            # Run Doberman's own action-bound challenge so the human can actually
            # approve in-session (issues #65/#67) — not just be told to.
            hook_result, auth_method = _resolve_auth(
                result.decision, result.challenge_action, result.repo_root, result.session_id
            )
            auth_path = AuthPath.host_hook_challenge
            # #505/#399: this is the row that used to read `AUTH ... auth=executed`
            # whether or not anyone saw a dialog. It now also records whether a
            # person actually approved, so an unconfirmed allow is greppable
            # instead of being indistinguishable from a confirmed one.
            human_confirmed = hookio.challenge_human_confirmed(hook_result, auth_method)
        else:
            hook_result = _decision_payload(result.decision)  # BLOCK -> deny
            auth_method = "blocked"
            # An objective BLOCK: no challenge ran, so nobody approved anything.
            auth_path = AuthPath.host_hook_objective
            human_confirmed = False
        _record_pre_history(
            result.decision,
            result.action,
            result.repo_root,
            result.session_id,
            hook_result,
            auth_result=auth_method,
            auth_path=auth_path,
            human_confirmed=human_confirmed,
        )
        return hook_result
    except Exception:  # noqa: BLE001 — fail closed; never surface the payload in an error
        return _deny()


def _pre_auth_result(hook_payload: dict[str, Any]) -> str:
    """``"executed"`` if *hook_payload* allows the call (an approved AUTH), else
    ``"blocked"`` (a denied AUTH, or the BLOCK payload itself — always a deny)."""
    permission = (hook_payload.get("hookSpecificOutput") or {}).get("permissionDecision")
    return "executed" if permission == "allow" else "blocked"


def _record_pre_history(
    decision: Decision,
    action: SecurityObject,
    repo_root: str,
    session_id: str | None,
    hook_result: dict[str, Any],
    *,
    auth_result: str | None = None,
    auth_path: str = AuthPath.host_hook_objective,
    human_confirmed: bool | None = None,
) -> None:
    """Best-effort: record a PreToolUse AUTH/BLOCK decision in ``doberman log``.

    Only called for the AUTH/BLOCK branches of ``evaluate_pre`` — a PASS is
    deliberately not recorded there (PreToolUse fires on every call; logging every
    pass would flood the log with a DB write on the hot path). ``hook_result`` is
    the payload actually being returned to the harness (after an AUTH challenge
    resolves), so the recorded outcome matches what really happened: ``"executed"``
    if the call was allowed, ``"blocked"`` if it was denied.

    Wrapped in its own broad except — a recording failure (including a lazy-import
    failure) must never raise into ``evaluate_pre``'s outer guard, which would
    otherwise turn an approved AUTH into a fail-closed deny for a purely
    observability-side reason.
    """
    try:
        _record_history_decision(
            decision,
            action,
            repo_root,
            session_id,
            auth_result=auth_result or _pre_auth_result(hook_result),
            auth_path=auth_path,
            human_confirmed=human_confirmed,
        )
    except Exception:  # noqa: BLE001,S110 — history must never alter the hook's return value
        pass


def _attach_integrity_warning(
    out: dict[str, Any] | None, payload: dict[str, Any]
) -> dict[str, Any] | None:
    """Add a ``systemMessage`` when Doberman's own registration diverged (#239).

    Warning-only: never changes ``hookSpecificOutput``; an excluded project is a
    true no-op; any failure returns *out* unchanged.
    """
    try:
        cwd = payload.get("cwd")
        if spine.is_excluded(cwd):
            return out
        from doberman.hosthooks.integrity import hook_warning

        warning = hook_warning(spine.resolve_root_and_mode(cwd)[0])
    except Exception:  # noqa: BLE001 — the guard must never alter a decision
        return out
    if warning is None:
        return out
    merged = dict(out or {})
    merged["systemMessage"] = warning
    return merged


def is_cursor_payload(payload: dict[str, Any]) -> bool:
    """True when a ``PreToolUse``-shaped payload was actually produced by
    Cursor's "Third Party Hooks" feature (it loads Claude Code hooks from the
    Claude settings files and invokes them with a Cursor-shaped document, not
    Claude Code's own). Cursor always sends ``cursor_version``; short of that,
    it sends a non-empty ``workspace_roots`` list with no usable top-level
    ``cwd`` (``""`` for a ``Shell`` call, absent for a ``Read``) — a shape
    Claude Code never produces (it always sends a real ``cwd``, never
    ``workspace_roots``). A pure function: tests pin it directly.
    """
    if "cursor_version" in payload:
        return True
    roots = payload.get("workspace_roots")
    cwd = payload.get("cwd")
    has_roots = isinstance(roots, list) and len(roots) > 0
    has_cwd = isinstance(cwd, str) and bool(cwd)
    return has_roots and not has_cwd


def _claude_output_for(response: dict[str, Any]) -> dict[str, Any] | None:
    """Map the Cursor adapter's response document onto Claude Code's hook-output
    shape. An ``allow`` (or a ``sessionStart`` acknowledgement, ``{}``) abstains
    — raise-only: Doberman never suppresses Cursor's own permission prompt by
    answering ``allow`` itself. A ``deny`` becomes the same ``hookSpecificOutput``
    block Claude Code's own BLOCK/AUTH-denied path returns."""
    if response.get("permission") == "deny":
        reason = response.get("user_message") or hookio.FAILSAFE_REASON
        return _hook_output("deny", reason)
    return None


def run_pre_hook(stdin: str | bytes) -> str | None:
    """Parse the hook stdin, evaluate, and return the JSON string to print to
    stdout — or ``None`` to abstain (print nothing).

    ``stdin`` may be raw bytes (the CLI now reads ``sys.stdin.buffer`` so a
    UTF-8 BOM — every ``cursor-agent`` payload carries one — decodes cleanly
    instead of breaking ``json.loads`` before :func:`is_cursor_payload` ever
    runs; see :func:`_decode_stdin`) or already-decoded text.

    A payload that does not parse to a JSON object is denied: an unidentifiable
    call fails closed rather than slipping through. A Cursor-shaped payload (see
    :func:`is_cursor_payload`) is delegated to the Cursor adapter — Cursor's
    "Third Party Hooks" setting loads Claude Code hooks and calls them with its
    own payload shape, which ``evaluate_pre`` cannot read (empty ``cwd``, a
    ``Shell`` tool name).
    """
    try:
        payload = json.loads(_decode_stdin(stdin))
    except Exception:  # noqa: BLE001 — unparseable input denies the unknown call
        return json.dumps(_deny())
    if not isinstance(payload, dict):
        return json.dumps(_deny())
    if is_cursor_payload(payload):
        from doberman.hosthooks import cursor  # lazy: the Claude hot path must not pay this import

        response = cursor.respond(payload, channel="claudeCompat")
        warn_payload = {**payload, "cwd": cursor.repo_root_of(payload) or ""}
        out = _attach_integrity_warning(_claude_output_for(response), warn_payload)
        return json.dumps(out) if out is not None else None
    out = _attach_integrity_warning(evaluate_pre(payload), payload)
    return json.dumps(out) if out is not None else None


# ---------------------------------------------------------------------------
# PostToolUse hook (HK.2)
# ---------------------------------------------------------------------------

#: Tools whose *output* we scan after execution.  Pure-read built-ins (Read,
#: Glob, Grep) are included here — their output may contain secrets even though
#: their *invocation* is safe.  The set is GATED_BUILTINS ∪ {Read, Glob, Grep};
#: all ``mcp__*`` tools are also gated (matched dynamically in evaluate_post).
_POST_GATED_BUILTINS: frozenset[str] = GATED_BUILTINS | frozenset({"Read", "Glob", "Grep"})

#: Internal / meta tools whose output we never scan.  Their responses are
#: harness-internal state (todo lists, task results) — not real-resource output.
_INTERNAL_TOOLS: frozenset[str] = frozenset(
    {"TodoWrite", "TodoRead", "Task", "ExitPlanMode", "Artifact", "NotebookRead"}
)

_POST_FAILSAFE_REASON = DOG + " Doberman: failing closed — could not vet this tool output."
_POST_REASON = (
    DOG + " Doberman [post]: output contains credential-like material "
    "({reasons}; action {action_id}).  Explanation: {explanation}"
)
#: Secret-related reason codes that RECORD a session taint + fingerprint (so the
#: multi-step floor and ``doberman log`` see the material). Includes the
#: lower-confidence ``possible_high_entropy_secret`` — a weak hit still taints.
_SECRET_REASON_CODES = frozenset(
    {"secret_exfiltration", "sensitive_secret_access", "possible_high_entropy_secret"}
)
#: The subset that HARD-BLOCKS a tool's output (a real secret must not reach the
#: model). The weak high-entropy code is deliberately NOT here — it false-positives
#: on hashes / UUIDs / base64 fragments, so it passes through (still recorded above)
#: rather than nuking a benign read. Only high-confidence grades block.
_POST_BLOCK_REASON_CODES = frozenset({"secret_exfiltration", "sensitive_secret_access"})

#: Tools that pull untrusted external content into the agent's context — the
#: "untrusted provenance" leg of the multi-step trifecta (HK.5.1 taint ledger)
#: AND the C1 echo tripwire's source classification. Single source of truth in
#: engine/taint_floor.py (imported at module top, not redefined) so the
#: host-hook and the proxy's record_output_taint never drift.


def _coerce_response_text(tool_response: Any) -> str:
    """Coerce ``tool_response`` (str, dict, list, …) to a single flat string.

    Never raises.  JSON-dumps non-string values so the secret scanner can look
    inside nested structures without recursive logic of its own.
    """
    if isinstance(tool_response, str):
        return tool_response
    try:
        return json.dumps(tool_response, ensure_ascii=False)
    except Exception:  # noqa: BLE001 — best-effort coercion
        try:
            return str(tool_response)
        except Exception:  # noqa: BLE001
            return ""


def _post_block(reason: str) -> dict[str, Any]:
    """PostToolUse block response: ``{"decision":"block","reason":"…"}``."""
    return {"decision": "block", "reason": reason}


def evaluate_post(payload: dict[str, Any]) -> dict[str, Any] | None:
    """Decide one ``PostToolUse`` call.

    Returns a block dict if the tool output contains secret material, or
    ``None`` to abstain (non-gated tool or clean output).  NEVER raises —
    any unhandled failure in the *security check* path returns a fail-closed
    block; failures in the *history* path are swallowed silently.

    Security check (fail-closed):
        Build a synthetic ``SecurityObject`` whose ``metadata["raw_arguments"]``
        contains the coerced tool output, run ``ObjectiveGuardrail``.  If a
        secret reason code fires, return a block whose reason is built only from
        the guardrail explanation + reason-code names (never the output text).

    History (best-effort, swallowed):
        Normalize the call, run ``decide``, and ``await record_decision``.
        Wrapped in a broad except so it can never affect the return value.
    """
    try:
        if spine.is_excluded(payload.get("cwd")):
            return None  # device-wide excluded project — full abstain, no I/O

        tool_name = payload.get("tool_name")
        if not isinstance(tool_name, str) or not tool_name:
            # No identifiable tool — fail closed.
            return _post_block(_POST_FAILSAFE_REASON)

        # Internal / meta tools produce harness-internal state, not resource
        # output — abstain entirely (no scan, no history).
        if tool_name in _INTERNAL_TOOLS:
            return None

        # Gate: only scan output for gated built-ins and mcp__ tools.
        is_mcp = tool_name.startswith("mcp__")
        if not is_mcp and tool_name not in _POST_GATED_BUILTINS:
            return None

        cwd = payload.get("cwd")
        repo_root, mode = _resolve_root_and_mode(cwd)
        raw_session = payload.get("session_id")
        session_id = raw_session if isinstance(raw_session, str) and raw_session else None

        # --- Security scan (fail closed on any exception) --------------------
        try:
            tool_response = payload.get("tool_response", "")
            output_text = _coerce_response_text(tool_response)

            raw_input = payload.get("tool_input")
            tool_input = raw_input if isinstance(raw_input, dict) else {}
            canonical, args = to_normalize_input(tool_name, tool_input)
            # Build a synthetic action whose raw_arguments expose the tool
            # output so the secret rule can scan it. The output text is
            # under "tool_output" — never under a key that normalize would
            # publish as the action target.
            scan_args = dict(args)
            scan_args["tool_output"] = output_text

            action = normalize(canonical, scan_args)
            # role=None is intentional here (not the parity gap fixed elsewhere in this
            # module): this action is synthetic, built to scan tool OUTPUT for secrets,
            # not the real call target. Role-boundary is meaningless against scan text.
            ctx = EvalContext(
                role=None,
                mode=mode,
                metadata={"raw_arguments": scan_args, "repo_root": repo_root},
            )

            scan_result = ObjectiveGuardrail().evaluate(action, ctx)
            fired_codes = {rc.value for rc in scan_result.reason_codes}

            # Sticky taint ledger (HK.5.1): record the multi-step-exfil
            # ingredients (a secret entered context, and/or untrusted data was
            # read) BEFORE any block return, so a *blocked* secret-output still
            # taints the session. No verdict authority here — HK.5.2 reads it to
            # raise risk on a later egress.
            _record_taint(tool_name, fired_codes, repo_root, session_id)
            # HK.5.2b: fingerprint the secret(s) in this output so a later egress
            # carrying the same value is a confirmed exfil — before any block return.
            _record_secret_fingerprints(output_text, fired_codes, repo_root, session_id)
            _record_untrusted_value_fingerprints(tool_name, output_text, repo_root, session_id)

            if fired_codes & _POST_BLOCK_REASON_CODES:
                reason = _POST_REASON.format(
                    reasons=", ".join(sorted(fired_codes & _POST_BLOCK_REASON_CODES)),
                    action_id=action.id,
                    explanation=(scan_result.explanation or "").strip() or "no further detail",
                )
                _record_blocked_post_history(scan_result, action, repo_root, session_id)
                return _post_block(reason)

        except Exception:  # noqa: BLE001 — scan failure → fail closed
            return _post_block(_POST_FAILSAFE_REASON)

        # --- History (best-effort, never raises, never blocks) ---------------
        _record_post_history(tool_name, tool_input, repo_root, mode, session_id)

        return None  # clean output — abstain

    except Exception:  # noqa: BLE001 — outer guard: fail closed
        return _post_block(_POST_FAILSAFE_REASON)


def _record_post_history(
    tool_name: str,
    tool_input: dict[str, Any],
    repo_root: str,
    mode: str,
    session_id: str | None,
) -> None:
    """Best-effort: normalize + decide + record_decision for history.

    Wrapped in a broad except — must never raise or affect any verdict. ``mode`` is
    the strictness mode already resolved by the caller (#51) so the history row uses
    the same safe mode as the live decision, never a re-derived ``load_mode(".")``.
    This is also the ONLY decision computed for pure-read tools (Read/Glob/Grep are
    gated here but never in evaluate_pre), so the active role rides along too — same
    real-input action as evaluate_pre, just recomputed post-execution for the log.
    """
    try:
        canonical, args = to_normalize_input(tool_name, tool_input)
        action = normalize(canonical, args)
        ctx = EvalContext(
            role=load_active_role(repo_root),
            mode=mode,
            metadata={"raw_arguments": args, "repo_root": repo_root},
        )
        decision = decide(action, ObjectiveGuardrail(), PASS_STUB, ctx)
        # PostToolUse history for a call that already ran: no challenge was
        # involved on this path, so nobody approved it.
        _record_history_decision(
            decision,
            action,
            repo_root,
            session_id,
            auth_result="executed",
            auth_path=AuthPath.host_hook_objective,
            human_confirmed=False,
        )
    except Exception:  # noqa: BLE001,S110 — history must never break the execution path
        pass


def _record_blocked_post_history(
    scan_result: Any,
    action: SecurityObject,
    repo_root: str,
    session_id: str | None,
) -> None:
    """Best-effort: record a PostToolUse output-scan block in ``doberman log``.

    The objective scan may return AUTH for "secret entered context", but the
    PostToolUse hook's enforcement decision is to block that output from reaching
    the model. The decision log should therefore show the hook-enforced BLOCK.
    """
    try:
        decision = Decision(
            action_id=action.id,
            final_verdict=Verdict.BLOCK,
            final_risk=max_risk(scan_result.risk, Risk.high),
            objective=scan_result,
            subjective=None,
            reason_codes=list(scan_result.reason_codes),
            explanation=scan_result.explanation,
            decided_at=action.ts,
        )
        _record_history_decision(
            decision,
            action,
            repo_root,
            session_id,
            auth_result="blocked",
            auth_path=AuthPath.host_hook_objective,
            human_confirmed=False,
        )
    except Exception:  # noqa: BLE001,S110 — history must never break the block path
        pass


def _record_taint(
    tool_name: str, fired_codes: set[str], repo_root: str, session_id: str | None
) -> None:
    """Best-effort: record the multi-step-exfil ingredients into the sticky taint
    ledger (HK.5.1) under the session + entity scope.

    Records ``secret_access`` when a secret reason code fired in the output scan,
    and ``untrusted_read`` when the tool pulls untrusted external content. No
    verdict authority — HK.5.2 reads the ledger to raise risk on a later egress.
    Guards the common (no-taint) path before importing storage so the hook stays
    light; wrapped so a taint write can never break the execution path.
    """
    has_secret = bool(fired_codes & _SECRET_REASON_CODES)
    has_untrusted = tool_name in _UNTRUSTED_READ_TOOLS
    if not has_secret and not has_untrusted:
        return  # nothing to record — avoid the storage import on the common path

    import asyncio  # lazy import keeps the module scope light

    from doberman.storage.taint import (  # lazy import (light: no numpy/scipy/river)
        TAINT_SECRET_ACCESS,
        TAINT_UNTRUSTED_READ,
        entity_scope,
        record_taints,
    )

    kinds: list[str] = []
    if has_secret:
        kinds.append(TAINT_SECRET_ACCESS)
    if has_untrusted:
        kinds.append(TAINT_UNTRUSTED_READ)

    # Build the scopes defensively: a failure computing the entity scope (e.g. the
    # HMAC key dir is unwritable on first use) must not drop the session-scoped
    # taint too — record under whatever scopes we can resolve.
    scopes: list[str] = [session_id] if session_id else []
    try:
        scopes.append(entity_scope(repo_root))
    except Exception:  # noqa: BLE001,S110 — keep the session scope even if the entity scope fails
        pass

    try:
        asyncio.run(record_taints(repo_root, scopes, kinds))
    except Exception:  # noqa: BLE001,S110 — taint recording must never break execution
        pass


def _record_secret_fingerprints(
    output_text: str, fired_codes: set[str], repo_root: str, session_id: str | None
) -> None:
    """Best-effort: record keyed-HMAC fingerprints of the secret(s) in a tool output
    into the read-vs-send store (HK.5.2b), under the session + entity scope, so a
    later egress carrying the same value is a confirmed exfil (→ BLOCK).

    Only acts when a secret reason code fired (a secret actually entered context).
    Light (the storage import is on the secret path only) and wrapped so a write can
    never break the execution path. The plaintext is fingerprinted, never stored.
    """
    if not (fired_codes & _SECRET_REASON_CODES):
        return  # no secret entered context — nothing to fingerprint

    from doberman.engine.rules.secrets import candidate_secret_fingerprints

    fps = candidate_secret_fingerprints(output_text)
    if not fps:
        return

    import asyncio

    from doberman.storage.taint import entity_scope, record_secret_fingerprints

    scopes: list[str] = [session_id] if session_id else []
    try:
        scopes.append(entity_scope(repo_root))
    except Exception:  # noqa: BLE001,S110 — keep the session scope even if entity scope fails
        pass

    try:
        asyncio.run(record_secret_fingerprints(repo_root, scopes, list(fps)))
    except Exception:  # noqa: BLE001,S110 — fingerprint recording must never break execution
        pass


def _record_untrusted_value_fingerprints(
    tool_name: str, output_text: str, repo_root: str, session_id: str | None
) -> None:
    """Best-effort (C1): record keyed-HMAC fingerprints of the host/URL/email
    VALUES in an untrusted-read tool's output, so a later egress reusing the
    SAME value raises PASS -> AUTH (engine/taint_floor.py's
    apply_echo_tripwire[_async]). Only acts for _UNTRUSTED_READ_TOOLS — a
    trusted local read is not an untrusted-provenance source. Light (the
    storage import is on the untrusted-read path only) and wrapped so a write
    can never break the execution path.

    Reviewer follow-up: calls ``taint_floor.untrusted_read_value_fingerprints``
    — the SAME function the proxy's ``record_output_taint`` calls — so a
    trusted/task-named host is excluded from this leg exactly like the proxy
    leg. The two record legs must never drift on what gets excluded.
    """
    if tool_name not in _UNTRUSTED_READ_TOOLS:
        return

    import asyncio

    from doberman.engine.taint_floor import untrusted_read_value_fingerprints
    from doberman.storage.taint import entity_scope, record_untrusted_values

    scopes: list[str] = [session_id] if session_id else []
    try:
        scopes.append(entity_scope(repo_root))
    except Exception:  # noqa: BLE001,S110 — keep the session scope even if entity scope fails
        pass

    async def _record() -> None:
        values = await untrusted_read_value_fingerprints(output_text, repo_root, session_id)
        if values:
            await record_untrusted_values(repo_root, scopes, list(values), tool_name)

    try:
        asyncio.run(_record())
    except Exception:  # noqa: BLE001,S110 — fingerprint recording must never break execution
        pass


def run_post_hook(stdin: str | bytes) -> str | None:
    """Parse the PostToolUse stdin, evaluate the tool output, and return the
    JSON decision string — or ``None`` to abstain (print nothing).

    ``stdin`` may be raw bytes or already-decoded text — see
    :func:`run_pre_hook` and :func:`_decode_stdin`.

    An unparseable payload or a non-object payload fails closed (block).
    """
    try:
        payload = json.loads(_decode_stdin(stdin))
    except Exception:  # noqa: BLE001 — unparseable input fails closed
        return json.dumps(_post_block(_POST_FAILSAFE_REASON))
    if not isinstance(payload, dict):
        return json.dumps(_post_block(_POST_FAILSAFE_REASON))
    out = _attach_integrity_warning(evaluate_post(payload), payload)
    return json.dumps(out) if out is not None else None

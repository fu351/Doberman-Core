"""The single execution chokepoint between the agent and downstream tools.

Every tool call intercepted by the proxy MUST flow through
:func:`decide_and_execute` — there is no other route to a downstream tool. The
decision engine (Feature 2) judges every normalized action; Feature 7 turns an
``AUTH`` into a real, action-specific challenge:

* ``PASS`` forwards the call.
* ``AUTH`` runs a tiered challenge (confirm / 2FA / role elevation). On approval
  the action is **re-decided** (TOCTOU guard) and, unless it now ``BLOCK``s,
  forwarded; a satisfied ``role_elevation`` grants a narrow, temporary, (for
  destructive scopes) single-use elevation first. Denial/timeout forwards
  nothing.
* ``BLOCK`` returns a policy error and is NEVER forwarded.

Any engine failure is itself a ``BLOCK`` (fail closed). The approval is bound to
exactly one action id (no replay onto a different call).
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone

from mcp.client.session import ClientSession
from mcp.types import CallToolResult, EmbeddedResource, TextContent, TextResourceContents

from doberman.auth.challenge import (
    AuthResult,
    AuthTier,
    Prompter,
    run_auth_challenge,
)
from doberman.auth.elevation import find_cover, scope_for_target
from doberman.config import (
    load_active_role,
    load_enforcement,
    load_message_tone,
    load_mode,
    load_preferences,
)
from doberman.egress.artifact import ArtifactPinStore, ArtifactVerdict
from doberman.engine.correlator import DecisionRow, correlate
from doberman.engine.decision_engine import Guardrail, decide, max_risk, max_verdict
from doberman.engine.effects import compute_delete_effects, unknown_effects
from doberman.engine.objective import ObjectiveGuardrail
from doberman.engine.rules import BUILTIN_RULE_TYPES
from doberman.engine.rules.commands import (
    command_line_from_arguments,
    delete_class_operands_and_dynamic,
)
from doberman.engine.rules.destinations import ExternalDestinationRule
from doberman.engine.rules.secrets import contains_strong_secret
from doberman.engine.subjective import SubjectiveGuardrail
from doberman.engine.taint_floor import (
    apply_echo_tripwire_async,
    apply_taint_floor_async,
    record_output_taint,
)
from doberman.models import (
    ActionType,
    Decision,
    EvalContext,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    Verdict,
)
from doberman.policy.drift import acted_verdict, effective_enforcement
from doberman.policy.sources import effective_policy
from doberman.proxy.interception_log import log_action
from doberman.proxy.normalize import challenge_copy, normalize
from doberman.storage import tool_pins
from doberman.storage.db import (
    active_elevations,
    claim_single_use,
    grant_elevation,
    open_db,
    revoke_elevation,
)
from doberman.storage.log import recent_session_decisions, record_decision
from doberman.subjective.baseline import (
    budget_allows_step_up,
    entity_id,
    observe,
    total_observations,
)
from doberman.subjective.drift import note_allowed, surprise_blended
from doberman.subjective.martingale import MONITOR_EVERY, note_belief, run_monitor
from doberman.subjective.revealed import (
    grant_scope_token,
    has_scope_token,
    maybe_nudge,
    record_feedback,
    revoke_tool_scope_tokens,
)
from doberman.subjective.score import inherit_turn_provenance, raised_surprise

_engine_logger = logging.getLogger("doberman.proxy.engine")

#: Repo root used for config + the elevation store. Module-level so tests can
#: point it at an isolated temp dir (the DB/config must never touch the repo).
REPO_ROOT = "."

#: Prompter for AUTH challenges. None ⇒ the provider's default CLI prompter
#: (stdin/stdout). The stdio ``serve`` path sets this to a controlling-terminal
#: prompter so a challenge never reads/writes the agent's MCP stream. Module-level
#: so tests can inject a headless fake.
AUTH_PROMPTER: Prompter | None = None


def _default_objective_rules(velocity_thresholds=None) -> list[Guardrail]:
    """Built-in rules for :data:`DEFAULT_OBJECTIVE` below.

    Identical to ``ObjectiveGuardrail()``'s own default construction except
    ``ExternalDestinationRule`` opts into egress-broker discovery
    (``load_broker=True``). Unlike the host-hook path (a fresh
    ``ObjectiveGuardrail()`` built on every tool call — see
    ``ExternalDestinationRule``'s docstring), this proxy singleton is built
    once per long-lived process, and ``discover_egress_brokers()`` is itself
    memoized, so the entry-point scan happens at most once here regardless.

    ``velocity_thresholds`` (a :class:`~doberman.egress.velocity.VelocityThresholds`
    or ``None``) is forwarded to ``ExternalDestinationRule`` so the
    policy-sourced egress-velocity thresholds (RB.6) take effect in the
    long-lived proxy singleton. ``None`` means the built-in module defaults
    apply (identical to the pre-RB.6 behaviour).
    """
    return [
        ExternalDestinationRule(load_broker=True, velocity_thresholds=velocity_thresholds)
        if rule_type is ExternalDestinationRule
        else rule_type()
        for rule_type in BUILTIN_RULE_TYPES
    ]


# Guardrail implementations used by the proxy: the real Feature 3 objective rule
# set and the real Feature 9 subjective (workflow-baseline) guardrail. Module-
# level so tests can monkeypatch the policy without touching the routing.
DEFAULT_OBJECTIVE: Guardrail = ObjectiveGuardrail(rules=_default_objective_rules())
DEFAULT_SUBJECTIVE: Guardrail = SubjectiveGuardrail()

#: Action types whose elevations are single-use (a destructive op should not be
#: silently repeatable on one approval).
_DESTRUCTIVE_ACTIONS = frozenset({ActionType.file_delete})

_DENIED_TEMPLATE = (
    "doberman: downstream call failed; action denied "
    "(reason: {reason}; error class: {error_class}; action id: {action_id})"
)

_VERDICT_TEMPLATES = {
    Verdict.AUTH: (
        "doberman: authentication required "
        "(reasons: {reasons}; {explanation}; action id: {action_id})"
    ),
    Verdict.BLOCK: (
        "doberman: blocked by policy (reasons: {reasons}; {explanation}; action id: {action_id})"
    ),
}

#: Reason codes whose presence in a forwarded tool's OUTPUT hard-blocks that
#: output from reaching the model — parity with the host-hook's PostToolUse
#: output scan (``doberman.hosthooks.claude_code._POST_BLOCK_REASON_CODES``).
#: The weaker ``possible_high_entropy_secret`` code is deliberately excluded:
#: it false-positives on hashes/UUIDs/base64 fragments, so it stays recorded
#: (via ``record_output_taint``, already wired below) but never hard-blocks
#: a read on its own.
_OUTPUT_BLOCK_REASON_CODES: frozenset[ReasonCode] = frozenset(
    {ReasonCode.secret_exfiltration, ReasonCode.sensitive_secret_access}
)

#: C3.1 session correlator: how many of the session's most-recent decisions to
#: read as pattern-check history. Bounded so the read stays a cheap, single
#: indexed query regardless of session length.
_CORRELATOR_WINDOW = 20

_STRICT_MODES: frozenset[str] = frozenset({"strict", "paranoid"})
_TOOL_SCHEMA_CHANGED_EXPLANATION = (
    "The tool's advertised contract changed after it was pinned; re-approve the pin "
    "from a human terminal before trusting the new schema."
)


async def _apply_tool_pin_floor(tool_name: str, decision: Decision) -> Decision:
    """Raise a changed tool contract to AUTH, or BLOCK in strict/paranoid."""
    if await tool_pins.pin_status(tool_name, repo_root=REPO_ROOT) != "changed":
        return decision
    # A changed contract also voids any live "approve for this task" comfort
    # tokens for this tool, for every entity — a token granted against the old
    # schema must not mute the step-up on the new one. Idempotent; raise-only.
    revoke_tool_scope_tokens(tool_name)
    floor = Verdict.BLOCK if load_mode(REPO_ROOT) in _STRICT_MODES else Verdict.AUTH
    risk = Risk.critical if floor is Verdict.BLOCK else Risk.high
    reasons = list(dict.fromkeys([*decision.reason_codes, ReasonCode.tool_schema_changed]))
    explanation = " ".join(
        part for part in (decision.explanation.strip(), _TOOL_SCHEMA_CHANGED_EXPLANATION) if part
    )
    return decision.model_copy(
        update={
            "final_verdict": max_verdict(decision.final_verdict, floor),
            "final_risk": max_risk(decision.final_risk, risk),
            "reason_codes": reasons,
            "explanation": explanation,
        }
    )


def _denied_result(reason: ReasonCode, error_class: str, action_id: str) -> CallToolResult:
    """Build a fail-closed error result (no payload or argument echo)."""
    return CallToolResult(
        content=[
            TextContent(
                type="text",
                text=_DENIED_TEMPLATE.format(
                    reason=reason, error_class=error_class, action_id=action_id
                ),
            )
        ],
        isError=True,
    )


def handler_failure_result(exc: Exception) -> CallToolResult:
    """Fail-closed result for an exception that escaped the whole chokepoint (H1).

    Mirrors :func:`_denied_result`: reason code + the exception's Python
    **class name** only — never ``str(exc)``, which could carry argument
    fragments (e.g. a ``KeyError``/pydantic ``ValidationError`` message often
    echoes the offending value). No :class:`SecurityObject` may exist yet at
    this point (the failure can occur before, or elsewhere inside,
    ``decide_and_execute``'s own orchestration), so a fresh id stands in for
    ``action_id`` — nothing here can be correlated with a persisted decision
    row, which is expected: nothing was safely decided.

    Called from ``doberman.proxy.mcp_proxy``'s ``_call_tool`` handler, the
    single point every ``tools/call`` passes through.
    """
    text = _DENIED_TEMPLATE.format(
        reason=ReasonCode.proxy_handler_error,
        error_class=type(exc).__name__,
        action_id=uuid.uuid4().hex,
    )
    # ponytail: every field above (a reason enum, an exception's own Python
    # type name, a fresh uuid) is structurally incapable of carrying argument
    # content — this scrub is defense-in-depth against a future edit to the
    # template that interpolates something unsafe.
    if contains_strong_secret(text):
        text = "doberman: internal error; action denied (redacted)"
    return CallToolResult(content=[TextContent(type="text", text=text)], isError=True)


def _verdict_result(decision: Decision) -> CallToolResult:
    """Agent-visible explanatory error for an AUTH/BLOCK decision."""
    template = _VERDICT_TEMPLATES[decision.final_verdict]
    return CallToolResult(
        content=[
            TextContent(
                type="text",
                text=template.format(
                    reasons=", ".join(decision.reason_codes) or "unspecified",
                    explanation=decision.explanation.strip() or "no further detail",
                    action_id=decision.action_id,
                ),
            )
        ],
        isError=True,
    )


def _engine_failure_decision(action: SecurityObject) -> Decision:
    """A synthetic fail-closed BLOCK used when the engine itself fails."""
    blocked = GuardrailResult(
        verdict=Verdict.BLOCK,
        risk=Risk.high,
        reason_codes=[ReasonCode.objective_guardrail_error],
        explanation="Decision engine failed; failing closed.",
    )
    return Decision(
        action_id=action.id,
        final_verdict=Verdict.BLOCK,
        final_risk=Risk.high,
        objective=blocked,
        subjective=None,
        reason_codes=list(blocked.reason_codes),
        explanation=blocked.explanation,
        decided_at=datetime.now(timezone.utc),
    )


def _build_ctx(
    arguments: dict | None,
    grants: tuple,
    surprise_score: float,
    *,
    budget_ok: bool = True,
    eid: str = "",
    scope_token: bool = False,
) -> EvalContext:
    """Assemble the EvalContext for one decision.

    The objective rules (Feature 3) inspect the UN-redacted call content via
    ``metadata['raw_arguments']`` (in-memory only, never logged/persisted). The
    active role (F4), mode (F6), preference vector (SL5), active elevations
    (F7), the precomputed per-entity surprise (SL4), and the step-up budget
    verdict ride along too — everything async (DB reads) happens here in the
    proxy so the synchronous subjective guardrail never touches the database.

    ``resolved_policy`` (#147) is set ONLY when non-empty — a repo with no
    committed ``doberman.policy.yaml`` and no registered policy-source plugin
    is byte-identical to before this seam existed (``PolicySourceRule`` abstains).
    """
    metadata = {
        "raw_arguments": dict(arguments or {}),
        "repo_root": REPO_ROOT,
        "elevations": grants,
        "surprise": surprise_score,
        "budget_ok": budget_ok,
        "scope_token": scope_token,
        "entity_id": eid,
        "preferences": load_preferences(REPO_ROOT),
    }
    policy = effective_policy(REPO_ROOT)
    if not policy.is_empty:
        metadata["resolved_policy"] = policy
    return EvalContext(
        role=load_active_role(REPO_ROOT),
        mode=load_mode(REPO_ROOT),
        metadata=metadata,
    )


async def _learn_from_auth(
    action: SecurityObject, decision: Decision, approved: bool, eid: str
) -> None:
    """SL6 hook: a SUBJECTIVE step-up's outcome is a revealed-preference label.

    Only fires when the subjective layer drove the ask (objective PASSed but
    the final verdict was AUTH). On approval a TTL'd, session-only scope token
    covers repeats of this exact algebra point (never for the trifecta), and
    accumulated feedback may propose a bounded weight nudge — every weakening
    still routes through the F10 gate. Best-effort, never breaks the path.
    """
    if decision.subjective is None or decision.objective.verdict is not Verdict.PASS:
        return
    try:
        await record_feedback(action, approved, entity_id=eid, repo_root=REPO_ROOT)
        if approved:
            grant_scope_token(action, list(decision.reason_codes), entity_id=eid)
            await maybe_nudge(entity_id=eid, repo_root=REPO_ROOT, prompter=AUTH_PROMPTER)
    except Exception:  # noqa: BLE001 — learning must never break the execution path
        _engine_logger.warning("revealed-preference hook failed (action %s); continuing", action.id)


async def _surprise_or_caution(action: SecurityObject, eid: str) -> float:
    """Precompute the per-entity surprise; ANY failure scores 1.0 (caution).

    The entity's current turn context (TG3.3) is applied raise-only on top —
    a flagged or style-outlier turn makes its follow-on actions score harsher;
    a clean turn contributes exactly nothing.
    """
    try:
        score = await surprise_blended(action, entity_id=eid, repo_root=REPO_ROOT)
    except Exception:  # noqa: BLE001 — a scoring failure must bias toward step-up
        _engine_logger.warning("surprise precompute failed (action %s); scoring 1.0", action.id)
        return 1.0
    return raised_surprise(score, eid)


async def _budget_or_surface(eid: str) -> bool:
    """Check the fatigue budget; overflow is logged for review, never hidden."""
    try:
        budget_ok = await budget_allows_step_up(entity_id=eid, repo_root=REPO_ROOT)
    except Exception:  # noqa: BLE001 — on doubt the step-up surfaces (more caution)
        return True
    if not budget_ok:
        _engine_logger.info(
            "subjective step-up budget exhausted (entity %s); overflow logged for review",
            eid[:12],
        )
    return budget_ok


async def _observe_allowed(action: SecurityObject, eid: str, surprise_score: float) -> None:
    """Record an allowed action in its entity baseline + monitors (best-effort).

    Only ever called after a successful forward — a blocked/denied attempt must
    never teach the baseline that it is "normal" (raise-only learning). The
    drift hook (ADWIN) feeds on the same allowed-only stream and may trigger a
    raise-safe refresh; the layer's belief (1 − surprise) feeds the SL8
    Martingale self-monitor, which runs every MONITOR_EVERY observations and
    can only ever refresh, hold, or surface for review — never loosen.
    """
    try:
        await observe(action, entity_id=eid, repo_root=REPO_ROOT)
        await note_allowed(action, entity_id=eid, repo_root=REPO_ROOT)
        await note_belief(eid, 1.0 - surprise_score, repo_root=REPO_ROOT)
        total = await total_observations(entity_id=eid, repo_root=REPO_ROOT)
        if total and total % MONITOR_EVERY == 0:
            await run_monitor(eid, repo_root=REPO_ROOT)
    except Exception:  # noqa: BLE001 — learning must never break the execution path
        _engine_logger.warning("baseline observe failed (action %s); continuing", action.id)


def _safe_decide(action: SecurityObject, ctx: EvalContext) -> Decision:
    """Run the engine; any failure becomes a fail-closed BLOCK (never crashes)."""
    try:
        return decide(action, DEFAULT_OBJECTIVE, DEFAULT_SUBJECTIVE, ctx)
    except Exception:  # noqa: BLE001 — engine failure must fail closed, not crash
        # BaseException (CancelledError, SystemExit) propagates on purpose — an
        # unwind is fail-closed by construction (no forward is reached).
        _engine_logger.exception("decision engine raised; failing closed (action %s)", action.id)
        return _engine_failure_decision(action)


async def _apply_correlator(
    action: SecurityObject, decision: Decision, mode: str, session_id: str | None
) -> Decision:
    """C3.1 — raise-only cross-call pattern check, run after the taint floor.

    Mirrors ``apply_taint_floor_async``'s own shape: read a bounded slice of
    this session's redacted decision history, run the pure ``correlate()``
    over it, and apply any raise directly via ``max_verdict``/``max_risk`` —
    bypassing the subjective clamp by construction, exactly like the taint
    floor, rather than adding a new code to ``SUBJECTIVE_HARD_BLOCK_ALLOWLIST``.

    Fails closed to the untouched ``decision``: a DB read failure or a
    correlator bug must never crash the path or (via a swallowed exception
    inside this function) silently escalate — both ``recent_session_decisions``
    and ``correlate`` are already individually fail-closed/fail-quiet, and this
    wrapper adds one more layer of defense-in-depth around the two calls.
    """
    try:
        raw_rows = await recent_session_decisions(REPO_ROOT, session_id, _CORRELATOR_WINDOW)
        rows = [
            row for row in (DecisionRow.from_storage(raw) for raw in raw_rows) if row is not None
        ]
        raise_result = correlate(rows, decision, action, mode)
    except Exception:  # noqa: BLE001 — the correlator must never break the execution path
        _engine_logger.warning(
            "session correlator failed (action %s); leaving decision as-is", action.id
        )
        return decision
    if raise_result is None:
        return decision
    reasons = list(dict.fromkeys([*decision.reason_codes, *raise_result.reason_codes]))
    explanation = " ".join(
        part for part in (decision.explanation.strip(), raise_result.explanation.strip()) if part
    )
    return decision.model_copy(
        update={
            "final_verdict": max_verdict(decision.final_verdict, raise_result.verdict),
            "final_risk": max_risk(decision.final_risk, raise_result.risk),
            "reason_codes": reasons,
            "explanation": explanation,
        }
    )


def _is_destructive(action: SecurityObject) -> bool:
    return action.action_type in _DESTRUCTIVE_ACTIONS


async def _forward(
    downstream: ClientSession,
    tool_name: str,
    arguments: dict | None,
    action: SecurityObject,
) -> CallToolResult:
    """Forward an approved call downstream, failing closed on any error."""
    try:
        return await downstream.call_tool(tool_name, arguments or {})
    except Exception as exc:  # noqa: BLE001 — fail closed on ANY failure mode
        # Never re-raise into the serving path and never echo arguments.
        # Deliberately `Exception`, not `BaseException`: cancellation and
        # interpreter shutdown must propagate (they carry no payload to leak).
        return _denied_result(ReasonCode.downstream_error, type(exc).__name__, action.id)


def _result_text(result: CallToolResult) -> str:
    """Flatten a tool result's text content blocks into one string (never raises)."""
    return "".join(block.text for block in result.content if isinstance(block, TextContent))


def _scannable_text(result: CallToolResult) -> str:
    """Every text-bearing channel of a tool result, for the secret scan + taint.

    A tool result can carry plaintext in more than bare ``TextContent`` blocks:
    ``structuredContent`` (a JSON object) and an ``EmbeddedResource``'s text
    (e.g. a returned file resource). A secret in either of those must not bypass
    the output scan just because it isn't a plain text block (CRIT-3), so this
    folds all three channels — separated by newlines so an adjacent boundary can
    neither hide nor fabricate a match — into the string the scan/taint see.

    Binary blobs (``BlobResourceContents``) and image/audio blocks are skipped:
    they carry no plaintext to leak here, and a full base64 blob is scan noise.
    Never raises — a malformed block must not break the forward/return path.

    ponytail: text channels only; if binary/blob exfil ever needs scanning,
    decode the blob here behind a size cap.
    """
    parts: list[str] = []
    for block in result.content:
        if isinstance(block, TextContent):
            parts.append(block.text)
        elif isinstance(block, EmbeddedResource) and isinstance(
            block.resource, TextResourceContents
        ):
            parts.append(block.resource.text)
    if result.structuredContent:
        try:
            parts.append(json.dumps(result.structuredContent, default=str, sort_keys=True))
        except (TypeError, ValueError):
            parts.append(str(result.structuredContent))
    return "\n".join(part for part in parts if part)


async def _record_result_taint(result: CallToolResult, tool_name: str) -> None:
    """Best-effort: feed a successful tool result's text to the taint floor.

    Mirrors the host-hook's PostToolUse recording so a secret OR an untrusted
    value read through the proxy taints the session for the next call's
    cross-call check (``apply_taint_floor_async`` / ``apply_echo_tripwire_async``).
    ``tool_name`` lets ``record_output_taint`` classify the untrusted-read leg
    (C1) — previously dropped here, so that leg was never recorded on this path.
    Guards non-text content blocks; never raises — ``record_output_taint`` is
    itself fail-closed/best-effort, but a malformed result must not break the
    forward/return path.
    """
    try:
        output_text = _scannable_text(result)
        if output_text:
            await record_output_taint(output_text, REPO_ROOT, None, tool_name=tool_name)
    except Exception:  # noqa: BLE001 — recording must never break the execution path
        _engine_logger.warning("output taint recording failed; continuing")


async def _scan_output_for_secrets(
    tool_name: str,
    arguments: dict | None,
    action: SecurityObject,
    result: CallToolResult,
) -> Decision | None:
    """Port of the host-hook's PostToolUse output-scan gate (parity-1).

    Re-normalizes this call with the downstream RESULT text folded into
    ``raw_arguments["tool_output"]`` and runs it back through the same
    ``ObjectiveGuardrail`` used for the pre-execution decision — reusing the
    shared ``doberman.engine.rules.secrets`` detection, never duplicating it.
    A high-confidence secret finding (``secret_exfiltration`` /
    ``sensitive_secret_access``) must not reach the model: this returns a
    synthetic BLOCK ``Decision`` naming only reason codes + a static
    explanation string (never the scanned output text — see
    ``SecretLeakageRule.evaluate``'s fixed explanation strings). Returns
    ``None`` when the output is clean (nothing to gate).

    Fails closed: any exception during the scan itself is treated exactly
    like a hard-block-worthy finding, so a broken scan blocks the output
    rather than silently letting it through.
    """
    try:
        output_text = _scannable_text(result)
        if not output_text:
            return None
        scan_args = dict(arguments or {})
        scan_args["tool_output"] = output_text
        scan_action = normalize(tool_name, scan_args)
        # role=None is intentional (mirrors the host-hook's synthetic scan
        # action): this action exists only to scan OUTPUT text for secrets,
        # not to re-judge the real call target — role-boundary rules are
        # meaningless against scan text.
        scan_ctx = EvalContext(
            role=None,
            mode=load_mode(REPO_ROOT),
            metadata={"raw_arguments": scan_args, "repo_root": REPO_ROOT},
        )
        scan_result = DEFAULT_OBJECTIVE.evaluate(scan_action, scan_ctx)
        if not set(scan_result.reason_codes) & _OUTPUT_BLOCK_REASON_CODES:
            return None
    except Exception:  # noqa: BLE001 — fail closed: a broken scan blocks the output
        scan_result = GuardrailResult(
            verdict=Verdict.BLOCK,
            risk=Risk.high,
            reason_codes=[ReasonCode.objective_guardrail_error],
            explanation="Output secret scan failed; failing closed.",
        )
    return Decision(
        action_id=action.id,
        final_verdict=Verdict.BLOCK,
        final_risk=max_risk(scan_result.risk, Risk.high),
        objective=scan_result,
        subjective=None,
        reason_codes=list(scan_result.reason_codes),
        explanation=scan_result.explanation,
        decided_at=datetime.now(timezone.utc),
    )


async def _verify_artifact_digest(
    action: SecurityObject, result: CallToolResult
) -> Decision | None:
    """Post-fetch pinned-digest check (RB.7), alongside the output secret-scan.

    **Post-fetch only.** A PASS is granted BEFORE the fetch happens, and the
    RB.2b broker relays TLS opaquely (it never sees plaintext response
    bytes), so this can only verify content Doberman already sees in the
    RESULT — it never gates the pre-fetch decision itself. Only meaningful
    for network-fetch actions with a target identity; anything else is a
    no-op. A pinned identity whose fetched content's digest disagrees
    withholds the content from the agent (synthetic BLOCK ``Decision``,
    reason-coded only — never the content or either digest). An unpinned
    identity is unchanged pass-through (the common case).

    Fails closed: any exception during verification is treated exactly like
    a mismatch, so a broken check blocks the output rather than silently
    letting unverified content through.
    """
    if action.action_type is not ActionType.network_request or not action.target:
        return None
    try:
        content_text = _result_text(result)
        if not content_text:
            return None
        store = ArtifactPinStore.from_repo(REPO_ROOT)
        verdict = store.verify(action.target, content_text.encode("utf-8"))
        if verdict is not ArtifactVerdict.mismatch:
            return None
        gate_result = GuardrailResult(
            verdict=Verdict.BLOCK,
            risk=Risk.high,
            reason_codes=[ReasonCode.artifact_digest_mismatch],
            explanation="Fetched content's digest did not match its pinned expected digest.",
        )
    except Exception:  # noqa: BLE001 — fail closed: a broken check blocks the output
        gate_result = GuardrailResult(
            verdict=Verdict.BLOCK,
            risk=Risk.high,
            reason_codes=[ReasonCode.objective_guardrail_error],
            explanation="Artifact digest verification failed; failing closed.",
        )
    return Decision(
        action_id=action.id,
        final_verdict=Verdict.BLOCK,
        final_risk=max_risk(gate_result.risk, Risk.high),
        objective=gate_result,
        subjective=None,
        reason_codes=list(gate_result.reason_codes),
        explanation=gate_result.explanation,
        decided_at=datetime.now(timezone.utc),
    )


async def _revoke_granted_elevation(elevation_id: str | None) -> None:
    """Revoke an elevation granted moments ago in THIS call, when a post-approval
    synthetic BLOCK follows it (issue #557).

    ``_handle_auth`` grants a role elevation, then re-checks the action (TOCTOU
    redecision, and C2's effect-set-divergence recompute) before releasing it. If
    either re-check now BLOCKs, the grant must not outlive the action it was
    approved for — an unrevoked grant stays active for its full TTL and an
    immediate retry could ride it to PASS. Best-effort/fail-closed: the BLOCK
    already being returned by the caller stands regardless of whether this
    revoke itself succeeds, and a revoke error is swallowed rather than crashing
    the decision path.
    """
    if elevation_id is None:
        return
    try:
        await revoke_elevation(REPO_ROOT, elevation_id)
    except Exception:  # noqa: BLE001 — a failed revoke must not crash/leak; the BLOCK still stands
        _engine_logger.warning(
            "elevation revoke failed after a post-approval BLOCK (elevation %s); "
            "grant remains until TTL expiry",
            elevation_id,
        )


async def _claim_single_use(action: SecurityObject, grants: tuple) -> bool:
    """Atomically claim any single-use elevation covering this action, BEFORE it forwards.

    True when there's nothing to claim (no cover, or the cover isn't single-use)
    or the claim succeeded — the caller may forward. False when a covering
    single-use grant was already spent/revoked, or the claim itself raised: the
    caller must deny instead, so two concurrent calls covered by the same grant
    can never both release.
    """
    try:
        grant = find_cover(action.target, grants, root=REPO_ROOT)
        if grant is None or not grant.single_use:
            return True
        return await claim_single_use(REPO_ROOT, grant.id)
    except Exception:  # noqa: BLE001 — a broken claim must fail closed, not release
        _engine_logger.warning("single-use elevation claim raised (action %s); denying", action.id)
        return False


def _single_use_unclaimable_decision(action: SecurityObject) -> Decision:
    """A synthetic BLOCK for a PASS whose covering single-use elevation couldn't be claimed."""
    blocked = GuardrailResult(
        verdict=Verdict.BLOCK,
        risk=Risk.high,
        reason_codes=[ReasonCode.single_use_elevation_unclaimable],
        explanation="Covering single-use elevation was already spent or could not be claimed.",
    )
    return Decision(
        action_id=action.id,
        final_verdict=Verdict.BLOCK,
        final_risk=Risk.high,
        objective=blocked,
        subjective=None,
        reason_codes=list(blocked.reason_codes),
        explanation=blocked.explanation,
        decided_at=datetime.now(timezone.utc),
    )


def _effect_set_diverged_decision(action: SecurityObject) -> Decision:
    """Synthetic BLOCK when the recomputed blast-radius effect set disagrees
    with what was shown at approval time (ADR 0094's TOCTOU guard for the
    delete-class preview) — the filesystem changed between preview and
    execution, in either direction, or a known count became unknown."""
    blocked = GuardrailResult(
        verdict=Verdict.BLOCK,
        risk=Risk.high,
        reason_codes=[ReasonCode.effect_set_diverged],
        explanation="The filesystem changed between the approved preview and "
        "execution; the effect set no longer matches what was shown.",
    )
    return Decision(
        action_id=action.id,
        final_verdict=Verdict.BLOCK,
        final_risk=Risk.high,
        objective=blocked,
        subjective=None,
        reason_codes=list(blocked.reason_codes),
        explanation=blocked.explanation,
        decided_at=datetime.now(timezone.utc),
    )


async def _persist(
    decision: Decision,
    action: SecurityObject,
    *,
    auth_result: str | None = None,
    elevation_id: str | None = None,
    eid: str | None = None,
) -> None:
    """Append one redacted row to the local decision log (best-effort).

    Wrapped so that even a catastrophic logging failure can never alter, block,
    or crash a decision that has already been enforced (logging is observational).
    ``eid`` (the keyed entity fingerprint) powers the per-entity step-up budget
    and revealed-preference learning.
    """
    try:
        await record_decision(
            decision,
            action,
            repo_root=REPO_ROOT,
            auth_result=auth_result,
            elevation_id=elevation_id,
            entity_id=eid,
        )
    except Exception:  # noqa: BLE001 — logging must never break the execution path
        _engine_logger.warning("decision log persist failed (action %s); continuing", action.id)


async def _handle_auth(
    downstream: ClientSession,
    tool_name: str,
    arguments: dict | None,
    action: SecurityObject,
    decision: Decision,
    now: datetime,
    surprise_score: float,
    eid: str,
) -> CallToolResult:
    """Run the tiered challenge for an AUTH decision and act on the outcome."""
    # C2 (ADR 0094): before the challenge is rendered, compute a bounded,
    # offline blast-radius preview for a delete-class command and attach it
    # to the decision every prompter reads. None of this runs (and no
    # filesystem walk happens) for any non-delete-class AUTH —
    # delete_class_operands_and_dynamic returns (None, ...) immediately for
    # those. A delete segment whose operands include a live shell
    # substitution ($( ), a backtick, ${ }, or $VAR) never gets a confirmed
    # count — the walker would silently see a partial/empty operand list,
    # and "0 files" would be a worse preview than none — so `dynamic` is
    # computed once here (M1: one walk_command parse for both the operand
    # list and the dynamic flag) and reused unchanged at the TOCTOU recompute
    # below. compute_delete_effects runs off the event loop (asyncio.to_thread,
    # same as run_auth_challenge below): a slow/adversarial walk must never
    # block the proxy loop (C1 amplifier).
    command = command_line_from_arguments(arguments or {})
    delete_operands, dynamic = (
        delete_class_operands_and_dynamic(command) if command else (None, False)
    )
    if delete_operands is not None:
        effects = (
            unknown_effects()
            if dynamic
            else await asyncio.to_thread(compute_delete_effects, delete_operands, REPO_ROOT)
        )
        decision = decision.model_copy(update={"effects": effects})

    # Off the event loop: the challenge blocks for a human, and an elicitation
    # answer arrives over the very session this loop services — waiting in-loop
    # would deadlock it (and freeze the proxy during GUI/TTY prompts too).
    # The challenge renders the raw command (credential tokens masked); logging
    # and everything after the challenge keep using `action`.
    challenge_action = challenge_copy(action, arguments or {})
    auth_result: AuthResult | None = None
    try:
        auth_result = await asyncio.to_thread(
            run_auth_challenge,
            decision,
            challenge_action,
            prompter=AUTH_PROMPTER,
            message_tone=load_message_tone(REPO_ROOT),
            repo_root=REPO_ROOT,
            session_id=None,
        )
    except Exception:  # noqa: BLE001 — a challenge failure must fail closed, not crash/leak
        _engine_logger.warning("auth challenge raised; failing closed (action %s)", action.id)
        approved = False
    else:
        # Approval is bound to THIS action id — never honor a result for another call.
        approved = auth_result.approved and auth_result.action_id == action.id
    await _learn_from_auth(action, decision, approved, eid)
    if not approved:
        # An expired challenge and a human "no" both deny — but only the log can
        # tell them apart, and they call for different operator responses (an
        # unwatched approval channel vs. a rejected action).
        method = auth_result.method if auth_result is not None else "error"
        if auth_result is not None and auth_result.approved:
            method = "denied"  # approved for a different action id is still a denial here
        await _persist(decision, action, auth_result=method, eid=eid)
        return _verdict_result(decision)

    # A satisfied role elevation grants a narrow, temporary permission first.
    elevation_id: str | None = None
    if auth_result.tier is AuthTier.role_elevation:
        scope = scope_for_target(action.target, root=REPO_ROOT)
        if scope is None:
            # No narrow scope can be formed (non-path / escapes root): refuse.
            await _persist(decision, action, auth_result="denied", eid=eid)
            return _verdict_result(decision)
        try:
            grant = await grant_elevation(
                REPO_ROOT,
                scope,
                action.id,
                now=now,
                single_use=_is_destructive(action),
            )
            elevation_id = grant.id
        except Exception:  # noqa: BLE001 — a failed grant must fail closed
            _engine_logger.warning("elevation grant failed (action %s); denying", action.id)
            await _persist(decision, action, auth_result="denied", eid=eid)
            return _verdict_result(decision)

    # TOCTOU guard: re-decide with refreshed elevations. A change to BLOCK must
    # block even post-approval; otherwise the human-approved action is released.
    grants = tuple(await active_elevations(REPO_ROOT, now))
    redecision = _safe_decide(action, _build_ctx(arguments, grants, surprise_score, eid=eid))
    redecision = await _apply_tool_pin_floor(tool_name, redecision)
    if redecision.final_verdict is Verdict.BLOCK:
        log_action(action, redecision.final_verdict)
        await _revoke_granted_elevation(elevation_id)
        await _persist(
            redecision, action, auth_result=auth_result.method, elevation_id=elevation_id, eid=eid
        )
        return _verdict_result(redecision)

    # C2 (ADR 0094): recompute the SAME operands against the live filesystem
    # and compare digests. Any divergence — in either direction, or a known
    # count becoming unknown — re-blocks: the human approved what the preview
    # showed, not what is on disk now. A dynamic delete segment stays unknown
    # at both ends (the same `dynamic` flag, unchanged since the preview), so
    # it does not re-block on dynamism alone — only on an actual mismatch.
    if decision.effects is not None:
        recomputed = (
            unknown_effects()
            if dynamic
            else await asyncio.to_thread(compute_delete_effects, delete_operands, REPO_ROOT)
        )
        if recomputed.digest != decision.effects.digest:
            diverged = _effect_set_diverged_decision(action)
            await _revoke_granted_elevation(elevation_id)
            await _persist(
                diverged,
                action,
                auth_result=auth_result.method,
                elevation_id=elevation_id,
                eid=eid,
            )
            return _verdict_result(diverged)

    if not await _claim_single_use(action, grants):
        _engine_logger.warning(
            "single-use elevation already spent or unclaimable (action %s); denying", action.id
        )
        # The human already approved this AUTH — persisting the original AUTH
        # decision with auth_result="denied" would misread as "human said no"
        # for what is actually a race/storage failure on the elevation claim.
        # Persist the synthetic unclaimable BLOCK instead, matching the PASS
        # path below.
        denial = _single_use_unclaimable_decision(action)
        await _revoke_granted_elevation(elevation_id)
        await _persist(
            denial, action, auth_result="unclaimable", elevation_id=elevation_id, eid=eid
        )
        return _verdict_result(denial)
    result = await _forward(downstream, tool_name, arguments, action)
    # The output-secret gate runs on EVERY result — success OR error (CRIT-2): a
    # secret rides an error payload to the model just as easily as a clean one.
    # The single-use grant is claimed atomically ABOVE, before the forward, so
    # it is spent whether this result errors or not (matching EXECUTION, not a
    # clean result) and two concurrent calls covered by one grant can't both
    # release.
    await _record_result_taint(result, tool_name)
    gate = await _scan_output_for_secrets(tool_name, arguments, action, result)
    if gate is not None:
        # Output-scan parity (parity-1): a secret in the RESULT must not reach
        # the model even though the call itself was approved. Log only the block
        # — skip the baseline "allowed" observation, since the outcome is not
        # confirmed safe (mirrors the host-hook: one log row, the block).
        await _persist(gate, action, auth_result="blocked", elevation_id=elevation_id, eid=eid)
        return _verdict_result(gate)
    if not result.isError:
        artifact_gate = await _verify_artifact_digest(action, result)
        if artifact_gate is not None:
            # RB.7: a pinned artifact's fetched content disagreed with its
            # expected digest — withhold it from the agent, same shape as the
            # secret-scan gate above (one log row, the block, not a clean one).
            await _persist(
                artifact_gate, action, auth_result="blocked", elevation_id=elevation_id, eid=eid
            )
            return _verdict_result(artifact_gate)
        await _observe_allowed(action, eid, surprise_score)
    await _persist(
        decision, action, auth_result=auth_result.method, elevation_id=elevation_id, eid=eid
    )
    return result


async def decide_and_execute(
    downstream: ClientSession,
    tool_name: str,
    arguments: dict | None,
) -> CallToolResult:
    """Decide whether to execute a tool call, then act on the verdict.

    This is THE chokepoint: normalize → decide → enforce. The downstream forward
    happens only on a PASS decision or a successfully-authenticated AUTH. One
    task-local SQLite connection spans the cycle; storage helpers still open
    their own connection when called outside this boundary.
    """
    async with open_db(REPO_ROOT):
        return await _decide_and_execute(downstream, tool_name, arguments)


async def _decide_and_execute(
    downstream: ClientSession,
    tool_name: str,
    arguments: dict | None,
) -> CallToolResult:
    """Run one decision cycle inside :func:`decide_and_execute`'s DB scope."""
    action: SecurityObject = normalize(tool_name, arguments, {"repo_root": REPO_ROOT})
    now = datetime.now(timezone.utc)
    eid = entity_id(action.agent_role, REPO_ROOT)
    # TG3.3: actions tracing to a flagged pasted turn inherit untrusted
    # provenance (raise-only — an already-untrusted class is left alone).
    action = inherit_turn_provenance(action, eid)

    # Active elevations (F7) may satisfy a role-boundary AUTH for the exact
    # covered target; the per-entity surprise (SL4) and fatigue-budget verdict
    # feed the subjective guardrail — all computed BEFORE the first decision so
    # the synchronous engine can read them from the context.
    grants = tuple(await active_elevations(REPO_ROOT, now))
    score = await _surprise_or_caution(action, eid)
    budget_ok = await _budget_or_surface(eid)
    token = has_scope_token(action, entity_id=eid)
    decision = _safe_decide(
        action,
        _build_ctx(arguments, grants, score, budget_ok=budget_ok, eid=eid, scope_token=token),
    )
    decision = await _apply_tool_pin_floor(tool_name, decision)

    # HK.5.2/5.2b cross-call exfil floor: raise-only, awaited directly (this
    # function already runs inside a live event loop — see taint_floor.py's
    # module docstring for why the sync `apply_taint_floor` must NOT be used here).
    # `session_id=None`: the proxy has no session id of its own, so the floor falls
    # back to the per-repo entity scope.
    decision = await apply_taint_floor_async(
        action, decision, load_mode(REPO_ROOT), REPO_ROOT, None, arguments or {}
    )

    # C1 — the untrusted-value echo tripwire, same session_id=None gap as the
    # taint floor above (see its comment): the pure-MCP proxy has no session
    # concept of its own.
    decision = await apply_echo_tripwire_async(
        action, decision, load_mode(REPO_ROOT), REPO_ROOT, None, arguments or {}
    )

    # C3.1 session correlator: cross-call PATTERN raise (raise-only), run right
    # after the taint floor for the same reason — see _apply_correlator's
    # docstring. Same `session_id=None` gap as the taint floor call above: the
    # pure-MCP proxy's `decide_and_execute`/`_call_tool` chokepoint (mcp_proxy.py)
    # takes only `(downstream, tool_name, arguments)` — no session concept exists
    # anywhere on this call path to thread through, so this deliberately keeps
    # reading an empty history (never fires) here. This is NOT a remaining gap:
    # doberman.hosthooks.spine.evaluate_action DOES have a real per-call session
    # id (HK.5.1, via extract_session_id) and is now wired to the same correlator
    # (doberman.engine.correlator.apply_correlator) — every host-hook adapter
    # (Claude Code, OpenClaw, Codex) fires the correlator for real; only the raw
    # MCP-proxy entry point remains session-less by design, exactly like the
    # taint floor above.
    decision = await _apply_correlator(action, decision, load_mode(REPO_ROOT), None)

    # Record every intercepted action with its REAL verdict. Logged before the
    # gate — safe because log_action swallows its own failures and forwards
    # nothing.
    log_action(action, decision.final_verdict)

    # F10: honor the enforcement dial (Option A). monitor/off soften a
    # DISCRETIONARY AUTH/BLOCK to observe-only (forward); the objective floor
    # (secrets / exfil / taint / destructive / role / policy / trifecta) stays live
    # in every state. Resolve through the ledger-verified clamp — a hand-edited
    # `enforcement: off` with no matching approved ledger row is clamped back to
    # enforce. The post-approval TOCTOU re-decision inside _handle_auth is left
    # fully live on purpose (a released action must still re-check the floor).
    enforcement, expires_at, revert = load_enforcement(REPO_ROOT)
    state = await effective_enforcement(
        REPO_ROOT, enforcement=enforcement, expires_at=expires_at, revert=revert
    )
    acted = acted_verdict(decision, state)

    if acted is Verdict.BLOCK:
        await _persist(decision, action, eid=eid)
        return _verdict_result(decision)

    if acted is Verdict.AUTH:
        return await _handle_auth(
            downstream, tool_name, arguments, action, decision, now, score, eid
        )

    # PASS — real, or a discretionary verdict softened by monitor/off — claim
    # any single-use elevation that covers it BEFORE forwarding, then forward.
    softened = decision.final_verdict is not Verdict.PASS
    if not await _claim_single_use(action, grants):
        _engine_logger.warning(
            "single-use elevation already spent or unclaimable (action %s); denying", action.id
        )
        denial = _single_use_unclaimable_decision(action)
        await _persist(denial, action, auth_result="unclaimable", eid=eid)
        return _verdict_result(denial)
    result = await _forward(downstream, tool_name, arguments, action)
    # The output-secret gate runs on EVERY result — success OR error (CRIT-2): a
    # secret rides an error payload to the model just as easily as a clean one.
    # The single-use grant is claimed atomically ABOVE, before the forward, so
    # it is spent whether this result errors or not (matching EXECUTION, not a
    # clean result) and two concurrent calls covered by one grant can't both
    # release.
    await _record_result_taint(result, tool_name)
    gate = await _scan_output_for_secrets(tool_name, arguments, action, result)
    if gate is not None:
        # Output-scan parity (parity-1): a secret in the RESULT must not reach
        # the model even though the call itself was PASS. Log only the block —
        # skip the baseline "allowed" observation below, since the outcome is
        # not confirmed safe (mirrors the host-hook: one log row, the block).
        await _persist(gate, action, auth_result="blocked", eid=eid)
        return _verdict_result(gate)
    if not result.isError:
        artifact_gate = await _verify_artifact_digest(action, result)
        if artifact_gate is not None:
            # RB.7: a pinned artifact's fetched content disagreed with its
            # expected digest — withhold it from the agent, same shape as the
            # secret-scan gate above (one log row, the block, not a clean one).
            await _persist(artifact_gate, action, auth_result="blocked", eid=eid)
            return _verdict_result(artifact_gate)
        if not softened:
            # Teach the baseline only on a GENUINE pass. A softened would-have
            # (monitor/off suppressed a step-up) is NOT confirmed-benign — feeding
            # it to the allowed-only baseline would desensitize the subjective layer
            # during monitor and quietly loosen it before a flip to enforce
            # (raise-only / poisoning-resistance).
            await _observe_allowed(action, eid, score)
    # Persist the REAL verdict. A genuine pass and a MONITOR would-have are recorded
    # (monitor's whole value is showing what would have happened); `off` is the
    # silent, non-recording state — matching the host-hook pre path.
    if not softened or state == "monitor":
        await _persist(decision, action, eid=eid)
    return result

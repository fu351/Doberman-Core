"""Append-only, redacted decision log (Feature 8, slice 8.2).

One immutable, **redacted** row per engine decision, written to the local
SQLite ``decisions`` table and fanned out to any registered audit sinks
(slice 8.4). This is the substrate explainability, learning, and drift defense
build on.

Redaction is structural and load-bearing:

* The row stores a path **class** (filename dropped), the action type, the
  verdict, reason codes, the decided layer, and ids — **never** the raw target,
  raw arguments, file contents, or a prompt. Secrets are represented only by the
  HMAC fingerprints already on the action, upserted into ``secret_fingerprints``.
* Writing is **append-only**: this module only ever ``INSERT``s into
  ``decisions`` (and upserts ``last_seen`` on fingerprints) — there is no
  ``UPDATE``/``DELETE`` path for a decision row.
* Writing is **best-effort**: any failure is logged to stderr and swallowed —
  it can never raise into the execution path and never flips a verdict. The
  decision has already been made and enforced before this runs.
"""

import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import PurePosixPath

from doberman.models import ActionType, Decision, EffectSet, SecurityObject
from doberman.storage.db import open_db
from doberman.storage.device_metrics import record_decision_metric
from doberman.storage.fingerprint import fingerprint
from doberman.storage.sinks import emit_to_sinks

logger = logging.getLogger("doberman.storage.log")

_PATH_ACTIONS = frozenset({ActionType.file_read, ActionType.file_write, ActionType.file_delete})

_INSERT_DECISION = (
    "INSERT INTO decisions "
    "(ts, action_id, agent_role, action_type, target_path_class, risk, source_context, "
    "final_verdict, decided_layer, reason_codes_json, auth_required, auth_result, "
    "auth_path, human_confirmed, elevation_id, "
    "entity_id, session_id, effects_file_count, effects_dir_count, effects_capped, "
    "effects_hits_git, effects_hits_outside_repo, effects_digest_fp) "
    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
)

_INSERT_SHADOW = (
    "INSERT INTO shadow_adjudications "
    "(ts, action_id, live_verdict, shadow_verdict, shadow_reason_codes, entity_id) "
    "VALUES (?, ?, ?, ?, ?, ?)"
)

_UPSERT_FINGERPRINT = (
    "INSERT INTO secret_fingerprints (fingerprint, label, first_seen, last_seen, source_path_class) "
    "VALUES (?, ?, ?, ?, ?) "
    "ON CONFLICT(fingerprint) DO UPDATE SET last_seen = excluded.last_seen"
)

_SELECT_DECISIONS = (
    "SELECT id, ts, action_id, agent_role, action_type, target_path_class, risk, source_context, "
    "final_verdict, decided_layer, reason_codes_json, auth_required, auth_result, "
    "auth_path, human_confirmed, elevation_id, "
    "entity_id, session_id, effects_file_count, effects_dir_count, effects_capped, "
    "effects_hits_git, effects_hits_outside_repo, effects_digest_fp "
    "FROM decisions ORDER BY id DESC"
)

# Mirrors _SELECT_DECISIONS but ascending + cursor-bounded, for the dash's live
# feed poll (doberman.dash): "give me what's new since the last row I saw".
_SELECT_DECISIONS_SINCE = (
    "SELECT id, ts, action_id, agent_role, action_type, target_path_class, risk, source_context, "
    "final_verdict, decided_layer, reason_codes_json, auth_required, auth_result, "
    "auth_path, human_confirmed, elevation_id, "
    "entity_id, session_id, effects_file_count, effects_dir_count, effects_capped, "
    "effects_hits_git, effects_hits_outside_repo, effects_digest_fp "
    "FROM decisions WHERE id > ? ORDER BY id ASC"
)

# C3.1 — the session correlator's history read (doberman.engine.correlator).
# Narrower than _SELECT_DECISIONS: only the redacted fields a correlation
# pattern needs, scoped to one session and newest-first so the caller can take
# the last N cheaply.
_SELECT_SESSION_DECISIONS = (
    "SELECT action_type, target_path_class, source_context, risk, reason_codes_json, "
    "final_verdict FROM decisions WHERE session_id = ? ORDER BY id DESC LIMIT ?"
)

# Maintenance deletes only fully-resolved decision rows. Every verdict except
# AUTH is final; an AUTH row remains eligible only once it has an explicit
# auth outcome (any non-NULL auth_result — the auth tier/method name,
# "blocked", "error", "approved", "denied", "executed", ...). A NULL
# auth_result (still pending) is deliberately kept.
_RESOLVED_DECISIONS_PREDICATE = "(final_verdict <> 'AUTH' OR auth_result IS NOT NULL)"
_DELETE_RESOLVED_DECISIONS = "DELETE FROM decisions WHERE " + _RESOLVED_DECISIONS_PREDICATE  # noqa: S608 — fixed clause, params bound
_DECISION_COLUMNS = [
    "id",
    "ts",
    "action_id",
    "agent_role",
    "action_type",
    "target_path_class",
    "risk",
    "source_context",
    "final_verdict",
    "decided_layer",
    "reason_codes_json",
    "auth_required",
    "auth_result",
    "auth_path",
    "human_confirmed",
    "elevation_id",
    "entity_id",
    "session_id",
    "effects_file_count",
    "effects_dir_count",
    "effects_capped",
    "effects_hits_git",
    "effects_hits_outside_repo",
    "effects_digest_fp",
]


def path_class(action: SecurityObject) -> str | None:
    """A redaction-safe class for a file target: drop the filename, keep dir + ext.

    ``backend/auth/session.ts`` → ``backend/auth/*.ts``; ``.ssh/id_rsa`` →
    ``.ssh/*`` (extensionless names under a directory are wildcarded like any
    other filename); ``.env`` → ``.env`` (a *top-level* dotfile/extensionless
    name, with no directory component, is itself the class). Non-file actions
    have no path class. Never returns the raw filename of a file under a
    directory, extensioned or not.

    Public (renamed from ``_path_class``) so D3's dashboard-approval queue
    (``doberman.auth.dashboard_prompter``) can derive the same redaction-safe
    path class for a pending row without duplicating this logic.
    """
    if action.target_path_class:
        return action.target_path_class
    if action.action_type not in _PATH_ACTIONS or not action.target:
        return None
    pure = PurePosixPath(str(action.target).replace("\\", "/"))
    parent = pure.parent.as_posix()
    parent = "" if parent == "." else parent
    # ponytail: extensionless names are their own class only with no
    # directory (the bare-dotfile shape, e.g. ".env"); under a directory an
    # extensionless name must be wildcarded too, or the raw filename leaks
    # verbatim (".ssh/id_rsa", "/etc/passwd").
    stem_class = f"*{pure.suffix}" if (pure.suffix or parent) else pure.name
    return f"{parent}/{stem_class}" if parent else stem_class


def _decided_layer(decision: Decision) -> str:
    """Which layer produced the verdict: objective alone, or combined with subjective."""
    return "objective" if decision.subjective is None else "combined"


def _effects_fields(effects: EffectSet | None) -> dict:
    """Redaction-safe :class:`EffectSet` fields for the audit row (issue #556).

    Every field is ``None`` when there's no preview (a non-delete-class
    decision) — never 0/False, so "no preview" stays distinguishable from "an
    empty one". ``effects_digest_fp`` is a keyed HMAC of the plain sha256
    digest, never the plain digest itself: a sha256 of a small, guessable
    relative-path set is brute-forceable without the key (CLAUDE.md §9).
    """
    if effects is None:
        return {
            "effects_file_count": None,
            "effects_dir_count": None,
            "effects_capped": None,
            "effects_hits_git": None,
            "effects_hits_outside_repo": None,
            "effects_digest_fp": None,
        }
    try:
        digest_fp = fingerprint(effects.digest)
    except Exception:  # noqa: BLE001 — a fingerprint()-key failure must lose only
        # this column, never the whole audit row (review fix for #556).
        logger.debug("decision log: could not fingerprint effects digest")
        digest_fp = None
    return {
        "effects_file_count": effects.file_count,
        "effects_dir_count": effects.dir_count,
        "effects_capped": effects.capped,
        "effects_hits_git": effects.hits_git,
        "effects_hits_outside_repo": effects.hits_outside_repo,
        "effects_digest_fp": digest_fp,
    }


def build_record(
    decision: Decision,
    action: SecurityObject,
    *,
    auth_result: str | None,
    elevation_id: str | None,
    now: datetime,
    entity_id: str | None = None,
    session_id: str | None = None,
    auth_path: str | None = None,
    human_confirmed: bool | None = None,
) -> dict:
    """Build the single redacted record persisted and handed to every sink.

    ``entity_id`` is a keyed HMAC fingerprint of role+workspace (SL4) — itself
    redaction-safe — that powers the per-entity step-up budget and
    revealed-preference learning. ``session_id`` is the host harness's opaque
    session identifier (HK.5.1) — a UUID, not a secret — used to correlate the
    calls of one agent session for the multi-step taint floor.

    ``auth_path`` (a :class:`~doberman.models.AuthPath` value) and
    ``human_confirmed`` record *who resolved* an authentication, which
    ``auth_result`` alone cannot express because each writer spells its outcomes
    differently (#505). Both default to ``None`` — a caller that does not know
    records "not recorded" rather than a guess, and a caller that knows no auth
    was involved passes ``AuthPath.none``. Neither field ever carries command
    text: ``auth_path`` is a closed enum and ``human_confirmed`` is a bool.
    """
    record = {
        "ts": now.isoformat(),
        "action_id": decision.action_id,
        "agent_role": action.agent_role,
        "action_type": action.action_type.value,
        "target_path_class": path_class(action),
        "risk": decision.final_risk.value,
        "source_context": action.source_context.value,
        "final_verdict": decision.final_verdict.value,
        "decided_layer": _decided_layer(decision),
        "reason_codes": [rc.value for rc in decision.reason_codes],
        "auth_required": decision.final_verdict.value == "AUTH",
        "auth_result": auth_result,
        "auth_path": auth_path,
        "human_confirmed": human_confirmed,
        "elevation_id": elevation_id,
        "entity_id": entity_id,
        "session_id": session_id,
    }
    record.update(_effects_fields(decision.effects))
    return record


async def record_decision(
    decision: Decision,
    action: SecurityObject,
    *,
    repo_root: str,
    auth_result: str | None = None,
    elevation_id: str | None = None,
    now: datetime | None = None,
    entity_id: str | None = None,
    session_id: str | None = None,
    auth_path: str | None = None,
    human_confirmed: bool | None = None,
) -> None:
    """Persist one redacted decision row and fan it out to sinks (best-effort).

    Never raises: building the record, the storage write, and the sink fan-out
    are all inside the failure boundary, so nothing here can alter or block the
    decision (which has already been enforced).
    """
    try:
        record = build_record(
            decision,
            action,
            auth_result=auth_result,
            elevation_id=elevation_id,
            now=now or datetime.now(timezone.utc),
            entity_id=entity_id,
            session_id=session_id,
            auth_path=auth_path,
            human_confirmed=human_confirmed,
        )
    except Exception:  # noqa: BLE001 — the decision log must never break execution
        logger.warning("decision log: could not build record for action %s", decision.action_id)
        return

    try:
        async with open_db(repo_root) as conn:
            await conn.execute(
                _INSERT_DECISION,
                (
                    record["ts"],
                    record["action_id"],
                    record["agent_role"],
                    record["action_type"],
                    record["target_path_class"],
                    record["risk"],
                    record["source_context"],
                    record["final_verdict"],
                    record["decided_layer"],
                    json.dumps(record["reason_codes"]),
                    int(record["auth_required"]),
                    record["auth_result"],
                    record["auth_path"],
                    # bool -> 1/0 for SQLite, but None stays None: "not recorded"
                    # is a third state and must never collapse into 0 ("no human").
                    None if record["human_confirmed"] is None else int(record["human_confirmed"]),
                    record["elevation_id"],
                    record["entity_id"],
                    record["session_id"],
                    record["effects_file_count"],
                    record["effects_dir_count"],
                    record["effects_capped"],
                    record["effects_hits_git"],
                    record["effects_hits_outside_repo"],
                    record["effects_digest_fp"],
                ),
            )
            for fp in action.payload_fingerprints:
                await conn.execute(
                    _UPSERT_FINGERPRINT,
                    (fp, "secret", record["ts"], record["ts"], record["target_path_class"]),
                )
            await conn.commit()
    except Exception:  # noqa: BLE001 — the decision log must never break execution
        logger.warning("decision log write failed for action %s; continuing", decision.action_id)

    # Fan-out is best-effort and isolated; never let it raise either.
    try:
        emit_to_sinks(record, repo_root=repo_root)
    except Exception:  # noqa: BLE001 — defense in depth (emit_to_sinks already isolates)
        logger.warning("audit sink fan-out failed for action %s; continuing", decision.action_id)

    # Device-global rollup for `doberman dashboard` (best-effort, defense in
    # depth — record_decision_metric already swallows its own failures).
    try:
        record_decision_metric(record["final_verdict"])
    except Exception:  # noqa: BLE001 — the device rollup must never break execution
        logger.warning("device metrics rollup failed for action %s; continuing", decision.action_id)


async def record_shadow(
    decision: Decision,
    action: SecurityObject,
    *,
    repo_root: str,
    entity_id: str | None = None,
) -> None:
    """Persist one redacted shadow-adjudication row (best-effort, shadow-only).

    Writes a row ONLY when ``decision.shadow`` is set. Stores the live verdict and
    the shadow verdict/reason-code **classes** — never a raw value — so this
    ledger is redaction-safe by construction. Like :func:`record_decision` it is
    outside the decision path: any failure is logged and swallowed, so it can
    never raise into execution or alter a verdict (the decision is already made).

    Not yet wired into the executor persist path — this slice provides + unit-tests
    the writer; wiring is a follow-up.
    """
    if decision.shadow is None:
        return
    try:
        shadow = decision.shadow
        ts = datetime.now(timezone.utc).isoformat()
        async with open_db(repo_root) as conn:
            await conn.execute(
                _INSERT_SHADOW,
                (
                    ts,
                    decision.action_id,
                    decision.final_verdict.value,
                    shadow.verdict.value,
                    json.dumps([rc.value for rc in shadow.reason_codes]),
                    entity_id,
                ),
            )
            await conn.commit()
    except Exception:  # noqa: BLE001 — the shadow log must never break execution
        logger.warning("shadow log write failed for action %s; continuing", decision.action_id)


async def prune_decisions(
    repo_root: str,
    *,
    older_than_days: int | None = None,
    max_rows: int | None = None,
    now: datetime | None = None,
) -> dict[str, int]:
    """Prune resolved decision-log rows by age and/or a retained row budget.

    This is an operator-initiated maintenance operation, not part of the hot
    decision path. It only removes rows whose verdict is final (or whose AUTH
    row has an explicit auth outcome — any non-NULL ``auth_result``); unresolved
    AUTH rows are never deleted. The append-only ``policy_changes`` ledger is
    not touched.

    ``older_than_days`` uses the same ISO-8601 timestamp convention as the rest
    of storage: exact cutoff stays, one second older goes. With ``max_rows``,
    the newest matching rows are retained first, so an old-but-unresolved row
    cannot displace a newer resolved row from the budget.

    Returns counts only and raises on storage errors rather than reporting a
    partial delete as successful.
    """
    if older_than_days is None and max_rows is None:
        raise ValueError("specify --older-than-days and/or --max-rows")
    if older_than_days is not None and older_than_days < 1:
        raise ValueError("--older-than-days must be at least 1")
    if max_rows is not None and max_rows < 0:
        raise ValueError("--max-rows cannot be negative")

    age_deleted = 0
    overflow_deleted = 0
    async with open_db(repo_root) as conn:
        if older_than_days is not None:
            when = now or datetime.now(timezone.utc)
            cutoff = (when - timedelta(days=older_than_days)).isoformat()
            cur = await conn.execute(_DELETE_RESOLVED_DECISIONS + " AND ts < ?", (cutoff,))
            age_deleted = cur.rowcount

        if max_rows is not None:
            query = (
                "DELETE FROM decisions WHERE "  # noqa: S608
                + _RESOLVED_DECISIONS_PREDICATE
                + " AND id NOT IN (SELECT id FROM decisions WHERE "
                + _RESOLVED_DECISIONS_PREDICATE
                + " ORDER BY id DESC LIMIT ?)"
            )  # noqa: S608 — fixed clauses, params bound
            cur = await conn.execute(
                query,
                (max_rows,),
            )
            overflow_deleted = cur.rowcount

        await conn.commit()
    return {"age_deleted": age_deleted, "overflow_deleted": overflow_deleted}


async def read_decisions(repo_root: str, *, limit: int | None = None) -> list[dict]:
    """Read decision rows, newest first (for ``doberman log``). Fails closed to []."""
    from doberman.storage.db import db_path

    if not db_path(repo_root).exists():
        return []
    query = _SELECT_DECISIONS + (f" LIMIT {int(limit)}" if limit is not None else "")
    try:
        async with open_db(repo_root) as conn:
            async with conn.execute(query) as cur:
                rows = await cur.fetchall()
    except Exception:  # noqa: BLE001 — a read failure must never crash the CLI
        return []
    return [dict(zip(_DECISION_COLUMNS, row, strict=True)) for row in rows]


async def read_decisions_since(
    repo_root: str, since_id: int, *, limit: int | None = None
) -> list[dict]:
    """Read decision rows with ``id > since_id``, oldest first (cursor-based poll).

    For the dash's live feed (``doberman.dash``): pass the highest ``id`` already
    seen and get back only what's new. Same shape/columns as :func:`read_decisions`
    and the same fail-closed-to-``[]`` behavior (missing/locked DB, any error).
    """
    from doberman.storage.db import db_path

    if not db_path(repo_root).exists():
        return []
    query = _SELECT_DECISIONS_SINCE + (f" LIMIT {int(limit)}" if limit is not None else "")
    try:
        async with open_db(repo_root) as conn:
            async with conn.execute(query, (since_id,)) as cur:
                rows = await cur.fetchall()
    except Exception:  # noqa: BLE001 — a read failure must never crash the dash
        return []
    return [dict(zip(_DECISION_COLUMNS, row, strict=True)) for row in rows]


async def recent_session_decisions(repo_root: str, session_id: str | None, n: int) -> list[dict]:
    """The last ``n`` decisions for ``session_id``, newest first — lightweight,
    already-redacted rows for the session correlator (``doberman.engine.correlator``).

    Each row is ``{"action_type", "target_path_class", "source_context", "risk",
    "reason_codes" (parsed list), "final_verdict"}`` — the same redacted
    vocabulary already persisted by :func:`record_decision`, never the raw
    target/arguments. Fails closed to ``[]`` on any error (missing/locked DB, no
    ``session_id``, a malformed row) — a degraded read must never fabricate
    session history, which would let the correlator either miss or invent a
    cross-call pattern.
    """
    from doberman.storage.db import db_path

    if not session_id or not db_path(repo_root).exists():
        return []
    try:
        async with open_db(repo_root) as conn:
            async with conn.execute(_SELECT_SESSION_DECISIONS, (session_id, int(n))) as cur:
                rows = await cur.fetchall()
    except Exception:  # noqa: BLE001 — a read failure must never break the decision path
        return []

    out: list[dict] = []
    for (
        action_type,
        target_path_class,
        source_context,
        risk,
        reason_codes_json,
        final_verdict,
    ) in rows:
        try:
            reason_codes = json.loads(reason_codes_json) if reason_codes_json else []
        except (TypeError, ValueError):
            reason_codes = []
        out.append(
            {
                "action_type": action_type,
                "target_path_class": target_path_class,
                "source_context": source_context,
                "risk": risk,
                "reason_codes": reason_codes,
                "final_verdict": final_verdict,
            }
        )
    return out


async def memory_summary(repo_root: str) -> dict:
    """Plain-language, redaction-safe profile for ``doberman memory``.

    Reports *classes and habits only*: how many decisions, the verdict mix, the
    most-touched path classes, and how many distinct secrets have been seen — as
    a **count**, never a fingerprint value, and never a raw secret.
    """
    from collections import Counter

    from doberman.storage.db import db_path

    summary = {"decisions": 0, "verdicts": {}, "top_path_classes": [], "secrets_seen": 0}
    if not db_path(repo_root).exists():
        return summary
    decisions = await read_decisions(repo_root)
    summary["decisions"] = len(decisions)
    summary["verdicts"] = dict(Counter(d["final_verdict"] for d in decisions))
    classes = Counter(d["target_path_class"] for d in decisions if d["target_path_class"])
    summary["top_path_classes"] = classes.most_common(5)
    try:
        async with open_db(repo_root) as conn:
            async with conn.execute("SELECT COUNT(*) FROM secret_fingerprints") as cur:
                row = await cur.fetchone()
        summary["secrets_seen"] = row[0] if row else 0
    except Exception:  # noqa: BLE001 — best-effort summary
        summary["secrets_seen"] = 0
    return summary

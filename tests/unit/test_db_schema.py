"""Slice 8.1 — SQLite schema, migrations, and the no-secret-column guarantee."""

import asyncio
import os
import sqlite3
import stat

import aiosqlite
import pytest

from doberman.storage.db import SCHEMA_VERSION, _add_column_if_missing, db_path, open_db

_EXPECTED_TABLES = {
    "schema_version",
    "elevations",
    "decisions",
    "secret_fingerprints",
    "baseline_counts",
    "policy_changes",
    "cost_events",
}

#: Column names that would (or could) hold raw secret material. The decisions
#: table must contain NONE of these — only a path *class*, codes, and ids.
_FORBIDDEN_COLUMNS = {
    "target",  # the raw path — only target_path_class is allowed
    "raw_args",
    "raw_arguments",
    "arguments",
    "content",
    "secret",
    "prompt",
    "password",
    "payload",
}


async def _table_names(conn) -> set[str]:
    async with conn.execute("SELECT name FROM sqlite_master WHERE type='table'") as cur:
        return {row[0] for row in await cur.fetchall()}


async def _columns(conn, table: str) -> list[str]:
    async with conn.execute(f"PRAGMA table_info({table})") as cur:  # noqa: S608 — fixed table name
        return [row[1] for row in await cur.fetchall()]


async def test_schema_creates_all_tables(tmp_path):
    async with open_db(str(tmp_path)) as conn:
        tables = await _table_names(conn)
    assert _EXPECTED_TABLES <= tables


async def test_version_row_records_current_schema(tmp_path):
    async with open_db(str(tmp_path)) as conn:
        async with conn.execute("SELECT version FROM schema_version") as cur:
            rows = await cur.fetchall()
    assert [r[0] for r in rows] == [SCHEMA_VERSION]


async def test_decisions_table_has_no_secret_bearing_columns(tmp_path):
    async with open_db(str(tmp_path)) as conn:
        cols = set(await _columns(conn, "decisions"))
    assert cols & _FORBIDDEN_COLUMNS == set()
    assert "target_path_class" in cols  # the redacted class IS present


async def test_cost_events_table_has_no_secret_bearing_columns(tmp_path):
    async with open_db(str(tmp_path)) as conn:
        cols = set(await _columns(conn, "cost_events"))
    assert cols & _FORBIDDEN_COLUMNS == set()
    assert {"kind", "units", "entity_id"} <= cols  # counts + coarse class + keyed id only


async def test_schema_creation_is_idempotent(tmp_path):
    root = str(tmp_path)
    async with open_db(root):
        pass
    async with open_db(root) as conn:  # second open must not duplicate or error
        async with conn.execute("SELECT COUNT(*) FROM schema_version") as cur:
            count = (await cur.fetchone())[0]
    assert count == 1


# --- v8 -> v9: last_touched retention stamps (Subj1) -----------------------


_V9_TABLES_AND_BACKFILL_SOURCE = {
    "baseline_counts": "last_seen",
    "baseline_transitions": None,
    "baseline_state": None,
    "score_history": "ts",
    "preference_feedback": "updated_at",
}


async def test_migration_adds_and_backfills_last_touched(tmp_path):
    # Hand-build a v8-shaped DB (pre-Subj1): every baseline/preference table
    # without last_touched, one existing row per table carrying real data in
    # whatever timestamp column it already had.
    path = db_path(str(tmp_path))
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = await aiosqlite.connect(str(path))
    await conn.executescript(
        """
        CREATE TABLE schema_version (version INTEGER NOT NULL);
        INSERT INTO schema_version (version) VALUES (8);
        CREATE TABLE baseline_counts (
            entity_id TEXT NOT NULL, feature_key TEXT NOT NULL, role TEXT,
            count INTEGER NOT NULL DEFAULT 0, mean REAL NOT NULL DEFAULT 0,
            m2 REAL NOT NULL DEFAULT 0, ewma_var REAL NOT NULL DEFAULT 0,
            first_seen TEXT, last_seen TEXT,
            PRIMARY KEY (entity_id, feature_key)
        );
        INSERT INTO baseline_counts (entity_id, feature_key, count, last_seen)
            VALUES ('hmac:aaa', '__total__', 3, '2026-01-01T00:00:00+00:00');
        CREATE TABLE baseline_transitions (
            entity_id TEXT NOT NULL, from_state TEXT NOT NULL, to_state TEXT NOT NULL,
            count INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (entity_id, from_state, to_state)
        );
        INSERT INTO baseline_transitions (entity_id, from_state, to_state, count)
            VALUES ('hmac:aaa', '1:x', 'y', 1);
        CREATE TABLE baseline_state (
            entity_id TEXT PRIMARY KEY, last_state TEXT, prev_state TEXT
        );
        INSERT INTO baseline_state (entity_id, last_state) VALUES ('hmac:aaa', 'y');
        CREATE TABLE score_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT, entity_id TEXT NOT NULL,
            ts TEXT NOT NULL, kind TEXT NOT NULL, value REAL NOT NULL
        );
        INSERT INTO score_history (entity_id, ts, kind, value)
            VALUES ('hmac:aaa', '2026-01-02T00:00:00+00:00', 'novelty', 0.5);
        CREATE TABLE preference_feedback (
            entity_id TEXT NOT NULL, dimension TEXT NOT NULL,
            approvals INTEGER NOT NULL DEFAULT 0, denials INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT, PRIMARY KEY (entity_id, dimension)
        );
        INSERT INTO preference_feedback (entity_id, dimension, approvals, updated_at)
            VALUES ('hmac:aaa', 'confidentiality', 1, '2026-01-03T00:00:00+00:00');
        """
    )
    await conn.commit()
    await conn.close()

    # Opening through Doberman triggers the additive migration.
    async with open_db(str(tmp_path)) as conn:
        for table, backfill_source in _V9_TABLES_AND_BACKFILL_SOURCE.items():
            cols = await _columns(conn, table)
            assert "last_touched" in cols
            if backfill_source is None:
                continue  # no prior timestamp column to backfill from
            async with conn.execute(f"SELECT last_touched, {backfill_source} FROM {table}") as cur:  # noqa: S608
                row = await cur.fetchone()
            assert row[0] == row[1]  # backfilled from the existing column, not invented
        # Existing data (not just the new column) survived the migration.
        async with conn.execute(
            "SELECT count FROM baseline_counts WHERE entity_id = 'hmac:aaa'"
        ) as cur:
            assert (await cur.fetchone())[0] == 3


async def test_fresh_db_has_last_touched_on_every_baseline_table(tmp_path):
    async with open_db(str(tmp_path)) as conn:
        for table in _V9_TABLES_AND_BACKFILL_SOURCE:
            assert "last_touched" in await _columns(conn, table)


async def test_reopening_a_v9_migrated_db_is_idempotent(tmp_path):
    # Re-running the v8->v9 ALTER/backfill guard on an already-v9 DB must not
    # error or double-add the column.
    root = str(tmp_path)
    async with open_db(root):  # first open -> fresh v9 DB
        pass
    async with open_db(root) as conn:  # second open re-runs the migration guard
        cols = await _columns(conn, "baseline_counts")
    assert cols.count("last_touched") == 1


# --- v14 -> v15: EffectSet audit-row fields (#556) --------------------------

_V15_EFFECTS_COLUMNS = (
    "effects_file_count",
    "effects_dir_count",
    "effects_capped",
    "effects_hits_git",
    "effects_hits_outside_repo",
    "effects_digest_fp",
)


async def test_migration_adds_effects_columns_without_losing_rows(tmp_path):
    # Hand-build a v14-shaped decisions table (pre-#556): no effects_* columns,
    # one existing row with real data.
    path = db_path(str(tmp_path))
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = await aiosqlite.connect(str(path))
    await conn.executescript(
        """
        CREATE TABLE schema_version (version INTEGER NOT NULL);
        INSERT INTO schema_version (version) VALUES (14);
        CREATE TABLE decisions (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            ts                TEXT NOT NULL,
            action_id         TEXT NOT NULL,
            agent_role        TEXT,
            action_type       TEXT,
            target_path_class TEXT,
            risk              TEXT,
            source_context    TEXT,
            final_verdict     TEXT NOT NULL,
            decided_layer     TEXT,
            reason_codes_json TEXT,
            auth_required     INTEGER NOT NULL DEFAULT 0,
            auth_result       TEXT,
            elevation_id      TEXT,
            entity_id         TEXT,
            session_id        TEXT
        );
        INSERT INTO decisions (ts, action_id, final_verdict)
            VALUES ('2026-01-01T00:00:00+00:00', 'legacy-action', 'PASS');
        """
    )
    await conn.commit()
    await conn.close()

    # Opening through Doberman triggers the additive migration.
    async with open_db(str(tmp_path)) as conn:
        cols = await _columns(conn, "decisions")
        for column in _V15_EFFECTS_COLUMNS:
            assert column in cols
        # Existing row survived, and the new columns read back NULL (no
        # preview existed pre-migration) rather than a fabricated 0/False.
        async with conn.execute(
            "SELECT action_id, effects_file_count, effects_capped, effects_digest_fp "
            "FROM decisions WHERE action_id = 'legacy-action'"
        ) as cur:
            row = await cur.fetchone()
    assert row[0] == "legacy-action"
    assert row[1] is None
    assert row[2] is None
    assert row[3] is None


async def test_fresh_db_has_effects_columns_on_decisions(tmp_path):
    async with open_db(str(tmp_path)) as conn:
        cols = await _columns(conn, "decisions")
    for column in _V15_EFFECTS_COLUMNS:
        assert column in cols


async def test_reopening_a_v15_migrated_db_is_idempotent(tmp_path):
    # Re-running the v14->v15 ALTER guard on an already-v15 DB must not error
    # or double-add a column.
    root = str(tmp_path)
    async with open_db(root):  # first open -> fresh v15 DB
        pass
    async with open_db(root) as conn:  # second open re-runs the migration guard
        cols = await _columns(conn, "decisions")
    assert cols.count("effects_file_count") == 1


async def test_migration_tolerates_a_racing_process_adding_a_column_first(tmp_path):
    # Review fix (Minor): two processes opening the same v14 DB can race the
    # v14->v15 ALTER block. Simulate the loser's view by hand-adding one of the
    # six new columns (not the sentinel `effects_file_count`, so the guard
    # still enters the loop) before this process's own migration runs.
    path = db_path(str(tmp_path))
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = await aiosqlite.connect(str(path))
    await conn.executescript(
        """
        CREATE TABLE schema_version (version INTEGER NOT NULL);
        INSERT INTO schema_version (version) VALUES (14);
        CREATE TABLE decisions (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            ts                TEXT NOT NULL,
            action_id         TEXT NOT NULL,
            agent_role        TEXT,
            action_type       TEXT,
            target_path_class TEXT,
            risk              TEXT,
            source_context    TEXT,
            final_verdict     TEXT NOT NULL,
            decided_layer     TEXT,
            reason_codes_json TEXT,
            auth_required     INTEGER NOT NULL DEFAULT 0,
            auth_result       TEXT,
            elevation_id      TEXT,
            entity_id         TEXT,
            session_id        TEXT
        );
        """
    )
    await conn.execute("ALTER TABLE decisions ADD COLUMN effects_capped INTEGER")
    await conn.commit()
    await conn.close()

    async with open_db(str(tmp_path)) as conn:  # must not raise OperationalError
        cols = await _columns(conn, "decisions")
        for column in _V15_EFFECTS_COLUMNS:
            assert column in cols
        async with conn.execute("SELECT version FROM schema_version") as cur:
            versions = [row[0] for row in await cur.fetchall()]
    assert versions == [SCHEMA_VERSION]


# --- _add_column_if_missing itself (direct unit test, review fix for #619) -


async def test_add_column_if_missing_returns_true_then_false_then_reraises(tmp_path):
    # For a single-column ALTER (unlike the v14->v15 six-column loop),
    # _migrate_legacy's own "is this column already there" guard short-circuits
    # before _add_column_if_missing ever runs once the column is present, so
    # no _migrate_legacy-shaped test can reach the helper's except-branch.
    # Exercise the helper directly instead: first call adds the column and
    # returns True; a second call with the same column_def hits sqlite's
    # "duplicate column name" and returns False without raising; a genuinely
    # different OperationalError (ALTER against a table that doesn't exist)
    # still re-raises.
    path = db_path(str(tmp_path))
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = await aiosqlite.connect(str(path))
    await conn.execute("CREATE TABLE widgets (id INTEGER PRIMARY KEY)")
    await conn.commit()

    assert await _add_column_if_missing(conn, "widgets", "name TEXT") is True
    assert "name" in await _columns(conn, "widgets")

    assert await _add_column_if_missing(conn, "widgets", "name TEXT") is False

    with pytest.raises(sqlite3.OperationalError):
        await _add_column_if_missing(conn, "no_such_table", "name TEXT")

    await conn.close()


# --- v2 -> v3: decisions gain `entity_id` (oldest guarded ALTER) -----------


async def test_migration_tolerates_entity_id_already_present(tmp_path):
    # NOT a race-branch test (that would require reaching _add_column_if_missing
    # with the column already present, but _migrate_legacy's own presence-check
    # short-circuits first for this single-column ALTER — see
    # test_add_column_if_missing_returns_true_then_false_then_reraises above for
    # direct coverage of the helper's guard). This test instead confirms the
    # ordinary migration path: a v2-shaped decisions table (entity_id already
    # in the CREATE, as a hand-built fixture would look after any prior
    # migration) plus one existing row still opens cleanly, migrates to
    # SCHEMA_VERSION, and keeps its data.
    path = db_path(str(tmp_path))
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = await aiosqlite.connect(str(path))
    await conn.executescript(
        """
        CREATE TABLE schema_version (version INTEGER NOT NULL);
        INSERT INTO schema_version (version) VALUES (2);
        CREATE TABLE decisions (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            ts                TEXT NOT NULL,
            action_id         TEXT NOT NULL,
            agent_role        TEXT,
            action_type       TEXT,
            target_path_class TEXT,
            risk              TEXT,
            source_context    TEXT,
            final_verdict     TEXT NOT NULL,
            decided_layer     TEXT,
            reason_codes_json TEXT,
            auth_required     INTEGER NOT NULL DEFAULT 0,
            auth_result       TEXT,
            elevation_id      TEXT,
            entity_id         TEXT
        );
        INSERT INTO decisions (ts, action_id, final_verdict)
            VALUES ('2026-01-01T00:00:00+00:00', 'legacy-action', 'PASS');
        """
    )
    await conn.commit()
    await conn.close()

    async with open_db(str(tmp_path)) as conn:  # must not raise OperationalError
        cols = await _columns(conn, "decisions")
        assert "entity_id" in cols
        assert "session_id" in cols  # later additive ALTERs still run too
        async with conn.execute(
            "SELECT action_id FROM decisions WHERE action_id = 'legacy-action'"
        ) as cur:
            row = await cur.fetchone()
        assert row[0] == "legacy-action"  # existing row survived
        async with conn.execute("SELECT version FROM schema_version") as cur:
            versions = [r[0] for r in await cur.fetchall()]
    assert versions == [SCHEMA_VERSION]


def test_db_file_is_owner_only(tmp_path):
    async def _create():
        async with open_db(str(tmp_path)):
            pass

    asyncio.run(_create())
    path = db_path(str(tmp_path))
    assert path.exists()
    if os.name != "nt":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


async def test_reopen_at_current_version_skips_the_migration(tmp_path, monkeypatch):
    # Every open used to re-run the whole migration (legacy probes, the full
    # CREATE script, a committed version rewrite) — ~11 opens per decided
    # action, each paying an fsync; on the Windows CI leg that made three
    # integration tests take 180-200 s. A DB already at SCHEMA_VERSION needs
    # none of it; anything else (fresh, older, no version table) still does.
    from doberman.storage import db as db_module

    calls: list[int] = []
    real = db_module._migrate_legacy

    async def counting(conn):
        calls.append(1)
        await real(conn)

    monkeypatch.setattr(db_module, "_migrate_legacy", counting)
    async with open_db(str(tmp_path)):
        pass
    assert calls == [1]  # fresh DB: migrated once
    async with open_db(str(tmp_path)) as conn:
        async with conn.execute("SELECT version FROM schema_version") as cur:
            assert [r[0] for r in await cur.fetchall()] == [SCHEMA_VERSION]
    assert calls == [1]  # current DB: nothing to migrate

    async with aiosqlite.connect(str(db_path(str(tmp_path)))) as conn:
        await conn.execute("UPDATE schema_version SET version = ?", (SCHEMA_VERSION - 1,))
        await conn.commit()
    async with open_db(str(tmp_path)):
        pass
    assert calls == [1, 1]  # older DB: migrated again


def test_schema_text_change_requires_a_version_bump():
    # open_db() migrates only when the version row is stale, so a DB already
    # at SCHEMA_VERSION never sees a new table added to _SCHEMA unless the
    # version moves too. Editing _SCHEMA: bump SCHEMA_VERSION, then update both
    # literals here.
    import hashlib

    from doberman.storage.db import _SCHEMA

    assert SCHEMA_VERSION == 17
    assert hashlib.sha256(_SCHEMA.encode()).hexdigest()[:16] == "7acc17c533b1f2de"

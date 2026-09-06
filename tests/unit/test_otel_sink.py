"""
tests/unit/test_otel_sink.py
────────────────────────────
Tests for OtelAuditSink (Issue #245).

Fixtures are shaped on the output of ``storage.log.build_record()`` — the real
producer — so that a field rename in log.py fails these tests rather than
silently emptying the export.

build_record() emits:
    ts, action_id, agent_role, action_type, target_path_class, risk,
    source_context, final_verdict, decided_layer, reason_codes,
    auth_required, auth_result, elevation_id, entity_id, session_id,
    effects_file_count, effects_dir_count, effects_capped, effects_hits_git,
    effects_hits_outside_repo, effects_digest_fp

_ALLOWED_FIELDS selects the redaction-safe exportable subset:
    ts, action_type, risk, final_verdict, decided_layer,
    reason_codes, auth_result, session_id
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import yaml

from doberman.storage.otel_sink import (
    _ALLOWED_FIELDS,
    OtelAuditSink,
    _build_otlp_payload,
    _validate_endpoint,
)

# ── fixtures shaped on the real build_record() output ────────────────────────


def _build_record(**overrides: Any) -> dict[str, Any]:
    """
    Return a dict with exactly the shape build_record() in storage/log.py
    produces.  Tests must use this helper so that a future field rename in
    log.py breaks the tests here instead of silently emptying the export.

    Non-exportable fields (action_id, agent_role, target_path_class,
    source_context, auth_required, elevation_id, entity_id, and the #556
    EffectSet fields) are included because the real producer always emits
    them — the sink must strip them.
    """
    base: dict[str, Any] = {
        # ── exported (in _ALLOWED_FIELDS) ──────────────────────────────────
        "ts": "2026-08-14T10:00:00+00:00",
        "action_type": "bash_command",
        "risk": "high",
        "final_verdict": "BLOCK",
        "decided_layer": "objective",
        "reason_codes": ["destructive_command"],
        "auth_result": None,
        "session_id": "sess-abc123",
        # ── NOT exported (must be stripped by the sink) ────────────────────
        "action_id": "act-0001",
        "agent_role": "unknown",
        "target_path_class": "*.env",
        "source_context": "direct",
        "auth_required": False,
        # #505: recorded locally, deliberately NOT exported. They are
        # redaction-safe (a closed AuthPath enum; a bool), so this is a
        # data-minimization choice rather than a redaction one — the sink ships
        # what a remote collector needs, and "who approved this" is not that.
        # Opting them in later is a one-line _ALLOWED_FIELDS change.
        "auth_path": "none",
        "human_confirmed": None,
        "elevation_id": None,
        "entity_id": None,
        "effects_file_count": None,
        "effects_dir_count": None,
        "effects_capped": None,
        "effects_hits_git": None,
        "effects_hits_outside_repo": None,
        "effects_digest_fp": None,
    }
    base.update(overrides)
    return base


# ── config helpers ────────────────────────────────────────────────────────────


def _make_config(tmp_path: Path, extra: dict | None = None) -> Path:
    policy_dir = tmp_path / ".doberman"
    policy_dir.mkdir(exist_ok=True)
    cfg: dict[str, Any] = {"endpoint": "https://otel-collector.example.com:4318"}
    if extra:
        cfg.update(extra)
    (policy_dir / "audit_otel.yaml").write_text(yaml.dump(cfg))
    return policy_dir


# ── 1. emit() never blocks or raises ─────────────────────────────────────────


class TestEmitNonBlocking:
    def test_emit_returns_immediately_without_posting(self, tmp_path: Path) -> None:
        _make_config(tmp_path)
        sink = OtelAuditSink.from_repo(str(tmp_path))
        post_unblocked = threading.Event()
        original_post = sink._post

        def slow_post(record: dict) -> None:
            post_unblocked.wait(timeout=5)
            original_post(record)

        assert sink._worker_thread is not None
        sink._post = slow_post  # type: ignore[method-assign]

        t0 = time.monotonic()
        sink.emit(_build_record())
        elapsed = time.monotonic() - t0

        assert elapsed < 0.5, f"emit() took {elapsed:.3f}s — it is blocking"
        post_unblocked.set()
        sink.close()

    def test_emit_does_not_raise_on_wedged_endpoint(self, tmp_path: Path) -> None:
        _make_config(tmp_path)
        sink = OtelAuditSink.from_repo(str(tmp_path))
        assert sink._worker_thread is not None

        def always_raise(_: dict) -> None:
            raise OSError("connection refused")

        sink._post = always_raise  # type: ignore[method-assign]
        for _ in range(5):
            sink.emit(_build_record())
        sink.close()

    def test_emit_never_raises_on_exception_in_worker(self, tmp_path: Path) -> None:
        _make_config(tmp_path)
        sink = OtelAuditSink.from_repo(str(tmp_path))
        assert sink._worker_thread is not None
        sink._post = MagicMock(side_effect=RuntimeError("boom"))  # type: ignore[method-assign]
        try:
            sink.emit(_build_record())
        except Exception as exc:  # noqa: BLE001
            pytest.fail(f"emit() raised: {exc}")
        sink.close()


# ── 2. Queue overflow drops-and-counts ────────────────────────────────────────


class TestQueueOverflow:
    def test_overflow_drops_oldest_and_counts(self, tmp_path: Path) -> None:
        _make_config(tmp_path, extra={"queue_max": 3})
        sink = OtelAuditSink.from_repo(str(tmp_path))
        pause = threading.Event()
        original_post = sink._post

        def blocking_post(record: dict) -> None:
            pause.wait(timeout=10)
            original_post(record)

        assert sink._worker_thread is not None
        sink._post = blocking_post  # type: ignore[method-assign]

        for i in range(3):
            sink.emit(_build_record(session_id=f"sess-{i}"))
        sink.emit(_build_record(session_id="sess-overflow"))

        assert sink.drops >= 1
        pause.set()
        sink.close()

    def test_queue_never_grows_beyond_max(self, tmp_path: Path) -> None:
        max_q = 10
        _make_config(tmp_path, extra={"queue_max": max_q})
        sink = OtelAuditSink.from_repo(str(tmp_path))
        pause = threading.Event()
        original_post = sink._post

        def blocking_post(r: dict) -> None:
            pause.wait(timeout=10)
            original_post(r)

        assert sink._worker_thread is not None
        sink._post = blocking_post  # type: ignore[method-assign]

        for i in range(max_q * 3):
            sink.emit(_build_record(session_id=f"s-{i}"))

        assert sink._queue.qsize() <= max_q
        pause.set()
        sink.close()


# ── 3. Allowlist — only real build_record() fields are exported ───────────────


class TestFieldAllowlist:
    """
    These tests are the ones the reviewer flagged as the critical fix.
    Fixtures use _build_record() (real producer shape) not hand-built dicts.
    """

    def test_non_exportable_fields_are_stripped(self, tmp_path: Path) -> None:
        """Fields present in build_record() but NOT in _ALLOWED_FIELDS must be stripped."""
        _make_config(tmp_path)
        sink = OtelAuditSink.from_repo(str(tmp_path))
        captured: list[dict] = []
        sink._post = lambda r: captured.append(r)  # type: ignore[method-assign]

        # Full build_record() shape — non-exportable fields included
        sink.emit(_build_record())
        time.sleep(0.1)

        assert len(captured) == 1
        exported = captured[0]

        # These fields exist in build_record() but must NOT be exported
        for bad_key in (
            "action_id",
            "agent_role",
            "target_path_class",
            "source_context",
            "auth_required",
            "elevation_id",
            "entity_id",
        ):
            assert bad_key not in exported, (
                f"Field '{bad_key}' from build_record() leaked into OTel export"
            )
        sink.close()

    def test_all_allowed_fields_pass_through(self, tmp_path: Path) -> None:
        """Every field in _ALLOWED_FIELDS that build_record() emits must survive."""
        _make_config(tmp_path)
        sink = OtelAuditSink.from_repo(str(tmp_path))
        captured: list[dict] = []
        sink._post = lambda r: captured.append(r)  # type: ignore[method-assign]

        record = _build_record()
        sink.emit(record)
        time.sleep(0.1)

        assert captured
        exported = captured[0]
        for field in _ALLOWED_FIELDS:
            if field in record:
                assert field in exported, (
                    f"Allowed field '{field}' was stripped — is it still in build_record()?"
                )
        sink.close()

    def test_sink_adds_no_extra_fields(self, tmp_path: Path) -> None:
        """The sink must not inject fields the producer didn't emit."""
        _make_config(tmp_path)
        sink = OtelAuditSink.from_repo(str(tmp_path))
        captured: list[dict] = []
        sink._post = lambda r: captured.append(r)  # type: ignore[method-assign]

        sink.emit(_build_record())
        time.sleep(0.1)

        for key in captured[0]:
            assert key in _ALLOWED_FIELDS, (
                f"Sink injected field '{key}' that was not in the producer record"
            )
        sink.close()

    def test_old_field_names_are_gone(self, tmp_path: Path) -> None:
        """
        The original wrong field names (timestamp, verdict, tool, explanation)
        must not appear in _ALLOWED_FIELDS — they don't exist in build_record().
        """
        stale_names = {"timestamp", "verdict", "tool", "explanation"}
        overlap = stale_names & _ALLOWED_FIELDS
        assert not overlap, (
            f"_ALLOWED_FIELDS still contains stale field names: {overlap}. "
            "These don't exist in build_record() and would silently empty the export."
        )

    def test_allowed_fields_are_subset_of_build_record_keys(self) -> None:
        """Every name in _ALLOWED_FIELDS must exist as a key in the REAL
        build_record() output — asserted against storage.log.build_record()
        itself, not this file's _build_record() mirror, so a field rename in
        log.py fails here instead of silently emptying the export."""
        from datetime import datetime, timezone

        from doberman.engine.decision_engine import PASS_STUB, decide
        from doberman.models import EvalContext
        from doberman.proxy.normalize import normalize
        from doberman.storage.log import build_record

        action = normalize("file_write", {"path": "notes.txt"}, {})
        decision = decide(action, objective=PASS_STUB, subjective=PASS_STUB, ctx=EvalContext())
        real_record = build_record(
            decision,
            action,
            auth_result=None,
            elevation_id=None,
            now=datetime.now(timezone.utc),
            session_id="sess-abc123",
        )
        unknown = _ALLOWED_FIELDS - set(real_record.keys())
        assert not unknown, (
            f"_ALLOWED_FIELDS contains keys not in build_record(): {unknown}. "
            "These will always be absent from exported records."
        )
        # And this file's fixture must stay in lock-step with the real producer,
        # or every other test here is validating a shape production never emits.
        assert set(_build_record().keys()) == set(real_record.keys()), (
            "_build_record() in this file has drifted from storage.log.build_record()"
        )


# ── 4. Absent config → inert ──────────────────────────────────────────────────


class TestAbsentConfig:
    def test_no_config_means_inert(self, tmp_path: Path) -> None:
        (tmp_path / ".doberman").mkdir()
        sink = OtelAuditSink.from_repo(str(tmp_path))
        assert not sink.is_active
        assert sink._worker_thread is None

    def test_emit_on_inert_sink_is_noop(self, tmp_path: Path) -> None:
        (tmp_path / ".doberman").mkdir()
        sink = OtelAuditSink.from_repo(str(tmp_path))
        with patch("urllib.request.urlopen") as mock_open:
            sink.emit(_build_record())
            mock_open.assert_not_called()

    def test_malformed_config_means_inert(self, tmp_path: Path) -> None:
        policy_dir = tmp_path / ".doberman"
        policy_dir.mkdir()
        (policy_dir / "audit_otel.yaml").write_text("not: a: valid: structure: [")
        sink = OtelAuditSink.from_repo(str(tmp_path))
        assert not sink.is_active

    def test_missing_endpoint_key_means_inert(self, tmp_path: Path) -> None:
        policy_dir = tmp_path / ".doberman"
        policy_dir.mkdir()
        (policy_dir / "audit_otel.yaml").write_text(yaml.dump({"auth_env": "TOKEN"}))
        sink = OtelAuditSink.from_repo(str(tmp_path))
        assert not sink.is_active

    def test_nonexistent_policy_dir_means_inert(self, tmp_path: Path) -> None:
        sink = OtelAuditSink.from_repo(str(tmp_path / "does_not_exist"))
        assert not sink.is_active


# ── 5. OTLP payload shape ─────────────────────────────────────────────────────


class TestOtlpPayload:
    def test_payload_is_valid_json(self) -> None:
        assert "resourceLogs" in json.loads(_build_otlp_payload(_build_record()))

    def test_payload_contains_service_name(self) -> None:
        payload = json.loads(_build_otlp_payload(_build_record()))
        attrs = payload["resourceLogs"][0]["resource"]["attributes"]
        svc = next((a for a in attrs if a["key"] == "service.name"), None)
        assert svc is not None
        assert svc["value"]["stringValue"] == "doberman"

    def test_payload_strips_non_exportable_fields(self) -> None:
        """OTLP body must not contain fields outside _ALLOWED_FIELDS."""
        record = _build_record()
        payload = json.loads(_build_otlp_payload(record))
        body = json.loads(
            payload["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]["body"]["stringValue"]
        )
        for bad_key in ("action_id", "agent_role", "target_path_class", "auth_required"):
            assert bad_key not in body, f"Non-exportable field '{bad_key}' found in OTLP body"

    def test_payload_contains_allowed_fields(self) -> None:
        record = _build_record()
        payload = json.loads(_build_otlp_payload(record))
        body = json.loads(
            payload["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]["body"]["stringValue"]
        )
        for field in _ALLOWED_FIELDS:
            if field in record and field != "ts":
                assert field in body, f"Allowed field '{field}' missing from OTLP body"

    def test_payload_scope_name(self) -> None:
        payload = json.loads(_build_otlp_payload(_build_record()))
        assert payload["resourceLogs"][0]["scopeLogs"][0]["scope"]["name"] == "doberman.audit"


# ── 6. Auth token ─────────────────────────────────────────────────────────────


class TestAuthToken:
    def test_auth_header_set_from_env_var(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("MY_OTEL_TOKEN", "Bearer secret-token-xyz")
        _make_config(tmp_path, extra={"auth_env": "MY_OTEL_TOKEN"})
        sink = OtelAuditSink.from_repo(str(tmp_path))
        captured_headers: list[dict] = []

        def fake_urlopen(req: Any, timeout: float) -> Any:
            captured_headers.append(dict(req.headers))
            m = MagicMock()
            m.__enter__ = lambda s: s
            m.__exit__ = MagicMock(return_value=False)
            m.read.return_value = b""
            return m

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            assert sink._worker_thread is not None
            sink._post(_build_record())

        assert any(
            "authorization" in {k.lower(): v for k, v in h.items()} for h in captured_headers
        )
        sink.close()

    def test_token_never_logged(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        secret_val = "super-secret-bearer-token-must-not-appear-in-logs"  # noqa: S105
        monkeypatch.setenv("OTEL_SECRET_TOKEN", f"Bearer {secret_val}")
        _make_config(tmp_path, extra={"auth_env": "OTEL_SECRET_TOKEN"})
        sink = OtelAuditSink.from_repo(str(tmp_path))
        with patch("urllib.request.urlopen", side_effect=OSError("forced error")):
            try:
                sink._post(_build_record())
            except OSError:
                pass
        for rec in caplog.records:
            assert secret_val not in rec.getMessage()
        sink.close()


# ── 7. Lifecycle ──────────────────────────────────────────────────────────────


class TestLifecycle:
    def test_close_makes_emit_noop(self, tmp_path: Path) -> None:
        _make_config(tmp_path)
        sink = OtelAuditSink.from_repo(str(tmp_path))
        captured: list[dict] = []
        sink._post = lambda r: captured.append(r)  # type: ignore[method-assign]
        sink.close()
        sink.emit(_build_record())
        time.sleep(0.1)
        assert captured == []

    def test_close_stops_worker(self, tmp_path: Path) -> None:
        _make_config(tmp_path)
        sink = OtelAuditSink.from_repo(str(tmp_path))
        assert sink._worker_thread is not None
        sink.close()
        sink._worker_thread.join(timeout=2.0)
        assert not sink._worker_thread.is_alive()

    def test_close_drains_pending_records(self, tmp_path: Path) -> None:
        _make_config(tmp_path)
        sink = OtelAuditSink.from_repo(str(tmp_path))
        delivered: list[dict] = []
        gate = threading.Event()

        def gated_post(record: dict) -> None:
            gate.wait(timeout=5)
            delivered.append(record)

        sink._post = gated_post  # type: ignore[method-assign]
        sink.emit(_build_record(session_id="drain-me"))
        gate.set()
        sink.close(drain_timeout_s=3.0)
        assert len(delivered) >= 1

    def test_close_is_idempotent(self, tmp_path: Path) -> None:
        _make_config(tmp_path)
        sink = OtelAuditSink.from_repo(str(tmp_path))
        sink.close()
        sink.close()

    def test_close_respects_timeout(self, tmp_path: Path) -> None:
        _make_config(tmp_path)
        sink = OtelAuditSink.from_repo(str(tmp_path))
        stuck = threading.Event()
        sink._post = lambda _r: stuck.wait(timeout=60)  # type: ignore[method-assign]
        sink.emit(_build_record())
        t0 = time.monotonic()
        sink.close(drain_timeout_s=0.3)
        elapsed = time.monotonic() - t0
        assert elapsed < 2.0
        stuck.set()

    def test_emit_close_race_no_stranded_record(self, tmp_path: Path) -> None:
        _make_config(tmp_path)
        sink = OtelAuditSink.from_repo(str(tmp_path))
        captured: list[dict] = []
        emit_inside_lock = threading.Event()
        close_called = threading.Event()
        original_put = sink._queue.put_nowait

        def blocking_put(item: dict) -> None:
            emit_inside_lock.set()
            close_called.wait(timeout=2)
            original_put(item)

        sink._queue.put_nowait = blocking_put  # type: ignore[method-assign]
        sink._post = lambda r: captured.append(r)  # type: ignore[method-assign]

        def do_emit() -> None:
            sink.emit(_build_record(session_id="race-record"))

        t = threading.Thread(target=do_emit)
        t.start()
        emit_inside_lock.wait(timeout=2)
        close_called.set()
        sink.close(drain_timeout_s=3.0)
        t.join(timeout=2)
        assert len(captured) == 1


# ── 8. Endpoint validation ────────────────────────────────────────────────────


class TestEndpointValidation:
    def test_https_accepted(self) -> None:
        assert _validate_endpoint("https://collector.example.com:4318") is not None

    def test_http_accepted(self) -> None:
        assert _validate_endpoint("http://collector.internal:4318") is not None

    def test_file_scheme_rejected(self) -> None:
        assert _validate_endpoint("file:///etc/passwd") is None

    def test_ftp_scheme_rejected(self) -> None:
        assert _validate_endpoint("ftp://collector.example.com") is None

    def test_localhost_rejected(self) -> None:
        assert _validate_endpoint("https://localhost:4318") is None

    def test_127_0_0_1_rejected(self) -> None:
        assert _validate_endpoint("https://127.0.0.1:4318") is None

    def test_ipv6_loopback_rejected(self) -> None:
        assert _validate_endpoint("https://[::1]:4318") is None

    def test_loopback_config_makes_sink_inert(self, tmp_path: Path) -> None:
        policy_dir = tmp_path / ".doberman"
        policy_dir.mkdir()
        (policy_dir / "audit_otel.yaml").write_text(
            yaml.dump({"endpoint": "https://localhost:4318"})
        )
        sink = OtelAuditSink.from_repo(str(tmp_path))
        assert not sink.is_active


# ── 9. Secret never exported ──────────────────────────────────────────────────


class TestSecretNeverExported:
    """
    Use a build_record()-shaped record with a synthetic secret in a
    non-exportable field to confirm it never reaches the OTLP payload.
    """

    SYNTHETIC_SECRET = "AKIAIOSFODNN7SYNTHETIC"  # noqa: S105

    def test_not_in_otlp_body(self) -> None:
        # Inject secret into a non-exportable field (agent_role)
        record = _build_record(agent_role=self.SYNTHETIC_SECRET)
        payload = _build_otlp_payload(record)
        assert self.SYNTHETIC_SECRET not in payload.decode()

    def test_not_in_emitted_record(self, tmp_path: Path) -> None:
        _make_config(tmp_path)
        sink = OtelAuditSink.from_repo(str(tmp_path))
        captured_payloads: list[bytes] = []
        sink._post = lambda r: captured_payloads.append(json.dumps(r).encode())  # type: ignore[method-assign]

        sink.emit(_build_record(agent_role=self.SYNTHETIC_SECRET))
        time.sleep(0.1)

        for payload in captured_payloads:
            assert self.SYNTHETIC_SECRET not in payload.decode()
        sink.close()


# ── 10. Wiring — emit_to_sinks() reaches OTel sink ───────────────────────────


class TestWiring:
    def test_emit_to_sinks_reaches_otel_sink(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from doberman.storage import otel_sink as otel_module
        from doberman.storage.sinks import emit_to_sinks

        _make_config(tmp_path)
        sink = OtelAuditSink.from_repo(str(tmp_path))
        delivered: list[dict] = []
        sink._post = lambda r: delivered.append(r)  # type: ignore[method-assign]

        original_sinks = dict(otel_module._otel_sinks)
        monkeypatch.setattr("doberman.engine.registry.discover_audit_sinks", list)

        from doberman.storage import sinks as sinks_module
        from doberman.storage.sinks import WebhookAuditSink

        monkeypatch.setattr(
            sinks_module, "_get_builtin_webhook_sink", lambda *a, **kw: WebhookAuditSink(None)
        )
        monkeypatch.setattr(sinks_module, "_get_builtin_otel_sink", lambda *a, **kw: sink)

        # Use a real build_record()-shaped record
        record = _build_record()
        emit_to_sinks(record, repo_root=str(tmp_path))
        time.sleep(0.15)

        assert len(delivered) == 1, "OTel sink did not receive record via emit_to_sinks()"

        # Confirm only allowed fields arrived
        exported = delivered[0]
        for bad_key in ("action_id", "agent_role", "target_path_class", "auth_required"):
            assert bad_key not in exported, f"Non-exportable field '{bad_key}' leaked"
        for field in _ALLOWED_FIELDS:
            if field in record:
                assert field in exported, f"Allowed field '{field}' missing from delivered record"

        otel_module._otel_sinks.clear()
        otel_module._otel_sinks.update(original_sinks)
        sink.close()

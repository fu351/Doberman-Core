"""Unit tests for Feature HK.3 — doberman install-hooks / uninstall-hooks.

Covers:
- Pure functions in ``doberman.hosthooks.install`` (merge, remove, resolve, load, write).
- CLI commands ``install-hooks`` and ``uninstall-hooks`` via Typer's CliRunner.

All tests use ``tmp_path``; no real ``~/.claude`` directory is ever touched.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

import doberman.cli.main as cli_module
from doberman.auth.challenge import DEFAULT_CHALLENGE_TIMEOUT_S
from doberman.hosthooks.install import (
    DASHBOARD_COMMAND,
    HOOK_TIMEOUT_S,
    POST_COMMAND,
    POST_MATCHER,
    PRE_COMMAND,
    PRE_MATCHER,
    _is_doberman_group,
    load_settings,
    merge_doberman_hooks,
    remove_doberman_hooks,
    resolve_settings_path,
    write_settings,
)

runner = CliRunner()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _count_doberman(settings: dict, event_key: str) -> int:
    """Count Doberman-owned groups in a hook event list."""
    return sum(1 for g in settings.get("hooks", {}).get(event_key, []) if _is_doberman_group(g))


def _pre_commands(settings: dict) -> list[str]:
    return [
        h["command"]
        for g in settings.get("hooks", {}).get("PreToolUse", [])
        for h in g.get("hooks", [])
    ]


def _post_commands(settings: dict) -> list[str]:
    return [
        h["command"]
        for g in settings.get("hooks", {}).get("PostToolUse", [])
        for h in g.get("hooks", [])
    ]


def _session_start_commands(settings: dict) -> list[str]:
    return [
        h["command"]
        for g in settings.get("hooks", {}).get("SessionStart", [])
        for h in g.get("hooks", [])
    ]


# ---------------------------------------------------------------------------
# merge_doberman_hooks
# ---------------------------------------------------------------------------


class TestMergeDobermanHooks:
    def test_empty_settings_produces_both_hook_events(self):
        result = merge_doberman_hooks({})
        assert "hooks" in result
        assert PRE_COMMAND in _pre_commands(result)
        assert POST_COMMAND in _post_commands(result)

    def test_session_start_session_summary_entry_added(self):
        result = merge_doberman_hooks({})
        assert _session_start_commands(result) == ["doberman session-summary"]

    def test_session_start_idempotent_no_duplicates(self):
        once = merge_doberman_hooks({})
        twice = merge_doberman_hooks(once)
        assert _count_doberman(twice, "SessionStart") == 1
        assert _session_start_commands(twice) == [DASHBOARD_COMMAND]

    def test_pre_matcher_is_correct(self):
        result = merge_doberman_hooks({})
        pre_groups = result["hooks"]["PreToolUse"]
        doberman_groups = [g for g in pre_groups if _is_doberman_group(g)]
        assert len(doberman_groups) == 1
        assert doberman_groups[0]["matcher"] == PRE_MATCHER

    def test_post_matcher_is_correct(self):
        result = merge_doberman_hooks({})
        post_groups = result["hooks"]["PostToolUse"]
        doberman_groups = [g for g in post_groups if _is_doberman_group(g)]
        assert len(doberman_groups) == 1
        assert doberman_groups[0]["matcher"] == POST_MATCHER

    def test_preserves_existing_unrelated_key_and_hook(self):
        existing = {
            "model": "x",
            "hooks": {
                "PreToolUse": [
                    {"matcher": "Foo", "hooks": [{"type": "command", "command": "other"}]}
                ]
            },
        }
        result = merge_doberman_hooks(existing)
        # Top-level key survives.
        assert result["model"] == "x"
        # Existing non-Doberman PreToolUse entry survives.
        pre = result["hooks"]["PreToolUse"]
        non_dob = [g for g in pre if not _is_doberman_group(g)]
        assert len(non_dob) == 1
        assert non_dob[0]["matcher"] == "Foo"
        assert non_dob[0]["hooks"][0]["command"] == "other"
        # Doberman entry was added.
        assert PRE_COMMAND in _pre_commands(result)

    def test_idempotent_no_duplicates(self):
        once = merge_doberman_hooks({})
        twice = merge_doberman_hooks(once)
        # Exactly one Doberman group per event after two merges.
        assert _count_doberman(twice, "PreToolUse") == 1
        assert _count_doberman(twice, "PostToolUse") == 1

    def test_does_not_mutate_input(self):
        original: dict = {}
        merge_doberman_hooks(original)
        assert original == {}

    def test_does_not_mutate_nested_input(self):
        existing = {"hooks": {"PreToolUse": [{"matcher": "Foo", "hooks": []}]}}
        import copy

        snapshot = copy.deepcopy(existing)
        merge_doberman_hooks(existing)
        assert existing == snapshot


# ---------------------------------------------------------------------------
# HOOK_TIMEOUT_S (#658): the Claude Code hook pin must strictly outlast
# Doberman's own challenge ceiling, or a timed-out hook fails open at the
# harness before Doberman ever writes its deny.
# ---------------------------------------------------------------------------


class TestHookTimeoutPin:
    def test_pin_strictly_outlasts_the_challenge_ceiling(self):
        """Pins the RELATIONSHIP, not just a literal value: if either constant
        moves (the challenge ceiling raised, or this margin trimmed) without
        the other keeping pace, this must fail CI rather than silently
        reopening the #658 race."""
        assert HOOK_TIMEOUT_S > DEFAULT_CHALLENGE_TIMEOUT_S

    def test_both_entries_carry_the_pin(self):
        result = merge_doberman_hooks({})
        pre_group = next(g for g in result["hooks"]["PreToolUse"] if _is_doberman_group(g))
        post_group = next(g for g in result["hooks"]["PostToolUse"] if _is_doberman_group(g))
        assert pre_group["hooks"][0]["timeout"] == HOOK_TIMEOUT_S
        assert post_group["hooks"][0]["timeout"] == HOOK_TIMEOUT_S

    def test_merge_replaces_an_old_entry_with_no_timeout(self):
        """The idempotent replace in `merge_doberman_hooks` keys on the command
        string, so re-running install-hooks over a pre-#658 install (same
        matcher/command, no `timeout`) must swap in the new pinned entry
        rather than leaving the stale one or duplicating it."""
        old_settings = {
            "hooks": {
                "PreToolUse": [
                    {"matcher": PRE_MATCHER, "hooks": [{"type": "command", "command": PRE_COMMAND}]}
                ],
                "PostToolUse": [
                    {
                        "matcher": POST_MATCHER,
                        "hooks": [{"type": "command", "command": POST_COMMAND}],
                    }
                ],
            }
        }
        result = merge_doberman_hooks(old_settings)

        pre_groups = [g for g in result["hooks"]["PreToolUse"] if _is_doberman_group(g)]
        post_groups = [g for g in result["hooks"]["PostToolUse"] if _is_doberman_group(g)]
        assert len(pre_groups) == 1
        assert len(post_groups) == 1
        assert pre_groups[0]["hooks"][0]["timeout"] == HOOK_TIMEOUT_S
        assert post_groups[0]["hooks"][0]["timeout"] == HOOK_TIMEOUT_S


# ---------------------------------------------------------------------------
# remove_doberman_hooks
# ---------------------------------------------------------------------------


class TestRemoveDobermanHooks:
    def _settings_with_both_and_other(self) -> dict:
        return merge_doberman_hooks(
            {
                "model": "x",
                "hooks": {
                    "PreToolUse": [
                        {"matcher": "Foo", "hooks": [{"type": "command", "command": "other"}]}
                    ]
                },
            }
        )

    def test_removes_only_doberman_entries(self):
        settings = self._settings_with_both_and_other()
        result = remove_doberman_hooks(settings)
        # Non-Doberman PreToolUse "other" survives.
        pre = result.get("hooks", {}).get("PreToolUse", [])
        assert any(g.get("matcher") == "Foo" for g in pre)
        # Doberman entries are gone.
        assert _count_doberman(result, "PreToolUse") == 0
        assert _count_doberman(result, "PostToolUse") == 0
        assert _count_doberman(result, "SessionStart") == 0

    def test_removes_old_and_new_session_start_entries(self):
        settings = {
            "hooks": {
                "SessionStart": [
                    {"hooks": [{"type": "command", "command": "doberman dashboard"}]},
                    {"hooks": [{"type": "command", "command": "doberman session-summary"}]},
                ]
            }
        }

        result = remove_doberman_hooks(settings)

        assert "hooks" not in result

    def test_preserves_model_key(self):
        settings = self._settings_with_both_and_other()
        result = remove_doberman_hooks(settings)
        assert result["model"] == "x"

    def test_no_op_when_no_doberman_entries(self):
        settings = {"model": "y", "hooks": {"PreToolUse": []}}
        result = remove_doberman_hooks(settings)
        assert result["model"] == "y"

    def test_drops_empty_hook_event_list(self):
        settings = merge_doberman_hooks({})
        result = remove_doberman_hooks(settings)
        # Both PreToolUse and PostToolUse were only Doberman entries → entire hooks key removed.
        assert "hooks" not in result

    def test_drops_empty_hooks_dict(self):
        settings = merge_doberman_hooks({})
        result = remove_doberman_hooks(settings)
        assert "hooks" not in result

    def test_does_not_mutate_input(self):
        settings = merge_doberman_hooks({})
        import copy

        snapshot = copy.deepcopy(settings)
        remove_doberman_hooks(settings)
        assert settings == snapshot

    def test_no_op_on_empty_dict(self):
        result = remove_doberman_hooks({})
        assert result == {}


# ---------------------------------------------------------------------------
# resolve_settings_path
# ---------------------------------------------------------------------------


class TestResolveSettingsPath:
    def test_project_scope(self, tmp_path):
        p = resolve_settings_path("project", str(tmp_path))
        assert p == tmp_path / ".claude" / "settings.json"

    def test_local_scope(self, tmp_path):
        p = resolve_settings_path("local", str(tmp_path))
        assert p == tmp_path / ".claude" / "settings.local.json"

    def test_global_scope_is_home(self, tmp_path):
        p = resolve_settings_path("global", str(tmp_path))
        assert p == Path.home() / ".claude" / "settings.json"

    def test_unknown_scope_raises(self, tmp_path):
        with pytest.raises(ValueError, match="Unknown scope"):
            resolve_settings_path("invalid", str(tmp_path))


# ---------------------------------------------------------------------------
# load_settings / write_settings
# ---------------------------------------------------------------------------


class TestLoadSettings:
    def test_missing_file_returns_empty_dict(self, tmp_path):
        p = tmp_path / "nonexistent.json"
        assert load_settings(p) == {}

    def test_valid_json_file_is_parsed(self, tmp_path):
        p = tmp_path / "settings.json"
        p.write_text('{"model": "z"}', encoding="utf-8")
        assert load_settings(p) == {"model": "z"}

    def test_invalid_json_raises_value_error(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("{not: valid json}", encoding="utf-8")
        with pytest.raises(ValueError, match="Could not parse"):
            load_settings(p)


class TestWriteSettings:
    def test_creates_dot_claude_directory(self, tmp_path):
        p = tmp_path / ".claude" / "settings.json"
        write_settings(p, {"k": "v"})
        assert p.exists()

    def test_round_trips_json(self, tmp_path):
        p = tmp_path / ".claude" / "settings.json"
        data = {"hooks": {"PreToolUse": [{"matcher": "X", "hooks": []}]}}
        write_settings(p, data)
        assert json.loads(p.read_text(encoding="utf-8")) == data

    def test_trailing_newline(self, tmp_path):
        p = tmp_path / ".claude" / "settings.json"
        write_settings(p, {})
        assert p.read_text(encoding="utf-8").endswith("\n")

    def test_creates_bak_when_overwriting(self, tmp_path):
        p = tmp_path / ".claude" / "settings.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text('{"old": true}', encoding="utf-8")
        write_settings(p, {"new": True})
        bak = p.with_suffix(".json.bak")
        assert bak.exists()
        assert json.loads(bak.read_text(encoding="utf-8")) == {"old": True}

    def test_no_bak_for_new_file(self, tmp_path):
        p = tmp_path / ".claude" / "settings.json"
        write_settings(p, {"x": 1})
        bak = p.with_suffix(".json.bak")
        assert not bak.exists()


# ---------------------------------------------------------------------------
# CLI — install-hooks
# ---------------------------------------------------------------------------


class TestInstallHooksCLI:
    def test_writes_settings_json_with_both_hooks(self, tmp_path):
        result = runner.invoke(cli_module.app, ["install-hooks", "--path", str(tmp_path)])
        assert result.exit_code == 0, result.output
        settings_path = tmp_path / ".claude" / "settings.json"
        assert settings_path.exists()
        data = json.loads(settings_path.read_text(encoding="utf-8"))
        assert PRE_COMMAND in _pre_commands(data)
        assert POST_COMMAND in _post_commands(data)

    def test_dry_run_writes_nothing(self, tmp_path):
        result = runner.invoke(
            cli_module.app, ["install-hooks", "--path", str(tmp_path), "--dry-run"]
        )
        assert result.exit_code == 0, result.output
        assert "[dry-run]" in result.output
        settings_path = tmp_path / ".claude" / "settings.json"
        assert not settings_path.exists()

    def test_dry_run_output_mentions_hooks(self, tmp_path):
        result = runner.invoke(
            cli_module.app, ["install-hooks", "--path", str(tmp_path), "--dry-run"]
        )
        assert "doberman hook pre" in result.output
        assert "doberman hook post" in result.output

    def test_dry_run_shows_the_command_the_installer_writes(self, tmp_path):
        result = runner.invoke(
            cli_module.app, ["install-hooks", "--path", str(tmp_path), "--dry-run"]
        )

        assert result.exit_code == 0, result.output
        assert f"SessionStart -> {DASHBOARD_COMMAND}" in result.output
        assert "doberman dashboard" not in result.output

    def test_install_is_idempotent(self, tmp_path):
        runner.invoke(cli_module.app, ["install-hooks", "--path", str(tmp_path)])
        runner.invoke(cli_module.app, ["install-hooks", "--path", str(tmp_path)])
        settings_path = tmp_path / ".claude" / "settings.json"
        data = json.loads(settings_path.read_text(encoding="utf-8"))
        assert _count_doberman(data, "PreToolUse") == 1
        assert _count_doberman(data, "PostToolUse") == 1
        assert _count_doberman(data, "SessionStart") == 1

    def test_writes_exactly_one_session_start_dashboard_entry(self, tmp_path):
        result = runner.invoke(cli_module.app, ["install-hooks", "--path", str(tmp_path)])
        assert result.exit_code == 0, result.output
        settings_path = tmp_path / ".claude" / "settings.json"
        data = json.loads(settings_path.read_text(encoding="utf-8"))
        assert data["hooks"]["SessionStart"] == [
            {"hooks": [{"type": "command", "command": DASHBOARD_COMMAND}]}
        ]

    def test_invalid_existing_json_exits_2(self, tmp_path):
        dot_claude = tmp_path / ".claude"
        dot_claude.mkdir(parents=True)
        (dot_claude / "settings.json").write_text("{bad json}", encoding="utf-8")
        result = runner.invoke(cli_module.app, ["install-hooks", "--path", str(tmp_path)])
        assert result.exit_code == 2

    def test_output_confirms_written_path(self, tmp_path):
        result = runner.invoke(cli_module.app, ["install-hooks", "--path", str(tmp_path)])
        assert result.exit_code == 0
        assert "settings.json" in result.output

    def test_confirmation_message(self, tmp_path):
        result = runner.invoke(cli_module.app, ["install-hooks", "--path", str(tmp_path)])
        assert "Doberman will now gate" in result.output


# ---------------------------------------------------------------------------
# CLI — uninstall-hooks
# ---------------------------------------------------------------------------


class TestUninstallHooksCLI:
    def _install(self, tmp_path: Path) -> None:
        runner.invoke(cli_module.app, ["install-hooks", "--path", str(tmp_path)])

    def test_removes_doberman_hooks(self, tmp_path):
        self._install(tmp_path)
        result = runner.invoke(cli_module.app, ["uninstall-hooks", "--path", str(tmp_path)])
        assert result.exit_code == 0, result.output
        settings_path = tmp_path / ".claude" / "settings.json"
        data = json.loads(settings_path.read_text(encoding="utf-8"))
        assert _count_doberman(data, "PreToolUse") == 0
        assert _count_doberman(data, "PostToolUse") == 0

    def test_uninstall_preserves_other_hooks(self, tmp_path):
        # Manually write a settings file that has both Doberman and a foreign hook.
        settings_path = tmp_path / ".claude" / "settings.json"
        settings_path.parent.mkdir(parents=True)
        initial: dict = {
            "model": "x",
            "hooks": {
                "PreToolUse": [
                    {"matcher": "Foo", "hooks": [{"type": "command", "command": "other"}]}
                ]
            },
        }
        merged = merge_doberman_hooks(initial)
        settings_path.write_text(json.dumps(merged, indent=2) + "\n", encoding="utf-8")

        result = runner.invoke(cli_module.app, ["uninstall-hooks", "--path", str(tmp_path)])
        assert result.exit_code == 0, result.output

        data = json.loads(settings_path.read_text(encoding="utf-8"))
        assert data["model"] == "x"
        pre = data.get("hooks", {}).get("PreToolUse", [])
        assert any(g.get("matcher") == "Foo" for g in pre)
        assert _count_doberman(data, "PreToolUse") == 0

    def test_no_doberman_hooks_reports_not_found(self, tmp_path):
        result = runner.invoke(cli_module.app, ["uninstall-hooks", "--path", str(tmp_path)])
        assert result.exit_code == 0
        assert (
            "nothing to remove" in result.output.lower() or "no doberman" in result.output.lower()
        )

    def test_dry_run_writes_nothing(self, tmp_path):
        self._install(tmp_path)
        settings_path = tmp_path / ".claude" / "settings.json"
        content_before = settings_path.read_text(encoding="utf-8")
        result = runner.invoke(
            cli_module.app, ["uninstall-hooks", "--path", str(tmp_path), "--dry-run"]
        )
        assert result.exit_code == 0
        assert "[dry-run]" in result.output
        assert f"SessionStart -> {DASHBOARD_COMMAND}" in result.output
        assert "doberman dashboard" not in result.output
        assert settings_path.read_text(encoding="utf-8") == content_before

    def test_creates_bak_on_uninstall(self, tmp_path):
        self._install(tmp_path)
        settings_path = tmp_path / ".claude" / "settings.json"
        runner.invoke(cli_module.app, ["uninstall-hooks", "--path", str(tmp_path)])
        bak = settings_path.with_suffix(".json.bak")
        assert bak.exists()

    def test_invalid_existing_json_exits_2(self, tmp_path):
        dot_claude = tmp_path / ".claude"
        dot_claude.mkdir(parents=True)
        (dot_claude / "settings.json").write_text("{bad json}", encoding="utf-8")
        result = runner.invoke(cli_module.app, ["uninstall-hooks", "--path", str(tmp_path)])
        assert result.exit_code == 2

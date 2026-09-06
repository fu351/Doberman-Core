"""Idempotent install/uninstall of Doberman's Claude Code hooks into a settings.json file.

Pure functions in this module never mutate their inputs (always return new dicts),
making them straightforward to unit-test without file-system side-effects.
"""

from __future__ import annotations

import copy
import json
import shutil
from pathlib import Path
from typing import Any

from doberman.auth.challenge import DEFAULT_CHALLENGE_TIMEOUT_S

# ---------------------------------------------------------------------------
# Hook entry constants
# ---------------------------------------------------------------------------

#: Regex matcher for tools gated by the PreToolUse hook (writes, network, MCP).
PRE_MATCHER = "Bash|Edit|Write|NotebookEdit|WebFetch|WebSearch|mcp__.*"

#: Command registered as the PreToolUse hook.
PRE_COMMAND = "doberman hook pre"

#: Regex matcher for tools scanned by the PostToolUse hook (adds reads to the pre set).
POST_MATCHER = "Bash|Edit|Write|NotebookEdit|WebFetch|WebSearch|Read|Glob|Grep|mcp__.*"

#: Command registered as the PostToolUse hook.
POST_COMMAND = "doberman hook post"

#: Command registered as the SessionStart hook (prints the session summary).
DASHBOARD_COMMAND = "doberman session-summary"

#: Claude Code's per-hook timeout (seconds). Claude Code's own default is 600s,
#: and its docs say a timed-out PreToolUse hook "doesn't block the tool call" -
#: it fails OPEN, letting the call through the harness's normal permission flow.
#: Doberman's own challenge ceiling (`DEFAULT_CHALLENGE_TIMEOUT_S`) is also 600s
#: and starts a second or two later (the hook process has to start and import
#: first), so the pin here must strictly outlast it or the harness kills the
#: hook a moment before Doberman would have written its deny (#658). Mirrors
#: `install_cursor.GATE_TIMEOUT_S`, which does the same for Cursor.
HOOK_TIMEOUT_S = int(DEFAULT_CHALLENGE_TIMEOUT_S) + 60  # 660

#: Sentinel substring used to detect Doberman-owned hook entries.
_DOBERMAN_MARKER = "doberman hook "

#: SessionStart entries use a different command shape (`doberman hook `
#: doesn't match the summary commands), so they need their own markers.
_DASHBOARD_MARKER = "doberman dashboard"
_SESSION_SUMMARY_MARKER = "doberman session-summary"

_PRE_ENTRY: dict[str, Any] = {
    "matcher": PRE_MATCHER,
    "hooks": [{"type": "command", "command": PRE_COMMAND, "timeout": HOOK_TIMEOUT_S}],
}

_POST_ENTRY: dict[str, Any] = {
    "matcher": POST_MATCHER,
    "hooks": [{"type": "command", "command": POST_COMMAND, "timeout": HOOK_TIMEOUT_S}],
}

# SessionStart isn't scoped to a tool, so - unlike Pre/PostToolUse - this entry
# has no `matcher` key; it runs on every session start regardless of source.
_SESSION_START_ENTRY: dict[str, Any] = {
    "hooks": [{"type": "command", "command": DASHBOARD_COMMAND}],
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_doberman_group(group: dict[str, Any]) -> bool:
    """Return True if *any* hook command in this matcher group belongs to Doberman."""
    for h in group.get("hooks", []):
        cmd = h.get("command", "")
        if isinstance(cmd, str) and (
            _DOBERMAN_MARKER in cmd or _DASHBOARD_MARKER in cmd or _SESSION_SUMMARY_MARKER in cmd
        ):
            return True
    return False


def doberman_groups(settings: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Doberman-owned hook groups per event key (for the install manifest).

    Only groups :func:`_is_doberman_group` recognises are returned, so a foreign
    hook's command never reaches the manifest even as a fingerprint input.
    """
    hooks_section = settings.get("hooks") or {}
    out: dict[str, list[dict[str, Any]]] = {}
    for event_key, groups in hooks_section.items():
        if not isinstance(groups, list):
            continue
        ours = [g for g in groups if isinstance(g, dict) and _is_doberman_group(g)]
        if ours:
            out[event_key] = ours
    return out


# ---------------------------------------------------------------------------
# Pure merge / remove functions
# ---------------------------------------------------------------------------


def merge_doberman_hooks(settings: dict[str, Any]) -> dict[str, Any]:
    """Return a *new* settings dict with Doberman's PreToolUse and PostToolUse entries added.

    Existing non-Doberman hook entries and every other top-level key are preserved.
    **Idempotent:** if a Doberman matcher group is already present it is replaced in-place
    (same position) so that calling this function twice never creates duplicates.
    """
    result: dict[str, Any] = copy.deepcopy(settings)
    hooks: dict[str, Any] = copy.deepcopy(result.get("hooks") or {})

    for event_key, doberman_entry in (
        ("PreToolUse", _PRE_ENTRY),
        ("PostToolUse", _POST_ENTRY),
        ("SessionStart", _SESSION_START_ENTRY),
    ):
        existing: list[dict[str, Any]] = list(hooks.get(event_key) or [])
        # Remove any pre-existing Doberman group (idempotency: replace, never duplicate).
        non_doberman = [g for g in existing if not _is_doberman_group(g)]
        hooks[event_key] = [*non_doberman, copy.deepcopy(doberman_entry)]

    result["hooks"] = hooks
    return result


def remove_doberman_hooks(settings: dict[str, Any]) -> dict[str, Any]:
    """Return a *new* settings dict with Doberman's hook entries removed.

    Non-Doberman hook entries and every other top-level key are preserved.
    Empty lists are dropped; if the ``hooks`` key becomes empty it is removed too.
    Calling this on a dict that has no Doberman entries is a safe no-op.
    """
    result: dict[str, Any] = copy.deepcopy(settings)
    if "hooks" not in result:
        return result

    hooks: dict[str, Any] = copy.deepcopy(result["hooks"])
    cleaned_hooks: dict[str, Any] = {}
    for event_key, groups in hooks.items():
        if not isinstance(groups, list):
            cleaned_hooks[event_key] = groups
            continue
        kept = [g for g in groups if not _is_doberman_group(g)]
        if kept:  # drop empty lists
            cleaned_hooks[event_key] = kept

    if cleaned_hooks:
        result["hooks"] = cleaned_hooks
    else:
        del result["hooks"]  # drop empty hooks dict
    return result


# ---------------------------------------------------------------------------
# Path resolution
# ---------------------------------------------------------------------------


def hook_install_states(project_root: str) -> list[tuple[str, str, bool]]:
    """Report, for every Claude Code settings scope, whether Doberman's hooks are wired in.

    Returns one ``(scope, settings_path, installed)`` tuple per scope
    (``project`` / ``global`` / ``local`` — the same scopes ``install-hooks``
    writes to). **Never raises:** an unreadable or unparseable settings file is
    reported as *not installed* rather than crashing the caller (``status`` /
    ``doctor`` must stay read-only and never error out over a bad settings file).
    """
    states: list[tuple[str, str, bool]] = []
    for scope in ("project", "global", "local"):
        settings_path = resolve_settings_path(scope, project_root)
        installed = False
        try:
            settings = load_settings(settings_path)
            hooks_section = settings.get("hooks") or {}
            installed = any(
                _is_doberman_group(group)
                for groups in hooks_section.values()
                if isinstance(groups, list)
                for group in groups
            )
        except Exception:  # noqa: BLE001,S110 — a bad settings file must not crash the caller
            pass
        states.append((scope, str(settings_path), installed))
    return states


def resolve_settings_path(scope: str, project_root: str) -> Path:
    """Resolve the target ``settings.json`` path for the given *scope*.

    Args:
        scope: One of ``"project"`` (default), ``"global"``, or ``"local"``.
        project_root: Filesystem path to the project root (used for project/local scopes).

    Returns:
        Resolved :class:`~pathlib.Path` for the settings file.

    Raises:
        ValueError: If *scope* is not one of the three recognised values.
    """
    root = Path(project_root)
    match scope:
        case "project":
            return root / ".claude" / "settings.json"
        case "global":
            return Path.home() / ".claude" / "settings.json"
        case "local":
            return root / ".claude" / "settings.local.json"
        case _:
            raise ValueError(f"Unknown scope {scope!r}; expected 'project', 'global', or 'local'.")


# ---------------------------------------------------------------------------
# File I/O
# ---------------------------------------------------------------------------


def load_settings(path: Path) -> dict[str, Any]:
    """Load and parse the JSON settings file at *path*.

    Returns an empty dict if the file does not exist.

    Raises:
        ValueError: If the file exists but cannot be parsed as valid JSON.
    """
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Could not parse {path} as JSON: {exc}.  "
            "Fix or remove the file before running install-hooks."
        ) from exc
    if not isinstance(data, dict):
        raise ValueError(
            f"{path} is valid JSON but not a settings object (got {type(data).__name__}).  "
            "Fix or remove the file before running install-hooks."
        )
    return data


def write_settings(path: Path, settings: dict[str, Any]) -> None:
    """Write *settings* as pretty JSON to *path*.

    Side-effects (in order):
    1. Ensures the parent ``.claude/`` directory exists.
    2. If the file already exists, copies it to ``<path>.bak`` before overwriting.
    3. Writes the new content with ``indent=2`` and a trailing newline.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        shutil.copy2(path, path.with_suffix(path.suffix + ".bak"))
    path.write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")

"""Health checks backing ``doberman doctor`` (issue #94).

A **read-only** self-check: every check *diagnoses*, it never mutates state. The
logic lives here (a pure function over a repo root) so it is trivially testable
without Typer and so the CLI command in :mod:`doberman.cli.main` is a thin
renderer. The one deliberate exception is the "Policy version" check, which
records the observed policy version into ``.doberman/policies.db`` — itself a
diagnostic record, never a change to policy, a decision, or enforcement.

Two safety rules, straight from the Prime Directives:

* **Fail closed in the reporting.** A check that cannot be determined resolves to
  a :class:`CheckStatus.WARN`, never a false ``OK`` — an unknown is never "all good".
* **Script-friendly exit code.** The three checks that decide whether Doberman is
  actually wired up and healthy — host hooks, config, decision DB — are marked
  *critical*. The CLI exits non-zero if any critical check is not ``OK`` (a fail
  *or* an indeterminate warning), so a half-configured install is caught in CI.
"""

from __future__ import annotations

import os
import shutil
import sqlite3
import stat
import sys
import sysconfig
from dataclasses import dataclass
from enum import Enum
from importlib.util import find_spec
from pathlib import Path


class CheckStatus(str, Enum):
    """Traffic-light state of a single health check."""

    OK = "ok"
    WARN = "warn"
    FAIL = "fail"


@dataclass(frozen=True)
class CheckResult:
    """One line of the ``doctor`` checklist."""

    name: str
    status: CheckStatus
    detail: str
    #: Critical checks drive the process exit code (see :func:`is_healthy`).
    critical: bool = False


def _safe_check(name: str, critical: bool, fn):
    """Run one check, converting any unexpected error into a fail-closed WARN.

    A check must never crash ``doctor`` and must never report ``OK`` when it
    could not actually determine health.
    """
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001 — a diagnostic must never crash; fail closed to WARN
        return CheckResult(
            name, CheckStatus.WARN, f"could not be determined ({type(exc).__name__})", critical
        )


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------


def _check_hooks(path: str) -> CheckResult:
    from doberman.hosthooks.install_codex import codex_hook_install_states, protection_state

    # Round 8 item P0: sourced from the shared predicate (also used by
    # `status`) so this listing can never drift out of sync with it; the
    # plugin scope isn't part of that predicate (see its docstring), so it's
    # still probed and appended here directly, same as before.
    _protected, _reason, hooks = protection_state(path)
    installed = [scope for scope, _p, ok in hooks if ok]
    installed += [
        f"codex:{scope}"
        for scope, _p, ok in codex_hook_install_states(path)
        if scope == "plugin" and ok
    ]
    if installed:
        return CheckResult("Host hooks", CheckStatus.OK, f"installed ({', '.join(installed)})")
    return CheckResult(
        "Host hooks",
        CheckStatus.FAIL,
        "not installed in any scope - run `doberman install-hooks` (add `--host codex` for "
        "Codex, `--host cursor` for Cursor)",
        critical=True,
    )


def _bin_dir_hint() -> str:
    """Best-effort directory this Python environment installs console scripts
    into, so the PATH remedy below can name a concrete directory instead of a
    generic "check your PATH" (item 8). ``sys.executable``'s own directory IS
    that directory in every common layout (venv, pipx venv, `--user`, conda) -
    an entry-point script installs alongside the interpreter that runs it.
    Falls back to ``sysconfig.get_path('scripts')`` if that directory doesn't
    look like a script dir for some reason; never raises.
    """
    try:
        exe_dir = Path(sys.executable).resolve().parent
        if exe_dir.name.lower() in ("bin", "scripts"):
            return str(exe_dir)
    except Exception:  # noqa: BLE001, S110 — a diagnostic hint must never crash doctor
        pass
    try:
        return sysconfig.get_path("scripts")
    except Exception:  # noqa: BLE001 — same
        return "your Python install's script directory"


def _check_hook_command(path: str) -> CheckResult:
    """Every hook entry runs the bare ``doberman`` command, so the host can only
    execute them if ``doberman`` is on PATH. A dangling entry (package removed, or
    its bin dir not on PATH) makes the host fail the hook and carry on
    **unmediated** - critical whenever hooks are installed (ADR 0086 follow-up).

    Diagnosis only: the fix is putting the binary back on PATH or stripping the
    entries with ``uninstall-hooks``; ``doctor`` never edits settings. Resolution
    happens on *this* process's PATH, which can differ from the host's, so the
    detail says so.
    """
    from doberman.hosthooks.install_codex import protection_state

    resolved = shutil.which("doberman")
    if resolved:
        return CheckResult("Hook command", CheckStatus.OK, f"`doberman` resolves to {resolved}")
    # Round 8 item P0: same shared predicate as `_check_hooks`/`status` - its
    # "no_hooks" reason is exactly "nothing installed in any scope that
    # counts here" (Claude's three scopes + Codex user/repo, plugin excluded).
    _protected, reason, _hooks = protection_state(path)
    if reason == "no_hooks":
        return CheckResult(
            "Hook command",
            CheckStatus.WARN,
            "`doberman` is not on PATH (checked from this shell) - hooks installed later would not run",
        )
    return CheckResult(
        "Hook command",
        CheckStatus.FAIL,
        "hooks call `doberman`, which is not on PATH (checked from this shell): the host cannot run "
        f"them, so tool calls go unmediated. Add {_bin_dir_hint()} to PATH, or `pipx install "
        "doberman-core`, or strip the dangling entries with `doberman uninstall-hooks` "
        "(`--global` for the user-wide ones)",
        critical=True,
    )


def _check_hook_integrity(path: str) -> CheckResult:
    """#239: has Doberman's own hook registration changed since install-hooks?"""
    from doberman.hosthooks.install import hook_install_states
    from doberman.hosthooks.install_codex import codex_hook_install_states
    from doberman.hosthooks.install_cursor import cursor_hook_install_states
    from doberman.hosthooks.integrity import check_all

    name = "Hook integrity"
    statuses = check_all(path)
    diverged = [s for s in statuses if s.state == "diverged"]
    intact = [s for s in statuses if s.state == "intact"]
    if diverged:
        where = ", ".join(f"{s.host} {s.scope}: {'/'.join(s.diverged_events)}" for s in diverged)
        critical = any(s.critical for s in diverged)
        return CheckResult(
            name,
            CheckStatus.FAIL if critical else CheckStatus.WARN,
            f"diverged ({where}) - Doberman's hook registration changed since install; "
            "run `doberman install-hooks` to restore",
            critical=critical,
        )
    if intact:
        detail = "intact (" + ", ".join(f"{s.host} {s.scope}" for s in intact) + ")"
        seen = [s.divergence_seen for s in intact if s.divergence_seen]
        if seen:
            detail += f" - a divergence was seen at {max(seen)}; re-run install-hooks to clear"
        return CheckResult(name, CheckStatus.OK, detail)
    installed = (
        any(ok for _s, _p, ok in hook_install_states(path))
        or any(ok for s, _p, ok in codex_hook_install_states(path) if s != "plugin")
        or any(ok for _s, _p, ok in cursor_hook_install_states(path))
    )
    if installed:
        return CheckResult(
            name,
            CheckStatus.WARN,
            "untracked - installed before integrity tracking; re-run `doberman install-hooks` "
            "to record a manifest",
        )
    return CheckResult(name, CheckStatus.OK, "nothing to verify (no hooks installed)")


def _check_hook_timeout(path: str) -> CheckResult:
    """#658: a Claude Code PreToolUse/PostToolUse hook entry with no `timeout`
    (or one too small) times out at Claude Code's own 600s default before
    Doberman's own challenge ceiling (`DEFAULT_CHALLENGE_TIMEOUT_S`) elapses,
    and a timed-out hook fails OPEN - the tool call proceeds unmediated. This
    inspects the LIVE settings.json content per installed scope (mirrors
    `_check_cursor_hooks`), not just "is something installed", so a stale
    install from before this pin existed is reported instead of silently
    trusted.
    """
    from doberman.auth.challenge import DEFAULT_CHALLENGE_TIMEOUT_S
    from doberman.hosthooks.install import _is_doberman_group, hook_install_states, load_settings

    name = "Hook timeout"
    states = hook_install_states(path)
    installed_scopes = [scope for scope, _p, ok in states if ok]
    if not installed_scopes:
        return CheckResult(
            name, CheckStatus.OK, "nothing to verify (no Claude Code hooks installed)"
        )

    problems: list[str] = []
    good_scopes: list[str] = []
    for scope, settings_path, ok in states:
        if not ok:
            continue
        try:
            settings = load_settings(Path(settings_path))
        except ValueError:
            problems.append(f"{scope}: settings.json unreadable")
            continue
        hooks_section = settings.get("hooks") or {}
        scope_ok = True
        for event in ("PreToolUse", "PostToolUse"):
            groups = hooks_section.get(event)
            if not isinstance(groups, list):
                continue
            for group in groups:
                if not isinstance(group, dict) or not _is_doberman_group(group):
                    continue
                for h in group.get("hooks", []):
                    timeout = h.get("timeout") if isinstance(h, dict) else None
                    is_number = isinstance(timeout, (int, float)) and not isinstance(timeout, bool)
                    if not is_number or timeout <= DEFAULT_CHALLENGE_TIMEOUT_S:
                        scope_ok = False
                        problems.append(
                            f"{scope} {event}: timeout "
                            f"{f'{timeout}s' if is_number else 'missing'} does not outlast the "
                            f"{int(DEFAULT_CHALLENGE_TIMEOUT_S)}s challenge ceiling"
                        )
        if scope_ok:
            good_scopes.append(scope)

    if problems:
        return CheckResult(
            name,
            CheckStatus.FAIL,
            f"stale install ({'; '.join(problems)}) - run `doberman install-hooks` to restore",
            critical=True,
        )
    return CheckResult(name, CheckStatus.OK, f"pinned ({', '.join(good_scopes)})")


def _check_cursor_hooks(path: str) -> CheckResult:
    """Weak-registration + liveness self-check for the Cursor adapter (slice 2).

    Cursor's own hook contract can fail OPEN (a crash or timeout runs the tool)
    unless every gating entry carries ``failClosed: true`` and a timeout that
    outlasts Doberman's approval dialog - so this check inspects the LIVE
    hooks.json content, not just "is something installed". A weak registration
    is a critical FAIL (Doberman may not actually be gating); a missing
    sessionStart callback is only a WARN (it means "unverified", not
    "unprotected" - `doctor` cannot always tell them apart from the file
    alone). Claude Code's own hook contract can *also* fail open on a timeout -
    see :func:`_check_hook_timeout` for that check.
    """
    from doberman.hosthooks.install import load_settings
    from doberman.hosthooks.install_cursor import (
        cursor_hook_install_states,
        last_session_start,
        registration_issues,
    )

    name = "Cursor hooks"
    states = cursor_hook_install_states(path)
    installed_scopes = [scope for scope, _p, ok in states if ok]
    if not installed_scopes:
        return CheckResult(name, CheckStatus.OK, "not installed (only needed for `--host cursor`)")

    criticals: list[str] = []
    warnings: list[str] = []
    for scope, hooks_path, ok in states:
        if not ok:
            continue
        try:
            settings = load_settings(Path(hooks_path))
        except ValueError:
            criticals.append(f"{scope}: hooks.json unreadable")
            continue
        for message, critical in registration_issues(settings):
            (criticals if critical else warnings).append(f"{scope} {message}")

    if criticals:
        return CheckResult(
            name,
            CheckStatus.FAIL,
            f"weak registration ({'; '.join(criticals)}) - run `doberman install-hooks "
            "--host cursor` to restore",
            critical=True,
        )
    if warnings:
        return CheckResult(name, CheckStatus.WARN, "; ".join(warnings))

    seen = last_session_start(path)
    if seen:
        return CheckResult(
            name,
            CheckStatus.OK,
            f"wired ({', '.join(installed_scopes)}); failClosed on every gating event; "
            f"last session start {seen}",
        )
    return CheckResult(
        name,
        CheckStatus.WARN,
        f"wired ({', '.join(installed_scopes)}) but no Cursor session has called back yet - "
        "open this project in Cursor and re-run doctor (Cursor hooks are known to "
        "intermittently not fire)",
    )


def _check_codex_version() -> CheckResult:
    """Report the installed Codex CLI version against the adapter's supported
    range. Always **non-critical** (WARN, never FAIL): a newer or absent Codex is
    not "Doberman may not be protecting you" — Codex support is opt-in.

    Windows regression (live-tested): a bare ``["codex", "--version"]`` argv
    cannot resolve npm's ``codex.cmd`` shim — Windows ``CreateProcess`` does not
    apply ``PATHEXT`` to a bare command name the way a shell does — so this
    reported a false "not found" on a box where ``codex`` ran fine from a
    terminal. Resolving via :func:`shutil.which` first (it *does* apply
    ``PATHEXT``) fixes this on every platform, POSIX included.
    """
    import shutil
    import subprocess

    from doberman.hosthooks.codex import SUPPORTED_CODEX_RANGE

    resolved = shutil.which("codex")
    if resolved is None:
        return CheckResult(
            "Codex CLI", CheckStatus.WARN, "not found (only needed for `--host codex`)"
        )

    try:
        # noqa on the argv line: fixed argv (from shutil.which, not user input), no
        # shell. Timeout raised from 2s -> 5s: the npm shim is a colder start.
        proc = subprocess.run(  # noqa: S603
            [resolved, "--version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except OSError:  # resolved path became unreachable between the which() and run()
        return CheckResult(
            "Codex CLI", CheckStatus.WARN, "not found (only needed for `--host codex`)"
        )
    except subprocess.SubprocessError:
        return CheckResult("Codex CLI", CheckStatus.WARN, "version could not be determined")

    import re

    match = re.search(r"(\d+\.\d+\.\d+)", proc.stdout or proc.stderr or "")
    if not match:
        return CheckResult("Codex CLI", CheckStatus.WARN, "version string not recognized")
    version = match.group(1)
    low, high = SUPPORTED_CODEX_RANGE
    if _version_tuple(low) <= _version_tuple(version) < _version_tuple(high):
        return CheckResult("Codex CLI", CheckStatus.OK, f"{version} (supported)")
    return CheckResult(
        "Codex CLI",
        CheckStatus.WARN,
        f"{version} outside tested range [{low}, {high}) - adapter may need an update",
    )


def _version_tuple(v: str) -> tuple[int, ...]:
    try:
        return tuple(int(p) for p in v.split("."))
    except ValueError:
        return (0,)


def _check_optional_extra(name: str, module: str, install_extra: str) -> CheckResult:
    """Report an optional UI dependency without importing it."""
    if find_spec(module) is not None:
        return CheckResult(name, CheckStatus.OK, "installed")
    return CheckResult(
        name,
        CheckStatus.WARN,
        f"not installed (optional) - pip install 'doberman[{install_extra}]'",
    )


def _check_dash_extra() -> CheckResult:
    return _check_optional_extra("Dash extra", "starlette", "dash")


def _check_tui_extra() -> CheckResult:
    return _check_optional_extra("TUI extra", "textual", "tui")


def _check_config(path: str) -> CheckResult:
    from doberman.config import CONFIG_DIR, POLICY_FILE, load_policy

    policy_file = Path(path) / CONFIG_DIR / POLICY_FILE
    doc = load_policy(path)
    if doc is not None:
        enabled = sum(1 for it in doc.items if it.enabled)
        return CheckResult(
            "Config", CheckStatus.OK, f"policy loaded ({enabled}/{len(doc.items)} items enabled)"
        )
    if policy_file.exists():
        # File is there but load_policy returned None → corrupt/unreadable. Fail closed.
        return CheckResult(
            "Config",
            CheckStatus.FAIL,
            f"{policy_file} present but failed to load (corrupt?)",
            critical=True,
        )
    return CheckResult(
        "Config",
        CheckStatus.FAIL,
        "no policy saved - run `doberman setup` or `doberman review --yes`",
        critical=True,
    )


def _check_db(path: str) -> CheckResult:
    from doberman.storage.db import db_path

    p = db_path(path)
    if not p.exists():
        # Absent is the normal state of a fresh install (the DB appears on the
        # first gated decision), so it must not fail the run — a red "may not be
        # protecting you" on a healthy first-run `doctor` teaches users to
        # ignore the tool. Present-but-unreadable below stays a critical FAIL.
        return CheckResult(
            "Decision DB",
            CheckStatus.WARN,
            "not created yet - appears on the first gated decision",
        )
    # Read-only probe: open in SQLite `mode=ro` so we never create or migrate.
    try:
        conn = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
        try:
            # Must touch the schema: a bare `SELECT 1` never reads the file, so
            # a corrupt/non-SQLite file would probe as healthy.
            conn.execute("SELECT 1 FROM sqlite_master LIMIT 1").fetchone()
        finally:
            conn.close()
    except sqlite3.Error as exc:
        return CheckResult(
            "Decision DB", CheckStatus.FAIL, f"present but unreadable ({exc})", critical=True
        )
    return CheckResult("Decision DB", CheckStatus.OK, f"reachable ({p})")


def _check_enforcement(path: str) -> CheckResult:
    from doberman.config import load_mode, resolve_enforcement_sync

    mode = load_mode(path)
    enforcement = resolve_enforcement_sync(path)  # fails closed to "enforce"
    detail = f"enforcement={enforcement}, mode={mode}"
    if enforcement == "enforce":
        return CheckResult("Enforcement", CheckStatus.OK, detail)
    # monitor / off: Doberman is not blocking. Surface it loudly (still not a
    # critical *health* failure — it is an intentional, human-gated dial).
    return CheckResult("Enforcement", CheckStatus.WARN, f"{detail} - NOT blocking (advisory only)")


def _check_policy_versions(path: str) -> CheckResult:
    from doberman.storage.policy_catalogue import (
        ORIGIN_OBSERVED,
        observe_current,
        read_observations,
        read_versions,
    )

    version = observe_current(path, origin=ORIGIN_OBSERVED)
    if version is None:
        return CheckResult(
            "Policy version", CheckStatus.WARN, "could not build the current policy snapshot"
        )
    short = version[:16] + "..."
    versions = read_versions(path)
    if not any(v["version"] == version for v in versions):
        return CheckResult(
            "Policy version",
            CheckStatus.WARN,
            f"{short} computed, but .doberman/policies.db could not be written",
        )
    latest = read_observations(path, limit=1)
    since = latest[0]["ts"] if latest else "unknown"
    return CheckResult(
        "Policy version",
        CheckStatus.OK,
        f"{short} ({len(versions)} version(s); in force since {since})",
    )


def _check_2fa() -> CheckResult:
    from doberman.auth import totp

    if totp.is_enrolled():
        return CheckResult("2FA", CheckStatus.OK, "enrolled")
    return CheckResult(
        "2FA", CheckStatus.WARN, "not enrolled (optional) - run `doberman 2fa setup`"
    )


def _check_phone_approvals() -> CheckResult:
    from doberman.auth import approval_config, ntfy

    cfg = ntfy.load_config()
    if cfg is None or not approval_config.is_enabled(ntfy.METHOD_NAME):
        return CheckResult(
            "Phone approvals",
            CheckStatus.WARN,
            "not configured (optional) - run `doberman phone setup`",
        )
    return CheckResult("Phone approvals", CheckStatus.OK, "configured")


def _check_password() -> CheckResult:
    from doberman.auth import password

    if password.is_enrolled():
        return CheckResult("Password", CheckStatus.OK, "set")
    return CheckResult(
        "Password", CheckStatus.WARN, "not set (optional) - run `doberman password set`"
    )


def _check_fingerprint_key() -> CheckResult:
    from doberman.storage.fingerprint import _key_path

    p = _key_path()
    if not p.exists():
        return CheckResult(
            "Fingerprint key", CheckStatus.WARN, "not yet created (generated on first use)"
        )
    if os.name == "nt":
        # POSIX mode bits are meaningless on Windows ACLs, so permissions
        # can't be verified here - but the key genuinely IS present, and
        # there is nothing actionable for the user to fix about an OS
        # limitation (round 6 item 11: this is an OK fact, not a warning).
        return CheckResult(
            "Fingerprint key", CheckStatus.OK, "present (permissions not verifiable on Windows)"
        )
    mode = stat.S_IMODE(p.stat().st_mode)
    if mode & 0o077:
        return CheckResult(
            "Fingerprint key",
            CheckStatus.WARN,
            f"present but group/other-accessible ({oct(mode)}; expected 0o600)",
        )
    return CheckResult("Fingerprint key", CheckStatus.OK, f"present with {oct(mode)} permissions")


# ---------------------------------------------------------------------------
# Aggregate
# ---------------------------------------------------------------------------


def run_checks(path: str = ".") -> list[CheckResult]:
    """Run every health check against *path* and return the results in display order."""
    return [
        _safe_check("Host hooks", True, lambda: _check_hooks(path)),
        _safe_check("Hook command", True, lambda: _check_hook_command(path)),
        _safe_check("Hook integrity", True, lambda: _check_hook_integrity(path)),
        _safe_check("Cursor hooks", True, lambda: _check_cursor_hooks(path)),
        _safe_check("Hook timeout", True, lambda: _check_hook_timeout(path)),
        _safe_check("Config", True, lambda: _check_config(path)),
        _safe_check("Decision DB", True, lambda: _check_db(path)),
        _safe_check("Enforcement", False, lambda: _check_enforcement(path)),
        _safe_check("Policy version", False, lambda: _check_policy_versions(path)),
        _safe_check("2FA", False, _check_2fa),
        _safe_check("Phone approvals", False, _check_phone_approvals),
        _safe_check("Password", False, _check_password),
        _safe_check("Fingerprint key", False, _check_fingerprint_key),
        _safe_check("Codex CLI", False, _check_codex_version),
        _safe_check("Dash extra", False, _check_dash_extra),
        _safe_check("TUI extra", False, _check_tui_extra),
    ]


def critical_failures(results: list[CheckResult]) -> list[CheckResult]:
    """Critical checks that are not ``OK`` (a fail *or* an indeterminate warning)."""
    return [r for r in results if r.critical and r.status is not CheckStatus.OK]


def is_healthy(results: list[CheckResult]) -> bool:
    """True iff every *critical* check passed — the process-exit health signal."""
    return not critical_failures(results)

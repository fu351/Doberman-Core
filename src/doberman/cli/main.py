"""The ``doberman`` CLI entry point (Features 5-7).

Exposes ``doberman scan`` (risk map), ``review`` / ``mode`` / ``status``
(policy), and local auth surfaces: ``doberman password set``, ``doberman 2fa
setup`` (optional TOTP enrollment), and ``doberman revoke`` (revoke a role
elevation). ``status`` also lists currently-active elevations.
"""

import asyncio
import importlib.util
import json
import logging
import os
import secrets
import shlex
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import typer

import doberman
from doberman import __version__
from doberman.auth import password, totp
from doberman.auth.challenge import TIMEOUT_METHOD
from doberman.auth.ntfy import DEFAULT_SERVER as NTFY_DEFAULT_SERVER
from doberman.auth.provider import CliPrompter
from doberman.cli import telemetry_cmd
from doberman.config import (
    CONFIG_DIR,
    MESSAGE_TONES,
    default_role_enabled,
    load_active_role,
    load_approval_memory_seconds,
    load_enforcement,
    load_message_tone,
    load_mode,
    load_policy,
    load_preferences,
    save_default_role_enabled,
    save_message_tone,
    save_mode,
    save_policy,
    save_preferences,
)
from doberman.demo import format_outcome_line, format_summary_table, run_demo
from doberman.discovery.mcp_scan import MCP_CONFIG_FILES, scan_mcp_configs
from doberman.discovery.scan import enumerate_capabilities, rate_capabilities, render_risk_map
from doberman.egress.velocity import (
    _BURST_THRESHOLD,
    _FANOUT_THRESHOLD,
    _VOLUME_THRESHOLD_BYTES,
    VelocityThresholds,
)
from doberman.explain import why_body
from doberman.hosthooks.install import DASHBOARD_COMMAND
from doberman.models import ActionType
from doberman.policy.checklist import recommend_policy
from doberman.policy.drift import (
    Classification,
    _prefs_classify,
    _run_weaken_gate,
    _verify_possession_factor,
    apply_change,
    apply_egress_velocity_change,
    apply_enforcement_change,
    apply_mode_change,
    apply_preferences_change,
    apply_standing_elevation,
    classify_change,
    decide_change,
    decide_preferences_change,
    read_policy_changes,
    record_change,
)
from doberman.policy.friction import build_friction_report, generate_proposals
from doberman.policy.modes import SecurityMode, resolve_mode
from doberman.policy.preferences import DIMENSIONS, preset_name
from doberman.policy.sources import (
    PIN_CORRUPT,
    POLICY_FILE_NAME,
    PolicySnapshot,
    glob_state_map,
    load_raw_file,
    read_pin,
    write_pin,
)
from doberman.render import (
    format_utc_timestamp,
    humanize_auth_result,
    next_step_line,
    style_text,
    verdict_label,
    verdict_label_str,
    wrap_detail,
)
from doberman.storage.approval_memory import clear as clear_approval_memory
from doberman.storage.approval_memory import count_live as count_live_approval_memory
from doberman.storage.db import active_elevations, grant_elevation, revoke_elevation
from doberman.storage.exclusions import add_exclusion, is_excluded, remove_exclusion
from doberman.storage.log import memory_summary, prune_decisions, read_decisions
from doberman.storage.memory import prune_stale_entities, reset_memory
from doberman.storage.taint import clear_taint, entity_scope, read_taint
from doberman.storage.tool_pins import approve_pin


def _ensure_encode_safe_stdio() -> None:
    """Make CLI output safe on a console that cannot encode Unicode.

    Windows' default console is cp1252; printing a non-ASCII character (an arrow,
    box-drawing rule, or emoji) there raises ``UnicodeEncodeError`` and crashes
    onboarding (``doberman setup`` / ``install-hooks``). Reconfigure stdout/stderr
    to UTF-8 with error-replacement so output can never crash on the console
    encoding -- a no-op where ``reconfigure`` is unavailable. Runs at import,
    before any command emits a character.

    Also forces line buffering on both streams (round 6 item 12): when stdout
    isn't a real terminal (piped, or redirected with ``2>&1`` to one file), a
    Python process defaults it to full block buffering while stderr stays
    unbuffered/line-buffered - so a redirected transcript can show every
    stderr `error:`/reprompt line arriving well before the stdout prompt line
    it's actually answering, because stdout's buffer hadn't flushed yet. Line
    buffering both keeps their relative order close to the actual call order.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
        except (ValueError, OSError):  # detached / unsupported stream
            pass


_ensure_encode_safe_stdio()

_WINDOWS = os.name == "nt"

app = typer.Typer(
    help="Doberman - adaptive authorization layer for coding agents.",
    no_args_is_help=True,
)

twofa_app = typer.Typer(help="Two-factor (TOTP) enrollment.", no_args_is_help=True)
app.add_typer(twofa_app, name="2fa", rich_help_panel="Auth")
methods_app = typer.Typer(
    help="Approval methods (biometric/push) that replace the 2FA code with a tap.",
    no_args_is_help=True,
)
twofa_app.add_typer(methods_app, name="methods")

phone_app = typer.Typer(
    help="Phone approvals via ntfy push notifications (tap Approve/Deny from your phone).",
    no_args_is_help=True,
)
app.add_typer(phone_app, name="phone", rich_help_panel="Auth")

password_app = typer.Typer(
    help="Local password possession factor (the minimum lowering-gate auth).",
    no_args_is_help=True,
)
app.add_typer(password_app, name="password", rich_help_panel="Auth")

taint_app = typer.Typer(
    help="Sticky session-taint recovery (gated - requires an enrolled possession factor).",
    no_args_is_help=True,
)
app.add_typer(taint_app, name="taint", rich_help_panel="Policy internals")

tools_app = typer.Typer(
    help="MCP tool-schema pin management (gated re-approval).",
    no_args_is_help=True,
)
app.add_typer(tools_app, name="tools", rich_help_panel="Policy internals")

approvals_app = typer.Typer(
    help="Bounded exact-action approval memory.",
    no_args_is_help=True,
)
app.add_typer(approvals_app, name="approvals", rich_help_panel="Advanced")

plugins_app = typer.Typer(
    help="Opt-in-by-name entry-point plugin allowlist (every registry seam).",
    no_args_is_help=True,
)
app.add_typer(plugins_app, name="plugins", rich_help_panel="Advanced")

memory_app = typer.Typer(
    help="Learned behavioral memory: profile, gated reset, and retention pruning.",
    no_args_is_help=False,
)
app.add_typer(memory_app, name="memory")

hook_app = typer.Typer(
    help=(
        "Host-harness integration hooks (e.g. Claude Code PreToolUse/PostToolUse, "
        "Codex CLI PreToolUse)."
    ),
    no_args_is_help=True,
)
app.add_typer(hook_app, name="hook", rich_help_panel="Advanced")

role_app = typer.Typer(
    help="Agent role boundary (Feature 4) — the opt-in built-in default role.",
    no_args_is_help=True,
)
app.add_typer(role_app, name="role", rich_help_panel="Policy")
telemetry_cmd.register_cli_telemetry(
    app, twofa_app, password_app, taint_app, tools_app, memory_app, role_app
)


def _print_version_and_exit(show_version: bool) -> None:
    if show_version:
        typer.echo(__version__)
        raise typer.Exit()


@app.callback()
def _main_callback(
    ctx: typer.Context,
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        help="Print the installed Doberman version and exit.",
        callback=_print_version_and_exit,
        is_eager=True,
    ),
) -> None:
    # `--dry-run` (setup / install-hooks / uninstall-hooks / uninstall) means
    # "write nothing" — telemetry state (distinct id, notice-shown flag) is a
    # write like any other, so it's skipped too. `--help` never executes the
    # subcommand at all (Click prints help and exits) - recording it here would
    # print the first-run notice ABOVE the usage text (item 3/10). This
    # callback runs before the subcommand parses its own options, so sys.argv
    # is the only signal available for either check.
    argv_tail = sys.argv[1:]
    if "--dry-run" not in argv_tail and "--help" not in argv_tail:
        telemetry_cmd.record_root_command(ctx.invoked_subcommand)


def _configure_stderr_logging(level: int = logging.INFO) -> None:
    """Send Doberman logs to STDERR only.

    In ``serve`` mode this process's stdout IS the agent's MCP channel, so any log written
    there would corrupt the protocol. Pin every ``doberman.*`` logger to stderr and stop
    propagation, and - defense in depth - strip any stdout handler from the root logger so a
    library (mcp/asyncio) or host-configured logger cannot leak a record onto stdout either.
    """
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("doberman: %(message)s"))
    doberman_logger = logging.getLogger("doberman")
    for existing in doberman_logger.handlers[:]:
        doberman_logger.removeHandler(existing)
    doberman_logger.addHandler(handler)
    doberman_logger.setLevel(level)
    doberman_logger.propagate = False

    root = logging.getLogger()
    for existing in root.handlers[:]:
        if (
            isinstance(existing, logging.StreamHandler)
            and getattr(existing, "stream", None) is sys.stdout
        ):
            root.removeHandler(existing)
    if not root.handlers:  # keep a stderr fallback so non-doberman logs aren't silently dropped
        root.addHandler(logging.StreamHandler(sys.stderr))


#: Shown once, only to a human at a terminal, before `serve` blocks on stdin.
#: Run bare, the proxy logs two lines and then goes silent forever waiting for a
#: client's JSON-RPC — indistinguishable from a hang, and easy to read as "serve
#: is supposed to start my agent and didn't". It starts nothing: an MCP client
#: spawns *it*. Never write this to stdout; stdout IS the MCP channel.
_SERVE_WAITING_HINT = (
    "waiting for an MCP client to connect on stdin - this command does not start your agent. "
    "Register it once (`claude mcp add doberman -- doberman serve -- <your tool server>`), then "
    "start the agent separately. For Claude Code, `doberman setup` instead wires hooks that gate "
    "every tool call with no MCP reconfig."
)


def _stderr_is_tty() -> bool:
    """Whether a human is watching stderr. A seam: a CLI test runner replaces
    ``sys.stderr`` with a non-tty capture, so this is the patch point."""
    return sys.stderr.isatty()


@app.command(
    rich_help_panel="Advanced",
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
    help="Run Doberman as an MCP proxy in front of a downstream MCP tool server.",
)
def serve(
    ctx: typer.Context,
    path: str = typer.Option(
        ".", "--path", "-p", help="Repo root whose .doberman/ policy governs decisions."
    ),
    url: str | None = typer.Option(
        None,
        "--url",
        help=(
            "Front a remote MCP server at this http(s) URL instead of spawning a command "
            "(Streamable HTTP by default)."
        ),
    ),
    transport: str = typer.Option(
        "http",
        "--transport",
        help="With --url: 'http' (Streamable HTTP, default) or 'sse' (legacy SSE).",
    ),
    header: list[str] = typer.Option(  # noqa: B008 — Typer's Option() factory, not a mutable default
        [],
        "--header",
        "-H",
        help=(
            "With --url: extra request header, 'Name: value' (repeatable). Pass secrets via "
            "your shell's env expansion; argv is visible to local processes."
        ),
    ),
) -> None:
    """Run Doberman as an MCP proxy in front of a downstream MCP server.

    Everything after `--` is the downstream server command, for example:

        doberman serve -- npx -y @modelcontextprotocol/server-filesystem /path/to/repo

    Or front a remote MCP server directly (Streamable HTTP by default; `--transport sse` for
    legacy endpoints):

        doberman serve --url https://mcp.example.com/mcp

    A bearer token goes through a header, expanded by your shell so it never lands in argv or
    shell history: `doberman serve --url ... -H "Authorization: Bearer $MCP_TOKEN"`.

    Point your agent's MCP config at this instead of the real server. AUTH prompts appear on
    your terminal; with no terminal attached (headless) an AUTH action is denied (fail closed).

    This does not launch your agent - the agent's MCP client spawns this process. Run bare in a
    terminal it just waits on stdin for a client.
    """
    # Imported here, not at module scope, so non-serve CLI commands (`--help`,
    # `log`, `status`, `scan`, ...) don't pay the cost of loading the subjective
    # layer's heavy numeric stack (river/numpy/scipy) on every invocation. These
    # imports run synchronously, before asyncio.run, so nothing loads in-loop.
    from mcp import StdioServerParameters

    from doberman.proxy.serve import _redacted, serve_http, serve_stdio

    downstream_argv = list(ctx.args)

    if url is not None and downstream_argv:
        typer.echo("error: use --url or a downstream command after '--', not both", err=True)
        raise typer.Exit(code=2)
    if url is None and not downstream_argv:
        typer.echo("error: provide the downstream server command after `--`", err=True)
        raise typer.Exit(code=2)

    if url is not None and not (url.startswith("http://") or url.startswith("https://")):
        typer.echo("error: --url must be an http(s) URL", err=True)
        raise typer.Exit(code=2)
    if transport not in ("http", "sse"):
        typer.echo("error: --transport must be 'http' or 'sse'", err=True)
        raise typer.Exit(code=2)

    headers: dict[str, str] | None = None
    if url is None:
        # A downstream command was given (the checks above ruled out "neither").
        if header:
            typer.echo("error: --header only applies with --url", err=True)
            raise typer.Exit(code=2)
        if transport != "http":
            typer.echo("error: --transport only applies with --url", err=True)
            raise typer.Exit(code=2)
        params = StdioServerParameters(command=downstream_argv[0], args=downstream_argv[1:])
    else:
        parsed_headers: dict[str, str] = {}
        for entry in header:
            name, _sep, value = entry.partition(":")
            name, value = name.strip(), value.strip()
            if not _sep or not name or not value:
                typer.echo("error: --header expects 'Name: value'", err=True)
                raise typer.Exit(code=2)
            parsed_headers[name] = value
        headers = parsed_headers or None

    _configure_stderr_logging()
    if _stderr_is_tty():  # a human ran it; a client-spawned process gets a pipe
        typer.echo(f"doberman: {_SERVE_WAITING_HINT}", err=True)
    try:
        if url is not None:
            asyncio.run(serve_http(url, repo_root=path, headers=headers, transport=transport))
        else:
            asyncio.run(serve_stdio(params, repo_root=path))
    except Exception as exc:  # noqa: BLE001 - surface a clean stderr error, never a raw traceback
        if url is not None:
            # Never echo `exc` here: transport errors embed the request URL (query
            # string included) and can quote header values.
            typer.echo(
                f"error: doberman serve failed: could not serve {_redacted(url)} "
                f"({type(exc).__name__})",
                err=True,
            )
        else:
            typer.echo(f"error: doberman serve failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc


@app.command(rich_help_panel="Advanced")
def scan(
    path: str = typer.Option(".", "--path", "-p", help="Repository root to scan."),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        "-q",
        help="Suppress human-readable stdout (exit code unchanged; useful for CI).",
    ),
    as_json: bool = typer.Option(
        False,
        "--json",
        help="Emit one deterministic JSON document on stdout instead of the risk map.",
    ),
    mcp: bool = typer.Option(
        False,
        "--mcp",
        help="Statically scan known repository MCP configs for suspicious patterns.",
    ),
) -> None:
    """Show a read-only risk map of the agent's capabilities and sensitive surface.

    Sensitive files are detected by name only and never read; nothing is written.
    Tool-derived capabilities require a live proxy session and are omitted here.
    """
    capabilities = rate_capabilities(enumerate_capabilities(tools=[], repo_root=path))
    mcp_findings = scan_mcp_configs(path) if mcp else []
    mcp_files = (
        [name for name in MCP_CONFIG_FILES if (Path(path) / Path(name)).is_file()] if mcp else []
    )
    if as_json:
        # Stable schema for scripts/editor integrations (#178).
        payload = {
            "version": 1,
            "path": path,
            "capabilities": [
                {
                    "name": c.name,
                    "category": c.category,
                    "present": c.present,
                    "risk": (c.risk.value if c.risk is not None else None),
                    "evidence": list(c.evidence),
                }
                for c in sorted(capabilities, key=lambda x: (x.category, x.name))
            ],
        }
        if mcp:
            payload["mcp"] = {
                "findings": [
                    {
                        "server": finding.server,
                        "source_file": finding.source_file,
                        "category": finding.category,
                        "pattern_class": finding.pattern_class,
                        "risk": finding.risk.value,
                    }
                    for finding in mcp_findings
                ],
                "files_scanned": mcp_files,
            }
        typer.echo(json.dumps(payload, sort_keys=True, separators=(",", ":")))
        return
    if not quiet:
        output = render_risk_map(capabilities)
        if mcp:
            lines = ["", "MCP configuration admission scan", "=" * 32]
            if mcp_findings:
                lines.extend(
                    f"[{finding.risk.value.upper():^8}] {finding.source_file} "
                    f"{finding.server} ({finding.category}/{finding.pattern_class})"
                    for finding in mcp_findings
                )
            else:
                lines.append("No suspicious MCP configuration patterns found.")
            output = "\n".join([output, *lines])
        typer.echo(output)


@app.command(rich_help_panel="Policy")
def review(
    path: str = typer.Option(".", "--path", "-p", help="Repository root."),
    yes: bool = typer.Option(
        False, "--yes", "-y", help="Accept the recommended policy and save it."
    ),
) -> None:
    """Review (and with --yes, save) the recommended policy checklist.

    Core hard blocks are shown but are not disableable here (that requires the
    policy-change approval flow). Without --yes this is read-only.
    """
    role = load_active_role(path)
    capabilities = rate_capabilities(enumerate_capabilities(tools=[], repo_root=path))
    doc = load_policy(path) or recommend_policy(role, capabilities)

    typer.echo("Doberman policy checklist")
    typer.echo("=" * 32)
    for item in doc.items:
        box = "[x]" if item.enabled else "[ ]"
        tags = []
        if item.core:
            tags.append("core/non-disableable")
        if not item.applicable:
            tags.append("N/A - capability absent")
        suffix = f"  ({', '.join(tags)})" if tags else ""
        typer.echo(f"{box} {verdict_label(item.verdict)} {item.id}{suffix}")
    typer.echo(f"\nMode: {doc.mode}")

    if yes:
        save_policy(doc, path)
        typer.echo(f"\nSaved policy to {path}/.doberman/policies.yaml")
    else:
        typer.echo("\n(read-only; re-run with --yes to save)")


#: Mode -> (color, bold) for the setup wizard's summary line, via render.style_text.
#: A monotonic gradient (light -> paranoid), each mode visually distinct.
_MODE_STYLE: dict[str, tuple[str, bool]] = {
    "light": ("green", False),
    "balanced": ("cyan", False),
    "strict": ("yellow", True),
    "paranoid": ("bright_red", True),
}


def _section(title: str, width: int | None = None, *, marker: str = "--") -> str:
    """A ``-- <title> ----...`` section rule for the setup wizard, sized to the
    terminal (capped at 78 columns so a very wide terminal doesn't print an
    absurdly long rule) and bold when the terminal supports color.

    Width math always uses the *plain* title so a long title still gets a
    rule (even a short one) instead of the dash count going negative and
    silently vanishing.

    *marker* (round 6 item 10): the honest-end headers use ``"!!"`` instead of
    the default ``"--"`` so ``Setup incomplete``/``Setup pending``/``Setup
    partly pending`` are distinguishable from ``Setup complete`` without
    relying on color at all (``NO_COLOR``, a piped terminal, or
    colorblindness all lose the red/yellow styling). ``"--"`` reads as one
    continuous rule (``-- title ----...``); any other marker gets its own
    closing copy right after the title, since (unlike ``-``) it doesn't read
    as a continuation of the fill dashes (``!! title !! ----...`` - round 8
    item P1: one space before the fill, same as the ``"--"`` case gets, not
    glued straight onto the closing marker).
    """
    if width is None:
        term_width, _ = shutil.get_terminal_size(fallback=(100, 24))
        width = min(term_width, 78)
    styled = style_text(title, "cyan", bold=True)
    if marker == "--":
        plain_prefix = f"-- {title} "
        dashes = "-" * max(0, width - len(plain_prefix))
        return f"-- {styled} {dashes}"
    plain_prefix = f"{marker} {title} {marker} "
    dashes = "-" * max(0, width - len(plain_prefix))
    return f"{marker} {styled} {marker} {dashes}"


#: How many invalid answers a `setup` wizard menu tolerates before it gives up
#: rather than looping forever (item 6).
_MAX_MENU_ATTEMPTS = 5

#: round 5 item 3: every OpenClaw doc pointer in the CLI is a live GitHub URL,
#: never the bare relative path (dead outside a cloned working tree).
_OPENCLAW_README_URL = (
    "https://github.com/DobermanCore/Doberman-Core/blob/main/adapters/openclaw/README.md"
)


def _abort_message(written: str | None) -> str:
    """The exact text every abort in this wizard prints.

    Round 7 item 5: pulled out of :func:`_abort_setup` so the closing demo
    offer's own 'q' can print the identical wording without also raising
    ``typer.Exit`` - by the time that prompt is reached ``setup`` has already
    fully succeeded, so quitting the still-optional demo must never flip its
    exit code (see the demo offer below), but the phrasing stays consistent
    with every other abort in this wizard.
    """
    if written:
        return f"Aborted - {written} already written; nothing else was."
    return "Aborted - nothing written."


def _abort_setup(*, mid_line: bool = False, written: str | None = None) -> None:
    """Abort the setup wizard cleanly: 'q'/'quit', an exhausted stdin, or too
    many invalid answers in a row all end the same way - never a bare Click
    ``Aborted!`` and never a claim that contradicts what actually happened
    (item 1/6). *mid_line* covers a prompt that already printed its text with
    no trailing newline (e.g. Click's ``... [Y/n]: ``) before stdin ran out -
    a blank line first keeps this message from gluing onto it (item 11/13).

    *written* names whatever this run has ALREADY persisted to disk before the
    abort (e.g. ``"hooks (<path>)"`` or ``"security mode balanced, preferences,
    and hooks (<path>)"``) - the message must say so instead of the
    generically false "nothing written" (round 5 item P1: the mode/prefs are
    now persisted only after per-host wiring succeeds, so almost every abort in
    this wizard genuinely writes nothing; the one exception is an abort at the
    telemetry prompt, reached only after that persist step already ran).
    ``None`` means nothing has been written yet.
    """
    if mid_line:
        typer.echo(err=True)
    typer.echo(_abort_message(written), err=True)
    raise typer.Exit(code=1)


def _read_yes_no_or_quit(prompt_text: str, default: bool) -> str:
    """Read one y/n answer, building a ``"[Y/n/q]"``/``"[y/N/q]"`` prompt -
    Click's own ``confirm()`` builds ``"[Y/n]"``/``"[y/N]"`` (no notion of
    'q'; unrecognized input there just reprints "Error: invalid input" and
    re-reads forever, with no escape) but read through ``typer.prompt`` (like
    :func:`_prompt_menu`) instead so 'q'/'quit' can be recognized too (round 7
    item 5). Round 8 item P1: 'q' is now advertised in the suffix itself
    (every caller here already accepts it) instead of being a silent escape
    hatch nobody discovers without reading the docs, and the invalid-input
    error matches :func:`_prompt_menu`'s own lowercase ``error: ...`` grammar
    rather than Click's capitalized generic one.

    Returns the lowercased, stripped answer as one of ``"y"``, ``"n"``,
    ``"q"``, or ``""`` (blank - caller applies *default*); loops on any other
    input the same way Click's ``confirm()`` does. Raises ``EOFError``/
    ``typer.Abort`` exactly like ``typer.prompt`` on a closed/exhausted stdin
    or Ctrl-C - every caller decides what that means for itself, the same
    split :func:`_confirm_or_abort` and the closing demo offer already need.
    """
    suffix = "Y/n/q" if default else "y/N/q"
    full_prompt = f"{prompt_text} [{suffix}]"
    while True:
        raw = typer.prompt(full_prompt, default="", show_default=False)
        value = raw.strip().lower()
        if value in ("y", "yes"):
            return "y"
        if value in ("n", "no"):
            return "n"
        if value in ("q", "quit"):
            return "q"
        if value == "":
            return ""
        typer.echo("error: answer y, n, or q", err=True)


def _confirm_or_abort(prompt_text: str, default: bool, *, written: str | None = None) -> bool:
    """``typer.confirm`` wrapped in the wizard's own abort discipline (round 5
    item 2): an exhausted stdin or Ctrl-C here aborts with this wizard's own
    message, never a bare Click ``Aborted!``, matching every other prompt in
    this wizard (:func:`_prompt_menu`). *written* is forwarded to
    :func:`_abort_setup` verbatim (see there).

    Round 7 item 5: 'q'/'quit' aborts here too, the same as every
    :func:`_prompt_menu` menu - see :func:`_read_yes_no_or_quit`.
    """
    try:
        answer = _read_yes_no_or_quit(prompt_text, default)
    except (EOFError, typer.Abort):
        _abort_setup(mid_line=True, written=written)
    if answer == "q":
        _abort_setup(written=written)
    if answer == "":
        return default
    return answer == "y"


def _prompt_menu(prompt_text: str, default: str, parse, *, written: str | None = None):
    """Reprompt loop shared by every `setup` wizard menu (hosts, mode, weight
    tuning): every prompt ends with "(q to quit)" so quitting is discoverable
    (item 5); 'q'/'quit' aborts cleanly, a closed/exhausted stdin aborts the
    same way instead of a bare Click ``Aborted!``, and five invalid answers in
    a row aborts too rather than looping forever (item 6). A re-prompt after a
    bad answer starts on a fresh stdout line rather than gluing onto the
    previous prompt's text (item 15). *written* is forwarded to
    :func:`_abort_setup` verbatim (see there).
    """
    prompt_text = f"{prompt_text} (q to quit)"
    # item 7 (round 6): the Hosts prompt alone runs to 92 chars with this
    # suffix - wrap it like every other detail line in the wizard. Click's
    # `prompt()` writes this string as-is before reading input, so an
    # embedded newline just moves the visible prompt (and the default/answer
    # that follows it) onto the wrapped line's own row - it doesn't change
    # the parsing at all.
    prompt_text = "\n".join(wrap_detail(prompt_text, indent=0))
    for attempt in range(_MAX_MENU_ATTEMPTS):
        if attempt:
            typer.echo()  # item 15: own line for the re-prompt, stdout side
        try:
            raw = typer.prompt(prompt_text, default=default)
        except (EOFError, typer.Abort):
            _abort_setup(mid_line=True, written=written)
        if raw.strip().lower() in ("q", "quit"):
            _abort_setup(written=written)
        try:
            return parse(raw)
        except ValueError as exc:
            typer.echo(f"error: {exc} - try again", err=True)
    _abort_setup(written=written)


def _parse_weight(raw: str) -> float:
    """Parse one preference-tuning weight; any bad input (non-numeric or out
    of range) raises the same friendly message so the wizard never leaks a
    raw ``could not convert string to float`` fragment (item 4).
    """
    try:
        value: float | None = float(raw)
    except ValueError:
        value = None
    if value is None or not 0.0 <= value <= 1.0:
        raise ValueError(f"{raw!r} is not a number between 0 and 1")
    return value


def _dim_label(name: str, value: float) -> str:
    """Render one ``name=value`` weight token, glossing ``blast_radius``
    inline where it's shown (item 10) - the other three dimensions read as
    plain English already."""
    token = f"{name}={value:.2f}"
    if name == "blast_radius":
        token += " (actions affecting many targets)"
    return token


def _apply_mode_change(
    name: str, path: str, reason: str, *, establish_ok: bool = False
) -> str | None:
    """Sync CLI wrapper around :func:`doberman.policy.drift.apply_mode_change`.

    The gate itself (possession-factor requirement on a lowering, frictionless
    raising, ``establish_ok`` first-run bypass) lives there so the CLI and the
    dashboard's ``/api/mode`` share one implementation instead of two that could
    drift apart.
    """
    return asyncio.run(apply_mode_change(name, path, reason, establish_ok=establish_ok))


@app.command(rich_help_panel="Policy")
def mode(
    name: str = typer.Argument(None, help="Mode to set (light/balanced/strict/paranoid)."),
    path: str = typer.Option(".", "--path", "-p", help="Repository root."),
) -> None:
    """Show or set the security strength mode.

    Lowering strictness requires a possession factor — a 2FA code if enrolled,
    otherwise your Doberman password (set via `doberman password set`). Raising
    is always frictionless.
    """
    if name is None:
        current = load_mode(path)
        # round 7 item 8: no policy has ever been saved for this repo, so
        # `current` is the pure fallback default, never an explicit choice -
        # say so, the same way `telemetry status` names its own implicit
        # default (round 5 item 12), instead of printing a bare mode name
        # that reads as a deliberate decision someone made.
        if load_policy(path) is None:
            typer.echo(f"{current} (default)")
        else:
            typer.echo(current)
        return
    try:
        saved = _apply_mode_change(name, path, "doberman mode CLI")
    except ValueError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    if saved is None:
        # item P1 (round 5): name WHY, never the old bare "mode change denied;
        # unchanged" - `apply_mode_change` only ever returns None on a refused
        # lowering (raising is always frictionless), so this is unconditionally
        # accurate. Round 8 item P1: with NOTHING enrolled, "then retry" was a
        # second hop the user had to discover on their own - a bare retry
        # fails closed again with no possession factor to satisfy the gate.
        # Name the whole path in one line instead. With a factor already
        # enrolled, a retry genuinely is the whole fix (supply the code/
        # confirm this time), so that message stays as-is.
        if totp.is_enrolled() or password.is_enrolled():
            typer.echo(
                "error: lowering needs a possession factor - run 'doberman password set' "
                "first, then retry",
                err=True,
            )
        else:
            typer.echo(
                "error: lowering needs a possession factor: run 'doberman password set', "
                f"then 'doberman mode {name}'",
                err=True,
            )
        raise typer.Exit(code=1)
    typer.echo(f"mode set to {saved}")


@app.command("policy-file", rich_help_panel="Policy")
def policy_file(
    accept: bool = typer.Option(
        False, "--accept", help="Approve a pending drop, gated behind a possession factor."
    ),
    path: str = typer.Option(".", "--path", "-p", help="Repository root."),
) -> None:
    """Show ``doberman.policy.yaml``'s status, or accept a pending drop (#147).

    ``doberman.policy.yaml`` at the repo root is a team-committed policy file:
    its ``blocked``/``sensitive`` globs are resolved into every action decision
    alongside the local role. Raise-only across file EDITS too -- a file that
    drops a glob the last-approved version enforced never silently loosens
    what is blocked/sensitive; the stricter, pinned set stays in force until a
    human explicitly accepts the drop here. Accepting is gated the same way as
    `doberman mode`/`doberman memory reset`: confirmation of the rendered diff
    plus the strongest enrolled possession factor (a 2FA code if enrolled,
    otherwise the local password) -- there is no `--yes` bypass and no
    confirm-only path.
    """
    file_snapshot, _digest, rejected, reason = load_raw_file(path)
    pin = read_pin(path)
    pin_corrupt = pin is PIN_CORRUPT
    pin_snapshot = (
        PolicySnapshot(blocked_globs=pin["blocked"], sensitive_globs=pin["sensitive"])
        if isinstance(pin, dict)
        else PolicySnapshot()
    )

    if not accept:
        present = (Path(path) / POLICY_FILE_NAME).exists()
        typer.echo(f"{POLICY_FILE_NAME}: {'present' if present else 'absent'}")
        if rejected:
            # A rejected file (unreadable/malformed) is NOT the same as a
            # legitimately empty one -- reporting "Applied: 0" here would let
            # a one-character typo read as an intentional empty policy, and
            # nothing is "pending" for a file that was never actually parsed.
            typer.echo(f"{POLICY_FILE_NAME}: rejected ({reason})")
            return
        typer.echo(
            f"Applied: {len(file_snapshot.blocked_globs)} blocked, "
            f"{len(file_snapshot.sensitive_globs)} sensitive glob(s)."
        )
        dropped = (set(pin_snapshot.blocked_globs) | set(pin_snapshot.sensitive_globs)) - (
            set(file_snapshot.blocked_globs) | set(file_snapshot.sensitive_globs)
        )
        if dropped:
            typer.echo(
                f"Pending: {len(dropped)} glob(s) still enforced from the last approval but "
                f"no longer in the file: {', '.join(sorted(dropped))}. Run `doberman "
                "policy-file --accept` to approve the drop."
            )
        return

    if rejected:
        # Refuse outright: nothing was actually decided, so there is nothing
        # to gate or ledger, and definitely nothing to pin -- the failure
        # mode this guards is `--accept` writing an EMPTY pin from a
        # malformed file and disarming enforcement.
        typer.echo(f"error: {POLICY_FILE_NAME} rejected ({reason}); nothing to accept", err=True)
        raise typer.Exit(code=1)

    # Same glob-keyed view load_file_policy() uses for its own raise-only
    # check, so the loader and this gate always agree on what's a drop.
    before = glob_state_map(pin_snapshot)
    after = glob_state_map(file_snapshot)

    classification = classify_change(before, after)
    if not pin_corrupt and classification is not Classification.weaken:
        typer.echo("nothing to accept")
        raise typer.Exit(code=0)
    if pin_corrupt:
        # The prior approved state is unknown, not merely empty --
        # classify_change can only ever call an empty "before" a strengthen,
        # never a weaken, but re-pinning from an unreadable pin must not be
        # waved through as if it were a verified strengthening. Route it
        # through the same confirm + possession-factor gate as any other
        # weaken, and record it as one.
        classification = Classification.weaken

    if not totp.is_enrolled() and not password.is_enrolled():
        # Same check `memory reset`/`taint clear` make before ever rendering a
        # diff: with nothing enrolled the gate can never succeed regardless of
        # how confirm() is answered, so deny right away instead of showing a
        # WEAKENING diff for a decision the possession-factor step could never
        # actually reach.
        typer.echo(
            "error: accepting doberman.policy.yaml requires an enrolled possession "
            "factor - run `doberman 2fa setup` or `doberman password set` first",
            err=True,
        )
        asyncio.run(
            record_change(
                before,
                after,
                classification,
                "accept doberman.policy.yaml",
                repo_root=path,
                approved=False,
                method="no_factor_enrolled",
            )
        )
        raise typer.Exit(code=1)

    approved, method = _run_weaken_gate(before, after, "accept doberman.policy.yaml", CliPrompter())
    asyncio.run(
        record_change(
            before,
            after,
            classification,
            "accept doberman.policy.yaml",
            repo_root=path,
            approved=approved,
            method=method,
        )
    )
    if not approved:
        typer.echo(f"error: doberman.policy.yaml accept denied ({method}); unchanged", err=True)
        raise typer.Exit(code=1)

    write_pin(path, file_snapshot)
    typer.echo(
        f"doberman.policy.yaml accepted; pin updated ({len(file_snapshot.blocked_globs)} "
        f"blocked, {len(file_snapshot.sensitive_globs)} sensitive glob(s))."
    )


_ENFORCEMENT_STATES = ("enforce", "monitor", "off")


@app.command(rich_help_panel="Policy internals")
def enforcement(
    state: str = typer.Argument(None, help="Enforcement state to set (enforce/monitor/off)."),
    path: str = typer.Option(".", "--path", "-p", help="Repository root."),
) -> None:
    """Show or set the enforcement dial (enforce / monitor / off).

    Orthogonal to the strictness ``mode``: this decides whether Doberman *acts*
    on a discretionary verdict (``enforce``, the default) or only observes
    (``monitor`` records what would have happened; ``off`` skips the discretionary
    layer). The objective floor (secret exfil, destructive commands, ...) stays
    live in every state.

    Turning the dial DOWN is a weaken: it is confirmed -- plus the strongest
    enrolled possession factor (a 2FA code if enrolled, else the local password)
    -- and recorded in the append-only policy-change ledger. With neither factor
    enrolled the change fails closed (run ``doberman password set`` first).
    Re-arming (``-> enforce``) is a strengthen and applies automatically. A
    softened state is honored only while the ledger confirms it; hand-editing
    ``policies.yaml`` is clamped back to ``enforce`` (fail closed). With no
    argument, prints the current on-disk state.
    """
    current, _expires, _revert = load_enforcement(path)
    if state is None:
        typer.echo(current)
        return
    new = state.strip().lower()
    if new not in _ENFORCEMENT_STATES:
        typer.echo(
            f"error: unknown enforcement state {state!r}; "
            f"choose one of {', '.join(_ENFORCEMENT_STATES)}",
            err=True,
        )
        raise typer.Exit(code=2)
    if new == current:
        typer.echo(f"enforcement already {current}")
        return
    # Route through the gated chokepoint: it confirms a soften behind the
    # strongest enrolled possession factor (fails closed if none is enrolled),
    # auto-approves a re-arm, and records every attempt to the ledger. Persist the
    # new state ONLY when it approved, and persist the exact fields the ledger just
    # recorded so the read-side effective_enforcement clamp confirms the soften.
    outcome = asyncio.run(
        apply_enforcement_change(
            {"enforcement": current},
            {"enforcement": new},
            "doberman enforcement CLI",
            repo_root=path,
        )
    )
    if not outcome.approved:
        typer.echo("error: enforcement change denied; unchanged", err=True)
        raise typer.Exit(code=1)
    doc = load_policy(path) or recommend_policy()
    save_policy(doc.with_enforcement(new), path, ledger_ts=outcome.ts)
    typer.echo(f"enforcement set to {new}")


@role_app.command("enable-default")
def role_enable_default(
    path: str = typer.Option(".", "--path", "-p", help="Repository root."),
) -> None:
    """Turn on the built-in opt-in least-privilege default role (D1).

    Activates the packaged ``"default"`` role (see ``builtin_roles.yaml``)
    whenever this repo has no explicit ``.doberman/role.yaml`` — an explicit
    role file always takes precedence. Enabling is a strengthen (adds a role
    boundary that wasn't enforced before) and applies immediately, no gate.
    """
    was = default_role_enabled(path)
    if was:
        typer.echo("the default role is already enabled")
        return
    # A strengthen: apply_change auto-approves (no gate) and still records the
    # attempt to the append-only ledger.
    outcome = asyncio.run(
        apply_change(
            {"default_role_enabled": was},
            {"default_role_enabled": True},
            "doberman role enable-default CLI",
            repo_root=path,
        )
    )
    save_default_role_enabled(True, path, ledger_ts=outcome.ts)
    typer.echo("the built-in default role is now enabled (used when no role.yaml is set)")


@role_app.command("disable-default")
def role_disable_default(
    path: str = typer.Option(".", "--path", "-p", help="Repository root."),
) -> None:
    """Turn off the built-in opt-in least-privilege default role (D1).

    Disabling removes an active role boundary — a ``weaken`` — so it is gated
    behind the strongest enrolled possession factor (a 2FA code if enrolled,
    otherwise the Doberman password set via ``doberman password set``); with
    neither enrolled the change fails closed (denied, nothing changes).
    """
    was = default_role_enabled(path)
    if not was:
        typer.echo("the default role is already disabled")
        return
    outcome = asyncio.run(
        apply_change(
            {"default_role_enabled": was},
            {"default_role_enabled": False},
            "doberman role disable-default CLI",
            repo_root=path,
        )
    )
    if not outcome.approved:
        typer.echo("error: disabling the default role was denied; unchanged", err=True)
        raise typer.Exit(code=1)
    save_default_role_enabled(False, path, ledger_ts=outcome.ts)
    typer.echo("the built-in default role is now disabled")


@app.command(rich_help_panel="Policy internals")
def prefs(
    dimension: str = typer.Argument(
        None, help=f"Preference dimension to set ({', '.join(DIMENSIONS)})."
    ),
    value: float = typer.Argument(None, help="New weight in [0, 1]."),
    path: str = typer.Option(".", "--path", "-p", help="Repository root."),
) -> None:
    """Show or set the subjective preference vector (SL5).

    With no arguments, prints the active vector and which mode preset it
    matches (if any). Weights tune SUBJECTIVE step-up propensity only - the
    objective hard-block floor is unaffected by every weight. Lowering a
    weight requires a possession factor — a 2FA code if enrolled, otherwise
    your Doberman password (set via `doberman password set`). Raising is always frictionless.
    """
    if dimension is None:
        vector = load_preferences(path)
        preset = preset_name(vector)
        typer.echo("Doberman preference vector")
        typer.echo("=" * 32)
        for name in DIMENSIONS:
            typer.echo(f"{name:<23} {getattr(vector, name):.2f}")
        typer.echo(f"preset: {preset or '(custom mix)'}")
        return
    if value is None:
        typer.echo(
            "error: provide a value in [0, 1] (e.g. `doberman prefs confidentiality 0.8`)", err=True
        )
        raise typer.Exit(code=2)
    current = load_preferences(path)
    try:
        updated = current.with_weight(dimension, value)
    except (KeyError, ValueError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    outcome = asyncio.run(
        apply_preferences_change(
            current.to_mapping(),
            updated.to_mapping(),
            "doberman prefs CLI",
            repo_root=path,
        )
    )
    if not outcome.approved:
        typer.echo("error: preference change denied; unchanged", err=True)
        raise typer.Exit(code=1)
    save_preferences(updated, path, ledger_ts=outcome.ts)
    typer.echo(f"{dimension} set to {value:.2f}")


@app.command("egress-velocity", rich_help_panel="Policy internals")
def egress_velocity(
    knob: str = typer.Argument(
        None,
        help="Threshold to set: burst, volume-bytes, or fanout.",
    ),
    value: int = typer.Argument(None, help="New integer value (positive)."),
    path: str = typer.Option(".", "--path", "-p", help="Repository root."),
) -> None:
    """Show or set the egress-velocity detection thresholds (RB.6).

    With no arguments, prints the three active thresholds and the built-in
    defaults they override (if any).

    The three knobs and their security direction:

    \b
      burst        max connection events before a burst signal trips (lower = tighter)
      volume-bytes max bytes sent before a volume signal trips      (lower = tighter)
      fanout       max unique destination hosts before fan-out trips (lower = tighter)

    Tightening (lowering a threshold relative to the current stored value)
    is frictionless. Loosening (raising it) requires a possession factor —
    a TOTP code if enrolled, otherwise your Doberman password — because a
    looser threshold means fewer egress anomalies are caught.
    """
    doc = load_policy(path) or recommend_policy()
    current_thresholds = doc.egress_velocity_thresholds or VelocityThresholds()

    if knob is None:
        typer.echo("Egress-velocity thresholds")
        typer.echo("=" * 32)
        typer.echo(f"{'burst':<23} {current_thresholds.burst}  (built-in: {_BURST_THRESHOLD})")
        typer.echo(
            f"{'volume-bytes':<23} {current_thresholds.volume_bytes}"
            f"  (built-in: {_VOLUME_THRESHOLD_BYTES})"
        )
        typer.echo(f"{'fanout':<23} {current_thresholds.fanout}  (built-in: {_FANOUT_THRESHOLD})")
        return

    knob = knob.lower().replace("_", "-")
    _VALID_KNOBS = {"burst", "volume-bytes", "fanout"}
    if knob not in _VALID_KNOBS:
        typer.echo(
            f"error: unknown knob {knob!r}; choose from: {', '.join(sorted(_VALID_KNOBS))}",
            err=True,
        )
        raise typer.Exit(code=2)

    if value is None:
        typer.echo(
            f"error: provide a value (e.g. `doberman egress-velocity {knob} 10`)",
            err=True,
        )
        raise typer.Exit(code=2)
    if value <= 0:
        typer.echo("error: value must be a positive integer", err=True)
        raise typer.Exit(code=2)

    # Build the updated VelocityThresholds from the current effective values.
    before = {
        "burst": current_thresholds.burst,
        "volume_bytes": current_thresholds.volume_bytes,
        "fanout": current_thresholds.fanout,
    }
    # Normalise the CLI knob name to the internal dict key.
    key = knob.replace("-", "_")
    after = {**before, key: value}

    outcome = asyncio.run(
        apply_egress_velocity_change(
            before,
            after,
            f"doberman egress-velocity CLI: {knob}={value}",
            repo_root=path,
        )
    )
    if not outcome.approved:
        typer.echo("error: egress-velocity change denied; unchanged", err=True)
        raise typer.Exit(code=1)

    updated_thresholds = VelocityThresholds(
        burst=after["burst"],
        volume_bytes=after["volume_bytes"],
        fanout=after["fanout"],
    )
    updated_doc = doc.with_egress_velocity_thresholds(updated_thresholds)
    save_policy(updated_doc, path, ledger_ts=outcome.ts)
    typer.echo(f"{knob} set to {value}")


@app.command("message-tone", rich_help_panel="Policy internals")
def message_tone(
    tone: str = typer.Argument(None, help=f"New tone ({', '.join(MESSAGE_TONES)})."),
    path: str = typer.Option(".", "--path", "-p", help="Repository root."),
) -> None:
    """Show or set the AUTH challenge message tone (S1; cosmetic display only).

    With no argument, prints the active tone. "human" (the default) renders a
    plain, friendly challenge; "technical" keeps the original detailed format.
    This never changes what is evaluated, blocked, or logged — reason codes
    stay on every decision either way — so, unlike `prefs`/`mode`, it needs no
    possession factor to change.
    """
    if tone is None:
        typer.echo(load_message_tone(path))
        return
    try:
        saved = save_message_tone(tone, path)
    except ValueError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(f"message tone set to {saved}")


def _hook_install_states(path: str) -> list[tuple[str, str, bool]]:
    """Per-scope Doberman hook install state, Claude AND Codex alike.

    Round 8 item P0: sourced from :func:`doberman.hosthooks.install_codex.protection_state`,
    the one predicate ``doctor`` already used (its "Host hooks"/"Hook command"
    checks) so a Codex-only wired repo reads as protected here too instead of
    only in ``doctor`` — the two can no longer drift out of sync. Kept as a
    thin wrapper so ``status`` (and its tests) keep a stable name to monkeypatch.
    """
    from doberman.hosthooks.install_codex import protection_state

    _protected, _reason, hooks = protection_state(path)
    return hooks


def _status_payload(path: str) -> dict:
    """Collect the same redacted data the text and JSON status views share.

    Nothing secret-shaped is included: enrollment is a boolean, elevations carry
    ids/scopes/expiry only, decisions carry ts/verdict/reason codes only.
    """
    from doberman.storage.policy_catalogue import current_snapshot, policy_version

    role = load_active_role(path)
    doc = load_policy(path)
    vector = load_preferences(path)
    mode = load_mode(path)
    tone = load_message_tone(path)
    # Read-only: unlike `doctor`'s "Policy version" check, `status` never
    # records an observation - it only computes the id (pure hashing, no I/O).
    snapshot = current_snapshot(path)
    policy_version_full = policy_version(snapshot) if snapshot is not None else None
    twofa = totp.is_enrolled()
    password_enrolled = password.is_enrolled()
    grants = asyncio.run(active_elevations(path, datetime.now(timezone.utc)))
    taints = asyncio.run(read_taint(path, entity_scope(path)))
    hook_states = _hook_install_states(path)
    recent_rows = asyncio.run(read_decisions(path, limit=5))
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    missed_challenges = 0
    for row in asyncio.run(read_decisions(path, limit=200)):
        if row.get("auth_result") != TIMEOUT_METHOD:
            continue
        try:
            occurred_at = datetime.fromisoformat(row["ts"])
            if occurred_at.tzinfo is not None and occurred_at >= cutoff:
                missed_challenges += 1
        except (TypeError, ValueError):
            continue

    policy: dict | None
    if doc is None:
        policy = None
    else:
        enabled = sum(1 for it in doc.items if it.enabled)
        policy = {"enabled": enabled, "total": len(doc.items)}

    recent_decisions: list[dict] = []
    for row in recent_rows:
        try:
            reasons = json.loads(row["reason_codes_json"] or "[]")
        except json.JSONDecodeError:
            reasons = []
        recent_decisions.append(
            {
                "ts": row["ts"],
                "final_verdict": row["final_verdict"],
                "reason_codes": reasons,
            }
        )

    return {
        "version": 1,
        "path": path,
        "doberman_version": __version__,
        "role": role.name if role else None,
        "mode": mode,
        "message_tone": tone,
        "prefs": {name: getattr(vector, name) for name in DIMENSIONS},
        "prefs_preset": preset_name(vector) or "custom",
        "policy": policy,
        "policy_version": policy_version_full,
        "twofa": twofa,
        "password": password_enrolled,
        "elevations": [
            {
                "id": grant.id,
                "scope_glob": grant.scope_glob,
                "expires_at": grant.expires_at.isoformat(),
                "single_use": grant.single_use,
            }
            for grant in grants
        ],
        "taint": dict(taints) if taints else {},
        "hooks": [
            {"scope": scope, "path": settings_path, "installed": installed}
            for scope, settings_path, installed in hook_states
        ],
        "excluded_from_global": is_excluded(path),
        "recent_decisions": recent_decisions,
        "missed_challenges_24h": missed_challenges,
    }


def _protected_line(payload: dict) -> str:
    """The headline verdict: hooks installed for at least one host AND
    `doberman` resolvable on this shell's PATH - the same two facts `doctor`'s
    "Host hooks"/"Hook command" checks diagnose, condensed to one line."""
    any_installed = any(hook["installed"] for hook in payload["hooks"])
    doberman_on_path = shutil.which("doberman") is not None
    if any_installed and doberman_on_path:
        return "Protected: yes"
    if not any_installed:
        return "Protected: no - no hooks installed for any host (run `doberman setup`)"
    return (
        "Protected: no - `doberman` is not on PATH, so the installed hooks cannot run it "
        "(fix your PATH, then run `doberman doctor`)"
    )


def _render_status_text(payload: dict) -> None:
    """Human view: `_section`-grouped, same grammar `setup`/`doctor` use (item 2).

    Layout: the "Protected: ..." headline, then the version/role identity
    lines, then four sections - Hooks, Policy (mode/prefs/policy version,
    shortened; the full hash is JSON-only), Auth (2FA/password/elevations/
    taint), and Health (one line pointing at `doberman doctor` for detail) -
    followed by Recent decisions, which stays its own trailing block since it
    is activity history, not a health/auth/policy fact.
    """
    modes = ", ".join(m.value for m in SecurityMode)
    typer.echo(_protected_line(payload))
    typer.echo("")
    typer.echo("Doberman status")
    typer.echo("=" * 32)
    doberman_version = payload["doberman_version"]

    role = payload["role"]
    typer.echo(f"Role:   {role if role else '(none - role enforcement off)'}")

    # -- Hooks --
    typer.echo("")
    typer.echo(_section("Hooks"))
    # Same cheap check `doctor`'s "Hook command" uses: an installed hook that
    # calls a `doberman` not on THIS shell's PATH would go unmediated.
    doberman_on_path = shutil.which("doberman") is not None
    for hook in payload["hooks"]:
        state = "installed" if hook["installed"] else "not installed"
        path_hint = "" if doberman_on_path or not hook["installed"] else "  (not on PATH)"
        typer.echo(f"  {hook['scope']:<8} {hook['path']}  [{state}]{path_hint}")
    if payload.get("excluded_from_global"):
        typer.echo("  excluded from global/Codex-user hooks (run `doberman install-hooks` to undo)")

    # -- Policy --
    typer.echo("")
    typer.echo(_section("Policy"))
    typer.echo(f"Mode:   {payload['mode']}  (of: {modes})")
    typer.echo(f"Messages: {payload['message_tone']}  (set via `doberman message-tone`)")
    prefs = payload["prefs"]
    typer.echo(
        "Prefs:  "
        + "  ".join(f"{name}={prefs[name]:.2f}" for name in DIMENSIONS)
        + f"  (preset: {payload['prefs_preset']})"
    )
    policy = payload["policy"]
    if policy is None:
        typer.echo("Policy: (none saved - run `doberman review --yes`)")
    else:
        typer.echo(f"Policy: {policy['enabled']}/{policy['total']} items enabled")
    version_full = payload.get("policy_version")
    # Shortened to 8 hex chars here; `--json`'s `policy_version` carries the
    # full pv1:<sha256> id (item 2).
    version_short = f"{version_full[:12]}..." if version_full else "(unavailable)"
    typer.echo(f"Policy version: {version_short}")
    # item 9 (round 5): the Doberman package version moves below the
    # "Protected: ..." headline context, into the section it's closest kin
    # to ("Policy version" right above it) rather than sitting right under
    # the ASCII-art header before any real content.
    if doberman_version == "0.0.0+unknown":
        # Matches the sentinel doberman.__version__ falls back to when the
        # package metadata can't be found (running straight from a source
        # checkout, no install) - "0.0.0+unknown" reads as a broken install.
        typer.echo("Version: unknown (source checkout)")
    else:
        typer.echo(f"Version: {doberman_version}")

    # -- Auth --
    typer.echo("")
    typer.echo(_section("Auth"))
    twofa_status = "yes" if payload["twofa"] else "no"
    typer.echo(f"2FA:    {twofa_status} (optional; run `doberman 2fa setup`)")
    enrolled = "yes" if payload["password"] else "no (run `doberman password set`)"
    typer.echo(f"Password: {enrolled}")
    elevations = payload["elevations"]
    if not elevations:
        typer.echo("Elevations: (none active)")
    else:
        typer.echo(f"Elevations: {len(elevations)} active")
        for grant in elevations:
            kind = "single-use" if grant["single_use"] else "reusable"
            typer.echo(
                f"  {grant['id']}  {grant['scope_glob']}  (expires {grant['expires_at']}; {kind})"
            )
    taint = payload["taint"]
    if not taint:
        typer.echo("Taint: (none)")
    else:
        typer.echo(f"Taint: {', '.join(f'{kind}={count}' for kind, count in taint.items())}")

    # -- Health --
    typer.echo("")
    typer.echo(_section("Health"))
    typer.echo("Health: run `doberman doctor` for the full checklist.")

    typer.echo("")
    typer.echo("Recent decisions:")
    recent = payload["recent_decisions"]
    if not recent:
        typer.echo("  (no decisions recorded yet)")
    else:
        for row in recent:
            reasons = ", ".join(row["reason_codes"]) or "-"
            typer.echo(f"  {row['ts']}  {verdict_label_str(row['final_verdict'])}  {reasons}")

    missed = payload["missed_challenges_24h"]
    if missed:
        typer.echo("")
        typer.echo(f"warning: {missed} challenge(s) auto-denied in the last 24h - see doberman log")


@app.command(rich_help_panel="Daily")
def status(
    path: str = typer.Option(".", "--path", "-p", help="Repository root."),
    as_json: bool = typer.Option(
        False,
        "--json",
        help="Emit one deterministic JSON document on stdout instead of the sectioned text view.",
    ),
) -> None:
    """Show the active role, security mode, policy summary, hook install state,
    taint state, and the most recent decisions."""
    payload = _status_payload(path)
    if as_json:
        # Same style as ``scan --json`` / ``doctor --json`` (#178 / #179).
        typer.echo(json.dumps(payload, sort_keys=True, separators=(",", ":")))
        return
    _render_status_text(payload)
    # Passive, best-effort upgrade nudge (never on --json). Refreshes in the
    # background and shows the cached result on the next run — never blocks status.
    from doberman import update_check

    update_check.refresh_async()
    notice = update_check.pending_notice()
    if notice:
        typer.echo("")
        typer.echo(notice)


@app.command(rich_help_panel="Getting started")
def update() -> None:
    """Check PyPI for a newer Doberman and show the upgrade command.

    Read-only: it never installs anything, only tells you the ``pip`` command to
    run. Honours ``DO_NOT_TRACK`` / ``CI`` / ``DOBERMAN_UPDATE_CHECK=off``.
    """
    from doberman import update_check

    reason = update_check.disabled_reason()
    if reason:
        typer.echo(f"Update check is off ({reason}).")
        typer.echo(f"You have {__version__}. Check manually with: {update_check.UPGRADE_HINT}")
        return
    latest = update_check.refresh(force=True)
    if latest is None:
        typer.echo(f"You have {__version__}. Could not reach PyPI to check for updates.")
        return
    if update_check.is_newer(latest, __version__):
        typer.echo(f"A new version is available: {latest} (you have {__version__}).")
        typer.echo(f"Upgrade with: {update_check.UPGRADE_HINT}")
    else:
        typer.echo(f"You're on the latest version ({__version__}).")


@app.command(rich_help_panel="Getting started")
def doctor(
    path: str = typer.Option(".", "--path", "-p", help="Repository root."),
    as_json: bool = typer.Option(
        False,
        "--json",
        help="Emit one JSON document on stdout; health exit codes are unchanged.",
    ),
) -> None:
    """Run a read-only health self-check and print a green/red checklist.

    Answers "is Doberman actually wired up and healthy?" in one shot: host hooks,
    config, the decision DB, 2FA, the enforcement dial + strictness mode, and the
    fingerprint key. It only *diagnoses* - it never changes state, except that the
    Policy version check records the observed policy version into
    `.doberman/policies.db` (itself a diagnostic record; it never touches policy,
    decisions, or enforcement). Exits non-zero if any critical check
    (hooks / hook command on PATH / config / DB) is not healthy, so it is
    script-friendly (`doberman doctor && ...`).
    """
    from doberman.cli.doctor import CheckStatus, critical_failures, run_checks

    # ASCII marks only: CLI output must survive a cp1252 console (see setup wizard).
    marks = {CheckStatus.OK: "[ ok ]", CheckStatus.WARN: "[warn]", CheckStatus.FAIL: "[FAIL]"}

    results = run_checks(path)
    failures = critical_failures(results)
    if as_json:
        payload = {
            "version": 1,
            "path": path,
            "ok": not failures,
            "checks": [
                {
                    "name": r.name,
                    "status": r.status.value if hasattr(r.status, "value") else str(r.status),
                    "detail": r.detail,
                }
                for r in results
            ],
            "critical_failures": [f.name for f in failures],
        }
        typer.echo(json.dumps(payload, sort_keys=True, separators=(",", ":")))
        if failures:
            raise typer.Exit(code=1)
        return

    typer.echo("Doberman doctor")
    typer.echo("=" * 32)
    # Same four-section grammar `status` uses (item 2): Hooks, Policy, Auth,
    # Health - a check not named below falls into Health, the catch-all for
    # optional extras/adapters. Ordered within each section to match
    # `run_checks`'s existing order, so no test pinning check ORDER breaks.
    section_for = {
        "Host hooks": "Hooks",
        "Hook command": "Hooks",
        "Hook integrity": "Hooks",
        "Config": "Policy",
        "Enforcement": "Policy",
        "Policy version": "Policy",
        "2FA": "Auth",
        "Phone approvals": "Auth",
        "Password": "Auth",
        "Fingerprint key": "Auth",
    }
    by_section: dict[str, list] = {}
    for result in results:
        by_section.setdefault(section_for.get(result.name, "Health"), []).append(result)
    for section_name in ("Hooks", "Policy", "Auth", "Health"):
        section_results = by_section.get(section_name, [])
        if not section_results:
            continue
        typer.echo("")
        typer.echo(_section(section_name))
        for result in section_results:
            header = f"{marks[result.status]} {result.name}: "
            # round 7 item 7: a hanging indent, so a wrapped remedy (many
            # detail strings ARE a remedy sentence, e.g. the Hook command
            # FAIL) never starts flush at column 0 on a narrow terminal -
            # continuation lines land indented under the mark instead.
            for line in wrap_detail(f"{header}{result.detail}", indent=0, hang=7):
                typer.echo(line)

    typer.echo("")
    if failures:
        # item 2: name the failing checks instead of a bare count, so the
        # closing line is useful even piped through `2>/dev/null`.
        names = ", ".join(f.name for f in failures)
        typer.echo(
            f"error: {len(failures)} critical: {names} - Doberman may not be protecting you."
        )
        raise typer.Exit(code=1)
    typer.echo("All critical checks passed.")


@hook_app.command("pre")
def hook_pre() -> None:
    """Claude Code PreToolUse hook - gate one tool call (allow / ask / deny).

    Reads the harness hook payload as JSON on stdin and writes the hook decision
    as JSON to stdout (nothing on a PASS - Doberman is raise-only and never
    suppresses the harness's own prompts). Runs only the fast deterministic
    objective floor (no numpy/scipy/river), so it adds minimal latency to every
    tool call, and fails closed (deny) on any malformed input or engine error.

    Wire it into Claude Code's settings (or run ``doberman install-hooks``).
    """
    # This process's stdout IS the harness's hook channel (it parses our JSON), so
    # pin every doberman.* log to stderr and strip any stdout handler first - a
    # stray log line on stdout would corrupt the decision the harness reads (and a
    # malformed hook response can fail open). Same guard the `serve` command uses.
    _configure_stderr_logging()
    # Imported here, not at module scope, so the other CLI commands don't load
    # the decision path on every `--help`/`status`/`log` invocation.
    from doberman.hosthooks.claude_code import run_pre_hook

    # Raw bytes: run_pre_hook decodes UTF-8 itself (Cursor's Third Party Hooks
    # feature calls this same command with cursor-agent's BOM-prefixed payload —
    # a cp1252 console would turn it into mojibake and fail every hook closed).
    stream = getattr(sys.stdin, "buffer", None)
    out = run_pre_hook(stream.read() if stream is not None else sys.stdin.read())
    if out is not None:
        # The harness parses stdout as JSON; write ONLY the decision there, with a
        # trailing newline so a line-delimited reader sees a complete record.
        sys.stdout.write(out + "\n")
    raise typer.Exit(0)


@hook_app.command("post")
def hook_post() -> None:
    """Claude Code PostToolUse hook - scan tool output for secrets; record history.

    Reads the harness hook payload as JSON on stdin.  If the tool output
    contains credential-like material, writes ``{"decision":"block","reason":"..."}``
    to stdout (exit 0) so Claude never uses the tainted result.  On a clean
    output (or a non-gated / internal tool) nothing is written to stdout.

    History is best-effort: the call is always recorded in the local decision
    log when the tool is a gated built-in or an MCP tool, but a history write
    failure never blocks or raises.

    Runs only the fast deterministic objective floor (no numpy/scipy/river),
    fails closed on any malformed input or engine error.

    Wire it into Claude Code's settings (or run ``doberman install-hooks``).
    """
    _configure_stderr_logging()
    from doberman.hosthooks.claude_code import run_post_hook

    # Raw bytes: same reasoning as `hook pre` above (Cursor's compat path calls
    # this command too, and its payloads carry a UTF-8 BOM).
    stream = getattr(sys.stdin, "buffer", None)
    out = run_post_hook(stream.read() if stream is not None else sys.stdin.read())
    if out is not None:
        sys.stdout.write(out + "\n")
    raise typer.Exit(0)


@hook_app.command("openclaw")
def hook_openclaw() -> None:
    """OpenClaw ``before_tool_call`` plugin hook - gate one tool call.

    Reads the event as JSON on stdin (see ``adapters/openclaw/``) and ALWAYS
    writes exactly one JSON verdict to stdout - unlike the Claude Code hooks
    above, this bridge is a fresh subprocess spawned per call under a hard
    timeout on the OpenClaw side, so silence would be indistinguishable from a
    hang and the shim would fail closed on every benign PASS too.

    Runs only the fast deterministic objective floor (no numpy/scipy/river),
    fails closed (``{"verdict":"block",...}``) on any malformed input or
    engine error.

    Wire it into an OpenClaw gateway via the ``adapters/openclaw/`` plugin
    (see its README for install + the mandatory "verify it's live" canary).
    """
    _configure_stderr_logging()
    # Imported here, not at module scope, so the other CLI commands don't load
    # the decision path on every `--help`/`status`/`log` invocation.
    from doberman.hosthooks.openclaw import run_before_tool_call_hook

    out = run_before_tool_call_hook(sys.stdin.read())
    sys.stdout.write(out + "\n")
    raise typer.Exit(0)


@hook_app.command("codex-pre")
def hook_codex_pre() -> None:
    """Codex CLI PreToolUse hook - gate one tool call (allow / ask / deny).

    Reads the Codex hook payload as JSON on stdin and writes the hook decision
    as JSON to stdout (nothing on a PASS - Doberman is raise-only). Codex's hook
    layer is a Claude Code compatibility shim, so this shares the same decision
    spine and deny shape as ``hook pre``; it runs only the fast deterministic
    objective floor (no numpy/scipy/river) and fails closed on any malformed
    input or engine error.

    Wire it in with ``doberman install-hooks --host codex``.
    """
    _configure_stderr_logging()
    from doberman.hosthooks.codex import run_codex_pre

    out = run_codex_pre(sys.stdin.read())
    if out is not None:
        sys.stdout.write(out + "\n")
    raise typer.Exit(0)


@hook_app.command("cursor")
def hook_cursor() -> None:
    """Cursor hook - gate one Cursor event as allow / deny.

    One command for every gating event (``preToolUse``, ``beforeShellExecution``,
    ``beforeMCPExecution``, ``beforeReadFile``; ``sessionStart`` is acknowledged).
    Reads Cursor's hook payload as JSON on stdin (a leading UTF-8 BOM is
    tolerated) and writes Cursor's response document to stdout. A deny also
    exits 2, which Cursor treats as a block even if the document is lost. Runs
    only the fast deterministic objective floor and fails closed on any
    malformed input or engine error. Register it in ``.cursor/hooks.json`` with
    ``"failClosed": true`` (see adapters/cursor/README.md).

    Wire it in with ``doberman install-hooks --host cursor``.
    """
    _configure_stderr_logging()
    from doberman.hosthooks.cursor import run_cursor

    # Raw bytes: the adapter decodes UTF-8 itself (a cp1252 console would turn
    # cursor-agent's Windows BOM into mojibake and fail every hook closed).
    stream = getattr(sys.stdin, "buffer", None)
    text, code = run_cursor(stream.read() if stream is not None else sys.stdin.read())
    sys.stdout.write(text + "\n")
    raise typer.Exit(code)


@password_app.command("set")
def password_set(
    force: bool = typer.Option(
        False, "--force", help="Rotate an existing password after proving the current one."
    ),
) -> None:
    """Set or deliberately rotate the local password possession factor."""
    prompter = CliPrompter()
    current_password = None
    if force and password.is_enrolled():
        current_password = prompter.read_code("Enter your current Doberman password")
    new_password = prompter.read_code("Enter a new Doberman password")
    repeated_password = prompter.read_code("Enter the new Doberman password again")
    if new_password != repeated_password:
        typer.echo("error: passwords do not match", err=True)
        raise typer.Exit(code=1)
    try:
        password.enroll(
            new_password,
            force=force,
            current_password=current_password,
        )
    except (ValueError, RuntimeError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo("Password set. Stored locally with owner-only permissions; never committed.")


@twofa_app.command("setup")
def twofa_setup(
    force: bool = typer.Option(
        False, "--force", help="Rotate an existing secret (invalidates the old one)."
    ),
) -> None:
    """Enroll TOTP two-factor and print the provisioning URI for your authenticator."""
    current_code = None
    if force and totp.is_enrolled():
        current_code = CliPrompter().read_code("Current 2FA code")
    try:
        uri = totp.enroll(force=force, current_code=current_code)
    except RuntimeError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo("2FA enrolled. Add this to your authenticator app (or scan it as a QR):")
    typer.echo(uri)
    typer.echo("This secret is stored locally with owner-only permissions and is never committed.")


def _method_available(method: object) -> bool:
    """Best-effort ``is_available`` for CLI display — never raises."""
    try:
        return bool(method.is_available())  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001 — display only
        return False


@methods_app.command("list")
def twofa_methods_list() -> None:
    """List approval methods, whether each is available here, and if it's enabled."""
    from doberman.auth import approval_config
    from doberman.engine.registry import discover_approval_methods

    enabled = approval_config.enabled_methods()
    methods = discover_approval_methods()
    if not methods:
        typer.echo("No approval methods are installed; TOTP is the second factor.")
        return
    typer.echo("Approval methods (enable one to replace the 2FA code with a tap):")
    for method in methods:
        name = getattr(method, "name", "?")
        avail = "available" if _method_available(method) else "unavailable here"
        state = "ENABLED" if name in enabled else "disabled"
        typer.echo(f"  {name:16s} {state:9s} ({avail})")
    if enabled:
        typer.echo(
            f"\nPreference order: {', '.join(enabled)} — first available wins, TOTP is the fallback."
        )


@methods_app.command("enable")
def twofa_methods_enable(
    name: str = typer.Argument(..., help="Method name, e.g. windows_hello."),
) -> None:
    """Enable an approval method (opt-in). It replaces the 2FA code when available."""
    from doberman.auth import approval_config
    from doberman.engine.registry import discover_approval_methods

    known = {getattr(m, "name", None) for m in discover_approval_methods()}
    known.discard(None)
    if name not in known:
        listed = ", ".join(sorted(str(n) for n in known)) or "(none installed)"
        typer.echo(f"error: unknown method {name!r}. Installed: {listed}", err=True)
        raise typer.Exit(code=1)
    try:
        approval_config.enable(name)
    except ValueError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Enabled {name}; it will handle 2FA when available. TOTP remains the fallback.")
    if not totp.is_enrolled():
        typer.echo(
            "note: enroll TOTP too (`doberman 2fa setup`) so a fallback exists when the "
            "device is unavailable."
        )


@methods_app.command("disable")
def twofa_methods_disable(
    name: str = typer.Argument(..., help="Method name to disable."),
) -> None:
    """Disable an approval method. 2FA then falls back to the next method or TOTP."""
    from doberman.auth import approval_config

    approval_config.disable(name)
    typer.echo(f"Disabled {name}.")


@methods_app.command("status")
def twofa_methods_status() -> None:
    """Show which proof the next 2FA challenge would use."""
    from doberman.auth.approval import resolve_approval_method

    active = resolve_approval_method()
    if active is None:
        typer.echo("Active 2FA proof: TOTP code (no approval method enabled and available).")
    else:
        typer.echo(
            f"Active 2FA proof: {active.name} — a tap replaces the code; TOTP is the fallback."
        )


def _phone_send_test_notification(cfg) -> str | None:
    """Send phone approvals' connectivity test notification (no Approve/Deny
    buttons). ``None`` on success, else the one-line failure reason."""
    from doberman.auth.ntfy import NtfyChannel, NtfyUnavailable

    try:
        NtfyChannel(cfg).publish(title="Doberman", message="Doberman is connected to this phone")
    except NtfyUnavailable as exc:
        return str(exc)
    return None


@phone_app.command("setup")
def phone_setup(
    server: str = typer.Option(NTFY_DEFAULT_SERVER, "--server", help="ntfy server URL."),
    token: str = typer.Option(
        "", "--token", help="Bearer token, for a self-hosted/auth-protected server."
    ),
    wait: int = typer.Option(
        60, "--wait", help="Seconds to wait for a tap before falling back (clamped 10-300)."
    ),
    force: bool = typer.Option(False, "--force", help="Overwrite an existing config."),
) -> None:
    """Set up phone approvals: generate the topics, opt in, send a test notification."""
    from doberman.auth import approval_config, ntfy

    if ntfy.load_config() is not None and not force:
        typer.echo(
            "error: phone approvals are already configured; use --force to overwrite", err=True
        )
        raise typer.Exit(code=1)
    cfg = ntfy.new_config(server=server, token=token, wait_s=wait)
    ntfy.save_config(cfg)
    approval_config.enable(ntfy.METHOD_NAME)
    typer.echo(
        f"Subscribe on your phone: install the ntfy app, add topic {cfg.topic} on {cfg.server}"
    )
    typer.echo(f"Waiting {cfg.wait_s}s for a tap before falling back to the local prompt.")
    reason = _phone_send_test_notification(cfg)
    if reason is not None:
        typer.echo(
            f"warning: test notification failed ({reason}); config kept, run doberman phone "
            "test after subscribing"
        )


@phone_app.command("test")
def phone_test() -> None:
    """Send the phone approvals connectivity test notification (no Approve/Deny buttons)."""
    from doberman.auth import ntfy

    cfg = ntfy.load_config()
    if cfg is None:
        typer.echo("error: phone approvals are not configured; run doberman phone setup", err=True)
        raise typer.Exit(code=1)
    reason = _phone_send_test_notification(cfg)
    if reason is not None:
        typer.echo(f"error: test notification failed ({reason})", err=True)
        raise typer.Exit(code=1)
    typer.echo("Test notification sent — check your phone.")


@phone_app.command("status")
def phone_status() -> None:
    """Show whether phone approvals are on, and where they publish (never the full topics)."""
    from urllib.parse import urlparse

    from doberman.auth import approval_config, ntfy

    cfg = ntfy.load_config()
    if cfg is None or not approval_config.is_enabled(ntfy.METHOD_NAME):
        typer.echo("phone approvals: off (doberman phone setup)")
        return
    host = urlparse(cfg.server).hostname or cfg.server
    typer.echo(f"phone approvals: on — {host}, topic {cfg.topic[:4]}…, wait {cfg.wait_s} s")


@phone_app.command("off")
def phone_off() -> None:
    """Turn phone approvals off: disable the method and delete the local config."""
    from doberman.auth import approval_config, ntfy

    approval_config.disable(ntfy.METHOD_NAME)
    if ntfy.delete_config():
        typer.echo("Phone approvals disabled; config removed.")
    else:
        typer.echo("Phone approvals disabled; no config was present.")


@plugins_app.command("list")
def plugins_list() -> None:
    """List enabled plugin names, and every installed entry point across all seams.

    Installed entry points are discovered WITHOUT loading them (names only) —
    listing an untrusted plugin's presence must never import its code.
    """
    from doberman.engine import plugin_config
    from doberman.engine.registry import ALL_GROUPS, _iter_entry_points

    enabled = plugin_config.enabled_plugins()
    typer.echo("Enabled (opt-in by name): " + (", ".join(enabled) if enabled else "(none)"))
    typer.echo("\nInstalled entry points (not loaded merely to list them):")
    found = False
    for group in ALL_GROUPS:
        for entry_point in _iter_entry_points(group):
            found = True
            name = getattr(entry_point, "name", "?")
            state = "ENABLED" if name in enabled else "disabled"
            typer.echo(f"  {group:34s} {name:24s} {state}")
    if not found:
        typer.echo("  (none installed)")


@plugins_app.command("enable")
def plugins_enable(
    name: str = typer.Argument(..., help="Entry-point name to trust, e.g. my_rule."),
) -> None:
    """Enable a plugin by entry-point name. Nothing is imported until it's named here."""
    from doberman.engine import plugin_config

    try:
        names = plugin_config.enable(name)
    except ValueError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Enabled {name!r}. Enabled plugins: {', '.join(names)}")


@plugins_app.command("disable")
def plugins_disable(
    name: str = typer.Argument(..., help="Entry-point name to stop trusting."),
) -> None:
    """Disable a plugin. No registry seam will import it again."""
    from doberman.engine import plugin_config

    names = plugin_config.disable(name)
    typer.echo(f"Disabled {name!r}. Enabled plugins: {', '.join(names) if names else '(none)'}")


@twofa_app.command("remove")
def twofa_remove() -> None:
    """Remove TOTP enrollment, proving possession of the factor being dropped.

    Losing a possession factor weakens Doberman, so this needs your current 2FA
    code — the same rate-limited check that gates a rotation. Removal is
    deliberately not delegable to the password: whoever drops 2FA must hold it.
    """
    if not totp.is_enrolled():
        typer.echo("error: 2FA is not enrolled; nothing to remove", err=True)
        raise typer.Exit(code=1)
    prompter = CliPrompter()
    if not prompter.confirm(
        "Remove 2FA? Policy weakenings will then be gated by your local password instead"
    ):
        typer.echo("error: aborted; 2FA is unchanged", err=True)
        raise typer.Exit(code=1)
    current_code = prompter.read_code("Current 2FA code")
    try:
        totp.unenroll(current_code=current_code)
    except RuntimeError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo("2FA removed. Delete the Doberman entry in your authenticator app too.")
    if not password.is_enrolled():
        typer.echo(
            "warning: no possession factor is enrolled now, so every policy weakening "
            "will be denied - run `doberman password set` (or `doberman 2fa setup`) to "
            "restore one.",
            err=True,
        )


@twofa_app.command("reset-lockout")
def twofa_reset_lockout() -> None:
    """Clear the TOTP lockout early, proving possession with your password.

    Too many wrong 2FA codes lock further attempts for a short cooldown. That
    window self-recovers, so this is a convenience: prove you own this machine
    and retry now instead of waiting. It is gated on your password, not 2FA - a
    locked-out factor cannot verify itself, and someone who tripped the lockout
    by guessing codes must not be able to lift it. Clearing the counter never
    disables the rate limiter: fresh wrong codes lock it again.
    """
    if not totp.is_enrolled():
        typer.echo("error: 2FA is not enrolled; there is no lockout to reset", err=True)
        raise typer.Exit(code=1)
    if not password.is_enrolled():
        typer.echo(
            "error: clearing the 2FA lockout needs your local password, but none is "
            "enrolled. The lockout clears itself after a short cooldown - wait it out, "
            "or run `doberman password set` to enable an early reset next time.",
            err=True,
        )
        raise typer.Exit(code=1)
    current_password = CliPrompter().read_code("Doberman password")
    if not password.verify(current_password):
        typer.echo("error: incorrect password; the 2FA lockout is unchanged", err=True)
        raise typer.Exit(code=1)
    totp.reset_attempts()
    typer.echo("2FA lockout cleared. You can enter a fresh code now.")


@taint_app.command("clear")
def taint_clear(
    path: str = typer.Option(".", "--path", "-p", help="Repository root."),
) -> None:
    """Clear this repo's sticky session taint — a gated recovery action.

    Reading a secret taints a session for the rest of it (by design — a timed
    reset would just be a bypass an attacker waits out), and in strict/paranoid
    that raises every later egress to AUTH or BLOCK. This is the explicit,
    human-only escape hatch: it requires an enrolled possession factor (2FA if
    set up, otherwise your Doberman password) and clears BOTH taint stores for
    this repo. There is no confirm-only path and no silent timer.
    """
    if not totp.is_enrolled() and not password.is_enrolled():
        typer.echo(
            "error: clearing taint requires an enrolled possession factor - "
            "run `doberman 2fa setup` or `doberman password set` first",
            err=True,
        )
        raise typer.Exit(code=1)

    prompter = CliPrompter()
    try:
        approved, method = _verify_possession_factor(prompter, action_label="clearing taint")
    except Exception:  # noqa: BLE001 — any input/EOF/timeout error denies the clear
        # `_verify_possession_factor` does not guard its own prompt; its other
        # caller (`_run_weaken_gate`) wraps it for exactly this reason. A
        # non-interactive stdin raises rather than returning, and an unguarded
        # raise here would be a traceback, not a denial.
        approved, method = False, "denied"
    if not approved:
        typer.echo(f"error: taint clear denied ({method}); unchanged", err=True)
        raise typer.Exit(code=1)

    try:
        taint_rows, fingerprint_rows, untrusted_rows = asyncio.run(clear_taint(path))
    except Exception as exc:  # noqa: BLE001 — never report success on a failed clear
        typer.echo(f"error: taint clear failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    typer.echo(
        f"Taint cleared ({taint_rows} record(s), {fingerprint_rows} fingerprint(s), "
        f"{untrusted_rows} untrusted-value fingerprint(s)). "
        "This session's memory of a secret being read, or an untrusted value being seen, "
        "is gone; egress in this repo returns to the mode default until something taints it again."
    )


@tools_app.command("approve")
def tools_approve(
    tool_name: str = typer.Argument(..., help="Tool name whose last-seen schema to approve."),
    path: str = typer.Option(".", "--path", "-p", help="Repository root."),
) -> None:
    """Approve a changed MCP tool fingerprint after possession-factor verification."""
    if not totp.is_enrolled() and not password.is_enrolled():
        typer.echo(
            "error: approving a tool pin requires an enrolled possession factor - "
            "run `doberman 2fa setup` or `doberman password set` first",
            err=True,
        )
        raise typer.Exit(code=1)

    try:
        approved, method = _verify_possession_factor(
            CliPrompter(), action_label=f"approving the {tool_name} tool pin"
        )
    except Exception:  # noqa: BLE001 - any input/EOF/timeout error denies approval
        approved, method = False, "denied"
    if not approved:
        typer.echo(f"error: tool pin approval denied ({method}); unchanged", err=True)
        raise typer.Exit(code=1)

    try:
        approved_fp = asyncio.run(approve_pin(tool_name, repo_root=path))
    except Exception as exc:  # noqa: BLE001 - failed storage update is never success
        typer.echo(f"error: tool pin approval failed (error class: {type(exc).__name__})", err=True)
        raise typer.Exit(code=1) from exc
    if approved_fp is None:
        typer.echo(f"error: no last-seen pin exists for tool {tool_name}", err=True)
        raise typer.Exit(code=1)
    typer.echo(f"Tool pin approved for {tool_name}: {approved_fp}")


@approvals_app.command("status")
def approvals_status(
    path: str = typer.Option(".", "--path", "-p", help="Repository root."),
) -> None:
    """Show live count and policy TTL without exposing fingerprints."""
    seconds = load_approval_memory_seconds(path)
    live = asyncio.run(count_live_approval_memory(datetime.now(timezone.utc), repo_root=path))
    state = "enabled" if seconds else "disabled"
    typer.echo(f"Approval memory: {state}; TTL: {seconds} second(s); live entries: {live}")


@approvals_app.command("clear")
def approvals_clear(
    path: str = typer.Option(".", "--path", "-p", help="Repository root."),
) -> None:
    """Clear all exact-action approval memory (ungated strengthening)."""
    removed = asyncio.run(clear_approval_memory(path))
    typer.echo(f"Approval memory cleared ({removed} record(s)).")


@approvals_app.command("ttl")
def approvals_ttl(
    seconds: int = typer.Argument(..., min=0, max=900, help="Memory TTL in seconds (0 disables)."),
    path: str = typer.Option(".", "--path", "-p", help="Repository root."),
) -> None:
    """Set the 0-900 second TTL; raising it is a gated weakening."""
    current = load_approval_memory_seconds(path)
    if seconds > current:
        approved, method = _run_weaken_gate(
            {"approval_memory_seconds": current},
            {"approval_memory_seconds": seconds},
            "doberman approvals ttl CLI",
            CliPrompter(),
        )
        if not approved:
            typer.echo(f"error: approval-memory TTL change denied ({method}); unchanged", err=True)
            raise typer.Exit(code=1)
    doc = load_policy(path) or recommend_policy()
    save_policy(doc.with_approval_memory_seconds(seconds), path)
    typer.echo(f"Approval memory TTL set to {seconds} second(s).")


@app.command(rich_help_panel="Auth")
def revoke(
    elevation_id: str = typer.Argument(..., help="Id of the elevation to revoke."),
    path: str = typer.Option(".", "--path", "-p", help="Repository root."),
) -> None:
    """Revoke an active role elevation by id (see `doberman status`)."""
    revoked = asyncio.run(revoke_elevation(path, elevation_id))
    if revoked:
        typer.echo(f"revoked elevation {elevation_id}")
    else:
        typer.echo(f"error: no elevation with id {elevation_id}", err=True)
        raise typer.Exit(code=1)


@app.command(rich_help_panel="Daily")
def tune(
    path: str = typer.Option(".", "--path", "-p", help="Repository root."),
    json_out: bool = typer.Option(
        False, "--json", help="Emit the report + proposals as one JSON document."
    ),
    last: int = typer.Option(2000, "--last", help="Consider the most recent N decisions."),
    min_occurrences: int = typer.Option(
        5,
        "--min-occurrences",
        help="Minimum all-approved occurrences before a standing-elevation proposal is emitted.",
    ),
    accept: str = typer.Option(
        None, "--accept", help="Accept a proposal id from the last `doberman tune` report."
    ),
) -> None:
    """Friction report - interventions/session, top AUTH reasons - plus gated tuning proposals.

    Never applies anything by itself. Where an AUTH class has been approved
    every time, often enough, `doberman tune` proposes a standing, revocable,
    time-limited elevation; `--accept <id>` routes acceptance through the same
    possession-factor-gated weaken chokepoint as any other policy loosening
    (`doberman revoke <elevation-id>` reverses it early).
    """
    rows = asyncio.run(read_decisions(path, limit=max(0, last)))
    proposals = generate_proposals(rows, min_occurrences=min_occurrences)

    if accept is not None:
        proposal = next((p for p in proposals if p["id"] == accept), None)
        if proposal is None:
            typer.echo("error: unknown or stale proposal id; rerun 'doberman tune'", err=True)
            raise typer.Exit(code=1)
        typer.echo(proposal["what_would_loosen"])
        outcome = asyncio.run(
            apply_standing_elevation(
                scope_glob=proposal["target_path_class"],
                reason=f"doberman tune accept {accept}",
                repo_root=path,
                ttl_days=proposal["ttl_days"],
            )
        )
        if not outcome.approved:
            typer.echo("error: change denied; nothing granted", err=True)
            raise typer.Exit(code=1)
        grant = asyncio.run(
            grant_elevation(
                path,
                proposal["target_path_class"],
                task_id=f"tune:{accept}",
                now=datetime.now(timezone.utc),
                ttl_seconds=proposal["ttl_days"] * 86400,
            )
        )
        typer.echo(
            f"Granted standing elevation {grant.id} for {proposal['target_path_class']} "
            f"until {grant.expires_at.isoformat()}. Revoke any time: doberman revoke {grant.id}"
        )
        return

    report = build_friction_report(rows)
    if json_out:
        typer.echo(
            json.dumps(
                {**report, "proposals": proposals},
                sort_keys=True,
                separators=(",", ":"),
                default=str,
            )
        )
        return

    if not rows:
        typer.echo("(no decisions recorded yet)")
        return

    typer.echo("Doberman friction report")
    typer.echo("=" * 32)
    ips = report["interventions_per_session"]
    typer.echo(
        f"Interventions/session: {ips:.2f}" if ips is not None else "Interventions/session: n/a"
    )
    typer.echo(
        f"{report['decisions']} decisions across {report['sessions']} session(s) "
        f"({report['unsessioned_decisions']} unsessioned); {report['interventions']} intervention(s) (AUTH)"
    )
    if report["top_auth_reason_codes"]:
        typer.echo("Top AUTH reasons:")
        for code, n in report["top_auth_reason_codes"]:
            typer.echo(f"  {code}: {n}")
    if report["approval_rate_by_reason"]:
        typer.echo("Approval rate by reason:")
        for code, stats in sorted(report["approval_rate_by_reason"].items()):
            rate = f"{stats['rate']:.0%}" if stats["rate"] is not None else "n/a"
            typer.echo(f"  {code}: {stats['approved']}/{stats['n']} ({rate})")
    if report["approval_rate_by_target"]:
        typer.echo("Approval rate by target:")
        for target, stats in sorted(report["approval_rate_by_target"].items()):
            rate = f"{stats['rate']:.0%}" if stats["rate"] is not None else "n/a"
            typer.echo(f"  {target}: {stats['approved']}/{stats['n']} ({rate})")
    if report["trend"]:
        typer.echo("Recent trend:")
        for week, stats in sorted(report["trend"].items())[-8:]:
            week_ips = stats["interventions_per_session"]
            week_ips_str = f"{week_ips:.2f}/session" if week_ips is not None else "n/a"
            typer.echo(
                f"  {week}: {stats['decisions']} decisions, {stats['interventions']} interventions, "
                f"{stats['sessions']} session(s), {week_ips_str}"
            )
    if proposals:
        typer.echo("")
        typer.echo("Tuning proposals (nothing applied automatically):")
        for p in proposals:
            typer.echo(f"  [{p['id']}] {p['what_would_loosen']}")
            typer.echo(f"    why: {p['why']}")
            typer.echo(f"    To accept: doberman tune --accept {p['id']}")
        typer.echo(
            "  Accepting requires your possession factor and grants a revocable, "
            "time-limited elevation (doberman revoke <elevation-id>)."
        )


# Columns from ``_DECISION_COLUMNS`` that ``log --jsonl`` emits in addition to the
# six fields the human view shows. Every one is already redacted at write time by
# ``build_record`` — no raw target, argument, or secret reaches the table at all.
# #505 adds auth_path/human_confirmed here deliberately: they are the columns
# that say WHO resolved an authentication, and a decision log you cannot query
# for "allowed without a human" cannot answer the question #399 raised. Both are
# closed values (an AuthPath enum member; 1/0/NULL) and can never carry command
# text, so exporting them widens the stream by nothing an operator must redact.
_JSONL_EXTRA_COLUMNS = ("id", "agent_role", "risk", "auth_path", "human_confirmed")

# Keep every action type in one column even when a new enum member outgrows the
# historical 13-character values (network_request/package_install are 15).
_ACTION_WIDTH = max(len(action.value) for action in ActionType)


@app.command(rich_help_panel="Daily")
def log(
    last: int = typer.Option(20, "--last", "-n", help="Show the most recent N decisions."),
    path: str = typer.Option(".", "--path", "-p", help="Repository root."),
    jsonl: bool = typer.Option(
        False,
        "--jsonl",
        help="Emit one redacted JSON object per line (no headings; empty if none).",
    ),
    why: bool = typer.Option(
        False,
        "--why",
        help=(
            "Under each BLOCK/AUTH row, also print a one-line plain-language "
            "why plus the same Next: step the tui shows. Ignored with --jsonl."
        ),
    ),
) -> None:
    """Show the recent redacted decision log (newest first).

    Every row is already redacted - a path class, reason codes, the verdict, and
    the auth outcome. No raw target, argument, or secret is ever stored or shown.
    """
    rows = asyncio.run(read_decisions(path, limit=max(0, last)))
    if jsonl:
        for row in rows:
            # Decode structured fields; keep only the redacted representation.
            try:
                reasons = json.loads(row.get("reason_codes_json") or "[]")
            except json.JSONDecodeError:
                reasons = []
            if not isinstance(reasons, list):
                reasons = []
            record = {
                "ts": row.get("ts"),
                "final_verdict": row.get("final_verdict"),
                "action_type": row.get("action_type"),
                "target_path_class": row.get("target_path_class"),
                "reason_codes": reasons,
                "auth_result": row.get("auth_result"),
            }
            # Include other redacted columns if present. This is an allowlist on
            # purpose: a column added to the decisions table later must be opted
            # in here deliberately, rather than leaking into the stream by default.
            record.update({key: row[key] for key in _JSONL_EXTRA_COLUMNS if key in row})
            typer.echo(json.dumps(record, sort_keys=True, separators=(",", ":"), default=str))
        return
    if not rows:
        typer.echo("(no decisions recorded yet)")
        return
    typer.echo("Doberman decision log")
    typer.echo("=" * 32)
    # round 7 design critique item 6: `--why` over a window with no BLOCK/AUTH
    # row must say so explicitly rather than silently printing nothing extra -
    # a reviewer scanning for "did --why do anything here" shouldn't have to
    # infer "no" from an absence.
    any_explained = False
    for row in rows:
        target = row["target_path_class"] or "-"
        reasons = ", ".join(json.loads(row["reason_codes_json"] or "[]")) or "-"
        # A pending AUTH row (no answer yet) must never look identical to "no
        # auth step at all" - round 5 design critique item 7.
        auth = (
            f"; auth={humanize_auth_result(row['auth_result'], verdict=row['final_verdict'])}"
            if row["auth_result"] or row["final_verdict"] == "AUTH"
            else ""
        )
        # round 8 design critique item 7: the same "YYYY-MM-DD HH:MM:SS UTC"
        # format the tui's why panel shows (no microseconds) - `--jsonl`
        # keeps the raw stored `ts` string unchanged (scripts parse that one).
        typer.echo(
            f"{format_utc_timestamp(row['ts'])}  {verdict_label_str(row['final_verdict'])} "
            f"{row['action_type']:<{_ACTION_WIDTH}} {target}  [{reasons}]{auth}"
        )
        # --why (round 4 design critique item 8, round 6 item 7): a compact,
        # indented plain-language block under each BLOCK/AUTH row - the row
        # above already shows the verdict and raw reason codes, so `why_body`
        # (the "what was attempted" + "Reasons: ..." sentences, everything
        # `template_explanation` says minus the trailing technical "(Checked
        # by: ...)" aside) is what actually ADDS information, unlike the old
        # one-line `first_sentence` alone. Same "Next" remedy the tui shows,
        # so both surfaces agree.
        if why and row["final_verdict"] in ("BLOCK", "AUTH"):
            any_explained = True
            for line in wrap_detail(why_body(row)):
                typer.echo(line)
            next_line = next_step_line(row["final_verdict"], tui_hint=False)
            if next_line:
                for line in wrap_detail(next_line):
                    typer.echo(line)
    if why and not any_explained:
        typer.echo("(no BLOCK or AUTH rows in this window - nothing to explain)")


@app.command(rich_help_panel="Daily")
def tui(
    path: str = typer.Option(".", "--path", "-p", help="Repository root."),
    last: int = typer.Option(500, "--last", "-n", min=1, help="Load the most recent N decisions."),
) -> None:
    """Browse the redacted decision log interactively, with a plain-language "why" panel.

    Every row shown is already redacted - a path class, reason codes, the verdict,
    the risk, and the auth outcome - the same data `doberman log` prints. Requires
    the optional 'textual' extra; `doberman log` remains the plain,
    dependency-free fallback. The load is bounded by `--last` (mirrors
    `doberman log --last`); the header shows how many rows are loaded versus how
    many currently match the in-app filter.
    """
    target = Path(path)
    if not target.exists():
        typer.echo(f"error: --path {path} does not exist", err=True)
        raise typer.Exit(code=2)
    if not target.is_dir():
        typer.echo(f"error: --path {path} is not a directory", err=True)
        raise typer.Exit(code=2)
    if importlib.util.find_spec("textual") is None:
        typer.echo(
            "error: The TUI requires the optional 'textual' extra: "
            'pip install "doberman-core[tui]"',
            err=True,
        )
        raise typer.Exit(code=1)
    from doberman.tui import run_tui

    run_tui(path, last=last)


_DASH_HOST = "127.0.0.1"
_DASH_DEFAULT_PORT = 8642


@app.command(rich_help_panel="Daily")
def dash(
    port: int = typer.Option(_DASH_DEFAULT_PORT, "--port", help="Port to bind the dashboard to."),
    path: str = typer.Option(".", "--path", "-p", help="Repository root to report on."),
) -> None:
    """Launch the local dashboard (preview) - a localhost-only control surface.

    Binds to 127.0.0.1 only, never a public interface. A fresh, single-use
    token is generated for this run and embedded in the printed URL; every API
    route requires it as a bearer token, checked in constant time. Reports the
    live decision feed, summary stats, mode, and enforcement state for
    ``--path`` (default: the current repo), plus an interactive AUTH
    approve/deny queue: a challenge on the decision path engages this
    dashboard only while it is running (see the heartbeat below), and falls
    back to the terminal/GUI otherwise. Requires the optional 'dash' extra.
    """
    try:
        import uvicorn

        from doberman.dash import create_app
    except ImportError as exc:
        typer.echo(
            'error: The dashboard requires the optional "dash" extra: '
            'pip install "doberman-core[dash]"',
            err=True,
        )
        raise typer.Exit(code=1) from exc

    import threading

    from doberman.storage.heartbeat import touch_heartbeat

    # ponytail: a daemon thread ticking a file mtime - simplest possible
    # liveness signal the decision-path process can check without any IPC.
    # Dies with the process; no explicit stop needed for a CLI-lifetime thread.
    stop_heartbeat = threading.Event()

    def _heartbeat_loop() -> None:
        while not stop_heartbeat.is_set():
            touch_heartbeat(path)
            stop_heartbeat.wait(2.0)

    threading.Thread(target=_heartbeat_loop, daemon=True).start()

    token = secrets.token_urlsafe(32)
    typer.echo(f"Dashboard: http://{_DASH_HOST}:{port}/?token={token}")
    # access_log=False: the single-use token rides in the URL query string, so
    # uvicorn's request access log would write it verbatim into a log line.
    # Disable it so the bearer token never lands in a log.
    uvicorn.run(create_app(token, path), host=_DASH_HOST, port=port, access_log=False)


@app.command(rich_help_panel="Getting started")
def demo(
    path: str = typer.Option(".", "--path", "-p", help="Repository root to log decisions against."),
    mode: str = typer.Option(
        "balanced", "--mode", help="Security mode to evaluate scenarios under."
    ),
    fast: bool = typer.Option(False, "--fast", help="Skip the pacing delay between scenarios."),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        "-q",
        help="Suppress the banner, narration, and closing hint; the summary and exit code stay.",
    ),
) -> None:
    """Run a scripted attack reel through the REAL decision engine.

    Drives a fixed list of canned tool calls -- a secret-exfiltration attempt,
    a destructive command, a protected-branch force push, a Unicode-smuggled
    egress, a sensitive-file read, a git clone to an external host (the real
    engine's AUTH verdict -- human-in-the-loop, not a fake one), and two
    benign calls -- through the SAME normalize -> decide -> record_decision
    pipeline the real proxy uses, so the redacted decision log (and
    `doberman dash`) fills with genuine verdicts. Nothing is ever executed
    against a real tool or downstream server: no network call, no unexpected
    file mutation, and no auth prompt (an AUTH verdict is recorded and shown
    here, never challenged).
    """
    try:
        resolved_mode = resolve_mode(mode)
    except ValueError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    if not quiet:
        typer.echo("Doberman demo -- scripted attack reel (real engine, nothing executed)")
        typer.echo("")

    outcomes = run_demo(
        mode=resolved_mode.value,
        repo_root=path,
        fast=fast,
        on_scenario=None if quiet else lambda outcome: typer.echo(format_outcome_line(outcome)),
    )

    if not quiet:
        typer.echo("")
    typer.echo(format_summary_table(outcomes))
    if not quiet:
        typer.echo("")
        typer.echo("Run `doberman dash` in another terminal to watch this live.")

    if not all(outcome.matched for outcome in outcomes):
        raise typer.Exit(code=1)


@memory_app.callback(invoke_without_command=True, rich_help_panel="Policy internals")
def memory(
    ctx: typer.Context,
    path: str = typer.Option(".", "--path", "-p", help="Repository root."),
    as_json: bool = typer.Option(
        False,
        "--json",
        help="Emit the learned-memory summary as one JSON document.",
    ),
) -> None:
    """Show a plain-language, redaction-safe profile of what Doberman has learned.

    Reads as classifications and habits - counts, verdict mix, most-touched path
    classes, and how many distinct secrets have been *seen* (a count only). It
    never shows a fingerprint value or any raw secret.

    Run with no subcommand for this summary; see `doberman memory reset` (gated
    wipe of the learned behavioral baseline/preference memory) and `doberman
    memory prune` (drop stale entities' rows past a retention window).
    """
    if ctx.invoked_subcommand is not None:
        return
    summary = asyncio.run(memory_summary(path))
    if as_json:
        # Same style as ``scan --json`` / ``status --json`` (#178 / #179).
        typer.echo(json.dumps(summary, sort_keys=True, separators=(",", ":")))
        return
    typer.echo("Doberman learned memory")
    typer.echo("=" * 32)
    typer.echo(f"Decisions recorded: {summary['decisions']}")
    verdicts = summary["verdicts"]
    if verdicts:
        mix = ", ".join(f"{v}={n}" for v, n in verdicts.items())
        typer.echo(f"Verdict mix:        {mix}")
    if summary["top_path_classes"]:
        typer.echo("Most-touched path classes:")
        for cls, count in summary["top_path_classes"]:
            typer.echo(f"  {cls}  x{count}")
    typer.echo(f"Distinct secrets seen (count only, never stored): {summary['secrets_seen']}")


@memory_app.command("reset")
def memory_reset(
    entity: str | None = typer.Option(
        None, "--entity", help="Scope to one entity id; omit to reset every entity in this repo."
    ),
    path: str = typer.Option(".", "--path", "-p", help="Repository root."),
) -> None:
    """Wipe learned behavioral memory for this repo — a gated recovery action.

    The subjective baseline and revealed-preference tables are persistent,
    per-entity memory (RAND's "reliable deletion" requirement): if that memory
    were ever poisoned — trained on a compromised session's behavior — nothing
    short of this clears it. Deleting it is raise-SAFE by construction (same as
    the v2->v3 baseline re-key): a colder baseline scores everything as MORE
    novel until it relearns, never less protected. Requires an enrolled
    possession factor (2FA if set up, otherwise your Doberman password), the
    same gate as `doberman taint clear` - there is no confirm-only path. A
    successful reset is recorded to the append-only policy-change ledger
    (`doberman policy-history`), redacted to a row count and an entity-scope
    class - never raw baseline content. A denied attempt leaves no ledger row,
    same as `doberman taint clear` (ADR 0067).
    """
    if not totp.is_enrolled() and not password.is_enrolled():
        typer.echo(
            "error: resetting memory requires an enrolled possession factor - "
            "run `doberman 2fa setup` or `doberman password set` first",
            err=True,
        )
        raise typer.Exit(code=1)

    prompter = CliPrompter()
    try:
        approved, method = _verify_possession_factor(
            prompter, action_label="resetting learned memory"
        )
    except Exception:  # noqa: BLE001 — any input/EOF/timeout error denies the reset
        # Mirrors taint_clear: `_verify_possession_factor` does not guard its own
        # prompt, so a non-interactive stdin must deny cleanly, not traceback.
        approved, method = False, "denied"

    scope_label = "one entity" if entity else "all entities"
    if not approved:
        # No ledger row here: `apply_change` can only record what it itself
        # decided (a same-state before/after always classifies neutral ->
        # auto-approved), so forcing a denied attempt through it would
        # misrecord the denial as approved. Mirrors `doberman taint clear`,
        # which also leaves a denied gate with no ledger trace (ADR 0067).
        typer.echo(f"error: memory reset denied ({method}); unchanged", err=True)
        raise typer.Exit(code=1)

    try:
        counts = asyncio.run(reset_memory(path, entity))
    except Exception as exc:  # noqa: BLE001 — never report success on a failed reset
        typer.echo(f"error: memory reset failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    total = sum(counts.values())
    asyncio.run(
        apply_change(
            {"memory.reset": "present"},
            {"memory.reset": f"cleared:{scope_label}"},
            f"doberman memory reset ({scope_label}, {total} row(s))",
            repo_root=path,
        )
    )
    typer.echo(
        f"Memory reset ({scope_label}, {total} row(s) across {len(counts)} table(s)). "
        "The learned baseline/preference history for this scope is gone; it starts "
        "cold and relearns from here - colder means more novel, never less protected."
    )


@memory_app.command("prune")
def memory_prune(
    older_than_days: int = typer.Option(
        ...,
        "--older-than-days",
        min=1,
        help="Drop every entity whose most recent activity is older than this many days.",
    ),
    path: str = typer.Option(".", "--path", "-p", help="Repository root."),
) -> None:
    """Drop stale entities' learned memory past a retention window.

    A maintenance op, not a security decision - unlike `doberman memory reset`
    this is not gated behind a possession factor. It never touches the decision
    log (the audit trail is not behavioral memory) and never prunes an entity
    whose activity can't be dated (fail-safe: unknown age is never treated as
    stale). Output is counts only - entity ids are never printed.
    """
    try:
        result = asyncio.run(prune_stale_entities(path, older_than_days=older_than_days))
    except Exception as exc:  # noqa: BLE001 — never report success on a failed prune
        typer.echo(f"error: memory prune failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    entities = result.pop("entities_pruned")
    total_rows = sum(result.values())
    typer.echo(
        f"Memory pruned: {entities} stale entity class(es), {total_rows} row(s) across "
        f"{len(result)} table(s) untouched for {older_than_days}+ day(s)."
    )


@memory_app.command("seed")
def memory_seed(
    from_file: str = typer.Option(
        ...,
        "--from",
        help="Path to a JSONL file of ALLOWED-action traces (docs/BASELINE_SEEDING.md).",
    ),
    path: str = typer.Option(".", "--path", "-p", help="Repository root."),
    now: str | None = typer.Option(
        None,
        "--now",
        help="ISO-8601 timestamp to seed with (default: current UTC). Makes a run reproducible.",
    ),
    as_json: bool = typer.Option(
        False, "--json", help="Emit the seed summary as one JSON document."
    ),
) -> None:
    """Warm the per-entity streaming baseline from operator-supplied ALLOWED-action traces.

    Issue #326 named this `doberman baseline seed`; it lives under `memory` instead because
    `memory reset`/`memory prune` already own these same tables and a one-verb `baseline` group
    would split the surface — see docs/BASELINE_SEEDING.md.

    Every line of the trace file is validated BEFORE anything is written: any row that is not an
    allowed trace (`verdict: "PASS"` / `allowed: true`), or that fails to parse or validate,
    refuses the WHOLE file — nothing is observed, and the error names only the bad line numbers,
    never row content. A clean file is replayed through the same `observe()` path the live proxy
    calls, entity-scoped the same way (`entity_id(agent_role, repo_root)`), so a seeded baseline
    is the one live traffic reads. This can only warm the surprise baseline: it never changes a
    verdict, the mode, or `policies.yaml`.
    """
    # Imported here, not at module scope (same reasoning as `serve`'s lazy import above):
    # doberman.subjective.baseline imports `river` at module load, which drags in the heavy
    # numeric stack (river/numpy/scipy) — non-seed CLI commands (`--help`, `log`, `status`,
    # `scan`, ...) must not pay that cold-start cost just because `memory seed` exists.
    from doberman.subjective.seed import seed_baseline

    stamp: datetime | None = None
    if now is not None:
        try:
            stamp = datetime.fromisoformat(now)
        except ValueError:
            typer.echo(f"error: --now {now!r} is not a valid ISO-8601 timestamp", err=True)
            raise typer.Exit(code=1) from None
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=timezone.utc)

    try:
        summary = asyncio.run(seed_baseline(from_file, repo_root=path, now=stamp))
    except OSError as exc:
        typer.echo(f"error: could not read {from_file!r}: {type(exc).__name__}", err=True)
        raise typer.Exit(code=1) from exc

    if summary.errors:
        lines = ", ".join(str(e.line_no) for e in summary.errors)
        typer.echo(
            f"error: seed refused - {len(summary.errors)} invalid row(s) at line(s): {lines}; "
            "nothing observed",
            err=True,
        )
        raise typer.Exit(code=1)

    if as_json:
        payload = {
            "seeded": summary.seeded,
            "entities": [
                {
                    "entity": e.entity,
                    "seeded": e.seeded,
                    "total_observations": e.total_observations,
                    "warm": e.warm,
                    "hst": e.hst,
                }
                for e in summary.entities
            ],
        }
        typer.echo(json.dumps(payload, sort_keys=True, separators=(",", ":")))
        return

    typer.echo(f"Seeded {summary.seeded} allowed-action trace(s).")
    for e in summary.entities:
        warm_label = "warm" if e.warm else "cold"
        typer.echo(
            f"  entity {e.entity}...  +{e.seeded} observation(s), total {e.total_observations} "
            f"({warm_label}), HST {e.hst}"
        )


@app.command("policy-history", rich_help_panel="Policy internals")
def policy_history(
    last: int = typer.Option(20, "--last", "-n", help="Show the most recent N changes."),
    path: str = typer.Option(".", "--path", "-p", help="Repository root."),
    as_json: bool = typer.Option(
        False,
        "--json",
        help="Print redacted ledger rows as a JSON array (machine-readable).",
    ),
) -> None:
    """Show the append-only policy-change ledger (newest first).

    Records every classified change - strengthen / weaken / neutral - **including
    denied weakening attempts** (the poisoning signal). Each row shows the rule,
    the before->after states, the classification, and how it was approved.
    """
    rows = asyncio.run(read_policy_changes(path, limit=max(0, last)))
    if as_json:
        # Same redacted row dicts the human view uses (no raw paths/secrets).
        typer.echo(json.dumps(rows, sort_keys=True, separators=(",", ":"), default=str))
        return
    if not rows:
        typer.echo("(no policy changes recorded yet)")
        return
    typer.echo("Doberman policy-change ledger")
    typer.echo("=" * 32)
    for row in rows:
        status = "approved" if row["approved"] else "DENIED"
        typer.echo(
            f"{row['ts']}  {row['classification']:<10} {row['rule_id']}: "
            f"{row['from_state']} -> {row['to_state']}  "
            f"[{status} via {row['approval_method']}]"
        )


@app.command("policy-versions", rich_help_panel="Policy internals")
def policy_versions(
    show: str | None = typer.Option(
        None,
        "--show",
        help="Print one version's snapshot: a full pv1: id or at least 8 hex characters of one.",
    ),
    verify: bool = typer.Option(
        False,
        "--verify",
        help="Recompute every stored digest and check the on-disk policy is the recorded one.",
    ),
    path: str = typer.Option(".", "--path", "-p", help="Repository root."),
    as_json: bool = typer.Option(False, "--json", help="Machine-readable output."),
) -> None:
    """Every policy version that has been in force here (newest first).

    A version is `pv1:` plus the SHA-256 of the canonical policy snapshot (see
    docs/POLICY_VERSIONS.md). Listing records the policy in force right now;
    `--verify` only reads.
    """
    from doberman.storage.policy_catalogue import (
        ORIGIN_OBSERVED,
        observe_current,
        read_observations,
        read_versions,
        verify_catalogue,
    )

    if show is not None:
        _policy_versions_show(show, path)
        return
    if verify:
        report = verify_catalogue(path)
        if as_json:
            typer.echo(json.dumps(report, sort_keys=True, separators=(",", ":")))
        elif report["status"] == "ok":
            typer.echo(f"ok ({report['versions']} version(s); current {report['current']})")
        elif report["status"] == "mismatch":
            typer.echo(
                "mismatch: stored content no longer hashes to " + ", ".join(report["mismatched"])
            )
        else:
            typer.echo(
                f"drift: the policy on disk is {report['current']} but the last recorded "
                f"version is {report['recorded']} (run `doberman doctor` to record it)"
            )
        if report["status"] != "ok":
            raise typer.Exit(code=1)
        return

    observe_current(path, origin=ORIGIN_OBSERVED)
    in_force: dict[str, tuple[str, str]] = {}
    for obs in read_observations(path):  # newest first: the first hit is the latest
        in_force.setdefault(obs["version"], (obs["ts"], obs["origin"]))
    rows = [
        {
            **row,
            "in_force_since": in_force.get(row["version"], (None, None))[0],
            "origin": in_force.get(row["version"], (None, None))[1],
        }
        for row in read_versions(path)
    ]
    if as_json:
        typer.echo(json.dumps(rows, sort_keys=True, separators=(",", ":")))
        return
    if not rows:
        typer.echo("(no policy versions recorded yet)")
        return
    typer.echo("Doberman policy versions")
    typer.echo("=" * 24)
    for row in rows:
        typer.echo(
            f"{row['version'][:16]}...  first seen {row['first_seen']}  engine {row['engine']}  "
            f"in force since {row['in_force_since']}  via {row['origin']}"
        )


def _policy_versions_show(show: str, path: str) -> None:
    from doberman.storage.policy_catalogue import VERSION_PREFIX, find_versions, read_snapshot

    needle = show[len(VERSION_PREFIX) :] if show.startswith(VERSION_PREFIX) else show
    if len(needle) < 8 or any(ch not in "0123456789abcdef" for ch in needle.lower()):
        typer.echo("error: --show takes a pv1: id or at least 8 hex characters of one", err=True)
        raise typer.Exit(code=2)
    matches = find_versions(path, needle)
    if not matches:
        typer.echo(f"error: no policy version matches {show}", err=True)
        raise typer.Exit(code=1)
    if len(matches) > 1:
        typer.echo("error: ambiguous prefix; matches " + ", ".join(matches), err=True)
        raise typer.Exit(code=1)
    snapshot = read_snapshot(path, matches[0])
    if snapshot is None:
        typer.echo(f"error: could not read the snapshot for {matches[0]}", err=True)
        raise typer.Exit(code=1)
    typer.echo(json.dumps({"version": matches[0], "snapshot": snapshot}, indent=2, sort_keys=True))


@app.command("decision-log-prune", rich_help_panel="Daily")
def decision_log_prune(
    older_than_days: int | None = typer.Option(
        None,
        "--older-than-days",
        min=1,
        help="Delete resolved decisions older than this many days (a row exactly at the cutoff is kept).",
    ),
    max_rows: int | None = typer.Option(
        None,
        "--max-rows",
        min=0,
        help="Retain at most this many newest resolved decisions; delete the rest.",
    ),
    path: str = typer.Option(".", "--path", "-p", help="Repository root."),
) -> None:
    """Prune resolved decision rows by age and/or retained-row budget.

    A maintenance operation outside the decision path. It never touches pending
    AUTH rows and never modifies the append-only policy-change ledger.
    """
    if older_than_days is None and max_rows is None:
        typer.echo("error: specify --older-than-days and/or --max-rows", err=True)
        raise typer.Exit(code=2)
    try:
        result = asyncio.run(
            prune_decisions(path, older_than_days=older_than_days, max_rows=max_rows)
        )
    except Exception as exc:  # noqa: BLE001 — never report a failed prune as success
        typer.echo(f"error: decision-log prune failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    deleted = result["age_deleted"] + result["overflow_deleted"]
    typer.echo(f"Decision log pruned: {deleted} row(s).")


def _record_manifest(host: str, scope: str, settings_path: Path, groups: dict) -> None:
    """Record the install manifest entry; a failure is reported, never fatal."""
    from doberman.hosthooks.integrity import record_install

    try:
        record_install(host, scope, settings_path, groups)
    except Exception as exc:  # noqa: BLE001 - tracking must never break an install
        typer.echo(
            f"warning: could not record the hook install manifest ({type(exc).__name__}); "
            "`doberman doctor` will report the hook integrity as untracked.",
            err=True,
        )


def _clear_manifest(host: str, scope: str, settings_path: Path) -> None:
    """Forget the manifest entry BEFORE removing hooks; a failure is reported, never fatal."""
    from doberman.hosthooks.integrity import clear_install

    try:
        clear_install(host, scope, settings_path)
    except Exception as exc:  # noqa: BLE001
        typer.echo(
            f"warning: could not clear the hook install manifest ({type(exc).__name__}); "
            "`doberman doctor` may report a divergence until you re-run install-hooks.",
            err=True,
        )


@app.command("install-hooks", rich_help_panel="Getting started")
def install_hooks(
    global_: bool = typer.Option(
        False,
        "--global",
        "-g",
        help="Install into the user-wide file (Claude: ~/.claude; Codex: ~/.codex).",
    ),
    local: bool = typer.Option(
        False, "--local", help="Install into .claude/settings.local.json (Claude only)."
    ),
    host: str = typer.Option(
        "claude", "--host", help="Which host to wire: claude | codex | cursor."
    ),
    path: str = typer.Option(".", "--path", "-p", help="Project root (default: current dir)."),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Print what would change; write nothing."
    ),
) -> None:
    """Wire Doberman's hooks into a host so every tool call is gated before it runs.

    Idempotent - safe to run more than once. Claude Code (default): PreToolUse +
    PostToolUse + SessionStart into a `settings.json` (`--global` user-wide,
    `--local` project-local, else project `.claude/settings.json`). Codex CLI
    (`--host codex`): a PreToolUse hook into a `hooks.json` (`--global` ->
    `~/.codex/hooks.json`, else `<repo>/.codex/hooks.json`). Cursor
    (`--host cursor`): the five Cursor events into `.cursor/hooks.json`
    (`--global` -> `~/.cursor/hooks.json`, else `<repo>/.cursor/hooks.json`)
    with `failClosed: true` on every gating event.

    `--host` here is claude, codex, or cursor only - mcp and openclaw don't write
    a hook file, so there's nothing for this command to wire; `doberman setup
    --host mcp`/`--host openclaw` prints the pointer for those instead.

    New here? `doberman setup` runs this for you and asks which hosts to guard.
    """
    if host == "codex":
        _install_codex(global_=global_, local=local, path=path, dry_run=dry_run)
        return
    if host == "cursor":
        _install_cursor(global_=global_, local=local, path=path, dry_run=dry_run)
        return
    if host != "claude":
        typer.echo(
            f"error: unknown --host {host!r}; expected 'claude', 'codex', or 'cursor'.", err=True
        )
        raise typer.Exit(2)

    from doberman.hosthooks.install import (
        doberman_groups,
        load_settings,
        merge_doberman_hooks,
        resolve_settings_path,
        write_settings,
    )

    scope = "global" if global_ else ("local" if local else "project")
    settings_path = resolve_settings_path(scope, path)

    try:
        current = load_settings(settings_path)
    except ValueError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from exc

    merged = merge_doberman_hooks(current)

    if dry_run:
        typer.echo(f"[dry-run] target: {settings_path}")
        typer.echo("[dry-run] would add:")
        typer.echo("  PreToolUse   -> doberman hook pre")
        typer.echo("  PostToolUse  -> doberman hook post")
        typer.echo(f"  SessionStart -> {DASHBOARD_COMMAND}")
        return

    if merged == current:
        typer.echo(f"already wired: {settings_path}")
    else:
        write_settings(settings_path, merged)
        typer.echo(f"wrote {settings_path}")
    _record_manifest("claude", scope, settings_path, doberman_groups(merged))
    typer.echo("Doberman will now gate every tool call in this project.")
    typer.echo("The session dashboard will print at the start of every session.")
    if remove_exclusion(path):
        typer.echo("This project is no longer excluded from global hooks.")


def _write_codex_hook(scope: str, path: str, *, show_verify: bool = True) -> tuple[Path, bool]:
    """Write Doberman's Codex hook for *scope* and print the TRUST notice.

    Shared by ``install-hooks --host codex`` (:func:`_install_codex`) and the
    ``setup`` wizard's per-host wiring, so the write + notice text lives once.
    A re-run whose merged hooks are unchanged prints ``already wired`` instead
    of ``wrote`` (bold, item 2), same as the Claude Code write path. Returns
    ``(hooks_path, already_wired)`` so a caller (the setup wizard's summary)
    can say which one happened without re-deriving it.

    *show_verify* prints the trailing "Verify it's live" pointer; ``setup``
    passes ``False`` (item 14) because its own epilogue already gives every
    wired host - Codex included - the same pointer once, and this ritual's
    "cat .env" text otherwise duplicated it.
    """
    from doberman.hosthooks.install import load_settings, write_settings
    from doberman.hosthooks.install_codex import (
        codex_doberman_groups,
        merge_codex_hooks,
        resolve_codex_hooks_path,
    )

    hooks_path = resolve_codex_hooks_path(scope, path)

    try:
        current = load_settings(hooks_path)
    except ValueError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from exc

    merged = merge_codex_hooks(current)
    already_wired = merged == current
    if already_wired:
        typer.echo(style_text(f"already wired: {hooks_path}", bold=True))
    else:
        write_settings(hooks_path, merged)
        typer.echo(style_text(f"wrote {hooks_path}", bold=True))
    _record_manifest("codex", scope, hooks_path, codex_doberman_groups(merged))
    if remove_exclusion(path):
        typer.echo("This project is no longer excluded from global hooks.")
    typer.echo("")
    # Round 6 item 5: the trust notice comes FIRST - the gating claim used to
    # print right after the write, unconditionally, then immediately be
    # contradicted by "Codex requires you to TRUST this hook before it runs"
    # a few lines later. Now the gating line comes after, and is phrased
    # conditionally on that trust step actually happening.
    typer.echo("Codex requires you to TRUST this hook before it runs:")
    typer.echo("  run a Codex command and approve the hook when prompted, or launch with")
    typer.echo("  --dangerously-bypass-hook-trust only if you already vet the hook source.")
    typer.echo("Once you trust the hook in Codex, Doberman gates its tool calls in this scope.")
    if show_verify:
        typer.echo("Verify it's live: ask Codex to `cat .env` and confirm it is blocked.")
    return hooks_path, already_wired


def _install_codex(*, global_: bool, local: bool, path: str, dry_run: bool) -> None:
    """`install-hooks --host codex`: wire ``doberman hook codex-pre`` into a
    Codex hooks.json. ``--global`` -> ``~/.codex/hooks.json`` (user), else
    ``<repo>/.codex/hooks.json`` (repo). ``--local`` has no Codex equivalent."""
    if local:
        typer.echo(
            "error: --local has no Codex equivalent; use --global (user) or the default (repo).",
            err=True,
        )
        raise typer.Exit(2)

    scope = "user" if global_ else "repo"

    if dry_run:
        from doberman.hosthooks.install_codex import resolve_codex_hooks_path

        hooks_path = resolve_codex_hooks_path(scope, path)
        typer.echo(f"[dry-run] target: {hooks_path}")
        typer.echo("[dry-run] would add:")
        typer.echo("  PreToolUse -> doberman hook codex-pre")
        return

    _write_codex_hook(scope, path)  # returns (path, already_wired); install-hooks needs neither


def _uninstall_codex(*, global_: bool, local: bool, path: str, dry_run: bool) -> None:
    """`uninstall-hooks --host codex`: remove Doberman's Codex hook group."""
    if local:
        typer.echo("error: --local has no Codex equivalent.", err=True)
        raise typer.Exit(2)
    from doberman.hosthooks.install import _is_doberman_group, load_settings, write_settings
    from doberman.hosthooks.install_codex import remove_codex_hooks, resolve_codex_hooks_path

    scope = "user" if global_ else "repo"
    hooks_path = resolve_codex_hooks_path(scope, path)

    try:
        current = load_settings(hooks_path)
    except ValueError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from exc

    hooks_section = current.get("hooks") or {}
    had_doberman = any(
        _is_doberman_group(g)
        for groups in hooks_section.values()
        if isinstance(groups, list)
        for g in groups
    )
    if not had_doberman:
        typer.echo("No Doberman Codex hooks found - nothing to remove.")
        return

    cleaned = remove_codex_hooks(current)
    if dry_run:
        typer.echo(f"[dry-run] target: {hooks_path}")
        typer.echo("[dry-run] would remove:  PreToolUse -> doberman hook codex-pre")
        return

    _clear_manifest("codex", scope, hooks_path)
    write_settings(hooks_path, cleaned)
    typer.echo(f"wrote {hooks_path}")
    typer.echo("Doberman Codex hooks removed.")
    typer.echo(
        "Note: a plugin-bundled hook (if installed) is removed by removing the plugin "
        "(`codex plugin remove`), not by this command."
    )


def _write_cursor_hook(scope: str, path: str, *, show_verify: bool = True) -> tuple[Path, bool]:
    """Write Doberman's Cursor hooks for *scope* and print the notice.

    Shared by ``install-hooks --host cursor`` (:func:`_install_cursor`) and, in
    future, a ``setup`` wizard cursor step. Mirrors :func:`_write_codex_hook`'s
    already-wired/wrote/manifest/exclusion shape. Returns ``(hooks_path,
    already_wired)``.
    """
    from doberman.hosthooks.install import load_settings, write_settings
    from doberman.hosthooks.install_cursor import (
        cursor_doberman_groups,
        merge_cursor_hooks,
        resolve_cursor_hooks_path,
    )

    hooks_path = resolve_cursor_hooks_path(scope, path)

    try:
        current = load_settings(hooks_path)
    except ValueError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    merged = merge_cursor_hooks(current)
    already_wired = merged == current
    if already_wired:
        typer.echo(style_text(f"already wired: {hooks_path}", bold=True))
    else:
        write_settings(hooks_path, merged)
        typer.echo(style_text(f"wrote {hooks_path}", bold=True))
    _record_manifest("cursor", scope, hooks_path, cursor_doberman_groups(merged))
    if remove_exclusion(path):
        typer.echo("This project is no longer excluded from global hooks.")
    typer.echo("")
    typer.echo("Restart your Cursor session so it reloads hooks.json.")
    typer.echo(
        "Doberman now gates Cursor's built-in tools, shell commands, MCP calls and file reads "
        "in this scope (failClosed: a hook crash or timeout denies)."
    )
    if show_verify:
        typer.echo("Verify it's live: ask Cursor to `cat .env` and confirm it is blocked.")
    return hooks_path, already_wired


def _install_cursor(*, global_: bool, local: bool, path: str, dry_run: bool) -> None:
    """`install-hooks --host cursor`: wire ``doberman hook cursor`` into a
    Cursor hooks.json. ``--global`` -> ``~/.cursor/hooks.json`` (user), else
    ``<repo>/.cursor/hooks.json`` (project). ``--local`` has no Cursor equivalent."""
    if local:
        typer.echo(
            "error: --local has no Cursor equivalent; use --global (user) or the default "
            "(project).",
            err=True,
        )
        raise typer.Exit(2)

    scope = "user" if global_ else "project"

    if dry_run:
        from doberman.hosthooks.cursor import EVENT_SESSION_START
        from doberman.hosthooks.install_cursor import (
            GATE_EVENTS,
            GATE_TIMEOUT_S,
            SESSION_START_TIMEOUT_S,
            resolve_cursor_hooks_path,
        )

        hooks_path = resolve_cursor_hooks_path(scope, path)
        typer.echo(f"[dry-run] target: {hooks_path}")
        typer.echo("[dry-run] would add:")
        for event in (*GATE_EVENTS, EVENT_SESSION_START):
            timeout = SESSION_START_TIMEOUT_S if event == EVENT_SESSION_START else GATE_TIMEOUT_S
            typer.echo(f"  {event} -> doberman hook cursor (failClosed, {timeout}s)")
        return

    _write_cursor_hook(scope, path)  # returns (path, already_wired); install-hooks needs neither


def _uninstall_cursor(*, global_: bool, local: bool, path: str, dry_run: bool) -> None:
    """`uninstall-hooks --host cursor`: remove Doberman's Cursor hook entries."""
    if local:
        typer.echo("error: --local has no Cursor equivalent.", err=True)
        raise typer.Exit(2)
    from doberman.hosthooks.cursor import EVENT_SESSION_START
    from doberman.hosthooks.install import load_settings, write_settings
    from doberman.hosthooks.install_cursor import (
        GATE_EVENTS,
        _is_doberman_entry,
        remove_cursor_hooks,
        resolve_cursor_hooks_path,
    )

    scope = "user" if global_ else "project"
    hooks_path = resolve_cursor_hooks_path(scope, path)

    try:
        current = load_settings(hooks_path)
    except ValueError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from exc

    hooks_section = current.get("hooks") or {}
    had_doberman = any(
        _is_doberman_entry(entry)
        for entries in hooks_section.values()
        if isinstance(entries, list)
        for entry in entries
    )
    if not had_doberman:
        typer.echo("No Doberman Cursor hooks found - nothing to remove.")
        return

    cleaned = remove_cursor_hooks(current)
    if dry_run:
        typer.echo(f"[dry-run] target: {hooks_path}")
        typer.echo("[dry-run] would remove:")
        for event in (*GATE_EVENTS, EVENT_SESSION_START):
            typer.echo(f"  {event} -> doberman hook cursor")
        return

    _clear_manifest("cursor", scope, hooks_path)
    write_settings(hooks_path, cleaned)
    typer.echo(f"wrote {hooks_path}")
    typer.echo("Doberman Cursor hooks removed.")


@app.command("uninstall-hooks", rich_help_panel="Leaving")
def uninstall_hooks(
    global_: bool = typer.Option(
        False,
        "--global",
        "-g",
        help="Remove from the user-wide file (Claude: ~/.claude; Codex: ~/.codex).",
    ),
    local: bool = typer.Option(
        False, "--local", help="Remove from .claude/settings.local.json (Claude only)."
    ),
    host: str = typer.Option(
        "claude", "--host", help="Which host to unwire: claude | codex | cursor."
    ),
    path: str = typer.Option(".", "--path", "-p", help="Project root (default: current dir)."),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Print what would change; write nothing."
    ),
) -> None:
    """Remove Doberman's hooks from a host.

    Idempotent - safe to run even when hooks are not present.  Non-Doberman hooks
    and every other setting are left untouched. ``--host codex`` removes the Codex
    hook group instead of the Claude Code hooks; ``--host cursor`` removes the
    Cursor hook entries.
    """
    if host == "codex":
        _uninstall_codex(global_=global_, local=local, path=path, dry_run=dry_run)
        return
    if host == "cursor":
        _uninstall_cursor(global_=global_, local=local, path=path, dry_run=dry_run)
        return
    if host != "claude":
        typer.echo(
            f"error: unknown --host {host!r}; expected 'claude', 'codex', or 'cursor'.", err=True
        )
        raise typer.Exit(2)

    from doberman.hosthooks.install import (
        _is_doberman_group,
        load_settings,
        remove_doberman_hooks,
        resolve_settings_path,
        write_settings,
    )

    scope = "global" if global_ else ("local" if local else "project")
    settings_path = resolve_settings_path(scope, path)

    try:
        current = load_settings(settings_path)
    except ValueError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from exc

    # Detect whether any Doberman entries exist before removing.
    hooks_section = current.get("hooks") or {}
    had_doberman = any(
        _is_doberman_group(g)
        for groups in hooks_section.values()
        if isinstance(groups, list)
        for g in groups
    )

    if not had_doberman:
        typer.echo("No Doberman hooks found - nothing to remove.")
        return

    cleaned = remove_doberman_hooks(current)

    if dry_run:
        typer.echo(f"[dry-run] target: {settings_path}")
        typer.echo("[dry-run] would remove:")
        typer.echo("  PreToolUse   -> doberman hook pre")
        typer.echo("  PostToolUse  -> doberman hook post")
        typer.echo(f"  SessionStart -> {DASHBOARD_COMMAND}")
        return

    _clear_manifest("claude", scope, settings_path)
    write_settings(settings_path, cleaned)
    typer.echo(f"wrote {settings_path}")
    typer.echo("Doberman hooks removed.")
    typer.echo("")
    typer.echo("What remains (manual, optional cleanup):")
    typer.echo("  .doberman/              policy, decision log, taint state")
    typer.echo("  ~/.doberman/metrics.db  device metrics")
    typer.echo("  password / 2FA enrollment")
    typer.echo(
        "These are not removed automatically; delete them only if you no longer use Doberman."
    )
    typer.echo("Run `doberman uninstall` to also remove this project's `.doberman/` state.")


def _project_uninstall_targets(path: str) -> list[tuple[str, str]]:
    """Project-scoped removal targets: ``(description, path)`` pairs.

    Deliberately excludes the ``global``/``user`` hook scopes (they protect every
    project on this machine, not just this one) and the Codex ``plugin`` scope
    (owned by ``codex plugin``, not writable here) — ``doberman uninstall`` is
    project-scoped only.
    """
    from doberman.hosthooks.install_codex import codex_hook_install_states
    from doberman.hosthooks.install_cursor import cursor_hook_install_states

    targets: list[tuple[str, str]] = []
    for scope, settings_path, installed in _hook_install_states(path):
        if scope in ("project", "local") and installed:
            targets.append((f"Claude Code hooks ({scope})", settings_path))
    for scope, hooks_path, installed in codex_hook_install_states(path):
        if scope == "repo" and installed:
            targets.append(("Codex CLI hooks (repo)", hooks_path))
    for scope, hooks_path, installed in cursor_hook_install_states(path):
        if scope == "project" and installed:
            targets.append(("Cursor hooks (project)", hooks_path))
    doberman_dir = Path(path) / CONFIG_DIR
    if doberman_dir.exists():
        targets.append((".doberman/ (policy + decision database)", str(doberman_dir)))
    return targets


def _path_is_in_pipx_venv(value: str | None) -> bool:
    if not value:
        return False
    parts = {part.casefold() for part in Path(value).parts}
    return "pipx" in parts and "venvs" in parts


def _package_remover() -> tuple[str, list[str]]:
    """Return the detected package-install kind and its removal argv."""
    if _path_is_in_pipx_venv(sys.executable) or _path_is_in_pipx_venv(shutil.which("doberman")):
        return "pipx", ["pipx", "uninstall", "doberman-core"]

    package_file = Path(doberman.__file__ or "").resolve()
    package_dir = package_file.parent
    if (
        package_dir.name == "doberman"
        and package_dir.parent.name == "src"
        and (package_dir.parent.parent / "pyproject.toml").is_file()
    ):
        return "development", []

    return "pip", [sys.executable, "-m", "pip", "uninstall", "-y", "doberman-core"]


def _format_command(argv: list[str]) -> str:
    return subprocess.list2cmdline(argv) if _WINDOWS else shlex.join(argv)


def _global_uninstall_targets(path: str) -> tuple[list[tuple[str, str]], str, list[str]]:
    """Every global-uninstall plan entry, including absent and read-only targets."""
    from doberman.hosthooks.install_codex import codex_hook_install_states
    from doberman.hosthooks.install_cursor import cursor_hook_install_states
    from doberman.storage import device_metrics, fingerprint

    claude_states = {scope: settings_path for scope, settings_path, _ in _hook_install_states(path)}
    codex_states = {scope: hooks_path for scope, hooks_path, _ in codex_hook_install_states(path)}
    cursor_states = {scope: hooks_path for scope, hooks_path, _ in cursor_hook_install_states(path)}
    kind, argv = _package_remover()
    targets = [
        ("Claude Code hooks (global)", claude_states["global"]),
        ("Claude Code hooks (project)", claude_states["project"]),
        ("Claude Code hooks (local)", claude_states["local"]),
        ("Codex CLI hooks (user)", codex_states["user"]),
        ("Codex CLI hooks (repo)", codex_states["repo"]),
        ("Codex CLI hooks (plugin scope; not writable)", codex_states["plugin"]),
        ("Cursor hooks (user)", cursor_states["user"]),
        ("Cursor hooks (project)", cursor_states["project"]),
        (".doberman/ (policy + decision database)", str(Path(path) / CONFIG_DIR)),
        ("TOTP enrollment", str(totp.resolve_path())),
        ("password enrollment", str(password.resolve_path())),
        ("fingerprint key", str(fingerprint.resolve_path())),
        ("device-wide state directory", str(device_metrics.resolve_path())),
        ("package", _format_command(argv) if argv else "development install; left in place"),
    ]
    return targets, kind, argv


def _remove_file(path: Path, errors: list[str]) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError as exc:
        errors.append(f"{path}: {exc}")


def _launch_package_removal(argv: list[str], errors: list[str]) -> None:
    command = _format_command(argv)
    typer.echo(f"package removal command: {command}")
    if _WINDOWS:
        try:
            subprocess.Popen(  # noqa: S603 — fixed package-manager argv, delayed for locked files
                ["cmd", "/c", f"ping -n 3 127.0.0.1 >nul & {command}"],  # noqa: S607 — ping = 2 s delay; `timeout` aborts on redirected stdin
                creationflags=getattr(subprocess, "DETACHED_PROCESS", 0x00000008)
                | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200),
                close_fds=True,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except OSError as exc:
            errors.append(f"package removal ({command}): {exc}")
            return
        typer.echo(f"package removal scheduled: {command} (runs after this command exits)")
        return

    try:
        completed = subprocess.run(argv, check=False)  # noqa: S603 — fixed package-manager argv
    except OSError as exc:
        errors.append(f"package removal ({command}): {exc}")
        return
    typer.echo(f"package removal exit code: {completed.returncode}")
    if completed.returncode != 0:
        errors.append(f"package removal ({command}): exit code {completed.returncode}")


def _uninstall_global(path: str, yes: bool, dry_run: bool, keep_package: bool) -> None:
    from doberman.hosthooks.install import (
        load_settings,
        remove_doberman_hooks,
        resolve_settings_path,
        write_settings,
    )
    from doberman.hosthooks.install_codex import (
        codex_hook_install_states,
        remove_codex_hooks,
        resolve_codex_hooks_path,
    )
    from doberman.hosthooks.install_cursor import (
        cursor_hook_install_states,
        remove_cursor_hooks,
        resolve_cursor_hooks_path,
    )
    from doberman.storage import device_metrics, fingerprint

    targets, package_kind, package_argv = _global_uninstall_targets(path)
    typer.echo(f"Doberman GLOBAL UNINSTALL requested for this device ({Path(path).resolve()}):")
    for description, target_path in targets:
        typer.echo(f"  - {description}: {target_path}")
    typer.echo("")
    typer.echo("Codex plugin-scope hooks are not writable by Doberman.")
    typer.echo("  Run `codex plugin remove doberman` if that plugin is installed.")

    if dry_run:
        typer.echo("")
        typer.echo("[dry-run] nothing removed.")
        return

    if not totp.is_enrolled() and not password.is_enrolled():
        typer.echo(
            "\nerror: uninstalling requires an enrolled possession factor - "
            "run `doberman 2fa setup` or `doberman password set` first",
            err=True,
        )
        raise typer.Exit(code=1)

    prompter = CliPrompter()
    try:
        if not yes:
            typed = typer.prompt("Type DOBERMAN to confirm device-wide removal")
            if typed.strip() != "DOBERMAN":
                typer.echo("error: uninstall denied (DOBERMAN did not match); unchanged", err=True)
                raise typer.Exit(code=1)
        approved, method = _verify_possession_factor(
            prompter, action_label="uninstalling Doberman from this device"
        )
    except typer.Exit:
        raise
    except Exception:  # noqa: BLE001 — any input/EOF/timeout error denies the uninstall
        approved, method = False, "denied"
    if not approved:
        typer.echo(f"error: uninstall denied ({method}); unchanged", err=True)
        raise typer.Exit(code=1)

    errors: list[str] = []
    claude_installed = {
        scope: installed for scope, _settings_path, installed in _hook_install_states(path)
    }
    for scope in ("global", "project", "local"):
        if not claude_installed.get(scope):
            continue
        target = resolve_settings_path(scope, path)
        try:
            current = load_settings(target)
            _clear_manifest("claude", scope, target)
            write_settings(target, remove_doberman_hooks(current))
        except (ValueError, OSError) as exc:
            errors.append(f"{target}: {exc}")

    codex_installed = {
        scope: installed
        for scope, _hooks_path, installed in codex_hook_install_states(path)
        if scope != "plugin"
    }
    for scope in ("user", "repo"):
        if not codex_installed.get(scope):
            continue
        target = resolve_codex_hooks_path(scope, path)
        try:
            current = load_settings(target)
            _clear_manifest("codex", scope, target)
            write_settings(target, remove_codex_hooks(current))
        except (ValueError, OSError) as exc:
            errors.append(f"{target}: {exc}")

    cursor_installed = {
        scope: installed for scope, _hooks_path, installed in cursor_hook_install_states(path)
    }
    for scope in ("user", "project"):
        if not cursor_installed.get(scope):
            continue
        target = resolve_cursor_hooks_path(scope, path)
        try:
            current = load_settings(target)
            _clear_manifest("cursor", scope, target)
            write_settings(target, remove_cursor_hooks(current))
        except (ValueError, OSError) as exc:
            errors.append(f"{target}: {exc}")

    project_dir = Path(path) / CONFIG_DIR
    if project_dir.exists():
        try:
            shutil.rmtree(project_dir)
        except OSError as exc:
            errors.append(f"{project_dir}: {exc}")

    for target in (totp.resolve_path(), password.resolve_path(), fingerprint.resolve_path()):
        _remove_file(target, errors)

    device_dir = device_metrics.resolve_path()
    if device_dir.exists():
        try:
            shutil.rmtree(device_dir)
        except OSError as exc:
            errors.append(f"{device_dir}: {exc}")

    typer.echo(
        "warning: device-wide 2FA enrollment, password, and fingerprint key are removed; "
        "a fresh `doberman setup` re-enrolls them."
    )

    if keep_package:
        if package_argv:
            typer.echo(f"package left in place (--keep-package): {_format_command(package_argv)}")
        else:
            typer.echo("development install detected; package left in place")
    elif package_kind == "development":
        typer.echo("development install detected; package left in place")
    else:
        _launch_package_removal(package_argv, errors)

    if errors:
        typer.echo("error: uninstall finished with errors - some items were NOT removed:", err=True)
        for error in errors:
            typer.echo(f"  - {error}", err=True)
        raise typer.Exit(code=1)

    typer.echo("\nDoberman removed from this device.")


@app.command(rich_help_panel="Leaving")
def uninstall(
    path: str = typer.Option(".", "--path", "-p", help="Project root (default: current dir)."),
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="Skip the typed confirmation. The possession-factor check is never skipped.",
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Print what would be removed; remove nothing."
    ),
    global_: bool = typer.Option(
        False, "--global", "-g", help="Remove Doberman from the whole device."
    ),
    keep_package: bool = typer.Option(
        False, "--keep-package", help="Remove hooks and state, but leave the package installed."
    ),
) -> None:
    """Fully remove Doberman from this project: host hooks + `.doberman/`.

    Project-scoped only. This does **not** touch `--global` hooks themselves (they
    protect every project on this machine) or your device-wide password / 2FA /
    fingerprint key / `~/.doberman/metrics.db` — removing those is a separate,
    deliberate action, not a side effect of cleaning up one project. But a global
    (or Codex user-scope) hook would otherwise keep firing here even after this
    project's own hooks/`.doberman/` are gone, so when one is detected as still
    installed, this project is also added to a device-wide exclusion list that the
    global hook checks and skips — closing that gap without touching the hook file
    itself. Run `doberman install-hooks` here again to clear the exclusion.

    Requires an enrolled possession factor (2FA if set up, otherwise your Doberman
    password) — the same gate as `doberman taint clear` / `doberman memory reset`.
    With neither enrolled, this fails closed and removes nothing. A destructive,
    irreversible action, so it also asks you to type the project directory name
    back before proceeding (skippable with `--yes`; the factor check is not).
    """
    if global_:
        _uninstall_global(path, yes, dry_run, keep_package)
        return
    from doberman.hosthooks.install_codex import (
        codex_hook_install_states,
        remove_codex_hooks,
        resolve_codex_hooks_path,
    )
    from doberman.hosthooks.install_cursor import (
        cursor_hook_install_states,
        remove_cursor_hooks,
        resolve_cursor_hooks_path,
    )

    targets = _project_uninstall_targets(path)
    if not targets:
        typer.echo("Nothing to remove for this project.")
        return

    global_hook_active = any(
        scope == "global" and installed for scope, _, installed in _hook_install_states(path)
    ) or any(
        scope == "user" and installed for scope, _, installed in codex_hook_install_states(path)
    )

    project_name = Path(path).resolve().name
    typer.echo(f"Doberman UNINSTALL requested for this project ({Path(path).resolve()}):")
    for description, target_path in targets:
        typer.echo(f"  - {description}: {target_path}")
    typer.echo("")
    typer.echo("This will NOT remove (shared across every project on this machine):")
    typer.echo("  - hooks installed with --global")
    typer.echo("  - your Doberman password / 2FA enrollment / fingerprint key")
    typer.echo("  - ~/.doberman/metrics.db (device metrics)")
    if global_hook_active:
        typer.echo("")
        typer.echo(
            "A global (or Codex user-scope) hook is still installed on this machine — this "
            "project will also be added to the device-wide exclusion list, so it skips it too."
        )

    if dry_run:
        typer.echo("")
        typer.echo("[dry-run] nothing removed.")
        return

    if not totp.is_enrolled() and not password.is_enrolled():
        typer.echo(
            "\nerror: uninstalling requires an enrolled possession factor - "
            "run `doberman 2fa setup` or `doberman password set` first",
            err=True,
        )
        raise typer.Exit(code=1)

    prompter = CliPrompter()
    try:
        if not yes:
            if not prompter.confirm("\nProceed?"):
                typer.echo("error: uninstall denied (confirmation declined); unchanged", err=True)
                raise typer.Exit(code=1)
            typed = typer.prompt(f"Type the project directory name ({project_name}) to confirm")
            if typed.strip() != project_name:
                typer.echo("error: uninstall denied (name did not match); unchanged", err=True)
                raise typer.Exit(code=1)
        approved, method = _verify_possession_factor(
            prompter, action_label="uninstalling Doberman from this project"
        )
    except typer.Exit:
        raise
    except Exception:  # noqa: BLE001 — any input/EOF/timeout error denies the uninstall
        approved, method = False, "denied"
    if not approved:
        typer.echo(f"error: uninstall denied ({method}); unchanged", err=True)
        raise typer.Exit(code=1)

    from doberman.hosthooks.install import (
        load_settings,
        remove_doberman_hooks,
        resolve_settings_path,
        write_settings,
    )

    errors: list[str] = []
    for scope, settings_path, installed in _hook_install_states(path):
        if scope not in ("project", "local") or not installed:
            continue
        try:
            current = load_settings(resolve_settings_path(scope, path))
            _clear_manifest("claude", scope, resolve_settings_path(scope, path))
            write_settings(resolve_settings_path(scope, path), remove_doberman_hooks(current))
        except (ValueError, OSError) as exc:
            errors.append(f"{settings_path}: {exc}")

    for scope, hooks_path, installed in codex_hook_install_states(path):
        if scope != "repo" or not installed:
            continue
        try:
            current = load_settings(resolve_codex_hooks_path(scope, path))
            _clear_manifest("codex", scope, resolve_codex_hooks_path(scope, path))
            write_settings(resolve_codex_hooks_path(scope, path), remove_codex_hooks(current))
        except (ValueError, OSError) as exc:
            errors.append(f"{hooks_path}: {exc}")

    for scope, hooks_path, installed in cursor_hook_install_states(path):
        if scope != "project" or not installed:
            continue
        try:
            current = load_settings(resolve_cursor_hooks_path(scope, path))
            _clear_manifest("cursor", scope, resolve_cursor_hooks_path(scope, path))
            write_settings(resolve_cursor_hooks_path(scope, path), remove_cursor_hooks(current))
        except (ValueError, OSError) as exc:
            errors.append(f"{hooks_path}: {exc}")

    doberman_dir = Path(path) / CONFIG_DIR
    if doberman_dir.exists():
        try:
            shutil.rmtree(doberman_dir)
        except OSError as exc:
            errors.append(f"{doberman_dir}: {exc}")

    if errors:
        typer.echo("error: uninstall finished with errors - some items were NOT removed:", err=True)
        for err in errors:
            typer.echo(f"  - {err}", err=True)
        raise typer.Exit(code=1)

    typer.echo("\nDoberman removed from this project.")

    if global_hook_active:
        add_exclusion(path)
        typer.echo(
            "This project has been added to the device-wide exclusion list, so the global "
            "(or Codex user-scope) hook will skip it too. Run `doberman install-hooks` here "
            "to bring protection back."
        )


@app.command(rich_help_panel="Getting started")
def setup(
    yes: bool = typer.Option(False, "--yes", "-y", help="Accept all defaults with no prompts."),
    mode_name: str = typer.Option(
        None, "--mode", "-m", help="Security mode (light/balanced/strict/paranoid)."
    ),
    global_: bool = typer.Option(
        False,
        "--global",
        "-g",
        help="Install hooks user-wide (Claude: ~/.claude/settings.json; Codex: ~/.codex/hooks.json).",
    ),
    hosts: list[str] = typer.Option(  # noqa: B008 — Typer's Option() factory, not a mutable default
        None,
        "--host",
        help=(
            "Host to wire (repeatable): claude | codex | mcp | openclaw, or 'all'. "
            "Default: detected hosts, else claude."
        ),
    ),
    path: str = typer.Option(".", "--path", "-p", help="Project root (default: current dir)."),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Print what would be set/written; persist nothing."
    ),
    no_telemetry: bool = typer.Option(
        False,
        "--no-telemetry",
        help="Disable telemetry for this run and persist it (same as `doberman telemetry off`).",
    ),
) -> None:
    """Friendly first-run wizard: pick your hosts and security posture, then wire them.

    Detects which agents you have installed (Claude Code, Codex CLI, an MCP client,
    OpenClaw), asks which ones to guard, then walks through security mode,
    preference tuning, and per-host wiring, finishing with a doctor pass. Exits
    0 once fully wired and healthy, 1 if that doctor pass finds a critical (e.g.
    hooks call `doberman`, which is not on PATH) - so a broken install is never
    reported as complete - and 3 if setup itself succeeded but nothing is wired
    yet (mcp/openclaw only: a manual paste-and-restart step still stands
    between here and protection).
    Later lowerings require a possession factor - a 2FA code if enrolled,
    otherwise your Doberman password (set via `doberman password set`).
    Pass `--yes` for a fully non-interactive run (useful for CI or scripting);
    pass `--dry-run` to preview the mode/prefs/files without writing anything
    (mirrors `install-hooks --dry-run`); pass `--no-telemetry` to opt out for
    good without answering the telemetry question. `--host` accepts claude,
    codex, mcp, and openclaw (`install-hooks --host` only wires claude/codex -
    mcp/openclaw have no hook file to write, only the pointer this wizard prints).
    """
    from doberman.hosthooks import setup as hosthooks_setup
    from doberman.hosthooks.install import (
        doberman_groups,
        load_settings,
        merge_doberman_hooks,
        resolve_settings_path,
        write_settings,
    )
    from doberman.hosthooks.install_codex import resolve_codex_hooks_path
    from doberman.hosthooks.setup import (
        DIMENSION_DESCRIPTIONS,
        HOSTS,
        default_hosts,
        detect_hosts,
        host_menu_lines,
        mode_menu_lines,
        parse_host_choice,
        parse_mode_choice,
    )
    from doberman.policy.preferences import vector_for

    # ------------------------------------------------------------------
    # 0. Usage validation that must happen before any banner prints (item 9):
    # a bad --host OR a bad --mode is a hard usage error, not something worth
    # a welcome message first (item 2).
    # ------------------------------------------------------------------
    valid_host_keys = [h.key for h in HOSTS]
    if hosts:
        # item 4 (round 6): `--host all` matches the interactive prompt's own
        # "or 'all'" shorthand (`parse_host_choice`) - expand it to every host
        # instead of failing the unknown-host check below.
        if any(h.lower() == "all" for h in hosts):
            hosts = list(valid_host_keys)
        invalid = sorted(set(hosts) - set(valid_host_keys))
        if invalid:
            typer.echo(
                f"error: unknown host(s) {', '.join(invalid)}; valid: "
                + ", ".join(valid_host_keys),
                err=True,
            )
            raise typer.Exit(2)

    chosen_mode_from_flag: SecurityMode | None = None
    if mode_name is not None:
        try:
            chosen_mode_from_flag = parse_mode_choice(mode_name)
        except ValueError as exc:
            typer.echo(f"error: {exc}", err=True)
            raise typer.Exit(2) from exc

    # A non-interactive preview: `--dry-run` with no `--yes` and no TTY on
    # stdin has nothing to read from (item 12) - rather than let the first
    # prompt hit EOF and abort, behave like `--yes --dry-run` and say so.
    # With a real TTY, the prompts stay interactive even under --dry-run.
    non_tty_preview = dry_run and not yes and not sys.stdin.isatty()
    if non_tty_preview:
        yes = True

    def _note(text: str) -> None:
        """Print a long ``note: ...`` guidance line wrapped to the terminal width."""
        for line in wrap_detail(text, indent=0):
            typer.echo(line, err=True)

    # ------------------------------------------------------------------
    # a. Welcome
    # ------------------------------------------------------------------
    typer.echo("")
    typer.echo("Welcome to Doberman setup!")
    for line in wrap_detail(
        "Doberman sits between your coding agent and its tools, turning every "
        "meaningful action into a risk-based allow / authenticate / block decision.",
        indent=0,
    ):
        typer.echo(line)
    typer.echo("")
    if non_tty_preview:
        _note("note: stdin is not a terminal - using defaults for the preview")

    # item 11: exactly one blank line ever separates two sections, even when
    # every optional prompt between them was skipped (flags / --yes) and
    # nothing else printed in the gap. `blank_pending` tracks whether the last
    # thing this command echoed to stdout was already a blank line; every
    # section header (and the two other section-adjacent blanks below) routes
    # through `_print_step_section`/the guard instead of an unconditional
    # `typer.echo("")`, and `_mark_content()` flags the few spots that print
    # real content WITHOUT a guarded header of their own (the global-scope
    # confirmation, and each per-host wiring block for claude/codex, whose
    # write line has no header at all under --yes/flags).
    blank_pending = True  # the welcome banner just printed the opening blank

    def _mark_content() -> None:
        nonlocal blank_pending
        blank_pending = False

    # ------------------------------------------------------------------
    # Step counter plan (item 3): only an interactive run has anything to
    # count - `--yes` prompts for nothing, so it never shows one. A stage
    # applies only if this run's flags mean it will actually show a prompt;
    # "Preference tuning"/"Telemetry"/"Doctor"/"Demo" are counted whenever
    # reached even on the rare path where a refused mode lowering skips the
    # tuning body - ponytail: an exactly precise dynamic denominator isn't
    # worth the complexity for that edge case. "Demo" (item 7) covers the
    # closing "see it work?" offer. item 4 (round 5): each host actually
    # being wired gets its OWN step number instead of one shared "Wiring"
    # slot - a `--host all` run used to show the identical "[N of M]" four
    # times in a row. The real host list is only known once section b below
    # finishes, so this is built once now with a single-slot placeholder
    # (used only for the "Hosts" section header itself, when hosts are still
    # being chosen interactively) and rebuilt for real right after - a no-op
    # when exactly one host ends up chosen, which is why the existing
    # single-host tests see no change.
    # ------------------------------------------------------------------
    def _build_step_names(wiring_slots: list[str], *, know_hosts: bool = False) -> list[str]:
        names: list[str] = []
        if not hosts and not yes:
            names.append("Hosts")
        if mode_name is None and not yes:
            names.append("Security mode")
        if not yes:
            names.append("Preference tuning")
            names.extend(wiring_slots)
            names.extend(["Telemetry", "Doctor"])
            # item 6 (round 6): the Demo offer only ever prints when at least
            # one hooks-kind host got wired (its own gate further down is
            # `if hooks_kind_wired:`) - an mcp/openclaw-only run must never
            # reserve a step number for an offer it will never show, or the
            # last header this run actually prints reads "[N of M]" with N
            # short of M. `know_hosts=False` (the placeholder call below, for
            # the "Hosts" section header itself - the real list isn't known
            # yet) assumes a hooks-kind host, matching every prior single-host
            # run's M unchanged; only the real, post-selection rebuild can
            # accurately drop the slot for a genuinely manual-only choice.
            if not know_hosts or any(h.kind == "hooks" for h in HOSTS if h.key in wiring_slots):
                names.append("Demo")
        return names

    step_names = _build_step_names(["Wiring"])
    step_total = len(step_names)
    step_index = {name: i + 1 for i, name in enumerate(step_names)}

    def _step_section(title: str, stage: str | None = None, *, marker: str = "--") -> str:
        n = step_index.get(stage or title)
        return _section(f"{title} [{n} of {step_total}]" if n else title, marker=marker)

    def _print_step_section(title: str, stage: str | None = None, *, marker: str = "--") -> None:
        """Print one section header, preceded by exactly one blank line -
        never two in a row (item 11)."""
        nonlocal blank_pending
        if not blank_pending:
            typer.echo("")
        typer.echo(_step_section(title, stage, marker=marker))
        blank_pending = False

    # ------------------------------------------------------------------
    # Written-so-far tracker (round 5 item 2/P1): every prompt in this wizard
    # aborts through this, so the message never overclaims. `wired` fills in
    # as section e runs; nothing else here writes to disk before its own
    # persist step (right after wiring succeeds) further down.
    # ------------------------------------------------------------------
    wired: list[tuple[str, str | None]] = []

    def _wired_files_clause() -> str | None:
        paths = [target for _host, target in wired if target]
        if not paths:
            return None
        return "hooks (" + ", ".join(paths) + ")"

    # ------------------------------------------------------------------
    # b. Hosts
    # ------------------------------------------------------------------
    detected = detect_hosts(path, hosthooks_setup._home())

    if hosts:
        chosen_hosts = [k for k in valid_host_keys if k in set(hosts)]
    elif yes:
        chosen_hosts = default_hosts(detected)
    else:
        _print_step_section("Hosts")
        for line in host_menu_lines(detected):
            typer.echo(line)
        typer.echo("")
        default_nums = ",".join(
            str(i) for i, h in enumerate(HOSTS, start=1) if h.key in default_hosts(detected)
        )
        chosen_hosts = _prompt_menu(
            "Which hosts should Doberman guard? (numbers or names, comma-separated, or 'all')",
            default_nums,
            lambda raw: parse_host_choice(raw, detected),
        )

    # item 4 (round 5): now that the real host list is known, expand the
    # single "Wiring" placeholder into one numbered step per host actually
    # chosen, in the same order section e below processes them.
    step_names = _build_step_names([h.key for h in HOSTS if h.key in chosen_hosts], know_hosts=True)
    step_total = len(step_names)
    step_index = {name: i + 1 for i, name in enumerate(step_names)}

    # ------------------------------------------------------------------
    # c. Security mode
    # ------------------------------------------------------------------
    if mode_name is not None:
        # Already validated in step 0, before the welcome banner (item 2).
        chosen_mode = chosen_mode_from_flag
    elif yes:
        chosen_mode = SecurityMode.balanced
    else:
        _print_step_section("Security mode")
        for line in mode_menu_lines():
            typer.echo(line)
        # item 7 (round 6): routed through wrap_detail like every other detail
        # line in this wizard, for consistency (it already fits at 78/60).
        for line in wrap_detail(
            "Not sure? `doberman demo --mode strict` shows what each mode blocks.", indent=0
        ):
            typer.echo(line)
        typer.echo("")
        chosen_mode = _prompt_menu("Choose a mode (name or number)", "balanced", parse_mode_choice)

    # ------------------------------------------------------------------
    # c2. --dry-run: preview only, persist nothing (mirrors install-hooks --dry-run)
    # ------------------------------------------------------------------
    if dry_run:
        preview_vector = vector_for(chosen_mode)
        _print_step_section("Dry run")
        dry_run_mode_line = (
            f"[dry-run] would set mode: {chosen_mode.value} (preset: "
            + "  ".join(_dim_label(n, getattr(preview_vector, n)) for n in DIMENSIONS)
            + ")"
        )
        for line in wrap_detail(dry_run_mode_line, indent=0, hang=2):  # item 4
            typer.echo(line)
        if "claude" in chosen_hosts:
            claude_scope_preview = "global" if global_ else "project"
            preview_path = resolve_settings_path(claude_scope_preview, path)
            typer.echo(f"[dry-run] would write: {preview_path}  (claude)")
        if "codex" in chosen_hosts:
            codex_scope_preview = "user" if global_ else "repo"
            preview_codex_path = resolve_codex_hooks_path(codex_scope_preview, path)
            typer.echo(f"[dry-run] would write: {preview_codex_path}  (codex)")
        if "mcp" in chosen_hosts:
            typer.echo("[dry-run] mcp: paste the proxy block into your client (no file written)")
        if "openclaw" in chosen_hosts:
            typer.echo(f"[dry-run] openclaw: follow {_OPENCLAW_README_URL} (no file written)")
        from doberman import telemetry

        telemetry_state = "on" if telemetry.is_enabled() else "off"
        typer.echo(f"[dry-run] would record telemetry consent: {telemetry_state}")
        # item 5: --dry-run has an ending - the last line says plainly that
        # nothing was written and names the one flag that changes that.
        typer.echo("Dry run - nothing written. Re-run without --dry-run to apply.")
        return

    # ------------------------------------------------------------------
    # c3. --global writes the real home directory: confirm first, or (--yes)
    # print the exact path before writing it.
    # ------------------------------------------------------------------
    global_declined = False
    if global_ and ("claude" in chosen_hosts or "codex" in chosen_hosts):
        global_targets: list[str] = []
        if "claude" in chosen_hosts:
            global_targets.append(str(resolve_settings_path("global", path)))
        if "codex" in chosen_hosts:
            global_targets.append(str(resolve_codex_hooks_path("user", path)))
        for target in global_targets:
            typer.echo(f"Installing globally: {target}")
        if not yes and not _confirm_or_abort(
            "Write to your real home directory now?", False, written=_wired_files_clause()
        ):
            _note("note: falling back to project scope (not writing to your home directory)")
            global_ = False
            global_declined = True
        _mark_content()  # item 11: real content just printed, unguarded by a section header

    # A genuinely fresh repo (no persisted policy yet) mirrors apply_mode_change's
    # own establish_ok first-run bypass: choosing an initial mode/preference
    # posture establishes it, it doesn't weaken one.
    first_run = load_policy(path) is None

    # ------------------------------------------------------------------
    # c4. Security mode - GATE ONLY (round 5 item P1: no raised-mode trap;
    # round 6 item P0: no fictional audit row either). This runs the exact
    # same gate a lowering has always run (confirm + possession factor, or the
    # free establish_ok bypass on a genuinely fresh repo) at the same point in
    # the flow as before - but it writes NEITHER `.doberman/policies.yaml` NOR
    # a ledger row yet. Both the actual `save_mode` call AND the ledger write
    # for an APPROVED outcome are deferred to right after per-host wiring
    # succeeds (section e1 below), so an abort or crash anywhere before that
    # point (the tuning prompts, a host-scope confirm, ...) leaves BOTH the
    # mode file untouched AND `doberman policy-history` unchanged -
    # `_abort_setup`'s "Aborted - nothing written." stays literally true, and
    # `policy-history` never shows a "[approved]" row for a mode change this
    # run never actually committed. A DENIED lowering is recorded immediately
    # below instead (via `record_change`): the attempt itself already fully
    # happened - the mode file is never touched by it either way - so there is
    # nothing to defer, same as `apply_change`'s direct callers.
    # ------------------------------------------------------------------
    mode_order = list(SecurityMode)
    current_mode = resolve_mode(load_mode(path))
    mode_applied = True
    mode_ledger_ts: str | None = None
    mode_before = {"mode": current_mode.value}
    mode_after = {"mode": chosen_mode.value}
    # Set only for an APPROVED-but-not-yet-recorded change; written to the
    # ledger at the same point `save_mode` runs, never before.
    mode_ledger_pending: tuple[Classification, str, str] | None = None

    if yes and not first_run and mode_order.index(chosen_mode) < mode_order.index(current_mode):
        # Round 8 item P1: with a factor already enrolled, running
        # interactively genuinely is the whole fix (it can prompt for the
        # code/confirm --yes can't). With NOTHING enrolled, "run interactively"
        # is a second hop that still fails closed - the gate denies before it
        # would even prompt (no factor to prompt for) - so name the real first
        # step instead.
        if totp.is_enrolled() or password.is_enrolled():
            _note(
                f"note: --yes cannot lower the mode from {current_mode.value} to "
                f"{chosen_mode.value}: a lowering needs a possession factor (a 2FA code if "
                f"enrolled, otherwise your Doberman password). Run `doberman mode "
                f"{chosen_mode.value}` interactively."
            )
        else:
            _note(
                f"note: --yes cannot lower the mode from {current_mode.value} to "
                f"{chosen_mode.value}: lowering needs a possession factor: run 'doberman "
                f"password set', then 'doberman mode {chosen_mode.value}'."
            )
        mode_applied = False
    elif chosen_mode is current_mode:
        pass  # no-op: nothing to gate or ledger; save_mode below just re-affirms it
    elif first_run:
        # establish_ok bypass: choosing an initial posture is free, mirrors
        # apply_mode_change's own first-run bypass - still ledgered, but only
        # once wiring below actually succeeds (see comment above).
        mode_ledger_pending = (
            classify_change(mode_before, mode_after),
            "doberman setup wizard",
            "logged",
        )
    else:
        classification, approved, method = asyncio.run(
            decide_change(mode_before, mode_after, "doberman setup wizard")
        )
        if approved:
            mode_ledger_pending = (classification, "doberman setup wizard", method)
        else:
            asyncio.run(
                record_change(
                    mode_before,
                    mode_after,
                    classification,
                    "doberman setup wizard",
                    repo_root=path,
                    approved=False,
                    method=method,
                )
            )
            if totp.is_enrolled() or password.is_enrolled():
                _note(
                    "note: mode not lowered (a lowering needs an enrolled possession factor - "
                    "a 2FA code if enrolled, otherwise your Doberman password); keeping the "
                    "current mode"
                )
            else:
                # Round 8 item P1: name the whole path, not just the reason -
                # nothing enrolled means a bare retry (interactive or not)
                # fails closed again with no factor to satisfy the gate.
                _note(
                    "note: mode not lowered - lowering needs a possession factor: run "
                    f"'doberman password set', then 'doberman mode {chosen_mode.value}'; "
                    "keeping the current mode"
                )
            mode_applied = False

    persisted_mode = chosen_mode if mode_applied else current_mode

    # ------------------------------------------------------------------
    # d. Guardrails / preferences - also GATE ONLY (round 5 item P1; round 6
    # item P0 - see the mode section above for why). The actual
    # `save_preferences` call, AND the ledger write for an approved change,
    # are deferred alongside `save_mode` below.
    # ------------------------------------------------------------------
    display_vector = load_preferences(path)  # fallback: unchanged unless overwritten below
    prefs_to_persist = None
    prefs_ledger_ts: str | None = None
    # Set only for an APPROVED-but-not-yet-recorded preferences change.
    prefs_ledger_pending: tuple[dict, dict, Classification, str] | None = None
    if not mode_applied:
        # The mode stayed put; writing a preset/tuned vector for the requested
        # (unapplied) mode would silently overwrite the persisted preferences
        # with no possession-factor check at all. Skip the write entirely.
        prefs_source = "unchanged (the mode change was not applied)"
        typer.echo("note: preferences unchanged (the mode change was not applied)", err=True)
    else:
        preset_vector = vector_for(persisted_mode)
        tune_prefs = False

        if not yes:
            _print_step_section("Preference tuning")
            for line in wrap_detail(
                f"The {persisted_mode.value!r} preset applies these weights: "
                + "  ".join(_dim_label(n, getattr(preset_vector, n)) for n in DIMENSIONS),
                indent=0,
            ):
                typer.echo(line)
            tune_prefs = _confirm_or_abort(
                "Tune individual weights? (advanced)", False, written=_wired_files_clause()
            )

        if tune_prefs:
            vector = preset_vector
            # round 7 item 6: restate which preset is being tuned right above
            # the four prompts - the preset's own weights line printed above
            # (before the "Tune individual weights?" question) can have
            # scrolled off by the time someone answers the fourth prompt.
            typer.echo(f"Tuning the {persisted_mode.value!r} preset:")
            typer.echo("Enter a weight in [0, 1] for each dimension (press Enter to keep current):")
            changed_dims: list[str] = []
            for i, dim in enumerate(DIMENSIONS):
                current = getattr(vector, dim)
                if i:
                    typer.echo()  # item 11 (round 5): own line, or it glues onto the
                    # previous dimension's un-terminated prompt line under a
                    # non-tty stdin (no echo of the fed answer to separate them).
                # item 7 (round 6): every description runs 100+ chars unwrapped
                # with the 2-space indent - wrap it like every other detail
                # line in this wizard.
                for line in wrap_detail(DIMENSION_DESCRIPTIONS[dim], indent=2, hang=0):
                    typer.echo(line)
                # item 9: the identifier is spoken as words in the prompt itself
                # (e.g. "interruption tolerance"); the "tuned: ..." summary below
                # keeps the underscored form since it doubles as the exact
                # `doberman prefs <dimension> <value>` argument. Nothing is
                # written yet at this point (item P1), so an abort here is a
                # genuine "nothing written".
                value = _prompt_menu(
                    f"  {dim.replace('_', ' ')}",
                    f"{current:.2f}",
                    _parse_weight,
                    written=_wired_files_clause(),
                )
                if value != current:
                    changed_dims.append(dim)
                vector = vector.with_weight(dim, value)
            new_vector = vector
            # item 4: name exactly the dimensions that changed, or fall back to
            # the preset name when the user tuned nothing after all.
            prefs_source = (
                f"custom (tuned: {', '.join(changed_dims)})"
                if changed_dims
                else f"preset defaults for {persisted_mode.value}"
            )
        else:
            new_vector = preset_vector
            prefs_source = f"preset defaults for {persisted_mode.value}"

        if first_run:
            # Establishing the initial preference posture is free, same as the
            # mode's own establish_ok bypass.
            prefs_to_persist = new_vector
            display_vector = new_vector
        else:
            # Route through the same gated, raise-only chokepoint `doberman
            # prefs` uses: a lowering relative to the persisted vector needs a
            # possession factor. Under --yes, refuse a lowering up front rather
            # than let the gate open a real confirmation prompt on stdin.
            current_vector = load_preferences(path)
            prefs_before = current_vector.to_mapping()
            prefs_after = new_vector.to_mapping()
            classification = _prefs_classify(prefs_before, prefs_after)
            if classification is Classification.weaken and yes:
                _note(
                    "note: --yes cannot lower preferences below the persisted vector: a "
                    "lowering needs a possession factor (a 2FA code if enrolled, otherwise "
                    "your Doberman password). Run `doberman prefs <dimension> <value>` "
                    "interactively."
                )
                prefs_source = "unchanged (not lowered)"
                display_vector = current_vector
            else:
                classification, approved, method = asyncio.run(
                    decide_preferences_change(prefs_before, prefs_after, "doberman setup wizard")
                )
                if approved:
                    prefs_to_persist = new_vector
                    # Deferred (round 6 item P0, same reasoning as the mode
                    # section above): recorded only once wiring below actually
                    # succeeds.
                    prefs_ledger_pending = (prefs_before, prefs_after, classification, method)
                    display_vector = new_vector
                else:
                    asyncio.run(
                        record_change(
                            prefs_before,
                            prefs_after,
                            classification,
                            "doberman setup wizard",
                            repo_root=path,
                            approved=False,
                            method=method,
                        )
                    )
                    _note(
                        "note: preferences not lowered (a lowering needs a possession "
                        "factor - a 2FA code if enrolled, otherwise your Doberman password); "
                        "keeping the current preferences"
                    )
                    prefs_source = "unchanged (not lowered)"
                    display_vector = current_vector

    # ------------------------------------------------------------------
    # e. Per-host wiring
    # ------------------------------------------------------------------
    # item 2: whether each hooks-kind host was freshly written or was already
    # wired, so both the write line itself and the "Hosts:" summary agree.
    wired_state: dict[str, str] = {}
    claude_scope = "none"

    if yes and ("claude" in chosen_hosts or "codex" in chosen_hosts):
        # item 7 (round 5): the "wrote .../already wired: ..." lines used to
        # print with no header at all under --yes (interactive shows one per
        # host) - give them the same section-header discipline, minus the
        # step counter --yes never shows (item 3). mcp/openclaw already print
        # their own specific header unconditionally, so this only needs to
        # cover the gap for claude/codex.
        _print_step_section("Wiring")

    if "claude" in chosen_hosts:
        if global_:
            claude_scope = "global"
        elif yes or global_declined:
            claude_scope = "project"
        else:
            _print_step_section("Hook installation (Claude Code)", stage="claude")
            # round 7 item 4: name the blast radius before asking - "globally"
            # alone doesn't say WHOSE global, and a wrong answer here wires
            # every other project on this machine into this repo's posture.
            for line in wrap_detail(
                "Global hooks apply to every project on this machine, not just this repo.",
                indent=0,
            ):
                typer.echo(line)
            use_global = _confirm_or_abort(
                "Install hooks globally (~/.claude/settings.json)?",
                False,
                written=_wired_files_clause(),
            )
            claude_scope = "global" if use_global else "project"

        settings_path = resolve_settings_path(claude_scope, path)
        try:
            current = load_settings(settings_path)
        except ValueError as exc:
            typer.echo(f"error: could not read existing settings: {exc}", err=True)
            raise typer.Exit(2) from exc
        merged = merge_doberman_hooks(current)
        if merged == current:
            typer.echo(style_text(f"already wired: {settings_path}", bold=True))
            wired_state["claude"] = "already"
        else:
            try:
                write_settings(settings_path, merged)
            except OSError as exc:
                typer.echo(f"error: could not write {settings_path}: {exc}", err=True)
                raise typer.Exit(1) from exc
            typer.echo(style_text(f"wrote {settings_path}", bold=True))
            wired_state["claude"] = "wrote"
        _record_manifest("claude", claude_scope, settings_path, doberman_groups(merged))
        wired.append(("claude", str(settings_path)))
        _mark_content()  # item 11: no header under --yes/flags, but real content just printed

    if "codex" in chosen_hosts:
        if global_:
            codex_scope = "user"
        elif yes or global_declined:
            codex_scope = "repo"
        else:
            _print_step_section("Hook installation (Codex CLI)", stage="codex")
            use_user = _confirm_or_abort(
                "Install the Codex hook user-wide (~/.codex/hooks.json)?",
                False,
                written=_wired_files_clause(),
            )
            codex_scope = "user" if use_user else "repo"
        # item 14: the epilogue gives Codex the same "Verify it's live" pointer
        # every wired host gets, so this ritual doesn't print its own copy.
        codex_hooks_path, codex_already = _write_codex_hook(codex_scope, path, show_verify=False)
        wired_state["codex"] = "already" if codex_already else "wrote"
        wired.append(("codex", str(codex_hooks_path)))
        _mark_content()  # item 11: same as claude above

    if "mcp" in chosen_hosts:
        _print_step_section("MCP proxy (Cursor / Claude Desktop / other MCP client)", stage="mcp")
        for line in wrap_detail(
            "Doberman can't edit this host's MCP config for you; paste this into it, "
            "replacing <your-mcp-server-command> with your existing tool server command:",
            indent=0,
        ):
            typer.echo(line)
        typer.echo("")
        typer.echo("  doberman serve -- <your-mcp-server-command>")
        typer.echo("")
        typer.echo("Or, in a Claude-Desktop-style mcpServers config file:")
        typer.echo("{")
        typer.echo('  "mcpServers": {')
        typer.echo('    "doberman": {')
        typer.echo('      "command": "doberman",')
        typer.echo('      "args": ["serve", "--", "<your-mcp-server-command>"]')
        typer.echo("    }")
        typer.echo("  }")
        typer.echo("}")
        wired.append(("mcp", None))

    if "openclaw" in chosen_hosts:
        _print_step_section("OpenClaw", stage="openclaw")
        # item 7 (round 6): 83 chars unwrapped - the very next line already
        # goes through wrap_detail, this one just got missed.
        for line in wrap_detail(
            "OpenClaw agents route through Doberman via a small local plugin, not a hook-pack.",
            indent=0,
        ):
            typer.echo(line)
        for line in wrap_detail(
            f"See {_OPENCLAW_README_URL} for install steps and the mandatory canary check.",
            indent=0,
        ):
            typer.echo(line)
        wired.append(("openclaw", None))

    hooks_kind_wired = [h for h in wired if next(x for x in HOSTS if x.key == h[0]).kind == "hooks"]

    # ------------------------------------------------------------------
    # e1. Persist the mode + preferences NOW that per-host wiring has
    # succeeded (round 5 item P1: no raised-mode trap). Everything above this
    # point only computed what WOULD be written and ran the interactive gate
    # (confirm + possession factor on a lowering) - nothing touched
    # `.doberman/policies.yaml` until here, so every abort/crash above this
    # line leaves the mode/prefs genuinely unwritten. Round 6 item P0: the
    # ledger row for an APPROVED change is written here too, not before - so
    # `doberman policy-history` never shows an entry for a change this run
    # never actually persisted.
    # ------------------------------------------------------------------
    if mode_applied:
        if mode_ledger_pending is not None:
            classification, reason, method = mode_ledger_pending
            mode_ledger_ts = asyncio.run(
                record_change(
                    mode_before,
                    mode_after,
                    classification,
                    reason,
                    repo_root=path,
                    approved=True,
                    method=method,
                )
            ).ts
        save_mode(persisted_mode.value, path, ledger_ts=mode_ledger_ts)
    if prefs_to_persist is not None:
        if prefs_ledger_pending is not None:
            p_before, p_after, classification, method = prefs_ledger_pending
            prefs_ledger_ts = asyncio.run(
                record_change(
                    p_before,
                    p_after,
                    classification,
                    "doberman setup wizard",
                    repo_root=path,
                    approved=True,
                    method=method,
                )
            ).ts
        save_preferences(prefs_to_persist, path, ledger_ts=prefs_ledger_ts)

    def _post_wiring_written_clause() -> str | None:
        """What this run has now persisted - used only by the telemetry
        prompt below, the one prompt reached after the write above (round 5
        item 2): names the mode/prefs it just saved, plus any wired hook file
        (e.g. `.claude/settings.json`), instead of the generic pre-wiring
        "nothing written"."""
        parts: list[str] = []
        if mode_applied:
            parts.append(f"security mode {persisted_mode.value}")
        if prefs_to_persist is not None:
            parts.append("preferences")
        hooks_clause = _wired_files_clause()
        if hooks_clause:
            parts.append(hooks_clause)
        return ", ".join(parts) if parts else None

    # ------------------------------------------------------------------
    # e2. Telemetry - after wiring (nothing to consent to before there's a
    # host to report), before the doctor pass (so a critical below still
    # reports whatever consent was just given).
    # ------------------------------------------------------------------
    _print_step_section("Telemetry")
    if no_telemetry:
        from doberman import telemetry

        telemetry.disable()
        typer.echo("off (--no-telemetry)")
    else:
        telemetry_cmd.configure_setup_consent(
            yes,
            confirm=lambda text, default: _confirm_or_abort(
                text, default, written=_post_wiring_written_clause()
            ),
        )
    _mark_content()  # item 11: the consent branch's own confirm prompt isn't tracked

    # ------------------------------------------------------------------
    # f. Doctor pass
    # ------------------------------------------------------------------
    _print_step_section("Doctor")
    # Starts empty so a doctor *crash* (caught below) reads as "could not be
    # determined" rather than as a known critical — the honest-end gate below
    # only fires on an *actual* critical the doctor pass found, not on doctor
    # itself being unavailable (a separate, already-reported failure mode).
    critical: list = []
    try:
        from doberman.cli.doctor import CheckStatus, critical_failures, run_checks

        results = run_checks(path)
        critical = critical_failures(results)
        if not hooks_kind_wired:
            # Nothing hooks-based was wired this run (mcp/openclaw only) — the
            # hook checks have nothing to diagnose, so they'd only ever read as
            # a false "not installed" critical. Scope them out and say so.
            hooks_only = {"Host hooks", "Hook command"}
            critical = [r for r in critical if r.name not in hooks_only]
        # Non-critical warnings (no decision DB or fingerprint key yet, no TUI
        # extra) are normal right after a fresh setup — count them, don't list
        # them as failures; `doberman doctor` has the detail.
        warnings = [r for r in results if r.status is not CheckStatus.OK and r not in critical]
        passed = len(results) - len(critical) - len(warnings)
        line = f"Doctor: {passed} passed"
        if warnings:
            # item 11 (round 6): name each warning right here instead of
            # making every run open `doberman doctor` just to find out which
            # checks warned.
            warning_names = ", ".join(r.name for r in warnings)
            line += f", {len(warnings)} warning(s): {warning_names} (`doberman doctor` for detail)"
        if critical:
            line += f", {len(critical)} critical - needs attention:"
        if not hooks_kind_wired:
            line += " (hooks n/a for this host)"
        if critical:
            fg, bold = "bright_red", True
        elif warnings:
            fg, bold = "yellow", True
        else:
            fg, bold = "green", False
        for summary_line in wrap_detail(line, indent=0):
            typer.echo(style_text(summary_line, fg, bold=bold))
        for r in critical:
            for wrapped_line in wrap_detail(f"- {r.name}: {r.detail}", indent=2, hang=2):
                typer.echo(wrapped_line)
    except Exception:  # noqa: BLE001 — a diagnostic pass must never crash setup
        typer.echo("Doctor: could not run here; verify with `doberman doctor`")

    # ------------------------------------------------------------------
    # g. Summary
    # ------------------------------------------------------------------
    # Honest end (P0): a critical the doctor pass just found means Doberman is
    # NOT actually protecting this repo yet, so the header, the "hooks
    # written/activates" claim, and the exit code must say so - never "complete"
    # + exit 0 on top of a diagnostic that says tool calls go unmediated. And a
    # run that wired only mcp/openclaw (no hook-kind host) has nothing running
    # yet either - a manual paste-and-restart step still stands between here
    # and protection, so it is "pending", never "complete".
    # Round 6 item P1: a MIXED run (e.g. `--host claude --host mcp`) used to
    # compute `pending` as "nothing hooks-kind wired at all" - so one wired
    # hooks-kind host (claude, active) hid an still-unwired mcp/openclaw host
    # (a manual paste-and-restart step still outstanding) behind "Setup
    # complete" + exit 0. `manual_wired` names the mcp/openclaw hosts this run
    # actually chose; "partly pending" is the mixed case, distinct from the
    # existing "pending" (every chosen host is manual-only).
    manual_wired = [h for h in wired if h not in hooks_kind_wired]
    setup_ok = not critical
    fully_manual_pending = setup_ok and not hooks_kind_wired and bool(wired)
    mixed_pending = setup_ok and bool(hooks_kind_wired) and bool(manual_wired)
    pending = fully_manual_pending or mixed_pending
    if not setup_ok:
        header = "Setup incomplete"
    elif mixed_pending:
        header = "Setup partly pending"
    elif fully_manual_pending:
        header = "Setup pending"
    else:
        header = "Setup complete"
    marker = "--" if header == "Setup complete" else "!!"
    # round 7 item P1 (2): a refused `--mode <lower>` request is folded right
    # into the closing header, not just the "Mode:" line below it - a reader
    # who only sees the header (or a script keying off it) still learns the
    # requested mode was refused. The exit code is unchanged either way (0 for
    # "Setup complete": the run completed as designed - see docs/CLI.md and
    # docs/SETUP.md, which spell out that exit 0 means "ran to completion",
    # never "you got the mode you asked for").
    if persisted_mode is not chosen_mode:
        header += f" (mode kept: {persisted_mode.value}; {chosen_mode.value} refused)"
    docs_url = "https://github.com/DobermanCore/Doberman-Core/blob/main/docs/SETUP.md"

    _print_step_section(header, marker=marker)
    # item 4: wrap through wrap_detail with a hanging indent, so a long "not
    # lowered" reason wraps under the mode value's column instead of running
    # off past 78 columns. Wrap the PLAIN text first (styling wraps the mode
    # value in ANSI codes that would otherwise inflate the counted width),
    # then color just that one word on the first wrapped line.
    plain_mode_line = f"Mode:       {persisted_mode.value}"
    if persisted_mode is not chosen_mode:
        # item 5: the reason travels with the summary line itself, so
        # redirected stdout alone (`2>/dev/null`) still explains the refusal.
        # item 12 (round 6): "possession factor" is glossed right here too -
        # a stdout-only redirect drops every earlier stderr `note:` that
        # already glossed it, so this line is that reader's first (and only)
        # encounter with the term.
        # Round 8 item P1: with nothing enrolled, naming just the retry
        # command was a second hop - a bare `doberman mode <name>` fails
        # closed again with no factor to satisfy the gate. Name the whole
        # path in that case; with a factor already enrolled, the retry
        # command alone is the whole fix.
        if totp.is_enrolled() or password.is_enrolled():
            plain_mode_line += (
                f" (requested {chosen_mode.value}; not lowered - a possession factor (a "
                f"2FA code if enrolled, otherwise your Doberman password) is required, "
                f"run 'doberman mode {chosen_mode.value}')"
            )
        else:
            plain_mode_line += (
                f" (requested {chosen_mode.value}; not lowered - lowering needs a "
                f"possession factor: run 'doberman password set', then 'doberman mode "
                f"{chosen_mode.value}')"
            )
    mode_lines = wrap_detail(plain_mode_line, indent=0, hang=12)
    fg, bold = _MODE_STYLE[persisted_mode.value]
    mode_lines[0] = mode_lines[0].replace(
        persisted_mode.value, style_text(persisted_mode.value, fg, bold=bold), 1
    )
    for line in mode_lines:
        typer.echo(line)
    # item 9: the setup summary's "Prefs:" line restates the four numbers, not
    # just the source label - `status`'s own "Prefs:" line does the same.
    plain_prefs_line = f"Prefs:      {prefs_source}: " + "  ".join(
        _dim_label(n, getattr(display_vector, n)) for n in DIMENSIONS
    )
    for line in wrap_detail(plain_prefs_line, indent=0, hang=12):
        typer.echo(line)
    typer.echo("Hosts:")
    verify_hosts: list[str] = []
    for host_key, target in wired:
        if host_key == "claude":
            verb = (
                "already wired:" if wired_state.get("claude") == "already" else "hooks written to"
            )
            typer.echo(f"  claude   {verb} {target}")
            verify_hosts.append("claude")
        elif host_key == "codex":
            verb = "already wired:" if wired_state.get("codex") == "already" else "hook written to"
            typer.echo(f"  codex    {verb} {target}")
            # item 1: Codex gets the same "verify it's live" epilogue pointer
            # as Claude/mcp, not only the mid-wiring TRUST ritual above.
            verify_hosts.append("codex")
        elif host_key == "mcp":
            typer.echo("  mcp      paste the block above into your client, then restart it")
            verify_hosts.append("mcp")
        elif host_key == "openclaw":
            # item 7 (round 6): the URL alone pushes this well past 78 columns
            # - wrapped like every other detail line (the URL token itself is
            # never split mid-token by `wrap_detail`, so its own line is
            # exempt from the width cap, same as every other URL here).
            for line in wrap_detail(
                f"openclaw follow {_OPENCLAW_README_URL}, then run its canary check",
                indent=2,
                hang=2,
            ):
                typer.echo(line)
    typer.echo("")
    blank_pending = True  # item 11: the "Hosts:" block just ended on this blank

    # An incomplete run gets the remedy and nothing else: no Telemetry/Also/
    # demo epilogue, and never the demo/verify peak-end below.
    if not setup_ok:
        for line in wrap_detail(f"Docs: {docs_url}", indent=0):
            typer.echo(line)
        typer.echo("Check health:  doberman doctor")
        first = critical[0]
        # item 8: the doctor block above already printed this critical's full
        # "- name: detail" once; the closing sentence references it by name
        # only, instead of repeating (a truncated copy of) the same detail.
        for line in wrap_detail(
            f"Not protecting this repo yet: fix '{first.name}' above, then run 'doberman doctor'.",
            indent=0,
        ):
            typer.echo(style_text(line, "bright_red", bold=True))
        raise typer.Exit(code=1)

    if hooks_kind_wired:
        # item 6: never claim "Hooks written." on a re-run that wrote nothing -
        # true only if at least one hooks-kind host was freshly written this
        # run; a run where every one was already wired says so instead.
        any_freshly_written = any(wired_state.get(h) == "wrote" for h, _ in hooks_kind_wired)
        verb = "Hooks written." if any_freshly_written else "Hooks already in place."
        # Round 8 item P1: Claude Code and Codex activate differently - saying
        # only "restart your session" is flatly wrong for a Codex-only wire
        # (nothing to restart; Codex arms the hook once you trust it on its
        # first run, already explained mid-wiring above). Say whichever is
        # actually true for the host(s) this run wired.
        wired_kind_keys = {h for h, _ in hooks_kind_wired}
        codex_activation = (
            "Codex asks you to trust the hook the first time it runs; Doberman "
            "gates its tool calls after that."
        )
        if wired_kind_keys == {"codex"}:
            activation = codex_activation
        elif "codex" in wired_kind_keys:
            activation = f"Doberman activates when you restart your session. {codex_activation}"
        else:
            activation = "Doberman activates when you restart your session."
        hooks_message = f"{verb} {activation}"
        for line in wrap_detail(hooks_message, indent=0):
            typer.echo(line)
        blank_pending = False

    telemetry_cmd.capture_setup_completed(
        chosen_mode.value, [h for h, _ in wired], claude_scope, yes
    )
    if password.is_enrolled() or totp.is_enrolled():
        factor = "2FA" if totp.is_enrolled() else "password"
        if not blank_pending:
            typer.echo("")
        typer.echo(f"Possession factor: set ({factor}).")
        blank_pending = False

    # ------------------------------------------------------------------
    # Peak-end epilogue (item 1): one primary next step, not seven
    # equal-weight lines. Order: Verify it's live -> Next (bold) -> Also
    # (muted, everything else, compact). A pending run (mcp/openclaw only)
    # has nothing live to verify yet - it gets its own pointer to the still-
    # manual paste-and-restart step instead. `pending` and `verify_hosts`/
    # `hooks_kind_wired` are complementary given `setup_ok` is True here (we
    # already returned above otherwise), so exactly one of the two blocks
    # below prints - the leading blank (item 11) is never followed by nothing.
    # ------------------------------------------------------------------
    if not blank_pending:
        typer.echo("")
    if pending:
        # item 13: openclaw has no paste step, unlike mcp - name the actual
        # remaining manual step instead of a generic "paste the block". item 8
        # (round 5): this IS "Next:" for a pending run - the in-process demo
        # below doesn't prove the still-manual mcp/openclaw wiring works, so
        # it must never claim that slot; it's a low-key `Also:` pointer there
        # instead.
        pending_hosts = {host_key for host_key, _ in wired}
        if "mcp" in pending_hosts:
            # item 12 (round 6): one colon, not two - the second (after
            # "client") is a comma now; the label's own colon is the only one.
            pending_message = (
                "Next: After you paste the block and restart your client, ask your agent "
                "to read .env and confirm it is blocked."
            )
        else:
            pending_message = (
                f"Next: After you follow {_OPENCLAW_README_URL} and restart, ask your "
                "agent to read .env and confirm it is blocked."
            )
        for line in wrap_detail(pending_message, indent=0, hang=6):
            typer.echo(style_text(line, bold=True))
    elif verify_hosts:
        for line in wrap_detail(
            "Verify it's live: ask your agent to read .env and confirm it is blocked.",
            indent=0,
        ):
            typer.echo(line)

    if hooks_kind_wired and not pending:
        # item 7: the demo offer counts as a step too; item 12: the prompt
        # text itself carries no "Next:" label - only the final printed line
        # (the fallback below, or --yes's own line) does. item 8 (round 5):
        # a pending run no longer reaches this offer at all - see above.
        # round 7 item 3: a MIXED (partly-pending) run has ``hooks_kind_wired``
        # non-empty too, so ``not pending`` is the guard that actually keeps
        # this offer out of that case - without it the "pending" block above
        # AND this offer's own EOF/--yes/"n" fallback each print their own
        # "Next:" line, so a partly-pending close showed two.
        # item 7 (round 6): runs to 90+ chars unwrapped - wrap it like every
        # other prompt text in the wizard. `typer.confirm` writes this string
        # as-is before reading input, so an embedded newline just moves the
        # visible prompt (and the ``[Y/n]:`` suffix/answer that follows it)
        # onto the wrapped line. Round 8 item P1: the ``[N of M]`` step
        # counter used to be appended mid-sentence here - it now lives in its
        # own section header (``_print_step_section`` below), same as every
        # other step, instead of tacked onto the question text.
        demo_question = "\n".join(
            wrap_detail(
                "See it work? Run a scripted attack through the real engine now "
                "(`doberman demo --fast`)",
                indent=0,
            )
        )
        if yes:
            typer.echo(style_text("Next: `doberman demo --fast`", bold=True))
        else:
            _print_step_section("See it work", stage="Demo")
            try:
                answer = _read_yes_no_or_quit(style_text(demo_question, bold=True), True)
            except (EOFError, typer.Abort):
                # A closed/exhausted stdin (or Ctrl-C) here must never fail an
                # already-succeeded setup. The confirm prompt already wrote
                # its text with no trailing newline (item 11/13) - a blank
                # line first keeps the "Next:" fallback below from gluing
                # onto it.
                typer.echo()
                answer = "n"
            if answer == "q":
                # round 7 item 5: 'q' here declines the demo, not the whole
                # run - setup already succeeded by this point (this offer
                # never even runs otherwise - see ``not pending`` above), so
                # quitting the still-optional demo must never flip the exit
                # code. The wording matches every other abort in this wizard
                # even though the exit code doesn't (see _abort_message).
                typer.echo(_abort_message(_wired_files_clause()), err=True)
            want_demo = answer in ("y", "")
            if want_demo:
                typer.echo("")
                demo_outcomes = run_demo(
                    mode=persisted_mode.value,
                    repo_root=path,
                    fast=True,
                    on_scenario=lambda outcome: typer.echo(format_outcome_line(outcome)),
                )
                typer.echo("")
                typer.echo(format_summary_table(demo_outcomes))
            else:
                # item 8 (round 6): an explicit interactive "n" used to end
                # the run on NOTHING - only the EOF/--yes paths got the
                # "Next:" pointer. Every success path ends on one, now.
                typer.echo(style_text("Next: `doberman demo --fast`", bold=True))

    # item 6 (round 5): the close doesn't compete with itself - at most THREE
    # items here. `doberman password set` moves into `doctor`'s own advice
    # (its Password check already warns and names the same command), and
    # `doberman telemetry off` moves into the Telemetry section's own line
    # above - neither is repeated here. A pending run's demo pointer (item 8)
    # is the one thing that takes a 4th slot's "budget" - a fully-manual
    # pending run (no hooks-kind host) never adds `uninstall-hooks` too,
    # keeping the count at three there. A "Setup partly pending" (round 6 item
    # P1) run has both, for four bullets - honest over terse when a run
    # genuinely has both a wired hooks host to remove and a manual step left.
    also_bullets: list[str] = ["`doberman doctor`"]
    if hooks_kind_wired:
        also_bullets.append("`doberman uninstall-hooks`")
    if pending:
        also_bullets.append("`doberman demo --fast` (see it work first)")
    also_bullets.append(f"docs: {docs_url}")
    typer.echo("")
    for line in wrap_detail("Also: " + " | ".join(also_bullets), indent=0):
        typer.echo(style_text(line, "bright_black"))

    if pending:
        # item 7: "pending" is a distinct, honest exit code - not the same 0
        # a fully-wired run gets, and not the 1 an actual critical gets.
        raise typer.Exit(code=3)


@app.command("session-summary", rich_help_panel="Daily")
def session_summary() -> None:
    """Print the device-global session-guard summary and exit.

    Formerly ``doberman dashboard``.

    Reads the lifetime rollup at ``~/.doberman/metrics.db`` (every decision on
    this device, across all repos/sessions, increments it - see
    ``doberman.storage.device_metrics``) and prints a compact panel. This is a
    print-and-exit command, not an interactive dashboard: it is wired as a
    Claude Code SessionStart hook (``doberman install-hooks``), so it must
    never block or crash a session - it always exits 0 and never raises.
    """
    try:
        from doberman.storage.device_metrics import read_metrics, render_dashboard

        typer.echo(render_dashboard(read_metrics()))
    except Exception:  # noqa: BLE001, S110 — a dashboard must never break session start
        pass
    raise typer.Exit(0)


@app.command("dashboard", hidden=True)
def dashboard() -> None:
    """Run the deprecated alias for ``doberman session-summary``."""
    session_summary()


@app.command(rich_help_panel="Advanced")
def version() -> None:
    """Print the installed Doberman version."""
    typer.echo(__version__)


# Typer/Rich list commands within a help panel in `app.registered_commands`
# order. `setup` (the guided path) should lead "Getting started", followed by
# `demo` (the best onboarding asset), then the rest - reorder that list once
# here (a stable sort, so every other command keeps its registration order)
# instead of moving command definitions around this file.
_GETTING_STARTED_LEAD = {"setup": 0, "demo": 1, "doctor": 2, "install-hooks": 3, "update": 4}


def _command_name(command: typer.models.CommandInfo) -> str:
    return command.name or command.callback.__name__.replace("_", "-")


app.registered_commands.sort(
    key=lambda c: _GETTING_STARTED_LEAD.get(_command_name(c), len(_GETTING_STARTED_LEAD))
)


if __name__ == "__main__":  # pragma: no cover
    app()

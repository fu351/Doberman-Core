"""Destructive-command rule (Feature 3, slice 3.4).

Blocks catastrophic shell/git commands and steps up authentication on
risky-but-recoverable ones. Command parsing is treated as **adversarial**: a
single command string may chain many commands with ``;``, ``&``, ``&&``, ``||``,
or pipes, hide work in ``$(...)``/backtick substitutions, or carry an opaque
payload (``bash -c "<base64>"``). We therefore:

* split the command line into segments on the shell operators, and recurse into
  command-substitution bodies, so a destructive segment anywhere in the line is
  seen;
* match each segment's argv (parsed with :mod:`shlex`, env-assignment and
  ``sudo``/``nice`` prefixes stripped) against deny / step-up tables;
* treat anything we **cannot** confidently parse — opaque ``-c`` payloads,
  unbalanced quoting — as ``AUTH``, never PASS. We never *execute* anything to
  analyze it.

Verdicts:

* ``rm -rf /`` (or ``~`` / ``/*``), disk wipes (``mkfs``, ``dd of=/dev/...``),
  ``git push --force`` to a protected branch, fork bombs → ``BLOCK
  (destructive_command)``.
* recoverable-but-risky (``sudo``, ``curl | sh``, bulk deletes at/over the
  threshold, ``git reset --hard``) → ``AUTH``.
* opaque / unparseable commands → ``AUTH (opaque_command)``.
* small/benign commands → abstain (``PASS``).

SECURITY: the explanation names the *category* of danger, never echoes the
command string or its arguments.
"""

import fnmatch
import posixpath
import re
import shlex
from collections.abc import Iterable

from doberman.engine.rules.paths import names_control_plane, needs_filesystem_resolution
from doberman.models import (
    ActionType,
    EvalContext,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    Verdict,
)
from doberman.policy.modes import thresholds_for

# Doberman's own CLI subcommands that install/remove the host hooks or otherwise
# mutate the control plane (posture, enforcement, auth factors, or an active
# elevation): an agent invoking these through a shell is tampering with the cop,
# not doing project work (HK.5.0b). The human runs these directly (not via a
# gated tool), so the hook only ever sees the *agent* invoking them. Read/utility
# verbs (`status`, `doctor`, `encode-safe`, `log`, `scan`, `review`) are
# deliberately excluded — they don't mutate anything. `memory` joined this set
# with Subj1's `memory reset`/`memory prune` (they mutate the learned behavioral
# baseline/preference memory, the same class of action as `taint`); the bare
# read-only `doberman memory` summary is blocked as collateral — the CLI verb
# has no subcommand granularity here, and an unrecognized/ambiguous case fails
# closed like everywhere else in this module.
_DOBERMAN_CONTROL_SUBCOMMANDS = {
    "install-hooks",
    "uninstall-hooks",
    "uninstall",
    "setup",
    "mode",
    "prefs",
    "enforcement",
    "2fa",
    "taint",
    "password",
    "revoke",
    "memory",
    "decision-log-prune",
    "tools",
    "approvals",
    # `tune --accept` grants a standing elevation (a weakening) through the
    # same gated chokepoint as any other loosening (#243) — shelling it out
    # is the same tampering shape as `revoke`/`2fa`/`taint`.
    "tune",
}

#: Default bulk-operation threshold: deleting/touching this many paths in one
#: command steps up to AUTH. Overridable (F6 wires this from policy/mode).
DEFAULT_BULK_THRESHOLD = 25

#: Action types the proxy itself labels as command-bearing (normalize.py's
#: ``_COMMAND_EGRESS_ACTIONS``) — these get the ``action.target`` fallback too.
_COMMAND_ACTION_TYPES = frozenset(
    {ActionType.shell_exec, ActionType.git_op, ActionType.package_install}
)

#: Branch names whose history is protected — a force-push here is catastrophic.
DEFAULT_PROTECTED_BRANCHES: tuple[str, ...] = ("main", "master", "release", "develop")


def _normalize_branch_name(name: str) -> str:
    """Normalize a protected-branch name to match how the actual pushed ref
    gets normalized (see ``_git_force_push_to_protected`` below): strip
    surrounding whitespace, lower-case, then drop a leading ``refs/heads/``
    (lower-cased first so a differently-cased prefix still strips). Without
    this, a copy-pasted ``"refs/heads/staging"`` or ``" staging"`` would pass
    schema validation but silently never match a real push (#199 review).

    Mirrored in ``doberman.config._extra_protected_branches`` for role.yaml
    entries -- keep both in sync if this logic changes.
    """
    stripped = name.strip().lower()
    if stripped.startswith("refs/heads/"):
        stripped = stripped[len("refs/heads/") :]
    return stripped


#: git commit flags that skip hooks or signing (C4). Pre-commit/pre-push hooks
#: often run tests/lint, and a commit signature vouches for authorship — an
#: agent quietly disabling either is stepping around a safety net it is
#: supposed to satisfy, not a catastrophic/irreversible act on its own, so this
#: is AUTH with its OWN reason code — never ReasonCode.destructive_command,
#: which sits on FLOOR_HARD_BLOCKS (policy/modes.py) and would silently turn
#: every skip into a mode-independent hard BLOCK.
_VERIFICATION_BYPASS_LONG_FLAGS = {"--no-verify", "--no-gpg-sign"}

#: git config keys that can reproduce --no-verify/--no-gpg-sign's effect at
#: the CONFIG level (``-c key=value`` / ``--config-env=key=envvar`` BEFORE the
#: subcommand) instead of as a flag ON ``commit`` itself — same evasion class,
#: different syntax, so the flag-only scan above misses it entirely.
#: ``core.hooksPath`` repoints (or empties, e.g. ``/dev/null``) the hooks
#: directory for the WHOLE invocation regardless of value: an override is
#: suspicious on its own, and a ``--config-env=`` indirection through an
#: environment variable can't be resolved statically either, so presence
#: alone is enough to raise. ``commit.gpgsign`` only bypasses signing when set
#: to a git-boolean-false value.
_GIT_HOOKS_PATH_CONFIG_KEY = "core.hookspath"
_GIT_GPGSIGN_CONFIG_KEY = "commit.gpgsign"
_GIT_FALSY_CONFIG_VALUES = {"false", "no", "off", "0"}

#: git global options that take their value as a SEPARATE following token
#: (``-C <path>``, ``-c <k=v>``, and every long option below in its bare —
#: i.e. no ``=`` — form) — both the option and its value token must be
#: skipped when hunting for the actual subcommand. Verified against installed
#: ``git 2.54.0.windows.1``: each of these accepts BOTH ``--opt <value>`` and
#: ``--opt=<value>`` identically (issue #550 review — the space-separated
#: form previously desynced the verb walk: ``/repo`` in
#: ``git --git-dir /repo push --force`` was read as the verb, so a real
#: force-push silently PASSed). Every other long global option
#: (``--no-pager``, ``--bare``, ...) either carries its value in the same
#: token (``=``) or takes none at all (``--html-path``/``--man-path``/
#: ``--info-path`` — confirmed these ignore any following token, ``=``-joined
#: or not, rather than consuming it, so they're correctly left OUT of this
#: set), so a generic "any other leading -/-- token" skip covers them.
_GIT_GLOBAL_OPTIONS_WITH_VALUE = {
    "-C",
    "-c",
    "--git-dir",
    "--work-tree",
    "--namespace",
    "--exec-path",
    "--super-prefix",
    "--config-env",
}

#: git commit short options that take a MANDATORY value — either as the rest
#: of their own cluster (``-mFixBug``) or, when the cluster ends exactly at
#: the option letter (bare ``-m``), as the following token. Once one of these
#: is seen, the remainder of that cluster is the option's value, and — for
#: the bare form — so is the whole next token; neither is ever scanned for
#: further flags.
_GIT_COMMIT_MANDATORY_VALUE_SHORT_OPTIONS = set("mFCct")

#: git commit short options whose value is OPTIONAL, and — critically — when
#: present is ONLY ever attached in the SAME token. ``-S[<keyid>]`` (GPG-sign)
#: and ``-u[<mode>]`` (``--untracked-files[=<mode>]``) are git's two such
#: commit options: ``-Skeyid``/``-uno`` carry their value attached, but a bare
#: ``-S``/``-u`` never consumes the next token — unlike the mandatory-value
#: options above. Seeing one of these still ends the cluster scan (the rest of
#: the token, if any, is its value), but must NEVER set skip_next — doing so
#: would swallow the next flag token whole (e.g. ``-S --no-verify`` would
#: silently skip ``--no-verify``), a fail-open bug. Without ``"u"`` here,
#: ``-uno``/``-unormal``/``-uall`` were misread by the generic per-char scan:
#: the "n" in "no"/"normal" was mistaken for the ``-n`` bypass flag.
_GIT_COMMIT_OPTIONAL_VALUE_SHORT_OPTIONS = set("Su")

# Command-substitution bodies: $(...) and `...`. We recurse into these so a
# destructive command hidden inside a substitution is still evaluated.
_SUBSTITUTION = re.compile(r"\$\((?P<paren>[^()]*)\)|`(?P<backtick>[^`]*)`")

# Env-assignment prefixes (FOO=bar) and benign wrappers we look through.
_ENV_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")

# T5 — wrapper name -> the options that consume the NEXT token as a value. A
# value written attached (``-uroot``) or with ``=`` (``--user=root``) is
# self-contained and is just a flag; only a BARE spelling from this set pops
# an extra token. Every other leading ``-``/``--`` token on a wrapper is
# popped as a bare flag (its arity is unknown, so it's dropped, never treated
# as the command) -- see ``argv_from_tokens``. ``sudo``'s ``-h`` is
# deliberately absent: ``sudo -h`` is help, a bare flag, not a value option.
_WRAPPER_VALUE_OPTIONS: dict[str, frozenset[str]] = {
    "sudo": frozenset(
        {
            "-u",
            "-g",
            "-C",
            "-D",
            "-p",
            "-r",
            "-t",
            "-T",
            "-U",
            "-R",
            "--user",
            "--group",
            "--chdir",
            "--prompt",
            "--role",
            "--type",
            "--close-from",
            "--other-user",
            "--timeout",
        }
    ),
    "doas": frozenset({"-u", "-C"}),
    # I2: `-c`/`--command` are deliberately absent — runuser's own payload
    # option is opaque like `su -c`, never a transparent value option (see
    # `_WRAPPER_OPAQUE_OPTIONS`/`_wrapper_opaque_option_ahead` below).
    "runuser": frozenset({"-u", "-g", "-G", "--user", "--group", "--supp-group"}),
    "env": frozenset({"-u", "-C", "-S", "--unset", "--chdir", "--split-string"}),
    "nice": frozenset({"-n", "--adjustment"}),
    "ionice": frozenset(
        {"-c", "-n", "-p", "-P", "-u", "--class", "--classdata", "--pid", "--pgid", "--uid"}
    ),
    "timeout": frozenset({"-k", "-s", "--kill-after", "--signal"}),
    "chroot": frozenset({"--userspec", "--groups"}),
    "time": frozenset({"-f", "-o", "--format", "--output"}),
    "exec": frozenset({"-a"}),
    "stdbuf": frozenset({"-i", "-o", "-e", "--input", "--output", "--error"}),
    "nohup": frozenset(),
    "command": frozenset(),
    "setsid": frozenset(),
    # #555: `builtin <name> [args]` forces builtin resolution over any
    # same-named function, exactly like `command` forces external resolution
    # — transparent, no options of its own, so it hides a destructive segment
    # (`builtin rm -rf /`) the same way an unstripped `command`/`exec` would.
    "builtin": frozenset(),
    # #634: strace/taskset/flock/unshare were missing entirely, so their bare
    # name shifted argv so a flag (or its value) was misread as the wrapped
    # command — a silent PASS for `strace -f rm -rf /`, `taskset -c 0 rm -rf
    # /`, `flock /tmp/lock rm -rf /`, `unshare -n rm -rf /` (and, via the
    # shared `_command_verb` egress classifier, `unshare -n curl ...`).
    # strace(1): only the options that take a SEPARATE value token; `-f`/
    # `--seccomp-bpf`/etc. are bare flags with no value and fall through to
    # the generic bare-flag drop.
    "strace": frozenset(
        {
            "-o",
            "-e",
            "-p",
            "-s",
            "-a",
            "-E",
            "-I",
            "-P",
            "-u",
            "-X",
            "-b",
            "-O",
            "-S",
            "--output",
            "--trace",
            "--attach",
            "--user",
        }
    ),
    # taskset(1): `-a`/`-c`/`--cpu-list`/`-p`/`--pid` are all bare flags (no
    # `:` in taskset's own getopt string) — the CPU mask/list that follows is
    # a fixed positional, not an option value (see `_WRAPPER_POSITIONALS`).
    "taskset": frozenset(),
    # unshare(1): its own namespace flags (`-m`/`-u`/`-i`/`-n`/`-p`/`-U`/
    # `-C`/`-T`, `--mount-proc`, `--kill-child`) take only an OPTIONAL value
    # attached via `=`/same-token — never a separate token — so they are bare
    # flags here, same as `--fork`/`-r`/`--map-root-user`. The set below is
    # the options that DO take a mandatory separate-token value.
    "unshare": frozenset(
        {
            "--map-user",
            "--map-group",
            "--propagation",
            "--setgroups",
            "-R",
            "--root",
            "-w",
            "--wd",
            "-S",
            "--setuid",
            "-G",
            "--setgid",
        }
    ),
    # flock(1): the lock file/fd is a fixed positional (`_WRAPPER_POSITIONALS`
    # below); `-c`/`--command` is an opaque payload option, not a value
    # option (`_WRAPPER_OPAQUE_OPTIONS`).
    "flock": frozenset({"-w", "--timeout", "-E", "--conflict-exit-code"}),
}
#: Existing readers of the bare-name set keep working.
_TRANSPARENT_WRAPPERS = frozenset(_WRAPPER_VALUE_OPTIONS)
#: Wrappers that take a fixed number of positional arguments BEFORE the
#: wrapped command (``timeout DURATION cmd``, ``chroot NEWROOT cmd``,
#: ``taskset MASK cmd``, ``flock FILE cmd``).
_WRAPPER_POSITIONALS = {"timeout": 1, "chroot": 1, "taskset": 1, "flock": 1}

#: I2 — a wrapper key here is otherwise transparent (its OTHER options are in
#: `_WRAPPER_VALUE_OPTIONS`), but one of these markers turns the whole
#: invocation opaque, exactly like ``su -c``: ``runuser -c``/``--command`` is
#: a root shell running an arbitrary payload, not a value option whose arity
#: is "one following token". See ``_wrapper_opaque_option_ahead``.
_WRAPPER_OPAQUE_OPTIONS: dict[str, frozenset[str]] = {
    "runuser": frozenset({"-c", "--command"}),
    # #634: flock's `-c`/`--command` runs its payload through the shell,
    # exactly like `su -c`/`runuser -c` — opaque, never a transparent value
    # option (see `_opaque_shell_payload`, which recognizes this marker on
    # `flock` the same way it already does for `su`/`runuser`).
    "flock": frozenset({"-c", "--command"}),
}

# `env`'s own no-op flags (no operand) and its unset flags (take one operand),
# recognised so `env -i -0 -u FOO` with no trailing command still resolves to
# "no command to run" -> a dump, same as bare `env`.
_ENV_NOOP_FLAGS = {"-i", "-0", "--null", "--ignore-environment"}
_ENV_UNSET_FLAGS = {"-u", "--unset"}
# `Get-ChildItem`/`gci`/`dir`/`ls` are all valid PowerShell aliases for the
# same provider cmdlet; `Env:` (optionally trailing `\`) is the environment
# drive - listing it prints every variable and value, same as POSIX `env`.
_POWERSHELL_LISTING_VERBS = {"get-childitem", "gci", "dir", "ls"}
_POWERSHELL_ENV_DRIVE = re.compile(r"(?i)^env:\\?$")

# Shells that take an opaque "-c <payload>" we cannot statically vet.
_SHELLS = {"bash", "sh", "zsh", "dash", "ksh", "fish"}

# PowerShell / cmd.exe: same "opaque inline payload" problem as _SHELLS, but a
# different flag vocabulary (-Command/-EncodedCommand, /c) — see _opaque_shell_payload.
_WINDOWS_SHELLS = {"powershell", "powershell.exe", "pwsh", "pwsh.exe"}
_CMD_SHELLS = {"cmd", "cmd.exe"}

# Non-shell interpreters whose inline payloads can directly mutate files.
_INTERPRETERS = {"python", "python3", "py", "node", "nodejs", "deno", "bun", "perl", "ruby"}
_INLINE_CODE_FLAGS = {"-c", "-e", "--eval", "-p", "--print"}
# Attached forms (no space before the payload): shlex glues the quoted body to
# the flag, e.g. `python -c"..."` -> token `-cimport ...` (never equals "-c").
_SHORT_INLINE_CODE_FLAGS = ("-c", "-e")
_LONG_INLINE_CODE_FLAG_PREFIXES = ("--eval=", "--print=")
_DESTRUCTIVE_INTERPRETER_OP = re.compile(
    r"\b(?:shutil\.)?rmtree\b|\bos\.(?:remove|unlink)\b|\brmSync\b|"
    r"\bunlinkSync\b|\bfs\.rm\b|\bRemove-Item\b|\brm\s+-rf\b|\bunlink\b",
    re.IGNORECASE,
)

# HK.5.6 — raw-socket / bare-TCP egress shapes the destructive-command walk
# does not otherwise see: a shell redirection into /dev/tcp or /dev/udp
# (bash's built-in TCP/UDP pseudo-device), netcat/ncat used in exec-on-connect
# (reverse/bind-shell) form, socat's EXEC:/SYSTEM: address type (socat's
# equivalent of `nc -e`), and openssl's TLS client mode. Two tiers (ADR 0097):
# the exec-on-connect subset — a network channel wired to command execution
# (`nc -e`/`--sh-exec`, socat EXEC:/SYSTEM:, and, in an interpreter payload, a
# socket AND a subprocess/shell spawn) — is an unambiguous reverse/bind shell
# with no benign DevOps use, so it BLOCKs. Everything else here (a bare
# `/dev/tcp` redirect, a routine port probe `nc -zv host port`, `openssl
# s_client`, a bare inline socket, DNS-label exfil) stays AUTH: it must remain
# indistinguishable from ordinary DevOps without an entropy/calibration signal
# this module doesn't have. See docs/REASON_CODES.md and the README
# known-limitations entry for `raw_socket_channel`.
_DEV_TCP_UDP_RE = re.compile(r"/dev/(?:tcp|udp)/")
_NC_LIKE_COMMANDS = {"nc", "ncat", "netcat"}
# The exec-on-connect flags that turn a network tool into a reverse/bind
# shell: `-e`/`--exec` (classic netcat/ncat), ncat's `-c`/`--sh-exec` (runs
# the command via /bin/sh -c). A bare port probe (`-zv`) never sets these.
_NC_EXEC_FLAGS = {"-e", "--exec", "-c", "--sh-exec"}
# socat's EXEC:/SYSTEM: address types spawn a subprocess wired to the socket
# (socat's equivalent of `nc -e`) — not socat's routine port-forwarding use.
_SOCAT_EXEC_ADDRESS_RE = re.compile(r"(?i)\b(?:exec|system):")
# Best-effort shape match over an inline interpreter payload's source text
# (paired with _INTERPRETERS/_INLINE_CODE_FLAGS above): a socket/network-
# client call assembled directly in a `python -c`/`node -e` one-liner. Layered
# on top of the existing opaque-payload AUTH, not static analysis — misses an
# obfuscated variant (string concatenation, getattr, a base64-decoded module
# name); see the README known-limitations entry for `raw_socket_channel`.
# `urllib` is narrowed to `urllib.request`/`urlopen` (bare `\burllib\b` matched
# the non-network `urllib.parse` too); bare `connect(` stays broad on purpose
# (spec-mandated) even though it also matches a non-network `sqlite3.connect(`
# — see the README known-limitations entry.
_INLINE_SOCKET_OP = re.compile(
    r"\bsocket\.|\bconnect\(|\bcreate_connection\(|\bhttp\.client\b|\brequests\.|"
    r"\burllib\.request\b|\burlopen\b|\bnet\.Socket\b|\bfetch\(",
    re.IGNORECASE,
)

# Exec-on-connect / socket-wired-to-a-shell — the discrete reverse/bind-shell
# signature (a network channel handed to command execution). Unlike a bare
# socket, a port probe, or a /dev/tcp redirect (all indistinguishable from
# ordinary DevOps, so AUTH), this shape has no benign use, so it BLOCKs (ADR
# 0097). Interpreter side: a socket op (_INLINE_SOCKET_OP) AND a subprocess/
# exec/pty spawn in the SAME inline payload. Best-effort shape match over source
# text (an obfuscated variant is out of scope, same as the layer it sits on).
_INLINE_SHELL_SPAWN = re.compile(
    r"subprocess|os[.]system|os[.]popen|os[.]exec[lv][ep]*|os[.]dup2|"
    r"pty[.]spawn|pexpect|child_process|execve?[(]|/bin/(?:sh|bash|zsh|dash)",
    re.IGNORECASE,
)

# T2 — process-kill vocabulary. `os.kill`/`os.killpg` (Python) and
# `process.kill` (Node) are unambiguous kill calls on their own. `.kill(`/
# `.terminate(` alone are too common non-destructively (a subprocess handle, a
# promise) to flag by themselves, so they only count when the payload also
# names `psutil` — the process-management library this shape targets.
_INLINE_PROCESS_KILL = re.compile(r"os[.]kill(?:pg)?[(]|process[.]kill[(]", re.IGNORECASE)
_PSUTIL_KILL_TERMINATE = re.compile(r"[.]kill[(]|[.]terminate[(]", re.IGNORECASE)

# T2 (privilege half) — os.setuid/seteuid/setreuid/setresuid and the gid
# equivalents. Unambiguous process-privilege changes on their own.
_INLINE_PRIVILEGE_OP = re.compile(r"os[.]set(?:e|re|res)?[ug]id[(]", re.IGNORECASE)

# T3 — an interpreter one-liner that hands a COMMAND LINE to a subprocess
# (subprocess.*, os.system/popen/exec*/spawn*, pty.spawn, pexpect, Node's
# child_process/execSync/spawnSync/execFile(Sync), perl/ruby's bare
# system(). Distinct from _INLINE_SHELL_SPAWN above (that one is the
# reverse-shell conjunction term, paired with a socket op): this one gates
# _interpreter_spawn_literals, which walks the command-line string/list
# literals the call passes so the shared destructive-command walk can see
# what the spawned subprocess would actually run.
#: T5 extra item 7: a bare ``system(`` (perl/ruby's unqualified spawn call)
#: false-fired on a METHOD call sharing the name (``platform.system()``,
#: ``foo.system(``) — the lookbehind excludes any identifier/dot character
#: immediately before ``system(`` so a bare call still matches while a call
#: on some object never does. Not ``\b`` (a word boundary alone still allows
#: a preceding ``.``) and deliberately not `` \.`` either (that would only
#: exclude a directly-preceding dot, missing ``foo.system(``).
_INLINE_PROCESS_SPAWN = re.compile(
    r"subprocess[.]|os[.]system[(]|os[.]popen[(]|os[.]exec[lv]p?e?[(]|os[.]spawn[lv]p?e?[(]|"
    r"pty[.]spawn[(]|pexpect[.]|child_process|execSync[(]|spawnSync[(]|execFile(?:Sync)?[(]|"
    r"(?<![A-Za-z0-9_.])system[(]",
    re.IGNORECASE,
)

# Shared work bound for every static command walk. Exhaustion is ambiguity,
# never silent success.
_MAX_COMMAND_SEGMENTS = 256

#: #549 — bound on the number of characters of one (already substitution-
#: stripped) segment that get handed to `shlex.split`. `_MAX_COMMAND_SEGMENTS`
#: only bounds segment *count*; a single oversized segment (a heredoc, a
#: base64 blob passed as one bare/quoted token) still drove `shlex.split`
#: into super-linear time on its own (~31.5s measured locally on a 1 MB
#: payload, ~7.7 min reported on an 800 KB one elsewhere; root cause is
#: CPython's `shlex.read_token`, not this module).
#: ponytail: a hard truncation, not a smarter parser. 64 KiB clears every
#: existing adversarial payload in this module's own test suite (the
#: largest quotes a ~16 KB `-c` script with its dangerous call placed AFTER
#: a filler blob, on purpose, to prove the scan isn't position-limited —
#: see test_control_plane_path_behind_filesystem_filler_still_blocks) with
#: >3x headroom, while still cutting the reported 800 KB-1 MB payload down
#: to a bounded, fast parse. Any cut — whether shlex raises on it (an open
#: quote) or not (a cut landing in plain unquoted text) — always marks the
#: walk `ambiguous = True`, so a destructive shape truncated away past the
#: cut fails upward (AUTH, never a silent ALLOW) instead of vanishing. The
#: truncated prefix is still handed to `shlex.split`, so a destructive head
#: within the first 64 KiB still hits BLOCK on its own. Raise this if a real
#: command legitimately needs more than 64 KiB in one segment.
_MAX_SEGMENT_SCAN_BYTES = 65536

# Any shell expansion can construct a destination at runtime. The shared walk
# reports the fact; consumers decide whether it matters for their rule.
_DYNAMIC_SHELL = re.compile(r"\$\(|`|\$(?:\{|[A-Za-z_])")

# Whole-word trigger for _normalize_windows_backslashes: any command naming one
# of these Windows verbs/shells (or `rm`, whose own unrecoverable-data check also
# needs a backslash-separated operand intact) gets `\` -> `/` before tokenization.
_WINDOWS_PATH_TRIGGER_RE = re.compile(
    r"(?i)\b(?:"
    r"rm|remove-item|ri|rmdir|del|erase|rd|clear-content|clc|"
    r"powershell(?:\.exe)?|pwsh(?:\.exe)?|cmd(?:\.exe)?|"
    r"format-volume|clear-disk|format"
    r")\b"
)


def _strip_substitutions(segment: str) -> tuple[str, list[str]]:
    """Remove ``$()``/backtick bodies from a segment, returning them separately."""
    bodies: list[str] = []

    def _collect(match: re.Match[str]) -> str:
        body = match.group("paren")
        if body is None:
            body = match.group("backtick") or ""
        if body.strip():
            bodies.append(body)
        return " "

    stripped = _SUBSTITUTION.sub(_collect, segment)
    return stripped, bodies


#: T6-fix: cap on how many ``$(`` nesting levels ``_substitution_end`` will
#: recurse through. Without it, a command string with enough nesting can
#: exhaust the interpreter's own call stack (``RecursionError``) — crash-based,
#: undocumented, and reported under the wrong reason code. Past the cap the
#: region is treated exactly like any other unterminated one (see below),
#: never by letting Python's own recursion limit decide the outcome.
_MAX_SUBSTITUTION_DEPTH = 64


def _substitution_end(command: str, index: int, depth: int = 0) -> tuple[int, bool]:
    """Scan a ``$(...)`` region starting at ``index`` (the position just after
    the opening ``$(``); return ``(index just after the matching ')', terminated)``.

    T6: tracks ``paren_depth``/``quote``/``escaped`` exactly like the flat
    scanner this replaces, with ONE addition — whenever it sees ``$``
    followed by ``(`` and ``quote`` is not ``'``, it RECURSES. That's the
    fix: a flat single ``quote`` variable for the whole region let a quote
    belonging to a NESTED substitution (e.g. the ``"'`` inside
    ``"$(printf '%d' "'$c")"``) be read against the OUTER string instead —
    one stray quote could then make depth never return to zero, silently
    swallowing everything to the end of the command. Recursing gives every
    nesting level its own independent quote state, even inside a ``"…"``
    string. ``$((…))`` needs no special case: the recursion's own depth
    counting closes the extra ``(`` the same as any other nested paren — it
    is never itself a ``$(``. ``terminated`` is ``False`` when the region
    runs off the end of ``command`` with ``paren_depth`` still open (at any
    nesting level) — the caller must fail closed on that, never silently
    accept a truncated region.

    T6-fix: ``depth`` counts RECURSION levels (nested ``$(``), separate from
    ``paren_depth``'s plain-paren counting within one level. Past
    ``_MAX_SUBSTITUTION_DEPTH`` we stop recursing and report the region as
    unterminated — the existing fail-closed path — instead of recursing
    further.
    """
    if depth >= _MAX_SUBSTITUTION_DEPTH:
        return index, False
    paren_depth = 1
    quote: str | None = None
    escaped = False
    while index < len(command):
        char = command[index]
        if escaped:
            escaped = False
            index += 1
            continue
        if char == "\\" and quote != "'":
            escaped = True
            index += 1
            continue
        if char == "$" and quote != "'" and command[index + 1 : index + 2] == "(":
            index, ok = _substitution_end(command, index + 2, depth + 1)
            if not ok:
                return index, False
            continue
        if quote is not None:
            if char == quote:
                quote = None
            index += 1
            continue
        if char in {"'", '"'}:
            quote = char
            index += 1
            continue
        if char == "(":
            paren_depth += 1
            index += 1
            continue
        if char == ")":
            paren_depth -= 1
            index += 1
            if paren_depth == 0:
                return index, True
            continue
        index += 1
    return index, False


def _split_segments(command: str) -> tuple[list[str], bool]:
    """Split a command line into top-level segments on shell operators.

    Returns ``(segments, unterminated)``. An unescaped, unquoted ``(`` or
    ``)`` is a segment separator too (exactly like ``;``) — a subshell, a
    ``{ ...; }`` brace-group trailer, or a function body must not hide a
    nested command from the walk. The one exception is a
    ``$(...)``/``$((...))`` command-substitution region: it is copied
    through intact (:func:`_substitution_end` does the depth/quote counting,
    recursing into a nested ``$(`` so it carries its own quote state — see
    its docstring) so :func:`_strip_substitutions` still sees it exactly as
    before. Parens inside quotes and backslash-escaped parens keep today's
    handling — both are already consumed by the quote/escape branches below,
    before either kind of paren handling is reached. Backticks are
    unchanged.

    T6: when a region never terminates (``_substitution_end`` runs off the
    end of ``command``), ``unterminated`` is set — the caller (``walk_command``)
    folds it into the existing ambiguity floor so an unterminated region
    fails closed (AUTH) rather than being silently accepted. The swallowed
    text (from just after the ``$(`` to the end of the string) is ALSO
    recursively split and its segments folded in here, so a destructive
    command hidden inside the swallowed text is still walked and can still
    raise the AUTH floor to BLOCK.
    """
    segments: list[str] = []
    current: list[str] = []
    quote: str | None = None
    escaped = False
    unterminated = False
    index = 0
    while index < len(command):
        char = command[index]
        if escaped:
            current.append(char)
            escaped = False
            index += 1
            continue
        if char == "\\" and quote != "'":
            current.append(char)
            escaped = True
            index += 1
            continue
        if quote is not None:
            current.append(char)
            if char == quote:
                quote = None
            index += 1
            continue
        if char in {"'", '"'}:
            quote = char
            current.append(char)
            index += 1
            continue
        if char == "$" and command[index + 1 : index + 2] == "(":
            start = index
            region_start = index + 2
            end, ok = _substitution_end(command, region_start)
            if ok:
                current.append(command[start:end])
                index = end
                continue
            unterminated = True
            nested_segments, nested_unterminated = _split_segments(command[region_start:end])
            segments.extend(nested_segments)
            unterminated = unterminated or nested_unterminated
            index = end
            continue

        operator_width = 2 if command[index : index + 2] in {"&&", "||"} else 0
        # A single ``&`` separates commands too: cmd.exe runs both sides
        # unconditionally and POSIX shells background the left and run the right.
        if operator_width or char in {"|", ";", "&", "\n", "(", ")"}:
            segment = "".join(current).strip()
            if segment:
                segments.append(segment)
            current = []
            index += operator_width or 1
            continue
        current.append(char)
        index += 1

    segment = "".join(current).strip()
    if segment:
        segments.append(segment)
    return segments, unterminated


#: Shell syntax words/tokens that carry no security meaning of their own —
#: they only ever introduce or close a nested command. Left in argv[0] they
#: hide that command from every consumer of :func:`walk_command` (this rule,
#: the proxy's egress classifier, dependency_admission.py), so they are
#: stripped when leading a segment. ``function`` is handled separately below
#: (it also swallows the following name token).
_SHELL_SYNTAX_TOKENS = {
    "if",
    "then",
    "else",
    "elif",
    "fi",
    "do",
    "done",
    "while",
    "until",
    "for",
    "select",
    "case",
    "esac",
    "in",
    "{",
    "}",
    "!",
    "coproc",
}


def walk_command(command: str) -> tuple[list[list[str]], bool, bool]:
    """Tokenize every shell segment/substitution without stripping prefixes.

    Returns ``(segments, ambiguous, dynamic)``. Each segment is the raw
    :func:`shlex.split` token list *before* env assignments or transparent
    wrappers are removed, so security consumers can still see proxy/route
    overrides. Leading shell-syntax tokens (``if``/``then``/``fi``, brace-group
    ``{``/``}``, ``function <name>``, ...) ARE dropped here, though — they
    carry no security meaning of their own, and left in argv[0] they would
    hide the nested command (see ``_SHELL_SYNTAX_TOKENS``) from every
    consumer of this walk. Unbalanced input, the shared work-cap, and an
    unterminated ``$(`` region (T6 — see ``_split_segments``) surface through
    ``ambiguous``. No command is executed.
    """
    pending, unterminated = _split_segments(command)
    segments: list[list[str]] = []
    ambiguous = unterminated
    processed = 0

    while pending and processed < _MAX_COMMAND_SEGMENTS:
        processed += 1
        segment = pending.pop()
        stripped, bodies = _strip_substitutions(segment)
        for body in bodies:
            body_segments, body_unterminated = _split_segments(body)
            pending.extend(body_segments)
            ambiguous = ambiguous or body_unterminated
        try:
            # #549: bound by BYTES, not just segment count — an oversized
            # single segment (a heredoc, a base64 blob) drove shlex.split
            # into super-linear time on its own. Truncation happens AFTER
            # substitution-stripping above, so a $()/backtick body deep in
            # an oversized segment is already queued for its own walk and
            # is never hidden by this cut.
            # #549 follow-up: a cut landing OUTSIDE a quote never raises —
            # shlex happily parses the truncated prefix — so a destructive
            # suffix past byte 65536 (`"rm " + "a" * 70000 + " -rf /"`) was
            # silently dropped with no failure-upward signal at all. Any cut
            # marks the walk ambiguous; the truncated prefix is still parsed
            # below so a destructive head still reaches BLOCK.
            if len(stripped) > _MAX_SEGMENT_SCAN_BYTES:
                ambiguous = True
            tokens = shlex.split(stripped[:_MAX_SEGMENT_SCAN_BYTES], comments=True, posix=True)
        except ValueError:
            ambiguous = True
            continue
        while tokens:
            if tokens[0] == "coproc":
                tokens = tokens[1:]
                # Bash grammar: `coproc [NAME] compound-command` — a NAME may
                # only precede a compound command. `coproc wipe { ...; }`
                # leaves `wipe` as argv[0] (hiding the body) unless it's
                # dropped here too; `coproc ls -la` (a simple command, no
                # NAME) must NOT have its own argv[0] eaten.
                if len(tokens) >= 2 and tokens[1] == "{":
                    tokens = tokens[1:]
                continue
            if tokens[0] in _SHELL_SYNTAX_TOKENS:
                tokens = tokens[1:]
                continue
            if tokens[0] == "function":
                tokens = tokens[2:]
                continue
            break
        if tokens:
            segments.append(tokens)

    if pending:
        ambiguous = True
    return segments, ambiguous, bool(_DYNAMIC_SHELL.search(command))


def _normalize_windows_backslashes(command: str) -> str:
    """``\\`` is a Windows path separator, but shlex (POSIX mode, used below) treats
    it as an escape character — it silently eats ``foo\\.env`` -> ``foo.env`` or
    raises ``ValueError`` on a trailing ``C:\\``. A line naming a Windows verb/shell
    (see ``_WINDOWS_PATH_TRIGGER_RE``) gets every backslash flipped to ``/`` before
    tokenization so a Windows path survives intact.

    ponytail: a whole-line, word-triggered flip rather than per-segment/per-operand
    surgery — simplest fix that passes the live-tested Windows commands, and a no-op
    (verified against the existing POSIX test suite) unless both a trigger word and a
    literal backslash are present. Known ceiling: a POSIX ``rm`` operand that
    legitimately backslash-escapes a space or glob character (rare) would have that
    escape flattened too; upgrade to a per-segment flip if that ever bites.
    """
    if _WINDOWS_PATH_TRIGGER_RE.search(command):
        return command.replace("\\", "/")
    return command


def _wrapper_name(token: str) -> str:
    """Wrapper-recognition basename: strip a ``/`` or ``\\`` directory prefix
    and a trailing ``.exe``, lower-cased — so ``/usr/bin/sudo`` and
    ``SUDO.EXE`` are both recognized as ``sudo``."""
    name = token.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return name.removesuffix(".exe")


def _wrapper_opaque_option_ahead(tokens: list[str], name: str) -> bool:
    """True when scanning ``name``'s own option run (the same run
    :func:`argv_from_tokens` is about to strip) reaches one of its opaque-
    payload markers (bare or ``=``-attached — see ``_WRAPPER_OPAQUE_OPTIONS``)
    before the wrapped command starts. I2: ``runuser -c``/``--command`` must
    stay visible whole for :func:`_opaque_shell_payload` to inspect, exactly
    the way ``su -c`` does (``su`` is simply never a recognized wrapper at
    all) — so :func:`argv_from_tokens` breaks BEFORE popping anything for
    this wrapper rather than dropping ``-c`` as a bare unknown-arity flag and
    losing the payload."""
    markers = _WRAPPER_OPAQUE_OPTIONS.get(name)
    if not markers:
        return False
    value_opts = _WRAPPER_VALUE_OPTIONS.get(name, frozenset())
    i = 1
    while i < len(tokens) and tokens[i].startswith("-"):
        opt = tokens[i]
        if opt == "--":  # noqa: S105 — option-parsing terminator, not a secret
            return False
        if opt in markers or any(opt.startswith(f"{marker}=") for marker in markers):
            return True
        i += 2 if opt in value_opts else 1
    return False


def argv_from_tokens(
    tokens: list[str],
    *,
    keep: frozenset[str] = frozenset(),
    consumed_value_option: list[bool] | None = None,
    consumed_any_option: list[bool] | None = None,
) -> list[str]:
    """Strip prefixes (env assignments + transparent-wrapper name/options) from
    an already-parsed segment for command classification.

    Shared contract: this is the one place that decides what a wrapped/
    env-prefixed segment's "real" command is, and both the engine's own
    rules (the destructive-command walk, dependency admission) and the
    proxy's command-verb classifier (``doberman.proxy.normalize._command_verb``,
    the allowed proxy -> engine import direction) call it so they always
    agree on that answer — env-assignment skipping, the wrapper option
    table, the ``env -S``/``--split-string`` splice, and leaving an
    unresolved leading option in place (see ``consumed_value_option``/
    ``consumed_any_option`` below) all behave identically for every caller.

    T5: a wrapper's own option used to shift argv so the option was misread
    as the command (``sudo -u root rm -rf /`` saw ``-u`` as argv[0]). Now:
    pop the wrapper's name (by basename, see ``_wrapper_name``), then every
    following ``-``/``--``-prefixed token — a bare spelling in
    ``_WRAPPER_VALUE_OPTIONS[name]`` also pops its value token (``env -S``'s
    value is a command string: ``shlex.split`` it and splice the tokens back
    at the front; a ``-S<value>``/``--split-string=<value>`` attached form
    (I3) is spliced the same way; on ``ValueError`` leave the option/value
    tokens untouched — the caller then fails upward as today), everything
    else is a bare flag with unknown arity, dropped but not otherwise
    consumed. A bare ``--`` itself is popped and ends option parsing. Then
    pop the wrapper's fixed positionals (``_WRAPPER_POSITIONALS``). Repeats,
    so wrapper chains (``sudo -n nice -n 5 rm -rf /``) unwind. ``keep`` names
    a wrapper whose own token must NOT be stripped (``_is_environment_dump_
    segment`` keeps ``env`` so it can still see it after unwrapping
    everything ahead of it). I2: a wrapper carrying one of its own
    ``_WRAPPER_OPAQUE_OPTIONS`` markers ahead is never stripped at all — see
    ``_wrapper_opaque_option_ahead``. ``consumed_value_option`` (I2) records
    whether a bare value-option pop happened (never a bare-flag drop —
    ``sudo -l``/``-h`` must not trip it); ``consumed_any_option`` (C1)
    records whether ANY wrapper option — value or bare-flag — was consumed,
    beyond the bare wrapper name/env-assignment prefixes.
    """
    tokens = list(tokens)
    while tokens:
        while tokens and _ENV_ASSIGNMENT.match(tokens[0]):
            tokens.pop(0)
        if not tokens:
            break
        name = _wrapper_name(tokens[0])
        if name not in _WRAPPER_VALUE_OPTIONS or name in keep:
            break
        if _wrapper_opaque_option_ahead(tokens, name):
            break
        value_opts = _WRAPPER_VALUE_OPTIONS[name]
        tokens.pop(0)  # the wrapper name itself
        while tokens and tokens[0].startswith("-"):
            opt = tokens[0]
            if opt == "--":  # noqa: S105 — option-parsing terminator, not a secret
                if consumed_any_option is not None:
                    consumed_any_option.append(True)
                tokens.pop(0)
                break
            if opt in value_opts:
                if name == "env" and opt in ("-S", "--split-string"):
                    if len(tokens) < 2:
                        tokens.pop(0)
                        break
                    try:
                        spliced = shlex.split(tokens[1], posix=True)
                    except ValueError:
                        break  # unparseable value: leave -S + its value untouched
                    if consumed_any_option is not None:
                        consumed_any_option.append(True)
                    tokens = spliced + tokens[2:]
                    continue
                if consumed_value_option is not None:
                    consumed_value_option.append(True)
                if consumed_any_option is not None:
                    consumed_any_option.append(True)
                tokens.pop(0)
                if tokens:
                    tokens.pop(0)
                continue
            # I3: env's `-S`/`--split-string` value IS a command line, unlike
            # every other option here — its attached forms must splice the
            # same way the bare-space form above does, not fall through to
            # the generic bare-flag drop and vanish untouched.
            if name == "env" and (
                (opt.startswith("-S") and len(opt) > 2) or opt.startswith("--split-string=")
            ):
                value = opt[2:] if opt.startswith("-S") else opt.split("=", 1)[1]
                try:
                    spliced = shlex.split(value, posix=True)
                except ValueError:
                    break  # unparseable attached value: leave the token untouched
                if consumed_any_option is not None:
                    consumed_any_option.append(True)
                tokens[0:1] = spliced
                continue
            if consumed_any_option is not None:
                consumed_any_option.append(True)
            tokens.pop(0)
        for _ in range(_WRAPPER_POSITIONALS.get(name, 0)):
            if tokens:
                tokens.pop(0)
    return tokens


# #589: renamed from the private `_argv_from_tokens` to a public name since it's
# a cross-module contract; kept as a one-release back-compat alias.
_argv_from_tokens = argv_from_tokens


def _leading_option(raw_tokens: list[str], tokens: list[str]) -> bool:
    """True when ``tokens[0]`` still looks like an option (``-``-prefixed)
    after :func:`argv_from_tokens` has stripped every env-assignment/wrapper
    prefix it can resolve, AND ``raw_tokens`` shows a wrapper actually sat in
    front of it (its first non-env-assignment token did not itself start
    with ``-``) — i.e. something was stripped and what's left is still an
    option, never a verbless line that simply begins with a flag.

    T5-fix: this happens when a wrapper's value-option splice itself fails
    (e.g. ``env -S <value>`` where ``<value>`` doesn't ``shlex.split`` —
    see ``argv_from_tokens``'s own docstring) and the option/value tokens
    are left in place, unresolved, ahead of whatever command follows. A
    leading option can never be the command being run, so a caller that
    keys classification off ``tokens[0]`` (``_segment_verdict``,
    ``delete_class_operands_and_dynamic``) must treat this as ambiguous
    rather than silently reading the segment as benign.

    T7-fix: a verbless segment that simply BEGINS with an option
    (``--grep it's``, ``-rf / rm``) never had a wrapper stripped — a real
    shell would reject it outright, and the tool-args form is a benign,
    common shape (Grep/Glob-style args lists) — so it must stay whatever the
    rest of the walk decides, not blanket-AUTH.
    """
    if not tokens or not tokens[0].startswith("-"):
        return False
    first_raw = next((t for t in raw_tokens if not _ENV_ASSIGNMENT.match(t)), None)
    return first_raw is not None and not first_raw.startswith("-")


def _argv(segment: str) -> list[str] | None:
    """Parse one segment into argv with shlex; ``None`` if it cannot be parsed.

    Unparseable (e.g. unbalanced quotes) returns ``None`` so the caller fails
    upward to AUTH rather than guessing.
    """
    try:
        tokens = shlex.split(segment, posix=True)
    except ValueError:
        return None
    return argv_from_tokens(tokens)


#: A Windows drive root in any form a delete operand can arrive in: ``C:\``,
#: ``C:/``, ``C:\*``, or the backslash-eaten ``C:*`` (see
#: ``_normalize_windows_backslashes`` — normally already flipped to ``C:/``).
_WINDOWS_ROOT_RE = re.compile(r"^[A-Za-z]:[/\\]?(\*)?$")


def _is_root_or_home_target(arg: str) -> bool:
    """True if an argument denotes ``/``, ``~``, a whole-tree wildcard, or a
    Windows drive root / home-profile variable (``C:\\``, ``~``, ``$env:USERPROFILE``)."""
    raw = arg.strip().strip("'\"")
    if raw.lower() in {"~", "$home", "$env:userprofile"}:
        return True
    if _WINDOWS_ROOT_RE.match(raw):
        return True
    normalized = posixpath.normpath(raw.replace("\\", "/"))
    if normalized.startswith("//"):
        normalized = "/" + normalized.lstrip("/")
    return normalized in {"/", "~", "~/", "/*", "/.", "~/*", "*"} or normalized.startswith("/*")


def _rm_is_catastrophic(tokens: list[str]) -> bool:
    """``rm`` with a recursive+force flag aimed at root/home/whole-tree."""
    flags = "".join(t[1:] for t in tokens[1:] if t.startswith("-") and not t.startswith("--"))
    long_flags = {t for t in tokens[1:] if t.startswith("--")}
    recursive = "r" in flags or "R" in flags or "--recursive" in long_flags
    force = "f" in flags or "--force" in long_flags
    if not (recursive and force):
        return False
    operands = [t for t in tokens[1:] if not t.startswith("-")]
    return any(_is_root_or_home_target(op) for op in operands)


def _count_delete_operands(tokens: list[str]) -> int:
    """Number of path operands to an ``rm`` (for the bulk-operation threshold)."""
    return len([t for t in tokens[1:] if not t.startswith("-")])


# Gitignored, unrecoverable-by-git data whose deletion git cannot undo: local
# databases and secret/key material. Matched lexically on the operand basename.
_UNRECOVERABLE_DELETE_GLOBS = ("*.db", "*.sqlite", "*.sqlite3", "*.key", ".env", ".env.*")


def _unrecoverable_basename(operand: str) -> str:
    """Basename of a delete operand, tolerant of Windows backslashes and a
    leading ``.\\`` (normalized to ``/`` before ``posixpath.basename``)."""
    return posixpath.basename(operand.strip().strip("'\"").replace("\\", "/"))


def _any_operand_unrecoverable(operands: Iterable[str]) -> bool:
    """True if any operand's basename matches an unrecoverable, gitignored data
    file (local DB / secret / key). Shared by the ``rm`` and Windows delete paths."""
    return any(
        fnmatch.fnmatch(_unrecoverable_basename(op), pattern)
        for op in operands
        for pattern in _UNRECOVERABLE_DELETE_GLOBS
    )


def _rm_targets_unrecoverable_data(tokens: list[str]) -> bool:
    """``rm`` whose operand basename matches an unrecoverable, gitignored data
    file (local DB / secret / key)."""
    # ponytail: lexical glob on operands only — no filesystem or git access in the
    # decision path. Catches file targets; a directory operand (rm -rf data/) cannot
    # be classified lexically and is deliberately out of scope (deferred — see ADR).
    operands = [t for t in tokens[1:] if not t.startswith("-")]
    return _any_operand_unrecoverable(operands)


# --- Windows/PowerShell delete-verb coverage --------------------------------
#
# Codex/agents on Windows run tool commands through PowerShell or cmd.exe, whose
# destructive-delete vocabulary (Remove-Item, del, rd, ...) is invisible to the
# POSIX-only `rm` handling above. `_windows_delete_verdict` maps these verbs onto
# the SAME severity ladder as `rm`'s own branches — not a second policy — and is
# kept separate from the `rm` branches so this addition can never regress `rm`.

#: Verbs that delete or wipe file content the Windows way.
_WINDOWS_DELETE_VERBS = frozenset(
    {"remove-item", "ri", "rmdir", "del", "erase", "rd", "clear-content", "clc"}
)


def _windows_delete_flag(token: str) -> tuple[bool, bool, bool]:
    """Classify one Windows delete-verb argument: ``(is_flag, recursive, force)``.

    PowerShell flags (``-Recurse``, ``-Force``, ...) abbreviate by prefix — ``-r``/
    ``-f`` alone are valid PowerShell abbreviations too, so we match "is this body a
    prefix of the canonical word" rather than the reverse. cmd.exe flags are the
    fixed 1-2 char ``/s`` (recursive) / ``/q``, ``/f`` (force). Any other ``-``/``/``
    -prefixed token (e.g. ``-Path``, whose value arrives as the next token) still
    counts as a flag so it isn't miscounted as an operand — it just isn't Recurse/Force.
    """
    if token.startswith("-") and len(token) > 1:
        body = token[1:].lower()
        # ponytail: prefix-match against "recurse"/"force" only (not the full
        # PowerShell parameter-disambiguation table) — over-classifying Force is
        # raise-only (safe); a non-recurse/force switch (-Path, -Confirm, ...) is
        # still correctly excluded from the operand count.
        return True, "recurse".startswith(body), "force".startswith(body)
    if token.startswith("/") and 1 <= len(token) - 1 <= 2:
        body = token[1:].lower()
        return True, body == "s", body in {"q", "f"}
    return False, False, False


def _windows_delete_flags_and_operands(tokens: list[str]) -> tuple[bool, bool, list[str]]:
    """``(recursive, force, operands)`` for a Windows delete-verb argv."""
    recursive = force = False
    operands: list[str] = []
    for token in tokens[1:]:
        is_flag, r, f = _windows_delete_flag(token)
        if is_flag:
            recursive = recursive or r
            force = force or f
        else:
            operands.append(token)
    return recursive, force, operands


def _windows_delete_verdict(tokens: list[str], bulk_threshold: int) -> GuardrailResult | None:
    """Windows/PowerShell delete-verb classifier (Remove-Item/del/rd/...): recursive
    + force at a root/home target -> BLOCK; bulk or unrecoverable-data operand ->
    AUTH; otherwise ``None`` (not a recognized Windows delete verb, or benign)."""
    if not tokens or tokens[0].lower() not in _WINDOWS_DELETE_VERBS:
        return None
    recursive, force, operands = _windows_delete_flags_and_operands(tokens)
    if recursive and force and any(_is_root_or_home_target(op) for op in operands):
        return _block("Recursive force-delete of a root/home/whole-tree target.")
    if len(operands) >= bulk_threshold:
        return _auth(
            ReasonCode.bulk_operation,
            "Bulk delete at or above the configured threshold; authentication required.",
        )
    if _any_operand_unrecoverable(operands):
        return _auth(
            ReasonCode.destructive_command,
            "Deleting an unrecoverable, gitignored data file (local database, "
            "secret, or key); authentication required.",
        )
    return None


def _git_force_push_to_protected(tokens: list[str], protected: Iterable[str]) -> bool:
    """``git push`` with a force flag targeting a protected branch.

    Keys on the actual git verb (via :func:`_git_leading_globals`, which skips
    leading global options like ``-C <path>``/``-c <k=v>``) and only inspects
    that ``push`` invocation's OWN argv — never the full argv, so a force flag
    or ``+ref``-shaped token that merely appears as another verb's *argument*
    (``git log --grep push --force``) is never mistaken for an actual force-push.
    """
    argv, _ = _git_leading_globals(tokens)
    if not argv or argv[0] != "push":
        return False
    push_args = argv[1:]
    has_force = any(
        t in ("-f", "--force") or t.startswith("--force-with-lease") or t == "+HEAD"
        for t in push_args
    )
    if not has_force:
        # A refspec like ``+main`` is also a force push of that ref.
        if not any(t.startswith("+") for t in push_args):
            return False
        has_force = True
    protected_set = {b.lower() for b in protected}
    positional = [t for t in push_args if not t.startswith("-")]
    explicit_refs = positional[1:]  # the first positional is the remote
    # Any token that names (or pushes to) a protected branch.
    for token in explicit_refs:
        ref = token.lstrip("+").split(":")[-1].lower()
        ref = re.sub(r"^(?:refs/(?:heads|tags)/|heads/)", "", ref)
        if ref in protected_set:
            return True
    # A bare ``git push --force`` (no explicit ref) defaults to the current
    # branch — unknown here, so treat it as protected (fail safe).
    return not explicit_refs


# Catastrophic non-rm commands (whole-disk wipes, fork bombs). IGNORECASE covers
# the Windows disk-wipe names (Format-Volume, Clear-Disk, format).
_DISK_WIPE = re.compile(
    r"^(?:mkfs(?:\.\w+)?|shred|wipefs|format-volume|clear-disk|format)$", re.IGNORECASE
)


def _is_doberman_control_cli(tokens: list[str]) -> bool:
    """``doberman <verb>`` for a posture/auth-mutating verb (install/uninstall-hooks,
    uninstall, setup, mode, prefs, enforcement, 2fa, taint, password, revoke) —
    control-plane tamper. Read/utility verbs are not in the set and stay allowed."""
    return (
        bool(tokens)
        and tokens[0] == "doberman"
        and any(t in _DOBERMAN_CONTROL_SUBCOMMANDS for t in tokens[1:])
    )


def _package_manager_removes_doberman(tokens: list[str]) -> bool:
    """True for package-manager commands that uninstall Doberman itself."""
    if (
        len(tokens) >= 3
        and tokens[0] in {"python", "python3", "py"}
        and tokens[1] == "-m"
        and tokens[2] == "pip"
    ):
        manager_args = tokens[2:]
    elif tokens[:2] == ["uv", "pip"]:
        manager_args = tokens[1:]
    else:
        manager_args = tokens
    if (
        len(manager_args) < 3
        or manager_args[0] not in {"pip", "pip3", "pipx", "uv"}
        or manager_args[1] not in {"uninstall", "remove"}
    ):
        return False
    packages = {
        token.lower().replace("-", "_") for token in manager_args[2:] if not token.startswith("-")
    }
    return bool(packages & {"doberman", "doberman_core", "doberman_enterprise"})


def _token_path_candidates(token: str) -> list[str]:
    """Path-like candidates from one argv token: the token itself and the value
    after ``=`` (for ``--flag=path`` forms). Redirection targets already arrive as
    their own tokens (``shlex`` keeps ``>``/``>>`` separate)."""
    if "=" in token:
        return [token, token.split("=", 1)[1]]
    return [token]


def _segment_targets_control_plane(tokens: list[str], root: str) -> bool:
    """True if any argv token (operand or redirect target) names Doberman's
    control plane. Skips a token's leading ``-`` switch but still checks a
    ``--flag=path`` value."""
    for token in tokens:
        for candidate in _token_path_candidates(token):
            if candidate and not candidate.startswith("-") and names_control_plane(candidate, root):
                return True
    return False


def _payload_targets_control_plane(candidates: list[str], root: str) -> tuple[bool, bool]:
    """``(hit, unresolved)`` for an inline-payload candidate list.

    Same token handling as :func:`_segment_targets_control_plane`, but the
    input is attacker-sized: every candidate is matched textually and only the
    first :data:`_MAX_PAYLOAD_PATH_RESOLVES` that need the filesystem are
    canonicalized; ``unresolved`` reports that at least one was not, so the
    caller floors its verdict at AUTH instead of trusting a partial scan.
    """
    resolves_left = _MAX_PAYLOAD_PATH_RESOLVES
    unresolved = False
    for token in candidates:
        for candidate in _token_path_candidates(token):
            if not candidate or candidate.startswith("-"):
                continue
            resolve = needs_filesystem_resolution(candidate)
            if resolve:
                if resolves_left > 0:
                    resolves_left -= 1
                else:
                    resolve, unresolved = False, True
            if names_control_plane(candidate, root, resolve=resolve):
                return True, unresolved
    return False, unresolved


def _control_plane_in_windows_form(command: str, root: str) -> bool:
    """True if the command names the control plane using ``\\`` separators.

    :func:`shlex.split` in POSIX mode treats ``\\`` as an **escape character**, so
    ``rm .doberman\\policies.yaml`` tokenizes to ``.dobermanpolicies.yaml`` — the
    separators are consumed before any path check runs, and the token matches no
    glob. Every control-plane guarantee in this module was therefore reachable on
    Windows just by spelling the path the way Windows spells it.

    Re-scan a separator-normalized copy of the raw command so the Windows form is
    caught too. This is **scan-only**: these tokens never reach verb
    classification, operand counting, or the bulk-delete threshold, so the pass
    can only ever add a control-plane BLOCK — it can never change what a command
    is understood to *do*, and never lowers a verdict.

    Normalizing is safe for a genuine POSIX escape (``rm my\\ file.txt`` becomes
    the harmless tokens ``my/`` and ``file.txt``) because only control-plane glob
    matching consumes the result.
    """
    if "\\" not in command:
        return False
    normalized = command.replace("\\", "/")
    try:
        tokens = shlex.split(normalized, comments=True, posix=True)
    except ValueError:
        # Unbalanced quoting: fall back to a crude split rather than give up —
        # the caller still treats an unparseable command as ambiguous.
        tokens = [t for t in re.split(r"[\s'\"`(){}\[\],;]+", normalized) if t]
    return _segment_targets_control_plane(tokens, root)


def _inline_payloads(tokens: list[str]) -> list[str]:
    """Every inline-code payload an interpreter's ``-c``/``-e``/``--eval``/``-p``/
    ``--print`` flag(s) carry. Empty (not just falsy) when ``tokens[0]`` isn't a
    recognized interpreter or no inline-code flag is present. Shared by
    :func:`_interpreter_payload_verdict` and :func:`_interpreter_spawn_literals` —
    both need the interpreter's inline source text, just to run different checks
    over it.
    """
    if not tokens or tokens[0] not in _INTERPRETERS:
        return []
    payloads: list[str] = []
    for index in range(1, len(tokens)):
        token = tokens[index]
        if token in _INLINE_CODE_FLAGS:
            if index + 1 < len(tokens):
                payloads.append(tokens[index + 1])
        elif token.startswith(_SHORT_INLINE_CODE_FLAGS) and len(token) > 2:
            payloads.append(token[2:])
        elif token.startswith(_LONG_INLINE_CODE_FLAG_PREFIXES):
            payloads.append(token.split("=", 1)[1])
    return payloads


#: Cap on how many command-line candidates one interpreter payload can push
#: back onto the walk — same "exhaustion is ambiguity, never silent success"
#: posture as _MAX_COMMAND_SEGMENTS, scoped to a single payload.
_MAX_SPAWN_LITERAL_CANDIDATES = 32

#: I6 — work bounds for _spawn_literal_candidates' own scan, independent of
#: (and cheaper to check than) the output cap above: the join loop
#: (`for group in stack: group.append(literal)`) runs once per open group
#: per literal, so an unbounded `stack` made it quadratic in payload size
#: (measured: 0.9s for a 20KB adversarial payload, 4x per doubling). Both
#: caps trade candidate completeness for bounded work, never a silent PASS —
#: see the AUTH-floor note on `_MAX_SPAWN_LITERAL_WORK_CANDIDATES`.
#: Round 3 (N1): filesystem resolves (symlink following for an absolute / `~` /
#: `..` token, ~0.6ms each on Windows) an inline payload's control-plane scan
#: may spend. Every candidate is still matched TEXTUALLY; past this budget the
#: payload floors at AUTH (`opaque_command`) — a bound on work, never a skip.
_MAX_PAYLOAD_PATH_RESOLVES = 32
_MAX_SPAWN_LITERAL_STACK_DEPTH = 32
#: Stop the scan itself once this many raw candidates have been collected —
#: a larger, separate bound from the final output cap above (4x it) so a
#: payload that is merely long (many literals, not deeply nested) still
#: fills the output cap before the scan gives up early. Safe to truncate
#: because `saw_interpreter_spawn` (set by the caller whenever this function
#: runs at all — see `_interpreter_spawn_literals`) already guarantees an
#: AUTH floor for the segment: truncation can only ever miss a candidate,
#: never manufacture a silent PASS.
_MAX_SPAWN_LITERAL_WORK_CANDIDATES = 4 * _MAX_SPAWN_LITERAL_CANDIDATES


def _spawn_literal_candidates(text: str) -> list[str]:
    """One pass over an interpreter payload: track ``(``/``[`` group depth
    (skipping over quoted string contents — a backslash escapes the next
    char so it never ends a string early), emitting every quoted string
    literal on its own, in source order, PLUS — for every group closed — the
    space-joined literals it contains. A literal is appended to every
    currently-open group when it's seen, so nested groups bubble up into
    their enclosing group's candidate too (T3-fix: replaces a ``[...]``-only
    regex join, which missed Node's two-arg ``execFile(cmd, [args])`` and a
    Python tuple argv) — UNLESS it sits inside a keyword-argument value
    (I5): a bare ``=`` at the CURRENT group depth (``cwd=``) opens a kwarg
    region that runs until the next comma back at that same depth, or the
    group itself closes; a literal seen anywhere in that region — whether
    right after the ``=`` (``cwd='/'``) or nested inside a call
    (``cwd=os.path.expanduser('~')``) — is still emitted as its own
    candidate but never joined into the group the kwarg sits in, or any
    group further out. Never part of the argv the group represents, so the
    old unconditional join manufactured a synthetic ``rm -rf /``/``rm -rf ~``
    out of ``rm -rf <var>`` plus an unrelated ``cwd`` kwarg. An unbalanced
    group is flushed at the payload end rather than dropped — no regex
    needed for the nesting."""
    candidates: list[str] = []
    stack: list[list[str]] = []
    kwarg_depth: int | None = None
    i, n = 0, len(text)
    while i < n and len(candidates) < _MAX_SPAWN_LITERAL_WORK_CANDIDATES:
        char = text[i]
        if char in "'\"":
            quote = char
            start = i + 1
            j = start
            while j < n and text[j] != quote:
                j += 2 if text[j] == "\\" and j + 1 < n else 1
            literal = text[start:j]
            candidates.append(literal)
            floor = kwarg_depth if kwarg_depth is not None else 0
            for group in stack[floor:]:
                group.append(literal)
            i = j + 1
            continue
        if char in "([":
            if len(stack) < _MAX_SPAWN_LITERAL_STACK_DEPTH:
                stack.append([])
        elif char in ")]" and stack:
            candidates.append(" ".join(stack.pop()))
            if kwarg_depth is not None and len(stack) < kwarg_depth:
                kwarg_depth = None  # the group the kwarg lived in just closed
        elif char == "=" and kwarg_depth is None:
            kwarg_depth = len(stack)
        elif char == "," and kwarg_depth is not None and len(stack) == kwarg_depth:
            kwarg_depth = None  # next positional/kwarg at the same depth
        i += 1
    while stack:
        candidates.append(" ".join(stack.pop()))
    return candidates


def _interpreter_spawn_literals(tokens: list[str]) -> tuple[list[str], bool] | None:
    """Command-line candidates an interpreter payload hands to a subprocess spawn.

    ``None`` unless ``tokens[0]`` is an interpreter AND some inline payload
    matches :data:`_INLINE_PROCESS_SPAWN` (a subprocess/exec/spawn call is
    actually present) — the caller uses ``is not None`` to distinguish "not a
    spawn call at all" from "a spawn call with nothing vettable in it" (an
    empty list). When it *is* a spawn call, returns ``(literals, truncated)``:
    every quoted string literal in the payload individually, plus every
    ``(``/``[`` group's literals space-joined into one candidate (see
    :func:`_spawn_literal_candidates`) — so ``execFile('rm', ['-rf', '/'])``
    yields ``"rm -rf /"`` from its outer call parens, and a tuple argv
    ``('rm', '-rf', '/')`` is covered the same way as a list. Stripped,
    empties dropped, deduped preserving order, capped at 32. ``truncated``
    (M4) is True when :func:`_spawn_literal_candidates`' own work cap
    (:data:`_MAX_SPAWN_LITERAL_WORK_CANDIDATES`) cut the scan short for any
    payload — the caller ORs it into ``saw_unparseable`` so a future refactor
    that decouples the ``saw_interpreter_spawn`` AUTH floor from this path
    does not turn a silent truncation into a silent miss.
    """
    payloads = _inline_payloads(tokens)
    if not any(_INLINE_PROCESS_SPAWN.search(payload) for payload in payloads):
        return None
    candidates: list[str] = []
    truncated = False
    for payload in payloads:
        payload_candidates = _spawn_literal_candidates(payload)
        truncated = truncated or len(payload_candidates) >= _MAX_SPAWN_LITERAL_WORK_CANDIDATES
        candidates.extend(payload_candidates)
    cleaned: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        candidate = candidate.strip()
        if candidate and candidate not in seen:
            seen.add(candidate)
            cleaned.append(candidate)
    return cleaned[:_MAX_SPAWN_LITERAL_CANDIDATES], truncated


def _interpreter_payload_verdict(tokens: list[str], root: str) -> GuardrailResult | None:
    """BLOCK obvious control-plane or destructive interpreter one-liners."""
    payloads = _inline_payloads(tokens)
    if not payloads:
        return None

    too_fragmented = False
    for payload in payloads:
        candidates = [
            candidate for candidate in re.split(r"[\s'\"`(){}\[\],;]+", payload) if candidate
        ]
        if len(candidates) > _MAX_SPAWN_LITERAL_WORK_CANDIDATES:
            # N1 (rounds 2-3): the cap is a FLOOR, never a short-circuit and
            # never a truncation. An early `return` here skipped the checks
            # below and every later payload; keeping only the first N
            # candidates let LEADING filler push the genuine tokens out of
            # the scanned window. So every candidate is control-plane-checked
            # (cheap now: names_control_plane() only touches the filesystem
            # for absolute/`~`/`..` tokens) and `too_fragmented` merely floors
            # the verdict at AUTH if nothing stronger below ever fires.
            too_fragmented = True
        hit, unresolved = _payload_targets_control_plane(candidates, root)
        if hit:
            return _block_control_plane(
                "Interpreter inline payload references Doberman's own control plane."
            )
        too_fragmented = too_fragmented or unresolved
    if any(_DESTRUCTIVE_INTERPRETER_OP.search(payload) for payload in payloads):
        return _block("Interpreter inline payload contains a destructive filesystem operation.")
    if any(
        _INLINE_SOCKET_OP.search(payload) and _INLINE_SHELL_SPAWN.search(payload)
        for payload in payloads
    ):
        return _block_raw_socket_exec(
            "Interpreter inline payload wires a network socket to command execution "
            "(reverse/bind shell); blocked."
        )
    if any(_INLINE_SOCKET_OP.search(payload) for payload in payloads):
        return _auth(
            ReasonCode.opaque_command,
            "Interpreter inline payload opens a network socket directly; authentication required.",
        )
    if any(
        _INLINE_PROCESS_KILL.search(payload)
        or (_PSUTIL_KILL_TERMINATE.search(payload) and "psutil" in payload)
        for payload in payloads
    ):
        return _auth(
            ReasonCode.destructive_command,
            "Interpreter inline payload signals or kills a process; authentication required.",
        )
    if any(_INLINE_PRIVILEGE_OP.search(payload) for payload in payloads):
        return _auth(
            ReasonCode.destructive_command,
            "Interpreter inline payload changes process privileges; authentication required.",
        )
    if too_fragmented:
        return _auth(
            ReasonCode.opaque_command,
            "Interpreter inline payload is too fragmented to fully vet; authentication required.",
        )
    return None


def _is_environment_dump_segment(raw_tokens: list[str]) -> bool:
    """True for a segment whose sole effect is to print the process
    environment: bare ``env``, ``printenv`` (any form), ``export``/``export
    -p``, ``declare -x``/``typeset -x`` with no named variable, or a
    PowerShell ``Env:`` drive listing.

    Runs on the RAW parsed segment, *before* :func:`argv_from_tokens` strips
    leading wrappers/assignments — that stripping is what makes bare ``env``
    invisible to :func:`_segment_verdict` (stripping ``env`` off ``["env"]``
    leaves an empty list, which the caller's ``if not tokens`` guard silently
    skips). We look through non-``env`` wrappers (``sudo env`` etc.) and
    env-assignment prefixes ourselves so this still fires under them, but stop
    at ``env``/``printenv`` themselves so we can inspect what follows.

    Known ceiling: ``dir``/``ls``/``gci`` are not in
    ``_WINDOWS_PATH_TRIGGER_RE``, so a literal trailing backslash (``dir
    env:\\``) fails POSIX shlex parsing before this function ever sees the
    segment and falls back to the generic ``opaque_command`` AUTH instead —
    still fails upward, just under a different reason code. The no-backslash
    form (``dir env:``) is unaffected.
    """
    rest = argv_from_tokens(raw_tokens, keep=frozenset({"env"}))
    if not rest:
        return False
    # M5: `keep={"env"}` stops the strip at env's own token so it stays
    # visible here, but a path-qualified `/usr/bin/env` or `ENV.EXE` is left
    # exactly as typed — _wrapper_name (I4's same fix) resolves it to "env".
    cmd, tail = _wrapper_name(rest[0]), rest[1:]

    if cmd == "printenv":
        return True  # every form reads the process environment

    if cmd == "env":
        i = 0
        while i < len(tail):
            token = tail[i]
            if _ENV_ASSIGNMENT.match(token) or token in _ENV_NOOP_FLAGS:
                i += 1
                continue
            if token in _ENV_UNSET_FLAGS:
                i += 2  # flag + its variable-name operand
                continue
            if token.startswith("--unset="):
                i += 1
                continue
            return False  # a real command to hand off to - not a dump
        return True

    if cmd in ("export", "declare", "typeset"):
        flags = [t for t in tail if t.startswith("-")]
        names = [t for t in tail if not t.startswith("-")]
        if names:
            return False  # names a specific variable, not a full listing
        return cmd == "export" or "-x" in flags

    if cmd.lower() in _POWERSHELL_LISTING_VERBS:
        return any(_POWERSHELL_ENV_DRIVE.match(t) for t in tail)

    return False


def _environment_dump_auth() -> GuardrailResult:
    return _auth(
        ReasonCode.environment_dump_command,
        "Command reads/prints the process environment, a common carrier for "
        "secrets (API keys, tokens); authentication required.",
    )


def _dev_tcp_udp_auth() -> GuardrailResult:
    return _auth(
        ReasonCode.raw_socket_channel,
        "Command opens a raw network channel outside the normal tool path "
        "(bare-TCP/UDP device redirection); authentication required.",
    )


# T2 — process-kill vocabulary (risky-but-recoverable, the same AUTH rung as
# `git reset --hard`). An agent gated on `rm -rf` but free to kill the
# operator's database, IDE, or CI runner has a gap that exists regardless of
# any benchmark. `xargs` piping into one of these is covered too (a common
# `pgrep ... | xargs kill` shape). Compared case-insensitively.
_PROCESS_KILL_COMMANDS = {"kill", "pkill", "killall", "taskkill", "stop-process", "spps"}

# `kill`'s own list/probe/help flags — benign only as the SOLE option present
# (T2-fix: `any(a in ... for a in args)` let a carve-out flag mixed with a
# real signal, e.g. `kill -0 -9 <pid>` or `kill -s 0 -s KILL <pid>`, slip
# through as PASS — see README's process-kill clause).
_KILL_LIST_HELP_FLAGS = {"-l", "-L", "--list", "--table", "-h", "--help"}
_KILL_VALUE_OPTIONS = {"-s", "-n", "--signal"}  # consume the next token as their value
_KILL_PROBE_OPTIONS = {"-0", ("-s", "0"), ("-n", "0"), ("--signal", "0"), "--signal=0"}
# The other kill-family tools carve out only their own bare help flag.
_KILL_HELP_ONLY_FLAGS = {"-h", "--help", "-?", "/?"}
# A `kill` operand naming the caller's OWN job/background process, never a
# foreign target: a job spec (`%1`, `%%`, `%+`, `%-`) or the last-background-
# pid / current-shell-pid shell parameters (`$!`, `$$`). shlex already strips
# surrounding quotes, so `"$!"` and `$!` tokenize identically.
_KILL_OWN_JOB_TARGET_RE = re.compile(r"^(?:%\d+|%%|%\+|%-|\$!|\$\$)$")

# xargs's own option vocabulary, so the process-kill check finds the command
# xargs actually invokes instead of scanning every token for a kill-family
# name (which false-fired on e.g. `xargs echo kill`).
_XARGS_SHORT_VALUE_OPTS = {"-I", "-n", "-P", "-L", "-l", "-d", "-a", "-E", "-s"}
_XARGS_LONG_VALUE_OPTS = {
    "--max-args",
    "--max-procs",
    "--max-lines",
    "--delimiter",
    "--arg-file",
    "--eof",
    "--replace",
    "--max-chars",
}

_KillOption = str | tuple[str, str | None]


def _kill_parse_options(args: list[str]) -> tuple[list[_KillOption], list[str]]:
    """Split a ``kill`` argv into ``(options, operands)``. A bare ``--`` ends
    option parsing (dropped, not kept as an operand); ``-s``/``-n``/
    ``--signal`` consume the next token as their value, folded into the
    option as e.g. ``("-s", "0")`` (left valueless if nothing follows);
    ``--signal=0`` is self-contained; every other ``-...`` token is a bare
    flag option."""
    options: list[_KillOption] = []
    operands: list[str] = []
    stop = False
    i, n = 0, len(args)
    while i < n:
        token = args[i]
        if not stop and token == "--":  # noqa: S105 — arg-parsing terminator, not a secret
            stop = True
            i += 1
            continue
        if not stop and token.startswith("-") and len(token) > 1:
            if token in _KILL_VALUE_OPTIONS:
                if i + 1 < n:
                    options.append((token, args[i + 1]))
                    i += 2
                else:
                    options.append((token, None))
                    i += 1
            else:
                options.append(token)
                i += 1
            continue
        operands.append(token)
        i += 1
    return options, operands


def _kill_sole_option_is_carveout(options: list[_KillOption]) -> bool:
    """True iff ``options`` holds exactly one option and it is a list/help
    flag or a signal-0 probe — the only option-based carve-outs that hold no
    matter what operand(s) accompany them (a probe/list never signals a
    target, whatever the target is). A second option of any kind (another
    probe, a real signal) forfeits the carve-out."""
    return len(options) == 1 and (
        options[0] in _KILL_LIST_HELP_FLAGS or options[0] in _KILL_PROBE_OPTIONS
    )


def _kill_is_benign(args: list[str]) -> bool:
    """PASS carve-outs for ``kill`` (never ``pkill``/``killall``/...): a
    list/help/probe flag as the SOLE option (see
    ``_kill_sole_option_is_carveout``), or every operand names the caller's
    own job — never someone else's process. I1: deliberately no "no args at
    all" carve-out — ``_strip_substitutions`` replaces `$(...)`/backticks
    with a space before tokenization, so ``kill $(pgrep sshd)`` reaches here
    as ``args == []`` too, indistinguishable from a bare usage-error `kill`;
    a stripped substitution must never masquerade as "no operands", so a
    truly-empty `args` fails closed like any other kill target."""
    options, operands = _kill_parse_options(args)
    if _kill_sole_option_is_carveout(options):
        return True
    return bool(operands) and all(_KILL_OWN_JOB_TARGET_RE.match(op) for op in operands)


def _xargs_command_start(tokens: list[str]) -> int:
    """Index of the first token after xargs's own option tokens — the
    command xargs invokes. A value-consuming xargs option eats the next
    token unless its value is attached (``-I{}``/``-n1``/``--max-args=1``);
    every other ``-...`` token is a bare xargs flag."""
    i, n = 0, len(tokens)
    while i < n:
        token = tokens[i]
        if not (token.startswith("-") and len(token) > 1):
            break
        if token in _XARGS_SHORT_VALUE_OPTS or token in _XARGS_LONG_VALUE_OPTS:
            i += 2 if i + 1 < n else 1
        else:
            # Either an attached value (`-I{}`/`--max-args=1`) or a bare
            # flag — both advance past just this one token.
            i += 1
    return i


def _xargs_invoked_command(tokens: list[str]) -> tuple[str, list[str]] | None:
    """The command xargs will run, and the tokens after it — or ``None`` if
    no command token follows xargs's own options. ``argv_from_tokens``
    strips env assignments and transparent wrappers first, so
    ``xargs sudo kill -9`` still resolves to ``kill``."""
    command_tokens = argv_from_tokens(tokens[_xargs_command_start(tokens) :])
    if not command_tokens:
        return None
    return command_tokens[0].lower(), command_tokens[1:]


def _process_kill_verdict(tokens: list[str]) -> GuardrailResult | None:
    """Signal/kill commands step up to AUTH: ``kill``/``pkill``/``killall``/
    ``taskkill``/``Stop-Process``, and ``xargs`` piping into one of these.
    Nothing else on an ``xargs`` command line is inspected — only the
    command it actually invokes."""
    if not tokens:
        return None
    cmd = tokens[0].lower()
    if cmd == "xargs":
        invoked = _xargs_invoked_command(tokens[1:])
        if invoked is None:
            return None
        cmd, rest = invoked
        if cmd not in _PROCESS_KILL_COMMANDS:
            return None
        if cmd == "kill":
            options, _operands = _kill_parse_options(rest)
            if _kill_sole_option_is_carveout(options):
                return None
        elif any(t in _KILL_HELP_ONLY_FLAGS for t in rest):
            return None
    elif cmd not in _PROCESS_KILL_COMMANDS:
        return None
    elif cmd == "kill":
        if _kill_is_benign(tokens[1:]):
            return None
    elif any(t in _KILL_HELP_ONLY_FLAGS for t in tokens[1:]):
        return None
    return _auth(
        ReasonCode.destructive_command,
        "Command signals or kills a process; authentication required.",
    )


def _segment_verdict(
    tokens: list[str], protected_branches: Iterable[str], bulk_threshold: int, root: str
) -> GuardrailResult | None:
    """Classify one parsed segment; ``None`` means this segment is benign."""
    if not tokens:
        return None
    cmd = tokens[0]

    # --- Control-plane tamper → BLOCK (HK.5.0b) ---
    # A shell command that names .doberman/ or the .claude/ hook config, or runs
    # the Doberman hook-install CLI, is disabling the cop — block it. (A path-
    # *target* rule misses a path hidden inside a command string.)
    if _segment_targets_control_plane(tokens, root):
        return _block_control_plane(
            "Shell command targets Doberman's own control plane "
            "(.doberman/ state or the .claude/ host-hook config)."
        )
    if _is_doberman_control_cli(tokens):
        return _block_control_plane(
            "Shell command would tamper with Doberman's control plane (install/remove/"
            "uninstall hooks, or change mode, enforcement, prefs, 2FA, taint, or password)."
        )
    if _package_manager_removes_doberman(tokens):
        return _block_control_plane(
            "Package-manager command would uninstall Doberman's guard (control-plane tamper)."
        )
    interpreter_payload = _interpreter_payload_verdict(tokens, root)
    if interpreter_payload is not None:
        return interpreter_payload

    # --- Catastrophic → BLOCK ---
    if cmd == "rm" and _rm_is_catastrophic(tokens):
        return _block("Recursive force-delete of a root/home/whole-tree target.")
    if _DISK_WIPE.match(cmd):
        return _block("Disk-wipe / filesystem-format command.")
    if cmd == "dd" and any("of=/dev/" in t for t in tokens[1:]):
        return _block("Raw write to a block device (data-destroying dd).")
    if cmd == "git" and _git_force_push_to_protected(tokens, protected_branches):
        return _block("Force-push to a protected branch (rewrites shared history).")
    # N2: the M1 false-positive fix removed the equivalent bare substring
    # check from _classify_line's RAW-command pre-check but left this
    # per-segment twin in place — it fires on ANY ":(){"-shaped substring
    # in the joined segment tokens (no trailing `|`/`&`/`;` body required),
    # so a quoted lookalike with no internal spaces (`grep -r ':(){' .`,
    # `echo ':(){'`) still false-BLOCKed here even after M1 shipped. A real
    # fork bomb never reaches this per-segment check intact in the first
    # place — `(`/`)` are segment separators, so the raw whole-command
    # check above (_FORK_BOMB_RE against the untouched string, before the
    # paren-splitting walk) is what actually has to catch it; this call is
    # a harmless backup using the same bounded regex.
    if _looks_like_fork_bomb(tokens):
        return _block("Fork-bomb-style command.")
    if _raw_socket_exec_on_connect(tokens):
        return _block_raw_socket_exec(
            "Command wires a network socket to command execution "
            "(exec-on-connect reverse/bind shell); blocked."
        )

    windows_delete = _windows_delete_verdict(tokens, bulk_threshold)
    if windows_delete is not None:
        return windows_delete

    # --- Risky but recoverable → AUTH ---
    if cmd == "rm" and _count_delete_operands(tokens) >= bulk_threshold:
        return _auth(
            ReasonCode.bulk_operation,
            "Bulk delete at or above the configured threshold; authentication required.",
        )
    if cmd == "rm" and _rm_targets_unrecoverable_data(tokens):
        return _auth(
            ReasonCode.destructive_command,
            "Deleting an unrecoverable, gitignored data file (local database, "
            "secret, or key); authentication required.",
        )
    if cmd == "git" and _git_is_history_rewrite(tokens):
        return _auth(
            ReasonCode.destructive_command,
            "Git history rewrite / hard reset; authentication required.",
        )
    if cmd == "git" and _git_commit_bypasses_verification(tokens):
        return _auth(
            ReasonCode.verification_bypass_flag,
            "Git commit bypasses its pre-commit hooks or signature verification; "
            "authentication required.",
        )
    if cmd == "git":
        _, assignments = _git_leading_globals(tokens)
        if _git_assignment_sets_alias(assignments):
            return _auth(
                ReasonCode.opaque_command,
                "Git command defines an alias (-c/--config-env= alias.*); the verb it "
                "actually runs cannot be determined statically, authentication required.",
            )
    if _is_pipe_to_shell(tokens):
        return _auth(
            ReasonCode.destructive_command,
            "Piping a downloaded payload into a shell; authentication required.",
        )
    channel = _raw_socket_channel_explanation(tokens)
    if channel is not None:
        return _auth(
            ReasonCode.raw_socket_channel,
            f"Command opens a raw network channel outside the normal tool path ({channel}); "
            "authentication required.",
        )
    process_kill = _process_kill_verdict(tokens)
    if process_kill is not None:
        return process_kill
    return None


#: The fork-bomb shape (``:(){ :|:& };:``) checked against the RAW command
#: string, before the paren-splitting walk — see the call site in
#: ``DestructiveCommandRule._classify_line`` for why the per-segment check
#: below can no longer see it alone once ``(``/``)`` are segment separators.
_FORK_BOMB_RE = re.compile(r":\s*[(]\s*[)]\s*[{][^}]*[|&;]\s*:")


def _looks_like_fork_bomb(tokens: list[str]) -> bool:
    joined = " ".join(tokens)
    return bool(_FORK_BOMB_RE.search(joined))


def _git_is_history_rewrite(tokens: list[str]) -> bool:
    """Keys on the actual git verb (see :func:`_git_leading_globals`) and only
    inspects that verb's OWN argv, so ``reset``/``filter-branch``/``clean``
    appearing merely as another verb's *argument* (``git log filter-branch``)
    is never mistaken for the real subcommand."""
    argv, _ = _git_leading_globals(tokens)
    if not argv:
        return False
    verb, rest = argv[0], argv[1:]
    if verb == "reset":
        return "--hard" in rest
    if verb == "filter-branch":
        return True
    # ``git clean -f`` permanently removes untracked files.
    return verb == "clean" and any(t.startswith("-") and "f" in t for t in rest)


def _git_leading_globals(tokens: list[str]) -> tuple[list[str], list[str]]:
    """``(subcommand_argv, config_assignments)`` — walk git's leading global
    options ONCE so the subcommand locator and the config-level
    verification-bypass check share one skip-loop. Skips ``-C <path>``/
    ``-c <k=v>`` and every option in ``_GIT_GLOBAL_OPTIONS_WITH_VALUE``
    (and each one's value token, space- or ``=``-separated), ``--no-pager``,
    ``-p``/``--paginate``, and any other leading ``-``/``--`` token — so
    ``git -C repo commit ...`` and ``git --git-dir /repo commit ...`` both
    still locate ``commit``, and a non-commit verb (``log``, ``tag``,
    ``shortlog``) that merely mentions "commit" among its own arguments is
    never mistaken for it. Along the way, every ``-c <k=v>`` value token and
    every ``--config-env`` value (space- or ``=``-separated) ``k=v`` is
    collected into ``config_assignments`` — these never appear as a flag ON
    the subcommand, so nothing downstream would otherwise see them."""
    if not tokens or tokens[0] != "git":
        return [], []
    rest = tokens[1:]
    i = 0
    assignments: list[str] = []
    while i < len(rest) and rest[i].startswith("-"):
        token = rest[i]
        if token == "-c":  # noqa: S105 — git's -c <k=v> option flag, not a secret
            if i + 1 < len(rest):
                assignments.append(rest[i + 1])
            i += 2
            continue
        if token.startswith("--config-env="):
            assignments.append(token[len("--config-env=") :])
            i += 1
            continue
        if token == "--config-env":  # noqa: S105 — git's --config-env <k=v> flag, not a secret
            if i + 1 < len(rest):
                assignments.append(rest[i + 1])
            i += 2
            continue
        i += 2 if token in _GIT_GLOBAL_OPTIONS_WITH_VALUE else 1
    return rest[i:], assignments


def _git_config_bypasses_verification(assignments: Iterable[str]) -> bool:
    """True if a leading ``-c``/``--config-env=`` assignment (see
    :func:`_git_leading_globals`) reproduces ``--no-verify``/``--no-gpg-sign``'s
    effect at the config level: see ``_GIT_HOOKS_PATH_CONFIG_KEY`` /
    ``_GIT_GPGSIGN_CONFIG_KEY`` above."""
    for assignment in assignments:
        key, sep, value = assignment.partition("=")
        if not sep:
            continue
        key = key.strip().lower()
        if key == _GIT_HOOKS_PATH_CONFIG_KEY:
            return True
        if key == _GIT_GPGSIGN_CONFIG_KEY and value.strip().lower() in _GIT_FALSY_CONFIG_VALUES:
            return True
    return False


def _git_assignment_sets_alias(assignments: Iterable[str]) -> bool:
    """True if a leading ``-c``/``--config-env=`` assignment (see
    :func:`_git_leading_globals`) defines a git alias (``alias.<name>=...``).

    Unlike :func:`_git_config_bypasses_verification`, which checks for a
    SPECIFIC known-dangerous key, this fires on the mere PRESENCE of any
    ``alias.*`` key, regardless of what it's set to: an alias lets the
    literal verb token (``p``, ``l``, ...) run ANY command git resolves it
    to, so once one is set, the actual verb this invocation runs can't be
    determined statically at all — the verb-keyed detectors
    (:func:`_git_force_push_to_protected`, :func:`_git_is_history_rewrite`)
    inspect only the literal token and would silently miss e.g.
    ``git -c alias.p="push --force" p origin main``."""
    for assignment in assignments:
        key, sep, _value = assignment.partition("=")
        if sep and key.strip().lower().startswith("alias."):
            return True
    return False


def _git_commit_bypasses_verification(tokens: list[str]) -> bool:
    """``git commit`` with ``--no-verify``/``-n``/``--no-gpg-sign`` (skips hooks or
    signing). ``-n`` is git's short alias for ``--no-verify`` and combines with
    other short commit flags (``-an``, ``-nm``), so any single-dash token
    containing the letter ``n`` counts — UNLESS that ``n`` sits inside a
    value-taking short option's attached value (``-mnote``), in which case the
    rest of that token is the option's VALUE and never scanned as flags —
    and, for a bare MANDATORY-value option (``-m``, ``-F``, ...), so is the
    whole next token. ``-S`` (GPG-sign) takes only an OPTIONAL, same-token
    value (``-Skeyid``); a bare ``-S`` never consumes the next token, so
    ``-S --no-verify`` and ``-S -n`` still resolve to bypass. A bare ``--``
    ends option parsing (git convention), so nothing after it is scanned as a
    flag. This also means a commit message is never misread as a flag.

    Also checks for a CONFIG-level bypass (``git -c core.hooksPath=... commit``
    / ``git -c commit.gpgsign=false commit`` / ``git --config-env=core.hooksPath=...
    commit``) — see :func:`_git_config_bypasses_verification`. Same evasion
    class, but the assignment never appears as a flag on ``commit`` itself."""
    argv, assignments = _git_leading_globals(tokens)
    if not argv or argv[0] != "commit":
        return False
    if _git_config_bypasses_verification(assignments):
        return True
    skip_next = False
    for token in argv[1:]:
        if skip_next:
            skip_next = False
            continue
        if token == "--":  # noqa: S105 — the git "end of options" marker, not a secret
            break  # end of options; remaining tokens are positional, never flags
        if token in _VERIFICATION_BYPASS_LONG_FLAGS:
            return True
        if not (token.startswith("-") and not token.startswith("--")):
            continue
        for i, ch in enumerate(token[1:], start=1):
            if ch == "n":
                return True
            if ch in _GIT_COMMIT_MANDATORY_VALUE_SHORT_OPTIONS:
                skip_next = len(token) == i + 1  # bare "-m": value is the NEXT token
                break
            if ch in _GIT_COMMIT_OPTIONAL_VALUE_SHORT_OPTIONS:
                break  # "-S"/"-Skeyid": value (if any) is never a separate token
    return False


def _is_pipe_to_shell(tokens: list[str]) -> bool:
    """A fetch tool (curl/wget) whose output is piped into a shell.

    Pipe splitting already separated segments, but ``curl ... | sh`` arrives as
    two segments; we flag the *fetch* side conservatively when it targets a
    shell via a following segment is handled at the line level. Here we catch a
    fetch that itself names a shell interpreter as an argument.
    """
    if tokens[0] not in {"curl", "wget"}:
        return False
    return any(part in _SHELLS for part in tokens[1:])


def _nc_has_exec_flag(tokens: list[str]) -> bool:
    """True if a netcat/ncat argv (past the command name) requests exec-on-
    connect: an exact flag (``_NC_EXEC_FLAGS``), an attached-value long flag
    (``--exec=...``/``--sh-exec=...``), or a clustered/glued short flag
    bundling ``e``/``c`` with other single-char flags or its own operand
    (``-lve``, ``-nve``, ``-le``, ``-e/bin/sh``). A bare port probe (``-zv``)
    has neither letter and stays unmatched."""
    for token in tokens:
        if token in _NC_EXEC_FLAGS or token.startswith(("--exec=", "--sh-exec=")):
            return True
        if (
            len(token) > 1
            and token[0] == "-"
            and token[1] != "-"
            and any(c in token[1:] for c in "ec")
        ):
            return True
    return False


def _raw_socket_exec_on_connect(tokens: list[str]) -> bool:
    """True for the exec-on-connect subset of the raw-socket shapes — a network
    tool wired to spawn a subprocess/shell (nc/ncat -e/--sh-exec, socat
    EXEC:/SYSTEM:). The discrete reverse/bind-shell predicate that earns a
    BLOCK; the broader raw-socket shapes (a bare /dev/tcp redirect, a nc -zv
    probe, openssl s_client) stay AUTH via
    :func:`_raw_socket_channel_explanation`."""
    if not tokens:
        return False
    cmd = tokens[0]
    if cmd in _NC_LIKE_COMMANDS and _nc_has_exec_flag(tokens[1:]):
        return True
    if cmd == "socat" and any(_SOCAT_EXEC_ADDRESS_RE.search(t) for t in tokens[1:]):
        return True
    return False


def _raw_socket_channel_explanation(tokens: list[str]) -> str | None:
    """Explanation fragment for a raw-socket/bare-TCP egress shape, or ``None``.

    Shapes: a ``/dev/tcp``/``/dev/udp`` redirection target (checked across
    every token, not just ``tokens[0]``, since bash writes it as a redirect
    operand anywhere in the segment); ``nc``/``ncat``/``socat`` used in
    exec-on-connect (reverse/bind-shell) form; or
    any ``openssl s_client`` invocation. Deliberately narrow (HK.5.6) so a routine
    port probe (``nc -zv host port``) or an unrelated ``openssl`` subcommand
    stays ``PASS``. Returns a small fixed string, never the matched token, so
    the caller's explanation never echoes a host/port/payload.
    """
    if any(_DEV_TCP_UDP_RE.search(token) for token in tokens):
        return "bare-TCP/UDP device redirection"
    cmd = tokens[0]
    if cmd in _NC_LIKE_COMMANDS and _nc_has_exec_flag(tokens[1:]):
        return "an exec-on-connect listener"
    if cmd == "socat" and any(_SOCAT_EXEC_ADDRESS_RE.search(t) for t in tokens[1:]):
        return "an exec-on-connect listener"
    if cmd == "openssl" and len(tokens) > 1 and tokens[1] == "s_client":
        # Match on the subcommand alone: s_client's only job is to open a TLS
        # client connection, and even a bare `openssl s_client` dials its
        # default target (localhost:4433), so every flag spelling that names a
        # target (-connect/--connect/-host/-port/-proxy/-unix/...) is covered
        # without enumerating them.
        return "a direct TLS client connection"
    return None


def _is_powershell_command_flag(token: str) -> bool:
    """``-Command``/``-c`` — PowerShell abbreviates parameter names by prefix,
    case-insensitive."""
    if not token.startswith("-") or len(token) < 2:
        return False
    return "command".startswith(token[1:].lower())


def _is_powershell_encoded_flag(token: str) -> bool:
    """``-EncodedCommand``/``-e`` — a base64 payload; never scanned (cannot
    decode/vet it), so the caller keeps this an opaque AUTH with no body scan."""
    if not token.startswith("-") or len(token) < 2:
        return False
    return "encodedcommand".startswith(token[1:].lower())


def _opaque_shell_payload(tokens: list[str]) -> bool:
    """True for ``bash -c <payload>``, PowerShell ``-Command``/``-EncodedCommand``,
    ``cmd /c <payload>``, ``su -c``/``su --command=``/``runuser -c``/
    ``runuser --command=``, or ``eval <words...>`` — a payload we cannot (or
    must not) statically vet. T5: ``su`` is a shell host like ``bash``, never a
    transparent wrapper — its own ``-c``/``--command`` payload is walked
    exactly the way ``bash -c``'s is (see ``_payload_command``). I2:
    ``runuser -c`` is ``su -c`` with a different name (a root shell running an
    arbitrary payload) — its own `_WRAPPER_OPAQUE_OPTIONS` entry keeps it, and
    its ``-c``/``--command`` marker, intact in ``tokens`` for this same check.
    #634: ``flock -c``/``--command`` is the same opaque payload shape — its
    own ``_WRAPPER_OPAQUE_OPTIONS`` entry keeps ``flock`` and the marker
    intact for this same check too.
    #555: ``eval`` is never a transparent wrapper either (absent from
    ``_WRAPPER_VALUE_OPTIONS``, so ``argv_from_tokens`` leaves it and its
    arguments untouched) — bash concatenates its arguments with a single
    space and re-parses the result as a shell command line, the same
    string-payload shape as ``bash -c``, so it gets the same opaque-AUTH
    floor with a body scan (see ``_payload_command``) rather than a silent
    PASS with the destructive segment hidden in one shlex token."""
    if not tokens:
        return False
    head = _wrapper_name(tokens[0])
    if head == "eval":
        return len(tokens) > 1
    if head in _SHELLS:
        return "-c" in tokens or "--command" in tokens
    if head in ("su", "runuser", "flock"):
        return (
            "-c" in tokens
            or "--command" in tokens
            or any(t.startswith("--command=") for t in tokens[1:])
        )
    if head in _WINDOWS_SHELLS:
        return any(
            _is_powershell_command_flag(t) or _is_powershell_encoded_flag(t) for t in tokens[1:]
        )
    if head in _CMD_SHELLS:
        return any(t.lower() == "/c" for t in tokens[1:])
    return False


def _block(explanation: str) -> GuardrailResult:
    return GuardrailResult(
        verdict=Verdict.BLOCK,
        risk=Risk.critical,
        reason_codes=[ReasonCode.destructive_command],
        explanation=explanation,
    )


def _block_raw_socket_exec(explanation: str) -> GuardrailResult:
    # A reverse/bind shell (socket wired to command execution). Keeps the
    # raw_socket_channel reason code (it IS a raw network channel) but at the
    # BLOCK tier: the exec-on-connect signature is unambiguous, unlike the
    # AUTH-tier probe/redirect shapes. Explanation is a fixed literal — no
    # host/port/shell path echoed (redaction).
    return GuardrailResult(
        verdict=Verdict.BLOCK,
        risk=Risk.critical,
        reason_codes=[ReasonCode.raw_socket_channel],
        explanation=explanation,
    )


# Surfaced on every control-plane block so a legitimate user isn't dead-ended:
# the agent is intentionally blocked from touching its own guard (anti-tamper),
# so the recovery path is out-of-band — a regular terminal where the hooks don't
# intercept. No user path is echoed here, so redaction holds.
_CONTROL_PLANE_RECOVERY_HINT = (
    " To change Doberman's own hooks/config, do it in a regular terminal outside the"
    " agent session (e.g. `doberman uninstall-hooks`) — the agent is intentionally"
    " blocked from tampering with its own guard."
)


def _block_control_plane(explanation: str) -> GuardrailResult:
    # Reuse the path rule's reason code — semantically this *is* a protected-path
    # hit, just surfaced from inside a command string (HK.5.0b).
    return GuardrailResult(
        verdict=Verdict.BLOCK,
        risk=Risk.critical,
        reason_codes=[ReasonCode.protected_path_blocked],
        explanation=explanation + _CONTROL_PLANE_RECOVERY_HINT,
    )


def _auth(reason: ReasonCode, explanation: str) -> GuardrailResult:
    return GuardrailResult(
        verdict=Verdict.AUTH,
        risk=Risk.high,
        reason_codes=[reason],
        explanation=explanation,
    )


def command_line_from_arguments(arguments: dict) -> str | None:
    """Reconstruct the command line a tool will run from its raw arguments.

    A string ``command``/``cmd``/``script`` is the line. A list-valued ``args``
    is an argv: joined with ``shlex.join`` so every token keeps its boundary
    (never plain-space-joined then re-split — that loses the token boundary of
    e.g. ``bash -c "rm -rf /"`` and mis-splits values with a bare apostrophe),
    and appended to a string ``command``/``cmd`` when both are present (the
    common ``{"command": "rm", "args": ["-rf", "/"]}`` shape). Never raises.
    """
    head: str | None = None
    for key in ("command", "cmd", "script"):
        value = arguments.get(key)
        if isinstance(value, str) and value.strip():
            head = value
            break
        if isinstance(value, (list, tuple)) and value:
            head = shlex.join(str(v) for v in value)
            break

    args_value = arguments.get("args")
    args_line: str | None = None
    if isinstance(args_value, (list, tuple)) and args_value:
        args_line = shlex.join(str(v) for v in args_value)

    if head is not None and args_line is not None:
        return f"{head} {args_line}"
    return head if head is not None else args_line


def _raw_command_payload(ctx: EvalContext) -> str | None:
    """Extract a command-shaped string from the un-redacted raw arguments, if any."""
    raw_arguments = ctx.metadata.get("raw_arguments") if isinstance(ctx.metadata, dict) else None
    if isinstance(raw_arguments, dict):
        return command_line_from_arguments(raw_arguments)
    return None


def _command_text(action: SecurityObject, ctx: EvalContext) -> str | None:
    """Extract the raw command string (from un-redacted context, else target)."""
    payload = _raw_command_payload(ctx)
    if payload is not None:
        return payload
    if action.target:
        return action.target
    return None


def delete_class_operands_and_dynamic(command: str) -> tuple[list[str] | None, bool]:
    """Path operands to every delete-class segment (``rm`` / a Windows delete
    verb) in ``command``, plus whether a live shell substitution appears
    anywhere in it — from a SINGLE :func:`walk_command` parse, using the SAME
    adversarial parse the destructive-command rule itself uses (prefix-
    stripped) — never a second parser.

    Returns ``(operands, dynamic)``. ``operands`` is ``None`` when no delete-
    class segment was found at all (the caller should not walk the
    filesystem for this command). Deliberately does NOT unwrap an opaque
    shell payload (``bash -c "..."``): that AUTHs via ``opaque_command``, not
    a delete-class reason, so showing no preview for a payload we cannot
    statically vet is correct — never a guess at what an opaque command
    deletes.

    **``operands`` can be empty or PARTIAL — never ``None`` — when a live
    shell substitution (``$( )``, backtick, ``${ }``, ``$VAR``) sits among the
    operands.** :func:`walk_command` flattens a substitution's body into its
    own sibling segment (see its own docstring), so that text is invisible
    here: a delete-class command word was still seen (``operands`` is not
    ``None``), but the list must NEVER be read as a confirmed/complete
    operand set in that case — check ``dynamic`` and treat a dynamic result
    as unknown, not as a confirmed (possibly zero) count.

    Used by :mod:`doberman.engine.effects` (ADR 0094); this module keeps its
    own no-filesystem-access contract — only the caller touches disk.

    M1 (C2 final review): a caller that needs both values (the blast-radius
    preview, ADR 0094) used to call two separate wrapper functions, re-
    parsing the same command line twice (0.046s each on a 44KB adversarial
    command). Call this once instead.
    """
    segments, _ambiguous, dynamic = walk_command(_normalize_windows_backslashes(command))
    operands: list[str] = []
    found = False
    for raw_segment in segments:
        tokens = argv_from_tokens(raw_segment)
        if not tokens or _leading_option(raw_segment, tokens):
            # T5-fix: an unresolved leading option (a failed wrapper-option
            # splice) is never a delete-class command — skip it rather than
            # risk misreading it as one; see `_leading_option`.
            continue
        cmd = tokens[0]
        if cmd == "rm":
            found = True
            operands.extend(t for t in tokens[1:] if not t.startswith("-"))
        elif cmd.lower() in _WINDOWS_DELETE_VERBS:
            found = True
            _, _, ops = _windows_delete_flags_and_operands(tokens)
            operands.extend(ops)
    return (operands if found else None), dynamic


class DestructiveCommandRule:
    """Detect catastrophic and risky shell/git commands; opaque → AUTH.

    ``protected_branches`` (constructor) is this instance's own protected set
    (``DEFAULT_PROTECTED_BRANCHES`` unless a caller overrides it — unchanged
    behaviour). Per call, ``evaluate`` additionally unions in any names from
    the active role's ``protected_branches`` (#199: the repo's
    ``.doberman/role.yaml`` ``protected_branches`` key, see
    ``doberman.config.load_active_role``) — a pure union, so it can only ever
    widen force-push protection for that one call, never narrow it.
    """

    def __init__(
        self,
        protected_branches: Iterable[str] = DEFAULT_PROTECTED_BRANCHES,
        bulk_threshold: int | None = None,
    ) -> None:
        # Normalized the same way as the config path (#199 review) so a
        # caller-supplied name with stray whitespace/casing/a refs/heads/
        # prefix matches like any other entry; a no-op for the defaults
        # (already normalized) and for any already-normalized override.
        self._protected = tuple(
            b for b in (_normalize_branch_name(raw) for raw in protected_branches) if b
        )
        # None → derive the bulk threshold from the active security mode (F6);
        # an explicit value overrides the mode (used by tests).
        self._bulk_threshold_override = bulk_threshold

    def _effective_protected(self, ctx: EvalContext) -> tuple[str, ...]:
        """``self._protected`` plus any role-configured extras (#199), unioned.

        No active role, or a role that doesn't set ``protected_branches``, is
        a no-op — byte-identical to before this existed.
        """
        role = getattr(ctx, "role", None)
        extra = getattr(role, "protected_branches", ()) or ()
        if not extra:
            return self._protected
        return self._protected + tuple(b for b in extra if b not in self._protected)

    def evaluate(self, action: SecurityObject, ctx: EvalContext) -> GuardrailResult:
        # Classify by payload shape, not by the tool's declared action type: a
        # command-bearing action type (shell_exec/git_op/package_install) also
        # gets the action.target fallback, but ANY action type carrying a
        # command-shaped raw_arguments payload (command/cmd/script/args) must
        # still be scanned — a tool label is not a safety boundary.
        if action.action_type in _COMMAND_ACTION_TYPES:
            command = _command_text(action, ctx)
        else:
            command = _raw_command_payload(ctx)
        if not command or not command.strip():
            return GuardrailResult(verdict=Verdict.PASS, risk=Risk.low)

        root = "."
        if isinstance(ctx.metadata, dict):
            root = str(ctx.metadata.get("repo_root") or ".")

        threshold = self._bulk_threshold_override
        if threshold is None:
            threshold = thresholds_for(getattr(ctx, "mode", "balanced")).bulk_delete_threshold
        return self._classify_line(command, threshold, root, self._effective_protected(ctx))

    def _classify_line(
        self, command: str, bulk_threshold: int, root: str, protected: Iterable[str]
    ) -> GuardrailResult:
        worst: GuardrailResult = GuardrailResult(verdict=Verdict.PASS, risk=Risk.low)

        # Checked against the RAW command, before shlex: POSIX tokenization eats
        # the `\` separators, so a Windows-spelled control-plane path never
        # survives to the per-segment scan below. _normalize_windows_backslashes
        # only fires on Windows-verb trigger words, so a POSIX verb with a
        # backslash-spelled path (`rm .doberman\policies.yaml`) needs this check.
        if _control_plane_in_windows_form(command, root):
            return _block_control_plane(
                "Shell command targets Doberman's own control plane "
                "(.doberman/ state or the .claude/ host-hook config)."
            )

        # Checked against the RAW command, before the paren-splitting walk:
        # `(`/`)` are now segment separators (command-walk hardening), which
        # shreds ":(){ :|:& };:" into benign no-op ":" segments before the
        # per-segment fork-bomb check (_segment_verdict) ever sees the whole
        # shape. Catch it here first, on the untouched command string.
        if _FORK_BOMB_RE.search(command):
            return _block("Fork-bomb-style command.")

        pending, saw_unparseable, _ = walk_command(_normalize_windows_backslashes(command))
        processed = 0
        # Set when an interpreter payload spawns a subprocess whose command
        # line we walk (see the block below) — the generic opaque_command AUTH
        # floor for that shape is applied AFTER the loop, only if nothing more
        # specific (e.g. the walked literal itself raising to BLOCK, or a
        # pushed literal segment like `env` earning its own reason code) already
        # raised `worst` past PASS. Applying it immediately would out-tie a
        # same-tier finding discovered on a later iteration (this module's
        # existing same-tier merge — _max_result — keeps the first result).
        saw_interpreter_spawn = False
        while pending and processed < _MAX_COMMAND_SEGMENTS:
            processed += 1
            raw_segment = pending.pop()
            # Checked on the RAW segment, before argv_from_tokens strips
            # env-assignment/wrapper prefixes: `D=/dev/tcp/...; cat f > $D` or
            # `TARGET=/dev/tcp/... cat f` carry the /dev/tcp path only in the
            # env-assignment token, which the stripped argv below never sees.
            if any(_DEV_TCP_UDP_RE.search(t) for t in raw_segment):
                worst = _max_result(worst, _dev_tcp_udp_auth())
            if _is_environment_dump_segment(raw_segment):
                worst = _max_result(worst, _environment_dump_auth())
                continue
            consumed_value_opt: list[bool] = []
            tokens = argv_from_tokens(raw_segment, consumed_value_option=consumed_value_opt)
            if not tokens:
                if consumed_value_opt:
                    # I2 root-cause: a wrapper VALUE option (one that ate a
                    # separate token as its value, e.g. `sudo -u root` with
                    # nothing after) emptied the segment entirely — the value
                    # it ate could have been an opaque payload, so this is
                    # never the same "no command at all" shape a bare-flag
                    # emptying (`sudo -l`, `sudo -h`) is. Fail upward rather
                    # than silently reading "nothing left" as benign.
                    worst = _max_result(
                        worst,
                        _auth(
                            ReasonCode.opaque_command,
                            "A wrapper option consumed the rest of the command; "
                            "authentication required.",
                        ),
                    )
                continue
            if _leading_option(raw_segment, tokens):
                # T5-fix: a wrapper's own option-value splice failed (e.g.
                # `env -S <value>` where `<value>` doesn't shlex.split), so
                # `argv_from_tokens` left the option/value tokens in place —
                # tokens[0] is still an option, never the command. Every
                # check below keys off tokens[0]; reading it as benign would
                # hide whatever command actually follows. Fail upward.
                worst = _max_result(
                    worst,
                    _auth(
                        ReasonCode.opaque_command,
                        "Command begins with an unresolved option after wrapper "
                        "stripping; authentication required.",
                    ),
                )
                continue
            if _opaque_shell_payload(tokens):
                # We cannot statically vet a -c payload → escalate, never guess.
                worst = _max_result(
                    worst,
                    _auth(
                        ReasonCode.opaque_command,
                        "Opaque shell payload (-c) that cannot be statically vetted; "
                        "authentication required.",
                    ),
                )
                # Still scan the payload body for obvious catastrophes — an
                # opaque AUTH can be raised to BLOCK if the body is e.g. rm -rf /.
                payload = _payload_command(tokens)
                if payload is not None:
                    payload_segments, payload_ambiguous, _ = walk_command(
                        _normalize_windows_backslashes(payload)
                    )
                    pending.extend(payload_segments)
                    saw_unparseable = saw_unparseable or payload_ambiguous
                continue

            # T3 — an interpreter payload that hands a subprocess a command
            # line (subprocess.*, os.system, child_process, ...): same rung as
            # bash -c's opaque payload above — push the command-line string/
            # list literals it passes back onto the walk so a catastrophic one
            # still raises this AUTH to BLOCK. Falls through (no continue) so
            # the rmtree/socket/control-plane checks in _segment_verdict still
            # run on THIS segment too.
            spawn_result = _interpreter_spawn_literals(tokens)
            if spawn_result is not None:
                spawn_literals, spawn_truncated = spawn_result
                saw_interpreter_spawn = True
                saw_unparseable = saw_unparseable or spawn_truncated
                for literal in spawn_literals:
                    literal_segments, literal_ambiguous, _ = walk_command(
                        _normalize_windows_backslashes(literal)
                    )
                    pending.extend(literal_segments)
                    saw_unparseable = saw_unparseable or literal_ambiguous

            verdict = _segment_verdict(tokens, protected, bulk_threshold, root)
            if verdict is not None:
                worst = _max_result(worst, verdict)
                if worst.verdict is Verdict.BLOCK:
                    return worst

        if pending:
            saw_unparseable = True

        if saw_interpreter_spawn and worst.verdict is Verdict.PASS:
            worst = _auth(
                ReasonCode.opaque_command,
                "Interpreter inline payload spawns a subprocess whose command line "
                "cannot be statically vetted; authentication required.",
            )

        # ``curl ... | sh`` arrives as two segments; if the line both fetches
        # and pipes into a shell, escalate (defense-in-depth at the line level).
        if worst.verdict is Verdict.PASS and _line_fetches_and_pipes_to_shell(command):
            worst = _auth(
                ReasonCode.destructive_command,
                "Piping a downloaded payload into a shell; authentication required.",
            )

        if saw_unparseable and worst.verdict is Verdict.PASS:
            return _auth(
                ReasonCode.opaque_command,
                "Command could not be parsed safely; authentication required.",
            )
        return worst


def _payload_command(tokens: list[str]) -> str | None:
    """Pull the argument after ``-c``/``-Command``/``cmd /c``/``su --command=``
    (or, #555, every word after ``eval``, bash-joined with a single space —
    ``eval``'s own concatenation rule) for a bounded shared-command walk.
    ``None`` for ``-EncodedCommand`` (base64 — cannot decode/vet) so the
    caller skips body scanning and keeps the opaque AUTH."""
    if tokens and _wrapper_name(tokens[0]) == "eval":
        return " ".join(tokens[1:]) if len(tokens) > 1 else None
    for flag in ("-c", "--command"):
        if flag in tokens:
            idx = tokens.index(flag)
            if idx + 1 < len(tokens):
                return tokens[idx + 1]
    for token in tokens[1:]:
        if token.startswith("--command="):
            return token.split("=", 1)[1]
    for idx, token in enumerate(tokens):
        if _is_powershell_encoded_flag(token):
            return None
        if _is_powershell_command_flag(token) or token.lower() == "/c":
            if idx + 1 < len(tokens):
                return tokens[idx + 1]
    return None


def _line_fetches_and_pipes_to_shell(command: str) -> bool:
    has_fetch = re.search(r"\b(?:curl|wget)\b", command) is not None
    piped_shell = re.search(r"\|\s*(?:sudo\s+)?(?:bash|sh|zsh|dash|ksh)\b", command) is not None
    return has_fetch and piped_shell


def _max_result(a: GuardrailResult, b: GuardrailResult) -> GuardrailResult:
    from doberman.models import VERDICT_ORDER

    return a if VERDICT_ORDER[a.verdict] >= VERDICT_ORDER[b.verdict] else b

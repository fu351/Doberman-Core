# Setup guide

This is the complete guide to installing Doberman, wiring it to your coding agent, locking in a
recovery factor, and confirming it works. New here? The [README](../README.md) has the 30-second
version.

**Contents**

- [1. Install](#1-install)
- [2. Run `doberman setup`](#2-run-doberman-setup)
- [3. Wire it to your agent](#3-wire-it-to-your-agent)
- [4. Set a password and 2FA](#4-set-a-password-and-2fa)
- [5. Check its health](#5-check-its-health)
- [6. Watch it work](#6-watch-it-work)
- [Appendix: a stale `doberman` on PATH](#appendix-a-stale-doberman-on-path)

---

## 1. Install

```bash
pip install doberman-core
```

> **Note**
> The distribution is `doberman-core` (the bare `doberman` name on PyPI belongs to an unrelated,
> abandoned project). The import name and CLI command are unchanged: you still `import doberman`
> and run `doberman`.

Install the latest from source instead:

```bash
pip install git+https://github.com/DobermanCore/Doberman-Core.git
```

Or for development:

```bash
git clone https://github.com/DobermanCore/Doberman-Core.git
cd Doberman-Core
pip install -e ".[dev]"
```

Any of these puts `doberman` on your PATH. If it behaves oddly (an old version, a missing
command), see the [PATH appendix](#appendix-a-stale-doberman-on-path). Maintainers: see
[RELEASING.md](../RELEASING.md).

## 2. Run `doberman setup`

One command does the whole job on any host. An interactive wizard detects which agents you have
installed (Claude Code, Codex CLI, an MCP client, OpenClaw), asks which ones to guard, picks your
security mode, tunes your guardrails, and wires each chosen host. Then it asks whether to send
anonymous usage stats, finishes with a doctor pass, and, if you wired a hooks-based host (Claude
Code or Codex), offers to run a scripted attack through the real engine right there so you can
watch it work:

```bash
doberman setup
```

```bash
doberman setup --yes
```

`--yes` accepts the defaults (detected hosts, or Claude Code if nothing is detected; balanced mode)
with no prompts, useful for CI or scripting. Pass `--host` (repeatable) to pick hosts explicitly,
e.g. `doberman setup --yes --host claude --host codex`, or `--host all` to wire all four at once.
Pass `--dry-run` to preview the mode, the preference weights, and every file it would write, with
nothing persisted (mirrors `install-hooks --dry-run`). `--global` writes to your real home directory
(hooks install for EVERY project on the machine, not just this repo; the prompt says so), so
without `--yes` it asks to confirm first, and with `--yes` it prints the exact path before writing.
Pass `--no-telemetry` to opt out for good without answering the telemetry question (same as
`doberman telemetry off`, just one step). Aborting the telemetry question itself (`q`, or a closed
stdin) is not consent either, and it also leaves telemetry off. The question's own default always
mirrors whatever is currently on disk, so a prior opt-out shows `[y/N]`, and a bare Enter re-affirms
"off" instead of silently reversing it; `--yes` never re-enables a persisted opt-out on its own.

Every prompt in the wizard accepts `q` or `quit` to abort cleanly instead of writing anything: this
covers the menus (which hosts, which mode, each tuning weight) and the yes/no confirms (telemetry,
global scope, weight tuning, the closing demo offer) alike, and menus print `(q to quit)` right in
the prompt. The one exception is the closing demo offer, reached only after setup has already fully
succeeded: there, `q` just declines the demo (printing the same "Aborted - ..." wording) without
turning a successful run into a failure. Either way, basic protection works immediately.

The closing doctor pass is not cosmetic. If it finds a critical problem (most commonly the
`doberman` command not being on PATH yet; the remedy now names the exact directory to add), the
wizard prints `!! Setup incomplete !!` and exits `1` instead of claiming success. Re-run `doberman
doctor` for the fix, then `doberman setup` again.

A run that wired ONLY `mcp` and/or `openclaw` (no hooks-based host at all) prints `!! Setup pending
!!` instead of `-- Setup complete --`. A MIXED run (e.g. `--host claude --host mcp`, where claude is
live but mcp still needs its manual paste-and-restart step) prints `!! Setup partly pending !!`
instead. Both non-`complete` headers use a second `!!` marker, not just color, so they stay
distinguishable in a piped or `NO_COLOR` transcript too, and both exit `3`, not `0`: something still
needs a manual step, but nothing is broken either, so a script can tell either apart from both a
fully-live run and a broken one. The `Hosts:` block in the summary names, per host, which one is
done and which still needs the manual step.

**Exit `0` means the run completed as designed. It does not mean you got the mode you asked for.**
A `--mode <lower>` request the raise-only gate refuses (run `doberman mode <name>` interactively to
actually lower it) still exits `0`: the closing header itself names the refusal right alongside the
outcome, e.g. `-- Setup complete (mode kept: balanced; light refused) --`, and the `Mode:` line below
it repeats the same reason.

When the wizard finishes, [set a possession factor](#4-set-a-password-and-2fa). `doberman doctor`,
one of the pointers in `doberman setup`'s own closing `Also:` line, already flags an unset one and
names the same command.

On a different host, or want to see exactly what gets wired? The next section covers each path by
hand.

## 3. Wire it to your agent

| Your host | How Doberman attaches | Where |
|---|---|---|
| Claude Code | Hooks: gate every built-in and MCP tool call (recommended) | [`doberman setup`](#2-run-doberman-setup) or [Claude Code hooks](#claude-code-hooks) |
| Codex CLI | Hooks | `doberman setup --host codex` or `doberman install-hooks --host codex`, see [Codex CLI](#codex-cli) |
| Claude Desktop, Cursor, any MCP client | MCP proxy: wrap your tool server | `doberman setup` prints the config; see [MCP proxy](#mcp-proxy) |
| OpenClaw | Native plugin adapter | `doberman setup` prints the pointer; see [OpenClaw](#openclaw) |

### Claude Code hooks

Hooks make Doberman gate every tool call your agent makes: built-ins (`Bash`, `Edit`, `Write`,
...) and any MCP tool, without rewiring your MCP config. The harness calls Doberman before each
tool call, and Doberman answers allow or deny. A sensitive action opens Doberman's own in-session
approval dialog (a confirm, or a TOTP code, the six-digit code an authenticator app generates for
2FA, two-factor authentication), so the agent can't bypass it by not "asking to use Doberman".

Install with one command:

```bash
doberman install-hooks
```

```bash
doberman install-hooks --global
```

```bash
doberman install-hooks --host codex
```

`install-hooks` writes `.claude/settings.json` for this project by default, `--global` writes
`~/.claude/settings.json` for every project, and `--host codex` wires `doberman hook codex-pre`
into a Codex CLI `hooks.json` instead. `--host` here is `claude` or `codex` only, since mcp and
openclaw don't write a hook file. `doberman setup --host mcp`/`--host openclaw` prints the pointer
for those instead. Add `--dry-run` to see what would change without writing anything; a re-run
whose merged hooks are unchanged prints `already wired: <path>` rather than `wrote <path>`. Remove
hooks with `doberman uninstall-hooks` (same `--global` / `--host` flags); it strips only Doberman's
entries and leaves your other hooks untouched.

`install-hooks` is idempotent, safe to re-run, and backs up an existing `settings.json` before
writing. `doberman setup` runs it for you.

`uninstall-hooks` only strips the hook entries. The project's `.doberman/` (policy, decision
database), any `--global` hooks, and your device-wide password, 2FA, and fingerprint key are all
left in place. To remove Doberman's protection from this project entirely, run `doberman
uninstall` instead: it removes the project- and local-scope hooks and `.doberman/` in one step. It
never touches `--global` hooks or device-wide auth state, since those protect every project on the
machine. Because it deletes state, it requires your enrolled possession factor (2FA if set up,
otherwise your password) and, being irreversible, also asks you to type the project directory name
back to confirm (`--yes` skips that confirmation, never the factor check). With neither factor
enrolled it fails closed and removes nothing.
If a global (or Codex `user`-scope) hook is still installed, `doberman uninstall` also adds the
project to a device-wide exclusion list that the global hook checks first, so the project gets a
true no-op; `doberman install-hooks` there clears it again (no gate, re-arming is a strengthen).

> **Note**
> `pip uninstall doberman-core` cannot also clean up the hook entries it wrote; pip has no hook
> for that. Run `doberman uninstall-hooks` first. If you already uninstalled the package and every
> tool call now fails with `doberman: command not found`, don't edit `settings.json` by hand:
> `pip install doberman-core` again and the existing hook entries start working the moment the
> binary is back.

On Claude Code it writes this, or add it by hand:

```jsonc
// .claude/settings.json (this project) or ~/.claude/settings.json (all projects)
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Edit|Write|NotebookEdit|WebFetch|WebSearch|mcp__.*",
        "hooks": [{ "type": "command", "command": "doberman hook pre", "timeout": 660 }]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "Bash|Edit|Write|NotebookEdit|WebFetch|WebSearch|Read|Glob|Grep|mcp__.*",
        "hooks": [{ "type": "command", "command": "doberman hook post", "timeout": 660 }]
      }
    ],
    "SessionStart": [
      {
        "hooks": [{ "type": "command", "command": "doberman session-summary" }]
      }
    ]
  }
}
```

Claude Code's own per-hook timeout defaults to 600s and a timed-out hook fails open (the tool call
proceeds unmediated), so the `timeout` pin above lets Doberman deny first.

**The pre-hook.** `doberman hook pre` reads the tool call on stdin and runs Doberman's
deterministic objective floor: path confinement, destructive-command detection, checks for
external destinations, secret-exfiltration checks (exfiltration: smuggling data out through some
other channel), and smuggled-token channels. A routine action passes silently. Doberman is
raise-only and never strips the harness's own prompts. A sensitive action opens Doberman's
approval dialog, a topmost confirm or TOTP prompt bound to that exact action. Approve it and the
call proceeds; decline it, or lose the channel, and it's denied. That is what "fail closed" means:
when Doberman can't confirm an action is safe, it blocks it. A dangerous action is blocked
outright, with a redaction-safe reason.

**The post-hook.** `doberman hook post` runs after a tool executes and scans its output for
credential-like material. Output containing a recognizable credential (a known key shape, a PEM
block, a secret file's contents) is blocked from reaching the model; the secret is never echoed.
A merely high-entropy token with no known credential shape (a hash, a UUID, a base64 fragment)
passes through, since that heuristic misfires on ordinary output too often to block on (a false
positive), but it is still recorded and taints the session: once a session has touched a secret,
it stays marked for the rest of that session. Taint powers a multi-step exfiltration floor. The
pre-hook raises any later egress, meaning an outbound call over the web, network, or MCP, in a
session that has already touched a secret: `ask` in light/balanced, a hard `deny` in
strict/paranoid. When an outbound value exactly matches, by keyed-HMAC fingerprint (a one-way
signature keyed to this device, not the raw secret), a secret that entered the session earlier,
that confirmed read-then-send is a hard `deny` in every mode, even light.

Both handlers fail closed and stay import-light, so they add minimal latency to each call. Every
decision lands in the same local, redacted history. `doberman log` shows PreToolUse AUTH/BLOCK
outcomes alongside PostToolUse ones. `doberman status` leads with a one-line `Protected: yes`
/ `Protected: no - <reason>` verdict (hooks installed for at least one host and `doberman`
resolvable on PATH), then four sections: Hooks (which settings file(s) carry the hooks), Policy
(mode, preferences, policy version, then the installed Doberman version), Auth (2FA, password,
elevations, taint), and Health (a one-line pointer to `doberman doctor`). It ends with the last
five decisions.

**Doberman protects its own hooks.** Once installed, the agent can't quietly remove them. A write
or edit to `.claude/settings.json` is blocked, and other `.claude/` changes require
authentication, so the agent can't disable enforcement by editing the harness config. This mirrors
how Doberman already hard-blocks its own `.doberman/` control plane, and it holds through the
shell too: a Bash command that writes or deletes the config, or runs `doberman uninstall-hooks`
(or `uninstall`), is blocked, not only the `Write`/`Edit` tools. The same block extends to every
posture- and auth-mutating verb (`mode`, `prefs`, `enforcement`, `2fa`, `password`, `revoke`,
`taint`, `uninstall`), while read/utility verbs (`status`, `doctor`, `log`, `scan`, `review`) stay
allowed.

### Codex CLI

`--host codex` wires a single `PreToolUse` hook (`doberman hook codex-pre`) into Codex's own
`hooks.json`, not Claude's `settings.json`. Everything else about `install-hooks` (idempotent,
`--dry-run`, `already wired: <path>` on a no-op re-run, `uninstall-hooks --host codex` to remove it)
works the same way:

```bash
doberman install-hooks --host codex
```

```bash
doberman install-hooks --host codex --global
```

The default (no `--global`) writes `<repo>/.codex/hooks.json`, wired for this project only;
`--global` writes `~/.codex/hooks.json`, wired for every project Codex runs in. `--local` has no
Codex equivalent: there's no per-project-untracked scope the way Claude Code has one.

**Trust it once.** Codex asks you to trust a new hook the first time it actually *runs*, not at
install time: run a Codex command and approve the hook when prompted, or launch with
`--dangerously-bypass-hook-trust` only if you already vet the hook source yourself. Until you trust
it, the hook is wired but inert; Codex skips it rather than gating the call. Once trusted, Doberman
gates every tool call in that scope from then on. Unlike Claude Code's hooks, there's no session
restart to wait for.

Verify it's live: ask Codex to `cat .env` and confirm it is blocked.

### MCP proxy

Doberman is a transparent MCP (Model Context Protocol, the standard your agent's tools speak)
proxy. Give it your existing tool server command after `--`, and it intercepts everything in
between:

```bash
# Before: agent talks directly to your tool server
npx -y @modelcontextprotocol/server-filesystem ~/my-project

# After: wrap it with Doberman
doberman serve -- npx -y @modelcontextprotocol/server-filesystem ~/my-project
```

To choose which repo's policy governs decisions (defaults to the current directory):

```bash
doberman serve --path ~/my-project -- npx -y @modelcontextprotocol/server-filesystem ~/my-project
```

Doberman communicates over stdio: it spawns your tool server as a managed subprocess and speaks
standard MCP. Your agent sees one server entry; the real tool server runs silently behind it.
Your agent's MCP client spawns `doberman serve`, not you. Typed bare into a terminal it blocks on
stdin waiting for a client to speak MCP (it prints one line saying so).

Point your agent at Doberman by replacing its existing MCP server entry with the wrapped version.

**Claude Code (CLI):**

```bash
claude mcp add doberman -- doberman serve -- npx -y @modelcontextprotocol/server-filesystem ~/my-project
```

**Claude Desktop** (`~/Library/Application Support/Claude/claude_desktop_config.json` on Mac,
`%APPDATA%\Claude\claude_desktop_config.json` on Windows):

```json
{
  "mcpServers": {
    "doberman": {
      "command": "doberman",
      "args": ["serve", "--",
               "npx", "-y", "@modelcontextprotocol/server-filesystem", "~/my-project"]
    }
  }
}
```

Cursor, Codex, or any MCP-compatible client uses the same `mcpServers` format in its own config
file; substitute your own tool server command after `--`.

**Remote servers.** A server reached over the network instead of spawned as a subprocess (Streamable
HTTP by default, or legacy SSE) is fronted with `--url` instead of a command after `--`:

```bash
doberman serve --url https://mcp.example.com/mcp
doberman serve --url https://mcp.example.com/sse --transport sse   # legacy SSE endpoint
```

A bearer token (or any credential) goes through `--header`/`-H` (repeatable, `"Name: value"`),
expanded by your shell so it never lands in argv or shell/process history:

```bash
doberman serve --url https://mcp.example.com/mcp -H "Authorization: Bearer $MCP_TOKEN"
```

Agent config JSON points `args` at `--url` instead of a spawned command:

```json
{
  "mcpServers": {
    "doberman": {
      "command": "doberman",
      "args": ["serve", "--url", "https://mcp.example.com/mcp"]
    }
  }
}
```

The proxy protects only the tools you route through it. To gate the agent's built-in tools too
(`Bash`, `Edit`, `Write`, ...), use [Claude Code hooks](#claude-code-hooks) where your host
supports them.

### OpenClaw

[OpenClaw](https://docs.openclaw.ai) agents route through Doberman via a small local plugin
instead of a hook-pack (OpenClaw's `before_tool_call` event is only reachable from a typed plugin
hook). It spawns `doberman hook openclaw` per call, the same fail-closed, deterministic objective
floor as the Claude Code hook, and maps the verdict to OpenClaw's own primitives: `allow` is a
no-op, `block` is terminal, and `auth` delegates to OpenClaw's own `/approve` flow (the gateway has
no interactive terminal of its own for Doberman's local challenge dialog). See
[`adapters/openclaw/README.md`](../adapters/openclaw/README.md) for install steps and the
mandatory "verify it's live" canary check. OpenClaw has shipped bugs where plugin hooks silently
never fire, so that check isn't optional.

## 4. Set a password and 2FA

Doberman is raise-only: tightening is always free, but a permanent policy lowering must prove
possession of a local factor. Set the minimum factor now; TOTP enrollment is optional, but becomes
the required, stronger factor once enrolled:

```bash
doberman password set
```

```bash
doberman 2fa setup
```

Rotating or dropping TOTP both need the code you currently hold, so a lost authenticator can't be
swapped out by anyone who merely reaches your shell:

```bash
doberman 2fa setup --force
```

```bash
doberman 2fa remove
```

Too many wrong 2FA codes lock further attempts for a short, self-recovering cooldown.
`doberman 2fa reset-lockout` clears it early by proving your password instead, since a locked-out
factor can't verify itself. It never disables the rate limiter; fresh wrong codes lock it again.

Removing the last possession factor is allowed but fails closed: with neither TOTP nor a password
enrolled, every policy weakening is denied until you enroll one again.

The same enrolled factor gates one other recovery action. Reading a secret taints a session for
the rest of it, and in strict/paranoid that raises later egress to AUTH or BLOCK with no automatic
reset. If that's expected and you want the repo's egress back to the mode default, `doberman taint
clear` wipes both taint stores after the same TOTP-or-password check. It still fails closed with
neither factor enrolled, and a denied or failed check leaves everything untouched.

## 5. Check its health

One read-only self-check that answers whether Doberman is wired up and healthy: host
hooks, config, the decision database, 2FA, the enforcement dial and strictness mode, and the
fingerprint key.

```bash
doberman doctor
```

It only diagnoses (it never changes state) and exits non-zero when a critical check (hooks, the
hook command being on PATH, config, or the decision database) isn't healthy, so it's safe to gate
a script on `doberman doctor && ...`.

Optionally, map what Doberman can see:

```bash
doberman scan
```

## 6. Watch it work

### Session summary

`install-hooks` also wires a `SessionStart` hook that runs `doberman session-summary`: a
print-and-exit summary (never interactive, never blocking) of a device-global, lifetime rollup.
Every decision Doberman makes, across every repo and session on this machine, increments a tiny
counter at `~/.doberman/metrics.db`: verdict class and count only, no path, no reason code, no
per-action detail. It shows total interceptions and the PASS/AUTH/BLOCK split:

```text
+------------------------------------------+
| Doberman - session guard summary          |
| Tracking since 2026-06-14 - this device   |
|                                            |
| Interceptions   1,204                     |
| Auto-passed      1,131  ( 93.9%)          |
| Authed              58  (  4.8%)          |
| Blocked             15  (  1.2%)          |
+------------------------------------------+
```

Run it any time with `doberman session-summary`. Output is plain ASCII, so it always renders on a
legacy Windows console, and the command always exits `0` and never raises: a session summary must
never break a session start.

### Decision log and TUI

`doberman log` prints the raw redacted rows; `doberman tui` browses the same rows interactively
and adds a plain-language "why" for whichever row is highlighted, built only from that row's
already-redacted verdict, layer, and reason codes. Arrow keys navigate; press `?` first for the
full keyboard reference (`/` filter, `b`/`B`/`a` jump to the next/previous BLOCK or next AUTH,
`w`/`enter` full-screen why, `tab` switch focus, `y` copy the action id, `home`/`end`, `r` reload,
`q` quit):

```bash
pip install "doberman-core[tui]"
```

```bash
doberman tui
```

By default the "why" is a deterministic, offline template: no network call, always available.
Enrich it with a short Claude-Haiku rewrite in plainer language if you want:

```bash
pip install "doberman-core[explain]"
```

```bash
export ANTHROPIC_API_KEY=...
export DOBERMAN_EXPLAIN_LLM=1
doberman tui
```

The LLM is a narrator, never a judge: it only rewords a verdict Doberman already made from the
redacted metadata above, and it can never change a decision. It's strictly opt-in (installed,
keyed, and flagged, all three), and any failure (missing key, no network, timeout, bad response)
silently falls back to the offline template. There is no `doberman explain` command; the TUI and
`doberman log` are the only surfaces for this.

A separate `[judge]` extra installs the same `anthropic` dependency for an unrelated,
experimental use: a constrained BYO-model second opinion evaluated offline against the labeled
corpus, not a CLI feature. See [`docs/BENCHMARKS.md`](BENCHMARKS.md#judge-agreement-offline-experimental)
- there is no live wiring and nothing here to run against a real session.

### Dashboard

```bash
pip install "doberman-core[dash]"
```

```bash
doberman dash --path .
```

A localhost-only web dashboard, off by default. It binds to `127.0.0.1` only and generates a
fresh, single-use token for that run; open the printed URL to connect, since every API call is
authenticated with that token. `--path` selects the repo to report on (default: the current
directory).

It shows a summary stats line, led by one focal number (the pending count while something needs a
human, otherwise the recent-window BLOCK count). Below that sit `decisions` (total, plus a
freshness timestamp, `updated HH:MM:SS (local)`), `verdicts (all time)` (the three badges, plus a
recent-window breakdown when it differs from the all-time counts), and `top reasons (all time)`,
where every count is explicitly labeled with its window so none can be confused with another. Below
that is a live decision feed that backfills recent decisions, then streams new ones, newest first.
Both are read-only and serve only already-redacted fields, never a raw target, argument, or secret.

Each feed row's timestamp is a client-computed relative age (`3m ago`, `2h ago`, `yesterday 11:00`,
refreshed every 30s) rather than a bare UTC clock, with the absolute local time and the explicitly
labeled UTC value in a hover `title`. Verdict filter chips default to `Needs attention` (BLOCK +
AUTH) rather than `All`, since a fresh dashboard should lead with what needs a human, not PASS
noise. `All`/`BLOCK`/`AUTH`/`PASS` are one click away, and the choice persists per browser. At
640px or narrower, the chips collapse into one `<select>`, with an `N of M shown` count next to it
that updates live as rows stream in.

A text filter (matching the visible explanation and reason-code gloss text too, not just the raw
codes) sits alongside it. At 640px or narrower it moves behind a collapsible `Filters` disclosure,
along with the `Announce new rows` toggle, so the first feed row still starts within budget on a
narrow screen. A dropped live connection or a failed refresh is always shown in the UI, never
silently, with a retry control.

An `AUTH` challenge can be answered from the dashboard instead of the terminal. It lists pending
approvals and resolves one at a time, a single-use transition, so two concurrent resolves of the
same row can never both win. Each pending card points at the channel that can actually answer.
`d` denies the action outright; it does not send it anywhere, so the note reads `The raw command
stays in your terminal. To read it before deciding, leave this card alone - it moves there in
M:SS.` with a live countdown. The row header shows the same live countdown (`answerable here for
M:SS, then it moves to your terminal`). At 0, the challenge has genuinely moved to the terminal/GUI
channel (not been denied), independent of the approval row's own longer DB TTL.

Both Approve and Deny need the same two-step arm-then-confirm gesture (a 5s countdown) before they
submit. The dashboard never verifies a TOTP code itself. A tier that needs one gets a real, visible
"6-digit code" label above the field, and the code rides opaquely to the same auth-challenge
machinery already running in the decision path. This channel engages only while the dashboard's own
heartbeat is fresh. A stale heartbeat, or an unanswered approval, falls back to the next channel
(MCP elicitation, then GUI dialog, then terminal) with no added latency.

Every `BLOCK`/`AUTH` row in the recent-decisions feed (and every pending card) leads with a one-line
human explanation, with its reason codes glossed via a hover tooltip. Expanding a row (click, tap,
or Enter/Space) reveals the same gloss text as a muted list, so keyboard and touch users reach it
too, not only a mouse hovering. Pending cards, which are never collapsed, just show that list
always. A row's explanation itself expands by click or tap as well as Enter/Space.

Keyboard shortcuts work from anywhere on the page: `/` to filter, `Esc` to clear it or close
whichever popover/panel is topmost, arrow keys/Home/End to move the active feed row, Enter/Space to
expand its explanation, `r` to refresh, `a`/`d` to arm-then-confirm Approve/Deny on the first
pending item, and `?` for the full list. A `Shortcuts: on/off` toggle in that same panel turns off
the five single-character bindings (`/ r ? a d`) specifically. Escape, the roving-focus keys, and
the on-screen buttons keep working regardless, and the toggle persists per browser. A manual
light/dark toggle also persists per browser regardless of the OS theme, and the browser tab's
favicon tints amber while an approval is pending.

You can also switch Light/Balanced/Strict/Paranoid from the dashboard. It goes through the same
gate as `doberman mode`. Raising applies immediately with a single click. Lowering restyles Save to
a warning color, states a factual one-line consequence of the mode you picked (derived from that
mode's real step-up thresholds; the floor hard blocks never change), and needs the same two-step
arm-then-confirm gesture (a 5s countdown) as approving a pending action, plus the same possession
factor. With neither enrolled, it fails closed.

Dismissing the popover (Escape or an outside click) with a change still pending keeps it open
instead of silently discarding it: it now visibly shakes and states so, since a silent no-op looked
identical to a closed popover. That warning stays put across a background stats poll too, clearing
only on Save, Cancel, or a new mode selection; Cancel always discards. While the popover is open,
the rest of the page sits behind a scrim and is genuinely `inert`, not just visually dimmed, and
the popover itself carries a visible "Security mode" title and a small tail pointing at its
trigger. Every attempt lands in the same append-only ledger (`doberman policy-history`).

Each `BLOCK`/`AUTH` feed row leads with a short, reason-first headline (e.g. "Recursive delete blocked -
shell_exec" or "Secret file read blocked - .env class") instead of the full explanation sentence, so a run
of consecutive BLOCKs no longer all read identically until expanded. Expanding a row keeps that headline
visible and reveals the full sentence underneath it, never repeating the reason codes the row's own gloss
list already shows. An absent or literally-`"unknown"` agent role reads as "an agent", never the bare
word `unknown`.

The feed itself is `role="log"` with `aria-live="off"` (a bare `role="log"` was silently announcing every
arriving row one at a time). An `Announce new rows: on/off` toggle next to the filter controls an ARIA
summary instead, debounced to one announcement per 2s (e.g. "3 new decisions: 2 BLOCK, 1 PASS"). A pending
card that crosses the dashboard's 90s answer window announces "Approval moved to your terminal" once. Two
tabs open on the same dashboard both catch up immediately on `visibilitychange` instead of waiting out the
poll interval.

At 640px or narrower, the topbar folds to one row (brand, connection chip, guard pill) plus a single
joined `posture: <mode> - <word>` badge and the `change` control. The theme toggle moves into the
shortcuts panel (opened via the `?` button, which stays put) to make room. `enforcement:` now reads
a single word (`enforcing`/`monitoring`/`off`; the raw dial name is still in its `title`), and the
"connected" chip is a plain rectangular tag with a dot inside it, rather than a second pill, so it
no longer looks like a duplicate of the guard pill. The topbar stays pinned to the top of the page
while scrolling, with a hairline/shadow that appears once actually scrolled, so the
connection/posture controls and the mode-change trigger stay reachable against a long feed.

The feed itself renders newest-first (a fresh dashboard opens on the latest activity, not the oldest
backfilled row). At 640px or narrower it drops its own inner scroller in favor of page scroll, so
there's no nested scroll trap on a touch device. Escape from a no-match filter (and `Clear
filters`/`Show all`) return focus to the first visible row, or the feed container itself if the
filter still leaves nothing visible. The `Needs attention` chip carries a `title` defining it
(`BLOCK + AUTH - what Doberman stopped or escalated`), repeated in the `?` shortcuts panel for
anyone who can't hover it. The no-match empty state says "these filters" once both the verdict
filter and the text query are narrowing the list together. `r` (and the Refresh button) announce
`Refreshed - N decisions, M pending`. A manual light/dark choice now also sets `color-scheme`
explicitly, so native form controls and scrollbars match it rather than following the OS preference
alone.

### Run the demo

Want to see real verdicts light up the dashboard without wiring up an agent? `doberman demo` runs
a scripted attack reel, five malicious tool calls and two benign ones, through the real decision
engine (no stubs) and logs every verdict, so the dashboard's live feed lights up with genuine
PASS/AUTH/BLOCK decisions. Nothing is ever executed against a real tool or downstream server.

```bash
# Terminal 1
doberman dash --path .
```

```bash
# Terminal 2
doberman demo --path .
```

Add `--fast` to skip the pacing delay between scenarios. Each scenario prints one line (verdict,
reason codes, explanation, never the raw tool arguments or any synthetic secret used to trip a
rule), then a summary table. Exit code is `0` only if every scenario matched its expected verdict,
so `doberman demo` doubles as a smoke test of the engine itself.

## Appendix: a stale `doberman` on PATH

If `doberman` behaves unexpectedly (missing a command you just added, running an old version,
ignoring your dev install), the shell may be resolving a different `doberman` executable than the
one in your active venv. This is common with more than one install method in play: a global
`pip`, `pipx`, and one or more venvs. Nothing below modifies PATH or removes anything; it only
reports.

**List every `doberman` executable on PATH.** Each command lists every match, not only the first;
the first result is the one your shell runs.

```bash
which -a doberman   # or: command -v doberman
```

```powershell
Get-Command -All doberman
```

**Compare it against your active virtual environment.** With your intended venv activated:

```bash
python -c "import sys; print(sys.prefix)"
command -v doberman
```

If `sys.prefix` doesn't match the directory the resolved `doberman` lives in (for example, it's
not under `.venv/bin` or `.venv/Scripts`), a different install is shadowing your venv's copy.

**Check common install locations.** These only report information; they don't remove or modify
anything.

```bash
.venv/bin/pip show doberman-core   # a pip-installed copy inside a venv
```

```bash
pipx list   # every pipx-managed package and its pinned interpreter
```

**Fix it, without touching PATH.** Re-activate the intended environment in the current shell
(`source .venv/bin/activate`, or `.venv\Scripts\activate` on Windows), then re-run the list step
to confirm it now resolves first. Or invoke the venv's executable directly, bypassing PATH
resolution: `./.venv/bin/doberman --version` (`.venv\Scripts\doberman.exe --version` on Windows).
If you recently activated or deactivated an environment, open a new shell; some shells cache the
resolved path for the current session (`hash -r` in bash clears this without restarting).

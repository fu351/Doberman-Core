# Roadmap

Doberman is the AI guard dog that stops your AI when it goes rogue. This page says what I am building toward and why, in plain words. The live list of work items is the [Doberman Roadmap board](https://github.com/users/fu351/projects/5). What already shipped is in the [changelog](CHANGELOG.md).

## The problem

A coding agent runs shell commands, edits files, and calls network services for you. It runs them the moment it decides to. Most guardrails read the prompt and offer advice before that moment, and an agent can talk itself past advice. Ten minutes before a hackathon demo, my agent deleted half my project to get rid of a bug it could not fix. Nothing was in the way.

## What Doberman is

Doberman sits between the agent and its tools. Every tool call passes through it and gets one verdict before it runs: PASS (routine, goes through), AUTH (sensitive, waits for a human), or BLOCK (dangerous, never runs). It plugs into Claude Code and Codex through their hooks (a point in the host where Doberman's check runs before a tool call), into OpenClaw as a plugin, and into Cursor through its hooks. Any other agent connects through an MCP proxy (MCP is the protocol agents use to call tools). It runs on your machine and writes a local, redacted log of every decision.

## Two promises that never change

1. Fail closed. On any error, crash, or unanswered prompt, the answer is deny. There is no path from the agent to a tool that skips the decision.
2. Raise-only. Doberman may tighten itself from what it sees. It never loosens itself. Every permanent loosening goes through a human, a second factor, and the audit log.

Every item below is judged against these two. A feature that would need either promise to bend does not ship.

## Where it is now (v0.18.6)

- Hosts: Claude Code, OpenClaw, and the MCP proxy, plus Codex and Cursor, both still marked experimental. The [parity matrix](docs/PARITY.md) shows which protection is proven on which host, with a link to the test behind each cell.
- Engine: rules for destructive commands, secret reads, data leaving the machine, protected branches, and hidden Unicode tricks in text. A session memory also judges a command differently once the agent has touched a secret.
- Approvals: a desktop dialog, a terminal prompt, and phone approvals (`doberman phone setup`), each with a hard deadline that resolves to deny. If the phone stays silent, the local dialog still opens with its usual deadline, so silence never approves anything. A password or TOTP (a one-time code app) guards any loosening.
- Log: an append-only SQLite decision log with secrets redacted and paths replaced by fingerprints (a one-way keyed hash that stands in for the real path), and `doberman log --why` to read the reasons behind a verdict.
- Benchmarks: an offline harness that scores the real engine over labeled tool calls, with the numbers and the failure cases in [docs/BENCHMARKS.md](docs/BENCHMARKS.md).
- Plugins: seams (Python entry points, a way for another package to register code without editing core) for rules, detectors, policy sources, auth providers, audit sinks, and drift observers (watchers that flag a policy change which loosens protection).

## Where it is going

### Now

- Promise bugs first. Two open reports say a promise bent: an AUTH that resolved without a human on Claude Code (#399), and the rule layer having no enforced authority ceiling (#630). Those are checked and fixed before anything below.
- Ambient monitoring. Today Doberman sees only the tool calls that pass through it. The ambient layer adds three pieces: an activity bus (#236, merged, ships in the next release), a warm daemon that scores activity from other sources in observe-only mode (#237), and basic collectors with a documented drop-in format (#238). Later, the same warm process should run the adaptive layer for the host hooks too (#639). The goal is one place that sees what every agent on the machine is doing.
- External benchmarks. Three third-party attack suites (RedCode-Exec, MSB, LLMail-Inject) already run through the harness next to my own corpus, so some of the numbers come from tests I did not write. The gaps those runs found are listed in [docs/BENCHMARKS.md](docs/BENCHMARKS.md), and closing them is on the board (#644).
- Host containment. When a host's own hook layer crashes, the agent must not run unguarded. Codex has shown this failure once (#335). After that come deeper parsing of shell commands (#634, #641), escalation when high-entropy data leaves the machine (#641), a honeytoken tripwire (#642), a per-session circuit breaker (#643), and a health check that cannot be fooled into saying hooks are on when they are off (#635, #636).

### Next

- Judgment as a last resort. An AI judge that can raise a verdict to AUTH when the rules are unsure, never lower one, with a spending cap and its own on-off switch (#559).
- Learning that forgets. Weights learned from your approve and deny history should decay back toward your chosen preset when they go stale (#410).
- A real algebra version. Stamp the action vocabulary's version on every decision and refuse to trust a mismatch (#424).
- A statistical channel for adversarial text. An optional extra that scores text with a small language model to catch the attacks the Unicode scanner cannot see (#235).

### Later

- Passkeys. A hardware-backed second factor as an option above TOTP (#145).
- A signed log. Sign the decision log and the policy ledger so tampering shows (#146).
- A team tier. Shared policy, dashboards, and sign-on for teams that run many agents. It will attach through the plugin seams that already exist, and the open core will keep working on its own with everything above in it.

## Non-goals

- Core will never need a cloud service to run.
- Doberman will never loosen itself automatically.
- Doberman judges what it can observe (the command, the path, the destination, the session so far). It does not read the model's mind.
- No single rule is airtight, and I will not claim one is. Doberman is one layer of defense, on the execution path, with a log.

## How to influence it

Open an issue or pick one up. Issues labeled good first issue are sized for a first contribution, and [CONTRIBUTING.md](CONTRIBUTING.md) explains the workflow. The [Discord](https://discord.gg/Sfy5XGNqty) is where I answer questions. If you run a coding agent that Doberman does not guard yet, open an issue and say which one.

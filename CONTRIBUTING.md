# Contributing to Doberman

Doberman is an Apache-2.0 project for AI-agent runtime authorization. This guide
gets you from a fresh clone to the same checks CI runs. `AGENTS.md` and
`CLAUDE.md` are the operating manual and source of truth for project invariants.

New here? Jump straight to [Pick a first task](#pick-a-first-task) for a
`good first issue`, then come back to the setup below to get your environment
running.

## Local setup

You need Python 3.11 or newer (CI tests 3.11, 3.12, and 3.13).

```bash
git clone https://github.com/DobermanCore/Doberman-Core.git
cd Doberman-Core
python -m venv .venv
source .venv/bin/activate  # Unix/macOS
# PowerShell: .venv\Scripts\Activate.ps1
# Command Prompt: .venv\Scripts\activate.bat
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

## Run the checks

Run these before opening a PR:

```bash
ruff check .
ruff format --check .
python scripts/check_markdown_links.py
lint-imports
pytest -n auto --cov=doberman --cov-report=term-missing --cov-fail-under=90
python -m tools.parity.generate_parity --check
```

CI runs exactly these checks: lint, import-boundary, link, and parity checks once on Linux; the
test suite on Linux 3.11 through 3.13 and Windows 3.12; a wheel smoke test on Linux and Windows;
and a full-history secret scan. Coverage is measured on the Linux 3.12 leg. Every test has a
5-minute timeout. The Windows leg runs the benchmark and gate modules with the faster test-size
half-space trees; the Linux legs and the nightly run them at production size.

A nightly deep run adds Windows 3.11 and 3.13, macOS, Python 3.14, random test order, warnings
treated as errors, production-size half-space trees, and a dependency vulnerability audit. A red
nightly means a bug in the suite or a dependency, not something to just rerun.

The optional extras `explain` (the Anthropic SDK) and `winhello` (Windows Hello) are not installed
in CI. Their tests use fakes there, so exercise the real thing locally when you touch them.

`-n auto` runs the suite in parallel (pytest-xdist ships in the `dev` extra), the
same way CI runs it.

After the standalone suite, the Linux 3.12 leg installs and tests the example plugins separately:

```bash
set -euo pipefail
for example in examples/plugin-*; do
  python -m pip install -e "$example"
  python -m pytest "$example/tests" --timeout=300
done
```

Keep these suites out of root `testpaths`: core must pass without example plugins installed.
Use a separate virtual environment for this command when continuing to test standalone core locally.

CI also verifies that `doberman-core` builds and tests without the private
enterprise package installed, then runs the same ruff, import-linter, pytest,
and secret-scan workflow.

## Choosing targeted tests

While developing a small, focused change, you can run only the tests related to
the area you're working on for faster feedback. Before marking a pull request
ready for review, always run the complete verification suite listed above.

### Common change areas

| Change area           | Suggested command                                                                                      |
| --------------------- | ------------------------------------------------------------------------------------------------------ |
| CLI                   | `pytest tests/unit/test_cli_help.py`                                                                   |
| Discovery / scan      | `pytest tests/unit/test_discovery_scan.py`                                                             |
| Policy / engine rules | `pytest tests/unit/test_objective_guardrail.py`                                                        |
| Storage / logging     | `pytest tests/unit/test_audit_sink.py`                                                                 |
| Proxy                 | `pytest tests/integration/test_proxy_passthrough.py`                                                   |
| Host hooks            | `pytest tests/unit/test_hosthook_control_plane.py`                                                     |
| Docs-only changes     | Preview the rendered Markdown when possible, then run the full verification suite before opening a PR. |

### Run a single test file

```bash
pytest tests/unit/test_discovery_scan.py
```

### Run a single test

```bash
pytest tests/unit/test_discovery_scan.py::test_scan_is_depth_bounded
```

### Run tests by keyword

```bash
pytest -k scan
```

This runs only tests whose names or node IDs match the given keyword.

### Before opening a pull request

Targeted tests are useful while iterating, but they do **not** replace the full
verification process. Before marking a pull request ready for review, run:

```bash
ruff check .
ruff format --check .
lint-imports
pytest -n auto --cov=doberman --cov-report=term-missing --cov-fail-under=90
```

The Markdown check is intentionally offline: it validates repository-local Markdown files and
heading anchors, skips external URLs and fenced code blocks, and never makes network requests.

## Architecture in five lines

1. A tool call enters Doberman through the MCP (Model Context Protocol, the standard interface
   between an agent and its tools) proxy, or through a host hook (code the host runs automatically
   around a tool call).
2. The call is normalized into a `SecurityObject`.
3. The decision engine runs objective and adaptive guardrails.
4. Guardrail verdicts merge through raise-only `combine()`: a merge can only tighten the result,
   never loosen it.
5. The execution gate returns `PASS`, `AUTH`, or `BLOCK`: allow, authenticate, or block.

## Where the docs live

| Doc                                            | What it covers                                        |
| ---------------------------------------------- | ----------------------------------------------------- |
| [`docs/SETUP.md`](./docs/SETUP.md)             | Install, first run, and host wiring                   |
| [`docs/CLI.md`](./docs/CLI.md)                 | Every `doberman` CLI command                          |
| [`docs/ADAPTER_GUIDE.md`](./docs/ADAPTER_GUIDE.md) | The shared shape of host adapters (proxy + hooks) |
| [`docs/REASON_CODES.md`](./docs/REASON_CODES.md) | Reason-code reference for decisions                 |
| [`docs/PARITY.md`](./docs/PARITY.md)           | Which guarantees hold on which host                   |
| [`docs/BENCHMARKS.md`](./docs/BENCHMARKS.md)   | The benchmark harness and metrics                     |
| [`docs/RELEASING.md`](./docs/RELEASING.md)     | Release process (maintainers)                         |

## Invariants

Every change must preserve these two safety properties:

- **Fail closed**: on any error, uncertainty, or unhandled case, deny or
  `BLOCK`; a protected agent must not reach a tool around Doberman.
- **Raise-only**: guardrails may auto-tighten, but may never silently loosen.
  Any permanent weakening goes through the human-gated policy path.

Also keep secrets out of commits, logs, fixtures, and PR examples. Redacted metadata,
classifications, and fingerprints (short tags derived from a secret key, so the original value
can't be worked out from them) are fine; raw secrets are not.

## Workflow

- Start from current `main` and make one focused slice per PR.
- Use the existing branch pattern: `feat/<feature>/<slice>`, `fix/...`, or
  `chore/...`.
- Use Conventional Commits, such as `fix(hosthooks): block control-plane writes`
  or `docs(contributing): add onboarding guide`.
- Tests travel with the code, and docs or README updates travel with behavior
  changes.
- Add a `changelog.d/<PR-number>.<type>.md` fragment instead of editing `CHANGELOG.md`; see `changelog.d/README.md` for the type names and bullet format.
- Fill out the PR template, including the public-release safety and security
  checklists.
- Note any AI assistance in the PR description.

## Pick a first task

Every open issue carries a difficulty label from `level-1` through `level-10`:

| Level | What it demands                                                                        |
| ----- | -------------------------------------------------------------------------------------- |
| 1     | Docs/Markdown only. Needs git and a text editor, no Python.                            |
| 2     | Mechanical: catalogue or transcribe what the code already does. Reads Python.          |
| 3     | Write a self-contained test, or add a flag following an existing sibling pattern.      |
| 4     | Touches a contract (redaction, reason codes). Needs one invariant understood.          |
| 5     | Multi-site change or cross-module test. Understand a subsystem, change no behaviour.   |
| 6     | Tooling/CI/packaging, or a new extension example. Expect unfamiliar failures.          |
| 7     | Additive engine change (new rule/detector/storage policy). Raise-only by construction. |
| 8     | Modifies existing risk classification. Needs maintainer design sign-off first.         |
| 9     | Complete an extension seam: interface, registry, tests and docs.                       |
| 10    | New subsystem, multi-week. Design discussion before any code.                          |

The ladder is meant to be climbed: finish a level-N issue, and a level-(N+1) issue in the same
area is the natural next step. Where an issue depends on another, it names that prerequisite.

Commenting on an issue claims it. Level-8 and above additionally expect a design comment, agreed
with a maintainer, before any code.

Start with the
[`good first issue`](https://github.com/DobermanCore/Doberman-Core/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)
or
[`help wanted`](https://github.com/DobermanCore/Doberman-Core/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22)
labels to find level-1/2/3 work, or browse a specific rung directly, e.g.
[`level-1`](https://github.com/DobermanCore/Doberman-Core/labels/level-1) (swap the number for any level
1-10). Good first PRs are usually narrow docs, tests, or guardrail hardening changes with a clear
issue to close. Ready for something meatier, the
[`good first challenge`](https://github.com/DobermanCore/Doberman-Core/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+challenge%22)
label marks well-scoped issues a rung or two further up the ladder.

## Questions and community

Ask questions on the issue you're working on. Maintainers watch the threads. For
roadmap and design conversation between PRs, join the
[Discord](https://discord.gg/Sfy5XGNqty).

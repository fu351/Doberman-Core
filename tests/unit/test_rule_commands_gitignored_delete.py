"""#198 — recursive delete of a gitignored, never-committed directory → AUTH.

Covers the gate that AN-1's lexical filename check deliberately deferred: a
*directory* operand (``rm -rf data/``) that git is ignoring and has never held a
commit of, i.e. data no ``git checkout`` can bring back.

The tests are split by what they prove:

* **Escalation** — the new AUTH actually fires, for ``rm`` and for the Windows
  delete verbs, including when only one operand of several qualifies.
* **No false positives** — tracked directories, gitignored-but-tracked paths
  (committed before they were ignored), and regenerable build/cache directories
  are all left exactly as they are today.
* **Fails toward today, never toward PASS** — no git binary, not a repository, a
  timeout, an OSError, an operand escaping the root: every one of them lands on
  the plain ``bulk_threshold`` behaviour rather than crashing or inventing a
  verdict.
* **Raise-only** — every BLOCK and every AUTH that fires today still fires, with
  its own reason code and its own explanation, unchanged.
* **Redaction** — the escalation's explanation names the category and never the
  directory it fired on.

Real ``git`` is used against real throwaway repositories under ``tmp_path``
rather than a mocked porcelain: the whole point of the gate is that we trust
git's answer over our own gitignore parsing, so a fake git would only test our
idea of what git says. The probe is deterministic (no network, no clock, fixed
committer identity) and each repo is built fresh per test.
"""

import os
import shutil
import subprocess
from datetime import datetime, timezone

import pytest

from doberman.engine.rules import commands as commands_module
from doberman.engine.rules.commands import DestructiveCommandRule
from doberman.models import (
    ActionType,
    EvalContext,
    ReasonCode,
    SecurityObject,
    Verdict,
)

RULE = DestructiveCommandRule()

requires_git = pytest.mark.skipif(
    shutil.which("git") is None, reason="the gate delegates to the git binary, which isn't here"
)


def _cmd(command, root, *, action_type=ActionType.shell_exec):
    """Evaluate ``command`` as if the agent ran it with ``root`` as the repo root."""
    action = SecurityObject(
        id="cmd-198",
        ts=datetime(2026, 6, 7, tzinfo=timezone.utc),
        agent_role="unknown",
        action_type=action_type,
        tool_name="shell_exec",
        target=command,
    )
    ctx = EvalContext(
        metadata={"raw_arguments": {"command": command}, "repo_root": str(root)},
    )
    return RULE.evaluate(action, ctx)


def _git(root, *args):
    subprocess.run(  # noqa: S603
        [shutil.which("git"), "-C", str(root), *args],
        check=True,
        capture_output=True,
        text=True,
    )


@pytest.fixture(autouse=True)
def _clear_git_lookup_cache():
    """``_git_executable`` is ``lru_cache``d for the decision path; clear it around
    every test so a monkeypatched ``shutil.which`` can never leak between them."""
    commands_module._git_executable.cache_clear()
    yield
    commands_module._git_executable.cache_clear()


@pytest.fixture
def repo(tmp_path):
    """A real git repo: ``data/`` and ``node_modules/`` gitignored and never
    committed, ``src/`` committed, ``legacy/`` committed *then* gitignored."""
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "test@example.invalid")
    _git(tmp_path, "config", "user.name", "Test")

    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "legacy").mkdir()
    (tmp_path / "legacy" / "old.txt").write_text("kept\n", encoding="utf-8")
    (tmp_path / ".gitignore").write_text("data/\nnode_modules/\n", encoding="utf-8")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "initial")

    # `legacy/` is ignored only AFTER it was committed — git still holds its
    # contents, which is exactly the "ignored but already tracked" false
    # positive `check-ignore` alone would get wrong. Ignoring it before the
    # commit would have meant it was never tracked at all.
    (tmp_path / ".gitignore").write_text("data/\nnode_modules/\nlegacy/\n", encoding="utf-8")
    _git(tmp_path, "add", ".gitignore")
    _git(tmp_path, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "ignore legacy")

    # Created only after the commit, so git has never held a copy of either.
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "local.state").write_text("unbacked\n", encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "pkg.js").write_text("//\n", encoding="utf-8")
    return tmp_path


# --- the escalation fires ---------------------------------------------------


@requires_git
@pytest.mark.parametrize("command", ["rm -rf data", "rm -rf data/", "rm -r data", "rm -Rf ./data"])
def test_recursive_delete_of_gitignored_uncommitted_dir_requires_auth(command, repo):
    result = _cmd(command, repo)
    assert result.verdict is Verdict.AUTH
    assert ReasonCode.destructive_command in result.reason_codes


@requires_git
def test_one_qualifying_operand_among_tracked_ones_still_escalates(repo):
    """The gate is ``any``, not ``all`` — hiding the ignored target in a list of
    harmless tracked ones must not launder it past the check."""
    assert _cmd("rm -rf src legacy data", repo).verdict is Verdict.AUTH


@requires_git
def test_windows_recursive_delete_of_gitignored_uncommitted_dir_requires_auth(repo):
    """An agent on Windows spells the same irrecoverable delete ``Remove-Item
    -Recurse data`` — the POSIX branch alone would ship a documented bypass."""
    result = _cmd("Remove-Item -Recurse data", repo)
    assert result.verdict is Verdict.AUTH
    assert ReasonCode.destructive_command in result.reason_codes


@requires_git
def test_escalation_survives_a_chained_segment(repo):
    """The worst verdict across the line wins, as everywhere else in this rule."""
    assert _cmd("echo hi && rm -rf data", repo).verdict is Verdict.AUTH


# --- no false positives -----------------------------------------------------


@requires_git
@pytest.mark.parametrize("command", ["rm -rf src", "rm -rf ./src", "rm -r src"])
def test_tracked_directory_is_unaffected(command, repo):
    """Acceptance criterion: the same command against a committed directory
    behaves exactly as it does today."""
    assert _cmd(command, repo).verdict is Verdict.PASS


@requires_git
def test_gitignored_but_already_tracked_directory_is_unaffected(repo):
    """``legacy/`` was committed *before* it was gitignored, so git still holds
    its contents and a delete is recoverable.

    Measured on git 2.47, ``check-ignore`` already declines to call a directory
    with tracked contents ignored, so the first probe is what catches this — the
    ``ls-files`` pass below is a backstop, not the load-bearing layer. This test
    asserts the *behaviour*; :func:`test_tracked_copy_backstop_blocks_a_false_positive`
    exercises the backstop directly, so neither layer can rot unnoticed.
    """
    assert _cmd("rm -rf legacy", repo).verdict is Verdict.PASS


@requires_git
def test_tracked_copy_backstop_blocks_a_false_positive(repo, monkeypatch):
    """If a git version ever *did* report a directory with committed contents as
    ignored, ``ls-files`` still has to stop the escalation.

    ``check-ignore``'s index-awareness is the default rather than a documented
    guarantee (it is what ``--no-index`` turns off), so this asserts the second
    layer independently instead of trusting the first to always be there.
    """
    monkeypatch.setattr(commands_module, "_git_ignored_subset", lambda cands, _root: list(cands))
    assert _cmd("rm -rf legacy", repo).verdict is Verdict.PASS
    # ...and the same stub must NOT suppress a genuinely uncommitted target.
    assert _cmd("rm -rf data", repo).verdict is Verdict.AUTH


@requires_git
@pytest.mark.parametrize("name", ["node_modules", "build", "dist", ".venv", "__pycache__"])
def test_regenerable_build_directories_are_carved_out(name, repo):
    """Deliberate scoping choice: tool-owned output is regenerated from committed
    sources, so escalating it would only teach people to click through prompts."""
    target = repo / name
    target.mkdir(exist_ok=True)
    (target / "artifact").write_text("generated\n", encoding="utf-8")
    (repo / ".gitignore").write_text(f"data/\n{name}/\n", encoding="utf-8")
    assert _cmd(f"rm -rf {name}", repo).verdict is Verdict.PASS


@requires_git
def test_carve_out_is_case_insensitive(repo):
    """Matched with ``fnmatchcase`` on a lowercased basename so the same command
    classifies identically on POSIX and on Windows."""
    (repo / "Build").mkdir()
    (repo / ".gitignore").write_text("Build/\n", encoding="utf-8")
    assert _cmd("rm -rf Build", repo).verdict is Verdict.PASS


@requires_git
def test_non_recursive_delete_never_escalates(repo):
    """A plain ``rm`` cannot remove a directory at all, so there is no
    directory-shaped loss to escalate — and the git probe stays off the
    overwhelmingly common non-recursive path."""
    assert _cmd("rm data", repo).verdict is Verdict.PASS


@requires_git
def test_nonexistent_target_does_not_escalate(repo):
    """Nothing on disk means nothing irrecoverable to lose."""
    assert _cmd("rm -rf never_created", repo).verdict is Verdict.PASS


@requires_git
def test_symlink_to_a_gitignored_dir_does_not_escalate(repo, tmp_path):
    """``rm -rf link`` unlinks the symlink; the tree behind it survives."""
    link = repo / "data_link"
    try:
        link.symlink_to(repo / "data", target_is_directory=True)
    except (OSError, NotImplementedError):  # unprivileged Windows
        pytest.skip("this platform will not let the test create a symlink")
    (repo / ".gitignore").write_text("data/\ndata_link\n", encoding="utf-8")
    assert _cmd("rm -rf data_link", repo).verdict is Verdict.PASS


@requires_git
def test_unexpanded_glob_operand_does_not_escalate(repo):
    """An operand still carrying a glob was never expanded, so we cannot know
    which path would actually be deleted — probing one would be a guess."""
    assert _cmd("rm -rf dat*", repo).verdict is Verdict.PASS


@requires_git
def test_operand_escaping_the_repo_root_does_not_escalate(repo, tmp_path):
    """Confinement is decided by the shared canonicalizer, not by this gate."""
    outside = tmp_path.parent / "outside_the_repo"
    outside.mkdir(exist_ok=True)
    assert _cmd("rm -rf ../outside_the_repo", repo).verdict is Verdict.PASS


# --- fails toward today, never toward PASS ----------------------------------


@requires_git
def test_no_git_binary_falls_back_to_todays_behaviour(repo, monkeypatch):
    monkeypatch.setattr(commands_module.shutil, "which", lambda _name: None)
    commands_module._git_executable.cache_clear()
    assert _cmd("rm -rf data", repo).verdict is Verdict.PASS


@requires_git
def test_not_a_git_repository_falls_back_to_todays_behaviour(tmp_path):
    """``check-ignore`` exits 128 here; that is an error, not an answer."""
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "local.state").write_text("x\n", encoding="utf-8")
    assert _cmd("rm -rf data", tmp_path).verdict is Verdict.PASS


@requires_git
@pytest.mark.parametrize(
    "boom",
    [
        subprocess.TimeoutExpired(cmd="git", timeout=2.0),
        OSError("git vanished between which() and run()"),
        subprocess.SubprocessError("spawn failed"),
        ValueError("bad argv"),
    ],
    ids=["timeout", "oserror", "subprocess-error", "valueerror"],
)
def test_every_git_failure_mode_falls_back_rather_than_crashing(boom, repo, monkeypatch):
    """A hung or broken git must never stall or crash a decision, and must never
    be read as either an escalation or a clean bill of health."""

    def _raise(*_args, **_kwargs):
        raise boom

    monkeypatch.setattr(commands_module.subprocess, "run", _raise)
    assert _cmd("rm -rf data", repo).verdict is Verdict.PASS


@requires_git
def test_ignored_but_tracked_state_unknown_falls_back(repo, monkeypatch):
    """``check-ignore`` answers but ``ls-files`` cannot: a committed copy is not
    ruled out, so the gate declines to escalate rather than guessing."""
    monkeypatch.setattr(commands_module, "_git_tracked_paths", lambda *_a, **_k: None)
    assert _cmd("rm -rf data", repo).verdict is Verdict.PASS


@requires_git
def test_probe_is_bounded_to_two_subprocesses_per_segment(repo, monkeypatch):
    """Cost ceiling: the operand count must not drive the process count."""
    calls = []
    real_run = commands_module.subprocess.run

    def _counting_run(argv, **kwargs):
        calls.append(argv)
        return real_run(argv, **kwargs)

    monkeypatch.setattr(commands_module.subprocess, "run", _counting_run)
    for extra in range(6):
        target = repo / f"data{extra}"
        target.mkdir()
        (target / "f").write_text("x\n", encoding="utf-8")
    (repo / ".gitignore").write_text("data*/\n", encoding="utf-8")
    assert _cmd("rm -rf " + " ".join(f"data{i}" for i in range(6)), repo).verdict is Verdict.AUTH
    assert len(calls) <= 2, calls


@requires_git
def test_timeout_is_actually_passed_to_the_subprocess(repo, monkeypatch):
    """The bound is only real if it reaches ``subprocess.run``."""
    seen = {}

    def _capture(argv, **kwargs):
        seen.update(kwargs)
        raise subprocess.TimeoutExpired(cmd="git", timeout=2.0)

    monkeypatch.setattr(commands_module.shutil, "which", lambda _n: os.fspath("git"))
    commands_module._git_executable.cache_clear()
    monkeypatch.setattr(commands_module.subprocess, "run", _capture)
    _cmd("rm -rf data", repo)
    assert seen.get("timeout") == commands_module._GIT_PROBE_TIMEOUT_S
    assert seen.get("shell") is not True


# --- raise-only: nothing that fires today changes ---------------------------


@requires_git
@pytest.mark.parametrize("command", ["rm -rf /", "rm -rf ~", "rm -rf /*"])
def test_catastrophic_deletes_still_block_inside_a_repo(command, repo):
    """The new branch sits far below these; a BLOCK can never become an AUTH."""
    result = _cmd(command, repo)
    assert result.verdict is Verdict.BLOCK
    assert ReasonCode.destructive_command in result.reason_codes


@requires_git
def test_bulk_threshold_keeps_precedence_and_its_own_reason_code(repo):
    """A bulk delete that also happens to be gitignored still reports
    ``bulk_operation`` — the new gate must not shadow an existing reason."""
    for i in range(30):
        (repo / f"d{i}").mkdir()
    (repo / ".gitignore").write_text("d*/\n", encoding="utf-8")
    result = _cmd("rm -rf " + " ".join(f"d{i}" for i in range(30)), repo)
    assert result.verdict is Verdict.AUTH
    assert ReasonCode.bulk_operation in result.reason_codes


@requires_git
def test_an1_lexical_gate_still_owns_the_file_case(repo):
    """AN-1 is built beside, not over: an unrecoverable *file* still resolves
    through its own branch and keeps its own wording."""
    (repo / "app.db").write_text("x\n", encoding="utf-8")
    result = _cmd("rm -rf app.db", repo)
    assert result.verdict is Verdict.AUTH
    assert "local database" in result.explanation


@requires_git
def test_control_plane_delete_still_blocks_inside_a_repo(repo):
    """The control-plane BLOCK runs before any of this and must stay first."""
    assert _cmd("rm -rf .doberman", repo).verdict is Verdict.BLOCK


# --- redaction --------------------------------------------------------------


@requires_git
def test_explanation_names_the_category_and_never_the_path(repo):
    """Same contract as every other explanation in this module: the class of
    danger, never the operand — this string reaches logs and auth prompts."""
    secret_dir = repo / "customer-exports-q3"
    secret_dir.mkdir()
    (secret_dir / "rows.csv").write_text("x\n", encoding="utf-8")
    (repo / ".gitignore").write_text("customer-exports-q3/\n", encoding="utf-8")

    result = _cmd("rm -rf customer-exports-q3", repo)
    assert result.verdict is Verdict.AUTH
    assert "customer-exports-q3" not in result.explanation
    assert "rows.csv" not in result.explanation
    assert str(repo) not in result.explanation
    assert "gitignored directory" in result.explanation

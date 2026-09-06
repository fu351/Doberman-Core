"""Exercise the actual example CI shell without installing plugins into core."""

from __future__ import annotations

import os
import subprocess
import tomllib
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]


def _example_step() -> dict:
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    steps = workflow["jobs"]["test"]["steps"]
    names = [step.get("name") for step in steps]
    assert names.index("Example plugin suites") > names.index("Test suite")
    config = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert all(
        not path.startswith("examples")
        for path in config["tool"]["pytest"]["ini_options"]["testpaths"]
    )
    return steps[names.index("Example plugin suites")]


@pytest.mark.skipif(os.name == "nt", reason="The example CI step runs on Linux only")
@pytest.mark.parametrize("failure", ["", "pip", "pytest"])
def test_example_ci_runs_each_package_and_propagates_failure(tmp_path: Path, failure: str) -> None:
    # Include a future package to pin discovery, not just the current three names.
    packages = ["plugin-a", "plugin-b", "plugin-future"]
    for name in packages:
        (tmp_path / "examples" / name / "tests").mkdir(parents=True)
    shim = tmp_path / "python"
    shim.write_text(
        "#!/bin/bash\n"
        'printf "%s\\n" "$*" >> "$CALLS"\n'
        'if [[ "$2" == "$FAILURE" ]]; then exit 17; fi\n'
    )
    shim.chmod(0o755)
    calls = tmp_path / "calls"
    result = subprocess.run(  # noqa: S603 - executes the checked-in CI step with a local shim
        ["bash", "-e", "-o", "pipefail", "-c", _example_step()["run"]],  # noqa: S607
        cwd=tmp_path,
        env={
            **os.environ,
            "PATH": f"{tmp_path}{os.pathsep}{os.environ['PATH']}",
            "CALLS": str(calls),
            "FAILURE": failure,
        },
        capture_output=True,
        text=True,
        check=False,
    )
    expected = [
        command
        for name in packages
        for command in (
            f"-m pip install -e examples/{name}",
            f"-m pytest examples/{name}/tests --timeout=300",
        )
    ]
    if failure:
        assert result.returncode == 17
        assert calls.read_text().splitlines() == expected[: 1 if failure == "pip" else 2]
    else:
        assert result.returncode == 0, result.stderr
        assert calls.read_text().splitlines() == expected

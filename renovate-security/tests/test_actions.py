"""Static checks of the composite actions using this package."""

import re
import shutil
import subprocess
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

ROOT = Path(__file__).resolve().parents[2]
ACTIONS = sorted(
    path
    for path in ROOT.glob("*/action.yml")
    if "renovate-security" in path.read_text() or path.parent.name.startswith("renovate-")
)


@pytest.fixture(params=ACTIONS, ids=[path.parent.name for path in ACTIONS])
def action(request):
    return request.param, yaml.safe_load(request.param.read_text())


def expressions(value) -> list[str]:
    text = yaml.safe_dump(value)
    return re.findall(r"\$\{\{(.*?)\}\}", text) + (
        [value["if"]] if isinstance(value, dict) and isinstance(value.get("if"), str) else []
    )


def test_actions_are_found():
    assert {path.parent.name for path in ACTIONS} >= {
        "renovate-triage",
        "renovate-auto-approve",
        "renovate-automerge",
    }


def test_inputs_and_steps_referenced_exist(action):
    path, data = action
    inputs = set(data.get("inputs") or {})
    steps = data["runs"]["steps"]
    ids = {step["id"] for step in steps if "id" in step}
    for step in steps:
        for expression in expressions(step):
            for name in re.findall(r"inputs\.(\w+)", expression):
                assert name in inputs, f"{path.parent.name}: unknown input {name}"
            for name in re.findall(r"steps\.([\w-]+)\.", expression):
                assert name in ids, f"{path.parent.name}: unknown step {name}"
    for output in (data.get("outputs") or {}).values():
        for name in re.findall(r"steps\.([\w-]+)\.", output["value"]):
            assert name in ids, f"{path.parent.name}: output from unknown step {name}"


def test_run_steps_declare_bash_and_pin_actions(action):
    path, data = action
    for step in data["runs"]["steps"]:
        if "run" in step:
            assert step.get("shell") == "bash", f"{path.parent.name}: {step['name']}"
            assert "${{" not in step["run"], f"{path.parent.name}: interpolate through env, not in run"
        if "uses" in step and not step["uses"].startswith("actions/") and "google-github-actions" not in step["uses"]:
            assert re.search(r"@[0-9a-f]{40}", step["uses"]), f"{step['uses']} must be pinned by SHA"


def test_trivy_is_a_fixed_release(action):
    path, data = action
    for step in data["runs"]["steps"]:
        if step.get("uses", "").startswith("aquasecurity/setup-trivy@"):
            version = (step.get("with") or {}).get("version", "latest")
            assert re.fullmatch(r"v\d+\.\d+\.\d+", version), f"{path.parent.name}: Trivy {version}"


@pytest.mark.skipif(not shutil.which("shellcheck"), reason="shellcheck not installed")
def test_run_steps_pass_shellcheck(action, tmp_path):
    path, data = action
    for index, step in enumerate(data["runs"]["steps"]):
        if "run" not in step:
            continue
        exports = "".join(f"export {name}=x\n" for name in step.get("env") or {})
        script = tmp_path / f"{path.parent.name}-{index}.sh"
        script.write_text(f"#!/usr/bin/env bash\nset -eo pipefail\n{exports}{step['run']}")
        result = subprocess.run(
            ["shellcheck", "-S", "warning", str(script)], capture_output=True, text=True
        )
        assert result.returncode == 0, result.stdout


def test_automerge_checks_the_reviews_right_before_merging():
    data = yaml.safe_load((ROOT / "renovate-automerge" / "action.yml").read_text())
    merge = next(step for step in data["runs"]["steps"] if step.get("id") == "merge")
    assert merge["run"].index("$REVIEW_GATE") < merge["run"].index("gh pr merge")


@pytest.mark.skipif(not shutil.which("shellcheck"), reason="shellcheck not installed")
def test_scripts_pass_shellcheck():
    for script in sorted((ROOT / "renovate-security" / "scripts").glob("*.sh")):
        result = subprocess.run(["shellcheck", "-S", "warning", str(script)], capture_output=True, text=True)
        assert result.returncode == 0, result.stdout

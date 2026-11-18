import json
import subprocess

import pytest

from renovate_security import cli
from renovate_security.advisories import Advisory
from renovate_security.ecosystems import Uv

LOCK = '[[package]]\nname = "{name}"\nversion = "{version}"\n'


def commit(repo, files, message):
    for path, content in files.items():
        (repo / path).parent.mkdir(parents=True, exist_ok=True)
        (repo / path).write_text(content)
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", message],
        cwd=repo,
        check=True,
    )
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True).stdout.strip()


@pytest.fixture
def repo(tmp_path, monkeypatch):
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("GITHUB_OUTPUT", raising=False)
    return tmp_path


def fake_uv_source(monkeypatch):
    def source(self, context):
        def fetch(name, version):
            if version == "3.1.2":
                return [Advisory("GHSA-1", None, "", "u", "critical", 9.8, ["3.1.6"])]
            return []

        return fetch

    monkeypatch.setattr(Uv, "source", source)


def test_triage_end_to_end(repo, monkeypatch):
    fake_uv_source(monkeypatch)
    base = commit(repo, {"uv.lock": LOCK.format(name="jinja2", version="3.1.2"), "README.md": "x"}, "base")
    head = commit(repo, {"uv.lock": LOCK.format(name="jinja2", version="3.1.6")}, "fix")
    output = repo / "out.txt"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))

    assert cli.main(["triage", "--base", base, "--head", head, "--hotfix-enabled", "false"]) == 0
    values = dict(line.split("=", 1) for line in output.read_text().splitlines())
    assert values["tier"] == "automerge"
    assert values["critical"] == "true"
    assert values["hotfix_pins"] == "uv:jinja2==3.1.6"
    assert values["update_level"] == "patch"
    assert values["ecosystems"] == "uv"
    assert json.loads((repo / "triage.json").read_text())["hotfix_enabled"] is False

    assert cli.main(["triage", "--base", base, "--head", head, "--frozen", "jinja2"]) == cli.EXIT_FROZEN


def test_triage_tells_unscored_files_from_a_pin(repo, monkeypatch):
    fake_uv_source(monkeypatch)
    files = {"uv.lock": LOCK.format(name="jinja2", version="3.1.2"), ".github/workflows/ci.yml": "a"}
    base = commit(repo, files, "base")
    action = commit(repo, {".github/workflows/ci.yml": "b"}, "update an action")
    # Committed before any triage writes its output files in the repository.
    pin = commit(repo, {"pyproject.toml": "[project]\n"}, "pin the range")

    assert cli.main(["triage", "--base", base, "--head", action, "--security-label"]) == 0
    result = json.loads((repo / "triage.json").read_text())
    assert result["tier"] == "manual"
    assert result["pin_only"] is False
    assert result["outside"] == [".github/workflows/ci.yml"]

    assert cli.main(["triage", "--base", action, "--head", pin, "--security-label"]) == 0
    result = json.loads((repo / "triage.json").read_text())
    assert result["pin_only"] is True
    assert result["outside"] == []


def test_triage_reads_file_names_git_would_quote(repo, monkeypatch):
    fake_uv_source(monkeypatch)
    base = commit(repo, {"uv.lock": LOCK.format(name="jinja2", version="3.1.2")}, "base")
    head = commit(repo, {"café/pyproject.toml": "[project]\n"}, "pin in a sub-project")
    assert cli.main(["triage", "--base", base, "--head", head, "--security-label"]) == 0
    result = json.loads((repo / "triage.json").read_text())
    assert result["outside"] == [] and result["pin_only"] is True


def test_triage_hotfix_threshold_above_ten_disables_hotfix(repo, monkeypatch):
    fake_uv_source(monkeypatch)
    base = commit(repo, {"uv.lock": LOCK.format(name="jinja2", version="3.1.2")}, "base")
    head = commit(repo, {"uv.lock": LOCK.format(name="jinja2", version="3.1.6")}, "fix")
    cli.main(["triage", "--base", base, "--head", head, "--hotfix-threshold", "11"])
    assert json.loads((repo / "triage.json").read_text())["tier"] == "automerge"
    cli.main(["triage", "--base", base, "--head", head])
    assert json.loads((repo / "triage.json").read_text())["tier"] == "hotfix"


def test_check_diff_only_allows_files_of_the_pinned_ecosystems(repo):
    base = commit(repo, {"uv.lock": "a", "Dockerfile": "FROM x:1\n"}, "base")
    lock_only = commit(repo, {"uv.lock": "b"}, "lock")
    assert cli.main(["check-diff", "--base", base, "--head", lock_only, "--pins", "uv:x==1"]) == 0
    both = commit(repo, {"Dockerfile": "FROM x:2\n"}, "docker")
    assert cli.main(["check-diff", "--base", base, "--head", both, "--pins", "uv:x==1"]) == 1
    assert cli.main(["check-diff", "--base", base, "--head", both, "--pins", "uv:x==1 docker:x==2"]) == 0


def test_replay_rejects_invalid_pins(repo):
    assert cli.main(["replay", "--pins", "ray==2.52.2"]) == cli.EXIT_REPLAY
    assert cli.main(["replay", "--pins", ""]) == cli.EXIT_REPLAY


def test_guard_mode_fails_on_scan_failures(repo, monkeypatch):
    from renovate_security.advisories import ScanFailed

    def source(self, context):
        def fetch(name, version):
            raise ScanFailed("GitHub unreachable")

        return fetch

    monkeypatch.setattr(Uv, "source", source)
    base = commit(repo, {"uv.lock": LOCK.format(name="jinja2", version="3.1.2")}, "base")
    head = commit(repo, {"uv.lock": LOCK.format(name="jinja2", version="3.1.6")}, "fix")
    assert cli.main(["triage", "--base", base, "--head", head]) == 0
    assert cli.main(["triage", "--base", base, "--head", head, "--fail-on-scan-failure"]) == cli.EXIT_SCAN_FAILED


@pytest.mark.parametrize("value", ["nan", "-1"])
def test_invalid_thresholds_are_rejected(value):
    with pytest.raises(SystemExit):
        cli.main(["triage", "--base", "a", "--head", "b", "--hotfix-threshold", value])


def test_thresholds_above_ten_are_allowed():
    assert cli.threshold("11") == 11.0


def test_check_diff_rejects_files_outside_the_lockfile_dir(repo):
    base = commit(repo, {"a/uv.lock": "1", "b/uv.lock": "1"}, "base")
    head = commit(repo, {"a/uv.lock": "2", "b/uv.lock": "2"}, "both")
    assert cli.main(["check-diff", "--base", base, "--head", head, "--pins", "uv:x==1"]) == 0
    assert cli.main(["check-diff", "--base", base, "--head", head, "--pins", "uv:x==1", "--lockfile-dir", "a"]) == 1

"""uv and Poetry lockfiles, scored with the GitHub Advisory Database (pip)."""

from __future__ import annotations

import os
import re
import tomllib
from pathlib import Path

from ..advisories import Source, github_source, normalize_pip
from .base import Ecosystem, ReplayError, Versions, merge_versions, owned_dirs, run


def parse_toml_lock(text: str) -> Versions:
    """uv.lock and poetry.lock can hold several versions of a package, split by markers."""
    versions: Versions = {}
    for pkg in tomllib.loads(text).get("package", []) if text else []:
        if "version" in pkg:
            versions.setdefault(pkg["name"], set()).add(pkg["version"])
    return versions


# Never hand a token to package build backends run by the resolver.
def tokenless_env() -> dict[str, str]:
    return {
        key: value
        for key, value in os.environ.items()
        if not re.search(r"TOKEN|SECRET|PASSWORD|PASSWD|KEY|CREDENTIAL|AUTH", key, re.I)
    }


class Uv(Ecosystem):
    name = "uv"
    lockfiles = ("uv.lock",)
    manifests = ("pyproject.toml",)
    has_patched_versions = True

    def parse(self, files: dict[str, str]) -> Versions:
        versions: Versions = {}
        for text in files.values():
            merge_versions(versions, parse_toml_lock(text))
        return versions

    def source(self, context: dict) -> Source:
        return github_source(context["github_token"], "pip")

    def replay(self, root: Path, pins: list[tuple[str, str]]) -> None:
        args = [arg for name, version in pins for arg in ("--upgrade-package", f"{name}=={version}")]
        for directory in owned_dirs(self, root):
            # --no-build: never run a package build backend; a fix needing one is manual.
            run(["uv", "lock", "--no-build", *args], directory, tokenless_env())


def direct_poetry_dependencies(pyproject: dict) -> set[str]:
    names = set()
    project = pyproject.get("project") or {}
    for spec in project.get("dependencies") or []:
        names.add(normalize_pip(re.split(r"[\s\[<>=!~;(]", spec, maxsplit=1)[0]))
    for specs in (project.get("optional-dependencies") or {}).values():
        for spec in specs:
            names.add(normalize_pip(re.split(r"[\s\[<>=!~;(]", spec, maxsplit=1)[0]))
    poetry = (pyproject.get("tool") or {}).get("poetry") or {}
    names.update(normalize_pip(name) for name in poetry.get("dependencies") or {})
    names.update(normalize_pip(name) for name in poetry.get("dev-dependencies") or {})
    for group in (poetry.get("group") or {}).values():
        names.update(normalize_pip(name) for name in group.get("dependencies") or {})
    names.discard("python")
    return names


class Poetry(Ecosystem):
    name = "poetry"
    lockfiles = ("poetry.lock",)
    manifests = ("pyproject.toml",)
    has_patched_versions = True

    def parse(self, files: dict[str, str]) -> Versions:
        versions: Versions = {}
        for text in files.values():
            merge_versions(versions, parse_toml_lock(text))
        return versions

    def source(self, context: dict) -> Source:
        return github_source(context["github_token"], "pip")

    def replay(self, root: Path, pins: list[tuple[str, str]]) -> None:
        for directory in owned_dirs(self, root):
            pyproject = tomllib.loads((directory / "pyproject.toml").read_text())
            direct = direct_poetry_dependencies(pyproject)
            indirect = [name for name, _ in pins if normalize_pip(name) not in direct]
            if indirect:
                raise ReplayError(
                    f"Poetry can only pin direct dependencies, not {', '.join(indirect)}"
                )
            run(
                ["poetry", "add", "--lock", *[f"{name}=={version}" for name, version in pins]],
                directory,
                tokenless_env(),
            )

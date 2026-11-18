"""package-lock.json (v1 to v3), scored with the GitHub Advisory Database (npm)."""

from __future__ import annotations

import json
from pathlib import Path

from ..advisories import Source, github_source
from ..versions import semver_key, semver_release
from .base import Ecosystem, ReplayError, Versions, owned_dirs, run
from .python import tokenless_env

DEPENDENCY_FIELDS = (
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
)


def parse_package_lock(text: str) -> Versions:
    versions: Versions = {}
    if not text:
        return versions
    lock = json.loads(text)
    packages = lock.get("packages")
    if packages is not None:
        for path, entry in packages.items():
            if not path or "node_modules/" not in path or entry.get("link"):
                continue
            name = entry.get("name") or path.rsplit("node_modules/", 1)[1]
            if "version" in entry:
                versions.setdefault(name, set()).add(entry["version"])
        return versions

    def walk(dependencies: dict) -> None:
        for name, entry in dependencies.items():
            if "version" in entry and not entry["version"].startswith(("file:", "link:")):
                versions.setdefault(name, set()).add(entry["version"])
            walk(entry.get("dependencies") or {})

    walk(lock.get("dependencies") or {})
    return versions


class Npm(Ecosystem):
    name = "npm"
    lockfiles = ("package-lock.json",)
    manifests = ("package.json",)
    release_fn = staticmethod(semver_release)
    key_fn = staticmethod(semver_key)
    has_patched_versions = True

    def parse(self, files: dict[str, str]) -> Versions:
        versions: Versions = {}
        for text in files.values():
            for name, found in parse_package_lock(text).items():
                versions.setdefault(name, set()).update(found)
        return versions

    def source(self, context: dict) -> Source:
        return github_source(context["github_token"], "npm", normalize=str.lower)

    def replay(self, root: Path, pins: list[tuple[str, str]]) -> None:
        for directory in owned_dirs(self, root):
            manifest_path = directory / "package.json"
            manifest = json.loads(manifest_path.read_text())
            direct = {name for field in DEPENDENCY_FIELDS for name in manifest.get(field) or {}}
            direct_pins = [f"{name}@{version}" for name, version in pins if name in direct]
            overrides = {name: version for name, version in pins if name not in direct}
            if overrides:
                existing = manifest.get("overrides") or {}
                conflicting = [n for n in overrides if isinstance(existing.get(n), dict)]
                if conflicting:
                    raise ReplayError(f"Nested overrides already set for {', '.join(conflicting)}")
                manifest["overrides"] = {**existing, **overrides}
                manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
            base = ["npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"]
            if direct_pins:
                run([*base, "--save-exact", *direct_pins], directory, tokenless_env())
            if overrides:
                run(base, directory, tokenless_env())

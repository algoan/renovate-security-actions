from __future__ import annotations

import fnmatch
import posixpath
import re
import subprocess
from pathlib import Path

from ..advisories import Source
from ..versions import KeyFn, ReleaseFn, package_level, release, version_key

Versions = dict[str, set[str]]


class ReplayError(Exception):
    """The fix cannot be replayed automatically: a human takes over."""


class Ecosystem:
    """A kind of dependency: where it is declared, how versions compare, how to replay a fix."""

    name = ""
    # Glob patterns (on the basename) of the files read to list the dependencies.
    lockfiles: tuple[str, ...] = ()
    # Files a replayed fix may touch, on top of the lockfiles.
    manifests: tuple[str, ...] = ()
    release_fn: ReleaseFn = staticmethod(release)
    key_fn: KeyFn = staticmethod(version_key)
    # Can the advisories give the smallest fixing version (GitHub Advisory Database)?
    has_patched_versions = False
    # Replay every dependency the PR changes, not only those with a fixed advisory.
    replay_whole_pr = False

    def owns(self, path: str) -> bool:
        return any(
            fnmatch.fnmatch(posixpath.basename(path), pattern) for pattern in self.lockfiles
        )

    def parse(self, files: dict[str, str]) -> Versions:
        """Dependencies and their versions, from the content of the files it owns."""
        raise NotImplementedError

    def level(self, before: set[str], after: set[str]) -> str:
        return package_level(before, after, self.release_fn, self.key_fn)

    def source(self, context: dict) -> Source:
        raise NotImplementedError

    def replay(self, root: Path, pins: list[tuple[str, str]]) -> None:
        """Apply `name==version` pins to the checkout at `root`."""
        raise NotImplementedError

    def allows(self, path: str) -> bool:
        """Can a replayed fix of this ecosystem touch `path`?"""
        name = posixpath.basename(path)
        return self.owns(path) or any(fnmatch.fnmatch(name, p) for p in self.manifests)


# Dockerfile, dockerfile.prod, api.Dockerfile, service.Dockerfile.dev: the same names as the
# detection of the actions, which install Trivy when one of them changes.
DOCKERFILE = re.compile(r"^([^/]*\.)?dockerfile(\.[^/]*)?$", re.I)


class DockerfileOwner:
    def owns(self, path: str) -> bool:
        return bool(DOCKERFILE.match(posixpath.basename(path)))


def run(cmd: list[str], cwd: Path, env: dict[str, str] | None = None) -> None:
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, env=env, check=False)
    if result.returncode != 0:
        raise ReplayError(
            f"`{' '.join(cmd)}` failed: {(result.stderr or result.stdout).strip()[-500:]}"
        )


def merge_versions(target: Versions, extra: Versions) -> Versions:
    for name, versions in extra.items():
        target.setdefault(name, set()).update(versions)
    return target


def owned_dirs(ecosystem: Ecosystem, root: Path) -> list[Path]:
    """Directories holding a lockfile of `ecosystem` in the checkout at `root`.

    `root` is the scope of the replay: the `lockfile_dir` of a monorepo project, so that a pin
    never touches the lockfiles of other projects.
    """
    listed = subprocess.run(
        ["git", "ls-files", "."], cwd=root, capture_output=True, text=True, check=True
    ).stdout.split("\n")
    return sorted({(root / path).parent for path in listed if path and ecosystem.owns(path)})

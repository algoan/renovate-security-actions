"""pnpm-lock.yaml (v5 to v9), scored with the GitHub Advisory Database (npm).

The lockfile is YAML, but only the keys of its `packages:` section are needed and they follow a
fixed shape, so it is read line by line without a YAML parser (the package runs on the runner's
bare python3). One entry per resolved package version:

    packages:                          # v6 / v9
      '@nestjs/common@11.2.7':         # v9 (scoped names are quoted)
      axios@1.18.1:                    # v9
      /axios@1.6.0:                    # v6 (leading slash)
      /@scope/pkg@1.0.0(peer@2.0.0):   # v6 (peer suffix)
      /axios/1.6.0:                    # v5 (slash-separated version)
      registry.example.com/axios@1.6.0: # v6+ (non-default registry, keyed by its host)
      axios@work:1.6.0:                # v9 (named registry alias)
"""

from __future__ import annotations

import re
from pathlib import Path

from ..advisories import Source, github_source
from ..versions import semver_key, semver_release
from .base import Ecosystem, ReplayError, Versions

# A 2-space indented key of the top-level `packages:` section, optionally quoted.
PACKAGE_KEY = re.compile(r"^  '?(?P<key>[^'\s][^']*?)'?:\s*$")
SECTION = re.compile(r"^(?P<name>[A-Za-z][\w-]*):\s*$")


def _split_key(key: str) -> tuple[str, str] | None:
    """`name@version[(peers)]` or `/name@version`, `/name/version` → (name, version)."""
    key = key.lstrip("/")
    key = key.split("(", 1)[0]  # peer dependency suffix of v6+ keys
    # A package from a registry other than the default one is keyed by its host:
    # `registry.example.com/name@version` (v6+) or `registry.example.com/name/version` (v5).
    # A package name may contain a dot too (`lodash.merge/4.6.2`), so only a first segment
    # followed by something that still looks like a package key is a registry host.
    host, _, rest = key.partition("/")
    if "." in host and not host.startswith("@") and rest and not rest[0].isdigit():
        key = rest
    if "/" in key:
        # v5: `name/version[_peers]` or `@scope/name/version[_peers]` — the last segment is the version.
        base, _, last = key.rpartition("/")
        if last and last[0].isdigit():
            return base, last.split("_", 1)[0]
    if "@" not in key[1:]:
        return None
    name, _, version = key.rpartition("@")
    # `node@runtime:24.6.0` is the Node.js runtime pnpm manages (devEngines), not an npm package.
    if version.startswith("runtime:"):
        return None
    # A package resolved through a named registry carries its alias: `foo@work:1.0.0`.
    version = version.rpartition(":")[2]
    if not name or not version or not version[0].isdigit():
        return None
    return name, version


def parse_pnpm_lock(text: str) -> Versions:
    versions: Versions = {}
    in_packages = False
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        section = SECTION.match(line)
        if section:
            in_packages = section["name"] == "packages"
            continue
        if not in_packages:
            continue
        match = PACKAGE_KEY.match(line)
        if not match:
            continue
        parsed = _split_key(match["key"])
        if parsed:
            name, version = parsed
            versions.setdefault(name, set()).add(version)
    return versions


class Pnpm(Ecosystem):
    name = "pnpm"
    lockfiles = ("pnpm-lock.yaml",)
    manifests = ("package.json", "pnpm-workspace.yaml")
    release_fn = staticmethod(semver_release)
    key_fn = staticmethod(semver_key)
    has_patched_versions = True

    def parse(self, files: dict[str, str]) -> Versions:
        versions: Versions = {}
        for text in files.values():
            for name, found in parse_pnpm_lock(text).items():
                versions.setdefault(name, set()).update(found)
        return versions

    def source(self, context: dict) -> Source:
        return github_source(context["github_token"], "npm", normalize=str.lower)

    def replay(self, root: Path, pins: list[tuple[str, str]]) -> None:
        # Transitive pins need `overrides` in pnpm-workspace.yaml (pnpm 11) or package.json (older),
        # and a `pnpm install --lockfile-only` whose output depends on the pnpm version and the
        # workspace settings (minimumReleaseAge, catalogs). Not automated yet: a hotfix is manual.
        raise ReplayError("pnpm fixes are not replayed automatically: open the hotfix by hand")

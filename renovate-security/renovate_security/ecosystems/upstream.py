"""Upstream sources pinned in Dockerfiles through Renovate regex comments, scored with NVD.

    # renovate: datasource=github-tags depName=openssl/openssl extractVersion=^openssl-(?<version>.+)$
    ENV OPENSSL_VERSION=3.6.5

An optional `cpe=vendor:product` field on the comment (or the `upstream_cpes` input) maps the
dependency to its NVD product. Dependencies without one are reported as not scored.
"""

from __future__ import annotations

import re
from pathlib import Path

from ..advisories import Source, nvd_source
from ..versions import loose_key, loose_release
from .base import DockerfileOwner, Ecosystem, ReplayError, Versions, owned_dirs

COMMENT = re.compile(r"^\s*#\s*renovate:\s*(?P<fields>.+?)\s*$")
ASSIGNMENT = re.compile(r"^\s*(?:ENV|ARG)\s+(?P<var>\w+)(?:=|\s+)(?P<value>\S+)\s*$", re.I)


def comment_fields(line: str) -> dict[str, str] | None:
    match = COMMENT.match(line)
    if not match:
        return None
    fields = dict(
        part.split("=", 1) for part in match["fields"].split() if "=" in part
    )
    return fields if "depName" in fields else None


def pinned_sources(text: str) -> list[tuple[dict[str, str], str, int]]:
    """(comment fields, value, line index of the value) for each `# renovate:` pin."""
    lines = text.splitlines()
    found = []
    for index, line in enumerate(lines):
        fields = comment_fields(line)
        if fields is None:
            continue
        for offset, candidate in enumerate(lines[index + 1 :], start=index + 1):
            if not candidate.strip():
                continue
            assignment = ASSIGNMENT.match(candidate)
            if assignment:
                found.append((fields, assignment["value"], offset))
            break
    return found


def parse_cpes(text: str) -> dict[str, str]:
    """`depName=vendor:product` lines (the `upstream_cpes` input)."""
    cpes = {}
    for line in text.splitlines():
        name, sep, product = line.strip().partition("=")
        if sep and ":" in product:
            cpes[name.strip()] = product.strip()
    return cpes


class Upstream(DockerfileOwner, Ecosystem):
    name = "upstream"
    release_fn = staticmethod(loose_release)
    key_fn = staticmethod(loose_key)
    has_patched_versions = True
    replay_whole_pr = True

    def __init__(self) -> None:
        self.cpes: dict[str, str] = {}

    def parse(self, files: dict[str, str]) -> Versions:
        versions: Versions = {}
        cpes: dict[str, str] = {}
        for text in files.values():
            for fields, value, _ in pinned_sources(text):
                name = fields["depName"]
                versions.setdefault(name, set()).add(value)
                if ":" in fields.get("cpe", ""):
                    cpes[name] = fields["cpe"]
        # The revision parsed last (the head of the comparison) wins: a corrected or removed
        # mapping applies.
        self.cpes = cpes
        return versions

    def source(self, context: dict) -> Source:
        cpes = {**self.cpes, **parse_cpes(context.get("upstream_cpes", ""))}
        return nvd_source(cpes, context.get("nvd_api_key", ""))

    def replay(self, root: Path, pins: list[tuple[str, str]]) -> None:
        targets = dict(pins)
        done: set[str] = set()
        for directory in owned_dirs(self, root):
            for path in directory.iterdir():
                if not (path.is_file() and self.owns(path.name)):
                    continue
                text = path.read_text()
                lines = text.splitlines(keepends=True)
                for fields, value, index in pinned_sources(text):
                    name = fields["depName"]
                    if name in targets:
                        lines[index] = lines[index].replace(value, targets[name], 1)
                        done.add(name)
                path.write_text("".join(lines))
        missing = set(targets) - done
        if missing:
            raise ReplayError(f"No `# renovate:` pin found for {', '.join(sorted(missing))}")

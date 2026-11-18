"""Images of `FROM` and `COPY --from` in Dockerfiles, scored by scanning both images with Trivy."""

from __future__ import annotations

import re
from pathlib import Path

from ..advisories import Source, trivy_source
from ..versions import loose_key, max_level
from .base import DockerfileOwner, Ecosystem, ReplayError, Versions, owned_dirs

FROM = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?(?P<ref>\S+)(?:\s+AS\s+(?P<alias>\S+))?", re.I)
COPY_FROM = re.compile(r"^\s*COPY\s+(?:--\S+\s+)*?--from=(?P<ref>\S+)", re.I)
TAG = re.compile(r"^v?(?P<numbers>\d+(?:\.\d+)*)(?P<suffix>.*)$")


def split_ref(ref: str) -> tuple[str, str] | None:
    """(image, version) where version is `tag`, `tag@digest` or `@digest`."""
    if "$" in ref or ref == "scratch":
        return None
    image, at, digest = ref.partition("@")
    slash = image.rfind("/")
    colon = image.rfind(":")
    if colon > slash:
        image, tag = image[:colon], image[colon + 1 :]
    else:
        tag = ""
    if not tag and not at:
        return None  # unpinned (latest): nothing to compare
    return image, tag + (f"@{digest}" if at else "")


def image_refs(text: str) -> list[tuple[str, str]]:
    aliases: set[str] = set()
    refs = []
    for line in text.splitlines():
        match = FROM.match(line) or COPY_FROM.match(line)
        if not match:
            continue
        ref = match["ref"]
        if ref.lower() in aliases or ref.isdigit():
            continue
        if match.groupdict().get("alias"):
            aliases.add(match["alias"].lower())
        parsed = split_ref(ref)
        if parsed:
            refs.append(parsed)
    return refs


def tag_of(version: str) -> str:
    return version.partition("@")[0]


def tag_parts(version: str) -> tuple[tuple[int, ...], str] | None:
    match = TAG.match(tag_of(version))
    if not match:
        return None
    return tuple(int(n) for n in match["numbers"].split(".")), match["suffix"]


def docker_release(version: str) -> tuple[int, ...] | None:
    parts = tag_parts(version)
    if parts is None:
        return None
    numbers = list(parts[0]) + [0, 0]
    return 0, *numbers[:3]


def docker_key(version: str) -> tuple:
    return loose_key(tag_of(version).partition("-")[0])


class Docker(DockerfileOwner, Ecosystem):
    name = "docker"
    release_fn = staticmethod(docker_release)
    key_fn = staticmethod(docker_key)
    replay_whole_pr = True

    def parse(self, files: dict[str, str]) -> Versions:
        versions: Versions = {}
        for text in files.values():
            for image, version in image_refs(text):
                versions.setdefault(image, set()).add(version)
        return versions

    def level(self, before: set[str], after: set[str]) -> str:
        if before == after:
            return "none"
        if {tag_of(v) for v in before} == {tag_of(v) for v in after}:
            return "digest"
        suffixes = {(tag_parts(v) or ((), v))[1] for v in before | after}
        if len(suffixes) > 1:
            return "major"  # another variant (e.g. -alpine) or an unparsable tag
        return max_level([super().level({tag_of(v) for v in before}, {tag_of(v) for v in after})])

    def source(self, context: dict) -> Source:
        return trivy_source()

    def replay(self, root: Path, pins: list[tuple[str, str]]) -> None:
        targets = dict(pins)
        done: set[str] = set()
        for directory in owned_dirs(self, root):
            for path in directory.iterdir():
                if not (path.is_file() and self.owns(path.name)):
                    continue
                lines = path.read_text().splitlines(keepends=True)
                for index, line in enumerate(lines):
                    match = FROM.match(line) or COPY_FROM.match(line)
                    parsed = split_ref(match["ref"]) if match else None
                    if parsed and parsed[0] in targets:
                        version = targets[parsed[0]]
                        new_ref = f"{parsed[0]}{version}" if version.startswith("@") else f"{parsed[0]}:{version}"
                        lines[index] = line.replace(match["ref"], new_ref, 1)
                        done.add(parsed[0])
                path.write_text("".join(lines))
        missing = set(targets) - done
        if missing:
            raise ReplayError(f"No Dockerfile line uses {', '.join(sorted(missing))}")

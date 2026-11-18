"""Version parsing, ordering and update levels for every supported ecosystem."""

from __future__ import annotations

import re
from collections.abc import Callable

UPDATE_LEVELS = {"none": 0, "digest": 1, "patch": 2, "minor": 3, "major": 4}

ReleaseFn = Callable[[str], tuple[int, ...] | None]
KeyFn = Callable[[str], tuple]

PEP440 = re.compile(
    r"""^\s*v?
    (?:(?P<epoch>\d+)!)?
    (?P<release>\d+(?:\.\d+)*)
    (?:[-_.]?(?P<pre_l>alpha|beta|preview|pre|rc|a|b|c)[-_.]?(?P<pre_n>\d+)?)?
    (?:-(?P<post_n1>\d+)|[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>\d+)?)?
    (?:[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>\d+)?)?
    \s*$""",
    re.VERBOSE | re.IGNORECASE,
)
PRE_ORDER = {
    "a": 0,
    "alpha": 0,
    "b": 1,
    "beta": 1,
    "c": 2,
    "rc": 2,
    "pre": 2,
    "preview": 2,
}


def parse_version(version: str) -> tuple | None:
    """PEP 440 ordering key (epoch, release, pre, post, dev), or None for an unsupported version.

    Local versions (`1.0+cu121`) are not published on PyPI and are left unsupported, so they
    take the conservative path (major update, never picked as a fix).
    """
    match = PEP440.match(version)
    if not match:
        return None
    release = [int(part) for part in match["release"].split(".")]
    while len(release) > 1 and release[-1] == 0:
        release.pop()
    has_post = match["post_n1"] is not None or match["post_l"] is not None
    has_dev = match["dev_l"] is not None
    if match["pre_l"]:
        pre = (PRE_ORDER[match["pre_l"].lower()], int(match["pre_n"] or 0))
    elif has_dev and not has_post:
        pre = (-1, 0)  # 1.0.dev1 sorts before 1.0a1
    else:
        pre = (3, 0)
    post = int(match["post_n1"] or match["post_n2"] or 0) if has_post else -1
    dev = (0, int(match["dev_n"] or 0)) if has_dev else (1, 0)
    return int(match["epoch"] or 0), tuple(release), pre, post, dev


def version_key(version: str) -> tuple:
    """Total PEP 440 order; unsupported versions sort first and are never picked as fixes."""
    parsed = parse_version(version)
    return (1, parsed) if parsed else (0, version)


def release(version: str) -> tuple[int, ...] | None:
    """(epoch, major, minor, patch) of a PEP 440 version, for comparing release lines."""
    match = PEP440.match(version)
    if not match:
        return None
    numbers = [int(part) for part in match["release"].split(".")] + [0, 0]
    return int(match["epoch"] or 0), *numbers[:3]


# Semver and the loose versions of upstream projects: 1.2.3, v1.25.1, 2.1-20250826, 2.1.0.19,
# 1.2.3-rc.1. Numbers joined by "-" stay in the release (luajit's 2.1-<date>).
LOOSE = re.compile(
    r"^\s*v?(?P<release>\d+(?:[.-]\d+)*)(?:[-.]?(?P<pre>[A-Za-z][0-9A-Za-z.-]*))?(?:\+[0-9A-Za-z.-]+)?\s*$"
)


def parse_loose(version: str) -> tuple | None:
    match = LOOSE.match(version)
    if not match:
        return None
    numbers = [int(part) for part in re.split(r"[.-]", match["release"])]
    while len(numbers) > 1 and numbers[-1] == 0:
        numbers.pop()
    if match["pre"]:
        pre = (0, tuple(
            (0, int(part), "") if part.isdigit() else (1, 0, part.lower())
            for part in re.split(r"[.-]", match["pre"])
        ))
    else:
        pre = (1, ())
    return tuple(numbers), pre


def loose_key(version: str) -> tuple:
    parsed = parse_loose(version)
    return (1, parsed) if parsed else (0, version)


def loose_release(version: str) -> tuple[int, ...] | None:
    match = LOOSE.match(version)
    if not match:
        return None
    numbers = [int(part) for part in re.split(r"[.-]", match["release"])] + [0, 0]
    return 0, *numbers[:3]


# npm versions: any "-" suffix is a prerelease (1.2.3-1 comes before 1.2.3), unlike LOOSE.
SEMVER = re.compile(
    r"^\s*v?(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)(?:-(?P<pre>[0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?\s*$"
)


def semver_key(version: str) -> tuple:
    match = SEMVER.match(version)
    if not match:
        return (0, version)
    numbers = (int(match["major"]), int(match["minor"]), int(match["patch"]))
    if match["pre"]:
        pre = (0, tuple(
            (0, int(part), "") if part.isdigit() else (1, 0, part)
            for part in match["pre"].split(".")
        ))
    else:
        pre = (1, ())
    return 1, numbers, pre


def semver_release(version: str) -> tuple[int, ...] | None:
    match = SEMVER.match(version)
    if not match:
        return None
    return 0, int(match["major"]), int(match["minor"]), int(match["patch"])


def package_level(
    before: set[str],
    after: set[str],
    release_fn: ReleaseFn = release,
    key_fn: KeyFn = version_key,
) -> str:
    """Update level of one package across all its locked versions.

    patch: every release line (epoch, major, minor) is kept and only moves forward;
    minor: a line is added, dropped or replaced within the same majors, or moves backward;
    major: the set of majors changes, or a version cannot be parsed.
    """
    if before == after:
        return "none"
    if not before or not after:
        return "minor"
    releases = {version: release_fn(version) for version in before | after}
    if None in releases.values():
        return "major"
    lines_before = {releases[v][:3]: v for v in before}
    lines_after = {releases[v][:3]: v for v in after}
    if len(lines_before) != len(before) or len(lines_after) != len(after):
        return "minor"
    if lines_before.keys() == lines_after.keys():
        forward = all(
            key_fn(lines_after[line]) >= key_fn(lines_before[line])
            for line in lines_before
        )
        return "patch" if forward else "minor"
    majors_before = {line[:2] for line in lines_before}
    majors_after = {line[:2] for line in lines_after}
    return "minor" if majors_before == majors_after else "major"


def max_level(levels: list[str]) -> str:
    return max(["none", *levels], key=UPDATE_LEVELS.__getitem__)

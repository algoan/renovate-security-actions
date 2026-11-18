"""Score the vulnerabilities fixed by a Renovate PR and pick its routing tier.

Tiers:
  hotfix    max CVSS >= the hotfix threshold, when the hotfix flow is enabled
  automerge max CVSS >= the automerge threshold (critical fixes too when hotfix is disabled)
  manual    a security fix below the automerge threshold (or with no known score)
  none      not a security fix
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .advisories import Advisory, ScanFailed, Source, Unscored
from .ecosystems import Ecosystem, Versions
from .versions import KeyFn, max_level, version_key

CRITICAL_SCORE = 9.0
MAX_CVSS = 10.0

# (ecosystem, package, removed versions, every version left in the new files)
Change = tuple[str, str, tuple[str, ...], tuple[str, ...]]


@dataclass
class PackageFix:
    name: str
    old: str
    new: str
    advisories: list[Advisory] = field(default_factory=list)
    minimal: str | None = None
    ecosystem: str = "uv"


@dataclass
class Triage:
    tier: str
    max_cvss: float | None
    fixes: list[PackageFix]
    update_level: str = "none"
    critical: bool = False
    hotfix_enabled: bool = True
    pin_only: bool = False
    unscored: list[str] = field(default_factory=list)
    # Dependencies whose source failed: their fixes are unknown.
    scan_failures: list[str] = field(default_factory=list)
    # Changes without a fixed advisory that a hotfix replays too (whole-PR ecosystems).
    companions: list[PackageFix] = field(default_factory=list)
    # Other changes without a fixed advisory: not replayed, but part of what the PR locks.
    unrelated: list[PackageFix] = field(default_factory=list)
    # Changed files no selected ecosystem scores (e.g. a GitHub Actions workflow).
    outside: list[str] = field(default_factory=list)


def changed_packages(old: Versions, new: Versions) -> list[tuple[str, tuple[str, ...], tuple[str, ...]]]:
    """(name, removed versions, every version left in the new files) per updated or dropped package."""
    return sorted(
        (
            name,
            tuple(sorted(versions - new.get(name, set()))),
            tuple(sorted(new.get(name, set()))),
        )
        for name, versions in old.items()
        if versions - new.get(name, set())
    )


def fixed_advisories(
    name: str, old: tuple[str, ...], new: tuple[str, ...], fetch: Source
) -> list[Advisory]:
    still_affected = {adv.id for version in new for adv in fetch(name, version)}
    fixed = {
        adv.id: adv
        for version in old
        for adv in fetch(name, version)
        if adv.id not in still_affected
    }
    return list(fixed.values())


def minimal_fix(
    name: str,
    locked: str,
    advisories: list[Advisory],
    fallback: str,
    fetch: Source,
    key: KeyFn = version_key,
) -> str:
    """Smallest version above the locked one fixing every advisory, backports included.

    Each advisory lists its first patched version per release line (e.g. 2.52.2 and 2.56.0):
    take the lowest one above the locked version, then the highest across advisories, and
    check that none of the advisories still affects it. Falls back to Renovate's version
    otherwise.
    """
    def supported(version: str) -> bool:
        return key(version)[0] == 1

    if not supported(locked):
        return fallback
    lowest_fixes = []
    for adv in advisories:
        above = [v for v in adv.patched if supported(v) and key(v) > key(locked)]
        if above:
            lowest_fixes.append(min(above, key=key))
    if not lowest_fixes:
        return fallback
    # Advisories without a patched version are covered by the database check below.
    target = max(lowest_fixes, key=key)
    fixed_ids = {adv.id for adv in advisories}
    if any(adv.id in fixed_ids for adv in fetch(name, target)):
        return fallback
    return target


def compute_tier(
    max_cvss: float | None,
    is_security: bool,
    hotfix: float,
    automerge: float,
    hotfix_enabled: bool = True,
) -> str:
    if hotfix_enabled and max_cvss is not None and max_cvss >= hotfix:
        return "hotfix"
    if max_cvss is not None and max_cvss >= automerge:
        return "automerge"
    return "manual" if is_security else "none"


def triage(
    changes: list[Change],
    sources: dict[str, Source],
    ecosystems: dict[str, Ecosystem],
    has_security_label: bool,
    hotfix_threshold: float,
    automerge_threshold: float,
    hotfix_enabled: bool = True,
    outside: list[str] | None = None,
) -> Triage:
    fixes: list[PackageFix] = []
    companions: list[PackageFix] = []
    unrelated: list[PackageFix] = []
    unscored: list[str] = []
    scan_failures: list[str] = []
    # Batched lookups first where the source supports them (GitHub Advisory Database): a
    # lockfile-maintenance PR would otherwise spend one request per old and new version.
    for eco_name, source in sources.items():
        prefetch = getattr(source, "prefetch", None)
        if prefetch:
            prefetch(
                (name, version)
                for eco, name, old, new in changes
                if eco == eco_name
                for version in (*old, *new)
            )
    for eco_name, name, old, new in changes:
        ecosystem = ecosystems[eco_name]
        fix = PackageFix(name, ", ".join(old), ", ".join(new) or "removed", ecosystem=eco_name)
        try:
            fix.advisories = fixed_advisories(name, old, new, sources[eco_name])
        except Unscored as reason:
            unscored.append(f"`{name}`: {reason}")
            if isinstance(reason, ScanFailed):
                scan_failures.append(name)
        if not fix.advisories:
            (companions if ecosystem.replay_whole_pr else unrelated).append(fix)
            continue
        fixes.append(fix)
        if (
            ecosystem.has_patched_versions
            and not ecosystem.replay_whole_pr
            and fix.new != "removed"
            and "," not in fix.old + fix.new
        ):
            try:
                fix.minimal = minimal_fix(
                    name, fix.old, fix.advisories, fix.new, sources[eco_name], ecosystem.key_fn
                )
            except Unscored as reason:
                # Its first patched version wasn't prefetched (e.g. a rate limit came first). The
                # fixes are known: only a hotfix replay would take Renovate's version instead.
                unscored.append(f"`{name}`: smallest fix unknown, a hotfix would use {fix.new} ({reason})")
    scores = [adv.score for fix in fixes for adv in fix.advisories if adv.score is not None]
    max_cvss = max(scores) if scores else None
    is_security = has_security_label or bool(fixes)
    tier = compute_tier(max_cvss, is_security, hotfix_threshold, automerge_threshold, hotfix_enabled)
    # An advisory without any score may be worse than the scored ones: no automatic merge.
    if tier == "automerge" and any(adv.score is None for fix in fixes for adv in fix.advisories):
        tier = "manual"
    return Triage(
        tier=tier,
        max_cvss=max_cvss,
        fixes=fixes,
        critical=max_cvss is not None and max_cvss >= CRITICAL_SCORE,
        # A threshold above the maximum CVSS is the other way to turn the hotfix flow off.
        hotfix_enabled=hotfix_enabled and hotfix_threshold <= MAX_CVSS,
        # A fix in files the triage doesn't score (e.g. an action) is not a pin.
        pin_only=is_security and not changes and not outside,
        unscored=unscored,
        scan_failures=scan_failures,
        companions=companions if fixes else [],
        unrelated=unrelated,
        outside=list(outside or []),
    )


def update_level(
    old: dict[str, Versions], new: dict[str, Versions], ecosystems: dict[str, Ecosystem]
) -> str:
    """Biggest update level across every dependency of every ecosystem."""
    levels = []
    for eco_name, ecosystem in ecosystems.items():
        before, after = old.get(eco_name, {}), new.get(eco_name, {})
        levels += [
            ecosystem.level(before.get(name, set()), after.get(name, set()))
            for name in before.keys() | after.keys()
        ]
    return max_level(levels)


MAX_ROWS = 20
MAX_FILES = 5
DIGEST = re.compile(r"@sha256:([0-9a-f]{12})[0-9a-f]+")


def short(version: str) -> str:
    """Shorten image digests, which make the table unreadable."""
    return DIGEST.sub(r"@sha256:\1…", version)


def code(text: str) -> str:
    """A Markdown code span the text cannot close: its fence is longer than any backtick run in it.

    Line breaks are escaped: a blank line would end the span and the paragraph.
    """
    text = text.replace("\r", "\\r").replace("\n", "\\n")
    fence = "`" * (max(map(len, re.findall(r"`+", text)), default=0) + 1)
    pad = " " if text.startswith("`") or text.endswith("`") else ""
    return f"{fence}{pad}{text}{pad}{fence}"


def render_markdown(result: Triage, hotfix_threshold: float, automerge_threshold: float) -> str:
    score = f"{result.max_cvss:.1f}" if result.max_cvss is not None else "unknown"
    automerge = "merged automatically once CI is green if it only bumps patch versions, otherwise one human review"
    decision = {
        "hotfix": f"🚨 **Hotfix** (CVSS ≥ {hotfix_threshold}): a hotfix PR applying only this fix on top of the production commit is opened, and merging it promotes to production. This PR brings the fix to main (one human review).",
        "automerge": (
            f"🚨 **Critical, hotfix flow disabled**: the fix ships through main, {automerge}. Promote it to production quickly."
            if result.critical and not result.hotfix_enabled
            else f"🤖 **Automerge** (CVSS ≥ {automerge_threshold}): {automerge}."
        ),
        "manual": "👀 **Manual review**: one human review is required.",
        "none": "No security fix detected.",
    }[result.tier]
    lines = [f"**Max CVSS:** {score}", "", decision]
    if result.pin_only:
        lines += [
            "",
            "ℹ️ **Pin only**: no locked version changes, this PR only pins the declared range. If the locked version is still vulnerable, Renovate opens the actual fix once this PR is merged.",
        ]
    if result.outside:
        # File names come from the PR: a backtick in one must not end its code span.
        shown = ", ".join(code(path) for path in result.outside[:MAX_FILES])
        more = len(result.outside) - MAX_FILES
        lines += [
            "",
            f"ℹ️ **Outside the scored ecosystems**: {shown}{f' and {more} more' if more > 0 else ''}. "
            "Vulnerabilities fixed there (e.g. in GitHub Actions) are not scored.",
        ]
    if result.update_level in ("minor", "major"):
        lines += [
            "",
            f"⚠️ **{result.update_level.capitalize()} version jump**: check the changelog, this is more than a patch.",
        ]
    if result.fixes:
        lines += [
            "",
            "| Package | Update | Advisory | Severity | CVSS |",
            "|---|---|---|---|---|",
        ]
        rows = sorted(
            ((fix, adv) for fix in result.fixes for adv in fix.advisories),
            key=lambda row: row[1].score or 0,
            reverse=True,
        )
        for fix, adv in rows[:MAX_ROWS]:
            ident = f"[{adv.id}]({adv.url})" + (
                f" / {adv.cve_id}" if adv.cve_id and adv.cve_id != adv.id else ""
            )
            cvss = f"{adv.score:.1f}" if adv.score is not None else "n/a"
            lines.append(
                f"| `{fix.name}` | {short(fix.old)} → {short(fix.new)} | {ident} | {adv.severity} | {cvss} |"
            )
        if len(rows) > MAX_ROWS:
            lines += ["", f"…and {len(rows) - MAX_ROWS} more advisories with a lower score."]
    if result.unscored:
        # A rate limit can leave every package of a lockfile-maintenance PR unscored.
        lines += ["", "**Not scored:**", *[f"- {item}" for item in result.unscored[:MAX_ROWS]]]
        if len(result.unscored) > MAX_ROWS:
            lines.append(f"- …and {len(result.unscored) - MAX_ROWS} more")
    return "\n".join(lines)


def frozen_changes(
    old: dict[str, Versions], new: dict[str, Versions], frozen: set[str]
) -> list[str]:
    """Dependencies that must not change at all in a hotfix (e.g. ray, tied to rayVersion in k8s/)."""
    changed = set()
    for eco_name in old.keys() | new.keys():
        before, after = old.get(eco_name, {}), new.get(eco_name, {})
        changed.update(n for n in frozen if before.get(n, set()) != after.get(n, set()))
    return sorted(changed)


def pin(fix: PackageFix, version: str) -> str:
    return f"{fix.ecosystem}:{fix.name}=={version}"


def parse_pin(value: str) -> tuple[str, str, str]:
    """(ecosystem, name, version) of an `ecosystem:name==version` pin."""
    ecosystem, _, rest = value.partition(":")
    name, _, version = rest.partition("==")
    return ecosystem, name, version


def pr_pins(result: Triage) -> list[str] | None:
    """Pins of every version the PR locks, or None if not a plain bump."""
    pins = []
    for fix in result.fixes + result.companions + result.unrelated:
        if fix.new == "removed" or "," in fix.new:
            return None
        pins.append(pin(fix, fix.new))
    return pins or None


def hotfix_pins(result: Triage) -> list[str] | None:
    """Pins replaying the fix on another commit, or None if it cannot be replayed."""
    pins = []
    for fix in result.fixes + result.companions:
        if fix.new == "removed" or "," in fix.new:
            return None
        pins.append(pin(fix, fix.minimal or fix.new))
    return pins or None

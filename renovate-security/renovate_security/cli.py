"""Command line entry point: `python -m renovate_security <command>`.

triage      score a diff (Renovate PR, hotfix, promotion candidate) and pick its tier
replay      apply `ecosystem:name==version` pins to the current checkout (hotfix)
check-diff  fail if a diff touches files no replayed ecosystem owns
"""

from __future__ import annotations

import argparse
import json
import math
import os
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path

from .ecosystems import ECOSYSTEMS, Ecosystem, ReplayError, Versions, select
from .triage import (
    changed_packages,
    frozen_changes,
    hotfix_pins,
    parse_pin,
    pr_pins,
    render_markdown,
    triage,
    update_level,
)

EXIT_FROZEN = 3
EXIT_REPLAY = 4
EXIT_SCAN_FAILED = 5


def git(*args: str) -> str:
    return subprocess.run(["git", *args], capture_output=True, text=True, check=True).stdout


def git_show(ref: str, path: str) -> str:
    result = subprocess.run(
        ["git", "show", f"{ref}:{path}"], capture_output=True, text=True, check=False
    )
    return result.stdout if result.returncode == 0 else ""


def tracked_paths(ref: str, directory: str) -> list[str]:
    paths = git("ls-tree", "-r", "--name-only", ref).splitlines()
    prefix = directory.strip("/")
    return [p for p in paths if not prefix or p == prefix or p.startswith(prefix + "/")]


def read_versions(ecosystem: Ecosystem, ref: str, paths: list[str]) -> Versions:
    return ecosystem.parse({p: git_show(ref, p) for p in paths if ecosystem.owns(p)})


def outside_files(changed: list[str], ecosystems: list[Ecosystem], directory: str) -> list[str]:
    """Changed files that no selected ecosystem scores: other managers, or outside `directory`."""
    prefix = directory.strip("/")
    return sorted(
        path
        for path in changed
        if (prefix and path != prefix and not path.startswith(prefix + "/"))
        or not any(ecosystem.allows(path) for ecosystem in ecosystems)
    )


def write_github_output(values: dict[str, str]) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    if path:
        with open(path, "a") as handle:
            handle.writelines(f"{key}={value}\n" for key, value in values.items())


def flag(value: str) -> bool:
    if value.lower() not in ("true", "false"):
        raise argparse.ArgumentTypeError("expected true or false")
    return value.lower() == "true"


def threshold(value: str) -> float:
    """A CVSS threshold; above 10 is allowed and means "never" (e.g. hotfix flow off)."""
    number = float(value)
    if math.isnan(number) or number < 0:
        raise argparse.ArgumentTypeError(f"invalid CVSS threshold {value!r}")
    return number


def cmd_triage(args: argparse.Namespace) -> int:
    base = args.base if args.direct else git("merge-base", args.base, args.head).strip()
    base_paths = tracked_paths(base, args.lockfile_dir)
    head_paths = tracked_paths(args.head, args.lockfile_dir)
    ecosystems = {e.name: e for e in select(args.ecosystems, base_paths + head_paths)}

    old = {n: read_versions(e, base, base_paths) for n, e in ecosystems.items()}
    new = {n: read_versions(e, args.head, head_paths) for n, e in ecosystems.items()}
    frozen = frozen_changes(old, new, {n.strip() for n in args.frozen.split(",") if n.strip()})
    if frozen:
        print(f"::error::Frozen dependencies changed: {', '.join(frozen)}")
        return EXIT_FROZEN

    changes = [
        (eco_name, name, removed, kept)
        for eco_name in ecosystems
        for name, removed, kept in changed_packages(old[eco_name], new[eco_name])
    ]
    context = {
        "github_token": os.environ.get("GITHUB_TOKEN", ""),
        "nvd_api_key": os.environ.get("NVD_API_KEY", ""),
        "upstream_cpes": os.environ.get("UPSTREAM_CPES", ""),
    }
    sources = {
        eco_name: ecosystems[eco_name].source(context)
        for eco_name in {change[0] for change in changes}
    }
    result = triage(
        changes,
        sources,
        ecosystems,
        args.security_label,
        args.hotfix_threshold,
        args.automerge_threshold,
        args.hotfix_enabled,
        outside_files(
            # NUL-separated: git would quote names with non-ASCII characters otherwise.
            [path for path in git("diff", "--name-only", "-z", base, args.head).split("\0") if path],
            list(ecosystems.values()),
            args.lockfile_dir,
        ),
    )
    result.update_level = update_level(old, new, ecosystems)

    with open(args.out, "w") as handle:
        json.dump(asdict(result), handle, indent=2)
    with open(args.markdown, "w") as handle:
        handle.write(render_markdown(result, args.hotfix_threshold, args.automerge_threshold))
    write_github_output(
        {
            "tier": result.tier,
            "max_cvss": "" if result.max_cvss is None else f"{result.max_cvss:.1f}",
            "critical": str(result.critical).lower(),
            "hotfix_pins": " ".join(hotfix_pins(result) or []),
            "pr_pins": " ".join(pr_pins(result) or []),
            "update_level": result.update_level,
            "ecosystems": ",".join(sorted({c[0] for c in changes})),
        }
    )
    for item in result.unscored:
        print(f"::notice title=Not scored::{item}")
    print(
        f"tier={result.tier} max_cvss={result.max_cvss} update={result.update_level} "
        f"packages={[fix.name for fix in result.fixes]}"
    )
    if args.fail_on_scan_failure and result.scan_failures:
        print(f"::error::Could not score {', '.join(result.scan_failures)}: their fixes are unknown")
        return EXIT_SCAN_FAILED
    return 0


def group_pins(values: list[str]) -> dict[str, list[tuple[str, str]]]:
    grouped: dict[str, list[tuple[str, str]]] = {}
    for value in values:
        ecosystem, name, version = parse_pin(value)
        if ecosystem not in ECOSYSTEMS or not name or not version:
            raise ReplayError(f"Invalid pin {value!r}, expected ecosystem:name==version")
        grouped.setdefault(ecosystem, []).append((name, version))
    return grouped


def cmd_replay(args: argparse.Namespace) -> int:
    try:
        grouped = group_pins(args.pins.split())
        if not grouped:
            raise ReplayError("Nothing to replay")
        for ecosystem, pins in grouped.items():
            ECOSYSTEMS[ecosystem]().replay(Path(args.root, args.lockfile_dir).resolve(), pins)
    except ReplayError as error:
        print(f"::error::{error}")
        return EXIT_REPLAY
    return 0


def cmd_check_diff(args: argparse.Namespace) -> int:
    """Files changed between two commits must belong to the ecosystems of the pins."""
    try:
        ecosystems = [ECOSYSTEMS[name]() for name in group_pins(args.pins.split())]
    except ReplayError as error:
        print(f"::error::{error}")
        return 1
    changed = git("diff", "--name-only", args.base, args.head).splitlines()
    scope = args.lockfile_dir.strip("/")
    unexpected = [
        path
        for path in changed
        if (scope and not path.startswith(scope + "/"))
        or not any(e.allows(path) for e in ecosystems)
    ]
    if unexpected:
        print(f"::error::Unexpected files changed: {', '.join(unexpected)}")
        return 1
    print(f"Changed files: {', '.join(changed) or 'none'}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="renovate_security", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)

    scoring = commands.add_parser("triage", help="score a diff and pick its tier")
    scoring.add_argument("--base", required=True)
    scoring.add_argument("--head", required=True)
    scoring.add_argument("--security-label", action="store_true")
    scoring.add_argument("--out", default="triage.json")
    scoring.add_argument("--markdown", default="triage.md")
    scoring.add_argument(
        "--direct",
        action="store_true",
        help="Compare --base and --head directly instead of from their merge base",
    )
    scoring.add_argument(
        "--frozen", default="", help="Comma-separated dependencies that must not change: exit 3 if they do"
    )
    scoring.add_argument("--ecosystems", default="auto", help=f"auto or a list of: {', '.join(ECOSYSTEMS)}")
    scoring.add_argument("--lockfile-dir", default="", help="Only read files under this directory")
    scoring.add_argument(
        "--hotfix-threshold", type=threshold,
        default=threshold(os.environ.get("CVSS_HOTFIX_THRESHOLD") or "9.0"),
        help="Above 10, no score reaches it: the hotfix tier is disabled",
    )
    scoring.add_argument(
        "--automerge-threshold", type=threshold,
        default=threshold(os.environ.get("CVSS_AUTOMERGE_THRESHOLD") or "4.0"),
    )
    scoring.add_argument("--hotfix-enabled", type=flag, default=True)
    scoring.add_argument(
        "--fail-on-scan-failure",
        action="store_true",
        help="Exit 5 when a source fails (Trivy, NVD): a guard must not pass on an unknown score",
    )
    scoring.set_defaults(handler=cmd_triage)

    replaying = commands.add_parser("replay", help="apply pins to the checkout")
    replaying.add_argument("--pins", required=True, help="Space-separated ecosystem:name==version")
    replaying.add_argument("--root", default=".")
    replaying.add_argument("--lockfile-dir", default="", help="Same scope as the triage")
    replaying.set_defaults(handler=cmd_replay)

    checking = commands.add_parser("check-diff", help="only files of the pinned ecosystems changed")
    checking.add_argument("--base", required=True)
    checking.add_argument("--head", required=True)
    checking.add_argument("--pins", required=True)
    checking.add_argument("--lockfile-dir", default="", help="Reject changes outside this directory")
    checking.set_defaults(handler=cmd_check_diff)

    args = parser.parse_args(argv)
    return args.handler(args)


if __name__ == "__main__":
    sys.exit(main())

import pytest

from renovate_security.advisories import Advisory, advisory_score, next_page, to_advisory
from renovate_security.ecosystems import Uv
from renovate_security.ecosystems.python import parse_toml_lock as parse_lock
from renovate_security.triage import (
    PackageFix,
    Triage,
    changed_packages,
    compute_tier,
    fixed_advisories,
    frozen_changes,
    hotfix_pins,
    minimal_fix,
    pr_pins,
    render_markdown,
)
from renovate_security.triage import triage as run_triage
from renovate_security.triage import update_level as eco_update_level
from renovate_security.versions import package_level, parse_version, version_key

UV = {"uv": Uv()}


def triage(changes, fetch, has_security_label, hotfix_threshold, automerge_threshold, hotfix_enabled=True):
    return run_triage(
        [("uv", *change) for change in changes],
        {"uv": fetch},
        UV,
        has_security_label,
        hotfix_threshold,
        automerge_threshold,
        hotfix_enabled,
    )


def update_level(old, new):
    return eco_update_level({"uv": old}, {"uv": new}, UV)


OLD_LOCK = """
version = 1

[[package]]
name = "jinja2"
version = "3.1.2"

[[package]]
name = "numpy"
version = "2.4.4"

[[package]]
name = "ray-serve-models"
source = { editable = "." }
"""

NEW_LOCK = OLD_LOCK.replace('version = "3.1.2"', 'version = "3.1.6"').replace(
    '"2.4.4"', '"2.4.5"'
)


def raw_advisory(ghsa_id, v3=None, v4=None, severity="medium"):
    return {
        "ghsa_id": ghsa_id,
        "cve_id": f"CVE-{ghsa_id}",
        "summary": "summary",
        "html_url": f"https://github.com/advisories/{ghsa_id}",
        "severity": severity,
        "cvss_severities": {"cvss_v3": {"score": v3}, "cvss_v4": {"score": v4}},
    }


def fetcher(advisories):
    return lambda name, version: [
        to_advisory(raw, name) for raw in advisories.get((name, version), [])
    ]


def test_changed_packages_ignores_unversioned_and_unchanged():
    changes = changed_packages(
        parse_lock(OLD_LOCK), parse_lock(NEW_LOCK)
    )
    assert changes == [
        ("jinja2", ("3.1.2",), ("3.1.6",)),
        ("numpy", ("2.4.4",), ("2.4.5",)),
    ]


MULTI_OLD_LOCK = """
[[package]]
name = "numba"
version = "0.53.1"

[[package]]
name = "numba"
version = "0.66.0"
"""


def test_changed_packages_keeps_every_locked_version():
    old = parse_lock(MULTI_OLD_LOCK)
    new = parse_lock(MULTI_OLD_LOCK.replace("0.53.1", "0.54.0"))
    assert changed_packages(old, new) == [
        ("numba", ("0.53.1",), ("0.54.0", "0.66.0"))
    ]


def test_advisory_still_affecting_another_locked_version_is_not_fixed():
    fetch = fetcher(
        {
            ("numba", "0.53.1"): [
                raw_advisory("SHARED", v3=9.8),
                raw_advisory("OLD_ONLY", v3=5.0),
            ],
            ("numba", "0.66.0"): [raw_advisory("SHARED", v3=9.8)],
        }
    )
    advisories = fixed_advisories(
        "numba", ("0.53.1",), ("0.54.0", "0.66.0"), fetch
    )
    assert [adv.id for adv in advisories] == ["OLD_ONLY"]


def test_parse_lock_handles_missing_file():
    assert parse_lock("") == {}


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (raw_advisory("A", v3=7.8, v4=5.4), 7.8),
        (raw_advisory("A", v3=0, v4=9.3), 9.3),
        (raw_advisory("A", severity="critical"), 9.0),
        ({**raw_advisory("A"), "cvss_severities": None, "cvss": {"score": 6.1}}, 6.1),
        (raw_advisory("A", severity="unknown"), None),
    ],
)
def test_advisory_score(raw, expected):
    assert advisory_score(raw) == expected


def test_only_advisories_fixed_by_the_new_version_are_kept():
    fetch = fetcher(
        {
            ("jinja2", "3.1.2"): [
                raw_advisory("FIXED", v3=8.8),
                raw_advisory("STILL", v3=9.8),
            ],
            ("jinja2", "3.1.6"): [raw_advisory("STILL", v3=9.8)],
        }
    )
    advisories = fixed_advisories("jinja2", ("3.1.2",), ("3.1.6",), fetch)
    assert [adv.id for adv in advisories] == ["FIXED"]


@pytest.mark.parametrize(
    ("max_cvss", "is_security", "expected"),
    [
        (9.0, True, "hotfix"),
        (8.9, True, "automerge"),
        (4.0, True, "automerge"),
        (3.9, True, "manual"),
        (None, True, "manual"),
        (None, False, "none"),
    ],
)
def test_compute_tier_boundaries(max_cvss, is_security, expected):
    assert (
        compute_tier(max_cvss, is_security, hotfix=9.0, automerge=4.0)
        == expected
    )


def test_triage_uses_the_highest_fixed_score():
    fetch = fetcher(
        {
            ("jinja2", "3.1.2"): [raw_advisory("A", v3=5.4), raw_advisory("B", v3=9.1)],
            ("numpy", "2.4.4"): [raw_advisory("C", v3=4.2)],
        }
    )
    changes = [("jinja2", ("3.1.2",), ("3.1.6",)), ("numpy", ("2.4.4",), ("2.4.5",))]
    result = triage(
        changes,
        fetch,
        has_security_label=False,
        hotfix_threshold=9.0,
        automerge_threshold=4.0,
    )
    assert result.tier == "hotfix"
    assert result.max_cvss == 9.1
    assert [fix.name for fix in result.fixes] == ["jinja2", "numpy"]


def test_triage_without_fix_depends_on_security_label():
    changes = [("numpy", ("2.4.4",), ("2.4.5",))]
    assert triage(changes, fetcher({}), False, 9.0, 4.0).tier == "none"
    assert triage(changes, fetcher({}), True, 9.0, 4.0).tier == "manual"


def test_render_markdown_lists_advisories():
    fetch = fetcher({("jinja2", "3.1.2"): [raw_advisory("GHSA-1", v3=7.5)]})
    result = triage(
        [("jinja2", ("3.1.2",), ("3.1.6",))], fetch, False, 9.0, 4.0
    )
    markdown = render_markdown(result, 9.0, 4.0)
    assert "**Max CVSS:** 7.5" in markdown
    assert "Automerge" in markdown
    assert (
        "| `jinja2` | 3.1.2 → 3.1.6 | [GHSA-1](https://github.com/advisories/GHSA-1) / CVE-GHSA-1 | medium | 7.5 |"
        in markdown
    )


def test_dropped_package_fixes_all_its_advisories():
    old = parse_lock(OLD_LOCK)
    new = parse_lock(
        OLD_LOCK.replace('name = "jinja2"\nversion = "3.1.2"\n', "")
    )
    changes = changed_packages(old, new)
    assert changes == [("jinja2", ("3.1.2",), ())]
    fetch = fetcher({("jinja2", "3.1.2"): [raw_advisory("CRIT", v3=9.8)]})
    result = triage(changes, fetch, False, 9.0, 4.0)
    assert result.tier == "hotfix"
    assert result.fixes[0].new == "removed"


def test_next_page_follows_the_link_header():
    header = '<https://api.github.com/advisories?after=abc>; rel="next", <https://api.github.com/advisories>; rel="first"'
    assert (
        next_page(header) == "https://api.github.com/advisories?after=abc"
    )
    assert (
        next_page('<https://api.github.com/advisories>; rel="prev"')
        is None
    )
    assert next_page(None) is None


def test_hotfix_pins():
    fix = PackageFix
    adv = [Advisory("A", None, "", "", "critical", 9.8)]
    result = Triage(
        "hotfix",
        9.8,
        [fix("jinja2", "3.1.2", "3.1.6", adv), fix("urllib3", "2.2.1", "2.2.2", adv)],
    )
    assert hotfix_pins(result) == ["uv:jinja2==3.1.6", "uv:urllib3==2.2.2"]


@pytest.mark.parametrize("new", ["removed", "0.54.0, 0.66.0"])
def test_hotfix_pins_cannot_replay_drops_or_split_versions(new):
    adv = [Advisory("A", None, "", "", "critical", 9.8)]
    result = Triage(
        "hotfix", 9.8, [PackageFix("numba", "0.53.1", new, adv)]
    )
    assert hotfix_pins(result) is None


@pytest.mark.parametrize(
    ("new_ray", "expected"),
    [
        ({"2.56.0"}, ["ray"]),
        ({"2.55.1", "2.56.0"}, ["ray"]),
        (set(), ["ray"]),
        ({"2.55.1"}, []),
    ],
)
def test_frozen_changes_compares_full_version_sets(new_ray, expected):
    old = {"ray": {"2.55.1"}, "jinja2": {"3.1.2"}}
    new = {"jinja2": {"3.1.6"}} | ({"ray": new_ray} if new_ray else {})
    assert frozen_changes({"uv": old}, {"uv": new}, {"ray"}) == expected


@pytest.mark.parametrize(
    ("lower", "higher"),
    [
        ("2.52.1", "2.52.2"),
        ("2.52.2", "2.56.0"),
        ("5.10.0rc1", "5.10.0"),
        ("1.9", "1.10"),
        ("2026.4.22", "2026.5.1"),
    ],
)
def test_version_key_orders_versions(lower, higher):
    assert version_key(lower) < version_key(higher)


@pytest.mark.parametrize(
    ("new", "level"),
    [
        ({"ray": {"2.52.2"}}, "patch"),
        ({"ray": {"2.56.0"}}, "minor"),
        ({"ray": {"3.0.0"}}, "major"),
        ({"ray": {"2.52.1"}, "mmh3": {"5.3.1"}}, "minor"),
        ({}, "minor"),
        ({"ray": {"2.52.1", "2.50.0"}}, "minor"),
        ({"ray": {"2.52.1.post1"}}, "patch"),
        ({"ray": {"not-a-version"}}, "major"),
        ({"ray": {"2.52.1"}}, "none"),
    ],
)
def test_update_level(new, level):
    assert update_level({"ray": {"2.52.1"}}, new) == level


def advisory_with_fixes(advisory_id, patched):
    return Advisory(advisory_id, None, "", "", "critical", 9.8, patched)


def test_minimal_fix_prefers_the_backport_of_the_locked_line():
    advisories = [advisory_with_fixes("A", ["2.56.0", "2.52.2"])]
    assert (
        minimal_fix("ray", "2.52.1", advisories, "2.59.0", fetcher({}))
        == "2.52.2"
    )


def test_minimal_fix_takes_the_highest_first_fix_across_advisories():
    advisories = [
        advisory_with_fixes("A", ["5.10.0"]),
        advisory_with_fixes("B", ["5.9.0"]),
    ]
    assert (
        minimal_fix(
            "transformers", "5.8.1", advisories, "5.19.0", fetcher({})
        )
        == "5.10.0"
    )


def test_minimal_fix_falls_back_when_unknown_or_still_affected():
    no_fix = [advisory_with_fixes("A", [])]
    assert (
        minimal_fix("x", "1.0.0", no_fix, "1.5.0", fetcher({})) == "1.5.0"
    )
    still = [advisory_with_fixes("A", ["1.1.0"])]
    fetch = fetcher({("x", "1.1.0"): [raw_advisory("A", v3=9.8)]})
    assert minimal_fix("x", "1.0.0", still, "1.5.0", fetch) == "1.5.0"


def test_advisory_keeps_first_patched_versions_of_its_package():
    raw = raw_advisory("A", v3=9.8) | {
        "vulnerabilities": [
            {"package": {"name": "Ray"}, "first_patched_version": "2.52.2"},
            {"package": {"name": "ray"}, "first_patched_version": "2.56.0"},
            {"package": {"name": "other"}, "first_patched_version": "9.9.9"},
            {"package": {"name": "ray"}, "first_patched_version": None},
        ]
    }
    assert to_advisory(raw, "ray").patched == ["2.52.2", "2.56.0"]


def test_hotfix_pins_use_the_minimal_fix():
    adv = [Advisory("A", None, "", "", "critical", 9.8)]
    fix = PackageFix("ray", "2.52.1", "2.59.0", adv, minimal="2.52.2")
    assert hotfix_pins(Triage("hotfix", 9.8, [fix])) == [
        "uv:ray==2.52.2"
    ]


def test_minimal_fix_covers_advisories_without_a_patched_version():
    partly = [advisory_with_fixes("A", []), advisory_with_fixes("B", ["1.2.0"])]
    assert (
        minimal_fix("x", "1.0.0", partly, "1.5.0", fetcher({})) == "1.2.0"
    )
    blocked = fetcher({("x", "1.2.0"): [raw_advisory("A", v3=9.8)]})
    assert minimal_fix("x", "1.0.0", partly, "1.5.0", blocked) == "1.5.0"


def test_version_key_treats_trailing_zeros_as_equal():
    assert version_key("1.0") == version_key("1.0.0")


def test_unsupported_versions_are_never_picked_as_minimal_fix():
    advisories = [advisory_with_fixes("A", ["not-a-version", "2.52.2"])]
    assert (
        minimal_fix("ray", "2.52.1", advisories, "2.59.0", fetcher({}))
        == "2.52.2"
    )
    assert (
        minimal_fix("ray", "weird", advisories, "2.59.0", fetcher({}))
        == "2.59.0"
    )


def test_pr_pins_keep_the_versions_the_pr_locks():
    adv = [Advisory("A", None, "", "", "critical", 9.8)]
    fix = PackageFix(
        "transformers", "5.8.1", "5.19.0", adv, minimal="5.10.0"
    )
    result = Triage("hotfix", 9.8, [fix])
    assert pr_pins(result) == ["uv:transformers==5.19.0"]
    assert hotfix_pins(result) == ["uv:transformers==5.10.0"]


def test_pr_pins_include_changes_the_hotfix_does_not_replay():
    adv = [Advisory("A", None, "", "", "critical", 9.8)]
    sources = {"uv": lambda name, version: adv if (name, version) == ("jinja2", "3.1.4") else []}
    changes = [("uv", "jinja2", ("3.1.4",), ("3.1.6",)), ("uv", "numpy", ("1.26.4",), ("2.2.0",))]
    result = run_triage(changes, sources, {"uv": Uv()}, False, 9.0, 4.0)
    assert hotfix_pins(result) == ["uv:jinja2==3.1.6"]
    assert pr_pins(result) == ["uv:jinja2==3.1.6", "uv:numpy==2.2.0"]


@pytest.mark.parametrize(
    ("before", "after", "level"),
    [
        ({"1.5.0", "2.0.0"}, {"1.5.1", "2.0.1"}, "patch"),
        ({"1.5.0", "2.0.0"}, {"1.6.0", "2.0.1"}, "minor"),
        ({"1.5.0", "2.0.0"}, {"1.5.0", "3.0.0"}, "major"),
        ({"2.52.3"}, {"2.52.1"}, "minor"),
        ({"2.52.1.post1"}, {"2.52.1"}, "minor"),
        ({"2.52.1"}, {"2.52.1"}, "none"),
    ],
)
def test_package_level_checks_every_release_line(before, after, level):
    assert package_level(before, after) == level


def test_local_versions_are_unsupported():
    assert parse_version("1.0+1") is None
    assert package_level({"1.0+2"}, {"1.0+1"}) == "major"
    advisories = [advisory_with_fixes("A", ["1.0+2", "1.1"])]
    assert (
        minimal_fix("x", "1.0", advisories, "1.5", fetcher({})) == "1.1"
    )


@pytest.mark.parametrize(
    ("hotfix", "enabled", "tier"),
    [(9.0, True, "hotfix"), (9.0, False, "automerge"), (11.0, True, "automerge"), (9.9, True, "automerge")],
)
def test_critical_fix_without_hotfix_flow_goes_to_automerge(hotfix, enabled, tier):
    fetch = fetcher({("jinja2", "3.1.2"): [raw_advisory("CRIT", v3=9.8)]})
    result = triage([("jinja2", ("3.1.2",), ("3.1.6",))], fetch, False, hotfix, 4.0, enabled)
    assert result.tier == tier
    assert result.critical


def test_render_markdown_flags_critical_fixes_shipped_through_main():
    fetch = fetcher({("jinja2", "3.1.2"): [raw_advisory("CRIT", v3=9.8)]})
    result = triage([("jinja2", ("3.1.2",), ("3.1.6",))], fetch, False, 9.0, 4.0, False)
    markdown = render_markdown(result, 9.0, 4.0)
    assert "Critical, hotfix flow disabled" in markdown
    assert "Hotfix**" not in markdown


def test_security_pr_without_locked_change_is_pin_only():
    result = triage([], fetcher({}), True, 9.0, 4.0)
    assert result.tier == "manual"
    assert result.pin_only
    assert "Pin only" in render_markdown(result, 9.0, 4.0)
    assert not triage([], fetcher({}), False, 9.0, 4.0).pin_only


def test_security_pr_changing_unscored_files_is_not_pin_only():
    outside = [".github/workflows/ci.yml", "a.yml", "b.yml", "c.yml", "d.yml", "e.yml"]
    result = run_triage([], {}, UV, True, 9.0, 4.0, outside=outside)
    assert result.tier == "manual"
    assert not result.pin_only
    markdown = render_markdown(result, 9.0, 4.0)
    assert "Pin only" not in markdown
    assert "`.github/workflows/ci.yml`" in markdown and "and 1 more" in markdown


def test_long_not_scored_lists_are_capped():
    from renovate_security.advisories import RateLimited

    def limited(name, version):
        raise RateLimited("GitHub API rate limit reached")

    changes = [(f"pkg{i}", ("1.0",), ("1.1",)) for i in range(25)]
    result = triage(changes, limited, True, 9.0, 4.0)
    assert len(result.scan_failures) == 25 and result.tier == "manual"
    markdown = render_markdown(result, 9.0, 4.0)
    assert markdown.count("rate limit reached") == 20 and "…and 5 more" in markdown


def test_triage_prefetches_every_version_of_the_changes():
    seen = []
    source = fetcher({})
    source.prefetch = seen.extend
    run_triage([("uv", "jinja2", ("3.1.2",), ("3.1.6",))], {"uv": source}, UV, False, 9.0, 4.0)
    assert seen == [("jinja2", "3.1.2"), ("jinja2", "3.1.6")]


def test_unscored_file_names_cannot_end_their_code_span():
    markdown = render_markdown(run_triage([], {}, UV, True, 9.0, 4.0, outside=["a`b.yml", "`c`"]), 9.0, 4.0)
    assert "``a`b.yml``" in markdown and "`` `c` ``" in markdown


def test_unscored_dependencies_are_reported_without_changing_the_tier():
    from renovate_security.advisories import Unscored
    from renovate_security.ecosystems import Upstream

    def nvd(name, version):
        if name == "openssl/openssl":
            return [Advisory("CVE-1", "CVE-1", "", "u", "high", 7.5, ["3.6.6"])] if version == "3.6.5" else []
        raise Unscored(f"no CPE known for {name}")

    result = run_triage(
        [
            ("upstream", "openssl/openssl", ("3.6.5",), ("3.6.6",)),
            ("upstream", "openresty/lua-resty-core", ("0.1.32",), ("0.1.33",)),
        ],
        {"upstream": nvd},
        {"upstream": Upstream()},
        False,
        9.0,
        4.0,
    )
    assert result.tier == "automerge"
    assert result.unscored == ["`openresty/lua-resty-core`: no CPE known for openresty/lua-resty-core"]
    # Upstream pins are replayed as a whole (paired modules), at the version the PR sets.
    assert hotfix_pins(result) == [
        "upstream:openssl/openssl==3.6.6",
        "upstream:openresty/lua-resty-core==0.1.33",
    ]
    assert "Not scored" in render_markdown(result, 9.0, 4.0)


def test_cve_ids_are_not_repeated_in_the_markdown():
    result = Triage(
        "automerge",
        7.5,
        [PackageFix("nginx", "1.31.6", "1.31.7", [Advisory("CVE-1", "CVE-1", "", "u", "high", 7.5)], ecosystem="upstream")],
    )
    assert "| [CVE-1](u) | high | 7.5 |" in render_markdown(result, 9.0, 4.0)


def test_render_markdown_shortens_digests_and_caps_rows():
    advisories = [Advisory(f"CVE-{i}", f"CVE-{i}", "", "u", "high", 5.0 + i / 10) for i in range(25)]
    old, new = "12.6.3-x@sha256:" + "a" * 64, "12.9.2-x@sha256:" + "b" * 64
    result = Triage("automerge", 7.4, [PackageFix("nvidia/cuda", old, new, advisories, ecosystem="docker")])
    markdown = render_markdown(result, 9.0, 4.0)
    assert "12.6.3-x@sha256:aaaaaaaaaaaa… → 12.9.2-x@sha256:bbbbbbbbbbbb…" in markdown
    assert markdown.count("| `nvidia/cuda` |") == 20
    assert "CVE-24" in markdown and "CVE-0)" not in markdown
    assert "…and 5 more advisories" in markdown


def test_scan_failures_are_told_apart_from_unsupported_dependencies():
    from renovate_security.advisories import ScanFailed
    from renovate_security.ecosystems import Docker

    def trivy(name, version):
        raise ScanFailed("registry unreachable")

    result = run_triage(
        [("docker", "private/image", ("1.0",), ("1.1",))], {"docker": trivy}, {"docker": Docker()}, False, 9.0, 4.0
    )
    assert result.scan_failures == ["private/image"]
    assert result.tier == "none"


def test_threshold_above_ten_reads_as_hotfix_disabled():
    fetch = fetcher({("jinja2", "3.1.2"): [raw_advisory("CRIT", v3=9.8)]})
    result = triage([("jinja2", ("3.1.2",), ("3.1.6",))], fetch, False, 11.0, 4.0)
    assert not result.hotfix_enabled
    assert "Critical, hotfix flow disabled" in render_markdown(result, 11.0, 4.0)


def test_unknown_scores_send_grouped_fixes_to_manual_review():
    fetch = fetcher(
        {
            ("jinja2", "3.1.2"): [raw_advisory("A", v3=7.5)],
            ("numpy", "2.4.4"): [raw_advisory("B", severity="unknown")],
        }
    )
    changes = [("jinja2", ("3.1.2",), ("3.1.6",)), ("numpy", ("2.4.4",), ("2.4.5",))]
    assert triage(changes, fetch, False, 9.0, 4.0).tier == "manual"
    critical = fetcher({**{("jinja2", "3.1.2"): [raw_advisory("A", v3=9.8)]}, ("numpy", "2.4.4"): [raw_advisory("B", severity="unknown")]})
    assert triage(changes, critical, False, 9.0, 4.0).tier == "hotfix"


def test_zero_cvss_is_kept():
    assert advisory_score(raw_advisory("A", v3=0.0, severity="low")) == 0.0


def test_an_unknown_smallest_fix_does_not_stop_the_triage():
    from renovate_security.advisories import RateLimited

    def fetch(name, version):
        if version == "3.1.4":
            raise RateLimited("GitHub API rate limit reached")
        return [to_advisory(raw_advisory("GHSA-1", v3=9.8), name)] if version == "3.1.2" else []

    fix = advisory_with_fixes("GHSA-1", ["3.1.4"])
    result = triage([("jinja2", ("3.1.2",), ("3.1.6",))], lambda n, v: [fix] if v == "3.1.2" else fetch(n, v), True, 9.0, 4.0)
    assert result.fixes and result.fixes[0].minimal is None and not result.scan_failures
    assert any("smallest fix unknown" in item for item in result.unscored)
    assert hotfix_pins(result) == ["uv:jinja2==3.1.6"]


def test_line_breaks_cannot_end_a_code_span():
    markdown = render_markdown(run_triage([], {}, UV, True, 9.0, 4.0, outside=["a\n\nb.yml"]), 9.0, 4.0)
    assert "`a\\n\\nb.yml`" in markdown and "\n\nb.yml" not in markdown

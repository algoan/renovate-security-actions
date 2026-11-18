import io
import json
import subprocess
import urllib.error
from urllib.parse import parse_qs, urlparse

import pytest

from renovate_security.advisories import (
    RateLimited,
    ScanFailed,
    Unscored,
    cpe_match_affects,
    github_source,
    nvd_score,
    nvd_source,
    trivy_advisories,
    trivy_source,
)


def cpe(product="openssl:openssl", version="*", **bounds):
    return {"vulnerable": True, "criteria": f"cpe:2.3:a:{product}:{version}:*:*:*:*:*:*:*", **bounds}


OPENSSL = "openssl:openssl"


@pytest.mark.parametrize(
    ("match", "version", "affected"),
    [
        (cpe(versionStartIncluding="3.6.0", versionEndExcluding="3.6.6"), "3.6.5", True),
        (cpe(versionStartIncluding="3.6.0", versionEndExcluding="3.6.6"), "3.6.6", False),
        (cpe(versionStartIncluding="3.6.0", versionEndExcluding="3.6.6"), "3.5.9", False),
        (cpe(versionEndIncluding="3.6.5"), "3.6.5", True),
        (cpe(versionStartExcluding="3.6.5", versionEndIncluding="3.7.0"), "3.6.5", False),
        (cpe(version="3.6.5"), "3.6.5", True),
        (cpe(version="3.6.5"), "v3.6.5", True),
        (cpe(version="3.6.5"), "3.6.6", False),
        (cpe(), "3.6.5", False),
        (cpe(product="f5:nginx", versionEndExcluding="9"), "3.6.5", False),
        ({**cpe(versionEndExcluding="9"), "vulnerable": False}, "3.6.5", False),
    ],
)
def test_cpe_match_affects(match, version, affected):
    assert cpe_match_affects(match, OPENSSL, version) is affected


def nvd_cve(cve_id, score, *matches):
    return {
        "cve": {
            "id": cve_id,
            "descriptions": [{"lang": "en", "value": f"{cve_id} issue\nmore"}],
            "metrics": {
                "cvssMetricV31": [{"cvssData": {"baseScore": score, "baseSeverity": "HIGH"}}],
                "cvssMetricV2": [{"cvssData": {"baseScore": 5.0}, "baseSeverity": "MEDIUM"}],
            },
            "configurations": [{"nodes": [{"cpeMatch": list(matches)}]}],
        }
    }


def test_nvd_score_takes_the_highest_metric():
    cve = nvd_cve("CVE-1", 7.5)["cve"]
    assert nvd_score(cve) == (7.5, "high")
    assert nvd_score({"metrics": {}}) == (None, "unknown")


def fake_nvd(pages):
    calls = []

    def get(url, headers):
        calls.append((url, headers))
        return pages[len(calls) - 1], {}

    return get, calls


def test_nvd_source_matches_versions_and_pages():
    pages = [
        {
            "resultsPerPage": 1,
            "totalResults": 2,
            "vulnerabilities": [
                nvd_cve("CVE-A", 9.8, cpe(versionStartIncluding="3.6.0", versionEndExcluding="3.6.6"))
            ],
        },
        {
            "resultsPerPage": 1,
            "totalResults": 2,
            "vulnerabilities": [nvd_cve("CVE-B", 5.3, cpe(versionEndExcluding="3.0.0"))],
        },
    ]
    get, calls = fake_nvd(pages)
    sleeps = []
    fetch = nvd_source({"openssl/openssl": "openssl:openssl"}, "key", get, sleeps.append)
    old = fetch("openssl/openssl", "3.6.5")
    assert [(a.id, a.score, a.patched) for a in old] == [("CVE-A", 9.8, ["3.6.6"])]
    assert old[0].summary == "CVE-A issue"
    assert fetch("openssl/openssl", "3.6.6") == []
    assert len(calls) == 2  # fetched once per product
    assert calls[0][1] == {"apiKey": "key"}
    assert "virtualMatchString=cpe%3A2.3%3Aa%3Aopenssl%3Aopenssl" in calls[0][0]


def test_nvd_source_without_cpe_or_reachable_api_is_unscored():
    def broken(url, headers):
        raise OSError("timeout")

    fetch = nvd_source({"nginx": "f5:nginx"}, "", broken, lambda _: None)
    with pytest.raises(Unscored, match="no CPE"):
        fetch("openresty/lua-resty-core", "0.1.32")
    with pytest.raises(Unscored, match="unreachable"):
        fetch("nginx", "1.31.6")


TRIVY_REPORT = {
    "Results": [
        {
            "Target": "ubuntu 24.04",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2025-1",
                    "PkgName": "libssl3",
                    "Title": "openssl: bug",
                    "Severity": "HIGH",
                    "CVSS": {"nvd": {"V3Score": 7.5}, "redhat": {"V3Score": 5.9}},
                },
                {
                    "VulnerabilityID": "CVE-2025-1",
                    "PkgName": "openssl",
                    "Severity": "HIGH",
                    "CVSS": {"nvd": {"V3Score": 7.5}},
                },
                {
                    "VulnerabilityID": "GHSA-xxxx",
                    "PkgName": "requests",
                    "Severity": "MEDIUM",
                    "CVSS": {"ghsa": {"V3Score": 6.1}},
                },
                {"VulnerabilityID": "CVE-2025-2", "PkgName": "zlib", "Severity": "CRITICAL"},
                {
                    "VulnerabilityID": "CVE-2025-3",
                    "PkgName": "libsqlite3-0",
                    "Severity": "MEDIUM",
                    "SeveritySource": "ubuntu",
                    "CVSS": {"nvd": {"V3Score": 9.8}},
                },
                {
                    "VulnerabilityID": "CVE-2025-4",
                    "PkgName": "libgnutls30",
                    "Severity": "MEDIUM",
                    "SeveritySource": "redhat",
                    "CVSS": {"nvd": {"V3Score": 8.2}, "redhat": {"V3Score": 5.9}},
                },
            ],
        },
        {"Target": "empty"},
    ]
}


def test_trivy_advisories_dedupe_and_score():
    advisories = {a.id: a for a in trivy_advisories(TRIVY_REPORT)}
    assert advisories["CVE-2025-1"].score == 7.5
    assert advisories["CVE-2025-3"].score == 4.0  # Ubuntu's severity, not NVD's 9.8
    assert advisories["CVE-2025-4"].score == 5.9  # the vendor's own CVSS
    assert advisories["CVE-2025-1"].cve_id == "CVE-2025-1"
    assert advisories["GHSA-xxxx"].score == 6.1
    assert advisories["GHSA-xxxx"].cve_id is None
    assert advisories["CVE-2025-2"].score == 9.0  # severity fallback


def test_trivy_source_scans_refs_once_and_reports_failures():
    commands = []

    def run(cmd):
        commands.append(cmd[-1])
        if "private" in cmd[-1]:
            return subprocess.CompletedProcess(cmd, 1, "", "UNAUTHORIZED")
        return subprocess.CompletedProcess(cmd, 0, json.dumps(TRIVY_REPORT), "")

    fetch = trivy_source(run)
    assert len(fetch("nvidia/cuda", "12.6.3-x@sha256:a")) == 5
    fetch("nvidia/cuda", "12.6.3-x@sha256:a")
    fetch("tools", "@sha256:b")
    assert commands == ["nvidia/cuda:12.6.3-x@sha256:a", "tools@sha256:b"]
    with pytest.raises(Unscored, match="UNAUTHORIZED"):
        fetch("private/image", "1.0")


def test_github_source_follows_pages_and_caches():
    raw = {"ghsa_id": "GHSA-1", "severity": "high", "vulnerabilities": []}
    responses = [
        ([raw], {"Link": '<https://api.github.com/advisories?after=x>; rel="next"'}),
        ([{**raw, "ghsa_id": "GHSA-2"}], {}),
    ]
    calls = []

    def get(url, headers):
        calls.append(url)
        return responses[len(calls) - 1]

    fetch = github_source("token", "npm", str.lower, get)
    assert [a.id for a in fetch("qs", "6.10.3")] == ["GHSA-1", "GHSA-2"]
    fetch("qs", "6.10.3")
    assert len(calls) == 2
    assert "ecosystem=npm" in calls[0] and "affects=qs%406.10.3" in calls[0]
    # Withdrawn advisories are not vulnerabilities.
    assert "is_withdrawn=false" in calls[0]


def http_error(code, headers, message):
    body = io.BytesIO(json.dumps({"message": message}).encode())
    return urllib.error.HTTPError("https://api.github.com/advisories", code, "error", headers, body)


def affects(url):
    return parse_qs(urlparse(url).query)["affects"][0]


def raw_advisory(ghsa_id, *packages):
    return {"ghsa_id": ghsa_id, "severity": "high", "vulnerabilities": [{"package": {"name": p}} for p in packages]}


def test_github_source_waits_for_a_short_rate_limit():
    calls, waits = [], []

    def get(url, headers):
        calls.append(url)
        if len(calls) == 1:
            raise http_error(403, {"Retry-After": "2"}, "You have exceeded a secondary rate limit")
        return [raw_advisory("GHSA-1", "qs")], {}

    fetch = github_source("token", "npm", str.lower, get, sleep=waits.append)
    assert [a.id for a in fetch("qs", "6.10.3")] == ["GHSA-1"]
    assert waits == [2.0] and len(calls) == 2


def test_github_source_stops_at_an_exhausted_rate_limit():
    calls = []

    def get(url, headers):
        calls.append(url)
        raise http_error(403, {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1800000000"}, "API rate limit exceeded")

    fetch = github_source("token", "npm", str.lower, get, sleep=lambda _: None, now=lambda: 1799990000.0)
    with pytest.raises(RateLimited, match="rate limit reached until 08:00 UTC"):
        fetch("qs", "6.10.3")
    with pytest.raises(RateLimited):
        fetch("lodash", "4.17.20")
    # Later lookups fail without calling GitHub again.
    assert len(calls) == 1


def test_github_source_reports_other_http_errors_as_scan_failures():
    def get(url, headers):
        raise http_error(403, {}, "Resource not accessible by integration")

    with pytest.raises(ScanFailed) as error:
        github_source("token", "npm", str.lower, get)("qs", "6.10.3")
    assert not isinstance(error.value, RateLimited)


def test_github_source_prefetches_one_version_per_package_and_query():
    responses = {
        "a@1,b@1": [raw_advisory("GHSA-A", "a"), raw_advisory("GHSA-AB", "a", "b")],
        "a@2": [],
        "a@1": [raw_advisory("GHSA-A", "a")],
        "b@1": [raw_advisory("GHSA-AB", "a", "b")],
    }
    calls = []

    def get(url, headers):
        calls.append(affects(url))
        return responses[affects(url)], {}

    fetch = github_source("token", "npm", str.lower, get)
    fetch.prefetch([("a", "1"), ("a", "2"), ("b", "1")])
    assert calls == ["a@1,b@1", "a@2"]
    assert fetch("a", "2") == []
    # GHSA-AB names both packages of its query: a@1 and b@1 are checked one by one.
    assert [x.id for x in fetch("a", "1")] == ["GHSA-A"]
    assert [x.id for x in fetch("b", "1")] == ["GHSA-AB"]
    assert calls == ["a@1,b@1", "a@2", "a@1", "b@1"]


def test_github_source_prefetch_leaves_failures_to_each_lookup():
    def get(url, headers):
        raise http_error(429, {}, "")

    fetch = github_source("token", "npm", str.lower, get, sleep=lambda _: None)
    fetch.prefetch([("qs", "6.10.3")])
    with pytest.raises(RateLimited):
        fetch("qs", "6.10.3")


def test_github_source_fails_fast_after_a_server_error_but_not_a_client_error():
    calls = []

    def get(url, headers):
        calls.append(affects(url))
        if affects(url) == "bad@1":
            raise http_error(422, {}, "Validation Failed")
        if affects(url) == "down@1":
            raise http_error(502, {}, "Bad Gateway")
        return [], {}

    fetch = github_source("token", "npm", str.lower, get)
    with pytest.raises(ScanFailed):
        fetch("bad", "1")
    # A client error only fails its own lookup.
    assert fetch("qs", "6.10.3") == []
    with pytest.raises(ScanFailed, match="HTTP 502"):
        fetch("down", "1")
    # A server error fails every later lookup at once.
    with pytest.raises(ScanFailed, match="HTTP 502"):
        fetch("lodash", "4.17.20")
    assert calls == ["bad@1", "qs@6.10.3", "down@1"]


def test_github_source_fails_fast_when_unreachable():
    calls = []

    def get(url, headers):
        calls.append(url)
        raise urllib.error.URLError("timed out")

    fetch = github_source("token", "npm", str.lower, get)
    for name in ("qs", "lodash"):
        with pytest.raises(ScanFailed, match="unreachable"):
            fetch(name, "1.0.0")
    assert len(calls) == 1


def test_github_source_prefetch_goes_on_after_a_failed_batch():
    calls = []

    def get(url, headers):
        calls.append(affects(url))
        if affects(url).startswith("a@1"):
            raise http_error(414, {}, "URI Too Long")
        return [], {}

    fetch = github_source("token", "npm", str.lower, get)
    fetch.prefetch([("a", "1"), ("a", "2")])
    assert calls == ["a@1", "a@2"]
    assert fetch("a", "2") == [] and calls == ["a@1", "a@2"]

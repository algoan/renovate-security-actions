"""Vulnerability sources: GitHub Advisory Database, NVD (CPE matching) and Trivy image scans.

Each source is a callable `(name, version) -> list[Advisory]` listing the advisories affecting
that version. A source that cannot score a dependency raises `Unscored`.
"""

from __future__ import annotations

import json
import re
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .versions import KeyFn, loose_key

GITHUB_API = "https://api.github.com"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
SEVERITY_FALLBACK_SCORE = {
    "critical": 9.0,
    "high": 7.0,
    "medium": 4.0,
    "moderate": 4.0,
    "low": 0.1,
}


@dataclass
class Advisory:
    id: str
    cve_id: str | None
    summary: str
    url: str
    severity: str
    score: float | None
    patched: list[str] = field(default_factory=list)


Source = Callable[[str, str], list[Advisory]]


class Unscored(Exception):
    """The dependency is not covered by the source (e.g. no NVD product known for it)."""


class ScanFailed(Unscored):
    """The source failed (API unreachable, image not pulled): the score is unknown, not zero."""


class RateLimited(ScanFailed):
    """GitHub refused the lookups because of a rate limit: the score is unknown, not zero."""


def normalize_pip(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def advisory_score(raw: dict) -> float | None:
    """Highest published CVSS score (v3 and v4 often disagree), else a severity-based estimate."""
    severities = raw.get("cvss_severities") or {}
    scores = [
        (severities.get(key) or {}).get("score") for key in ("cvss_v3", "cvss_v4")
    ]
    scores.append((raw.get("cvss") or {}).get("score"))
    scores = [float(score) for score in scores if score is not None]
    if scores:
        return max(scores)
    return SEVERITY_FALLBACK_SCORE.get((raw.get("severity") or "").lower())


def to_advisory(
    raw: dict, package: str = "", normalize: Callable[[str], str] = normalize_pip
) -> Advisory:
    """A GitHub advisory, with the first patched versions listed for `package`."""
    return Advisory(
        id=raw["ghsa_id"],
        cve_id=raw.get("cve_id"),
        summary=raw.get("summary", ""),
        url=raw.get("html_url") or f"https://github.com/advisories/{raw['ghsa_id']}",
        severity=raw.get("severity") or "unknown",
        score=advisory_score(raw),
        patched=[
            vuln["first_patched_version"]
            for vuln in raw.get("vulnerabilities") or []
            if vuln.get("first_patched_version")
            and normalize((vuln.get("package") or {}).get("name", ""))
            == normalize(package)
        ],
    )


def next_page(link_header: str | None) -> str | None:
    for part in (link_header or "").split(","):
        url, _, rel = part.partition(";")
        if rel.strip() == 'rel="next"':
            return url.strip()[1:-1]
    return None


def http_json(url: str, headers: dict[str, str]) -> tuple[object, dict]:
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response), dict(response.headers)


RATE_LIMIT_RETRIES = 2
RATE_LIMIT_MAX_WAIT = 60.0
# Packages per advisory query: each `name@version` adds ~40 characters to the URL.
AFFECTS_BATCH = 50


def rate_limit_wait(code: int, headers, message: str, now: float) -> float | None:
    """Seconds GitHub asks to wait before retrying, or None when the error is no rate limit."""
    if code not in (403, 429):
        return None
    retry_after = (headers.get("Retry-After") or "").strip()
    if retry_after.isdigit():
        return float(retry_after)
    if headers.get("X-RateLimit-Remaining") == "0":
        reset = (headers.get("X-RateLimit-Reset") or "").strip()
        return max(0.0, float(reset) - now) if reset.isdigit() else float("inf")
    # A secondary rate limit can come without those headers: GitHub then only documents the
    # error message ("You have exceeded a secondary rate limit") and a wait of at least a minute.
    if code == 429 or "rate limit" in message.lower():
        return 60.0
    return None  # e.g. a token without access


def affected_names(raw: dict, normalize: Callable[[str], str]) -> set[str]:
    return {
        normalize((vuln.get("package") or {}).get("name", ""))
        for vuln in raw.get("vulnerabilities") or []
    }


def github_source(
    token: str,
    ecosystem: str,
    normalize: Callable[[str], str] = normalize_pip,
    get: Callable = http_json,
    sleep: Callable[[float], None] = time.sleep,
    now: Callable[[], float] = time.time,
) -> Source:
    """GitHub Advisory Database for the `pip` or `npm` ecosystem.

    `fetch.prefetch(pairs)` looks many `(name, version)` up in a few queries (the default
    GITHUB_TOKEN allows 1,000 requests per hour per repository). A rate limit is retried when
    GitHub asks to wait up to a minute. Otherwise a rate limit, a server error or an unreachable
    API makes every later lookup fail at once, without a request: the rest of the run reports
    its dependencies as not scored rather than waiting on each of them. A client error (4xx)
    only fails its own lookup.
    """
    cache: dict[tuple[str, str], list[Advisory]] = {}
    broken: list[ScanFailed] = []
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    def fail_for_the_run(failure: ScanFailed) -> ScanFailed:
        broken.append(failure)
        return failure

    def request(url: str) -> tuple[object, dict]:
        for attempt in range(RATE_LIMIT_RETRIES + 1):
            if broken:
                raise type(broken[0])(str(broken[0]))
            try:
                return get(url, headers)
            except urllib.error.HTTPError as error:
                message = error.read().decode(errors="replace")[:300] if error.fp else ""
                wait = rate_limit_wait(error.code, error.headers or {}, message, now())
                if wait is None:
                    failure = ScanFailed(f"GitHub Advisory Database: HTTP {error.code}")
                    raise (fail_for_the_run(failure) if error.code >= 500 else failure) from error
                if wait <= RATE_LIMIT_MAX_WAIT and attempt < RATE_LIMIT_RETRIES:
                    sleep(wait)
                    continue
                reset = (error.headers or {}).get("X-RateLimit-Reset") or ""
                until = (
                    datetime.fromtimestamp(int(reset), timezone.utc).strftime(" until %H:%M UTC")
                    if reset.strip().isdigit()
                    else ""
                )
                limited = RateLimited(f"GitHub API rate limit reached{until}: re-run the triage then")
                raise fail_for_the_run(limited) from error
            except OSError as error:
                unreachable = ScanFailed(f"GitHub Advisory Database unreachable: {error}")
                raise fail_for_the_run(unreachable) from error
        raise AssertionError("unreachable")

    def query(affects: str) -> list[dict]:
        # Without is_withdrawn=false the API also returns withdrawn advisories, which are not
        # vulnerabilities (e.g. GHSA-8cp3-66vr-3r4c, 9.8 on formidable 2.1.5).
        params = {"ecosystem": ecosystem, "affects": affects, "is_withdrawn": "false", "per_page": 100}
        url: str | None = f"{GITHUB_API}/advisories?{urllib.parse.urlencode(params)}"
        raws: list[dict] = []
        while url:
            body, response_headers = request(url)
            raws += body
            url = next_page(response_headers.get("Link"))
        return raws

    def fetch(name: str, version: str) -> list[Advisory]:
        if (name, version) not in cache:
            raws = query(f"{name}@{version}")
            cache[(name, version)] = [to_advisory(raw, name, normalize) for raw in raws]
        return cache[(name, version)]

    def prefetch(pairs: Iterable[tuple[str, str]]) -> None:
        """Fill the cache with batched queries; whatever stays unknown is fetched one by one.

        A batched answer only tells advisories apart by package: a query holds one version per
        package, and an advisory naming several packages of the query is checked one by one.
        """
        layers: list[dict[str, tuple[str, str]]] = []
        for name, version in sorted({p for p in pairs if p not in cache}):
            layer = next((existing for existing in layers if normalize(name) not in existing), None)
            if layer is None:
                layer = {}
                layers.append(layer)
            layer[normalize(name)] = (name, version)
        for layer in layers:
            entries = list(layer.items())
            for start in range(0, len(entries), AFFECTS_BATCH):
                batch = dict(entries[start : start + AFFECTS_BATCH])
                try:
                    raws = query(",".join(f"{n}@{v}" for n, v in batch.values()))
                except ScanFailed:
                    continue  # the lookups one by one report it, per dependency
                found: dict[str, list[dict]] = {key: [] for key in batch}
                ambiguous: set[str] = set()
                for raw in raws:
                    keys = affected_names(raw, normalize) & batch.keys()
                    if len(keys) != 1:
                        ambiguous |= keys or set(batch)
                    for key in keys:
                        found[key].append(raw)
                for key, (name, version) in batch.items():
                    if key not in ambiguous:
                        cache[(name, version)] = [to_advisory(raw, name, normalize) for raw in found[key]]

    fetch.prefetch = prefetch  # type: ignore[attr-defined]
    return fetch


# --- NVD ------------------------------------------------------------------------------------


def nvd_score(cve: dict) -> tuple[float | None, str]:
    """Highest CVSS base score (v4.0, v3.1, v3.0, v2) and its severity."""
    best: tuple[float | None, str] = (None, "unknown")
    for key, metrics in (cve.get("metrics") or {}).items():
        if not key.startswith("cvssMetric"):
            continue
        for metric in metrics:
            data = metric.get("cvssData") or {}
            score = data.get("baseScore")
            severity = data.get("baseSeverity") or metric.get("baseSeverity") or "unknown"
            if score is not None and (best[0] is None or score > best[0]):
                best = (float(score), severity.lower())
    return best


def cpe_parts(criteria: str) -> tuple[str, str, str]:
    """(vendor, product, version) of a `cpe:2.3:a:vendor:product:version:...` string."""
    parts = criteria.split(":")
    return (parts[3], parts[4], parts[5]) if len(parts) > 5 else ("", "", "")


def cpe_match_affects(
    match: dict, product: str, version: str, key: KeyFn = loose_key
) -> bool:
    if not match.get("vulnerable"):
        return False
    vendor, name, cpe_version = cpe_parts(match.get("criteria", ""))
    if f"{vendor}:{name}" != product:
        return False
    if cpe_version not in ("*", "-", ""):
        return key(cpe_version) == key(version)
    current = key(version)
    bounds = (
        ("versionStartIncluding", lambda b: current >= b),
        ("versionStartExcluding", lambda b: current > b),
        ("versionEndIncluding", lambda b: current <= b),
        ("versionEndExcluding", lambda b: current < b),
    )
    present = [(match[name_], check) for name_, check in bounds if match.get(name_)]
    if not present:
        return False  # "every version" entries are too vague to score a bump
    return all(check(key(bound)) for bound, check in present)


def cve_matches(cve: dict, product: str) -> list[dict]:
    return [
        match
        for config in cve.get("configurations") or []
        for node in config.get("nodes") or []
        for match in node.get("cpeMatch") or []
        if f"{cpe_parts(match.get('criteria', ''))[0]}:{cpe_parts(match.get('criteria', ''))[1]}"
        == product
    ]


def nvd_advisory(cve: dict, product: str) -> Advisory:
    score, severity = nvd_score(cve)
    summary = next(
        (d["value"] for d in cve.get("descriptions") or [] if d.get("lang") == "en"), ""
    )
    return Advisory(
        id=cve["id"],
        cve_id=cve["id"],
        summary=summary.split("\n")[0][:200],
        url=f"https://nvd.nist.gov/vuln/detail/{cve['id']}",
        severity=severity,
        score=score,
        patched=sorted(
            {
                match["versionEndExcluding"]
                for match in cve_matches(cve, product)
                if match.get("vulnerable") and match.get("versionEndExcluding")
            }
        ),
    )


def nvd_source(
    cpes: dict[str, str],
    api_key: str = "",
    get: Callable = http_json,
    sleep: Callable[[float], None] = time.sleep,
) -> Source:
    """CVEs of `vendor:product` from NVD, matched locally against the version ranges.

    NVD allows 50 requests per 30 seconds with an API key and 5 without: each product is
    fetched once (paginated) and requests are spaced accordingly.
    """
    products: dict[str, list[dict]] = {}
    delay = 0.7 if api_key else 6.5
    last = [0.0]

    def throttled(url: str) -> dict:
        wait = last[0] + delay - time.monotonic()
        if last[0] and wait > 0:
            sleep(wait)
        last[0] = time.monotonic()
        headers = {"apiKey": api_key} if api_key else {}
        body, _ = get(url, headers)
        return body

    def cves_of(product: str) -> list[dict]:
        if product not in products:
            vendor, name = product.split(":", 1)
            cves: list[dict] = []
            start = 0
            while True:
                query = urllib.parse.urlencode(
                    {
                        "virtualMatchString": f"cpe:2.3:a:{vendor}:{name}",
                        "resultsPerPage": 2000,
                        "startIndex": start,
                    }
                )
                body = throttled(f"{NVD_API}?{query}")
                cves += [item["cve"] for item in body.get("vulnerabilities", [])]
                start += body.get("resultsPerPage") or 0
                if not body.get("resultsPerPage") or start >= body.get("totalResults", 0):
                    break
            products[product] = cves
        return products[product]

    def fetch(name: str, version: str) -> list[Advisory]:
        product = cpes.get(name)
        if not product:
            raise Unscored(f"no CPE known for {name}")
        try:
            cves = cves_of(product)
        except OSError as error:
            raise ScanFailed(f"NVD unreachable for {name}: {error}") from error
        return [
            nvd_advisory(cve, product)
            for cve in cves
            if any(cpe_match_affects(m, product, version) for m in cve_matches(cve, product))
        ]

    return fetch


# --- Trivy ----------------------------------------------------------------------------------


def trivy_score(vuln: dict) -> tuple[float | None, str]:
    """Score from the source Trivy took the severity from.

    For OS packages that is the distribution (e.g. Ubuntu rates a CVE "medium" when its build
    is barely exposed, while NVD scores the upstream flaw 9.8): its CVSS when it publishes one,
    else its severity mapped to a score. NVD only when Trivy has no other source.
    """
    cvss = vuln.get("CVSS") or {}
    severity = (vuln.get("Severity") or "unknown").lower()
    source = vuln.get("SeveritySource") or ""
    data = cvss.get(source) or {}
    for key in ("V40Score", "V3Score"):
        if data.get(key) is not None:
            return float(data[key]), severity
    if source and source not in ("nvd", "ghsa"):
        return SEVERITY_FALLBACK_SCORE.get(severity), severity
    scores = [
        float(d[k]) for d in cvss.values() for k in ("V40Score", "V3Score") if d.get(k) is not None
    ]
    nvd = (cvss.get("nvd") or {}).get("V3Score")
    if nvd is not None:
        return float(nvd), severity
    return (max(scores) if scores else SEVERITY_FALLBACK_SCORE.get(severity)), severity


def trivy_advisories(report: dict) -> list[Advisory]:
    """One advisory per vulnerability id found in a `trivy image --format json` report."""
    found: dict[str, Advisory] = {}
    for result in report.get("Results") or []:
        for vuln in result.get("Vulnerabilities") or []:
            vuln_id = vuln["VulnerabilityID"]
            score, severity = trivy_score(vuln)
            advisory = Advisory(
                id=vuln_id,
                cve_id=vuln_id if vuln_id.startswith("CVE-") else None,
                summary=f"{vuln.get('PkgName', '')}: {vuln.get('Title') or ''}".strip(": "),
                url=vuln.get("PrimaryURL") or f"https://avd.aquasec.com/nvd/{vuln_id.lower()}",
                severity=severity,
                score=score,
            )
            current = found.get(vuln_id)
            if current is None or (advisory.score or 0) > (current.score or 0):
                found[vuln_id] = advisory
    return list(found.values())


def trivy_source(run: Callable[[list[str]], subprocess.CompletedProcess] | None = None) -> Source:
    """Scan `image:tag[@digest]` with Trivy (OS packages and language libraries)."""
    run = run or (lambda cmd: subprocess.run(cmd, capture_output=True, text=True, check=False))
    cache: dict[str, list[Advisory]] = {}

    def fetch(name: str, version: str) -> list[Advisory]:
        ref = f"{name}{version}" if version.startswith("@") else f"{name}:{version}"
        if ref not in cache:
            result = run(
                ["trivy", "image", "--quiet", "--format", "json", "--scanners", "vuln", ref]
            )
            if result.returncode != 0:
                raise ScanFailed(f"Trivy could not scan {ref}: {result.stderr.strip()[-300:]}")
            cache[ref] = trivy_advisories(json.loads(result.stdout or "{}"))
        return cache[ref]

    return fetch

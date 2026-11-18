"""Create, update or release the Notion ticket tracking a Renovate security PR.

upsert   find the ticket linked to the PR (Git Pull Request property) or create it
release  mark the ticket as released in production
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import sys
import urllib.request
from dataclasses import dataclass, field

NOTION_API = "https://api.notion.com/v1"
NOTION_VERSION = "2025-09-03"
TICKETS_DATA_SOURCE_ID = "01cee5a0-2b64-49a0-b9de-82198932bfb6"

PR_URL_PROPERTY = "Git Pull Request"
TICKET_ID_PROPERTY = "ID"
ADVISORY_ID = re.compile(r"^[A-Z]+-[0-9A-Za-z-]+$")


@dataclass
class Settings:
    """Where tickets go and how they are labelled; option values are matched by prefix."""

    repository: str = "repository"
    data_source_id: str = TICKETS_DATA_SOURCE_ID
    options: dict[str, str] = field(
        default_factory=lambda: {
            "Type": "Vulnerability",
            "Project": "Technique",
            "Environment": "Production",
        }
    )


def priority_prefix(max_cvss: float | None) -> str:
    if max_cvss is None:
        return "P3"
    if max_cvss >= 9.0:
        return "P1"
    if max_cvss >= 7.0:
        return "P2"
    if max_cvss >= 4.0:
        return "P3"
    return "P4"


def resolve_option(schema: dict, property_name: str, prefix: str) -> str:
    """Option names carry emojis (e.g. "P1 - Urgent 🔥🔥🔥"), so match them by prefix."""
    prop = schema[property_name]
    options = prop.get(prop["type"], {}).get("options", [])
    for option in options:
        if option["name"].strip().lower().startswith(prefix.lower()):
            return option["name"]
    raise KeyError(
        f"No option starting with {prefix!r} in Notion property {property_name!r}"
    )


def option_value(schema: dict, property_name: str, prefix: str) -> dict:
    kind = schema[property_name]["type"]
    name = resolve_option(schema, property_name, prefix)
    return (
        {kind: [{"name": name}]} if kind == "multi_select" else {kind: {"name": name}}
    )


def ticket_title(triage: dict, settings: Settings) -> str:
    packages = ", ".join(fix["name"] for fix in triage["fixes"]) or "dependencies"
    return f"[DEPS] Security update of {packages} on {settings.repository}"


def ticket_properties(schema: dict, triage: dict, pr_url: str, settings: Settings) -> dict:
    properties = {
        "Name": {"title": [{"text": {"content": ticket_title(triage, settings)}}]},
        "Priority": option_value(
            schema, "Priority", priority_prefix(triage["max_cvss"])
        ),
        PR_URL_PROPERTY: {"url": pr_url},
    }
    for property_name, prefix in settings.options.items():
        if prefix:
            properties[property_name] = option_value(schema, property_name, prefix)
    return properties


def rich_text(text: str, link: str | None = None) -> list[dict]:
    return [
        {
            "type": "text",
            "text": {"content": text, "link": {"url": link} if link else None},
        }
    ]


def block(kind: str, text: str, link: str | None = None, **extra) -> dict:
    return {
        "object": "block",
        "type": kind,
        kind: {"rich_text": rich_text(text, link), **extra},
    }


def summary_blocks(triage: dict, pr_url: str, settings: Settings) -> list[dict]:
    """Generated part of the ticket, from the Description heading up to How to test."""
    score = "unknown" if triage["max_cvss"] is None else f"{triage['max_cvss']:.1f}"
    blocks = [
        block("heading_3", "Description"),
        block(
            "paragraph",
            f"Renovate security update on {settings.repository} (routing tier: {triage['tier']}, max CVSS: {score}).",
        ),
        block("paragraph", pr_url, link=pr_url),
        block("heading_3", "Vulnerabilities"),
    ]
    for fix in triage["fixes"]:
        for adv in fix["advisories"]:
            cvss = "n/a" if adv["score"] is None else f"{adv['score']:.1f}"
            cve = adv["cve_id"] if adv["cve_id"] and adv["cve_id"] != adv["id"] else None
            label = f"{adv['id']} ({cve or 'no other id'}) — {fix['name']} {fix['old']} → {fix['new']} — CVSS {cvss} — {adv['summary']}"
            blocks.append(block("bulleted_list_item", label, link=adv["url"]))
    if not triage["fixes"]:
        blocks.append(
            block(
                "paragraph",
                "No advisory resolved automatically, see the PR description.",
            )
        )
    return blocks


def ticket_content(triage: dict, pr_url: str, settings: Settings) -> list[dict]:
    return summary_blocks(triage, pr_url, settings) + [
        block("heading_3", "How to test"),
        block(
            "paragraph",
            "CI is green on the PR, then preprod runs without new errors after the merge.",
        ),
        block("heading_3", "TODOs for MEP"),
        block("to_do", "Send message on #ship-to-prod", checked=False),
        block("to_do", f"Applications to release: {settings.repository}", checked=False),
    ]


def heading_text(block_: dict) -> str | None:
    if block_["type"] != "heading_3":
        return None
    return "".join(part["plain_text"] for part in block_["heading_3"]["rich_text"])


def generated_blocks(children: list[dict]) -> tuple[str, list[str]] | None:
    """Id of the Description heading and ids of the generated blocks after it, if the layout is intact."""
    texts = [heading_text(child) for child in children]
    if "Description" not in texts or "How to test" not in texts:
        return None
    start, end = texts.index("Description"), texts.index("How to test")
    if start > end:
        return None
    return children[start]["id"], [child["id"] for child in children[start + 1 : end]]


def is_released(page: dict) -> bool:
    status = page["properties"].get("Status", {}).get("status") or {}
    return (status.get("name") or "").startswith("Released")


def triage_advisories(triage: dict) -> set[str]:
    return {adv["id"] for fix in triage["fixes"] for adv in fix["advisories"]}


def ticket_advisories(children: list[dict]) -> set[str]:
    """Advisory ids (GHSA-…, CVE-…) listed in a ticket's generated Vulnerabilities section."""
    ids = set()
    for child in children:
        if child["type"] == "bulleted_list_item":
            text = "".join(
                part["plain_text"] for part in child["bulleted_list_item"]["rich_text"]
            )
            first = text.split(" ", 1)[0]
            if ADVISORY_ID.match(first):
                ids.add(first)
    return ids


def open_ticket(pages: list[dict]) -> dict | None:
    """Newest ticket of the PR that is not released yet: a released one is never reused for new fixes."""
    return next((page for page in pages if not is_released(page)), None)


def ticket_id(page: dict) -> str:
    unique_id = page["properties"][TICKET_ID_PROPERTY]["unique_id"]
    return (
        f"{unique_id['prefix']}-{unique_id['number']}"
        if unique_id.get("prefix")
        else str(unique_id["number"])
    )


# Notion accepts at most 100 child blocks per request; a Docker update can fix more CVEs.
MAX_CHILDREN = 100


def chunks(blocks: list[dict], size: int = MAX_CHILDREN) -> list[list[dict]]:
    return [blocks[i : i + size] for i in range(0, len(blocks), size)]


class Notion:
    def __init__(self, token: str, data_source_id: str = TICKETS_DATA_SOURCE_ID) -> None:
        self.token = token
        self.data_source_id = data_source_id

    def request(self, method: str, path: str, body: dict | None = None) -> dict:
        request = urllib.request.Request(
            f"{NOTION_API}{path}",
            method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Notion-Version": NOTION_VERSION,
                "Content-Type": "application/json",
            },
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)

    def schema(self) -> dict:
        return self.request("GET", f"/data_sources/{self.data_source_id}")[
            "properties"
        ]

    def tickets_for_pr(self, pr_url: str) -> list[dict]:
        """Tickets linked to the PR, newest first."""
        body = {
            "filter": {"property": PR_URL_PROPERTY, "rich_text": {"equals": pr_url}},
            "sorts": [{"timestamp": "created_time", "direction": "descending"}],
            "page_size": 20,
        }
        return self.request(
            "POST", f"/data_sources/{self.data_source_id}/query", body
        )["results"]

    def children(self, page_id: str) -> list[dict]:
        blocks: list[dict] = []
        cursor = ""
        while True:
            page = self.request(
                "GET",
                f"/blocks/{page_id}/children?page_size=100"
                + (f"&start_cursor={cursor}" if cursor else ""),
            )
            blocks += page["results"]
            if not page.get("has_more"):
                return blocks
            cursor = page["next_cursor"]

    def append(self, page_id: str, blocks: list[dict], after: str | None = None) -> None:
        """Append in requests of at most MAX_CHILDREN blocks, keeping their order."""
        for chunk in chunks(blocks):
            body: dict = {"children": chunk}
            if after:
                body["after"] = after
            created = self.request("PATCH", f"/blocks/{page_id}/children", body)
            after = created["results"][-1]["id"] if after else None

    def create(self, properties: dict, children: list[dict]) -> dict:
        body = {
            "parent": {
                "type": "data_source_id",
                "data_source_id": self.data_source_id,
            },
            "icon": {"type": "emoji", "emoji": "🛡️"},
            "properties": properties,
            "children": children[:MAX_CHILDREN],
        }
        page = self.request("POST", "/pages", body)
        try:
            self.append(page["id"], children[MAX_CHILDREN:])
        except Exception:
            # A partial ticket could never be completed: trash it so the next run recreates it.
            self.request("PATCH", f"/pages/{page['id']}", {"in_trash": True})
            raise
        return page

    def update(self, page_id: str, properties: dict) -> dict:
        return self.request("PATCH", f"/pages/{page_id}", {"properties": properties})

    def refresh_summary(self, page_id: str, blocks: list[dict]) -> None:
        located = generated_blocks(self.children(page_id))
        if located is None:
            print(
                f"Ticket layout changed by hand, not refreshing its content ({page_id})"
            )
            return
        anchor, stale = located
        for block_id in stale:
            self.request("DELETE", f"/blocks/{block_id}")
        self.append(page_id, blocks, after=anchor)


def write_github_output(values: dict[str, str]) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    if path:
        with open(path, "a") as handle:
            handle.writelines(f"{key}={value}\n" for key, value in values.items())


def upsert(notion: Notion, triage: dict, pr_url: str, settings: Settings) -> dict:
    schema = notion.schema()
    tickets = notion.tickets_for_pr(pr_url)
    existing = open_ticket(tickets)
    released = next((page for page in tickets if is_released(page)), None)
    # Same fixes as the shipped ticket (rerun, rebase, title edit): keep it, untouched.
    if (
        not existing
        and released
        and ticket_advisories(notion.children(released["id"]))
        == triage_advisories(triage)
    ):
        return released
    if existing:
        properties = ticket_properties(schema, triage, pr_url, settings)
        page = notion.update(
            existing["id"], {key: properties[key] for key in ("Name", "Priority")}
        )
        notion.refresh_summary(existing["id"], summary_blocks(triage, pr_url, settings)[1:])
        return page
    return notion.create(
        ticket_properties(schema, triage, pr_url, settings),
        ticket_content(triage, pr_url, settings),
    )


def release(notion: Notion, pr_url: str) -> dict | None:
    existing = open_ticket(notion.tickets_for_pr(pr_url))
    if not existing:
        return None
    schema = notion.schema()
    return notion.update(
        existing["id"],
        {
            "Status": option_value(schema, "Status", "Released"),
            "Release date": {
                "date": {
                    "start": datetime.datetime.now(tz=datetime.UTC).date().isoformat()
                }
            },
        },
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["upsert", "release"])
    parser.add_argument("--pr-url", required=True)
    parser.add_argument("--triage", default="triage.json")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--data-source-id", default=TICKETS_DATA_SOURCE_ID)
    parser.add_argument(
        "--repository",
        default=os.environ.get("GITHUB_REPOSITORY", "repository").rsplit("/", 1)[-1],
    )
    parser.add_argument("--project", default="Technique", help="Option prefix, empty to skip")
    parser.add_argument("--sub-tech-team", default="", help="Option prefix, empty to skip")
    parser.add_argument("--type", default="Vulnerability")
    parser.add_argument("--environment", default="Production")
    args = parser.parse_args(argv)
    settings = Settings(
        repository=args.repository,
        data_source_id=args.data_source_id,
        options={
            "Type": args.type,
            "Project": args.project,
            "Sub-Tech-Team": args.sub_tech_team,
            "Environment": args.environment,
        },
    )

    if args.dry_run:
        with open(args.triage) as handle:
            triage = json.load(handle)
        print(
            json.dumps(
                {
                    "title": ticket_title(triage, settings),
                    "children": ticket_content(triage, args.pr_url, settings),
                },
                indent=2,
                ensure_ascii=False,
            )
        )
        return 0

    notion = Notion(os.environ["NOTION_TOKEN"], settings.data_source_id)
    if args.command == "upsert":
        with open(args.triage) as handle:
            page = upsert(notion, json.load(handle), args.pr_url, settings)
    else:
        page = release(notion, args.pr_url)
        if page is None:
            print(f"No Notion ticket linked to {args.pr_url}")
            return 0

    write_github_output({"ticket_id": ticket_id(page), "ticket_url": page["url"]})
    print(f"{ticket_id(page)} {page['url']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

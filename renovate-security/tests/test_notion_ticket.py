import pytest

from renovate_security import notion_ticket

SETTINGS = notion_ticket.Settings(
    repository="ray-serve-models",
    options={
        "Type": "Vulnerability",
        "Project": "Technique",
        "Sub-Tech-Team": "ML/Data Engineer",
        "Environment": "Production",
    },
)

SCHEMA = {
    "Priority": {
        "type": "select",
        "select": {
            "options": [
                {"name": "P1 - Urgent 🔥🔥🔥"},
                {"name": "P2 - ASAP 💥"},
                {"name": "P3 - Soon/In sprint 🆒"},
                {"name": "P4 - If time ⬇️"},
            ]
        },
    },
    "Type": {
        "type": "select",
        "select": {"options": [{"name": "bug 🐛"}, {"name": "Vulnerability"}]},
    },
    "Project": {
        "type": "multi_select",
        "multi_select": {"options": [{"name": "CI"}, {"name": "Technique"}]},
    },
    "Sub-Tech-Team": {
        "type": "multi_select",
        "multi_select": {"options": [{"name": "Back"}, {"name": "ML/Data Engineer"}]},
    },
    "Environment": {
        "type": "multi_select",
        "multi_select": {"options": [{"name": "Production"}]},
    },
    "Status": {
        "type": "status",
        "status": {"options": [{"name": "Developing 🏗"}, {"name": "Released ✅"}]},
    },
}

TRIAGE = {
    "tier": "hotfix",
    "max_cvss": 9.8,
    "fixes": [
        {
            "name": "jinja2",
            "old": "3.1.2",
            "new": "3.1.6",
            "advisories": [
                {
                    "id": "GHSA-1",
                    "cve_id": None,
                    "summary": "RCE",
                    "url": "https://github.com/advisories/GHSA-1",
                    "severity": "critical",
                    "score": 9.8,
                }
            ],
        }
    ],
}


@pytest.mark.parametrize(
    ("score", "prefix"),
    [(9.8, "P1"), (9.0, "P1"), (7.0, "P2"), (4.0, "P3"), (3.9, "P4"), (None, "P3")],
)
def test_priority_prefix(score, prefix):
    assert notion_ticket.priority_prefix(score) == prefix


def test_option_value_resolves_emoji_names_and_property_kind():
    assert notion_ticket.option_value(SCHEMA, "Priority", "P1") == {
        "select": {"name": "P1 - Urgent 🔥🔥🔥"}
    }
    assert notion_ticket.option_value(SCHEMA, "Project", "Technique") == {
        "multi_select": [{"name": "Technique"}]
    }
    assert notion_ticket.option_value(SCHEMA, "Status", "Released") == {
        "status": {"name": "Released ✅"}
    }


def test_option_value_fails_on_unknown_option():
    with pytest.raises(KeyError):
        notion_ticket.option_value(SCHEMA, "Type", "Epic")


def test_ticket_properties():
    properties = notion_ticket.ticket_properties(
        SCHEMA, TRIAGE, "https://github.com/algoan/ray-serve-models/pull/1", SETTINGS
    )
    assert (
        properties["Name"]["title"][0]["text"]["content"]
        == "[DEPS] Security update of jinja2 on ray-serve-models"
    )
    assert properties["Priority"] == {"select": {"name": "P1 - Urgent 🔥🔥🔥"}}
    assert properties["Type"] == {"select": {"name": "Vulnerability"}}
    assert properties["Sub-Tech-Team"] == {
        "multi_select": [{"name": "ML/Data Engineer"}]
    }
    assert properties["Git Pull Request"] == {
        "url": "https://github.com/algoan/ray-serve-models/pull/1"
    }


def test_ticket_content_lists_each_advisory():
    blocks = notion_ticket.ticket_content(
        TRIAGE, "https://github.com/algoan/ray-serve-models/pull/1", SETTINGS
    )
    bullets = [b for b in blocks if b["type"] == "bulleted_list_item"]
    assert len(bullets) == 1
    assert bullets[0]["bulleted_list_item"]["rich_text"][0]["text"]["link"] == {
        "url": "https://github.com/advisories/GHSA-1"
    }


def test_ticket_id():
    page = {"properties": {"ID": {"unique_id": {"prefix": "ALG", "number": 5440}}}}
    assert notion_ticket.ticket_id(page) == "ALG-5440"


def heading(block_id, text):
    return {
        "id": block_id,
        "type": "heading_3",
        "heading_3": {"rich_text": [{"plain_text": text}]},
    }


def paragraph(block_id):
    return {"id": block_id, "type": "paragraph", "paragraph": {"rich_text": []}}


def test_generated_blocks_spans_description_to_how_to_test():
    children = [
        heading("d", "Description"),
        paragraph("p1"),
        heading("v", "Vulnerabilities"),
        paragraph("b1"),
        heading("h", "How to test"),
        paragraph("t"),
    ]
    assert notion_ticket.generated_blocks(children) == ("d", ["p1", "v", "b1"])


def test_generated_blocks_ignores_edited_layout():
    assert (
        notion_ticket.generated_blocks(
            [heading("h", "How to test"), heading("d", "Description")]
        )
        is None
    )
    assert notion_ticket.generated_blocks([heading("d", "Description")]) is None


def test_ticket_content_starts_with_the_generated_summary():
    content = notion_ticket.ticket_content(
        TRIAGE, "https://github.com/algoan/ray-serve-models/pull/1", SETTINGS
    )
    summary = notion_ticket.summary_blocks(
        TRIAGE, "https://github.com/algoan/ray-serve-models/pull/1", SETTINGS
    )
    assert content[: len(summary)] == summary
    assert (
        content[len(summary)]["heading_3"]["rich_text"][0]["text"]["content"]
        == "How to test"
    )


def page(page_id, status):
    return {
        "id": page_id,
        "properties": {"Status": {"status": {"name": status} if status else None}},
    }


def test_open_ticket_skips_released_tickets():
    pages = [
        page("new", "Released ✅"),
        page("older", "Developing 🏗"),
        page("oldest", None),
    ]
    assert notion_ticket.open_ticket(pages)["id"] == "older"
    assert notion_ticket.open_ticket([page("done", "Released ✅")]) is None
    assert notion_ticket.open_ticket([]) is None


def bullet(text):
    return {
        "type": "bulleted_list_item",
        "bulleted_list_item": {"rich_text": [{"plain_text": text}]},
    }


def test_ticket_advisories_reads_generated_bullets():
    children = [
        heading("v", "Vulnerabilities"),
        bullet("GHSA-1 (CVE-1) — jinja2 3.1.2 → 3.1.6 — CVSS 9.8 — RCE"),
        bullet("a note"),
    ]
    assert notion_ticket.ticket_advisories(children) == {"GHSA-1"}
    assert notion_ticket.triage_advisories(TRIAGE) == {"GHSA-1"}


class FakeNotion:
    def __init__(self, tickets, children):
        self.tickets, self._children, self.calls = tickets, children, []

    def schema(self):
        return SCHEMA

    def tickets_for_pr(self, pr_url):
        return self.tickets

    def children(self, page_id):
        return self._children

    def create(self, properties, children):
        self.calls.append("create")
        return {"id": "created"}

    def update(self, page_id, properties):
        self.calls.append(("update", page_id))
        return {"id": page_id}

    def refresh_summary(self, page_id, blocks):
        self.calls.append(("refresh", page_id))


def test_upsert_reuses_released_ticket_when_fixes_are_unchanged():
    notion = FakeNotion(
        [page("shipped", "Released ✅")], [bullet("GHSA-1 (no CVE) — jinja2")]
    )
    assert notion_ticket.upsert(notion, TRIAGE, "url", SETTINGS)["id"] == "shipped"
    assert notion.calls == []


def test_upsert_creates_a_new_ticket_for_new_fixes_after_release():
    notion = FakeNotion(
        [page("shipped", "Released ✅")], [bullet("GHSA-OLD (no CVE) — jinja2")]
    )
    assert notion_ticket.upsert(notion, TRIAGE, "url", SETTINGS)["id"] == "created"


class RecordingNotion(notion_ticket.Notion):
    def __init__(self, pages=None):
        super().__init__("token", "ds")
        self.calls, self.pages = [], pages or []

    def request(self, method, path, body=None):
        self.calls.append((method, path, body))
        if method == "POST" and path == "/pages":
            return {"id": "page"}
        if method == "PATCH":
            return {"results": [{"id": f"b{len(self.calls)}-{i}"} for i in range(len(body["children"]))]}
        if method == "GET":
            return self.pages.pop(0)
        return {}


def test_create_appends_blocks_beyond_the_notion_limit():
    notion = RecordingNotion()
    blocks = [{"n": i} for i in range(230)]
    notion.create({}, blocks)
    sent = [body["children"] for _, _, body in notion.calls]
    assert [len(chunk) for chunk in sent] == [100, 100, 30]
    assert [b for chunk in sent for b in chunk] == blocks
    assert all("after" not in body for _, path, body in notion.calls if path != "/pages")


def test_create_trashes_a_partial_ticket():
    class FailingAppend(RecordingNotion):
        def request(self, method, path, body=None):
            if method == "PATCH" and path.endswith("/children"):
                raise OSError("rate limited")
            if method == "PATCH":
                self.calls.append((method, path, body))
                return {}
            return super().request(method, path, body)

    notion = FailingAppend()
    with pytest.raises(OSError):
        notion.create({}, [{"n": i} for i in range(150)])
    assert notion.calls[-1] == ("PATCH", "/pages/page", {"in_trash": True})


def test_refresh_keeps_order_after_the_anchor_and_paginates_reads():
    first = {"results": [heading("d", "Description"), paragraph("old")], "has_more": True, "next_cursor": "c1"}
    second = {"results": [heading("h", "How to test")], "has_more": False}
    notion = RecordingNotion([first, second])
    notion.refresh_summary("page", [{"n": i} for i in range(150)])
    gets = [path for method, path, _ in notion.calls if method == "GET"]
    assert gets[1].endswith("&start_cursor=c1")
    assert ("DELETE", "/blocks/old", None) in notion.calls
    patches = [body for method, _, body in notion.calls if method == "PATCH"]
    assert patches[0]["after"] == "d"
    assert patches[1]["after"] == f"b{len(notion.calls) - 1}-99"

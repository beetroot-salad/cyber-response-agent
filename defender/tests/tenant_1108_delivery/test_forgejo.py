"""A5/C19/C21: observed Forgejo wire format, pagination and fail-closed protection."""
from __future__ import annotations

import importlib
import json

import httpx
import pytest

from ._support import ORIGIN, TOKEN, ForgeHTTP


def forge(http):
    cls = importlib.import_module("defender.learning.author.forge").ForgejoForge
    return cls(origin=ORIGIN, token=TOKEN, client=http.client)


def row(number, head):
    return {"number": number, "head": {"ref": head},
            "html_url": f"http://forge.invalid:3000/tenants/blue/pulls/{number}"}


def test_open_pr_listing_traverses_pages_and_filters_head_prefix():
    http = ForgeHTTP()
    http.pages = {1: [row(1, "unrelated"), row(2, "lessons/a")],
                  2: [row(3, "lessons/b"), row(4, "lead-author/c")]}
    result = forge(http).list_open_prs("lessons/")
    assert result == [{"number": 2, "headRefName": "lessons/a", "url": row(2, "")["html_url"]},
                      {"number": 3, "headRefName": "lessons/b", "url": row(3, "")["html_url"]}]
    assert len(http.requests) == 2
    assert all(r.url.params["state"] == "open" for r in http.requests)
    assert all(TOKEN in r.headers["Authorization"] for r in http.requests)


def test_exact_head_lookup_does_not_accept_prefix_match():
    http = ForgeHTTP()
    http.pages = {1: [row(1, "lessons/ab"), row(2, "lessons/a")]}
    assert forge(http).list_prs_for_head("lessons/a") == [
        {"number": 2, "headRefName": "lessons/a", "url": row(2, "")["html_url"]}]


def test_create_sends_all_pr_fields_to_origin_repository():
    http = ForgeHTTP()
    url = forge(http).open_pr(base="main", head="lessons/a", title="tenant change", body="agent/lessons/a.md")
    request = http.requests[0]
    assert request.method == "POST"
    assert request.url == "http://forge.invalid:3000/api/v1/repos/tenants/blue/pulls"
    assert json.loads(request.content) == {"base": "main", "head": "lessons/a",
                                          "title": "tenant change", "body": "agent/lessons/a.md"}
    assert url.endswith("/tenants/blue/pulls/7")


@pytest.mark.parametrize("response", [httpx.Response(403, json={"message": "denied"}),
                                      httpx.Response(200, text="not json"),
                                      httpx.Response(200, json={"protected": True})])
def test_protection_read_failure_or_unknown_push_permission_refuses(response):
    from defender.learning.author.forge import ForgeError
    calls = []
    def reply(request):
        calls.append(request)
        return response
    client = httpx.Client(transport=httpx.MockTransport(reply))
    cls = importlib.import_module("defender.learning.author.forge").ForgejoForge
    with pytest.raises(ForgeError, match="protect|push|403|JSON|main"):
        cls(origin=ORIGIN, token=TOKEN, client=client).verify_main_protection()
    assert calls[0].url.path.endswith("/branches/main")


def test_protection_verification_reads_branch_but_never_changes_rules():
    http = ForgeHTTP()
    forge(http).verify_main_protection()
    assert [(r.method, r.url.path) for r in http.requests] == [
        ("GET", "/api/v1/repos/tenants/blue/branches/main")]

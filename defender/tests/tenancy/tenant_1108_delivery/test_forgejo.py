from __future__ import annotations

import importlib
import json

import httpx
import pytest

from ._identity import identity as fixture_identity

from ._support import (
    FORK,
    NAMESAKE,
    ORIGIN,
    RENAMED,
    SIBLING_FORK,
    TOKEN,
    ForgeHTTP,
    bounded,
    pr_row,
)


def _forge_module():
    return importlib.import_module("defender.learning.author.version_control.forgejo")


def forge(http, origin=ORIGIN):
    return _forge_module().ForgejoForge(origin=origin, identity=fixture_identity(), client=http.client)


def row(number, head):
    return pr_row(number, head)


def normalized(number, head):
    return {"number": number, "headRefName": head, "url": row(number, head)["html_url"]}


def _pages_asked(http):
    """The page numbers the listing requests asked for, in order (every one must name a page
    and a limit)."""
    listed = http.listed()
    assert all(page is not None and limit is not None and int(limit) > 0 for _, page, limit in listed), listed
    return [int(page) for _, page, _ in listed]


def _all_ours(http):
    """Every request went to our repository at our address, with the token."""
    assert http.foreign == [], [str(r.url) for r in http.foreign]
    assert all(TOKEN in r.headers["Authorization"] for r in http.requests)


def test_open_pr_listing_traverses_pages_and_filters_head_prefix():
    http = ForgeHTTP()
    http.pages = {1: [row(1, "unrelated"), row(2, "lessons/a")],
                  2: [row(3, "lessons/b"), row(4, "lead-author/c")]}
    result = forge(http).list_open_prs("lessons/")
    assert result == [normalized(2, "lessons/a"), normalized(3, "lessons/b")]
    assert _pages_asked(http)[:2] == [1, 2]
    assert all(state == "open" for state, _, _ in http.listed())
    _all_ours(http)


def test_create_sends_all_pr_fields_to_origin_repository():
    http = ForgeHTTP()
    url = forge(http).open_pr(base="main", head="lessons/a", title="tenant change", body="agent/lessons/a.md")
    [request] = [r for r in http.requests if r.method == "POST"]
    assert request.url == "http://forge.invalid:3000/api/v1/repos/tenants/blue/pulls"
    assert json.loads(request.content) == {"base": "main", "head": "lessons/a",
                                          "title": "tenant change", "body": "agent/lessons/a.md"}
    assert url.endswith("/tenants/blue/pulls/7")
    _all_ours(http)


#: Every forge call, as the host makes it.
_FORGE_CALLS = {
    "verify_main_protection": lambda f: f.verify_main_protection(),
    "list_open_prs": lambda f: f.list_open_prs("lessons/"),
    "open_pr": lambda f: f.open_pr(base="main", head="lessons/a", title="t", body="b"),
}


@pytest.mark.parametrize("fault", [httpx.ConnectError, httpx.ReadTimeout, httpx.RemoteProtocolError],
                         ids=["connect", "read-timeout", "protocol"])
@pytest.mark.parametrize("call", sorted(_FORGE_CALLS))
def test_a_transport_fault_is_a_forge_error(fault, call):
    http = ForgeHTTP()
    http.fault = lambda request: fault("the forge's transport failed", request=request)
    with pytest.raises(_forge_module().ForgeError):
        _FORGE_CALLS[call](forge(http))
    assert http.requests


@pytest.mark.parametrize("response", [httpx.Response(403, json={"message": "denied"}),
                                      httpx.Response(200, text="not json"),
                                      httpx.Response(200, json={"protected": True}),
                                      *[httpx.Response(200, text=value) for value in
                                        ["null", "[]", "true", "1", '"main"']]])
def test_protection_read_failure_or_unknown_push_permission_refuses(response):
    calls = []

    def reply(request):
        calls.append(request)
        return response
    client = httpx.Client(transport=httpx.MockTransport(reply))
    with pytest.raises(_forge_module().ForgeError, match="protect|push|403|JSON|main"):
        _forge_module().ForgejoForge(origin=ORIGIN, identity=fixture_identity(), client=client).verify_main_protection()
    assert any(call.url.path.endswith("/branches/main") for call in calls)


def test_protection_verification_reads_branch_but_never_changes_rules():
    http = ForgeHTTP()
    forge(http).verify_main_protection()
    assert ("GET", "/api/v1/repos/tenants/blue/branches/main") in [(r.method, r.url.path) for r in http.requests]
    assert {r.method for r in http.requests} == {"GET"}


def test_the_origin_is_parsed_once_into_one_forge_address():
    address = _forge_module().ForgeAddress
    ours = address.parse(ORIGIN)
    assert (ours.scheme, ours.host, ours.port, ours.owner, ours.repo) == (
        "http", "forge.invalid", 3000, "tenants", "blue")
    assert address.parse("HTTP://Forge.INVALID:3000/tenants/blue.git") == ours
    assert address.parse("http://forge.invalid:3000/tenants/blue") == ours
    assert address.parse("http://forge.invalid/tenants/blue.git").port == 80
    assert address.parse("https://forge.invalid/tenants/blue.git").port == 443
    assert address.parse("http://forge.invalid:80/tenants/blue.git") == \
        address.parse("http://forge.invalid/tenants/blue.git")
    for other in ("https://forge.invalid:3000/tenants/blue.git", "http://other.invalid:3000/tenants/blue.git",
                  "http://forge.invalid:3001/tenants/blue.git", "http://forge.invalid:3000/tenants/red.git",
                  "http://forge.invalid:3000/mallory/blue.git"):
        assert address.parse(other) != ours, other
    assert forge(ForgeHTTP()).address == ours


def test_owner_and_repository_compare_without_case():
    address = _forge_module().ForgeAddress
    cased = "http://forge.invalid:3000/Tenants/Blue.git"
    assert address.parse(cased) == address.parse(ORIGIN)
    assert address.parse("HTTP://FORGE.INVALID:3000/TENANTS/BLUE") == address.parse(ORIGIN)
    assert address.parse("http://forge.invalid:3000/Tenants/Red.git") != address.parse(ORIGIN)
    http = ForgeHTTP(origin=cased)
    http.pages = {1: [pr_row(1, "lessons/a", repo=FORK), pr_row(2, "lessons/a")],
                  2: [pr_row(3, "lessons/b", repo=SIBLING_FORK), pr_row(4, "lessons/b")]}
    assert forge(http, origin=cased).list_open_prs("lessons/") == [normalized(2, "lessons/a"),
                                                                   normalized(4, "lessons/b")]
    _all_ours(http)


@pytest.mark.parametrize("origin", ["ssh://git@forge.invalid/tenants/blue.git", "/srv/tenants/blue.git",
                                    "file:///srv/tenants/blue.git", "http://forge.invalid:3000/blue.git",
                                    "http://forge.invalid:3000/a/tenants/blue.git",
                                    "http://forge.invalid:bad/tenants/blue.git", "http:///tenants/blue.git"])
def test_an_origin_that_is_not_one_forge_repository_is_refused(origin):
    """O-G fails closed: no network scheme, no host, a bad port, or a path that is not
    exactly owner and repository is a `ForgeError` naming the origin, before any request."""
    http = ForgeHTTP()
    with pytest.raises(_forge_module().ForgeError):
        _forge_module().ForgeAddress.parse(origin)
    with pytest.raises(_forge_module().ForgeError):
        forge(http, origin=origin)
    assert http.requests == []


_LINKS = {
    "internal-root-url": None,
    "other-host": "http://other.invalid:3000/api/v1/repos/tenants/blue/pulls?page=2",
    "other-scheme": "https://forge.invalid:3000/api/v1/repos/tenants/blue/pulls?page=2",
    "other-port": "http://forge.invalid:3001/api/v1/repos/tenants/blue/pulls?page=2",
    "other-repository": "http://forge.invalid:3000/api/v1/repos/mallory/blue/pulls?page=2",
    "prefix-repository": "http://forge.invalid:3000/api/v1/repos/tenants/blue-fork/pulls?page=2",
    "dot-segments": "http://forge.invalid:3000/api/v1/repos/tenants/blue/../../mallory/blue/pulls?page=2",
    "bad-port": "http://forge.invalid:bad/api/v1/repos/tenants/blue/pulls?state=open&page=2",
    "bad-ipv6": "http://[invalid]/api/v1/repos/tenants/blue/pulls?page=2",
    "own-address-skipping": "http://forge.invalid:3000/api/v1/repos/tenants/blue/pulls?state=open&page=3&limit=2",
}


def _stored(http, heads):
    for number, head in enumerate(heads, start=1):
        http.add_pr(row(number, head))


@pytest.mark.parametrize("link", sorted(_LINKS))
def test_listings_ask_our_address_for_each_page_and_never_follow_link(link):
    http = ForgeHTTP()
    http.page_size = 2
    http.link = _LINKS[link]
    _stored(http, ["lessons/ab", "unrelated", "lessons/b", "lessons/a", "lessons/a"])
    found = forge(http).list_open_prs("lessons/a")
    assert found == [normalized(1, "lessons/ab"), normalized(4, "lessons/a"),
                     normalized(5, "lessons/a")]
    assert _pages_asked(http)[:3] == [1, 2, 3]
    _all_ours(http)


def test_a_listing_goes_on_past_a_page_the_server_clamped():
    http = ForgeHTTP()
    http.page_size = 1
    _stored(http, ["lessons/b", "unrelated", "lessons/a"])
    assert forge(http).list_open_prs("lessons/") == [normalized(1, "lessons/b"), normalized(3, "lessons/a")]
    assert _pages_asked(http)[:3] == [1, 2, 3]
    _all_ours(http)


@pytest.mark.parametrize("total", [True, False], ids=["with-total-count", "without-total-count"])
def test_a_long_listing_is_read_to_its_end(total):
    http = ForgeHTTP()
    http.page_size = 5
    http.total_count = total
    _stored(http, [*(f"unrelated/{n}" for n in range(259)), "lessons/a"])
    assert forge(http).list_open_prs("lessons/") == [normalized(260, "lessons/a")]
    assert _pages_asked(http)[:52] == list(range(1, 53))


@pytest.mark.parametrize("value", ["many", "1.5", "0x10"])
def test_a_total_count_that_is_not_a_number_is_a_forge_error(value):
    """Refusal contract (deck #677; orchestrator ruling): an `X-Total-Count` that is not a
    whole number is a `ForgeError`, never a `ValueError` escaping the forge."""
    http = ForgeHTTP()
    http.total_count = value
    http.pages = {1: [row(1, "lessons/a")]}
    with pytest.raises(_forge_module().ForgeError):
        forge(http).list_open_prs("lessons/")


@pytest.mark.parametrize("total", [True, False], ids=["with-total-count", "without-total-count"])
def test_a_short_page_before_the_end_is_not_the_end(total):
    http = ForgeHTTP()
    http.total_count = total
    http.pages = {1: [row(1, "lessons/a"), row(2, "lessons/b")], 2: [row(3, "lessons/c")],
                  3: [row(4, "lessons/d"), row(5, "lessons/e")]}
    found = forge(http).list_open_prs("lessons/")
    assert found == [normalized(n, f"lessons/{c}") for n, c in zip(range(1, 6), "abcde", strict=True)]
    pages = _pages_asked(http)
    assert pages[:3] == [1, 2, 3]
    if not total:
        assert pages == [1, 2, 3, 4], "without X-Total-Count only an empty page ends the listing"


def test_a_server_that_ignores_the_page_is_read_once_by_its_total_count():
    http = ForgeHTTP()
    http.every_page = [pr_row(1, "lessons/a", repo=FORK), pr_row(2, "lessons/a")]
    found, error, hung = bounded(lambda: forge(http).list_open_prs("lessons/"))
    assert not hung, "the listing never stopped"
    assert error is None, error
    assert found == [normalized(2, "lessons/a")]
    assert _pages_asked(http) == [1]


@pytest.mark.parametrize(("origin", "address"), [
    ("http://FORGE.INVALID:3000/tenants/blue.git", ("http", "forge.invalid", 3000)),
    ("HTTP://forge.invalid:3000/tenants/blue.git", ("http", "forge.invalid", 3000)),
    ("http://forge.invalid/tenants/blue.git", ("http", "forge.invalid", 80)),
    ("http://forge.invalid:80/tenants/blue.git", ("http", "forge.invalid", 80)),
    ("https://forge.invalid/tenants/blue.git", ("https", "forge.invalid", 443)),
])
def test_every_page_is_asked_of_the_parsed_address(origin, address):
    http = ForgeHTTP(origin=origin)
    http.pages = {1: [row(1, "lessons/ab")], 2: [row(2, "lessons/a")]}
    result = forge(http, origin=origin).list_open_prs("lessons/a")
    assert result == [normalized(1, "lessons/ab"), normalized(2, "lessons/a")]
    assert {(r.url.scheme, r.url.host, r.url.port or {"http": 80, "https": 443}[r.url.scheme])
            for r in http.requests} == {address}
    _all_ours(http)


def test_prefix_listing_counts_only_prs_whose_head_is_the_base_repository():
    """O-G (review finding #9): forks, under another owner or beside ours under the same
    owner, are not ours even when their head branch matches the prefix."""
    http = ForgeHTTP()
    http.pages = {1: [pr_row(1, "lessons/a", repo=FORK), pr_row(2, "lessons/b")],
                  2: [pr_row(3, "lessons/c", repo=SIBLING_FORK), pr_row(4, "lessons/d")]}
    assert forge(http).list_open_prs("lessons/") == [normalized(2, "lessons/b"),
                                                     normalized(4, "lessons/d")]


@pytest.mark.parametrize("fork", [FORK, SIBLING_FORK], ids=["other-owner", "same-owner"])
def test_a_listing_ignores_a_fork_with_the_same_branch_name(fork):
    http = ForgeHTTP()
    http.pages = {1: [pr_row(1, "lessons/a", repo=fork)], 2: [pr_row(2, "lessons/a")]}
    assert forge(http).list_open_prs("lessons/a") == [normalized(2, "lessons/a")]
    http.pages = {1: [pr_row(1, "lessons/a", repo=fork)]}
    assert forge(http).list_open_prs("lessons/a") == []


def test_repository_identity_is_the_repository_id():
    http = ForgeHTTP()
    http.pages = {1: [pr_row(1, "lessons/a", repo=NAMESAKE), pr_row(2, "lessons/a", repo=RENAMED)]}
    assert forge(http).list_open_prs("lessons/") == [normalized(2, "lessons/a")]


# `test_the_writer_lease_is_not_held_by_a_fork_pr` (the lease on `AuthorBranch`) is deleted with
# `AuthorBranch` (#1108 P4, OD12 class (i)). The writer lease is now pinned at the drains' real
# entry: `tenant_1108_p4/test_drains.py::test_od8_an_open_tenant_pr_of_the_lane_holds_the_writer_
# lease_and_nothing_else_does` (ours, a fork, a sibling fork, a namesake, no head repository, the
# other lane), on both drains; the listing's identity rules stay pinned above.


def test_a_pr_row_without_its_head_repository_is_skipped():
    http = ForgeHTTP()
    http.pages = {1: [pr_row(1, "lessons/a", repo=None), pr_row(2, "lessons/a")],
                  2: [pr_row(3, "lessons/a", repo=None)]}
    assert forge(http).list_open_prs("lessons/") == [normalized(2, "lessons/a")]


@pytest.mark.parametrize("origin", ['http://forge.invalid/tenants/blue.git\n',
    'http://forge.invalid"/tenants/blue.git', 'http://forge.invalid/tenants/blue.git\\'])
def test_origin_cannot_inject_transport_configuration(origin):
    http = ForgeHTTP()
    with pytest.raises(_forge_module().ForgeError):
        forge(http, origin)
    assert http.requests == []

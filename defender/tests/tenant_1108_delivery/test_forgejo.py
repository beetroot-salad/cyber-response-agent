"""A5/C19/C21, amendment 2's O-G and amendment 3's C4: the observed Forgejo wire format, one
parsed forge address that every request goes to (pages asked for by number, Forgejo's `Link`
never followed), repository identity by id (forks, namesakes and rows without a head
repository are not ours), and fail-closed protection."""
from __future__ import annotations

import importlib
import json

import httpx
import pytest

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
    return importlib.import_module("defender.learning.author.forge")


def forge(http, origin=ORIGIN):
    return _forge_module().ForgejoForge(origin=origin, token=TOKEN, client=http.client)


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


def test_exact_head_lookup_does_not_accept_prefix_match():
    http = ForgeHTTP()
    http.pages = {1: [row(1, "lessons/ab"), row(2, "lessons/a")]}
    assert forge(http).list_prs_for_head("lessons/a") == [normalized(2, "lessons/a")]


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
    "list_prs_for_head": lambda f: f.list_prs_for_head("lessons/a"),
    "open_pr": lambda f: f.open_pr(base="main", head="lessons/a", title="t", body="b"),
}


@pytest.mark.parametrize("fault", [httpx.ConnectError, httpx.ReadTimeout, httpx.RemoteProtocolError],
                         ids=["connect", "read-timeout", "protocol"])
@pytest.mark.parametrize("call", sorted(_FORGE_CALLS))
def test_a_transport_fault_is_a_forge_error(fault, call):
    """Refusal contract (deck #678): the forge unreachable, slow past the timeout, or
    speaking broken HTTP is a `ForgeError` from every call, like an HTTP error status, never
    an `httpx` exception escaping the forge."""
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
        _forge_module().ForgejoForge(origin=ORIGIN, token=TOKEN, client=client).verify_main_protection()
    assert any(call.url.path.endswith("/branches/main") for call in calls)


def test_protection_verification_reads_branch_but_never_changes_rules():
    http = ForgeHTTP()
    forge(http).verify_main_protection()
    assert ("GET", "/api/v1/repos/tenants/blue/branches/main") in [(r.method, r.url.path) for r in http.requests]
    assert {r.method for r in http.requests} == {"GET"}


# ---------------------------------------------------------------------------------------
# O-G: one parsed address
# ---------------------------------------------------------------------------------------

def test_the_origin_is_parsed_once_into_one_forge_address():
    """O-G: `ForgeAddress` holds scheme, host, port, owner and repo with the default port made
    explicit and scheme and host case folded, so equivalent spellings are one address; the
    forge keeps the one it parsed at construction. (Owner and repository case: the next
    test.)"""
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
    """O-G, orchestrator decision (README): Forgejo resolves owner and repository names
    without regard to case, so an origin spelling them in another case is the same address:
    equal once parsed, and under a cased origin the forge's own rows are counted as ours,
    every page asked of our address. A fork stays excluded."""
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
    assert forge(http, origin=cased).list_prs_for_head("lessons/a") == [normalized(2, "lessons/a")]
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


# ---------------------------------------------------------------------------------------
# C4: pages asked for by number on our own address; Forgejo's Link never followed
# ---------------------------------------------------------------------------------------

#: What Forgejo may put in `Link` (built from its `ROOT_URL`, not our address: review finding
#: #6), and worse: another host, scheme or port, another repository (one whose name begins
#: with ours, one reached through dot-segments), a URL that does not parse.
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
}


def _stored(http, heads):
    for number, head in enumerate(heads, start=1):
        http.add_pr(row(number, head))


@pytest.mark.parametrize("link", sorted(_LINKS))
@pytest.mark.parametrize("method", ["list_open_prs", "list_prs_for_head"])
def test_listings_ask_our_address_for_each_page_and_never_follow_link(link, method):
    """C4 / O-G (R6): a listing asks for `?page=N&limit=L` on the parsed address, pages 1, 2,
    3 in turn, and never follows or compares Forgejo's `Link`, whatever it names: no request
    goes anywhere but our repository at our address, every one carries the token, and every
    row past page 1 is found."""
    http = ForgeHTTP()
    http.page_size = 2
    http.link = _LINKS[link]
    _stored(http, ["lessons/ab", "unrelated", "lessons/b", "lessons/a", "lessons/a"])
    found = getattr(forge(http), method)("lessons/a")
    expected = [normalized(4, "lessons/a"), normalized(5, "lessons/a")]
    if method == "list_open_prs":
        expected = [normalized(1, "lessons/ab"), *expected]
    assert found == expected
    assert _pages_asked(http)[:3] == [1, 2, 3]
    _all_ours(http)


@pytest.mark.parametrize("method", ["list_open_prs", "list_prs_for_head"])
def test_a_listing_goes_on_past_a_page_the_server_clamped(method):
    """C4 (R6): the server clamps `limit` to its `max_response_items`, so a page shorter than
    the limit asked for is not the end: the listing goes on until the rows seen reach
    `X-Total-Count`, or a page comes back empty."""
    http = ForgeHTTP()
    http.page_size = 1
    _stored(http, ["lessons/b", "unrelated", "lessons/a"])
    if method == "list_open_prs":
        assert forge(http).list_open_prs("lessons/") == [normalized(1, "lessons/b"), normalized(3, "lessons/a")]
    else:
        assert forge(http).list_prs_for_head("lessons/a") == [normalized(3, "lessons/a")]
    assert _pages_asked(http)[:3] == [1, 2, 3]
    _all_ours(http)


@pytest.mark.parametrize("total", [True, False], ids=["with-total-count", "without-total-count"])
def test_a_short_page_before_the_end_is_not_the_end(total):
    """C4 (R6): a page shorter than the others is not the end. With `X-Total-Count` the
    listing goes on until the rows seen reach it; without the header it stops only at an
    empty page, which it must then ask for."""
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


@pytest.mark.parametrize("method", ["list_open_prs", "list_prs_for_head"])
def test_a_server_that_ignores_the_page_is_read_once_by_its_total_count(method):
    """C4: the rows seen are counted raw, before any fork or D-fork skip, against
    `X-Total-Count`. A server that answers every page with the same rows (here a fork's and
    ours: two rows, `X-Total-Count: 2`) is read once: one listing request, no row twice. A
    count of the kept rows only would ask again and find ours twice."""
    http = ForgeHTTP()
    http.every_page = [pr_row(1, "lessons/a", repo=FORK), pr_row(2, "lessons/a")]
    query = "lessons/" if method == "list_open_prs" else "lessons/a"
    found, error, hung = bounded(lambda: getattr(forge(http), method)(query))
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
@pytest.mark.parametrize("method", ["list_open_prs", "list_prs_for_head"])
def test_every_page_is_asked_of_the_parsed_address(origin, address, method):
    """O-G (review finding #6): whatever the origin's spelling (host or scheme case, a default
    port explicit or not), every request goes to the one parsed address, with the token, and
    page 2's rows count."""
    http = ForgeHTTP(origin=origin)
    http.pages = {1: [row(1, "lessons/ab")], 2: [row(2, "lessons/a")]}
    result = getattr(forge(http, origin=origin), method)("lessons/a")
    expected = [normalized(2, "lessons/a")]
    if method == "list_open_prs":
        expected = [normalized(1, "lessons/ab"), *expected]
    assert result == expected
    assert {(r.url.scheme, r.url.host, r.url.port or {"http": 80, "https": 443}[r.url.scheme])
            for r in http.requests} == {address}
    _all_ours(http)


# ---------------------------------------------------------------------------------------
# C1 / O-G: only PRs whose head repository id is the base repository's are ours (R10)
# ---------------------------------------------------------------------------------------

def test_prefix_listing_counts_only_prs_whose_head_is_the_base_repository():
    """O-G (review finding #9): forks, under another owner or beside ours under the same
    owner, are not ours even when their head branch matches the prefix."""
    http = ForgeHTTP()
    http.pages = {1: [pr_row(1, "lessons/a", repo=FORK), pr_row(2, "lessons/b")],
                  2: [pr_row(3, "lessons/c", repo=SIBLING_FORK), pr_row(4, "lessons/d")]}
    assert forge(http).list_open_prs("lessons/") == [normalized(2, "lessons/b"),
                                                     normalized(4, "lessons/d")]


@pytest.mark.parametrize("fork", [FORK, SIBLING_FORK], ids=["other-owner", "same-owner"])
def test_exact_head_lookup_ignores_a_fork_with_the_same_branch_name(fork):
    http = ForgeHTTP()
    http.pages = {1: [pr_row(1, "lessons/a", repo=fork)], 2: [pr_row(2, "lessons/a")]}
    assert forge(http).list_prs_for_head("lessons/a") == [normalized(2, "lessons/a")]
    http.pages = {1: [pr_row(1, "lessons/a", repo=fork)]}
    assert forge(http).list_prs_for_head("lessons/a") == []


@pytest.mark.parametrize("method", ["list_open_prs", "list_prs_for_head"])
def test_repository_identity_is_the_repository_id(method):
    """C1: a head repository is ours by its id, which a rename or a transfer keeps, not by its
    full name: our repository under another name is ours, and another repository that took
    our full name is not."""
    http = ForgeHTTP()
    http.pages = {1: [pr_row(1, "lessons/a", repo=NAMESAKE), pr_row(2, "lessons/a", repo=RENAMED)]}
    assert getattr(forge(http), method)("lessons/a" if method == "list_prs_for_head" else "lessons/") == \
        [normalized(2, "lessons/a")]


def test_the_writer_lease_is_not_held_by_a_fork_pr(tmp_path):
    """O-G on the prefix lease (`AuthorBranch.open_pr_exists`, the drain's writer lease): an
    open fork PR under the lessons prefix does not hold it, nor does a namesake's or a row
    with no head repository (D-fork); our own open PR does (control)."""
    from defender.learning.author.branch import AuthorBranch
    http = ForgeHTTP()
    branch = AuthorBranch(forge=forge(http), repo_root=tmp_path, branch_prefix="lessons/")
    others = [pr_row(1, "lessons/x", repo=FORK), pr_row(2, "lessons/y", repo=SIBLING_FORK),
              pr_row(5, "lessons/v", repo=NAMESAKE), pr_row(6, "lessons/w", repo=None)]
    http.pages = {1: others}
    assert branch.open_pr_exists() is False
    http.pages = {1: [*others, pr_row(3, "lessons/z")]}
    assert branch.open_pr_exists() is True


@pytest.mark.parametrize("method", ["list_open_prs", "list_prs_for_head"])
def test_a_pr_row_without_its_head_repository_is_skipped(method):
    """R10 (D-fork, the user's decision; it replaces choice 9's `ForgeError`): a row whose
    head repository is gone (Forgejo's listing of a deleted fork's PR) is skipped like any
    fork, in every listing, on any page; our own rows around it are found."""
    http = ForgeHTTP()
    http.pages = {1: [pr_row(1, "lessons/a", repo=None), pr_row(2, "lessons/a")],
                  2: [pr_row(3, "lessons/a", repo=None)]}
    assert getattr(forge(http), method)("lessons/a" if method == "list_prs_for_head" else "lessons/") == \
        [normalized(2, "lessons/a")]

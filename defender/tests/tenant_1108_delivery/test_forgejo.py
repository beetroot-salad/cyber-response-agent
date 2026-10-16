"""A5/C19/C21 and amendment 2's O-G: the observed Forgejo wire format, one parsed forge address,
pagination compared against it, fork exclusion, and fail-closed protection."""
from __future__ import annotations

import importlib
import json

import httpx
import pytest

from ._support import FORK, ORIGIN, SIBLING_FORK, TOKEN, ForgeHTTP, pr_row


def _forge_module():
    return importlib.import_module("defender.learning.author.forge")


def forge(http, origin=ORIGIN):
    return _forge_module().ForgejoForge(origin=origin, token=TOKEN, client=http.client)


def row(number, head):
    return pr_row(number, head)


def normalized(number, head):
    return {"number": number, "headRefName": head, "url": row(number, head)["html_url"]}


def test_open_pr_listing_traverses_pages_and_filters_head_prefix():
    http = ForgeHTTP()
    http.pages = {1: [row(1, "unrelated"), row(2, "lessons/a")],
                  2: [row(3, "lessons/b"), row(4, "lead-author/c")]}
    result = forge(http).list_open_prs("lessons/")
    assert result == [normalized(2, "lessons/a"), normalized(3, "lessons/b")]
    assert len(http.requests) == 2
    assert all(r.url.params["state"] == "open" for r in http.requests)
    assert all(TOKEN in r.headers["Authorization"] for r in http.requests)


def test_exact_head_lookup_does_not_accept_prefix_match():
    http = ForgeHTTP()
    http.pages = {1: [row(1, "lessons/ab"), row(2, "lessons/a")]}
    assert forge(http).list_prs_for_head("lessons/a") == [normalized(2, "lessons/a")]


def test_create_sends_all_pr_fields_to_origin_repository():
    http = ForgeHTTP()
    url = forge(http).open_pr(base="main", head="lessons/a", title="tenant change", body="agent/lessons/a.md")
    request = http.requests[0]
    assert request.method == "POST"
    assert request.url == "http://forge.invalid:3000/api/v1/repos/tenants/blue/pulls"
    assert json.loads(request.content) == {"base": "main", "head": "lessons/a",
                                          "title": "tenant change", "body": "agent/lessons/a.md"}
    assert url.endswith("/tenants/blue/pulls/7")


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
    assert calls[0].url.path.endswith("/branches/main")


def test_protection_verification_reads_branch_but_never_changes_rules():
    http = ForgeHTTP()
    forge(http).verify_main_protection()
    assert [(r.method, r.url.path) for r in http.requests] == [
        ("GET", "/api/v1/repos/tenants/blue/branches/main")]


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
    without regard to case, so an origin or a Link spelling them in another case is the same
    address: equal once parsed, its next page followed with the token, and the forge's own
    canonical rows counted as ours under a cased origin. A fork stays excluded."""
    address = _forge_module().ForgeAddress
    cased = "http://forge.invalid:3000/Tenants/Blue.git"
    assert address.parse(cased) == address.parse(ORIGIN)
    assert address.parse("HTTP://FORGE.INVALID:3000/TENANTS/BLUE") == address.parse(ORIGIN)
    assert address.parse("http://forge.invalid:3000/Tenants/Red.git") != address.parse(ORIGIN)
    for origin, next_url in [
            (ORIGIN, "http://forge.invalid:3000/api/v1/repos/Tenants/Blue/pulls?state=open&page=2"),
            (cased, "http://forge.invalid:3000/api/v1/repos/tenants/blue/pulls?state=open&page=2")]:
        calls, client = _paged([row(1, "lessons/ab")], next_url, [row(2, "lessons/a")])
        found = _forge_module().ForgejoForge(origin=origin, token=TOKEN, client=client).list_prs_for_head("lessons/a")
        assert found == [normalized(2, "lessons/a")], (origin, next_url)
        assert len(calls) == 2
        assert all(TOKEN in call.headers["Authorization"] for call in calls)
    http = ForgeHTTP()
    http.pages = {1: [pr_row(1, "lessons/a", repo=FORK), pr_row(2, "lessons/a"),
                      pr_row(3, "lessons/b", repo=SIBLING_FORK), pr_row(4, "lessons/b")]}
    assert forge(http, origin=cased).list_open_prs("lessons/") == [normalized(2, "lessons/a"),
                                                                   normalized(4, "lessons/b")]
    assert forge(http, origin=cased).list_prs_for_head("lessons/a") == [normalized(2, "lessons/a")]


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


def _paged(first_rows, next_url, second_rows):
    calls = []

    def reply(request):
        calls.append(request)
        if len(calls) == 1:
            return httpx.Response(200, json=first_rows, headers={"Link": f'<{next_url}>; rel="next"'})
        return httpx.Response(200, json=second_rows)
    return calls, httpx.Client(transport=httpx.MockTransport(reply))


@pytest.mark.parametrize("next_url", [
    "http://other.invalid:3000/api/v1/repos/tenants/blue/pulls?page=2",
    "https://forge.invalid:3000/api/v1/repos/tenants/blue/pulls?page=2",
    "http://forge.invalid:3001/api/v1/repos/tenants/blue/pulls?page=2",
    "http://forge.invalid:3000/api/v1/repos/tenants/red/pulls?page=2",
    "http://forge.invalid:3000/api/v1/repos/mallory/blue/pulls?page=2",
    "http://forge.invalid:3000/api/v1/repos/tenants/blue-fork/pulls?page=2",
    "http://forge.invalid:3000/api/v1/repos/tenants/blue/../../mallory/blue/pulls?page=2",
    "http://forge.invalid:bad/api/v1/repos/tenants/blue/pulls?state=open&page=2",
    "http://[invalid]/api/v1/repos/tenants/blue/pulls?page=2",
])
@pytest.mark.parametrize("method", ["list_open_prs", "list_prs_for_head"])
def test_pagination_refuses_outside_origin_repository_before_request(next_url, method):
    """O8/A5, O-G: an untrusted next-page Link that parses to another address, or does not
    parse, cannot redirect the bot token. The repository is compared exactly, on the parsed
    address: one whose name only begins with ours (`blue-fork`), or whose path reaches
    another repository through dot-segments while its text begins with ours, is not ours."""
    calls, client = _paged([row(1, "lessons/ab")], next_url, [])
    with pytest.raises(_forge_module().ForgeError, match="origin|host|repo|page|credential|[Ll]ink|URL|[Ii]nvalid (port|IPv6)"):
        getattr(_forge_module().ForgejoForge(origin=ORIGIN, token=TOKEN, client=client), method)("lessons/a")
    assert len(calls) == 1, "refuse the foreign Link before contacting its target"
    assert TOKEN in calls[0].headers["Authorization"]


@pytest.mark.parametrize(("origin", "next_url"), [
    (ORIGIN, "http://FORGE.INVALID:3000/api/v1/repos/tenants/blue/pulls?state=open&page=2"),
    (ORIGIN, "HTTP://forge.invalid:3000/api/v1/repos/tenants/blue/pulls?state=open&page=2"),
    ("http://forge.invalid/tenants/blue.git",
     "http://forge.invalid:80/api/v1/repos/tenants/blue/pulls?state=open&page=2"),
    ("http://forge.invalid:80/tenants/blue.git",
     "http://forge.invalid/api/v1/repos/tenants/blue/pulls?state=open&page=2"),
    ("https://forge.invalid/tenants/blue.git",
     "https://forge.invalid:443/api/v1/repos/tenants/blue/pulls?state=open&page=2"),
])
@pytest.mark.parametrize("method", ["list_open_prs", "list_prs_for_head"])
def test_pagination_follows_an_equivalent_spelling_of_the_origin(origin, next_url, method):
    """O-G (review finding #6): a Link spelling the same parsed address (host case, explicit
    or implicit default port, scheme case) is ours: the second page is fetched with the token
    and its rows count."""
    calls, client = _paged([row(1, "lessons/ab")], next_url, [row(2, "lessons/a")])
    result = getattr(_forge_module().ForgejoForge(origin=origin, token=TOKEN, client=client), method)("lessons/a")
    assert len(calls) == 2
    assert all(TOKEN in call.headers["Authorization"] for call in calls)
    assert calls[1].url.host == "forge.invalid"
    expected = [normalized(2, "lessons/a")]
    if method == "list_open_prs":
        expected = [normalized(1, "lessons/ab"), *expected]
    assert result == expected


def test_exact_head_lookup_traverses_same_origin_next_page_with_credentials():
    """O8/A5 positive control: accepted pagination still authenticates to the origin."""
    http = ForgeHTTP()
    http.pages = {1: [row(1, "lessons/ab")], 2: [row(2, "lessons/a")]}
    assert forge(http).list_prs_for_head("lessons/a") == [normalized(2, "lessons/a")]
    assert len(http.requests) == 2
    assert all(TOKEN in request.headers["Authorization"] for request in http.requests)


# ---------------------------------------------------------------------------------------
# O-G: only PRs whose head repository is the base repository are ours
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


def test_the_writer_lease_is_not_held_by_a_fork_pr(tmp_path):
    """O-G on the prefix lease (`AuthorBranch.open_pr_exists`, the drain's writer lease): an
    open fork PR under the lessons prefix does not hold it; our own open PR does (control)."""
    from defender.learning.author.branch import AuthorBranch
    http = ForgeHTTP()
    branch = AuthorBranch(forge=forge(http), repo_root=tmp_path, branch_prefix="lessons/")
    http.pages = {1: [pr_row(1, "lessons/x", repo=FORK), pr_row(2, "lessons/y", repo=SIBLING_FORK)]}
    assert branch.open_pr_exists() is False
    http.pages = {1: [pr_row(1, "lessons/x", repo=FORK), pr_row(3, "lessons/z")]}
    assert branch.open_pr_exists() is True


@pytest.mark.parametrize("method", ["list_open_prs", "list_prs_for_head"])
def test_a_pr_row_without_its_head_repository_is_a_forge_error(method):
    """PENDING A USER DECISION (README, choice 9). Fail closed: a row whose head repository
    is missing cannot be shown to be ours, and excluding it would release the lease; it is a
    `ForgeError`. Kept alone so the decision can change this case alone."""
    http = ForgeHTTP()
    http.pages = {1: [pr_row(1, "lessons/a", repo=None)]}
    with pytest.raises(_forge_module().ForgeError):
        getattr(forge(http), method)("lessons/a")

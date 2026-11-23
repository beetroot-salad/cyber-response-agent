"""#1471 (G-A11..G-A14, G-A8): the forge client gives a created PR's number and every row's `head.label`, and the forge double answers as the
live probes did. The doubles are asserted here so a later case that leans on them rests on observed behaviour."""
from __future__ import annotations

import pytest

from defender.learning.author.version_control import forgejo
from defender.learning.author.version_control.forgejo import ForgeError
from defender.tests.tenancy.tenant_1108_delivery._identity import identity as fixture_identity
from defender.tests.tenancy.tenant_1108_delivery._support import delivery, git, origin_of

from ._forge import AdoptionForge


def client(http, origin):
    return forgejo.ForgejoForge(origin=origin, identity=fixture_identity(), client=http.client)


@pytest.fixture
def served(repo):
    http = AdoptionForge()
    delivery(repo, http)  # points the double at the bare remote and the served origin
    git(repo[1], "update-ref", "refs/heads/adopt/x/aaaa", git(repo[1], "rev-parse", "refs/heads/main"))
    git(repo[1], "update-ref", "refs/heads/adopt/x/bbbb", git(repo[1], "rev-parse", "refs/heads/main"))
    return http, client(http, origin_of(repo))  # #1618 K8: no tenant clone; the origin the seed is served at


def _open(forge, head="adopt/x/aaaa"):
    return forge.open_pr(base="main", head=head, title="t", body="b")


def test_open_pr_answers_the_number_the_forge_gave_and_the_url(served):
    """`open_pr` returns the created PR's number (an int) with its URL. (r11 forge client)"""
    http, forge = served
    first, second = _open(forge, "adopt/x/aaaa"), _open(forge, "adopt/x/bbbb")
    assert (type(first.number), first.number + 1, second.number) == (int, second.number, first.number + 1)
    assert first.url.endswith(f"/pulls/{first.number}")
    assert second.url.endswith(f"/pulls/{second.number}")
    assert [r["number"] for r in http.prs] == [first.number, second.number]


def test_a_second_create_on_a_head_with_an_open_pr_is_a_409_forge_error(served):
    """G-A12: 409 `already exists`, read from `ForgeError.status`, and no second row."""
    http, forge = served
    _open(forge)
    with pytest.raises(ForgeError) as refused:
        _open(forge)
    assert refused.value.status == 409
    assert len(http.prs) == 1


def test_a_create_on_a_head_whose_pr_was_closed_is_201_and_a_new_pr(served):
    """G-A13: close, branch kept, create again: a new PR number."""
    http, forge = served
    first = _open(forge)
    http.settle(first.number, merged=False)
    again = _open(forge)
    assert again.number != first.number


def test_a_create_on_a_missing_head_is_a_404_forge_error(served):
    """G-A14: 404, not a 422."""
    _, forge = served
    with pytest.raises(ForgeError) as refused:
        _open(forge, "adopt/x/not-pushed")
    assert refused.value.status == 404


def test_a_row_carries_head_label_and_it_outlives_a_deleted_branch(served):
    """G-A11: open: `head_ref == head_label == branch`; after merge and delete `head_ref` is `refs/pull/N/head`, `head_label` the branch."""
    http, forge = served
    opened = _open(forge)
    [row] = forge.pull_requests()
    assert (row.head_ref, row.head_label) == ("adopt/x/aaaa", "adopt/x/aaaa")
    http.settle(opened.number, merged=True, delete_branch=True)
    [row] = forge.pull_requests()
    assert row.status == "merged"
    assert (row.head_ref, row.head_label) == (f"refs/pull/{opened.number}/head", "adopt/x/aaaa")
    assert forge.pull_request(opened.number).head_label == "adopt/x/aaaa"


def test_head_label_is_none_when_the_row_names_none(served):
    """A row whose head has no label reads `head_label` None (as `head_ref` is None when absent)."""
    http, forge = served
    row = http._row(9, "adopt/x/aaaa")
    del row["head"]["label"]
    http.add_pr(row)
    [read] = forge.pull_requests()
    assert read.head_label is None


def test_every_state_and_every_page_is_listed_with_its_label(served):
    """`pull_requests` reads open, merged and closed rows across pages (X-Total-Count), each with its label. (G-A8)"""
    http, forge = served
    http.page_size = 2
    numbers = []
    for n in range(5):
        git(http.remote, "update-ref", f"refs/heads/adopt/p/{n}", git(http.remote, "rev-parse", "refs/heads/main"))
        numbers.append(http.plant(f"adopt/p/{n}", state=("open", "merged", "closed")[n % 3], deleted=n == 1))
    rows = forge.pull_requests()
    assert sorted(r.number for r in rows) == sorted(numbers)
    assert {r.number: r.head_label for r in rows} == {num: f"adopt/p/{i}" for i, num in enumerate(numbers)}
    assert {r.status for r in rows} == {"open", "merged", "closed"}
    assert [p for _, p, _ in http.listed()][:3] == ["1", "2", "3"]

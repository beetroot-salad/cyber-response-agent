"""#1471 A3/A4/N-A1/N-A4/P-9: the adoption delivery step over a real bare remote and a forge answering as the live probes did
(G-A11..G-A14). `adopt(repository, system=, rendering=, digest=)` is given a test-chosen digest, so no case depends on how it is computed."""
from __future__ import annotations

import importlib
import re

import pytest

from defender.tests.tenancy.tenant_1108_delivery._support import (
    delivery,
    git,
    push_to_remote,
    remote_refs,
    git_bytes,
    target,
)

from defender.tests.tenancy.tenant_1108_delivery._clone_free_1618 import delivery_without_clone

from ._forge import (
    DIGEST,
    OTHER_DIGEST,
    RENDERING,
    SYSTEM,
    AdoptionForge,
    blobs_at,
    branch_for,
    commits_between,
    main_tip,
    racer_push,
    tree_diff,
)

BRANCH = branch_for(DIGEST)
OTHER_BRANCH = branch_for(OTHER_DIGEST)


def _adopt(repo, http, *, rendering=None, digest=DIGEST, system=SYSTEM):
    """The step over `repo`'s clone opened through the product's own `GitRepository.open` (so main's protection is verified)."""
    step = importlib.import_module("defender.learning.author.version_control.adoption")
    repository = delivery(repo, http).repository
    return step.adopt(repository, system=system, rendering=RENDERING if rendering is None else rendering, digest=digest)


def _outcome(record):
    return record.outcome, getattr(record, "pr_number", None)


def _land(repo, tmp_path, files, *, attributes=None):
    """A person's commit on the remote's `main` holding exactly `files` as blob bytes (no filter), as a merge of the offer would."""
    def edit(writer):
        if attributes is not None:
            (writer / ".gitattributes").write_text(attributes, encoding="utf-8")
            git(writer, "add", ".gitattributes")
        for path, data in files.items():
            oid = git_bytes(writer, "hash-object", "-w", "--no-filters", "--stdin", data=data).decode().strip()
            git(writer, "update-index", "--add", "--cacheinfo", f"100644,{oid},{path}")
    return push_to_remote(repo, tmp_path, edit, stage=False)


def _quiet(http, repo, main_before):
    """N-A1/N-A4: nothing merged, closed, deleted or reopened; main untouched; the only writes are POST /pulls."""
    writes = [(r.method, path) for method in ("POST", "PATCH", "PUT", "DELETE") for path, r in http.requests_by(method)]
    assert all(m == "POST" and p == "/pulls" for m, p in writes), writes
    assert main_tip(repo[1]) == main_before


def _nothing_sent(http, repo):
    assert http.creates == [], http.creates
    assert [ref for ref in remote_refs(repo[1]) if "adopt/" in ref] == []


@pytest.fixture
def forge(repo):
    """The forge double over `repo`'s remote from the start, so a case can plant PRs before the step opens the repository."""
    return AdoptionForge(remote=repo[1])


def test_a_fresh_offer_is_one_commit_off_the_fetched_main_pushed_and_opened_once(repo, forge, tmp_path):
    """No PR, main lacks the files, local main stale: one commit of exactly the rendered paths off the REMOTE main, one PR, `opened` with its number. (A3.5, P-9, N-A4)"""
    _land(repo, tmp_path, {"agent/lessons/merged-since.md": b"landed after the clone fetched\n"})
    before = main_tip(repo[1])
    assert before != repo.seed, "premise: main moved on since the tenant was seeded"
    # (#1618: the "local clone is stale" premise is gone with the clone; the step's repository is fetched at its open.)

    record = _adopt(repo, forge)

    [created] = forge.creates
    assert created["head"] == BRANCH
    assert created["base"] == "main"
    [pr] = [r for r in forge.prs if r["head"]["label"] == BRANCH]
    assert _outcome(record) == ("opened", pr["number"])
    tip = git(repo[1], "rev-parse", f"refs/heads/{BRANCH}")
    assert commits_between(repo[1], before, tip) == [tip], "not exactly one commit off the fetched main"
    assert git(repo[1], "rev-parse", f"{tip}^") == before
    # a path the fixture's main already holds (its per-system skill) is modified, every other one added (repair 5)
    held = set(git(repo[1], "ls-tree", "-r", "--name-only", before).split())
    assert held & set(RENDERING), "premise: main holds one rendered path already, so a modified path is covered"
    assert set(RENDERING) - held, "premise: and lacks another, so an added path is covered"
    assert tree_diff(repo[1], before, tip) == sorted(("M" if p in held else "A", "100644", p) for p in RENDERING)
    assert blobs_at(repo[1], tip, RENDERING) == RENDERING
    _quiet(forge, repo, before)


def test_the_commit_holds_the_rendered_bytes_whatever_mains_attributes_say(repo, forge, tmp_path):
    """Blobs are the render's bytes (CRLF, `$Id$`, non-UTF-8) under `eol=crlf` and `ident` on main; mode 100644. (P-9 commit)"""
    _land(repo, tmp_path, {}, attributes="* text eol=crlf\n*.md ident\n")
    assert _outcome(_adopt(repo, forge))[0] == "opened"
    tip = git(repo[1], "rev-parse", f"refs/heads/{BRANCH}")
    assert blobs_at(repo[1], tip, RENDERING) == RENDERING


# --- A3 order ------------------------------------------------------------------------------------------------------

def test_step1_an_open_pr_on_any_digest_of_the_system_wins_over_everything_below(repo, forge, tmp_path):
    """Open on another digest, merged on d, main holding d: `already_open` with the open one's number, nothing sent. (A3.1)"""
    _land(repo, tmp_path, RENDERING)
    git(repo[1], "update-ref", f"refs/heads/{BRANCH}", main_tip(repo[1]))
    git(repo[1], "update-ref", f"refs/heads/{OTHER_BRANCH}", main_tip(repo[1]))
    forge.plant(BRANCH, state="merged")
    forge.plant(BRANCH, state="closed")
    opened = forge.plant(OTHER_BRANCH)
    before = main_tip(repo[1])
    refs = remote_refs(repo[1])

    assert _outcome(_adopt(repo, forge)) == ("already_open", opened)
    assert forge.creates == []
    assert remote_refs(repo[1]) == refs
    _quiet(forge, repo, before)


def test_step1_the_lowest_number_is_answered(repo, forge):
    """Two open adoption PRs: the lower number. (A3, several match)"""
    for digest in ("1" * 64, "2" * 64):
        git(repo[1], "update-ref", f"refs/heads/{branch_for(digest)}", main_tip(repo[1]))
    first, second = (forge.plant(branch_for(d)) for d in ("2" * 64, "1" * 64))
    assert first < second
    assert _outcome(_adopt(repo, forge)) == ("already_open", first)


@pytest.mark.parametrize("head", ["adopt/elastic2/" + DIGEST[:16], f"adopt/other/{DIGEST[:16]}", "adopt/elastic", "lessons/batch-1"],
                         ids=["prefix-sibling", "other-system", "no-digest", "not-an-adoption"])
def test_step1_only_this_systems_adoption_branches_count(repo, forge, head):
    """An open PR on another system's, a prefix-sibling's or a non-adoption branch is not this system's: the offer goes ahead. (A3.1)"""
    # `adopt/elastic` as a ref would make `adopt/elastic/<digest>` unpushable (a directory/file conflict), so that PR's
    # branch is gone and only its `head.label` names it (G-A11; repair 5)
    gone = head == "adopt/elastic"
    if not gone:
        git(repo[1], "update-ref", f"refs/heads/{head}", main_tip(repo[1]))
    forge.plant(head, deleted=gone)
    assert _outcome(_adopt(repo, forge))[0] == "opened"


@pytest.mark.parametrize("deleted", [False, True], ids=["branch-kept", "branch-deleted"])
def test_step2_a_merged_pr_on_d_is_nothing_to_adopt_even_when_its_branch_was_deleted(repo, forge, deleted):
    """Merged on d, main lacking the files (a reviewer edited the merge away): `nothing_to_adopt`, matched by `head.label` after the branch is gone. (A3.2, G-A11)"""
    git(repo[1], "update-ref", f"refs/heads/{BRANCH}", main_tip(repo[1]))
    number = forge.plant(BRANCH, state="merged")
    forge.settle(number, merged=True, delete_branch=deleted)
    [row] = [r for r in forge.prs if r["number"] == number]
    assert row["head"]["label"] == BRANCH
    assert row["head"]["ref"] == (f"refs/pull/{number}/head" if deleted else BRANCH), "premise: G-A11's row shape"

    assert _outcome(_adopt(repo, forge)) == ("nothing_to_adopt", None)
    assert forge.creates == []


def test_step2_merged_on_another_digest_does_not_stop_the_offer(repo, forge):
    """A merged PR of an older digest (a release since) is no answer for d. (A3.2, A4)"""
    git(repo[1], "update-ref", f"refs/heads/{OTHER_BRANCH}", main_tip(repo[1]))
    forge.settle(forge.plant(OTHER_BRANCH, state="merged"), merged=True, delete_branch=True)
    assert _outcome(_adopt(repo, forge))[0] == "opened"


def test_step3_main_holding_every_rendered_blob_is_nothing_to_adopt_even_under_a_closed_pr_on_d(repo, forge, tmp_path):
    """Main's blobs (not a checkout under `eol=crlf`) equal the rendering: `nothing_to_adopt`, before `rejected`; nothing sent. (A3.3, A3.4 order)"""
    _land(repo, tmp_path, RENDERING, attributes="* text eol=crlf\n")
    git(repo[1], "update-ref", f"refs/heads/{BRANCH}", main_tip(repo[1]))
    forge.plant(BRANCH, state="closed")
    before = main_tip(repo[1])
    refs = remote_refs(repo[1])

    assert _outcome(_adopt(repo, forge)) == ("nothing_to_adopt", None)
    assert forge.creates == []
    assert remote_refs(repo[1]) == refs
    _quiet(forge, repo, before)


@pytest.mark.parametrize("drift", ["one-byte", "one-file-missing"])
def test_step3_main_holding_the_files_inexactly_is_offered_the_rendering(repo, forge, tmp_path, drift):
    """Control: one byte off or one rendered file absent on main still gets the offer. (A3.3)"""
    held = dict(RENDERING)
    first = sorted(held)[0]
    if drift == "one-byte":
        held[first] = held[first] + b" "
    elif drift == "one-file-missing":
        del held[first]
    _land(repo, tmp_path, held)
    assert _outcome(_adopt(repo, forge))[0] == "opened"
    assert forge.creates_of(BRANCH)


@pytest.mark.parametrize("mode", ["100755", "120000"])
def test_step3_identical_bytes_under_another_mode_on_main_are_not_held_and_the_offer_rewrites_them(repo, forge, tmp_path, mode):
    """A3.3 is read as the tree entries the commit would write (P-9: mode 100644): main holding a rendered path with identical bytes but
    another mode is not holding it, so the rendering is offered, and the offer's diff is that path's mode alone. (A3.3, surface s7)"""
    held = sorted(RENDERING)[0]
    only = {held: RENDERING[held]}
    others = {p: d for p, d in RENDERING.items() if p != held}
    _land(repo, tmp_path, others)

    def odd_mode(writer):
        oid = git_bytes(writer, "hash-object", "-w", "--no-filters", "--stdin", data=only[held]).decode().strip()
        git(writer, "update-index", "--add", "--cacheinfo", f"{mode},{oid},{held}")
    push_to_remote(repo, tmp_path, odd_mode, stage=False)
    before = main_tip(repo[1])
    assert blobs_at(repo[1], before, RENDERING) == RENDERING, "premise: main holds every rendered path's exact bytes"
    assert git(repo[1], "ls-tree", before, held).split()[0] == mode, "premise: the path is held under another mode"

    assert _outcome(_adopt(repo, forge))[0] == "opened"
    tip = git(repo[1], "rev-parse", f"refs/heads/{BRANCH}")
    assert tree_diff(repo[1], before, tip) == [("T" if mode == "120000" else "M", "100644", held)], "the offer is the mode change alone"


def test_step4_a_closed_unmerged_pr_on_d_is_rejected_with_its_number_and_nothing_is_opened(repo, forge):
    """Closed on d (lowest of two): `rejected` with that number, no push, no new PR. (A3.4, A11-9)"""
    git(repo[1], "update-ref", f"refs/heads/{BRANCH}", main_tip(repo[1]))
    low, high = forge.plant(BRANCH, state="closed"), forge.plant(BRANCH, state="closed")
    refs = remote_refs(repo[1])
    assert _outcome(_adopt(repo, forge)) == ("rejected", low)
    assert low < high
    assert forge.creates == []
    assert remote_refs(repo[1]) == refs


def test_step4_a_closed_pr_on_another_digest_is_not_a_rejection_of_d(repo, forge):
    """Closed unmerged on a different digest: the offer for d goes ahead. (A3.4, A4)"""
    git(repo[1], "update-ref", f"refs/heads/{OTHER_BRANCH}", main_tip(repo[1]))
    forge.settle(forge.plant(OTHER_BRANCH), merged=False)
    assert _outcome(_adopt(repo, forge))[0] == "opened"


def test_step2_beats_step4_when_d_was_merged_and_closed(repo, forge):
    """Merged and closed PRs both on d: merged wins (`nothing_to_adopt`). (A3 order)"""
    git(repo[1], "update-ref", f"refs/heads/{BRANCH}", main_tip(repo[1]))
    forge.plant(BRANCH, state="closed")
    forge.plant(BRANCH, state="merged")
    assert _outcome(_adopt(repo, forge)) == ("nothing_to_adopt", None)


def test_a_matching_pr_on_a_later_listing_page_is_found(repo, forge):
    """PRs in every state are read page by page (X-Total-Count): the match on page 3 still answers. (A3, G-A8)"""
    for n in range(4):
        git(repo[1], "update-ref", f"refs/heads/lessons/b{n}", main_tip(repo[1]))
        forge.plant(f"lessons/b{n}", state="closed")
    git(repo[1], "update-ref", f"refs/heads/{BRANCH}", main_tip(repo[1]))
    number = forge.plant(BRANCH, state="closed")
    forge.page_size = 2
    assert _outcome(_adopt(repo, forge)) == ("rejected", number)
    assert max(int(p) for _, p, _ in forge.listed()) >= 3


# --- recovery: a refused push or create -----------------------------------------------------------------------------------

@pytest.mark.parametrize(("how", "answer"), [("open", "already_open"), ("merged", "nothing_to_adopt"), ("closed", "rejected")])
def test_a_racer_that_pushed_and_opened_first_is_answered_by_steps_1_to_4(repo, forge, tmp_path, how, answer):
    """The branch refused our push (a racer's commit of the same tree, other id) and a PR now names it: answered by steps 1-4. (A3 recovery, git non-ff)"""
    seen = {}

    def racer():
        racer_push(repo[1], tmp_path, BRANCH, RENDERING, message="the racer's own commit")
        seen["number"] = forge.plant(BRANCH, state="open" if how == "open" else how)
    forge.after_listing = racer
    record = _adopt(repo, forge)
    assert seen, "premise: the racer ran between the listing and the push"
    assert record.outcome == answer
    assert getattr(record, "pr_number", None) == (seen["number"] if answer != "nothing_to_adopt" else None)
    assert forge.creates == []


def test_a_racers_branch_with_the_same_tree_and_no_pr_is_opened_on_its_tip(repo, forge, tmp_path):
    """Push refused, no PR, the tip's tree holds the rendering at every path: the PR opens on that tip, nothing is force-pushed. (A3 recovery)"""
    tips = {}
    forge.after_listing = lambda: tips.update(racer=racer_push(repo[1], tmp_path, BRANCH, RENDERING, message="racer"))
    record = _adopt(repo, forge)
    assert tips, "premise: the racer ran"
    [pr] = [r for r in forge.prs if r["head"]["label"] == BRANCH]
    assert _outcome(record) == ("opened", pr["number"])
    assert git(repo[1], "rev-parse", f"refs/heads/{BRANCH}") == tips["racer"], "the racer's branch was moved"
    assert pr["head"]["sha"] == tips["racer"]


def test_a_racers_branch_with_another_tree_and_no_pr_fails_and_is_left_alone(repo, forge, tmp_path):
    """Push refused, no PR, the tip's tree lacks the rendering: `failed`, no PR, the branch untouched (no force). (A3 recovery)"""
    tips = {}
    wrong = {**RENDERING, f"agent/skills/{SYSTEM}/execution.md": b"# someone else's text\n"}
    forge.after_listing = lambda: tips.update(racer=racer_push(repo[1], tmp_path, BRANCH, wrong, message="racer"))
    record = _adopt(repo, forge)
    assert tips
    assert record.outcome == "failed"
    assert record.reason == "delivery_failed"
    assert forge.creates == []
    assert git(repo[1], "rev-parse", f"refs/heads/{BRANCH}") == tips["racer"]


def _racer_opens_first(forge):
    seen = {}

    def racer(request):
        if request.method == "POST" and request.url.path.endswith("/pulls") and not seen:
            seen["number"] = forge.plant(BRANCH)
    forge.on_request = racer


@pytest.mark.parametrize(("setup", "outcome"), [
    (lambda forge: None, "opened"),
    (lambda forge: forge.refuse("/pulls", 503, method="POST", times=1), "opened"),
    (lambda forge: forge.refuse("/pulls", 503, method="POST"), "failed"),
    (lambda forge: setattr(forge, "lose_reply", "5xx"), "already_open"),
    (lambda forge: setattr(forge, "lose_reply", "dropped"), "already_open"),
    (_racer_opens_first, "already_open"),
], ids=["created", "refused-once-then-created", "refused-always", "applied-reply-5xx", "applied-reply-dropped", "racer-409"])
def test_after_a_refused_or_lost_create_the_outcome_is_what_the_listing_shows_else_failed(repo, forge, setup, outcome):
    """One rule: a PR names the branch -> `already_open` with its number; none and a retried create lands -> `opened`; else `failed`/`delivery_failed`; never a second PR. (A3 recovery, G-A12)"""
    setup(forge)
    record = _adopt(repo, forge)
    listed = [r["number"] for r in forge.prs if r["head"]["label"] == BRANCH]
    assert record.outcome == outcome
    assert len(listed) == (0 if outcome == "failed" else 1), listed
    if outcome == "failed":
        assert record.reason == "delivery_failed"
    else:
        assert _outcome(record) == (outcome, listed[0])
    assert len(commits_between(repo[1], main_tip(repo[1]), f"refs/heads/{BRANCH}")) == 1, "a second commit was made"


# --- A4 -----------------------------------------------------------------------------------------------------------------

def test_a_later_release_offers_only_the_changed_files_and_deletes_nothing(repo, forge, tmp_path):
    """Release 2 changes one file, adds one and ships one fewer; main holds release 1 with a tenant edit: the new offer replaces the edit, leaves the dropped file, touches nothing else. (A4)"""
    one_file, dropped = sorted(RENDERING)[0], sorted(RENDERING)[1]
    tenant_edit = {one_file: b"a tenant edited this file\n", "agent/lessons/theirs.md": b"theirs\n"}
    _land(repo, tmp_path, {**RENDERING, **tenant_edit})
    release2 = {p: d for p, d in RENDERING.items() if p != dropped}
    release2[one_file] = b"release two text\n"
    release2["agent/skills/elastic/new.md"] = b"new in release two\n"
    before = main_tip(repo[1])

    record = _adopt(repo, forge, rendering=release2, digest=OTHER_DIGEST)

    assert record.outcome == "opened"
    tip = git(repo[1], "rev-parse", f"refs/heads/{OTHER_BRANCH}")
    assert tree_diff(repo[1], before, tip) == [("A", "100644", "agent/skills/elastic/new.md"), ("M", "100644", one_file)]
    assert blobs_at(repo[1], tip, [one_file, "agent/lessons/theirs.md", dropped])[dropped] == RENDERING[dropped]
    assert blobs_at(repo[1], tip, [one_file])[one_file] == b"release two text\n"
    _quiet(forge, repo, before)


def test_the_branch_name_is_the_systems_and_the_digests_first_16_hex(repo, forge):
    """Branch `adopt/<system>/<first 16 hex of the digest>`, nothing else pushed. (P-9)"""
    digest = "abcdef0123456789" + "f" * 48
    assert _outcome(_adopt(repo, forge, digest=digest, system=SYSTEM))[0] == "opened"
    pushed = [ref for ref in remote_refs(repo[1]) if "adopt/" in ref]
    assert [p.split()[0] for p in pushed] == [f"refs/heads/adopt/{SYSTEM}/abcdef0123456789"]
    assert re.fullmatch(r"adopt/elastic/[0-9a-f]{16}", forge.creates[0]["head"])


# --- A3, surface §7: a fetch fault of adopt()'s is `delivery_failed` (repair 5) ------------------------------------------
# #1618 (design "Retired promises": adoption's ref-lock collision and `repository_busy` writer): with one private repository
# per operation no other writer can hold a ref lock in it, so the `ref-lock` -> `repository_busy` arms are retired; a stored
# `repository_busy` stays readable (census "Keep"). Any other fetch fault is still `delivery_failed`.

def _no_fetching(repo):
    """Any fetch fault: the remote serves no fetch over HTTP (`http.uploadpack false`), pushes still land."""
    git(repo[1], "config", "http.uploadpack", "false")


def test_a_fetch_fault_at_the_repositorys_open_refuses_before_anything_is_offered(repo, forge, tmp_path):
    """#1618: the step's first fetch of `main` is its private repository's open (the old step fetched `origin/main` into
    the shared clone itself): a fetch fault there refuses the open, and nothing is pushed or opened. (A3, K4)"""
    _land(repo, tmp_path, {"agent/lessons/merged-since.md": b"landed before the step\n"})
    _no_fetching(repo)
    with pytest.raises(target().DeliveryRefused):
        delivery(repo, forge)
    _nothing_sent(forge, repo)


def test_the_fetch_after_a_refused_push_fault_is_delivery_failed(repo, forge, tmp_path):
    """The fetch of the branch after a racer refused our push: a fetch fault is `delivery_failed`; nothing is opened.
    (A3, surface §7)"""
    step = importlib.import_module("defender.learning.author.version_control.adoption")
    repository = delivery(repo, forge).repository
    seen = {}

    def racer():
        seen["racer"] = racer_push(repo[1], tmp_path, BRANCH, RENDERING, message="the racer's own commit")
        _no_fetching(repo)
    forge.after_listing = racer
    record = step.adopt(repository, system=SYSTEM, rendering=RENDERING, digest=DIGEST)
    assert seen, "premise: the racer pushed between the listing and our push"
    assert (record.outcome, getattr(record, "reason", None)) == ("failed", "delivery_failed")
    assert forge.creates == []


def test_1618_f7_an_offer_needs_no_clone_on_the_host_and_is_one_commit_off_the_remote_main(repo, forge, tmp_path):
    """With the clone, `exports/` and lock deleted, the step works from a private repository: one commit off the remote `main`, one PR. (F7, A3.5)"""
    _land(repo, tmp_path, {"agent/lessons/merged-since.md": b"landed after the host last fetched\n"})
    before = main_tip(repo[1])
    step = importlib.import_module("defender.learning.author.version_control.adoption")
    repository = delivery_without_clone(repo, forge).repository

    record = step.adopt(repository, system=SYSTEM, rendering=RENDERING, digest=DIGEST)

    [created] = forge.creates
    assert created["head"] == BRANCH
    assert _outcome(record)[0] == "opened"
    tip = git(repo[1], "rev-parse", f"refs/heads/{BRANCH}")
    assert git(repo[1], "rev-parse", f"{tip}^") == before
    assert blobs_at(repo[1], tip, RENDERING) == RENDERING
    _quiet(forge, repo, before)

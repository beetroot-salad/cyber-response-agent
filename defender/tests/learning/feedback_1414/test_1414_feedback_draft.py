"""#1414 F2 step 4 and F3: approvals become a registry-only PR a person merges (O6), settled once (A1/P6), delivered
by one recovery path (A2), appended under a format contract (A7), and cited by a later lookup (O8).
"""
from __future__ import annotations

import datetime as dt
import logging
from pathlib import Path

import pytest
import yaml

from defender.tests.learning.feedback_1414 import _spec1414 as S
from defender.tests.learning.feedback_1414._spec1414 import LOOKUP, LOOKUP_2, NAMED, OWNER, today
from defender.tests.tenancy.tenant_1108_delivery._support import (
    merge_on_remote,
    pr_row,
    set_pull_state,
)
from defender.tests.tenancy.tenant_1108_p4._drain_support import remote_branches, touched
from defender.tests.tenancy.tenant_1108_p4._support import git

FIELDS = ("pattern", "actor_scope", "host_scope", "added_by", "added_at", "review_by")


def _drafts(fb) -> dict[str, str]:
    return remote_branches(fb.t.remote, S.FEEDBACK_PREFIX)


def _registry_at(fb, rev: str) -> str:
    return git(fb.t.remote, "show", f"{rev}:{S.REGISTRY}") + "\n"


def _read(text: str, tmp: Path) -> list[dict]:
    from defender.systems import tacit_registry

    path = tmp / "read" / "registry.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    read = tacit_registry.read_registry(path)
    assert read.problems == [], read.problems
    return list(read.entries)


def _entries_at(fb, rev: str) -> list[dict]:
    return _read(_registry_at(fb, rev), fb.tmp)


def _approved(fb, case: str, *, by: str = OWNER, body: str = "expected: the nightly backup",
              lookups=None, **answer):
    """An issue for `case` (one tick), a comment by `by` on it, and a decider approving it."""
    fb.request(case, lookups=lookups)
    assert fb.tick(S.Decider()) == 0
    [issue] = fb.issues(case)
    comment = fb.forge.add_comment(issue["number"], user=by, body=body)
    return issue["number"], comment, S.Decider({comment["id"]: S.answer(**answer)})


def _pr_of(fb, branch):
    [pr] = [p for p in fb.forge.prs if p["head"]["ref"] == branch]
    return pr


def _main_with(fb, entries: list[dict]) -> None:
    fb.t.merge({S.REGISTRY: yaml.safe_dump({"entries": entries}, sort_keys=False)})


def _covering(**over) -> dict:
    return {"id": "tk-backup", "pattern": LOOKUP["pattern"], "actor_scope": "svc-backup",
            "host_scope": "db-0?.prod", "added_by": "ops@example.invalid",
            "added_at": (today() - dt.timedelta(days=5)).isoformat(),
            "review_by": (today() + dt.timedelta(days=60)).isoformat(),
            "justification": "nightly backup"} | over


# ---------------------------------------------------------------- O6: the draft

def test_1414_an_approval_drafts_host_filled_entries_on_a_registry_only_pr(fb):
    """Approved lookups become appended entries whose every field but the justification the host fills; the PR touches only the registry and names the ids. O6/P2/P3."""
    named_date = today() + dt.timedelta(days=30)
    number, first, decider = _approved(fb, "case-draft", lookups=[LOOKUP, LOOKUP_2], approve=(0,))
    second = fb.forge.add_comment(number, user=NAMED, body=f"also fine until {named_date}")
    decider.script[second["id"]] = S.answer(approve=(1,), review_by=named_date.isoformat())
    main_before = _registry_at(fb, "main")

    assert fb.tick(decider) == 0
    [(branch, tip)] = _drafts(fb).items()
    assert touched(fb.t.remote, "main", tip) == [S.REGISTRY]
    drafted = _registry_at(fb, tip)
    assert [ln for ln in main_before.splitlines() if ln.startswith("#")] == \
        [ln for ln in drafted.splitlines() if ln.startswith("#")], "the file's comments did not survive"

    by_id = {e["id"]: e for e in _read(drafted, fb.tmp)}
    one, two = by_id[S.entry_id(number, first["id"])], by_id[S.entry_id(number, second["id"])]
    assert {k: one[k] for k in FIELDS} == {
        "pattern": LOOKUP["pattern"], "actor_scope": LOOKUP["actor"], "host_scope": LOOKUP["host"],
        "added_by": OWNER, "added_at": today().isoformat(),
        "review_by": (today() + dt.timedelta(days=180)).isoformat()}
    assert first["body"] in one["justification"]
    assert f"/issues/{number}" in one["justification"]
    assert (two["pattern"], two["added_by"], two["review_by"]) == (LOOKUP_2["pattern"], NAMED, named_date.isoformat())
    body = _pr_of(fb, branch)["body"]
    assert S.entry_id(number, first["id"]) in body
    assert S.entry_id(number, second["id"]) in body


def test_1414_a_covered_or_globbed_lookup_is_not_drafted_and_the_reply_says_why(fb):
    """A lookup that already hits on main is "already covered by" its entry; a glob-holding one is named as not writable; neither is drafted. O6/P3/O5."""
    _main_with(fb, [_covering()])
    globbed = {"actor": "svc-backup", "host": "db-*", "pattern": "pg_dump --all as root"}
    number, comment, decider = _approved(fb, "case-covered", lookups=[LOOKUP, globbed], approve=(0, 1))

    assert fb.tick(decider) == 0
    assert _drafts(fb) == {}
    [reply] = fb.replies(number, comment["id"])
    assert "already covered by" in reply["body"]
    assert "tk-backup" in reply["body"]
    assert "db-*" in reply["body"]


def test_1414_a_below_minimum_scope_is_not_drafted_and_a_valid_sibling_is(fb):
    """A lookup whose host has under four literal characters gets no entry and is named; the valid one beside it is drafted. O6."""
    short = {"actor": "svc-backup", "host": "db1", "pattern": "pg_dump --all as root"}
    number, comment, decider = _approved(fb, "case-short", lookups=[short, LOOKUP_2], approve=(0, 1))

    assert fb.tick(decider) == 0
    [(_, tip)] = _drafts(fb).items()
    assert [e["pattern"] for e in _entries_at(fb, tip)] == [LOOKUP_2["pattern"]]
    [reply] = fb.replies(number, comment["id"])
    assert "db1" in reply["body"]


def test_1414_an_approval_gets_one_reply_with_its_marker_and_pr_link(fb):
    """Once the entry is on a PR the comment gets exactly one bot reply carrying its marker and the PR link; later ticks add none. O5."""
    number, comment, decider = _approved(fb, "case-reply", approve=(0,))
    for _ in range(3):
        assert fb.tick(decider) == 0
    [(branch, _)] = _drafts(fb).items()
    [reply] = fb.replies(number, comment["id"])
    assert _pr_of(fb, branch)["html_url"] in reply["body"]


# ---------------------------------------------------------------- A1 / P6: settlement recorded once

def test_1414_two_comments_approving_one_lookup_draft_one_entry_and_the_pr_lists_the_covered_id(fb):
    """A lookup approved twice drafts once; the second id is listed in the PR as covered and its reply names the first entry. O6/A1."""
    number, first, decider = _approved(fb, "case-twice", approve=(0,))
    second = fb.forge.add_comment(number, user=NAMED, body="agreed")
    decider.script[second["id"]] = S.answer(approve=(0,))

    assert fb.tick(decider) == 0
    [(branch, tip)] = _drafts(fb).items()
    assert [e["id"] for e in _entries_at(fb, tip)] == [S.entry_id(number, first["id"])]
    assert S.entry_id(number, second["id"]) in _pr_of(fb, branch)["body"]
    assert S.entry_id(number, first["id"]) in fb.replies(number, second["id"])[0]["body"]


def test_1414_closing_the_pr_settles_its_drafted_and_its_covered_entries_for_good(fb):
    """After a person closes the PR neither its entry nor the entry covered within the batch is drafted again, however many ticks run. P6/A1."""
    number, first, decider = _approved(fb, "case-no", approve=(0,))
    second = fb.forge.add_comment(number, user=NAMED, body="agreed")
    decider.script[second["id"]] = S.answer(approve=(0,))
    assert fb.tick(decider) == 0
    [(branch, _)] = _drafts(fb).items()
    set_pull_state(fb.t.remote, branch, merged=False, delete_branch=True)
    prs_before = len(fb.forge.prs)

    for _ in range(3):
        assert fb.tick(decider) == 0
    assert len(fb.forge.prs) == prs_before, "a declined entry was drafted again"
    assert _drafts(fb) == {}


def test_1414_removing_the_covering_entry_never_revives_a_judged_entry(fb):
    """An entry judged covered stays settled when its covering entry later leaves main; an entry not yet judged is drafted. A1."""
    _main_with(fb, [_covering()])
    number, comment, decider = _approved(fb, "case-revive", approve=(0,))
    assert fb.tick(decider) == 0
    assert _drafts(fb) == {}

    _main_with(fb, [])
    late = fb.forge.add_comment(number, user=NAMED, body="and this one")
    decider.script[late["id"]] = S.answer(approve=(0,))
    for _ in range(2):
        assert fb.tick(decider) == 0
    drafted = {e["id"] for _, tip in _drafts(fb).items() for e in _entries_at(fb, tip)}
    assert S.entry_id(number, comment["id"]) not in drafted, "a judged entry was revived"
    assert S.entry_id(number, late["id"]) in drafted, "positive control: an unjudged approval was not drafted"


def test_1414_a_draft_lost_before_its_pr_is_drafted_again_once(fb):
    """A refused PR create leaves the ids on no PR, so a later tick drafts them, once, without deciding the comment again. O4/P5/O9."""
    number, comment, decider = _approved(fb, "case-redo", approve=(0,))
    fb.forge.fail_create = True
    fb.tick(decider)
    assert [p for p in fb.forge.prs if S.entry_id(number, comment["id"]) in (p.get("body") or "")] == []
    assert fb.replies(number, comment["id"]) == [], "a reply was posted before the PR existed"

    fb.forge.fail_create = False
    for _ in range(2):
        assert fb.tick(decider) == 0
    named = [p for p in fb.forge.prs if S.entry_id(number, comment["id"]) in (p.get("body") or "")]
    assert len(named) == 1
    assert decider.decided == [comment["id"]]


def test_1414_a_person_pr_naming_an_id_settles_nothing(fb):
    """A closed PR not opened by the bot under feedback/ that names an entry id does not settle it, while the bot's own does. P6/A2."""
    number, comment, decider = _approved(fb, "case-impostor", approve=(0,))
    ident = S.entry_id(number, comment["id"])
    for head, user in (("feedback/fake", S.OUTSIDER), ("someone/fix", fb.bot)):
        row = pr_row(40 + len(fb.forge.prs), head, state="closed")
        row["body"] = f"settles {ident}"
        row["user"] = {"login": user}
        fb.forge.add_pr(row)

    assert fb.tick(decider) == 0
    [(branch, tip)] = _drafts(fb).items()
    assert [e["id"] for e in _entries_at(fb, tip)] == [ident], "a PR that was not the bot's feedback PR declined the entry"


# ---------------------------------------------------------------- A2: one recovery path

def test_1414_a_retained_delivery_holds_the_lease_and_is_redelivered_with_the_same_body(fb):
    """While a feedback branch is retained or its PR open no new batch starts; the retried PR carries the first attempt's body (ids drafted and covered). A2."""
    number, first, decider = _approved(fb, "case-lease", lookups=[LOOKUP, LOOKUP_2], approve=(0,))
    dup = fb.forge.add_comment(number, user=NAMED, body="agreed")
    decider.script[dup["id"]] = S.answer(approve=(0,))
    fb.forge.fail_create = True
    fb.tick(decider)
    [(branch, _)] = _drafts(fb).items()
    assert fb.forge.prs == []

    fb.forge.fail_create = False
    late = fb.forge.add_comment(number, user=NAMED, body="and another")
    decider.script[late["id"]] = S.answer(approve=(1,))
    assert fb.tick(decider) == 0
    attempts = [c["body"] for c in fb.forge.creates if "head" in c]
    assert len(attempts) == 2, attempts
    assert attempts[0] == attempts[1]
    assert S.entry_id(number, first["id"]) in attempts[1]
    assert S.entry_id(number, dup["id"]) in attempts[1]
    assert list(_drafts(fb)) == [branch], "a second batch started beside the retained one"

    assert fb.tick(decider) == 0
    assert list(_drafts(fb)) == [branch], "a batch started under an open feedback PR"
    assert len(fb.forge.prs) == 1

    set_pull_state(fb.t.remote, branch, merged=False)
    assert fb.tick(decider) == 0
    assert len(fb.forge.prs) == 2, "positive control: the lease did not release when the PR closed"


# ---------------------------------------------------------------- A7: the format contract

_ENTRY = ("  - id: tk-old\n    pattern: other pattern text\n    actor_scope: svc-other\n    host_scope: web-01.prod\n"
          "    added_by: ops@example.invalid\n    added_at: 2026-10-01\n    review_by: 2026-12-01\n    justification: kept\n")
_SHAPES = {
    "empty flow list": ("# header\nentries: []\n", True),
    "block list last": (f"# header\nentries:\n{_ENTRY}", True),
    "block list dash at column 0": ("# header\nentries:\n" + "".join(
        ln[2:] + "\n" if ln.startswith("  - ") else ln[2:] + "\n" for ln in _ENTRY.splitlines()), True),
    "non-empty flow list": ("entries: [{id: tk-old}]\n", False),
    "entries not last": (f"entries:\n{_ENTRY}owner: ops\n", False),
    "spaced empty list": ("entries: [ ]\n", False),
    "no entries key": ("# nothing\n", False),
}


@pytest.mark.parametrize("shape", sorted(_SHAPES))
def test_1414_the_registry_is_appended_to_only_in_the_two_shapes_the_contract_names(fb, shape, caplog):
    """A block list as the last key is appended to (earlier lines kept byte for byte) and `entries: []` rewritten once; any other shape refuses the draft loudly. A7/O9."""
    text, ok = _SHAPES[shape]
    fb.t.merge({S.REGISTRY: text})
    number, comment, decider = _approved(fb, "case-shape", approve=(0,))

    with caplog.at_level(logging.INFO):
        assert fb.tick(decider) == 0
    if not ok:
        assert _drafts(fb) == {}
        assert fb.forge.prs == []
        assert fb.replies(number, comment["id"]) == []
        assert any(r.levelno >= logging.WARNING for r in caplog.records), "the refused draft is not logged"
        return
    [(_, tip)] = _drafts(fb).items()
    drafted = _registry_at(fb, tip)
    kept = text.removesuffix("entries: []\n")
    assert drafted.startswith(kept), "lines before the append changed"
    ids = [e["id"] for e in _read(drafted, fb.tmp)]
    assert ids[-1] == S.entry_id(number, comment["id"])
    assert len(ids) == 1 + (shape != "empty flow list")
    assert "entries: []" not in drafted


def test_1414_a_second_batch_after_a_merge_appends_to_the_block_the_first_made(fb):
    """After the first batch is merged (the empty list rewritten) a later approval appends beneath it, both entries read. A7/F3."""
    number, first, decider = _approved(fb, "case-two-batches", lookups=[LOOKUP, LOOKUP_2], approve=(0,))
    assert fb.tick(decider) == 0
    [(branch, _)] = _drafts(fb).items()
    merge_on_remote(fb.t.p3, fb.t.scratch, branch)
    second = fb.forge.add_comment(number, user=NAMED, body="and this")
    decider.script[second["id"]] = S.answer(approve=(1,))
    assert fb.tick(decider) == 0

    [tip] = [t for b, t in _drafts(fb).items() if b != branch] or [None]
    assert tip is not None
    assert [e["id"] for e in _entries_at(fb, tip)] == [S.entry_id(number, first["id"]), S.entry_id(number, second["id"])]


# ---------------------------------------------------------------- F3 / O8

def test_1414_a_merged_entry_answers_a_later_lookup(fb, tmp_path):
    """After a person merges the draft, a lookup over main's registry hits the drafted entry for the looked-up host only. O8/F3."""
    from defender._git import REPO_ROOT
    from defender.systems.verbs import ModuleVerbRegistry, VerbContext, read_roster
    from defender.tests.support.tenancy import _tenants1106

    number, comment, decider = _approved(fb, "case-merge", approve=(0,))
    assert fb.tick(decider) == 0
    [(branch, _)] = _drafts(fb).items()
    merge_on_remote(fb.t.p3, fb.t.scratch, branch)

    root = tmp_path / "agent"
    target = root / "skills" / "tacit-knowledge" / "registry.yaml"
    target.parent.mkdir(parents=True)
    target.write_text(_registry_at(fb, "main"), encoding="utf-8")
    lookup = ModuleVerbRegistry(read_roster(REPO_ROOT / "defender" / "integrations"),
                                _tenants1106.fixture_grants().gather).verbs("tacit-knowledge")["lookup"]
    ctx = VerbContext(defender_dir=REPO_ROOT / "defender", run_dir=tmp_path / "run", env={},
                      tenant=_tenants1106.fixture_run_tenant(agent_root=root))

    hit = lookup(ctx, actor=LOOKUP["actor"], host=LOOKUP["host"], pattern=LOOKUP["pattern"])
    miss = lookup(ctx, actor=LOOKUP["actor"], host="db-03.prod", pattern=LOOKUP["pattern"])
    assert (hit["matched"] or {}).get("id") == S.entry_id(number, comment["id"])
    assert miss["matched"] is None

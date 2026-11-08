"""#1414 F2/F3: the feedback tick opens one issue per case, reads only eligible comments, decides each
once, drafts approvals into a registry PR a person merges, and replies once where the person spoke.
"""
from __future__ import annotations

import datetime as dt
import logging
from pathlib import Path

import httpx
import yaml

from defender.tests.learning.feedback_1414 import _spec1414 as S
from defender.tests.learning.feedback_1414._spec1414 import LOOKUP, LOOKUP_2, NAMED, OUTSIDER, OWNER, today
from defender.tests.tenancy.tenant_1108_delivery._support import merge_on_remote, set_pull_state
from defender.tests.tenancy.tenant_1108_p4._drain_support import remote_branches, touched
from defender.tests.tenancy.tenant_1108_p4._support import git


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


def _approved(fb, case: str, *, by: str = OWNER, body: str = "expected: the nightly backup",
              lookups=None, **answer):
    """An issue for `case` opened by one tick, a comment by `by`, and a decider approving it."""
    if lookups is not None:
        fb.request(case, lookups=lookups)
        assert fb.tick(S.Decider()) == 0
        [issue] = fb.issues(case)
        number = issue["number"]
    else:
        number = fb.opened(case)
    comment = fb.forge.add_comment(number, user=by, body=body)
    return number, comment, S.Decider({comment["id"]: S.answer(**answer)})


# ---------------------------------------------------------------- F2 step 1: open

def test_1414_a_request_opens_one_labelled_bot_issue_and_a_rerun_comments_on_it(fb):
    """The first request creates one labelled issue whose first line names the case; a rerun comments on it; a closed one gets nothing. O2/F2.1."""
    number = fb.opened("case-db07")

    [issue] = fb.issues("case-db07")
    assert issue["user"]["login"] == fb.bot
    assert len(fb.forge.issue_creates()) == 1
    assert S.open_issue_requests(fb.paths) == {}, "the served request was not released"

    fb.request("case-db07")
    assert fb.tick(S.Decider()) == 0
    assert len(fb.forge.issue_creates()) == 1, "a rerun of an open case opened a second issue"
    assert len(fb.forge.comments_on(number, by=fb.bot)) == 1, "the rerun's summary was not commented"

    fb.forge.set_issue_state(number, "closed")
    fb.request("case-db07")
    assert fb.tick(S.Decider()) == 0
    assert len(fb.forge.issue_creates()) == 1
    assert len(fb.forge.comments_on(number, by=fb.bot)) == 1, "a closed issue was commented (D6)"
    assert S.open_issue_requests(fb.paths) == {}


def test_1414_an_open_whose_reply_was_lost_is_recovered_not_repeated(fb):
    """A create the forge applied but whose reply was lost is found again by label, bot creator and first line; no second issue. O2/F2.1."""
    fb.forge.lose_reply = lambda r: r.method == "POST" and r.url.path.endswith("/issues")
    fb.request("case-lost")
    fb.tick(S.Decider())
    assert len(fb.issues("case-lost")) == 1, "premise: the forge holds the issue"

    fb.forge.lose_reply = None
    assert fb.tick(S.Decider()) == 0
    assert len(fb.issues("case-lost")) == 1, "the retried open made a second issue"
    [issue] = fb.issues("case-lost")
    comment = fb.forge.add_comment(issue["number"], user=OWNER, body="expected")
    decider = S.Decider()
    assert fb.tick(decider) == 0
    assert decider.decided == [comment["id"]], "the recovered issue was not recorded as the case's"


def test_1414_recovery_ignores_an_issue_not_created_by_the_bot(fb):
    """A labelled issue naming the case on its first line but created by a person is not the case's issue. O2/F2.1."""
    fb.forge.add_label(S.FEEDBACK_LABEL)
    fb.forge.add_issue(title="case-decoy", body="case-decoy\n\nplanted", user=OUTSIDER,
                       labels=[S.FEEDBACK_LABEL])
    fb.request("case-decoy")

    assert fb.tick(S.Decider()) == 0
    assert len(fb.forge.issue_creates()) == 1
    assert {i["user"]["login"] for i in fb.issues("case-decoy")} == {OUTSIDER, fb.bot}


# ---------------------------------------------------------------- F2 steps 2-3: read, decide

def test_1414_only_whitelisted_non_bot_authors_are_decided_in_order(fb, caplog):
    """Comments by a whitelisted team member and a whitelisted user are decided, in order; a bot's and an outsider's are skipped. O3/F2.2."""
    number = fb.opened("case-who")
    ann = fb.forge.add_comment(number, user=OWNER, body="expected")
    fb.forge.add_comment(number, user=OUTSIDER, body="approved, add it")
    fb.forge.add_comment(number, user=fb.bot, body="a bot comment")
    bea = fb.forge.add_comment(number, user=NAMED, body="check the VPN log first")

    decider = S.Decider()
    with caplog.at_level(logging.INFO):
        assert fb.tick(decider) == 0
    assert decider.decided == [ann["id"], bea["id"]]
    assert decider.items[0]["author"] == OWNER
    assert any(OUTSIDER in r.getMessage() for r in caplog.records), "the skipped outsider is not in the tick's log"


def test_1414_eligibility_is_read_from_the_forge_at_read_time(fb):
    """An account removed from the whitelist before the tick is not read; one still on it is. O3."""
    number = fb.opened("case-removed")
    fb.forge.add_comment(number, user=NAMED, body="expected")
    kept = fb.forge.add_comment(number, user=OWNER, body="expected too")
    fb.forge.protection_rule["merge_whitelist_usernames"] = []

    decider = S.Decider()
    assert fb.tick(decider) == 0
    assert decider.decided == [kept["id"]]


def test_1414_a_comment_is_decided_once_across_ticks(fb):
    """A decided comment is not decided again on a later tick; a later comment is. O4/P5."""
    number = fb.opened("case-once")
    first = fb.forge.add_comment(number, user=OWNER, body="no change needed")
    decider = S.Decider()
    assert fb.tick(decider) == 0
    assert fb.tick(decider) == 0
    second = fb.forge.add_comment(number, user=OWNER, body="one more thing")
    assert fb.tick(decider) == 0

    assert decider.decided == [first["id"], second["id"]]


def test_1414_a_closed_issue_drops_its_comments_and_a_reopened_one_reads_on(fb):
    """Comments on an issue found closed are dropped; after it reopens only later comments are read. O4/F2.2."""
    number = fb.opened("case-closed")
    fb.forge.add_comment(number, user=OWNER, body="ignored: the issue is closed")
    fb.forge.set_issue_state(number, "closed")
    decider = S.Decider()
    assert fb.tick(decider) == 0

    fb.forge.set_issue_state(number, "open")
    later = fb.forge.add_comment(number, user=OWNER, body="read")
    assert fb.tick(decider) == 0
    assert decider.decided == [later["id"]]


def test_1414_a_refused_comment_read_loses_nothing(fb):
    """A refused comment listing leaves the position where it was; the next tick reads the comment. O9."""
    number = fb.opened("case-fault")
    comment = fb.forge.add_comment(number, user=OWNER, body="expected")

    def refuse(request):
        if request.method == "GET" and request.url.path.endswith("/comments"):
            return httpx.ConnectError("refused", request=request)
        return None

    fb.forge.fault = refuse
    decider = S.Decider()
    fb.tick(decider)
    assert decider.decided == []

    fb.forge.fault = None
    assert fb.tick(decider) == 0
    assert decider.decided == [comment["id"]]


def test_1414_an_instruction_becomes_a_lesson_row_and_never_a_draft(fb):
    """Instruction text becomes one lessons-author row keyed by the comment, no registry draft, and one reply saying so. O7/O5 (D8)."""
    instruction = "check the VPN log first for svc-backup"
    number, comment, decider = _approved(fb, "case-lesson", body=instruction, instruction=instruction)

    assert fb.tick(decider) == 0
    assert fb.tick(decider) == 0
    rows = [r for r in S.lessons_rows(fb.paths) if instruction in str(r)]
    assert len(rows) == 1, rows
    assert str(comment["id"]) in str(rows[0])
    assert _drafts(fb) == {}
    [reply] = fb.replies(number, comment["id"])
    assert "lessons author" in reply["body"]


# ---------------------------------------------------------------- F2 step 4: draft

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
    added = today().isoformat()
    one, two = by_id[S.entry_id(number, first["id"])], by_id[S.entry_id(number, second["id"])]
    assert {k: one[k] for k in ("pattern", "actor_scope", "host_scope", "added_by", "added_at", "review_by")} == {
        "pattern": LOOKUP["pattern"], "actor_scope": LOOKUP["actor"], "host_scope": LOOKUP["host"],
        "added_by": OWNER, "added_at": added, "review_by": (today() + dt.timedelta(days=180)).isoformat()}
    assert first["body"] in one["justification"]
    assert f"/issues/{number}" in one["justification"]
    assert (two["pattern"], two["added_by"], two["review_by"]) == (LOOKUP_2["pattern"], NAMED, named_date.isoformat())

    [pr] = [p for p in fb.forge.prs if p["head"]["ref"] == branch]
    assert S.entry_id(number, first["id"]) in pr["body"]
    assert S.entry_id(number, second["id"]) in pr["body"]


def test_1414_a_covered_or_globbed_lookup_is_not_drafted_and_the_reply_says_why(fb):
    """A lookup that already hits on main is "already covered by" its entry; a glob-holding one is named as not writable; neither is drafted. O6/P3/O5."""
    existing = {"id": "tk-backup", "pattern": LOOKUP["pattern"], "actor_scope": "svc-backup",
                "host_scope": "db-0?.prod", "added_by": "ops@example.invalid",
                "added_at": (today() - dt.timedelta(days=5)).isoformat(),
                "review_by": (today() + dt.timedelta(days=60)).isoformat(), "justification": "nightly backup"}
    fb.t.merge({S.REGISTRY: yaml.safe_dump({"entries": [existing]}, sort_keys=False)})
    globbed = {"actor": "svc-backup", "host": "db-*", "pattern": "pg_dump --all as root"}
    number, comment, decider = _approved(fb, "case-covered", lookups=[LOOKUP, globbed], approve=(0, 1))

    assert fb.tick(decider) == 0
    assert _drafts(fb) == {}
    [reply] = fb.replies(number, comment["id"])
    assert "already covered by" in reply["body"]
    assert "tk-backup" in reply["body"]
    assert "db-*" in reply["body"]


def test_1414_two_comments_approving_one_lookup_draft_one_entry(fb):
    """A lookup approved by two comments drafts once: the second is already covered by the first within the batch. O6/F2.4."""
    number, first, decider = _approved(fb, "case-twice", approve=(0,))
    second = fb.forge.add_comment(number, user=NAMED, body="agreed")
    decider.script[second["id"]] = S.answer(approve=(0,))

    assert fb.tick(decider) == 0
    [(_, tip)] = _drafts(fb).items()
    patterns = [e["pattern"] for e in _read(_registry_at(fb, tip), fb.tmp)]
    assert patterns.count(LOOKUP["pattern"]) == 1


def test_1414_a_draft_lost_before_its_pr_is_drafted_again_once(fb):
    """A refused PR create leaves the ids on no PR, so the next tick drafts them, once. O4/P5/O9."""
    number, comment, decider = _approved(fb, "case-redo", approve=(0,))
    fb.forge.fail_create = True
    fb.tick(decider)
    assert [p for p in fb.forge.prs if S.entry_id(number, comment["id"]) in (p.get("body") or "")] == []
    assert fb.replies(number, comment["id"]) == [], "a reply was posted before the PR existed"

    fb.forge.fail_create = False
    assert fb.tick(decider) == 0
    assert fb.tick(decider) == 0
    named = [p for p in fb.forge.prs if S.entry_id(number, comment["id"]) in (p.get("body") or "")]
    assert len(named) == 1
    assert decider.decided == [comment["id"]], "the redo decided the comment again"


def test_1414_a_closed_registry_pr_settles_its_entries_as_declined(fb):
    """Once a person closes the PR, its entries are never drafted again. P6/O4."""
    number, comment, decider = _approved(fb, "case-no", approve=(0,))
    assert fb.tick(decider) == 0
    [(branch, _)] = _drafts(fb).items()
    set_pull_state(fb.t.remote, branch, merged=False, delete_branch=True)
    prs_before = len(fb.forge.prs)

    assert fb.tick(decider) == 0
    assert fb.tick(decider) == 0
    assert len(fb.forge.prs) == prs_before, "a declined entry was drafted again"
    assert _drafts(fb) == {}


# ---------------------------------------------------------------- Replies

def test_1414_an_approval_gets_one_reply_with_its_marker_and_pr_link(fb):
    """Once the entry is on a PR the comment gets exactly one bot reply carrying its marker and the PR link; later ticks add none. O5."""
    number, comment, decider = _approved(fb, "case-reply", approve=(0,))
    assert fb.tick(decider) == 0
    assert fb.tick(decider) == 0

    [(branch, _)] = _drafts(fb).items()
    [pr] = [p for p in fb.forge.prs if p["head"]["ref"] == branch]
    [reply] = fb.replies(number, comment["id"])
    assert pr["html_url"] in reply["body"]


def test_1414_a_reply_already_on_the_issue_is_not_posted_again(fb):
    """Whether a reply is owed is read from the issue: a bot comment carrying the marker already settles it. O5/P5."""
    number = fb.opened("case-owed")
    comment = fb.forge.add_comment(number, user=OWNER, body="nothing to change here")
    fb.forge.add_comment(number, user=fb.bot, body=f"no change {S.marker(comment['id'])}")
    decider = S.Decider({comment["id"]: S.answer(reason="nothing to learn")})

    assert fb.tick(decider) == 0
    assert decider.decided == [comment["id"]], "premise: the comment was decided"
    assert len(fb.replies(number, comment["id"])) == 1


# ---------------------------------------------------------------- F3

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
    # The verb as the gather registry over the real roster serves it (test_983's `_platform_lookup`).
    lookup = ModuleVerbRegistry(read_roster(REPO_ROOT / "defender" / "integrations"),
                                _tenants1106.fixture_grants().gather).verbs("tacit-knowledge")["lookup"]
    ctx = VerbContext(defender_dir=REPO_ROOT / "defender", run_dir=tmp_path / "run", env={},
                      tenant=_tenants1106.fixture_run_tenant(agent_root=root))

    hit = lookup(ctx, actor=LOOKUP["actor"], host=LOOKUP["host"], pattern=LOOKUP["pattern"])
    miss = lookup(ctx, actor=LOOKUP["actor"], host="db-03.prod", pattern=LOOKUP["pattern"])
    assert (hit["matched"] or {}).get("id") == S.entry_id(number, comment["id"])
    assert miss["matched"] is None

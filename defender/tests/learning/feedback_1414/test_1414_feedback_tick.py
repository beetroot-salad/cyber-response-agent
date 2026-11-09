"""#1414 F2 steps 1-2 and Replies: the tick opens one issue per run (ruling 2026-11-09), reads only eligible comments
(D13's record, D12's close rule), frames each by its issue's run, and replies once where the person spoke.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import json
import logging
import re

import httpx
import pytest

from defender.tests.learning.feedback_1414 import _attacks1414 as A
from defender.tests.learning.feedback_1414 import _spec1414 as S
from defender.tests.learning.feedback_1414._spec1414 import LOOKUP, LOOKUP_2, NAMED, OUTSIDER, OWNER
from defender.tests.tenancy.tenant_1108_p4._drain_support import remote_branches


def _loud(caplog, *words: str) -> bool:
    return any(r.levelno >= logging.WARNING and all(w in r.getMessage().lower() for w in words)
               for r in caplog.records)


def _run_issues(fb, run_dir) -> list[dict]:
    """The labelled bot-made issues whose title and host-written first body line name `run_dir`'s run id exactly
    (ruling 2026-11-09: the run id is on the issue body's first line, with the bot as creator, and in the title)."""
    named = re.compile(rf"(?<![\w-]){re.escape(S.run_id_of(run_dir))}(?![\w-])")
    return [i for i in fb.forge.issues
            if S.FEEDBACK_LABEL in {label["name"] for label in i["labels"]}
            and named.search((i["body"].splitlines() or [""])[0]) and named.search(i["title"])]


# ---------------------------------------------------------------- F2 step 1: open (O2, A6)

def test_1414_each_run_opens_its_own_labelled_bot_issue_naming_the_run(fb):
    """A request creates one labelled bot issue whose title and first line name its run; a rerun of the case opens a new one,
    whether the earlier issue is open or closed, and comments on neither. O2/F2.1 (ruling 2026-11-09: one issue per run)."""
    first = fb.request("case-db07")
    assert fb.tick(S.Decider()) == 0
    [issue] = _run_issues(fb, first)
    assert issue["user"]["login"] == fb.bot
    assert len(fb.forge.issue_creates()) == 1
    assert S.open_issue_requests(fb.paths) == {}, "the served request was not released"

    second = fb.request("case-db07")
    assert fb.tick(S.Decider()) == 0
    assert len(fb.forge.issue_creates()) == 2, "a rerun of the case did not open its own issue"
    [again] = _run_issues(fb, second)
    assert again["number"] != issue["number"]
    assert again["user"]["login"] == fb.bot
    assert _run_issues(fb, first) == [issue], "the rerun's issue names the earlier run"
    assert fb.forge.comments_on(issue["number"], by=fb.bot) == [], "the rerun commented on the earlier run's issue"

    fb.forge.set_issue_state(again["number"], "closed")
    third = fb.request("case-db07")
    assert fb.tick(S.Decider()) == 0
    assert len(fb.forge.issue_creates()) == 3, "a rerun after a closed issue opened nothing"
    assert len(_run_issues(fb, third)) == 1
    assert [len(fb.forge.comments_on(n, by=fb.bot)) for n in (issue["number"], again["number"])] == [0, 0]
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
    fb.forge.lose_reply = lambda r: r.method == "POST" and r.url.path.endswith("/issues")
    fb.request("case-decoy")
    fb.tick(S.Decider())
    fb.forge.lose_reply = None
    [made] = fb.issues("case-decoy")  # a real create the forge applied: its first line is the host's own
    made["user"]["login"] = OUTSIDER  # ... now shown as a person's, and the host never recorded it
    assert len(fb.forge.issue_creates()) == 1, "premise: one create so far"

    assert fb.tick(S.Decider()) == 0
    assert len(fb.forge.issue_creates()) == 2, "the person's issue was taken for the case's"
    assert {i["user"]["login"] for i in fb.issues("case-decoy")} == {OUTSIDER, fb.bot}


def test_1414_recovery_finds_the_runs_own_issue_never_another_runs_of_the_case(fb):
    """A create the forge applied but whose reply was lost is recovered as that run's issue, never taken for an earlier run's of
    the same case or another case's; a create the forge never applied is made on the retry. O2/F2.1/A6 (ruling 2026-11-09)."""
    first = fb.request("case-1")
    other = fb.request("case-10")
    assert fb.tick(S.Decider()) == 0
    assert len(fb.forge.issues) == 2, "premise: the earlier run's and another case's issues were made by a real tick"
    fb.forge.lose_reply = lambda r: r.method == "POST" and r.url.path.endswith("/issues")
    second = fb.request("case-1")
    fb.tick(S.Decider())
    fb.forge.lose_reply = None
    assert len(fb.forge.issues) == 3, "premise: the forge applied the lost create"

    assert fb.tick(S.Decider()) == 0
    assert len(fb.forge.issues) == 3, "the retried open made a second issue for the run"
    [one], [two], [ten] = (_run_issues(fb, r) for r in (first, second, other))
    assert len({one["number"], two["number"], ten["number"]}) == 3
    comment = fb.forge.add_comment(two["number"], user=OWNER, body="expected")
    decider = S.Decider()
    assert fb.tick(decider) == 0
    assert decider.decided == [comment["id"]], "the recovered issue was not recorded as the run's"
    assert decider.item(comment["id"])["run_id"] == S.run_id_of(second)

    fb.forge.fault = lambda r: (httpx.ConnectError("down", request=r)
                                if r.method == "POST" and r.url.path.endswith("/issues") else None)
    third = fb.request("case-1")
    fb.tick(S.Decider())
    assert _run_issues(fb, third) == [], "premise: this create was never applied"
    fb.forge.fault = None
    assert fb.tick(S.Decider()) == 0
    assert len(_run_issues(fb, third)) == 1, "positive control: a create never applied is made on the retry"
    assert len(fb.forge.issues) == 4
    assert S.open_issue_requests(fb.paths) == {}


def test_1414_an_issue_the_forge_no_longer_has_is_treated_as_closed_and_logged(fb, caplog):
    """A recorded issue the forge no longer has is read as closed: the loss is logged, the issue is never made again, and a
    later run of the case still opens its own. A6 (ruling 2026-11-09: one issue per run)."""
    number = fb.opened("case-gone")
    fb.forge.remove_issue(number)

    with caplog.at_level(logging.INFO):
        assert fb.tick(S.Decider()) == 0
        assert fb.tick(S.Decider()) == 0
    assert len(fb.forge.issue_creates()) == 1, "the gone issue was made again"
    assert any(str(number) in r.getMessage() for r in caplog.records), "the missing issue is not in the log"

    later = fb.request("case-gone")
    assert fb.tick(S.Decider()) == 0
    assert len(_run_issues(fb, later)) == 1, "a later run of the case opened nothing"
    assert len(fb.forge.issue_creates()) == 2
    assert S.open_issue_requests(fb.paths) == {}


def test_1414_a_comment_is_framed_by_its_issues_run(fb):
    """Each comment is decided with the run id, lookups and outcome of the run whose issue it is on, even when a later run
    of the case has its own issue by then. A3 (ruling 2026-11-09: no run markers; a comment is framed by its issue's run)."""
    decider = S.Decider()
    first = fb.request("case-frame", lookups=[LOOKUP])
    assert fb.tick(decider) == 0
    second = fb.request("case-frame", lookups=[LOOKUP_2])
    assert fb.tick(decider) == 0
    [one], [two] = _run_issues(fb, first), _run_issues(fb, second)
    late = fb.forge.add_comment(one["number"], user=OWNER, body="about the first run, said after the second")
    other = fb.forge.add_comment(two["number"], user=NAMED, body="about the second run")
    assert fb.tick(decider) == 0

    assert sorted(decider.decided) == sorted([late["id"], other["id"]])
    assert (decider.item(late["id"])["run_id"], decider.item(late["id"])["lookups"]) == (S.run_id_of(first), [LOOKUP])
    assert (decider.item(other["id"])["run_id"], decider.item(other["id"])["lookups"]) == (S.run_id_of(second), [LOOKUP_2])
    assert decider.item(other["id"])["outcome"] == "inconclusive"


# ---------------------------------------------------------------- F2 step 2: read (O3, O4, D12, D13)

def test_1414_only_eligible_non_bot_authors_are_decided_in_order(fb, caplog):
    """Comments by the record's two logins are decided in order; an outsider's, the bot's (even if recorded) and the forge-whitelisted outsider's are skipped and logged. O3/F2.2/D13."""
    fb.eligible(OWNER, NAMED, fb.bot)
    number = fb.opened("case-who")
    ann = fb.forge.add_comment(number, user=OWNER, body="expected")
    fb.forge.add_comment(number, user=OUTSIDER, body="approved, add it")
    fb.forge.add_comment(number, user=fb.bot, body="a bot comment")
    bea = fb.forge.add_comment(number, user=NAMED, body="check the VPN log first")

    decider = S.Decider()
    with caplog.at_level(logging.INFO):
        assert fb.tick(decider) == 0
    assert decider.decided == [ann["id"], bea["id"]]
    assert decider.item(ann["id"])["author"] == OWNER
    assert any(OUTSIDER in r.getMessage() for r in caplog.records), "the skipped outsider is not in the tick's log"
    assert fb.requests_to("branch_protections", "/teams", "/orgs/") == [], "the tick read the forge's own whitelist (D13)"


def test_1414_a_login_dropped_from_the_record_stops_counting_at_the_next_tick(fb):
    """After the service rewrites its record without an account, that account's comments are not read; the account still on it is. O3/D13."""
    number = fb.opened("case-removed")
    fb.eligible(OWNER)
    fb.forge.add_comment(number, user=NAMED, body="expected")
    kept = fb.forge.add_comment(number, user=OWNER, body="expected too")

    decider = S.Decider()
    assert fb.tick(decider) == 0
    assert decider.decided == [kept["id"]]


@pytest.mark.parametrize(("age", "bound", "env", "fresh"), [
    (dt.timedelta(seconds=50), None, None, True),       # inside the default bound (60 s, D15), env unset
    (dt.timedelta(seconds=70), None, None, False),      # past it
    (dt.timedelta(seconds=50), None, "30", False),      # the env bound (30 s) governs when no seam is given
    (dt.timedelta(seconds=50), None, "100", True),      # and a larger env bound admits it
    (dt.timedelta(seconds=30), dt.timedelta(seconds=60), None, True),
    (dt.timedelta(seconds=120), dt.timedelta(seconds=60), None, False),
    (dt.timedelta(seconds=30), dt.timedelta(seconds=60), "10", True),   # the seam wins over the env
])
def test_1414_a_stale_record_reads_no_comments_and_a_fresh_one_reads_them(fb, caplog, monkeypatch, age, bound, env, fresh):
    """A record older than the bound (the seam, else `LEARNING_FEEDBACK_ELIGIBILITY_MAX_AGE`, else 60 s) makes the tick read nothing and log why; the comment is read once it is fresh. D13/D15."""
    if env is None:
        monkeypatch.delenv(S.ELIGIBILITY_MAX_AGE_ENV, raising=False)
    else:
        monkeypatch.setenv(S.ELIGIBILITY_MAX_AGE_ENV, env)
    number = fb.opened("case-stale")
    comment = fb.forge.add_comment(number, user=OWNER, body="expected")
    fb.eligible(OWNER, NAMED, age=age)
    seams = {} if bound is None else {"eligibility_max_age": bound}

    decider = S.Decider()
    with caplog.at_level(logging.INFO):
        assert fb.tick(decider, **seams) == 0
    assert decider.decided == ([comment["id"]] if fresh else [])
    if not fresh:
        assert _loud(caplog, "eligib"), "a stale record is not logged"
        fb.eligible(OWNER, NAMED)
        assert fb.tick(decider, **seams) == 0
        assert decider.decided == [comment["id"]], "the position moved past a comment read under a stale record"
        assert fb.replies(number, comment["id"]), "the comment's outcome was not delivered once fresh"


def test_1414_an_absent_record_reads_no_comments_and_counts_nothing(fb, caplog):
    """A tenant whose row holds no eligibility record is read as stale: nothing decided, logged, and a comment two attempts into its ceiling is still decided normally once fresh. D13/A4."""
    number = fb.opened("case-absent")
    comment = fb.forge.add_comment(number, user=OWNER, body="expected")
    decider = S.Decider({comment["id"]: [S.answer(approve=(9,)), S.answer(approve=(9,)),
                                         S.answer(reason="nothing to learn")]})
    for _ in range(2):  # two refused answers: the comment stands at 2 of 3
        assert fb.tick(decider) == 0
    assert decider.decided == [comment["id"]] * 2
    bare = fb.t.directory_with()  # a tenant row the service never wrote a record to

    with caplog.at_level(logging.INFO):
        for _ in range(5):
            assert fb.tick(decider, directory=bare) == 0
    assert decider.decided == [comment["id"]] * 2, "a comment was read under an absent record"
    assert _loud(caplog, "eligib")
    assert fb.replies(number, comment["id"]) == []

    assert fb.tick(decider) == 0  # the scene's directory holds a fresh record
    assert decider.decided == [comment["id"]] * 3
    [reply] = fb.replies(number, comment["id"])
    assert "could not be processed" not in reply["body"], "stale ticks were counted as attempts"
    assert "nothing to learn" in reply["body"]


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


def test_1414_comments_before_the_close_are_decided_after_it_are_ignored_and_a_reopen_reads_on(fb):
    """On a closed issue, comments dated before closed_at are decided and replied to, later ones never read, even after a reopen. D12/O4."""
    number = fb.opened("case-closed")
    before = fb.forge.add_comment(number, user=OWNER, body="said before the close", created_at=fb.at(-20))
    after = fb.forge.add_comment(number, user=OWNER, body="said while closed", created_at=fb.at(-5))
    fb.forge.set_issue_state(number, "closed", at=fb.at(-10))
    decider = S.Decider()
    assert fb.tick(decider) == 0
    assert decider.decided == [before["id"]]
    assert len(fb.replies(number, before["id"])) == 1, "the pre-close comment's reply was not posted on the closed issue"

    fb.forge.set_issue_state(number, "open")
    later = fb.forge.add_comment(number, user=OWNER, body="read after the reopen")
    assert fb.tick(decider) == 0
    assert decider.decided == [before["id"], later["id"]]
    assert after["id"] not in decider.decided


def test_1414_a_decision_recorded_before_a_close_is_still_replied_to(fb):
    """A reply that could not be posted before the issue closed is posted on the closed issue. D12/O5."""
    number = fb.opened("case-late-reply")
    comment = fb.forge.add_comment(number, user=OWNER, body="nothing to change")
    fb.forge.respond = lambda r: (httpx.Response(503, json={}) if r.method == "POST" and r.url.path.endswith(f"/issues/{number}/comments") else None)
    decider = S.Decider({comment["id"]: S.answer(reason="nothing to learn")})
    fb.tick(decider)
    assert decider.decided == [comment["id"]]
    assert fb.replies(number, comment["id"]) == [], "premise: the reply was refused"

    fb.forge.respond = None
    fb.forge.set_issue_state(number, "closed")
    assert fb.tick(decider) == 0
    assert decider.decided == [comment["id"]], "the recorded decision was taken again"
    assert len(fb.replies(number, comment["id"])) == 1


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


# ---------------------------------------------------------------- Replies (O5)

def test_1414_a_no_change_gets_one_reply_with_its_marker_and_the_reason(fb):
    """A comment the model answers with a reason gets exactly one bot reply carrying its marker and that reason, however many ticks run. O5."""
    number = fb.opened("case-nochange")
    comment = fb.forge.add_comment(number, user=OWNER, body="thanks")
    decider = S.Decider({comment["id"]: S.answer(reason="a thanks, nothing to learn from it")})

    for _ in range(3):
        assert fb.tick(decider) == 0
    [reply] = fb.replies(number, comment["id"])
    assert "no change" in reply["body"].lower()
    assert "a thanks, nothing to learn from it" in reply["body"]
    assert reply["user"]["login"] == fb.bot


def test_1414_a_reply_already_on_the_issue_is_not_posted_again(fb):
    """Whether a reply is owed is read from the issue: a bot comment carrying the marker already settles it. O5/P5."""
    number = fb.opened("case-owed")
    comment = fb.forge.add_comment(number, user=OWNER, body="nothing to change here")
    fb.forge.add_comment(number, user=fb.bot, body=f"no change {S.marker(comment['id'])}")
    decider = S.Decider({comment["id"]: S.answer(reason="nothing to learn")})

    assert fb.tick(decider) == 0
    assert decider.decided == [comment["id"]], "premise: the comment was decided"
    assert len(fb.replies(number, comment["id"])) == 1


def test_1414_a_lost_reply_is_posted_again_but_a_seen_one_is_settled_for_good(fb):
    """A reply that never reached the issue is posted by a later tick; once seen, deleting it does not bring it back (the decision is settled). O5/A1."""
    number = fb.opened("case-settle")
    lost = fb.forge.add_comment(number, user=OWNER, body="one")
    fb.forge.respond = lambda r: (httpx.Response(503, json={}) if r.method == "POST" and r.url.path.endswith("/comments") else None)
    decider = S.Decider({lost["id"]: S.answer(reason="r1")})
    fb.tick(decider)
    assert fb.replies(number, lost["id"]) == []
    fb.forge.respond = None
    assert fb.tick(decider) == 0
    [reply] = fb.replies(number, lost["id"])

    assert fb.tick(decider) == 0  # the tick that sees the reply on the issue
    fb.forge.remove_comment(number, reply["id"])
    assert fb.tick(decider) == 0
    assert fb.replies(number, lost["id"]) == [], "a settled decision was read again and its reply re-posted"
    assert decider.decided == [lost["id"]]
    assert remote_branches(fb.t.remote, S.FEEDBACK_PREFIX) == {}


# ---------------------------------------------------------------- a rotated tenant (D13: every generation's bot)

def _rotated(fb):
    """The tenant after a rotation: its first generation destroyed, the fixture's bot live; the directory and the old bot's login."""
    from defender.tenancy import TenantDirectory
    from defender.tests.support.tenancy._active1214 import generation_fields
    from defender.tests.support.tenancy._proxied1391 import with_sign_login

    tid = fb.t.tenant_id
    old = with_sign_login(tid, generation_fields(tid, fb.tmp / "secrets", salt="g0", status="destroyed"))
    new = with_sign_login(tid, generation_fields(tid, fb.tmp / "secrets", salt="g1"))
    assert new["bot_login"] == fb.bot, "premise: the live generation is the forge's login"
    twin = fb.t.repository_with(generations=[old, new])
    asyncio.run(twin.record_merge_eligibility(
        tid, logins=frozenset({OWNER, NAMED, old["bot_login"]}), read_at=dt.datetime.now(dt.UTC)))
    return TenantDirectory(lambda: twin), old["bot_login"]


def test_1414_what_the_old_generations_bot_made_is_still_the_bots(fb):
    """After a rotation the old bot's issue is recovered as its run's, its replies are seen, and its comments are never
    decided. D13/O2/O3/A6 (ruling 2026-11-09: recovery by first line and a bot creator of any generation)."""
    directory, old_bot = _rotated(fb)
    case = "case-rotated"
    # The old generation's bot makes the run's issue, and the create's reply is lost, so the host never records it.
    fb.forge.login = old_bot
    fb.forge.lose_reply = lambda r: r.method == "POST" and r.url.path.endswith("/issues")
    run = fb.request(case)
    fb.tick(S.Decider(), directory=directory)
    fb.forge.lose_reply = None
    [issue] = _run_issues(fb, run)
    number = issue["number"]
    assert issue["user"]["login"] == old_bot, "premise: the old bot made the issue"
    fb.forge.login = fb.bot  # the live generation's bot recovers it
    decider = S.Decider()
    assert fb.tick(decider, directory=directory) == 0
    assert len(fb.forge.issue_creates()) == 1, "the old bot's issue was not recognised and a second was made"
    assert S.open_issue_requests(fb.paths) == {}

    spoken = fb.forge.add_comment(number, user=OWNER, body="nothing to change")
    decider.script[spoken["id"]] = S.answer(reason="nothing to learn")
    fb.forge.login = old_bot  # the old bot is still the forge's login when it replies
    assert fb.tick(decider, directory=directory) == 0
    assert [c["user"]["login"] for c in fb.forge.comments_on(number) if S.marker(spoken["id"]) in c["body"]] == [old_bot], \
        "premise: the old bot replied"
    fb.forge.login = fb.bot
    chatter = fb.forge.add_comment(number, user=old_bot, body="a note the old bot left")
    posted = len(fb.forge.comments_on(number))

    assert fb.tick(decider, directory=directory) == 0
    assert fb.tick(decider, directory=directory) == 0
    assert len(fb.forge.comments_on(number)) == posted, "a reply the old bot already made was posted again"
    assert decider.decided == [spoken["id"]], "the old bot's comment was decided, or the person's was not"
    assert chatter["id"] not in decider.decided
    positive = fb.forge.add_comment(number, user=NAMED, body="control: a person's later comment")
    assert fb.tick(decider, directory=directory) == 0
    assert decider.decided == [spoken["id"], positive["id"]]
    assert len(fb.replies(number, positive["id"])) == 1


# ---- regressions (#1414 attack triage)

def test_1414_a_lookup_with_a_lone_surrogate_does_not_wedge_the_requests_beside_it(fb):
    """A run whose captured lookups held a lone surrogate (a model's tool argument) queues no request the tick cannot send;
    its ordinary neighbour's issue still opens and its comment is still decided, tick after tick. F1/F2 (P3)."""
    import shutil
    from pathlib import Path

    from defender import run_common
    from defender.box import _scrub as scrub_mod
    from defender.investigation.run_state import RunState
    from defender.records import RunPaths
    from defender.tests.support.learning.core._state1135 import run_of
    from defender.tests.support.sandbox._spec791 import make_run_dir
    from defender.tests.support.shared._fixture_uuid import fixture_uuid
    from defender.tests.support.shared._locations_1210 import location_path
    from defender.tests.support.storage import _feedback1414 as F
    from defender.tests.support.tenancy import _tenants1106 as T1106

    settings = fb.tmp / "settings-copy"
    shutil.copytree(location_path(fb.t.tenant.settings), settings)
    (settings / S.SETTING_FILE).write_text(S.setting_text(["inconclusive"]), encoding="utf-8")
    runs = Path(location_path(fb.t.tenant.tenant_root)) / "runs"
    runs.mkdir(exist_ok=True)
    bad_dir = make_run_dir(runs, name=fixture_uuid("case-surrogate"), disposition="inconclusive",
                           alert_bytes=b'{"rule": {"id": "1414-surrogate"}}')
    scrub_mod.scrub(bad_dir)
    rows = {"l-1": [F.lookup_row("l-1", 0, {"actor": "ann", "host": "db-03", "pattern": "\ud800"}),
                    F.lookup_row("l-1", 1, {"actor": "ann", "host": "db-03", "pattern": "id"})]}
    run_state = RunState(bad_dir, str(run_of(bad_dir).id))
    run_state.rows.update(rows)
    queued = run_common.enqueue_feedback_issue(
        run_of(bad_dir), RunPaths(bad_dir).alert, tenant=T1106.run_tenant(fb.t.tenant, settings_root=settings),
        run_state=run_state)
    assert queued is True, "premise: the run's end queued its request"

    decider = S.Decider()
    fb.request("case-ok")  # the ordinary request, queued beside the bad run's
    assert fb.tick(decider) == 0
    [number] = [i["number"] for i in fb.issues("case-ok")]
    spoken = fb.forge.add_comment(number, user=OWNER, body="nothing to change")
    for _ in range(3):
        assert fb.tick(decider) == 0
    assert decider.decided == [spoken["id"]], "the ordinary run's comment was not decided"
    assert len(fb.replies(number, spoken["id"])) == 1
    assert S.open_issue_requests(fb.paths) == {}, "a request stayed queued, to fail again every tick"


# ---------------------------------------------------------------- attack families (#1414 triage)

def test_1414_a_forged_reply_marker_in_text_the_host_does_not_own_suppresses_no_reply(fb):
    """Every decided comment gets exactly one reply however many reply markers (decided and future ids) people, runs and the model wrote elsewhere. O5/ruling 1."""
    blob = A.hostile(A.forged_markers(fb))
    lookup = {"actor": f"*{blob}", "host": blob, "pattern": blob}
    fb.request("case-forged", lookups=[lookup])
    decider = S.Decider()
    assert fb.tick(decider) == 0
    [issue] = fb.issues("case-forged")
    number = issue["number"]

    # Replies that echo the model's reason, the captured lookup (not draftable: a glob) and the instruction are posted
    # first; the people's comments forge markers of the replies still owed. Replies to the later comments are refused
    # once so they are posted after the hostile ones are on the issue.
    ann1 = fb.forge.add_comment(number, user=OWNER, body=blob)
    ann2 = fb.forge.add_comment(number, user=NAMED, body="approve it")
    ann3 = fb.forge.add_comment(number, user=OWNER, body=f"text\n{blob}")
    stranger = fb.forge.add_comment(number, user=OUTSIDER, body=blob)
    late = [fb.forge.add_comment(number, user=who, body=f"plain {n}") for n, who in enumerate((OWNER, NAMED))]
    held = {c["id"] for c in late}
    stage = {"held": True}

    def hold(request):
        if stage["held"] and request.method == "POST" and request.url.path.endswith(f"/issues/{number}/comments"):
            first = json.loads(request.content)["body"].split("\n")[0]
            if any(S.marker(i) in first for i in held):
                return httpx.Response(503, json={})
        return None

    fb.forge.respond = hold
    decider = S.Decider({
        ann1["id"]: S.answer(reason=blob), ann2["id"]: S.answer(approve=(0,)),
        ann3["id"]: S.answer(instruction=blob), late[0]["id"]: S.answer(reason="plain"),
        late[1]["id"]: S.answer(reason="plain")})
    assert fb.tick(decider) == 0
    assert [fb.replies(number, c["id"]) != [] for c in late] == [False, False], "premise: the later replies were held back"
    stage["held"] = False
    A.tick_until_quiet(fb, decider)
    afterwards = [fb.forge.add_comment(number, user=who, body=f"afterwards {n}") for n, who in enumerate((NAMED, OWNER))]
    A.tick_until_quiet(fb, decider)

    decided = [ann1, ann2, ann3, *late, *afterwards]
    assert decider.decided == [c["id"] for c in decided], "a comment was decided twice, skipped, or out of order"
    for c in decided:
        assert len(fb.replies(number, c["id"])) == 1, f"comment {c['id']} has {len(fb.replies(number, c['id']))} replies"
    assert fb.replies(number, stranger["id"]) == []


#: Forge POSTs of the scenario in order: 1 the feedback label, 2 the issue, 3-4 the two replies. (k=2, reply lost,
#: closed in between): the recovered issue is the run's own however a person left it (ruling 2026-11-09, one issue per
#: run), so D12 reads its comments dated before the close.
_CRASHES = [pytest.param(k, lose, closed, id=f"{k}-{'lost' if lose else 'refused'}-{'closed' if closed else 'open'}")
            for k in (1, 2, 3, 4) for lose in (True, False) for closed in (False, True)]


@pytest.mark.parametrize(("k", "lose", "closed"), _CRASHES)
def test_1414_a_crash_at_any_forge_write_leaves_one_issue_and_one_reply_per_decided_comment(fb, k, lose, closed):
    """Whichever forge POST of the scenario (k-th) is applied-but-unanswered or refused, and whether or not a person closes the issue before the redo, the run has one issue and each eligible comment is decided once and replied to once. P5/O4/O5/A6."""
    scene = A.Scene(fb)
    crash = A.Crasher(fb, k, lose=lose)
    for _ in range(6):
        scene.step()
        if crash.fired and scene.comments:
            break
    assert crash.fired, "premise: the scenario makes fewer forge writes than k"
    if closed:
        scene.close()
    A.tick_until_quiet(fb, scene.decider)
    scene.verify()


def test_1414_an_issue_made_but_not_recorded_and_closed_before_the_redo_is_not_made_again(fb):
    """A create the forge applied (reply lost) whose issue a person then closes is found again by the redo, never re-created. O2/A6."""
    scene = A.Scene(fb)
    crash = A.Crasher(fb, 2, lose=True)
    scene.step()
    assert crash.fired, "premise: the create's reply was lost"
    assert len(fb.issues(scene.case)) == 1, "premise: the forge holds the unrecorded issue"
    scene.close()
    A.tick_until_quiet(fb, scene.decider)
    assert len(fb.issues(scene.case)) == 1, "the closed issue was not recovered and a second was made"
    assert S.open_issue_requests(fb.paths) == {}


@pytest.mark.parametrize(("folder", "stage"), [
    ("feedback-cases", "open"), ("feedback-items", "read"), ("feedback-positions", "read"), ("_pending", "read"),
    ("feedback-items", "first-comment"), ("feedback-items", "second-comment")])
def test_1414_a_failed_state_write_loses_no_comment_and_makes_no_second_issue(fb, folder, stage):
    """A tick that dies on a write into one of its state folders (the folder made unwritable on disk, no hook in the code) is redone whole: one issue, every eligible comment decided and replied to once, its lessons row written. P5/O4/A6."""
    scene = A.Scene(fb)
    record = None
    if stage != "open":
        scene.step()
        assert scene.comments, "premise: the issue was opened and the people commented"
        record = {"first-comment": 0, "second-comment": 1}.get(stage)
        record = None if record is None else str(scene.comments[record]["id"])
    blocked = A.BlockedFolder(fb, folder, record)
    scene.step()
    blocked.restore()
    for _ in range(3):
        if not scene.comments:
            scene.step()
    if stage != "open":
        assert fb.forge.comments_on(scene.number, by=fb.bot) == [] or folder == "_pending", \
            "premise: the failed write stopped the tick before its replies"
    A.tick_until_quiet(fb, scene.decider)
    scene.verify()


# ---------------------------------------------------------------- honest-code regressions (pre-fix e990542ab fails these)

def test_1414_a_newer_request_filed_while_the_older_is_served_survives_the_tick(fb):
    """A request for the case filed by a newer run while a tick opens the issue for the older one is still queued afterwards. A4/F1."""
    older = fb.request("case-mid")
    newer = {}

    def file_newer(request):
        if request.method == "POST" and request.url.path.endswith("/issues") and not newer:
            newer["run"] = S.run_id_of(fb.request("case-mid"))
        return None

    fb.forge.respond = file_newer
    assert fb.tick(S.Decider()) == 0
    assert newer, "premise: the hook ran while the older request was served"
    assert newer["run"] != S.run_id_of(older)
    assert newer["run"] in {r["run_id"] for r in S.open_issue_requests(fb.paths).values()}, \
        "the newer run's request was released with the older one's"


@pytest.mark.parametrize(("ahead", "fresh"), [
    (dt.timedelta(seconds=2), True), (dt.timedelta(seconds=60), False), (dt.timedelta(hours=1), False)])
def test_1414_an_eligibility_record_dated_in_the_future_is_stale_beyond_the_clock_skew(fb, caplog, ahead, fresh):
    """A record dated more than 5 s ahead of the host's clock reads no comments and is logged; one within 5 s is fresh. D13."""
    number = fb.opened("case-future")
    comment = fb.forge.add_comment(number, user=OWNER, body="expected")
    fb.eligible(OWNER, NAMED, age=-ahead)

    decider = S.Decider()
    with caplog.at_level(logging.INFO):
        assert fb.tick(decider) == 0
    assert decider.decided == ([comment["id"]] if fresh else [])
    if not fresh:
        assert _loud(caplog, "eligib"), "a record from the future is not logged"


def test_1414_on_a_closed_issue_a_comment_in_the_same_second_as_the_close_is_read_and_a_later_one_is_not(fb):
    """Comments created at or before closed_at are decided (same second included); one a second after is not. D12."""
    number = fb.opened("case-second")
    same = fb.forge.add_comment(number, user=OWNER, body="said as it closed", created_at=fb.at(-10))
    later = fb.forge.add_comment(number, user=OWNER, body="said a second later", created_at=fb.at(-9))
    fb.forge.set_issue_state(number, "closed", at=fb.at(-10))

    decider = S.Decider()
    assert fb.tick(decider) == 0
    assert decider.decided == [same["id"]]
    assert later["id"] not in decider.decided

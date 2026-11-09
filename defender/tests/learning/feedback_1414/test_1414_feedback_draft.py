"""#1414 F2 step 4 and F3: approvals become a registry-only PR a person merges (O6), settled once (A1/P6), delivered
by one recovery path (A2), appended under a format contract (A7), and cited by a later lookup (O8).
"""
from __future__ import annotations

import datetime as dt
import logging
import re
from pathlib import Path

import pytest
import yaml

from defender.tests.learning.feedback_1414 import _spec1414 as S
from defender.tests.learning.feedback_1414._spec1414 import LOOKUP, LOOKUP_2, NAMED, OWNER, today
from defender.tests.tenancy.tenant_1108_delivery._support import (
    _pulls_updating,
    _save_pulls,
    forge_pulls,
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
              lookups=None, created_at: str | None = None, **answer):
    """An issue for `case` (one tick), a comment by `by` on it (dated `created_at`, else now), and a decider approving it."""
    fb.request(case, lookups=lookups)
    assert fb.tick(S.Decider()) == 0
    [issue] = fb.issues(case)
    comment = fb.forge.add_comment(issue["number"], user=by, body=body, created_at=created_at)
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
    then = today() - dt.timedelta(days=3)
    number, first, decider = _approved(fb, "case-draft", lookups=[LOOKUP, LOOKUP_2], approve=(0,),
                                       created_at=fb.at(-3 * 86400))
    second = fb.forge.add_comment(number, user=NAMED, body=f"also fine until {named_date}")
    decider.script[second["id"]] = S.answer(approve=(1,), review_by=named_date.isoformat())
    main_before = _registry_at(fb, "main")

    assert fb.tick(decider) == 0
    [(branch, tip)] = _drafts(fb).items()
    assert touched(fb.t.remote, "main", tip) == [S.REGISTRY]
    # No gate test exists for F2: no test route puts a stray path into a batch's change set (draft and change set come
    # from the same export commit, and step 4 has no box or forge call between), so this census is what is observable.
    drafted = _registry_at(fb, tip)
    assert [ln for ln in main_before.splitlines() if ln.startswith("#")] == \
        [ln for ln in drafted.splitlines() if ln.startswith("#")], "the file's comments did not survive"

    by_id = {e["id"]: e for e in _read(drafted, fb.tmp)}
    one, two = by_id[S.entry_id(number, first["id"])], by_id[S.entry_id(number, second["id"])]
    assert {k: one[k] for k in FIELDS} == {
        "pattern": LOOKUP["pattern"], "actor_scope": LOOKUP["actor"], "host_scope": LOOKUP["host"],
        "added_by": OWNER, "added_at": then.isoformat(),
        "review_by": (then + dt.timedelta(days=180)).isoformat()}
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
    number, first, decider = _approved(fb, "case-impostor", lookups=[LOOKUP, LOOKUP_2], approve=(0,))
    assert fb.tick(decider) == 0
    [(branch, _)] = _drafts(fb).items()
    real = _pr_of(fb, branch)
    set_pull_state(fb.t.remote, branch, merged=False)  # the bot's own PR, closed: its entry is settled
    settled = S.entry_id(number, first["id"])
    assert settled in real["body"], "premise: the bot's real PR body names its entry"
    second = fb.forge.add_comment(number, user=NAMED, body="and this")
    decider.script[second["id"]] = S.answer(approve=(1,))
    unsettled = S.entry_id(number, second["id"])
    # The impostors carry the real body's own format; only the id they name is the other entry's.
    for head, user in (("feedback/fake", S.OUTSIDER), ("someone/fix", fb.bot)):
        row = pr_row(40 + len(fb.forge.prs), head, state="closed")
        row["body"] = real["body"].replace(settled, unsettled)
        row["user"] = {"login": user}
        fb.forge.add_pr(row)
    before = set(_drafts(fb))

    assert fb.tick(decider) == 0
    fresh = {b: t for b, t in _drafts(fb).items() if b not in before}
    [(_, tip)] = fresh.items()
    assert [e["id"] for e in _entries_at(fb, tip)] == [unsettled], \
        "a PR that was not the bot's feedback PR settled the entry, or the bot's own did not"


def test_1414_ids_in_a_bot_pr_body_are_read_only_from_its_drafted_and_covered_lines(fb):
    """An id of a not-yet-drafted approval written on any other line of the bot's own PR body (a person editing it) settles nothing: after the PR closes that approval is still drafted. P6/A2, ruling 1."""
    number, first, decider = _approved(fb, "case-forged-line", lookups=[LOOKUP, LOOKUP_2], approve=(0,))
    assert fb.tick(decider) == 0
    [(branch, _)] = _drafts(fb).items()
    real = _pr_of(fb, branch)
    assert S.entry_id(number, first["id"]) in real["body"], "premise: the bot's PR body names its entry"
    second = fb.forge.add_comment(number, user=NAMED, body="and this")
    decider.script[second["id"]] = S.answer(approve=(1,))
    later = S.entry_id(number, second["id"])
    # A merger may edit the bot's PR body; the ids are planted where the host never writes an id line.
    forged = (real["body"] + f"\nReviewed, also fine: {later}\n> drafted: {later} (quoted)\n"
              f"not covered: {later} by {S.entry_id(number, first['id'])}\nsee {later}\n")
    with _pulls_updating(fb.t.remote):
        rows = forge_pulls(fb.t.remote)
        [row] = [r for r in rows if r["number"] == real["number"]]
        row["body"] = forged
        _save_pulls(fb.t.remote, rows)
    assert later in _pr_of(fb, branch)["body"]

    assert fb.tick(decider) == 0  # the PR is still open; the forged ids are read, or not, on this tick
    assert fb.replies(number, second["id"]) == [], "an id on a line the host did not write settled the approval"
    set_pull_state(fb.t.remote, branch, merged=False)
    assert fb.tick(decider) == 0
    [(_, tip)] = [(b, t) for b, t in _drafts(fb).items() if b != branch]
    assert [e["id"] for e in _entries_at(fb, tip)][-1] == later, "the approval was settled by a forged line, not drafted"
    [reply] = fb.replies(number, second["id"])
    assert "already covered" not in reply["body"]


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


def test_1414_a_pr_the_forge_applied_but_never_answered_is_found_not_drafted_again(fb):
    """A crash between the PR's creation and the settlement record: the next tick reads the bot's feedback/ PR body, drafts nothing more and replies with its link. A1/A2/P6."""
    number, comment, decider = _approved(fb, "case-crash", approve=(0,))
    fb.forge.lose_reply = lambda r: r.method == "POST" and r.url.path.endswith("/pulls")
    fb.tick(decider)
    [(branch, _)] = _drafts(fb).items()
    assert len(fb.forge.prs) == 1, "premise: the forge applied the create"

    fb.forge.lose_reply = None
    for _ in range(3):
        assert fb.tick(decider) == 0
    assert len(fb.forge.prs) == 1, "the entry was drafted into a second PR"
    assert list(_drafts(fb)) == [branch]
    assert decider.decided == [comment["id"]]
    [reply] = fb.replies(number, comment["id"])
    assert _pr_of(fb, branch)["html_url"] in reply["body"]


def test_1414_while_a_feedback_pr_is_open_new_requests_and_no_change_replies_still_go_out(fb):
    """With the writer lease held by an open feedback PR, a new open-issue request still opens its issue and a no-change comment still gets its reply, in the same tick. P6/A2/O2/O5."""
    number, comment, decider = _approved(fb, "case-held", approve=(0,))
    assert fb.tick(decider) == 0
    [(branch, _)] = _drafts(fb).items()
    assert _pr_of(fb, branch)["state"] == "open"
    thanks = fb.forge.add_comment(number, user=NAMED, body="thanks")
    decider.script[thanks["id"]] = S.answer(reason="a thanks")
    fb.request("case-while-open")

    assert fb.tick(decider) == 0
    [fresh] = fb.issues("case-while-open")
    assert fresh["user"]["login"] == fb.bot
    assert S.open_issue_requests(fb.paths) == {}
    [reply] = fb.replies(number, thanks["id"])
    assert "a thanks" in reply["body"]
    assert len(fb.forge.prs) == 1


def test_1414_an_entry_the_reader_drops_on_main_does_not_block_drafting(fb):
    """A registry on main holding an entry the reader drops still takes the new entry, and keeps the dropped one's lines. O6/A7."""
    bad = {"id": "tk-bad", "pattern": "x"}  # missing every other field: the reader drops it
    _main_with(fb, [bad])
    number, comment, decider = _approved(fb, "case-dropped", approve=(0,))

    assert fb.tick(decider) == 0
    [(_, tip)] = _drafts(fb).items()
    drafted = _registry_at(fb, tip)
    assert [e["id"] for e in yaml.safe_load(drafted)["entries"]] == ["tk-bad", S.entry_id(number, comment["id"])]
    assert "tk-bad" in drafted
    assert fb.replies(number, comment["id"]), "the approval got no reply"


def test_1414_a_closed_issues_approval_is_drafted_and_replied_to(fb):
    """A comment written before an issue closed and approving a lookup is drafted and answered with the PR link after the close. D12/O6/O5."""
    number, comment, decider = _approved(fb, "case-closed-approval", approve=(0,), created_at=fb.at(-20))
    fb.forge.set_issue_state(number, "closed", at=fb.at(-10))

    assert fb.tick(decider) == 0
    [(branch, tip)] = _drafts(fb).items()
    assert [e["id"] for e in _entries_at(fb, tip)] == [S.entry_id(number, comment["id"])]
    [reply] = fb.replies(number, comment["id"])
    assert _pr_of(fb, branch)["html_url"] in reply["body"]


# ---------------------------------------------------------------- A7 / ruling 2: the read-back

_ENTRY = ("  - id: tk-old\n    pattern: other pattern text\n    actor_scope: svc-other\n    host_scope: web-01.prod\n"
          "    added_by: ops@example.invalid\n    added_at: 2026-10-01\n    review_by: 2026-12-01\n    justification: kept\n")
def _reading(text: str, tmp: Path, name: str):
    """The shared reader's whole reading of `text` (entries, refusals, fatal), not asserted on."""
    from defender.systems import tacit_registry

    path = tmp / "reading" / name / "registry.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.encode("utf-8"))
    return tacit_registry.read_registry(path)


def _crlf(text: str) -> str:
    return text.replace("\n", "\r\n")


def _mains(number: int, cid: int) -> dict[str, str]:
    """Registry texts a person may have merged to main. `duplicate id on main` already holds the id the second approved
    lookup will be given (the first, plain one stays free)."""
    taken = _ENTRY.replace("tk-old", f"fb-{number}-{cid}-2").replace("other pattern text", "an earlier text")
    bad = "  - id: tk-bad\n    pattern: x\n"
    return {
        "block list": f"# header\nentries:\n{_ENTRY}",
        "empty flow list": "# header\nentries: []\n",
        "entries null": "# header\nentries:\n",
        "comment-only entries": "entries:\n  # none yet\n  # still none\n",
        "document start": f"---\nentries:\n{_ENTRY}",
        "multi-document": "---\nentries: []\n---\nentries: []\n",
        "document end": f"entries:\n{_ENTRY}...\n",
        "crlf block list": _crlf(f"# header\nentries:\n{_ENTRY}"),
        "crlf empty flow list": _crlf("# header\nentries: []\n"),
        "duplicate id on main": f"entries:\n{_ENTRY}{taken}",
        "refused entry on main": f"entries:\n{_ENTRY}{bad}",
        "non-empty flow list": "# header\nentries: [{id: tk-old}]\n",
    }


_SPECIALS = ["\u0085", " ", " ", " ", " ", "\t", "'", '"', ": ", " #", "#", "\\", "é", "日本"]


def _lookups(seed: int, n: int = 8) -> list[dict]:
    """`n` lookups: the first plain, the rest with arbitrary Unicode at the start, middle or end of the actor, host
    and pattern (no glob character: F3 owns those). Every pattern is distinct, so none covers another."""
    import random

    rng = random.Random(seed)
    out = [{"actor": "svc-backup", "host": "db-07.prod", "pattern": "pg_dump --all as root 0"}]
    for i in range(1, n):
        fields = {"actor": ["svc-backup"], "host": ["db-07.prod"], "pattern": ["pg_dump --all as root ", str(i)]}
        for _ in range(rng.randint(1, 3)):
            parts = fields[rng.choice(sorted(fields))]
            parts.insert(rng.choice([0, len(parts) // 2, len(parts)]), rng.choice(_SPECIALS))
        out.append({k: "".join(v) for k, v in fields.items()})
    return out


def _entry_ids(number: int, cid: int, count: int) -> list[str]:
    return [S.entry_id(number, cid, n) for n in range(1, count + 1)]


def _segments(value: str) -> list[str]:
    """The parts of `value` a reply quoting it must still show: the printable ASCII runs (a quote, a backslash, a space or
    a control or non-ASCII character may be escaped or folded by the quoting, so they split the value)."""
    return [p for p in re.split(r"[^\x21-\x7e]|['\"\\]", value) if p]


def _naming_line(reply: str, eid: str) -> str | None:
    """The reply's statement about entry id `eid` (the line naming it as a whole id, not as the front of a longer one,
    and any lines after it up to the next "Entry" line, since a reader verdict may span lines), or None."""
    lines = reply.splitlines()
    for at, line in enumerate(lines):
        if re.search(rf"(?<![\w-]){re.escape(eid)}(?![\w-])", line):
            rest = []
            for more in lines[at + 1:]:
                if more.startswith("Entry "):
                    break
                rest.append(more)
            return "\n".join([line, *rest])
    return None


def _assert_names(reply: str, eid: str, lookup: dict, *fields: str) -> None:
    """The reply names `eid` and, on the same line, shows the named lookup fields' values."""
    line = _naming_line(reply, eid)
    assert line is not None, f"{eid} is not named in the reply"
    for field in fields:
        for part in _segments(lookup[field]):
            assert part in line, f"the line naming {eid} does not show the lookup's {field} ({part!r}): {line!r}"


def _assert_drafted_or_named(fb, mains_text: str, lookups: list[dict], number: int, comment: dict,
                             *, tick_logged: bool) -> dict[int, bool]:
    """The oracle for one approval of `lookups` over main text `mains_text`, from the shared reader's output on main
    and on the PR head. Returns which lookup indices were drafted."""
    ids = _entry_ids(number, comment["id"], len(lookups))
    drafts = _drafts(fb)
    reply_bodies = [r["body"] for r in fb.replies(number, comment["id"])]
    reply = reply_bodies[0] if reply_bodies else ""
    if not drafts:
        assert fb.forge.prs == [], "a PR was opened with nothing drafted"
        if _reading(mains_text, fb.tmp, "main-first").fatal is None:
            # main reads fine and the plain lookup was not drafted: the read-back failed for every entry, which is a
            # file-level failure (ruling 2), never an entry failing alone: no reply, a logged refusal, retried next tick
            assert not reply_bodies, "main reads fine, nothing was drafted, yet the approval was answered"
            assert tick_logged, "main reads fine, nothing was drafted and the refusal was not logged"
        elif reply_bodies:  # entry by entry: every approved lookup is named, with the value that stopped it
            for eid, lookup in zip(ids, lookups, strict=True):
                _assert_names(reply, eid, lookup, "actor", "host", "pattern")
        else:  # a file-level refusal: logged, and the approval settles nothing
            assert tick_logged, "nothing was drafted, no reply was posted and no refusal was logged"
        return {}
    [(branch, tip)] = drafts.items()
    assert touched(fb.t.remote, "main", tip) == [S.REGISTRY], "the feedback PR changes more than the registry"
    before, after = _reading(mains_text, fb.tmp, "main"), _reading(_registry_at(fb, tip), fb.tmp, "pr")
    assert after.fatal is None, f"the reader refuses the drafted registry: {after.fatal}"
    assert after.refusals == before.refusals, "the draft changes what the reader refuses"
    assert after.entries[:len(before.entries)] == before.entries, "the draft changes main's entries"
    extra = {e["id"]: e for e in after.entries[len(before.entries):]}
    assert len(extra) == len(after.entries) - len(before.entries)
    assert set(extra) <= set(ids), f"entries nobody approved were drafted: {sorted(set(extra) - set(ids))}"
    assert extra, "a PR was opened that drafts nothing"
    drafted = {}
    for k, (eid, lookup) in enumerate(zip(ids, lookups, strict=True)):
        drafted[k] = eid in extra
        if eid in extra:
            got = extra[eid]
            assert (got["actor_scope"], got["host_scope"], got["pattern"]) == \
                (lookup["actor"], lookup["host"], lookup["pattern"]), \
                f"{eid} was drafted as {got!r}, not as the lookup {lookup!r}"
        else:
            _assert_names(reply, eid, lookup, "actor", "host", "pattern")
    assert _pr_of(fb, branch)["html_url"] in reply
    return drafted


@pytest.mark.parametrize("seed", [11, 12])
@pytest.mark.parametrize("main", sorted(_mains(0, 0)))
def test_1414_every_drafted_entry_reads_back_as_the_lookup_and_the_rest_are_named(fb, main, seed, caplog):
    """Over any registry text on main and lookups holding arbitrary Unicode, the reader sees on the PR main's entries
    and refusals unchanged plus only entries equal to their lookup, and every other approval is named or logged. O6/A7."""
    lookups = _lookups(seed)
    number, comment, decider = _approved(fb, "case-readback", lookups=lookups, approve=tuple(range(len(lookups))))
    text = _mains(number, comment["id"])[main]
    fb.t.merge({S.REGISTRY: text})

    with caplog.at_level(logging.INFO):
        assert fb.tick(decider) == 0
    logged = any(r.levelno >= logging.WARNING and r.name != "httpx" for r in caplog.records)
    drafted = _assert_drafted_or_named(fb, text, lookups, number, comment, tick_logged=logged)
    assert drafted.get(0) or (not fb.replies(number, comment["id"]) and logged), (
        "positive control: the plain lookup was not drafted although main reads fine "
        "(then the read-back failed for every entry: a file-level failure, so no reply and a logged refusal)")


#: FC: candidate mains the test itself writes; each is kept only if the shared reader's own reading of main is fatal
#: (the premise is asserted below), so refusing the draft is the only honest outcome. `no entries key` is defensible
#: on that ground alone: main's own reading is fatal. Which texts the reader finds fatal is its call, not named here.
_UNREADABLE_MAINS = {
    "multi-document": "---\nentries: []\n---\nentries: []\n",
    "broken flow list": "entries: [unclosed\n",
    "top level is a scalar": "just some text\n",
    "no entries key": "other: 1\n",
}


@pytest.mark.parametrize("main", sorted(_UNREADABLE_MAINS))
def test_1414_a_file_level_read_back_failure_refuses_the_draft_and_settles_nothing(fb, main, caplog):
    """A main no append can be read back from (the reader refuses it) refuses the draft every tick, past the ceiling: uncounted, nothing quarantined, no branch, PR or reply, a warning; once a person fixes main the entry is drafted. A7/A8, ruling 2."""
    number, comment, decider = _approved(fb, "case-file-level", approve=(0,))
    text = _UNREADABLE_MAINS[main]
    fb.t.merge({S.REGISTRY: text})
    assert _reading(text, fb.tmp, "premise").fatal is not None, "premise: the reader reads this main"

    for tick in range(5):
        caplog.clear()
        with caplog.at_level(logging.INFO):
            assert fb.tick(decider) == 0
        assert _drafts(fb) == {}, f"tick {tick}: a branch was made"
        assert fb.forge.prs == [], f"tick {tick}: a PR was made"
        assert fb.replies(number, comment["id"]) == [], f"tick {tick}: the entry was settled and answered"
        assert any(r.levelno >= logging.WARNING and r.name != "httpx" for r in caplog.records), \
            f"tick {tick}: the refusal is not logged"
    assert decider.decided == [comment["id"]]

    fb.t.merge({S.REGISTRY: f"# header\nentries:\n{_ENTRY}"})
    assert fb.tick(decider) == 0
    [(_, tip)] = _drafts(fb).items()
    assert touched(fb.t.remote, "main", tip) == [S.REGISTRY]
    assert [e["id"] for e in _entries_at(fb, tip)][-1] == S.entry_id(number, comment["id"])
    assert decider.decided == [comment["id"]]


_GLOBS = ["*", "?", "[", "]", "[!x]", "[a-c]", "[!]x]"]


@pytest.mark.parametrize("glob", _GLOBS)
def test_1414_a_glob_character_in_either_scope_is_not_drafted_and_is_named(fb, glob):
    """A lookup whose actor or host holds a glob character at the start, middle or end is never drafted and the reply
    names it; a plain lookup beside them is. P3."""
    plain = {"actor": "svc-backup", "host": "db-07.prod", "pattern": "pg_dump --all as root 0"}
    lookups = [plain]
    for field, base in (("actor", "svc-backup"), ("host", "db-07.prod")):
        for value in (glob + base, base[:4] + glob + base[4:], base + glob):
            lookups.append({**plain, field: value, "pattern": f"pg_dump --all as root {len(lookups)}"})
    number, comment, decider = _approved(fb, "case-glob", lookups=lookups, approve=tuple(range(len(lookups))))

    assert fb.tick(decider) == 0
    [(branch, tip)] = _drafts(fb).items()
    assert touched(fb.t.remote, "main", tip) == [S.REGISTRY]
    assert [(e["actor_scope"], e["host_scope"], e["pattern"]) for e in _entries_at(fb, tip)[-1:]] == \
        [(plain["actor"], plain["host"], plain["pattern"])], "positive control: the plain lookup was not the one drafted"
    assert [e["id"] for e in _entries_at(fb, tip)] == [S.entry_id(number, comment["id"], 1)], "a globbed lookup was drafted"
    [reply] = fb.replies(number, comment["id"])
    for n in range(2, len(lookups) + 1):
        lookup = lookups[n - 1]
        offending = lookup["actor"] if lookup["actor"] != plain["actor"] else lookup["host"]
        line = _naming_line(reply["body"], S.entry_id(number, comment["id"], n))
        assert line is not None, f"the reply does not name {lookup!r}"
        assert offending in line, f"the reply does not show the glob value {offending!r}: {line!r}"


# ---------------------------------------------------------------- A1: covered means the shared reader's find_entry hits today

def _window(added: int, review: int) -> dict:
    return {"added_at": (today() + dt.timedelta(days=added)).isoformat(),
            "review_by": (today() + dt.timedelta(days=review)).isoformat()}


_WINDOWS = {
    "both before today": _window(-60, -10),
    "both after today": _window(10, 40),
    "spanning today": _window(-5, 60),
    "ending today": _window(-30, 0),
    "starting today": _window(0, 30),
}


@pytest.mark.parametrize("window", sorted(_WINDOWS))
def test_1414_an_approval_is_covered_exactly_when_find_entry_hits_main_today(fb, window):
    """An approved lookup is "already covered by" the entry on main iff the shared find_entry hits it today; otherwise it is drafted. O6/A1."""
    from defender.systems import tacit_registry

    _main_with(fb, [_covering(**_WINDOWS[window])])
    read = _reading(_registry_at(fb, "main"), fb.tmp, "main")
    hit = tacit_registry.find_entry(list(read.entries), actor=LOOKUP["actor"], host=LOOKUP["host"],
                                    pattern=LOOKUP["pattern"], now=today())
    number, comment, decider = _approved(fb, "case-window", approve=(0,))

    assert fb.tick(decider) == 0
    [reply] = fb.replies(number, comment["id"])
    if hit is not None:
        assert _drafts(fb) == {}
        assert f"already covered by entry {hit['id']}" in reply["body"]
    else:
        [(_, tip)] = _drafts(fb).items()
        assert touched(fb.t.remote, "main", tip) == [S.REGISTRY]
        assert [e["id"] for e in _entries_at(fb, tip)][-1] == S.entry_id(number, comment["id"])
        assert "already covered" not in reply["body"]


def test_1414_the_covering_windows_hold_both_outcomes():
    """The window table has a covering and a non-covering case, so the covered test cannot pass by one answer. A1."""
    from defender.systems import tacit_registry

    hits = {w: tacit_registry.find_entry([_covering(**_WINDOWS[w])], actor=LOOKUP["actor"], host=LOOKUP["host"],
                                         pattern=LOOKUP["pattern"], now=today()) is not None for w in _WINDOWS}
    assert hits == {"both before today": False, "both after today": False, "spanning today": True,
                    "ending today": True, "starting today": True}


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

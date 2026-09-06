"""#922 — O6/D9: the cutover record, and the two CLI stages that leave with it.

O6 is "the two loops never ran in production concurrently". Premise correction 5 makes it
CHECKABLE rather than historical: #791 removed the investigation's own enqueue, so the old loop
has no automatic feed and runs only when an operator invokes `loop.py <run_dir>` or
`loop.py --learn-drain` by hand. The check is therefore over OPERATOR INVOCATIONS, and D9 gives
it a mechanism in two halves, ORDERED:

  1. write the cutover record — the old loop's last hand-invoked run, and the first branch
     episode — as a dated file in the repo;
  2. remove the two CLI stages in the same change, so the record is written while the
     invocation still exists to be recorded.

Both halves are RED-FIRST: neither the record nor the removal exists at HEAD.

WHAT IS PINNED AND WHAT IS NOT. The record's CONTENT is a fact about this deployment's history
that only the human running the cutover can supply, so nothing here asserts a particular run id
or timestamp. What is pinned is that the record EXISTS at a resolvable address, that it names
both endpoints under keys a reader can find, and that the ORDER it records is the one O6 claims
— the old loop's last run does not follow the first branch episode. A record that merely
existed would discharge nothing; a record whose two timestamps interleave would REFUTE O6 and
must fail here rather than be filed as prose.

THE CLI DRIVES ARE DELIBERATELY UNEXECUTABLE AT HEAD. Both stages reach `DEFAULT_PATHS` — the
real checkout's learning state and the real git worktree — so a drive that let them run would
be a test doing the operator's work against the repository it lives in. Each argv below is
chosen so that HEAD's parser rejects it BEFORE dispatch (its own "takes no run_dir" arm, or the
run-id grammar refusal `run_one` raises before it writes anything), while a parser that no
longer knows the flag or the positional exits 2 out of argparse. The difference between "exit 1
with the stage's own message" and "SystemExit from argparse" is the whole demand.
"""
from __future__ import annotations

import re
from datetime import date, datetime
from pathlib import Path

import pytest

from defender._frontmatter import parse_frontmatter
from defender.learning.core import cli

DEFENDER = Path(__file__).resolve().parents[1]

#: Where D9's dated record lives. `docs/` is where this repo already keeps its retirement
#: records (`docs/review-gate-retirement.md`), and the name says what the file is about rather
#: than which issue filed it.
CUTOVER_RECORD = DEFENDER / "docs" / "learning-loop-cutover.md"

#: The two endpoint keys the record's frontmatter must carry. Each is a mapping with an `at`
#: the reader below parses; `at: never` is the honest value for an endpoint that has no
#: instance in this deployment, and it is a WORD rather than a null so an absent key and a
#: deliberate "this never happened" stay distinguishable.
LAST_OLD_RUN = "last_old_loop_run"
FIRST_EPISODE = "first_branch_episode"
NEVER = "never"


def _as_instant(value) -> datetime | None:
    """One endpoint's `at`, as an instant — or `None` for the recorded `never`.

    Accepts what YAML hands back for a timestamp scalar (a `datetime`/`date`) and the ISO-8601
    string form, because the record is hand-written and both spellings are legitimate; anything
    else is a value this reader will not stand behind, and it raises rather than sorting.
    """
    if isinstance(value, str) and value.strip().lower() == NEVER:
        return None
    if isinstance(value, datetime):
        return value.replace(tzinfo=None)
    if isinstance(value, date):
        return datetime(value.year, value.month, value.day)
    if isinstance(value, str):
        text = value.strip().replace("Z", "+00:00")
        parsed = datetime.fromisoformat(text)
        return parsed.replace(tzinfo=None)
    raise AssertionError(
        f"the cutover record's `at` is {value!r} ({type(value).__name__}) — expected an "
        f"ISO-8601 instant or the word {NEVER!r}")


def _endpoint(fm: dict, key: str) -> dict:
    value = fm.get(key)
    assert isinstance(value, dict), (
        f"the cutover record's frontmatter has no `{key}:` mapping — O6 is a claim about the "
        f"ORDER of two endpoints, and a record naming only one of them states nothing "
        f"(frontmatter keys: {sorted(fm)})")
    return value


def test_922_the_cutover_record_exists_and_is_dated():
    """RED-FIRST (fails at HEAD).

    D9's first half. The record is a dated file in the repo, with parseable frontmatter, so
    that O6's claim is readable by something other than a human scanning prose.

    AT HEAD: `defender/docs/learning-loop-cutover.md` does not exist.
    """
    assert CUTOVER_RECORD.is_file(), (
        f"{CUTOVER_RECORD.relative_to(DEFENDER.parent)} does not exist — D9 requires the "
        "cutover record to be written in the same change that removes the CLI stages, and "
        "BEFORE them: once the invocation is gone there is nothing left to record")
    fm, body = parse_frontmatter(CUTOVER_RECORD.read_text(encoding="utf-8"))
    assert _as_instant(fm.get("recorded")) is not None, (
        f"the cutover record carries no `recorded:` date (frontmatter keys: {sorted(fm)})")
    assert body.strip(), (
        "the cutover record has no body — the frontmatter is the machine-readable half; the "
        "prose is what tells the next reader how the two endpoints were established")


def test_922_the_cutover_record_names_both_endpoints_in_the_order_o6_claims():
    """RED-FIRST (fails at HEAD).

    D9's first half, at the part that carries the obligation. O6 says the two loops never ran
    concurrently; with no automatic feed the check is over operator invocations, so the record
    must name the old loop's LAST hand-invoked run and the branch loop's FIRST episode, and the
    first must not FOLLOW the second.

    The ordering is asserted rather than assumed, and it is asserted only when both endpoints
    are instants — an old loop recorded as `never` run in production discharges O6 outright,
    and that is a different (stronger) fact, not a weaker one. Which of the two held is
    reported in the failure message either way, so a record cannot satisfy this by being
    unreadable.

    AT HEAD: there is no record to read.
    """
    assert CUTOVER_RECORD.is_file(), (
        f"{CUTOVER_RECORD.relative_to(DEFENDER.parent)} does not exist — see the sibling "
        "demand; without the record there is no order to check")
    fm, _body = parse_frontmatter(CUTOVER_RECORD.read_text(encoding="utf-8"))
    last_old = _endpoint(fm, LAST_OLD_RUN)
    first_new = _endpoint(fm, FIRST_EPISODE)

    old_at = _as_instant(last_old.get("at"))
    new_at = _as_instant(first_new.get("at"))
    assert new_at is not None, (
        f"the record says the first branch episode is {NEVER!r} — the branch loop has shipped "
        "and produced episodes (#947, #1005), so this endpoint has an instance")

    if old_at is None:
        # The stronger discharge: the old loop was never hand-invoked in production, so the two
        # loops trivially never overlapped. Nothing is left to order — but the record must still
        # say so deliberately rather than leave the field blank.
        assert last_old.get("reason"), (
            f"the record says the old loop was {NEVER!r} run in production but gives no "
            "`reason:` — an endpoint with no instance is a claim about this deployment and "
            "needs its ground stated")
        return

    assert old_at <= new_at, (
        f"the record has the old loop's last hand-invoked run at {old_at} and the first branch "
        f"episode at {new_at} — the old loop ran AFTER the branch loop had started, which "
        "refutes O6 rather than discharging it")
    assert last_old.get("run_id"), (
        "the old loop's last run is dated but not identified — `run_id:` is what makes the "
        "claim checkable against the run dirs")
    assert first_new.get("episode_id"), (
        "the first branch episode is dated but not identified — `episode_id:` is what makes "
        "the claim checkable against the episode archive")


def test_922_the_bare_run_dir_stage_is_gone(tmp_path):
    """RED-FIRST (fails at HEAD).

    D9's second half, first stage. `loop.py <run_dir>` is the LEARN stage — the hand invocation
    that runs actor -> oracle -> judge over one finished run. It leaves with the pipeline, so
    the positional stops being a recognised argument and argparse exits 2.

    The argument is a directory whose name FAILS the run-id grammar, so at HEAD `run_one`
    refuses it (`RunUnprocessable`, mapped to the contracted exit 2) before it takes a lock or
    writes anything. That keeps the drive honest at HEAD without letting the deleted stage
    actually run against the checkout.

    AT HEAD: `cli.main` returns 2 and no `SystemExit` is raised.
    """
    bad = tmp_path / "not a run id"
    bad.mkdir()
    with pytest.raises(SystemExit) as exited:
        cli.main(["loop.py", str(bad)])
    assert exited.value.code == 2, (
        f"argparse exited {exited.value.code}, not 2 — the positional was consumed rather "
        "than rejected")


def test_922_the_learn_drain_stage_is_gone(capsys):
    """RED-FIRST (fails at HEAD).

    D9's second half, second stage. `--learn-drain` is the off-process LEARN worker that drains
    the learn-queue; the queue, its marker writer and its only out-of-`learning/` call site all
    go with it (D2), so the flag stops being a recognised argument.

    A positional rides along so that HEAD takes its OWN "--learn-drain takes no run_dir" arm and
    returns 1 without ever calling the drain — this test must not run a git-and-worktree drain
    against the checkout it lives in. After the cut the flag is unknown and argparse exits 2
    naming it, which is what the stderr assertion pins: an exit 2 alone would also be produced
    by the "mutually exclusive" arm or by a parser broken some other way.

    AT HEAD: `cli.main` returns 1 with "--learn-drain takes no run_dir", and nothing is raised.
    """
    with pytest.raises(SystemExit) as exited:
        cli.main(["loop.py", "--learn-drain", "/nonexistent/run-dir"])
    assert exited.value.code == 2
    err = capsys.readouterr().err
    assert "--learn-drain" in err, (
        f"argparse exited 2 without naming `--learn-drain`: {err!r}")
    assert re.search(r"unrecognized|invalid|not allowed", err), (
        f"argparse exited 2 but did not reject `--learn-drain` as unknown: {err!r}")


def test_922_the_surviving_drain_stages_still_parse(capsys):
    """GUARD (green now, must stay green) — the positive control for the two demands above.

    `--author-drain` and `--lead-author-drain` are KEEPERS. Both demands above assert that an
    argument is REJECTED, and both would pass on a `main()` that rejected everything — a parser
    broken outright, or one whose flags were all deleted together.

    Each surviving flag is driven with a positional, so the parser reaches the flag's own
    "takes no run_dir" arm and returns 1 with its own message — the stage itself never runs, so
    no drain touches the checkout, and the argument is still proven RECOGNISED.
    """
    for flag in ("--author-drain", "--lead-author-drain"):
        rc = cli.main(["loop.py", flag, "/nonexistent/run-dir"])
        assert rc == 1, f"{flag} was not recognised as a flag that takes no run_dir (rc={rc})"
        err = capsys.readouterr().err
        assert f"{flag} takes no run_dir" in err, (
            f"{flag} exited 1 for some other reason: {err!r}")

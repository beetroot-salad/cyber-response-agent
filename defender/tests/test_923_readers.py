"""#923 — every reader that partitions on a disposition literal, one case per reader (M6, R7).

This module discharges ONE demand of `spec-flow/specs/spec_graph_923-inconclusive.yaml`, and
that demand binds EIGHTEEN edges. The graph itself records that as a known limit: a single table
assertion over those edges passes when any subset of them agrees, which is precisely the bug the
per-reader binding exists to prevent. So the demand is written here as one case PER NAMED EDGE,
parametrized, each driving that reader and asserting what IT does with the new member — a failing
case names the reader that did not move.

The readers split three ways, and the split is what each case asserts:

* **unmoved consumers of the vocabulary** — they gain a fifth member and owe an explicit
  in-or-out verdict. "Out of scope but must not break" is not a verdict; each one below says
  what it does.
* **unmoved consumers of the committed report** — they read `report.md`'s frontmatter through
  the shared accessor and must read the new member back as a real headline rather than as an
  unreadable one, or a host-terminated run dead-letters the learning loop for a verdict the host
  itself wrote.
* **the malformed verdict, which is none of the three** — `test_a_malformed_committed_verdict_
  is_marked_not_coerced` is the read half of the §7-round-4 design change and stands outside
  the per-edge table on purpose: it is one statement about ALL these readers at once (a value
  that only reads as a member is answered exactly as a value that never was one), where the
  table asks each reader what it does with a real member.
* **the three surfaces newly pulled into scope** — above all the runtime visualizer's
  `_was_reviewed`, which today answers "was this reviewed?" against a hardcoded literal and
  would silently render a gate-forced run as REVIEWED once the verdict moves; and the two
  hand-enumerated model-facing rosters, which are asserted as a UNIVERSAL over the tree rather
  than as the two file names the design listed — this design has offered five short enumerations
  and the roster list was the fourth.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from defender._vocab import UNKNOWN_DISPOSITION
from defender.skills.invlang.validate import _DISPOSITION_GATES
from defender.tests._spec923 import (
    DEFENDER,
    GAP_MEMBER,
    MEMBER,
    PAYING_ROW,
    finished_run,
    paid,
    person_facing_refusal_defects,
)
from defender.tests._spec791 import (  # noqa: F401 — session-scoped autouse guard
    worktree_package_guard,
)

pytestmark = pytest.mark.gate

_NUMBER_WORDS = {
    "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7, "eight": 8,
}
_PRICE_COUNT_CLAIM = re.compile(r"(\w+)\s+(?:keywords|of them)\s+carry an ENTRY PRICE", re.I)
_MEMBER_ROSTER = ("`benign`", "`false-positive`", "`inconclusive`", "`malicious`")


def _prose_files() -> list[Path]:
    """Every non-test file in the shipping tree a MODEL can be shown: prose, prompts and the
    modules whose comments are lifted into one."""
    out: list[Path] = []
    for path in sorted(DEFENDER.rglob("*")):
        if not path.is_file() or path.suffix not in {".md", ".py", ".txt"}:
            continue
        parts = set(path.relative_to(DEFENDER).parts)
        # No hand-drawn carve-out for "data rather than instruction": the roster list going
        # stale is the fault this exists to catch, and a maintained exclusion list is the same
        # shape one level up. Measured: excluding the recorded-transcript and judge-alignment
        # trees changes neither universal's hit set, so the carve-out buys nothing and costs a
        # list someone has to keep right.
        if parts & {".venv", "tests", "__pycache__"}:
            continue
        out.append(path)
    return out


# --- the unmoved consumers of the vocabulary ------------------------------------------------

def _run_cycle_selects_no_direction(_tmp_path: Path) -> None:
    """Asserted as the WHOLE routing table rather than as one empty list: the router returns an
    empty list for any unrecognized string, so `== []` for one member is true on a build where
    nothing moved. The table fails if the new member routes anywhere, and it also fails if an
    existing member's routing shifted while the vocabulary grew."""
    from defender._vocab import DISPOSITION_ENUM
    from defender.learning.core.run_cycle import _directions_for

    routing = {member: sorted(_directions_for(member)) for member in sorted(DISPOSITION_ENUM)}
    assert routing == {
        "benign": ["adversarial"],
        "false-positive": [],
        GAP_MEMBER: ["adversarial", "benign"],
        "malicious": ["benign"],
        MEMBER: [],
    }, routing


def _ticket_seeds_does_not_sample_it(_tmp_path: Path) -> None:
    from datetime import UTC, datetime

    from defender.learning.tickets import ticket_seeds
    from defender.scripts.case_history import case_ticket

    now = datetime(2024, 5, 5, tzinfo=UTC)  # inside the window for an `evt:2024-05-01` ticket

    def _survived_comment() -> list[dict]:
        # The eligibility marker `sample_seeds` actually reads (`ticket_seed_eligible` ->
        # `parse_survival_from_comments`) — without it EVERY ticket in the pool is ineligible
        # and the two assertions below pass on an empty list regardless of disposition, which
        # is exactly the vacuous shape this test exists to rule out.
        return [{"author": "learning", "body": case_ticket.enrichment_to_comment("caught")["body"]}]

    def closed(_label):
        return [
            {"key": "case-a", "resolution": f"{MEMBER} — the host ended the run",
             "labels": ["evt:2024-05-01T00:00:00Z"], "comments": _survived_comment()},
            {"key": "case-b", "resolution": "benign — accounted for",
             "labels": ["evt:2024-05-01T00:00:00Z"], "comments": _survived_comment()},
        ]

    # The pool carries a hand-written host-only resolution BESIDE a legitimate, EQUALLY ELIGIBLE
    # one, because the refusal this change adds at the ticket AUTHORING surface must not turn
    # this READ path into a crash path: the sampler walks every closed ticket a person could
    # have edited, and a decoder that raises on one of them takes the whole benign-precedent
    # pool with it. Both tickets carry the same window label and the same survival marker, so
    # the ONLY thing that can separate them is the disposition decode — a pool that came back
    # empty (both excluded on eligibility, not disposition) would pass the two assertions below
    # for the wrong reason, which is why `seeds` is asserted non-empty first.
    seeds = ticket_seeds.sample_seeds(
        {"rule": {"id": "5710"}}, "case-self", "run-1", now=now,
        list_closed_fn=closed, signature_label_fn=lambda _alert: "sig:5710",
    )
    assert seeds, "the equally-eligible benign precedent was not sampled either — the pool came " \
        "back empty for an unrelated reason, and the disposition decode was never exercised"
    assert all(seed.disposition == "benign" for seed in seeds)
    assert not any(seed.case_id == "case-a" for seed in seeds), (
        "a host-terminated case was sampled as a benign precedent — the sampler's pool is "
        "evidence about the world and this run produced none"
    )


def _lessons_run_has_no_confident_ground_truth(_tmp_path: Path) -> None:
    """Asserted as the reader's answer for EVERY member including the new one, in both
    directions — not as the set of members it says yes to.

    A yes-set is the vacuous shape and this case shipped in it: this reader answers False for
    every value it does not name, so a table that only lists the members it accepts is
    identical before and after the vocabulary grows, and the case asserts nothing about the
    member it is named for. Keyed per member, the new member needs a cell, so the case is red
    until the vocabulary carries it and red again if it is ever taught to stand as ground truth
    for either hunt."""
    from defender._vocab import DISPOSITION_ENUM
    from defender.learning.author.lessons.run import _has_confident_ground_truth

    confident = {
        direction: {m: _has_confident_ground_truth(direction, m) for m in sorted(DISPOSITION_ENUM)}
        for direction in ("benign", "adversarial")
    }
    expected = {
        "benign": {GAP_MEMBER: False, MEMBER: False, "benign": False,
                   "false-positive": False, "malicious": True},
        "adversarial": {GAP_MEMBER: False, MEMBER: False, "benign": True,
                        "false-positive": False, "malicious": False},
    }
    assert confident == expected, confident


def _visualize_judge_selects_no_direction_view(_tmp_path: Path) -> None:
    from defender.scripts.visualize.visualize_judge import VIEWS, active_views

    assert active_views("run-923", MEMBER) == (), (
        "the judge page renders direction sections for a run that trained nothing"
    )
    assert active_views("run-923", "not-a-disposition") == VIEWS, (
        "the unreadable-headline fallback moved — an out-of-enum value must still show "
        "everything, and the new member must not be taking that branch"
    )


def _invlang_queries_finds_the_case(_tmp_path: Path) -> None:
    from defender.skills.invlang.corpus import Companion
    from defender.skills.invlang.parser import parse_dense_companion
    from defender.skills.invlang.queries import lead_sequence_pattern

    body, _warnings = parse_dense_companion(paid(PAYING_ROW, disposition=MEMBER))
    corpus = [Companion(case_id="case-923", source_path=Path("case-923.md"), body=body)]

    found = lead_sequence_pattern(corpus, disposition=MEMBER)
    assert found["count"] == 1, "a corpus lookup cannot name the new member at all"
    assert found["hits"][0]["disposition"] == MEMBER
    assert UNKNOWN_DISPOSITION not in found["hits"][0]["trace"], (
        "the corpus trace renders the new member as an unreadable headline"
    )


def _invlang_cli_accepts_it_as_a_filter(tmp_path: Path) -> None:
    """`corpus_root` is a required leading positional (`_build_parser`'s own shape,
    `test_invlang_parser.py::test_cli_prints_the_load_detail_to_stderr_and_quiet_suppresses_it`
    drives it the same way) — a real path is threaded through so this exercises the actual
    parser rather than a shape that omits an argument the CLI has always required."""
    from defender.skills.invlang.cli import _build_parser

    args = _build_parser().parse_args([str(tmp_path), "sequence", "--disposition", MEMBER])
    assert args.disposition == MEMBER, (
        "a read-only query filter that cannot name the new member is a reader disagreeing "
        "with the source it filters"
    )


def _ticket_lane_refuses_it_as_an_authored_resolution(_tmp_path: Path) -> None:
    """The refusal's TEXT is asserted here too, not just the exception class.

    This edge and `test_every_authoring_surface_refuses_the_host_only_verdict` are the two
    places a person meets this refusal, and a message check on one of them leaves the other
    free to raise a bare word. Both go through the same oracle."""
    from defender.scripts.case_history import case_ticket
    from defender.scripts.case_history.case_ticket import CaseTicketError

    with pytest.raises(CaseTicketError) as refusal:
        case_ticket.parse_disposition_from_resolution(f"{MEMBER} — I could not get to a verdict")
    defects = person_facing_refusal_defects(str(refusal.value), value=MEMBER)
    assert defects == [], f"{defects}; the text was {str(refusal.value)!r}"
    assert case_ticket.parse_disposition_from_resolution("malicious — confirmed") == "malicious"


# --- the unmoved consumers of the committed report -------------------------------------------

def _report_reader_reads_it_back(tmp_path: Path) -> None:
    from defender._report import read_report

    run_dir = finished_run(tmp_path, disposition=MEMBER)
    read = read_report(run_dir / "report.md")
    assert read.disposition == MEMBER
    assert read.reason is None, f"the shared accessor calls the host's own verdict unreadable: {read.reason}"


def _learning_validate_does_not_dead_letter(tmp_path: Path) -> None:
    from defender.learning.core.validate import normalize_disposition

    run_dir = finished_run(tmp_path, disposition=MEMBER)
    assert normalize_disposition(run_dir / "report.md") == MEMBER, (
        "the loop dead-letters a run for the verdict the host itself wrote"
    )


def _held_out_scores_it(tmp_path: Path) -> None:
    from defender.evals.held_out import predicted_disposition

    assert predicted_disposition(finished_run(tmp_path, disposition=MEMBER)) == MEMBER


def _trace_lesson_does_not_render_the_placeholder(tmp_path: Path) -> None:
    from defender.learning.ops.trace_lesson import _report_disposition

    run_dir = finished_run(tmp_path, disposition=MEMBER)
    assert _report_disposition(run_dir) == MEMBER, (
        "the trace table shows the unknown placeholder, where a silent `?` reads as a case "
        "that never resolved"
    )


def _ticket_lane_reads_the_committed_verdict(tmp_path: Path) -> None:
    from defender.scripts.case_history import case_ticket

    run_dir = finished_run(tmp_path, disposition=MEMBER)
    assert case_ticket.read_case_record(run_dir).disposition == MEMBER


def _visualize_primitives_reads_the_committed_verdict(tmp_path: Path) -> None:
    from defender.scripts.visualize.visualize_primitives import parse_report

    run_dir = finished_run(tmp_path, disposition=MEMBER)
    assert parse_report(run_dir).disposition == MEMBER


def _the_review_record_has_no_consumer_outside_the_runtime_view(tmp_path: Path) -> None:
    """A REAL fault through the real primitive: the numbered review record is made unreadable —
    a directory where a JSON file belongs — and every consumer of the finished run is driven
    over it. Each still answers, from `report.md` alone.

    That is what "the record's verdict field moves and nothing downstream re-keys" means as an
    observation. A test naming a module and asserting it holds no accessor would assert about a
    symbol rather than about a behaviour, and would keep passing if a consumer grew one."""
    from defender._report import read_report
    from defender.evals.held_out import predicted_disposition
    from defender.learning.core.validate import normalize_disposition
    from defender.scripts.case_history import case_ticket

    run_dir = finished_run(tmp_path, disposition=MEMBER)
    (run_dir / "review_record.1.json").mkdir()

    assert read_report(run_dir / "report.md").disposition == MEMBER
    assert normalize_disposition(run_dir / "report.md") == MEMBER
    assert predicted_disposition(run_dir) == MEMBER
    assert case_ticket.read_case_record(run_dir).disposition == MEMBER


# --- the three surfaces newly pulled into scope ----------------------------------------------

def _visualize_runtime_calls_it_unreviewed(tmp_path: Path) -> None:
    from defender.scripts.visualize import visualize_runtime

    for verdict in (MEMBER, GAP_MEMBER):
        assert visualize_runtime._was_reviewed({"reviewed_disposition": verdict}) is False, (
            f"a close committed WITHOUT a review renders as reviewed for {verdict!r} — the page "
            f"then reads as 'a review ran and the disposition held'"
        )
    assert visualize_runtime._was_reviewed({"reviewed_disposition": "malicious"}) is True, (
        "every attempt now renders as unreviewed"
    )


def _report_frontmatter_gate_admits_it(tmp_path: Path) -> None:
    from defender._artifact_schema import validate_artifact

    body = f"---\ndisposition: {MEMBER}\noutcome: forced-inconclusive\n---\n\nbody\n"
    assert validate_artifact("report.md", body, None) is None


def _no_roster_enumerates_a_stale_vocabulary(_tmp_path: Path) -> None:
    """The universal that replaces the design's two named files. Any shipped text enumerating
    the whole vocabulary must enumerate all of it — found by asking the tree, not by listing the
    rosters someone remembered."""
    stale = []
    for path in _prose_files():
        text = path.read_text(encoding="utf-8")
        if all(member in text for member in _MEMBER_ROSTER) and f"`{MEMBER}`" not in text:
            stale.append(str(path.relative_to(DEFENDER)))
    assert stale == [], (
        f"these enumerate the vocabulary and stop at four members: {stale} — a model is being "
        f"taught a roster the host no longer holds"
    )


def _no_roster_states_a_stale_price_count(_tmp_path: Path) -> None:
    """The other half: prose that COUNTS the priced keywords, checked against the owner's table.
    A count is the fault shape this design has been caught on five times, and the two sentences
    this finds are model-facing."""
    wrong = []
    for path in _prose_files():
        for match in _PRICE_COUNT_CLAIM.finditer(path.read_text(encoding="utf-8")):
            claimed = _NUMBER_WORDS.get(match.group(1).lower())
            if claimed != len(_DISPOSITION_GATES):
                wrong.append(f"{path.relative_to(DEFENDER)}: {match.group(0)!r}")
    assert wrong == [], (
        f"prose the model reads states a priced-keyword count the owner's table contradicts "
        f"(the table prices {len(_DISPOSITION_GATES)}): {wrong}"
    )


_READERS = {
    # the vocabulary's unmoved consumers
    "run_cycle": _run_cycle_selects_no_direction,
    "ticket_seeds": _ticket_seeds_does_not_sample_it,
    "lessons_run": _lessons_run_has_no_confident_ground_truth,
    "visualize_judge": _visualize_judge_selects_no_direction_view,
    "invlang_queries": _invlang_queries_finds_the_case,
    "invlang_cli": _invlang_cli_accepts_it_as_a_filter,
    "ticket_lane->disposition": _ticket_lane_refuses_it_as_an_authored_resolution,
    # the committed report's unmoved readers
    "report_reader": _report_reader_reads_it_back,
    "learning_validate": _learning_validate_does_not_dead_letter,
    "held_out": _held_out_scores_it,
    "trace_lesson": _trace_lesson_does_not_render_the_placeholder,
    "ticket_lane->report_md": _ticket_lane_reads_the_committed_verdict,
    "visualize_primitives": _visualize_primitives_reads_the_committed_verdict,
    "run_paths->review_record": _the_review_record_has_no_consumer_outside_the_runtime_view,
    # newly in scope
    "visualize_runtime": _visualize_runtime_calls_it_unreviewed,
    "decide_report_write": _report_frontmatter_gate_admits_it,
    "run_investigation->prompt_rosters": _no_roster_enumerates_a_stale_vocabulary,
    "decide_write->prompt_rosters": _no_roster_states_a_stale_price_count,
}


@pytest.mark.parametrize("edge", sorted(_READERS), ids=lambda e: e)
def test_each_reader_that_partitions_on_a_disposition_literal_classifies_the_new_member(
    edge, tmp_path,
):
    """Every reader that partitions on a disposition literal gives the new member an explicit
    in-or-out verdict, asserted AT THAT READER, one case per named site.

    A demand at the vocabulary's own altitude reads as green when two of three readers moved,
    which is the bug this is bound per-edge to prevent — so this is parametrized over the named
    edges and each case drives its own reader rather than asserting a structural property of a
    registry entry.

    The named unmoved readers each say what they do with `unresolved`; the surfaces newly pulled
    into scope say what they were CHANGED to do. `visualize_runtime._was_reviewed` is the sharp
    one: it answers "was this reviewed?" by comparing the numbered record against a hardcoded
    literal, so once the host's verdict moves it renders a gate-forced run as REVIEWED — and it
    agrees with the close's own bypass branch by a DUPLICATED LITERAL rather than by an import,
    which is why both verdicts are asserted there.

    The two prompt-roster edges are asserted as universals over the shipping tree rather than
    against the two files the design named: the design's roster list was the fourth short
    enumeration it offered, so the census asks the tree which prose enumerates the vocabulary or
    counts the priced keywords, and holds every answer to the owner's own values."""
    _READERS[edge](tmp_path)


# --- the design change: a malformed verdict is marked, never coerced -------------------------

def _reader_answers(run_dir: Path) -> dict[str, tuple[str, object]]:
    """Every consumer of a finished run's committed verdict, DRIVEN, with a refusal captured
    rather than raised: `("ok", value)` or `("refused", <error type>)`.

    Captured rather than asserted per reader so the comparison below is one statement about
    all of them at once — "a malformed verdict reads exactly like a value that was never a
    member, everywhere" is the outcome, and it survives whichever way the coercion is removed.
    """
    from defender._report import read_report
    from defender.evals.held_out import predicted_disposition
    from defender.learning.core.validate import normalize_disposition
    from defender.learning.ops.trace_lesson import _report_disposition
    from defender.scripts.case_history import case_ticket

    report = run_dir / "report.md"

    def call(fn):
        try:
            return ("ok", fn())
        except Exception as e:  # noqa: BLE001 — the refusal's TYPE is the observation
            return ("refused", type(e).__name__)

    return {
        "report_reader": call(lambda: read_report(report).disposition),
        "learning_validate": call(lambda: normalize_disposition(report)),
        "held_out": call(lambda: predicted_disposition(run_dir)),
        "ticket_lane": call(lambda: case_ticket.read_case_record(run_dir).disposition),
        "trace_lesson": call(lambda: _report_disposition(run_dir)),
    }


def test_a_malformed_committed_verdict_is_marked_not_coerced(tmp_path):
    """A committed verdict that is not a member of the vocabulary is never coerced into the
    member it resembles. Every reader of the finished run gives it the SAME answer it gives a
    value that was never a member at all, and none of them hands a member downstream.

    THIS IS A DESIGN CHANGE TAKEN BY A HUMAN DURING THE SPEC PHASE, and it changes shipped
    read-path behaviour. Today `_vocab.normalized_disposition` strips zero-width characters and
    answers with what a human would see, so `malicious` with a zero-width space in it reads
    back as `malicious` at four boundaries — a close no reader can tell from a clean one. The
    two WRITE gates already refuse such a value and each carries a comment saying they
    deliberately do not use the forgiving reader; the read side now agrees with them. The run is
    marked MALFORMED and left for human judgement: no coercion, and no placeholder standing in
    for a verdict nobody wrote.

    Both spellings are driven and they fail today for opposite reasons, which is the point of
    driving both: the zero-width one is COERCED today (this test is red on it), and the
    homoglyph is refused today and must STAY refused — the confusable fold J24's resolution
    pointed at would have made it equal to the member at four validating boundaries at once.

    WHAT THIS DELIBERATELY DOES NOT PIN, because the human left both to code review: WHERE the
    malformed mark is recorded — the ask is to reuse the existing path for runs that are not
    consumed rather than invent a second one — and that one malformed run in a batch is
    skipped-and-flagged rather than stopping the batch. What is pinned is the outcome a person
    depends on: nothing reads it as a verdict, and the refusal quotes the raw bytes so the
    invisible character is visible to whoever judges it.

    The paired positive control is the last block: the same run dir with the CLEAN spelling is
    read back as the member by every one of these readers. Without it the parity above is
    satisfied by a build where nothing can read a report at all."""
    from defender._report import read_report
    from defender.scripts.case_history import case_ticket
    from defender.tests._spec923 import MALFORMED_MEMBER_SPELLINGS, NOT_A_MEMBER

    unknown = _reader_answers(finished_run(tmp_path / "unknown", disposition=NOT_A_MEMBER))

    for i, spelling in enumerate(MALFORMED_MEMBER_SPELLINGS):
        run_dir = finished_run(tmp_path / f"malformed-{i}", disposition=spelling)
        answers = _reader_answers(run_dir)
        assert answers == unknown, (
            f"{spelling!r} is read differently from a value that was never a member: "
            f"{ {k: v for k, v in answers.items() if unknown[k] != v} } — a verdict that only "
            f"becomes a member after something strips or folds it is exactly the close no "
            f"reader can tell from a clean one"
        )
        assert not any(v == ("ok", "malicious") for v in answers.values()), (
            f"a reader coerced {spelling!r} into the member it resembles: {answers}"
        )
        reason = read_report(run_dir / "report.md").reason or ""
        assert repr(spelling) in reason or spelling in reason, (
            f"the run is refused without quoting what it actually held ({reason!r}) — a person "
            f"asked to judge a malformed verdict cannot see an invisible character described "
            f"in prose"
        )
        # The analyst-editable lane decodes the same value and must not hand it on either.
        assert case_ticket.parse_disposition_from_resolution(
            f"{spelling} — closed by hand",
        ) != "malicious", "the ticket lane decoded a malformed verdict into a real member"

    # THE PAIRED POSITIVE CONTROL: the clean spelling, same fixture, same readers.
    clean = _reader_answers(finished_run(tmp_path / "clean", disposition="malicious"))
    assert clean != unknown, "the readers answer the same for a real verdict and a garbage one"
    for name, (status, value) in clean.items():
        assert (status, value) == ("ok", "malicious"), (
            f"{name} does not read an ordinary committed verdict back: {(status, value)}"
        )

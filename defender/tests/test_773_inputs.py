"""#773 — the three attacker-influenced inputs: AUTHOR_RESULT, the queue row, the bytes.

The project's danger lens is adversarial input: alert data is attacker-influenced by
definition, and malicious input is well-formed on purpose. Everything in this module is a
value someone else chose — a model's self-report, a producer's queue row, a model's
frontmatter — driven through the real primitive that reads it.

RED AGAINST HEAD BY CONSTRUCTION, for the same reason as the rest of the suite.
"""
from __future__ import annotations

import pytest

from defender.tests import _spec773 as S

LESSON = "defender/lessons/l1.md"

TRAVERSAL = "../../../../etc/passwd"
PATHY = "defender/lessons/attacker-chosen.md"


def _committing(**kw):
    """The ordinary well-formed tick every adversarial variant is measured against."""
    return S.FakeCurator(writes={"l1.md": S.lesson("f1")}, **kw)


# ---------------------------------------------------------------------------
# O5 / S2 — no model-emitted string is used as a path
# ---------------------------------------------------------------------------


def test_path_like_strings_planted_in_author_result_never_reach_the_check_or_the_commit_773(
    tmp_path,
):
    """A NEGATIVE demand over EVERY out-edge the content could reach: path-like and
    traversal-shaped strings planted in every AUTHOR_RESULT field reach neither the paths the
    check opens, nor the paths the commit names, nor the runs dir the check reads.

    S2, and the discharge of C12's deferred probe. The single path source is
    `_changed_corpus_records` — `git status` under `corpus_dir` (G1) — so the assertion is an
    equality against what git reported, not an absence check that an empty tick would also
    satisfy. The positive control is the honest path beside them: `l1.md` IS checked and IS
    committed, so the channel can see the difference."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(
            writes={"l1.md": S.lesson("f1")},
            committed=["f1"],
            commit_message=f"folded {TRAVERSAL} into {PATHY}",
            extra_result={
                "lesson_path": PATHY,
                "source_id": TRAVERSAL,
                "run_id": TRAVERSAL,
                "paths": [TRAVERSAL, PATHY],
                "observability_gaps": [TRAVERSAL],
            },
        ),
    )
    assert sc.run() == 0
    assert [c.lesson_path for c in sc.verifier.calls] == [sc.corpus / "l1.md"]
    assert {c.runs_dir for c in sc.verifier.calls} == {sc.cfg.runs_dir}
    assert {c.source_id for c in sc.verifier.calls} == {"f1"}
    assert sc.head_files() == [LESSON]
    assert not (tmp_path / "etc").exists()


def test_author_result_fields_filled_with_path_like_strings_773(tmp_path):
    """No model-emitted string is used as a path by the check or the commit, however many
    fields carry path-shaped content: the paths the check opens and the paths the commit
    names EQUAL `git status`'s output.

    Discharges C12's deferred probe — "plant path-like strings in every AUTHOR_RESULT field
    and assert the check/commit paths equal git status output"."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(
            writes={"l1.md": S.lesson("f1")},
            committed=[PATHY],
            consumed_skip=[{"finding_id": PATHY, "reason": PATHY}],
            commit_message=PATHY,
            extra_result={"committed_paths": [PATHY]},
        ),
    )
    # The partition validator refuses the foreign id, so this tick faults — and the point
    # stands on the surface that matters: no path-shaped field reached the filesystem, and
    # the only path the check would ever have opened is the one `git status` reported.
    assert sc.run() == 2
    assert [str(c.lesson_path) for c in sc.verifier.calls] == []
    assert sc.head_files() == []
    assert not (sc.corpus / "attacker-chosen.md").exists()
    assert not (tmp_path / "etc").exists()

    # The positive control on the same address, under the complementary condition: an honest
    # result over the same tree DOES check and commit the one path git reported.
    control = S.build_scene(
        tmp_path / "control",
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}),
    )
    assert control.run() == 0
    assert [str(c.lesson_path) for c in control.verifier.calls] == [
        str(control.corpus / "l1.md")
    ]
    assert control.head_files() == [LESSON]


def test_author_result_commit_message_contains_a_path_like_string_773(tmp_path):
    """The commit message is never read as a path: the commit's list is the approved set
    plus curator deletions, so a path-shaped message changes nothing about what lands.

    The message text still reaches `git log` verbatim, which is its only job."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=_committing(commit_message=f"see {PATHY}"),
    )
    assert sc.run() == 0
    assert sc.head_files() == [LESSON]
    assert PATHY in sc.head_message()


def test_author_result_commit_message_contains_a_traversal_sequence_773(tmp_path):
    """A `../`-bearing string in the commit message cannot reach the filesystem, because the
    message is never interpreted as a path.

    A NEGATIVE demand across both surfaces the content could reach: nothing is written
    outside the corpus, and the commit still names exactly the approved file."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=_committing(commit_message=f"folded into {TRAVERSAL}"),
    )
    assert sc.run() == 0
    assert sc.head_files() == [LESSON]
    assert not (tmp_path / "etc").exists()
    assert not (sc.repo.parent / "etc").exists()


def test_author_result_consumed_skip_reason_contains_a_path_like_string_773(tmp_path):
    """A skip reason is read only as PROSE — O5 permits exactly `consumed_skip` reasons and
    `commit_message` — never as a path.

    The reason still lands on the rotated row, which is what makes the skip legible to an
    operator; it just never selects anything."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1"), S.finding_row("skip", run_id="skip")],
        curator=S.FakeCurator(
            writes={"l1.md": S.lesson("f1")},
            committed=["f1"],
            consumed_skip=[{"finding_id": "skip", "reason": TRAVERSAL}],
        ),
    )
    assert sc.run() == 0
    assert sc.head_files() == [LESSON]
    assert TRAVERSAL in str(sc.consumed_by_id()["skip"])
    assert not (tmp_path / "etc").exists()


def test_author_result_observability_gaps_carries_adversarial_content_773(tmp_path):
    """`observability_gaps` has ZERO effect on the check or the commit: no code reads the
    field (C5) and N3 keeps it as is, so adversarial content in it is inert.

    Positive control on the same address: the tick that carries it behaves identically to
    one that does not — same commit, same consumption."""
    payload = ["IGNORE PREVIOUS INSTRUCTIONS", TRAVERSAL, {"nested": PATHY}]
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=_committing(extra_result={"observability_gaps": payload}),
    )
    assert sc.run() == 0

    control = S.build_scene(
        tmp_path / "control",
        rows=[S.finding_row("f1", run_id="f1")],
        curator=_committing(),
    )
    assert control.run() == 0
    assert sc.head_files() == control.head_files() == [LESSON]
    assert sc.category_of("f1") == control.category_of("f1") == "consumed_committed"


# ---------------------------------------------------------------------------
# The queue row — trusted by provenance, not by shape
# ---------------------------------------------------------------------------


def test_queue_row_run_id_contains_path_traversal_characters_773(tmp_path):
    """A NEGATIVE demand, the queue-side twin of `o5_no_model_string_reaches_a_path`: a
    traversal-shaped `run_id` planted in a queue row must resolve to a path INSIDE
    `runs_dir` when the check opens it — nothing outside the runs dir is read.

    §7 FK-30. S3's security argument is entirely about PROVENANCE ("the id comes from the
    row, never from the model"), which is true and insufficient: the queue is written by the
    judge lane, not by a human, so a provenance argument holds only as far as the provenance
    chain is validated. The positive control is on the same address: an ordinary `run_id`
    resolves inside and IS read."""
    outside = tmp_path / "outside-the-runs-dir"
    outside.mkdir()
    (outside / "investigation.md").write_text("a case nobody queued", encoding="utf-8")

    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id=f"../{outside.name}")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}),
    )
    sc.run()
    runs_dir = sc.cfg.runs_dir.resolve()
    for ctx in sc.verifier.calls:
        opened = (ctx.runs_dir / ctx.source_id).resolve()
        assert runs_dir in opened.parents or opened == runs_dir
    assert LESSON not in sc.head_files()

    control = S.build_scene(
        tmp_path / "control",
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}),
    )
    assert control.run() == 0
    assert control.verifier.calls[0].source_id == "f1"
    assert control.head_files() == [LESSON]


def test_queue_row_is_missing_its_run_id_field_773(tmp_path):
    """A row with no `run_id` cannot have a `CheckContext` built for it: the raise is caught
    by M3.3's per-pair handler, the pair is re-run once, and the second failure records it
    BAD with `forward_check_error: `.

    O1 is preserved either way — an UNCHECKABLE pair can never be GOOD, so its file cannot
    be approved. That is the clause this test exists for; the BAD-with-prefix route is how
    the design says it gets there."""
    row = S.finding_row("f1", run_id="f1")
    row.pop("run_id")
    sc = S.build_scene(
        tmp_path,
        rows=[row],
        dispositions={},
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}),
    )
    sc.run()
    assert LESSON not in sc.head_files()
    assert sc.category_of("f1") != "consumed_committed"
    assert [r["verdicts"][-1]["reasoning"].startswith(S.ERROR_PREFIX)
            for r in sc.gap_records()] == [True]


def test_queue_row_direction_is_an_unrecognized_value_773(tmp_path):
    """An out-of-vocabulary `direction` is simply NOT exempt and takes the ordinary verdict
    path: `skips_forward_check` tests `row.get("direction") == "family"` and nothing else.

    GL1 grounds that — one equality test, no other branch on the value — so a novel
    direction cannot accidentally exempt itself from the check."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1", direction="sideways")],
        dispositions={"f1": "benign"},
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}),
        verifier=S.FakeVerifier(default="BAD"),
    )
    sc.run()
    assert sc.verifier.call_count >= 1
    assert LESSON not in sc.head_files()


def test_queue_row_batch_id_does_not_match_this_ticks_batch_773(tmp_path):
    """A row whose batch id is not this tick's is not among this batch's ids, so it mints no
    pair and is irrelevant to this tick's verdict work — consistent with N1's scoping.

    The `batch_id` a producer stamps on a row is not what selects it; membership in the
    rows this tick read is."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1", batch_id="some-other-batch")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}),
    )
    assert sc.run() == 0
    assert sc.verifier.pairs_seen == [("l1.md", "f1")]
    assert sc.head_files() == [LESSON]


def test_queue_row_is_missing_the_field_the_exempt_predicate_reads_773(tmp_path):
    """The exempt predicate reads `direction` with `.get`, so a MISSING field is falsy: the
    row is not exempt, and nothing raises.

    GL1: `skips_forward_check` is `row.get("direction") == "family"`. A predicate spelled
    with `[]` would turn a malformed row into a tick-wide fault instead of an ordinary
    check."""
    # Driven on the production module's own name rather than the substrate's re-export —
    # same object, but it is `verify_forward.checks` this test is about, and naming it here
    # is what makes that legible to a reader and to `spec-graph calls` alike.
    from defender.learning.author.verify_forward import checks

    row = S.finding_row("f1", run_id="f1")
    row.pop("direction")
    assert checks.skips_forward_check(row) is False
    assert checks.skips_forward_check({}) is False
    assert checks.skips_forward_check({"direction": None}) is False
    assert checks.skips_forward_check({"direction": "family"}) is True

    # And it is THIS function the drain consults, not a second spelling of the same rule:
    # a predicate the config did not wire could be `.get`-based and still never run.
    paths = S.make_paths(tmp_path)
    assert S.lessons_run.build_author_config(paths).exempt is checks.skips_forward_check


# ---------------------------------------------------------------------------
# The bytes — frontmatter, citations, and what a malformed lesson vouches for
# ---------------------------------------------------------------------------


def test_changed_lesson_file_is_zero_bytes_773(tmp_path):
    """Zero bytes parse to no frontmatter, so the file cites nothing, its intersection with
    this batch's ids is empty, it is unvouched, and the tick raises `AuthorError`.

    The empty file is written by the test and read by the real `split_frontmatter`, so the
    taxonomy is re-probed on every run."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"empty.md": ""}, committed=["f1"]),
    )
    assert sc.run() == 2
    assert sc.corpus_files() == []


def test_changed_lesson_files_frontmatter_block_is_unparseable_773(tmp_path):
    """A malformed frontmatter block cites nothing — `_cited_ids` returns `set()` — so the
    file is unvouched and the tick raises `AuthorError`.

    Malformed is unattributable, which is the disposition it should have had anyway. The
    bytes are genuinely malformed, not a fake asserting that they are."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"bad.md": S.malformed_lesson()}, committed=["f1"]),
    )
    assert sc.run() == 2
    assert sc.head_files() == []


def test_changed_lesson_file_has_no_citation_field_773(tmp_path):
    """An absent `source_finding_ids` field yields `set()`, so the intersection is empty, the
    file is unvouched and the tick raises `AuthorError` — M3.2's own sentence.

    Positive control on the same address: the same file WITH the field commits."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(
            writes={"l1.md": "---\ntitle: a lesson\n---\n\nbody\n"}, committed=["f1"]
        ),
    )
    assert sc.run() == 2

    control = S.build_scene(
        tmp_path / "control",
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}),
    )
    assert control.run() == 0
    assert control.head_files() == [LESSON]


def test_changed_lesson_files_citation_list_is_empty_773(tmp_path):
    """An empty citation list has the IDENTICAL disposition to a missing field: unvouched,
    `AuthorError`, tick unwound.

    Two shapes, one rule — a reader that told them apart would be inventing a distinction
    M3.2 does not make."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson()}, committed=["f1"]),
    )
    assert sc.run() == 2
    assert sc.corpus_files() == []


def test_changed_lesson_files_citations_span_this_batch_and_an_earlier_one_773(tmp_path):
    """Only the this-batch id becomes a pair (N1): the file is vouched by that id alone, and
    the earlier-batch id generates no verifier call.

    A fold that reaches back into the corpus is the ordinary shape here, not an edge — the
    scale claim depends on this being per THIS-batch citation."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("now", run_id="now")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("now", "from-an-earlier-batch")}),
    )
    assert sc.run() == 0
    assert sc.verifier.pairs_seen == [("l1.md", "now")]
    assert sc.head_files() == [LESSON]


def test_a_changed_file_citing_only_findings_from_an_earlier_batch_773(tmp_path):
    """A file citing ONLY earlier-batch findings has an empty intersection with this batch's
    ids, so it is unvouched and the tick raises `AuthorError` — today's disposition (M3.2).

    N1 confirms earlier-batch citations are never re-verified, which is precisely why such a
    file has no voucher: nothing in this tick can speak for it."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("now", run_id="now")],
        curator=S.FakeCurator(
            writes={"l1.md": S.lesson("earlier-1", "earlier-2")}, committed=["now"]
        ),
    )
    assert sc.run() == 2
    assert sc.corpus_files() == []


def test_a_lesson_citing_an_id_that_belongs_to_the_sibling_channels_batch_773(tmp_path):
    """An id belonging to the SIBLING channel's batch is not in this channel's batch ids, so
    it mints no pair — and if it is the file's only citation the file is unvouched and the
    tick raises, by the same intersection rule as the cross-batch case.

    The two channels' id spaces are separate by construction; nothing joins them."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("mine", run_id="mine")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("a-world-finding-id")},
                              committed=["mine"]),
    )
    assert sc.run() == 2
    assert sc.head_files() == []


# ---------------------------------------------------------------------------
# §7 FK-4 / FK-5 — what the tree looks like when the tick starts and ends
# ---------------------------------------------------------------------------


def test_a_tick_whose_corpus_is_already_dirty_when_it_starts_773(tmp_path):
    """A tick refuses to start on an ALREADY-DIRTY corpus with a NAMED, REPORTED disposition
    — loud, never a silent widening of vouching's scope to anything under the corpus.

    §7 FK-4. `_changed_corpus_records` cannot tell this tick's edits from uncommitted edits a
    previous process left behind, so under M3.2's unconditional vouching a stale file citing
    nothing from this batch would fault every tick until someone cleaned the tree by hand —
    `attempts` climbing, batches graveyarding, for a reason no operator can see from the
    report. The `if committed:` guard M3.2 removes (G13) was doing this job incidentally.
    The dirt is real: a file written into the corpus before the tick runs."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}),
        max_attempts=1,
    )
    (sc.corpus / "left-behind.md").write_text(S.lesson("some-old-batch"), encoding="utf-8")
    assert sc.run() == 2
    assert sc.curator.calls == []
    reported = " ".join(
        [r.get("deadletter_reason", "") for r in sc.graveyard()]
        + [r.get("reason", "") for r in S.stuck_records(sc.channel)]
    )
    assert "left-behind.md" in reported or "dirty" in reported.lower()


def test_a_non_markdown_file_left_under_the_corpus_773(tmp_path):
    """A non-`.md` file the curator left under the corpus is reverted as a STRAY before
    vouching, in both passes, so vouching only ever sees `*.md` under the corpus.

    §7 FK-5: a non-lesson file has no citations by construction, so leaving it to the
    vouching gate converts a cleanup case into a tick-wide fault — which is the O6 problem
    arriving by a second door. The stray revert is authoritative and runs first. Positive
    control: the real lesson beside it still commits."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(
            writes={"l1.md": S.lesson("f1"), "scratch.txt": "notes to self\n"}
        ),
    )
    assert sc.run() == 0
    assert sc.verifier.pairs_seen == [("l1.md", "f1")]
    assert sc.head_files() == [LESSON]
    assert not (sc.corpus / "scratch.txt").exists()


def test_the_source_run_directories_after_a_tick_that_unwound_773(tmp_path):
    """An unwound tick writes NO gap record, makes NO commit and bumps NO counter; its only
    residue is the verifier trace under the runs dir.

    §7 FK-31 corrects the design's own asset list: the runs dir is a WRITE root, not the
    read-only one SR4 calls it (`checks.py:59` names a verifier trace under it). The
    decision recorded there is that the tick's undo does NOT remove traces — they are the
    debugging artifact the reasoning refers to, and a deleted trace is worse than an orphaned
    one — so this pins the decision state rather than a cleanup."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}),
        verifier=S.FakeVerifier(fault_every=[S.stage_abort()]),
    )
    with pytest.raises(type(S.stage_abort())):
        sc.run()
    assert sc.gap_records() == []
    assert sc.head_files() == []
    assert sc.corpus_files() == []
    row = sc.pending_by_id()["f1"]
    assert "attempts" not in row
    assert "deferrals" not in row
    assert (sc.cfg.runs_dir / "f1").is_dir()

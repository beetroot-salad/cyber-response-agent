"""#1047 — the security dive's two negative universals, and the positive controls that make
them mean something.

ASSET: the grade and the ticket decision. ADVERSARY: the box.

    *No file under a box's rw bind is an input to "was this run cut short".*
    *The archived exit record is written by the archive, never copied.*

The box is ROOT on the run dir's mount (flagged fact F4), so every file in it — `report.md`,
`session_store_pointer.json`, `ticket_write.json`, a file planted at the record's own name — is
content an adversary chooses. The FIRST draft of this design put the exit class in `report.md`'s
frontmatter and would have handed the adversary a new capability: `validate_report` admits
unknown keys (claim h3, EXECUTED), the judge reads the archived copy of that box-written file
(claim h4), and a world could then have excluded itself from grading by writing one line. Every
negative below is that capability, checked to be absent.

TWO DISCIPLINES THIS FILE HOLDS TO, because a bare negative passes vacuously:

1. **Every negative compares against a CONTROL ROW, not against an absence.**
   `assert "request-limit" not in row` is also green for an empty row, for a pass that crashed,
   and for a reader that was never called. Each test here asserts the forged run produced the
   SAME observable as the unforged one, and names a positive control that shows the channel can
   see a difference at all.
2. **Every surface the content could reach is bound**, not just the obvious one. The forgeries
   are planted at every box-writable name (`_spec1047.FORGEABLE_NAMES`) **in the run dir** —
   the box's one rw bind (flagged fact F4, claims h23/n2) — and the REAL `archive_episode`
   runs over that tree, so the plant is where the archive READS. The observation is taken at
   the grade, at the family's verdict word, and at the ticket lane's outbound calls.

   NOT in the archived world dir. `worlds/<label>/run_end.json` is host-owned OUTPUT and is
   precisely the input `cut_short_row_shape` requires to move the grade; a negative that
   planted there and asserted the grade unmoved would assert that demand's exact negation, and
   no implementation could satisfy both. What a planted entry in the archive tree meets is a
   REFUSAL, not silence, and that belongs to the destination-screen demands
   (`s39`/`s72`/`archive_overwrites_the_record_through_the_guarded_seam`).

Fork F-N (auto, §7 round 2) added the surface this suite would otherwise have missed: forgery
of WHOSE WORLD a record is about, as opposed to forgery of the value.

RED against `59bdea44`: nothing here can pass, because nothing reads a run-end record at all.
"""
from __future__ import annotations

import json

from defender.tests import _spec1047 as S


def _rows_and_word(episode_dir):
    """One pass over one episode: every row, plus the family's word. The pair, because a
    forgery that moved only the word (or only one row) must not slip through an assertion that
    looked at the other."""
    grade = S.mod("learning.judge.family").grade_family(episode_dir)
    return S.rows(grade), S.word_of(grade)


# ---------------------------------------------------------------------------------------
# the universal, as one test over every surface
# ---------------------------------------------------------------------------------------


def test_no_file_a_box_can_write_is_an_input_to_was_this_run_cut_short(tmp_path):
    """The security dive's first negative universal, as one test over every surface the content
    could reach: with every box-writable file in the run dir replaced by a forgery — report.md
    frontmatter, a planted run_end.json, the case pointer — the grade and the ticket decision
    are byte-identical to the control's.

    Both lanes in one test because the universal is about both: the judge's row and the family
    word on one side, the ticket lane's outbound calls on the other. Positive controls:
    `cut_short_world_is_ungradable` and `ticket_request_limit_closes_unresolved` — the same two
    channels DO move when the host's own record and the in-process parameter say so, which is
    what makes "unmoved" here a finding rather than a tautology.

    THE PLANT GOES IN THE RUN DIR AND THE REAL ARCHIVE RUNS OVER IT. The demand's own scope is
    `run_dir.access[box-rw-bind]` — the box's one rw bind (flagged fact F4, claims h23/n2,
    pinned by `s83`) — so the forgery belongs in the tree the archive READS, never in the
    archived world dir the archive WRITES. `worlds/<label>/run_end.json` is host-owned output
    and is exactly the input `cut_short_row_shape` requires to move the grade; a negative
    planted there would assert that demand's own negation. What a planted entry in the ARCHIVE
    TREE meets is a refusal, not silence, and that is the destination screen's business
    (`s39`/`s72`/`archive_overwrites_the_record_through_the_guarded_seam`)."""
    archive = S.mod("learning.branch.archive")

    control_base, _src = S.runs_base(tmp_path / "control-base")
    control_ep = S.cut_short_episode(tmp_path / "control")
    archive.archive_episode(
        control_ep, {label: S.sibling_run_dir(control_base, label) for label in ("b", "c")})
    control_rows, control_word = _rows_and_word(control_ep)

    forged_base, _src = S.runs_base(tmp_path / "forged-base")
    forged_ep = S.cut_short_episode(tmp_path / "forged")
    forged_dirs = {label: S.sibling_run_dir(forged_base, label) for label in ("b", "c")}
    for run_dir in forged_dirs.values():
        S.salt_run_dir(run_dir, value="request-limit")
    archive.archive_episode(forged_ep, forged_dirs)
    forged_rows, forged_word = _rows_and_word(forged_ep)
    assert forged_rows == control_rows, (
        "a forgery planted in a box-writable file moved the grade")
    assert forged_word == control_word, "a forgery moved the family's verdict word"
    for label in ("b", "c"):
        assert not (forged_ep / "worlds" / label / S.run_end_name()).exists(), (
            f"{label}: a box-written file became the archived run-end record; the record is "
            "not in the copy list and no run dir entry is an input to it")

    honest = S.cut_short_episode(tmp_path / "honest", cut={"b": "request-limit"})
    assert S.graded(honest)["b"].get("cut_short") == "request-limit", (
        "the control failed: a HOST-written record no longer moves the grade either, so the "
        "assertions above are not about the forgery")

    control_ticket = S.close_ticket(
        S.closed_run_dir(tmp_path / "ticket-clean", disposition="benign"), truncated_by=None)
    salted = S.closed_run_dir(tmp_path / "ticket-salted", disposition="benign")
    S.salt_run_dir(salted, value="aborted")
    (salted / "report.md").write_text(S.report_text("benign"), encoding="utf-8")
    forged_ticket = S.close_ticket(salted, truncated_by=None)
    assert [(c.path.split("/")[-1], c.body) for c in forged_ticket.calls] == \
           [(c.path.split("/")[-1], c.body) for c in control_ticket.calls], (
        "a forgery under the run dir moved what the ticket lane did")


def test_every_box_writable_artifact_carrying_a_truncated_by_looking_value_leaves_the_grade_unmoved(
        tmp_path):
    """Every file under the box's bind carrying a truncated_by-looking value leaves the grade
    unmoved — the stated scope of `no_box_writable_input_to_cut_short`.

    Each name is planted ON ITS OWN, in the RUN DIR, one episode per name, and the REAL
    `archive_episode` runs over it — so the plant is in the tree the archive reads rather than
    in the archived world dir it writes. `worlds/<label>/run_end.json` is the host's own output
    and the very input `cut_short_row_shape` requires to move the grade; planting there and
    asserting the grade is unmoved would assert that demand's negation. One episode per name so
    a universal that held only because two forgeries cancelled out is not reported as a pass.
    Positive control: `cut_short_world_is_ungradable`, driven in-test below."""
    archive = S.mod("learning.branch.archive")
    control_base, _src = S.runs_base(tmp_path / "control-base")
    control_ep = S.cut_short_episode(tmp_path / "control")
    archive.archive_episode(control_ep, {"b": S.sibling_run_dir(control_base, "b")})
    control_rows, control_word = _rows_and_word(control_ep)
    for i, name in enumerate(S.FORGEABLE_NAMES):
        base, _src = S.runs_base(tmp_path / f"base-{i}")
        ep = S.cut_short_episode(tmp_path / f"forged-{i}-{name.replace('/', '_')}")
        run_dir = S.sibling_run_dir(base, "b")
        (run_dir / name).write_text(
            json.dumps(S.record_doc("request-limit")), encoding="utf-8")
        archive.archive_episode(ep, {"b": run_dir})
        assert not (ep / "worlds" / "b" / S.run_end_name()).exists(), (
            f"{name}: a box-written file became the archived run-end record")
        seen_rows, seen_word = _rows_and_word(ep)
        assert seen_rows == control_rows, f"{name}: a planted value moved the grade"
        assert seen_word == control_word, f"{name}: a planted value moved the verdict word"

    honest = S.cut_short_episode(tmp_path / "honest", cut={"b": "request-limit"})
    assert S.graded(honest)["b"].get("cut_short") == "request-limit", (
        "the control failed: a HOST-written record no longer moves the grade, so every "
        "`unmoved` above is a tautology rather than a finding")


def test_a_forged_run_end_record_in_the_run_dir_does_not_reach_the_grade(tmp_path):
    """A run_end.json planted in world b's run dir before the archive never reaches the judge:
    the archived record is the host's own, and b grades exactly as the control did.

    Driven through the REAL archive over a REAL run dir, so the plant is in the tree the archive
    actually reads, not in the archive it writes. Positive control:
    `cut_short_world_is_ungradable` — the same grading pass over the same episode with a HOST
    record present does file the third row shape."""
    base, _src = S.runs_base(tmp_path)
    archive = S.mod("learning.branch.archive")

    control_ep = S.cut_short_episode(tmp_path / "control")
    control_rows, control_word = _rows_and_word(control_ep)

    ep = S.cut_short_episode(tmp_path / "forged")
    run_dir = S.sibling_run_dir(base, "b")
    (run_dir / S.run_end_name()).write_text(
        json.dumps(S.record_doc("request-limit")), encoding="utf-8")
    archive.archive_episode(ep, {"b": run_dir})
    assert not (ep / "worlds" / "b" / S.run_end_name()).exists(), (
        "the planted file was copied into the archive; the run-end record is not in the copy "
        "list and a run dir entry at its name is not an input to anything")
    rows, word = _rows_and_word(ep)
    assert rows["b"].get("cut_short") is None
    assert word == control_word

    honest = S.cut_short_episode(tmp_path / "honest", cut={"b": "request-limit"})
    assert S.rows(S.mod("learning.judge.family").grade_family(honest))["b"].get(
        "cut_short") == "request-limit", (
        "the control failed: a HOST-written record no longer moves the grade either, so the "
        "assertion above is not about the forgery")
    assert control_rows["b"].get("cut_short") is None


def test_a_file_named_like_the_archived_run_end_record_planted_anywhere_under_the_run_dir_does_not_reach_the_grade(
        tmp_path):
    """A file named like the archived record, planted anywhere under the run dir, never reaches
    the grade: the archive copies only the host-side sidecar, which is outside the run dir.

    "Anywhere" is driven as three depths — the run dir's root, a nested directory the archive
    walks (`gather_raw/`), and the run dir's own parent-relative basename — because the archive
    DOES walk two directories per world and a per-entry screen that missed one of them would be
    invisible at the root alone. Positive control: `archive_writes_run_end_from_the_host`."""
    base, _src = S.runs_base(tmp_path)
    ep = S.cut_short_episode(tmp_path)
    run_dir = S.sibling_run_dir(base, "b")
    S.plant_sidecar(run_dir, truncated_by="aborted")
    forged = json.dumps(S.record_doc("request-limit"))
    (run_dir / S.run_end_name()).write_text(forged, encoding="utf-8")
    (run_dir / "gather_raw" / S.run_end_name()).write_text(forged, encoding="utf-8")
    nested = run_dir / "gather_raw" / "l-001"
    nested.mkdir(parents=True, exist_ok=True)
    (nested / S.run_end_name()).write_text(forged, encoding="utf-8")
    S.mod("learning.branch.archive").archive_episode(ep, {"b": run_dir})
    archived = json.loads(
        (ep / "worlds" / "b" / S.run_end_name()).read_text(encoding="utf-8"))
    assert archived == S.record_doc("aborted"), (
        f"a plant under the run dir reached the archived record: {archived!r}")
    assert S.graded(ep)["b"].get("cut_short") == "aborted"


def test_a_run_dir_salted_with_decoys_named_after_every_known_archived_artifact_still_yields_exactly_one_host_derived_run_end_record(
        tmp_path):
    """A run dir salted with decoys named after every known archived artifact still yields
    exactly one host-derived run-end record.

    The decoys are the archive's own names — the six roles plus the new leaf — each carrying a
    forged exit class, so a copy rule that reached for the wrong list would be visible as a
    second record or a wrong one. Positive control:
    `archive_writes_run_end_from_the_host`."""
    base, _src = S.runs_base(tmp_path)
    ep = S.cut_short_episode(tmp_path)
    run_dir = S.sibling_run_dir(base, "b")
    S.plant_sidecar(run_dir, truncated_by="store")
    for name in ("run_end.json", "scrub_verdict.json", "provenance.json", "lessons_loaded.jsonl",
                 "alert.json", "run_dir", S.run_end_name()):
        (run_dir / name).write_text(json.dumps(S.record_doc("request-limit")), encoding="utf-8")
    S.mod("learning.branch.archive").archive_episode(ep, {"b": run_dir})
    records = sorted(p.relative_to(ep) for p in ep.rglob(S.run_end_name()))
    assert [str(p) for p in records] == [f"worlds/b/{S.run_end_name()}"], (
        f"the archive produced {records} run-end records for one world")
    assert json.loads((ep / records[0]).read_text(encoding="utf-8")) == S.record_doc("store"), (
        "the one record the archive produced carries a decoy's value rather than the host "
        "sidecar's")


# ---------------------------------------------------------------------------------------
# report frontmatter — the surface the first design would have trusted
# ---------------------------------------------------------------------------------------


def _frontmatter_row(tmp_path, name, extra=None, raw=None):
    """One episode whose world b carries a planted `report.md`, graded."""
    ep = S.cut_short_episode(tmp_path / name)
    S.plant_frontmatter(ep / "worlds" / "b", extra=extra or "", raw=raw)
    return _rows_and_word(ep)


#: A frontmatter key that means nothing to anything, spelled to exactly the width of
#: `truncated_by`. The width matters: a malformed document's own refusal quotes the parser's
#: byte offset, so a control keyed on a shorter word would differ from the planted document in
#: the OFFSET rather than in anything about the exit class — and the test would then be reading
#: its own fixture's spelling as a finding.
INERT_KEY = "harmless_key"
assert len(INERT_KEY) == len("truncated_by")


def _apart_from_the_quoted_line(rows):
    """Rows with `ungradable_reason` dropped — for the MALFORMED arms only.

    A tier-2 refusal quotes the offending LINE of the document verbatim ("... line 4, column
    15: truncated_by: !!!"), so two documents that differ only in a key's spelling produce two
    reasons that differ in that spelling. That is the report reader's own pre-existing
    behaviour, not this piece's: a box already chose those bytes and already gets them echoed
    into the operator-facing reason, whatever key they sit under. What these tests own is the
    DECISION — whether the planted content changed the grade — so the quoted line is dropped
    here and the decision is compared. Recorded rather than silently tolerated: the
    box-chooses-the-reason-text surface predates #1047 and is not widened by it (the new row's
    own reason is host-composed from a label and a vocabulary member, never free text)."""
    return {label: {k: v for k, v in row.items() if k != "ungradable_reason"}
            for label, row in rows.items()}


def test_a_planted_truncated_by_line_in_report_frontmatter_changes_nothing(tmp_path):
    """A `truncated_by:` line spliced into world b's report.md frontmatter — which
    validate_report admits (claim h3) — changes neither b's row nor the family's verdict word.

    Claim h3 is EXECUTED: the spliced document went through `validate_report` and came back
    `None`, i.e. accepted, at 134 frontmatter bytes. Nothing rejects the key; what this pins is
    that nothing READS it either. Positive control: `cut_short_world_is_ungradable`."""
    control_rows, control_word = _rows_and_word(S.cut_short_episode(tmp_path / "control"))
    rows, word = _frontmatter_row(tmp_path, "planted", extra="truncated_by: request-limit\n")
    assert rows == control_rows, (
        "a frontmatter line the report validator admits moved the grade — the exact capability "
        "the revised design exists to withhold from the box")
    assert word == control_word, "a planted frontmatter line moved the family's verdict word"


def test_grading_given_a_planted_truncated_by_frontmatter_line_with_a_valid_value(tmp_path):
    """A planted frontmatter line carrying a VALID vocabulary member changes nothing.

    Every member is planted in turn, because "the value is immaterial" is a claim about the
    whole vocabulary and a reader that keyed on one member would pass a single-value test.
    Positive control: `cut_short_world_is_ungradable`."""
    control_rows, control_word = _rows_and_word(S.cut_short_episode(tmp_path / "control"))
    for member in S.vocabulary():
        rows, word = _frontmatter_row(tmp_path, f"valid-{member}",
                                      extra=f"truncated_by: {member}\n")
        assert rows == control_rows, f"{member}: a planted valid member moved the grade"
        assert word == control_word, f"{member}: a planted valid member moved the word"


def test_grading_given_a_planted_truncated_by_frontmatter_line_with_a_garbage_value(tmp_path):
    """A planted frontmatter line carrying garbage changes nothing either: frontmatter is not
    an input at all, so the planted value's shape is immaterial.

    Positive control: `cut_short_world_is_ungradable`."""
    for i, garbage in enumerate(("!!!", "[1, 2, 3]", "{a: b}", '"' + "x" * 200 + '"')):
        planted, planted_word = _frontmatter_row(
            tmp_path, f"garbage-{i}-with", extra=f"truncated_by: {garbage}\n")
        inert, inert_word = _frontmatter_row(
            tmp_path, f"garbage-{i}-without", extra=f"{INERT_KEY}: {garbage}\n")
        assert _apart_from_the_quoted_line(planted) == _apart_from_the_quoted_line(inert), (
            f"{garbage!r}: the grade differs between a garbage value under `truncated_by` and "
            "the same garbage under a key nothing has ever read — so the KEY is being read")
        assert planted_word == inert_word
        assert planted["b"].get("cut_short") is None, (
            f"{garbage!r}: a planted frontmatter value produced a cut_short key")


def test_grading_given_planted_row_shaped_keys_in_frontmatter(tmp_path):
    """Row-shaped keys planted in frontmatter are never merged into the row: the row is built by
    `_grade_world` from `read_world_facts`, not from report.md.

    The planted keys are the row's own discriminators — `ungradable`, `cut_short`, `malformed`,
    `ungradable_reason` — which is the merge an implementation that folded frontmatter into the
    row would produce. Positive control: `cut_short_world_is_ungradable`."""
    control_rows, control_word = _rows_and_word(S.cut_short_episode(tmp_path / "control"))
    rows, word = _frontmatter_row(tmp_path, "row-shaped", extra=(
        "ungradable: true\n"
        "cut_short: request-limit\n"
        "malformed: true\n"
        "ungradable_reason: planted by the box\n"))
    assert rows == control_rows, "a row-shaped frontmatter key was merged into the graded row"
    assert word == control_word


def test_grading_given_a_report_with_a_duplicate_frontmatter_key(tmp_path):
    """Whatever the frontmatter parser resolves a duplicate key to, the grade is unaffected —
    report frontmatter is outside grading's input set.

    The parser's own duplicate-key behaviour is existing untouched code and is deliberately NOT
    asserted here: this test pins only that the DECISION does not move, which is the half this
    piece owns. Positive control: `cut_short_world_is_ungradable`."""
    control_rows, control_word = _rows_and_word(S.cut_short_episode(tmp_path / "control"))
    rows, word = _frontmatter_row(tmp_path, "duplicate", extra=(
        "truncated_by: request-limit\ntruncated_by: aborted\n"))
    assert _apart_from_the_quoted_line(rows) == _apart_from_the_quoted_line(control_rows)
    assert word == control_word


def test_grading_given_an_oversized_or_malformed_frontmatter_block(tmp_path):
    """An oversized or malformed frontmatter block has no effect on the grading decision.

    "No effect" is asserted against the row the SAME malformation produces without any
    `truncated_by` content in it — an unclosed fence or a megabyte of padding legitimately
    changes how the report reads (that is pre-existing tier-1/tier-2 behaviour), and what this
    test owns is that the planted exit class adds nothing on top of it. Fork F-W (auto): the
    value is pinned, not a performance bound — neither input has an adversarial producer once
    the record is host-written.

    Positive control: `cut_short_world_is_ungradable`."""
    for name, with_value, without in (
        ("unclosed", "---\ndisposition: malicious\ntruncated_by: aborted\n",
         f"---\ndisposition: malicious\n{INERT_KEY}: aborted\n"),
        ("oversized", S.report_text("malicious", extra="truncated_by: aborted\npad: "
                                    + "x" * 200000 + "\n"),
         S.report_text("malicious", extra=f"{INERT_KEY}: aborted\npad: " + "x" * 200000 + "\n")),
    ):
        planted, planted_word = _frontmatter_row(tmp_path, f"{name}-with", raw=with_value)
        inert, inert_word = _frontmatter_row(tmp_path, f"{name}-without", raw=without)
        assert _apart_from_the_quoted_line(planted) == _apart_from_the_quoted_line(inert), (
            f"{name}: the planted exit class changed the grade")
        assert planted_word == inert_word
        assert planted["b"].get("cut_short") is None, (
            f"{name}: a malformed frontmatter block produced a cut_short key")


def test_grading_given_non_utf8_content_spliced_into_report_frontmatter(tmp_path):
    """Non-UTF-8 content spliced into frontmatter has no effect, by the same universal.

    Real bytes through the real reader: the document is written as bytes that are not valid
    UTF-8, so `read_guarded`'s decode answers for it rather than a stubbed exception. Asserted
    against the same bytes with the exit class replaced by an inert key. Positive control:
    `cut_short_world_is_ungradable`."""
    planted, planted_word = _frontmatter_row(
        tmp_path, "nonutf8-with",
        raw=b"---\ndisposition: malicious\ntruncated_by: \xff\xfe aborted\n---\n\nbody\n")
    inert, inert_word = _frontmatter_row(
        tmp_path, "nonutf8-without",
        raw=b"---\ndisposition: malicious\nharmless_key: \xff\xfe aborted\n---\n\nbody\n")
    assert _apart_from_the_quoted_line(planted) == _apart_from_the_quoted_line(inert)
    assert planted_word == inert_word
    assert planted["b"].get("cut_short") is None


# ---------------------------------------------------------------------------------------
# the owner's input channel, and whose world a record is about
# ---------------------------------------------------------------------------------------


def test_no_box_writable_files_content_is_ever_fed_as_the_value_argument_to_the_exit_class_normalizer(
        tmp_path):
    """No box-writable file's content is ever the value argument to the owner: the two sources
    are the archived record (from a host sidecar) and the in-process summary.

    Observed at each reader's OUTPUT rather than by wrapping the owner, because the demand is
    about what the readers answer and a recording wrapper would have to be patched in — the one
    thing the project's idioms forbid. A value planted in every box-writable name, at every one
    of the three sites, leaves all three answers identical to the control's; if any of that
    content were reaching the owner, at least one answer would have to move, since the planted
    value IS a member and the control's is not. Positive control: `normalized_truncated_by`."""
    base, _src = S.runs_base(tmp_path)
    archive = S.mod("learning.branch.archive")

    # site 1 — the archive
    clean_ep, forged_ep = S.episode(tmp_path / "clean"), S.episode(tmp_path / "forged")
    clean_dir, forged_dir = S.sibling_run_dir(base, "b"), S.sibling_run_dir(base, "c")
    S.plant_sidecar(clean_dir, truncated_by="aborted")
    S.plant_sidecar(forged_dir, truncated_by="aborted")
    S.salt_run_dir(forged_dir, value="request-limit")
    archive.archive_episode(clean_ep, {"b": clean_dir})
    archive.archive_episode(forged_ep, {"b": forged_dir})
    assert (clean_ep / "worlds" / "b" / S.run_end_name()).read_text(encoding="utf-8") == \
           (forged_ep / "worlds" / "b" / S.run_end_name()).read_text(encoding="utf-8"), (
        "the archive's record changed when box-written content changed")

    # site 2 — the judge. The salt goes in the RUN DIR and the real archive runs over it, for
    # the same reason it does everywhere in this module: `worlds/<label>/run_end.json` is the
    # host's own output, and a value planted THERE is supposed to move the grade
    # (`cut_short_row_shape`), so salting it would assert that demand's negation instead of
    # this one.
    judge_base, _src = S.runs_base(tmp_path / "judge-base")
    clean_grade = S.cut_short_episode(tmp_path / "judge-clean")
    forged_grade = S.cut_short_episode(tmp_path / "judge-forged")
    clean_world, forged_world = (S.sibling_run_dir(judge_base, "jb"),
                                 S.sibling_run_dir(judge_base, "jc"))
    S.plant_sidecar(clean_world, truncated_by="aborted")
    S.plant_sidecar(forged_world, truncated_by="aborted")
    S.salt_run_dir(forged_world, value="request-limit")
    archive.archive_episode(clean_grade, {"b": clean_world})
    archive.archive_episode(forged_grade, {"b": forged_world})
    assert S.graded(forged_grade)["b"].get("cut_short") == \
           S.graded(clean_grade)["b"].get("cut_short") == "aborted"

    # site 3 — the ticket lane
    clean_run = S.closed_run_dir(tmp_path / "ticket-clean", disposition="unresolved")
    forged_run = S.closed_run_dir(tmp_path / "ticket-forged", disposition="unresolved")
    S.salt_run_dir(forged_run, value="request-limit")
    (forged_run / "report.md").write_text(S.report_text("unresolved"), encoding="utf-8")
    a = S.close_ticket(clean_run, truncated_by="aborted")
    b = S.close_ticket(forged_run, truncated_by="aborted")
    assert [c.path.split("/")[-1] for c in a.calls] == [c.path.split("/")[-1] for c in b.calls]


def test_a_near_miss_spelling_of_a_real_exit_class_planted_in_any_box_writable_file_has_no_channel_to_reach_any_of_the_three_readers(
        tmp_path):
    """A near-miss spelling planted in any box-writable file has no channel to any of the three
    readers — which is why fork F-M's leniency question is not a security surface whichever way
    it resolves.

    The near-misses are F-M's own three arms: whitespace-padded, case-variant and a Cyrillic-а
    confusable. If any of them had a channel, the owner's strictness would be load-bearing
    against an adversary rather than a host-to-host contract choice, and F-M would have been a
    security decision instead of a style one. Positive control: `normalized_truncated_by`."""
    control = S.cut_short_episode(tmp_path / "control")
    control_rows, control_word = _rows_and_word(control)
    for i, near in enumerate((" request-limit ", "REQUEST-LIMIT", "аborted")):
        ep = S.cut_short_episode(tmp_path / f"near-{i}")
        S.salt_run_dir(ep / "worlds" / "b", value=near)
        rows, word = _rows_and_word(ep)
        assert rows == control_rows, f"{near!r}: a near-miss planted by the box reached a row"
        assert word == control_word, f"{near!r}: a near-miss moved the family's verdict word"

        run_dir = S.closed_run_dir(tmp_path / f"near-ticket-{i}", disposition="benign")
        S.salt_run_dir(run_dir, value=near)
        (run_dir / "report.md").write_text(S.report_text("benign"), encoding="utf-8")
        fake = S.close_ticket(run_dir, truncated_by=None)
        assert len(fake.transitions) == 1, (
            f"{near!r}: a near-miss planted by the box moved the ticket lane's transition")
        assert fake.notes == [], (
            f"{near!r}: a near-miss planted by the box raised an escalation note")


def test_a_planted_run_end_shaped_value_outside_the_truncated_by_vocabulary_does_not_produce_a_row_the_owner_functions_output_would_never_be(
        tmp_path):
    """No plant can produce a row value the owner would not itself have produced: every value
    that reaches the row passes through the owner's membership answer.

    Stated as a closed property rather than as a list of refusals: over every value planted —
    members, near-misses, garbage, non-strings — the set of `cut_short` values the rows carry is
    a subset of `{None} | TRUNCATED_BY_VALUES`. A reader that passed a raw string through would
    show up here whatever the planted spelling was. Positive control:
    `cut_short_world_is_ungradable`."""
    allowed = {None, *S.vocabulary()}
    seen = set()
    plants = [*S.vocabulary(), " aborted ", "REQUEST-LIMIT", "аborted", "", "!!!",
              "request_limit", "x" * 500]
    for i, value in enumerate(plants):
        ep = S.cut_short_episode(tmp_path / f"plant-{i}")
        S.salt_run_dir(ep / "worlds" / "b", value=value)
        S.plant_archived_record(ep, "c", raw=json.dumps({"truncated_by": value}))
        for row in _rows_and_word(ep)[0].values():
            seen.add(row.get("cut_short"))
    assert seen <= allowed, (
        f"rows carried cut_short values the owner would never return: {seen - allowed}")


def test_no_world_can_move_another_worlds_cut_short_row(tmp_path):
    """Content planted in world b's run dir or sidecar that claims to describe world c — a
    run_end.json under b's identity carrying c's label, or a sidecar forged to answer for c's
    run_id — never reaches c's row: worlds/b/run_end.json and worlds/c/run_end.json land at two
    distinct, non-interfering paths and each world's grade reflects only its own record.

    Fork F-N (auto, §7 round 2), minted by the phase-D gate: R2 fires on `run_end_json.identity`
    but a bare-edge bind let the facet obligation be answered without ever asking the
    cross-world question. The property is almost certainly already true (claims h23/n2: a box
    binds only its own run dir), which is exactly why the test is cheap and why leaving it
    unwritten would have been a structural gap rather than a behavioural one.

    Positive control: `cut_short_world_is_ungradable` — c's OWN record does move c's row."""
    base, _src = S.runs_base(tmp_path)
    ep = S.cut_short_episode(tmp_path)
    b_dir, c_dir = S.sibling_run_dir(base, "b"), S.sibling_run_dir(base, "c")
    S.plant_sidecar(b_dir, truncated_by="request-limit")
    S.plant_sidecar(c_dir, truncated_by=None)
    # b claims to answer for c, on both channels it has: a file in its own run dir naming c,
    # and a sidecar written at the path c's run dir would derive.
    (b_dir / S.run_end_name()).write_text(
        json.dumps({"world": "c", "label": "c", "run_id": c_dir.name,
                    "truncated_by": "aborted"}), encoding="utf-8")
    (b_dir / f"{c_dir.name}.forged.json").write_text(
        json.dumps(S.record_doc("aborted")), encoding="utf-8")
    S.mod("learning.branch.archive").archive_episode(ep, {"b": b_dir, "c": c_dir})
    records = {label: json.loads(
        (ep / "worlds" / label / S.run_end_name()).read_text(encoding="utf-8"))
        for label in ("b", "c")}
    assert records["b"]["truncated_by"] == "request-limit"
    assert records["c"]["truncated_by"] is None, (
        "world b's plant reached world c's record; the two records must land at distinct, "
        "non-interfering paths")
    graded = S.graded(ep)
    assert graded["b"].get("cut_short") == "request-limit"
    assert graded["c"].get("cut_short") is None, "world b moved world c's row"

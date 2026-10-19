"""#1047 — the security dive's two negative universals, and the positive controls that make them
mean something."""
from __future__ import annotations

import json

from defender._episode_handle import Episode
from defender.tests.support.shared.filesystem import _spec1047 as S


def _rows_and_word(episode_dir):
    """One pass over one episode: every row, plus what the family-scope call (which gives the
    family's word since #1224) was shown of each world."""
    return S.graded_with_view(episode_dir)


# the universal, as one test over every surface


def test_no_file_a_box_can_write_is_an_input_to_was_this_run_cut_short(tmp_path):
    archive = S.mod("learning.branch.archive")

    control_base, _src = S.runs_base(tmp_path / "control-base")
    control_ep = S.cut_short_episode(tmp_path / "control")
    with Episode.open(control_ep) as episode:
        archive.archive_episode(
            episode, {label: S.sibling_run_dir(control_base, label) for label in ("b", "c")})
    control_rows, control_word = _rows_and_word(control_ep)

    forged_base, _src = S.runs_base(tmp_path / "forged-base")
    forged_ep = S.cut_short_episode(tmp_path / "forged")
    forged_dirs = {label: S.sibling_run_dir(forged_base, label) for label in ("b", "c")}
    for run_dir in forged_dirs.values():
        S.salt_run_dir(run_dir, value="request-limit")
    with Episode.open(forged_ep) as episode:
        archive.archive_episode(episode, forged_dirs)
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

    control_ticket = S.record_ticket(
        S.closed_run_dir(tmp_path / "ticket-clean", disposition="benign"), truncated_by=None)
    salted = S.closed_run_dir(tmp_path / "ticket-salted", disposition="benign")
    S.salt_run_dir(salted, value="aborted")
    (salted / "report.md").write_text(S.report_text("benign"), encoding="utf-8")
    forged_ticket = S.record_ticket(salted, truncated_by=None)
    assert [(c.path.split("/")[-1], c.body) for c in forged_ticket.calls] == \
           [(c.path.split("/")[-1], c.body) for c in control_ticket.calls], (
        "a forgery under the run dir moved what the ticket lane did")


def test_every_box_writable_artifact_carrying_a_truncated_by_looking_value_leaves_the_grade_unmoved(
        tmp_path):
    """Every file under the box's bind carrying a truncated_by-looking value leaves the grade
    unmoved — the stated scope of `no_box_writable_input_to_cut_short`."""
    archive = S.mod("learning.branch.archive")
    control_base, _src = S.runs_base(tmp_path / "control-base")
    control_ep = S.cut_short_episode(tmp_path / "control")
    with Episode.open(control_ep) as episode:
        archive.archive_episode(episode, {"b": S.sibling_run_dir(control_base, "b")})
    control_rows, control_word = _rows_and_word(control_ep)
    for i, name in enumerate(S.FORGEABLE_NAMES):
        base, _src = S.runs_base(tmp_path / f"base-{i}")
        ep = S.cut_short_episode(tmp_path / f"forged-{i}-{name.replace('/', '_')}")
        run_dir = S.sibling_run_dir(base, "b")
        (run_dir / name).write_text(
            json.dumps(S.record_doc("request-limit")), encoding="utf-8")
        with Episode.open(ep) as episode:
            archive.archive_episode(episode, {"b": run_dir})
        assert not (ep / "worlds" / "b" / S.run_end_name()).exists(), (
            f"{name}: a box-written file became the archived run-end record")
        seen_rows, seen_word = _rows_and_word(ep)
        assert seen_rows == control_rows, f"{name}: a planted value moved the grade"
        assert seen_word == control_word, f"{name}: a planted value moved the verdict word"

    honest = S.cut_short_episode(tmp_path / "honest", cut={"b": "request-limit"})
    assert S.graded(honest)["b"].get("cut_short") == "request-limit", (
        "the control failed: a HOST-written record no longer moves the grade, so every "
        "`unmoved` above is a tautology rather than a finding")


def test_a_file_named_like_the_archived_run_end_record_planted_anywhere_under_the_run_dir_does_not_reach_the_grade(
        tmp_path):
    """A file named like the archived record, planted anywhere under the run dir, never reaches the
    grade: the archive copies only the host-side sidecar, which is outside the run dir."""
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
    with Episode.open(ep) as episode:
        S.mod("learning.branch.archive").archive_episode(episode, {"b": run_dir})
    archived = json.loads(
        (ep / "worlds" / "b" / S.run_end_name()).read_text(encoding="utf-8"))
    assert archived == S.record_doc("aborted"), (
        f"a plant under the run dir reached the archived record: {archived!r}")
    assert S.graded(ep)["b"].get("cut_short") == "aborted"


# report frontmatter — the surface the first design would have trusted


def _frontmatter_row(tmp_path, name, extra=None, raw=None):
    """One episode whose world b carries a planted `report.md`, graded."""
    ep = S.cut_short_episode(tmp_path / name)
    S.plant_frontmatter(ep / "worlds" / "b", extra=extra or "", raw=raw)
    return _rows_and_word(ep)


#: A frontmatter key that means nothing to anything, spelled to exactly the width of
INERT_KEY = "harmless_key"
assert len(INERT_KEY) == len("truncated_by")


def test_a_planted_truncated_by_line_in_report_frontmatter_changes_nothing(tmp_path):
    """A `truncated_by:` line spliced into world b's report.md frontmatter — which validate_report
    admits (claim h3) — changes neither b's row nor the family's verdict word."""
    control_rows, control_word = _rows_and_word(S.cut_short_episode(tmp_path / "control"))
    rows, word = _frontmatter_row(tmp_path, "planted", extra="truncated_by: request-limit\n")
    assert rows == control_rows, (
        "a frontmatter line the report validator admits moved the grade — the exact capability "
        "the revised design exists to withhold from the box")
    assert word == control_word, "a planted frontmatter line moved the family's verdict word"


def test_grading_given_a_planted_truncated_by_frontmatter_line_with_a_valid_value(tmp_path):
    """A planted frontmatter line carrying a VALID vocabulary member changes nothing."""
    control_rows, control_word = _rows_and_word(S.cut_short_episode(tmp_path / "control"))
    for member in S.vocabulary():
        rows, word = _frontmatter_row(tmp_path, f"valid-{member}",
                                      extra=f"truncated_by: {member}\n")
        assert rows == control_rows, f"{member}: a planted valid member moved the grade"
        assert word == control_word, f"{member}: a planted valid member moved the word"


# the owner's input channel, and whose world a record is about


def test_no_box_writable_files_content_is_ever_fed_as_the_value_argument_to_the_exit_class_normalizer(
        tmp_path):
    """No box-writable file's content is ever the value argument to the owner: the two sources are
    the archived record (from a host sidecar) and the in-process summary."""
    base, _src = S.runs_base(tmp_path)
    archive = S.mod("learning.branch.archive")

    # site 1 — the archive
    clean_ep, forged_ep = S.episode(tmp_path / "clean"), S.episode(tmp_path / "forged")
    clean_dir, forged_dir = S.sibling_run_dir(base, "b"), S.sibling_run_dir(base, "c")
    S.plant_sidecar(clean_dir, truncated_by="aborted")
    S.plant_sidecar(forged_dir, truncated_by="aborted")
    S.salt_run_dir(forged_dir, value="request-limit")
    with Episode.open(clean_ep) as episode:
        archive.archive_episode(episode, {"b": clean_dir})
    with Episode.open(forged_ep) as episode:
        archive.archive_episode(episode, {"b": forged_dir})
    assert (clean_ep / "worlds" / "b" / S.run_end_name()).read_text(encoding="utf-8") == \
           (forged_ep / "worlds" / "b" / S.run_end_name()).read_text(encoding="utf-8"), (
        "the archive's record changed when box-written content changed")

    judge_base, _src = S.runs_base(tmp_path / "judge-base")
    clean_grade = S.cut_short_episode(tmp_path / "judge-clean")
    forged_grade = S.cut_short_episode(tmp_path / "judge-forged")
    clean_world, forged_world = (S.sibling_run_dir(judge_base, "jb"),
                                 S.sibling_run_dir(judge_base, "jc"))
    S.plant_sidecar(clean_world, truncated_by="aborted")
    S.plant_sidecar(forged_world, truncated_by="aborted")
    S.salt_run_dir(forged_world, value="request-limit")
    with Episode.open(clean_grade) as episode:
        archive.archive_episode(episode, {"b": clean_world})
    with Episode.open(forged_grade) as episode:
        archive.archive_episode(episode, {"b": forged_world})
    assert S.graded(forged_grade)["b"].get("cut_short") == \
           S.graded(clean_grade)["b"].get("cut_short") == "aborted"

    # site 3 — the ticket lane
    clean_run = S.closed_run_dir(tmp_path / "ticket-clean", disposition="unresolved")
    forged_run = S.closed_run_dir(tmp_path / "ticket-forged", disposition="unresolved")
    S.salt_run_dir(forged_run, value="request-limit")
    (forged_run / "report.md").write_text(S.report_text("unresolved"), encoding="utf-8")
    a = S.record_ticket(clean_run, truncated_by="aborted")
    b = S.record_ticket(forged_run, truncated_by="aborted")
    assert [c.path.split("/")[-1] for c in a.calls] == [c.path.split("/")[-1] for c in b.calls]


def test_no_world_can_move_another_worlds_cut_short_row(tmp_path):
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
    with Episode.open(ep) as episode:
        S.mod("learning.branch.archive").archive_episode(episode, {"b": b_dir, "c": c_dir})
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

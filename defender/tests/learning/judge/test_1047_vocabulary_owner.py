"""#1047 — the vocabulary owner: ONE answer to what a `truncated_by` value means."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

from defender.tests.support.learning.branch import _triplet_947 as T

import json

from defender.records._episode_handle import Episode
from defender.tests.support.shared.filesystem import _spec1047 as S


def _owner():
    """The owner function, looked up at call time so a missing one fails the test."""
    return S.sym("records.session_store", "normalized_truncated_by")


# the seam itself


def test_session_store_owns_what_a_truncated_by_value_means():
    normalized = _owner()
    members = S.vocabulary()
    assert members, "TRUNCATED_BY_VALUES is empty; the vocabulary has no members to own"
    for member in members:
        assert normalized(member) == member, (
            f"{member!r} is a declared member of TRUNCATED_BY_VALUES and the owner refused it")
    for outside in (None, "", "request_limit", "REQUEST-LIMIT", 7, ["aborted"],
                    # Fragments a partial write leaves: near-misses, never completed.
                    "request-", "-limit", "requestlimit", "retry-exhaust"):
        assert normalized(outside) is None, (
            f"{outside!r} is not a member and the owner answered something other than None")


def test_normalized_truncated_by_is_strict_about_whitespace_case_and_confusables():
    normalized = _owner()
    assert normalized("aborted") == "aborted", (
        "control: the owner refused an exactly-spelled member")
    for spelling, why in (
        (" request-limit ", "whitespace-padded"),
        ("\trequest-limit\n", "whitespace-padded with tabs and newlines"),
        ("REQUEST-LIMIT", "a case variant"),
        ("Request-Limit", "a title-case variant"),
        ("аborted", "a Cyrillic-а confusable"),
        ("aborted​", "a zero-width space inside a member"),
    ):
        assert normalized(spelling) is None, (
            f"{spelling!r} ({why}) was coerced into the member it resembles")


# coherence — the three interpretation sites give one answer


def _three_sites(tmp_path, value):
    """Drive the exit value through the archive and both interpretation sites and return what each
    made of it: the archive's copied record, the judge's read, and the ticket lane's calls."""
    base, _src = location_path(S.runs_base)(tmp_path)
    ep = S.episode(tmp_path)
    run_dir = S.sibling_run_dir(base, "b")
    S.plant_sidecar(run_dir, truncated_by=value)
    with Episode.open(ep) as episode:
        S.mod("learning.branch.archive").archive_episode(episode, {T.world_id(episode.dir, 'b'): run_dir})
    archived = json.loads((ep / "worlds" / T.world_id(ep, "b") / S.run_end_name()).read_text(encoding="utf-8"))

    graded_ep = S.cut_short_episode(tmp_path / "graded")
    S.plant_archived_record(graded_ep, "b", raw=json.dumps(S.record_doc(value)))
    row = S.graded(graded_ep)["b"]

    ticket_run = S.closed_run_dir(tmp_path / "ticket")
    fake = S.record_ticket(ticket_run, truncated_by=value)
    return archived, row, fake


def test_every_reader_of_the_exit_class_takes_the_owners_answer(tmp_path):
    refused_archived, refused_row, refused_ticket = _three_sites(tmp_path / "no", "REQUEST-LIMIT")
    assert refused_archived["truncated_by"] == "REQUEST-LIMIT", (
        "the archive rewrote the sidecar's value instead of copying it")
    assert refused_row.get("cut_short") is None, "the judge read a value the owner refuses"
    assert len(refused_ticket.records) == 1, (
        "a value the owner refuses did not take the report-driven fallback at the ticket lane")

    ok_archived, ok_row, ok_ticket = _three_sites(tmp_path / "yes", "request-limit")
    assert ok_archived["truncated_by"] == "request-limit", (
        "the control failed: the archive did not carry a real member through")
    assert ok_row.get("cut_short") == "request-limit"
    assert len(ok_ticket.records) == 1, "the request-limit arm made no record at all"

    gate = S.mod("run_common").learning_refusal_gate
    assert gate(tmp_path, tmp_path / "alert.json", truncated_by="REQUEST-LIMIT") is not None, (
        "the corpus-refusal gate stopped refusing an unrecognized exit class")

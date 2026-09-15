"""#860 — the denial record's lead, and the surface that reads the denial stream (unit half).

The driven half lives in `tests/e2e/test_860_refused_on_judge_view.py`. Pinned here, at the
unit level:

* **M1** — `observe.RequestLogger.log_policy_denial` takes `lead_id` (defaulted `None`, since
  the fixture call sites pass none) and the record carries it, `None` included.
* **M3** — `lead_repository.load_denials(run_dir)` reads `<run_dir>/policy_denials.jsonl`
  through `read_jsonl_rows`' tolerance, keeps only `event_type == "policy_denial"` rows (the
  stream also carries `budget_refusal` records), answers `[]` for an absent file, and types
  each row as `Denial(seq, system, verb, lead_id)`.

The two new names are reached lazily (`getattr`) so a missing target is one red test each
rather than a collection error hiding the rest.
"""
from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

from defender._io import append_jsonl, read_jsonl_rows
from defender.learning import lead_repository
from defender.runtime import observe

DENIAL_KEYS = frozenset({
    "event_type", "ts", "seq", "role", "system", "verb", "call_id", "params_digest", "lead_id",
})


def _load_denials():
    """`lead_repository.load_denials`, or one red test."""
    fn = getattr(lead_repository, "load_denials", None)
    assert fn is not None, "lead_repository.load_denials does not exist"
    return fn


def _denial_type():
    typ = getattr(lead_repository, "Denial", None)
    assert typ is not None, "lead_repository.Denial does not exist"
    return typ


def _write(path: Path, *records) -> None:
    """A denial stream as the REAL writer leaves one: one record per line."""
    append_jsonl(path, list(records))


def _record(seq: int, *, lead_id, system: str = "ticket", verb: str = "get-ticket") -> dict:
    return {
        "event_type": observe.POLICY_DENIAL_EVENT_TYPE, "ts": "2026-09-15T12:00:00+00:00",
        "seq": seq, "role": "gather", "system": system, "verb": verb,
        "call_id": f"{system}.{verb}", "params_digest": "0123456789abcdef", "lead_id": lead_id,
    }


# ---------------------------------------------------------------------------------------
# M1 — the writer
# ---------------------------------------------------------------------------------------


def test_m1_the_writer_records_the_lead_it_is_given_and_none_without_one(tmp_path):
    """M1 — `log_policy_denial(..., lead_id="l-007")` leaves a record whose `lead_id` is
    `"l-007"`; a call with NO `lead_id` keyword (every pre-#860 call site) still writes, and its
    record carries `lead_id: None` — the key is present on every record, so a reader can tell
    "no lead context" from a record written before the column existed (N4). Both records have
    exactly the M1 key set; `seq` stays the denial stream's own counter.

    Observed failing by: the keyword refused (today), or a record without the key."""
    path = tmp_path / observe.POLICY_DENIALS
    logger = observe.RequestLogger(path)
    with_lead = logger.log_policy_denial(
        role="gather", system="ticket", verb="get-ticket", call_id="ticket.get-ticket",
        params={"ticket_id": "T-1"}, lead_id="l-007",
    )
    without = logger.log_policy_denial(
        role="gather", system="ticket", verb="key-pattern", call_id="ticket.key-pattern",
        params={},
    )
    logger.close()

    on_disk = read_jsonl_rows(path)
    assert [r["seq"] for r in on_disk] == [0, 1]
    assert on_disk[0] == with_lead, "the record on disk differs from the one returned"
    assert on_disk[1] == without
    assert set(on_disk[0]) == DENIAL_KEYS, f"keyed {sorted(on_disk[0])}"
    assert set(on_disk[1]) == DENIAL_KEYS, f"keyed {sorted(on_disk[1])}"
    assert on_disk[0]["lead_id"] == "l-007"
    assert on_disk[1]["lead_id"] is None
    assert "params" not in on_disk[0], "the raw blob reached the record beside the lead id"


# ---------------------------------------------------------------------------------------
# M3 — the reader
# ---------------------------------------------------------------------------------------


def test_m3_load_denials_answers_empty_for_an_absent_file(tmp_path):
    """M3 — a run dir with no `policy_denials.jsonl` (the common case: a clean run opens no
    such file) reads as `[]`, not an error.

    Observed failing by: the function missing, or raising on the absent file."""
    assert not (tmp_path / observe.POLICY_DENIALS).exists()
    assert _load_denials()(tmp_path) == []


def test_m3_load_denials_keeps_only_policy_denial_rows_typed_off_the_record(tmp_path):
    """M3 — over a stream holding a `policy_denial` record, a `budget_refusal` record (the
    shape `log_budget_refusal` writes into the SAME file), a record with an unknown
    `event_type`, a line that is not JSON, and a JSON line that is not an object: the answer
    is exactly ONE `Denial`, typed `(seq, system, verb, lead_id)` off the record — the
    tolerance is `read_jsonl_rows`' own (a bad line is skipped, not raised), and the filter is
    on `event_type`. A legacy record with no `lead_id` key reads as `lead_id None`.

    Observed failing by: a budget refusal typed as a denial, a bad line raising, or a field
    read off the wrong column."""
    path = tmp_path / observe.POLICY_DENIALS
    legacy = _record(5, lead_id=None, system="cmdb", verb="list-roles")
    del legacy["lead_id"]
    _write(
        path,
        {"event_type": "budget_refusal", "kind": "budget_refusal", "tool_name": "query",
         "agent_id": "main"},
        _record(3, lead_id="l-002"),
        {"event_type": "something_else", "seq": 4, "system": "x", "verb": "y", "lead_id": "l-002"},
        legacy,
    )
    with path.open("a", encoding="utf-8") as fh:
        fh.write("this line is not json\n")  # lint-jsonl-io: ok — the malformed line under test
        fh.write("[1, 2, 3]\n")  # lint-jsonl-io: ok — a JSON line that is not a row

    denials = _load_denials()(tmp_path)
    assert [(d.seq, d.system, d.verb, d.lead_id) for d in denials] == [
        (3, "ticket", "get-ticket", "l-002"),
        (5, "cmdb", "list-roles", None),
    ], f"load_denials answered {denials!r}"
    assert all(isinstance(d, _denial_type()) for d in denials)
    assert isinstance(denials[0].seq, int)


def test_m3_denial_is_typed_seq_system_verb_lead_id_and_nothing_else():
    """M3 — `Denial`'s fields are exactly `seq`, `system`, `verb`, `lead_id`, in that order: the
    stored row typed ONCE, and never the raw record (no `params_digest`, `call_id`, `ts` or
    `role` — none of which a render is allowed to name).

    Observed failing by: the type missing or carrying another field."""
    typ = _denial_type()
    names = ([f.name for f in dataclasses.fields(typ)] if dataclasses.is_dataclass(typ)
             else list(getattr(typ, "_fields", ())))
    assert names == ["seq", "system", "verb", "lead_id"], f"Denial is typed {names}"


def test_m3_joined_leads_carry_denials_and_the_fixture_lead_without_any_has_an_empty_list(
    tmp_path,
):
    """M3 — `JoinedLead.denials` exists on every joined lead: a lead file with no rows and no
    denial reads `denials == []`, and the same lead with one attributed record reads exactly
    that record. `queries` and `sentinels` are `[]` both times.

    Observed failing by: the field missing, or a denial changing the other two lists."""
    from defender.tests.test_1017_row_schema import _lead_file

    _lead_file(tmp_path, "G", lead_id="l-002")
    (lead,) = lead_repository.joined(tmp_path)
    assert (lead.lead_id, lead.queries, lead.sentinels) == ("l-002", [], [])
    assert lead.denials == []

    _write(tmp_path / observe.POLICY_DENIALS, _record(0, lead_id="l-002"))
    (lead,) = lead_repository.joined(tmp_path)
    assert (lead.queries, lead.sentinels) == ([], [])
    assert [(d.seq, d.system, d.verb, d.lead_id) for d in lead.denials] \
        == [(0, "ticket", "get-ticket", "l-002")]


@pytest.mark.parametrize("stray", [
    pytest.param({"seq": "0"}, id="string-seq"),
    pytest.param({"seq": None}, id="null-seq"),
])
def test_m3_a_non_integer_seq_on_a_record_does_not_raise_out_of_the_reader(tmp_path, stray):
    """M3 — the stream is a file in the box's rw bind; a record whose `seq` is not an integer
    must not raise out of `load_denials` (and so out of every judge render over the world).
    What it reads AS is not pinned — only that the reader survives and still answers the
    well-formed record beside it.

    Observed failing by: `TypeError`/`ValueError` out of the reader."""
    _write(tmp_path / observe.POLICY_DENIALS,
           {**_record(0, lead_id="l-002"), **stray}, _record(1, lead_id="l-003"))
    denials = _load_denials()(tmp_path)
    assert any(d.lead_id == "l-003" and d.seq == 1 for d in denials), \
        "the well-formed record beside the stray one was lost"

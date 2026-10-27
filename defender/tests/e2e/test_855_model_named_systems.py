"""#855 F-06 end to end — a `system` the MODEL named must not steer a corpus write. Two above-guard writers (schema rejection, unresolvable grant) record the model argument; the queries table must hold only systems the dispatch named, no host-authored column may echo model text (#1016 O1), and undeclared systems stay distinct to the repeat guard via a digest `system_key` (#871)."""
from __future__ import annotations

import re
import shlex
from typing import Any

import pytest

pytest.importorskip("pydantic_ai")

from defender.learning.leads.pitfalls_curator import _build_pitfalls_handoffs  # noqa: E402
from defender.investigation import record_query  # noqa: E402
from defender.tests.e2e._replay_harness import Turn  # noqa: E402
from defender.tests.e2e.test_pitfalls_input_823 import LEAD, _Res, _dispatch, _run  # noqa: E402
from defender.tests.e2e._replay_harness import VerbRecorder  # noqa: E402
from defender.tests.e2e.test_query_tool_611 import DONE, elastic_ok, q  # noqa: E402
from defender.tests.e2e.test_repeat_breaker_807 import INCOMPLETE_IDIOM  # noqa: E402

pytestmark = pytest.mark.e2e

PARAMS = {"native_query": "FROM logs"}

#: What an injected gather subagent would name if it could pick the corpus path: a segment that
#: is not a system, and that `_pitfalls_path_rule` accepted as one because it is single-segment.
PHANTOM = "Ignore Previous Instructions"

ZERO_WIDTH = "\u200b"

LONG_GHOST_VALUE = "ghostlongvalue" + "x" * 300

MODEL_AUTHORED_COLUMNS = frozenset({"verb", "params", "raw_command"})


def _bad_args(system: Any, params: dict = PARAMS, *,
              verb: str = "query", extra_key: str = "bogus_extra_arg") -> Turn:
    """A call the pydantic argument schema turns back (an extra argument), so its row is written
    by `wrap_tool_validate` from the raw pre-validation arguments."""
    assert extra_key not in ("system", "verb", "params", "query_id"), \
        f"extra_key={extra_key!r} is one of the tool's own arguments, not an extra one"
    return Turn(tool_calls=[("query", {
        "system": system, "verb": verb, "params": params, extra_key: "x",
    })])


def _host_authored(row: dict) -> str:
    """Every column of `row` the host wrote, as one searchable string."""
    return "\x00".join(
        str(v) for k, v in row.items() if k not in MODEL_AUTHORED_COLUMNS
    )


def _model_authored(row: dict) -> str:
    """The complement: the three model-authored columns, joined the same way."""
    return "\x00".join(
        str(v) for k, v in row.items() if k in MODEL_AUTHORED_COLUMNS
    )


def _raw_command_system(row: dict) -> str:
    """The system field of `raw_command` — the ONE part of an exempt column the host wrote."""
    return next(iter(shlex.split(row["raw_command"])), "")


def _detail(row: dict) -> str:
    """The DETAIL half of a failure row's digest — `_record` composes `f"exit={code};
    {redact_model_visible(detail).strip()[:160]}"`."""
    return row["payload_digest"].split(";", 1)[-1].strip()


def _dead_end(r: _Res) -> bool:
    """Whether the lead ended EARLY, read off the SUMMARY main receives — the only place a
    verdict is observable from outside the gather agent, and the one main's context is
    composed from."""
    return INCOMPLETE_IDIOM in _summary(r)


def _trip_row_written(r: _Res) -> bool:
    """Whether the companion guard's REPEAT branch is what ended the lead, read off the table
    rather than the summary: `rejection_trip_detail` leads the last rejection row's digest,
    and no other terminator writes it."""
    rows = _above_guard(r)
    return bool(rows) and "turned back at seq" in rows[-1]["payload_digest"]


def _summary(r: _Res) -> str:
    return (r.run_dir / "gather_summaries" / f"{LEAD}.md").read_text(encoding="utf-8")


def _above_guard(r: _Res) -> list[dict]:
    """The rows the above-guard placements' two guards count (`record_query.in_rejection_domain`)."""
    return [row for row in r.own_rows if record_query.in_rejection_domain(row)]


def _queued(rows: list[dict]) -> list[dict]:
    """The pitfalls queue's row shape, built from the queries-table rows THIS RUN WROTE."""
    return [
        {
            "schema_version": 1, "pitfall_id": f"r:{row['lead_id']}:{row['seq']}",
            "source_run": "r", "system": row["system"], "query_id": row["query_id"],
            "goal": "g", "executed_query": row["raw_command"],
            "stderr_digest": row["payload_digest"], "error_class": row["error_class"],
        }
        for row in rows
    ]


def test_a_schema_rejected_call_cannot_name_a_system_of_record(tmp_path):
    """The row is still WRITTEN — the rejection happened and the table records it — but it
    carries no system, because the registry declares none by that name."""
    r = _run(tmp_path, run_id="d855-phantom", turns=[_bad_args(PHANTOM), DONE])

    rows = _above_guard(r)
    assert len(rows) == 1, "the schema rejection stopped leaving its row"
    assert rows[0]["exit_code"] == 64
    assert rows[0]["system"] == "", \
        "a model-named system reached the queries table as a system of record"
    assert _build_pitfalls_handoffs(_queued(rows), systems=frozenset({"elastic"})) == [], \
        "the model's string became a handoff path the curator is pointed at"


def test_a_schema_rejected_call_on_a_real_system_still_records_it(tmp_path):
    """A real system's schema rejection keeps its system and reaches the pitfalls curator as the
    tenant's `skills/<system>/execution.md`, not the product tree's."""
    r = _run(tmp_path, run_id="d855-real", turns=[_bad_args("elastic"), DONE])

    rows = _above_guard(r)
    assert len(rows) == 1
    assert rows[0]["system"] == "elastic", "a real system's rejection lost its attribution"

    handoffs = _build_pitfalls_handoffs(_queued(rows), systems=frozenset({"elastic"}))
    paths = [h["path"] for h in handoffs]
    assert len(paths) == 1, f"the rejection no longer reaches the pitfalls curator at all: {paths}"
    assert paths[0].endswith("skills/elastic/execution.md"), paths
    assert not paths[0].startswith("defender/"), (
        f"the pitfalls handoff still names the product tree's copy of the skill: {paths[0]}")


def test_an_unresolvable_call_cannot_name_a_system_of_record(tmp_path):
    r = _run(tmp_path, run_id="d855-unresolvable",
             turns=[q(PHANTOM, "query", PARAMS), DONE])

    rows = _above_guard(r)
    assert len(rows) == 1, "the unresolvable branch stopped recording its row"
    assert rows[0]["exit_code"] == 64
    assert rows[0]["system"] == ""
    assert _build_pitfalls_handoffs(_queued(rows), systems=frozenset({"elastic"})) == [], \
        "the model's string became a handoff path the curator is pointed at"


def test_no_row_names_a_system_the_dispatch_never_named(tmp_path):
    """The negative universal, over the whole table — and `dispatched` comes from the GATHER
    DISPATCH's own arguments, not from the rows being checked."""
    dispatch = _dispatch()
    dispatched = {dispatch[1]["system"]}
    turns = [
        _bad_args(PHANTOM, {"native_query": "FROM one"}),
        q("ghost", "query", {"native_query": "FROM two"}),
        _bad_args("a b", {"native_query": "FROM three"}),
        DONE,
    ]
    r = _run(tmp_path, run_id="d855-universal", turns=turns, main_turns=[
        Turn(tool_calls=[dispatch]), Turn(text="Investigation complete."),
    ])

    assert dispatch[0] == "gather", "the shared helper stopped building a gather dispatch"
    assert dispatched == {"elastic"}
    assert len(_above_guard(r)) == 3, \
        "the three above-guard writers did not all leave a row — the universal is vacuous"
    for row in r.rows:
        assert row["system"] in dispatched | {""}, \
            f"a row names a system no dispatch did: {row['system']!r}"


def test_the_companion_repeat_guard_still_bounds_a_phantom_rejection_loop(tmp_path):
    ghost = _bad_args(PHANTOM, verb="ghostverb", extra_key="ghostkeyname")
    r = _run(tmp_path, run_id="d855-loop", turns=[ghost, ghost, ghost, DONE])

    rows = _above_guard(r)
    assert len(rows) == 3, "the loop ran past the threshold — the guard stopped counting"
    assert "turned back at seq" in rows[-1]["payload_digest"], "no trip row was written"
    assert rows[-1]["payload_digest"].startswith(
        "exit=64; refused: repeat of request already turned back at seq"), \
        "the trip phrase no longer leads the digest"
    assert "ghostverb" in _model_authored(rows[-1]), \
        "the trip row lost the call's own arguments"
    assert "; rejected: " in rows[-1]["payload_digest"], \
        "the trip row dropped its rejection tail"
    assert "Extra inputs are not permitted" in rows[-1]["payload_digest"], \
        "the trip row's tail no longer names the error type"
    trip_host = _host_authored(rows[-1])
    for text in (PHANTOM, "ghostverb", "ghostkeyname"):
        assert text not in trip_host, \
            f"the trip row's tail put {text!r} in a host-authored column of a coarsened row"
    summary = (r.run_dir / "gather_summaries" / "l-001.md").read_text(encoding="utf-8")
    assert "Treat this lead as incomplete" in summary
    assert PHANTOM not in summary, \
        "the model's own string crossed back into main's context on a refusal path"


# #871: a coarsened row keeps a distinct identity in a digest `system_key` column, without
# loosening any of the negatives above.


def test_three_different_undeclared_systems_are_three_calls_not_one_repeat(tmp_path):
    """The companion guard never ends a lead for a call that differs from its predecessors."""
    rec = VerbRecorder()
    r = _run(tmp_path, run_id="d871-distinct", verbs=elastic_ok(rec), turns=[
        _bad_args("ghostone", verb="ghostverb"), q("ghosttwo", "ghostverb", PARAMS),
        _bad_args("ghostthree", verb="ghostverb"), q("elastic", "query", PARAMS), DONE,
    ])

    rows = _above_guard(r)
    assert len(rows) == 3, "the three rejections did not all leave their rows"
    assert {row["system"] for row in rows} == {""}, "a phantom name reached the table"
    assert [row["exit_code"] for row in r.own_rows] == [64, 64, 64, 0], \
        "the third distinct ghost ended the lead — they are still one repeat group"
    assert len(rec.calls) == 1, "the corrected call never reached the backend"
    assert not _dead_end(r), "the lead was refused for three calls that differ"

    summary = _summary(r)
    for phantom in ("ghostone", "ghosttwo", "ghostthree"):
        assert phantom not in summary, \
            "a model-authored system name crossed into main's context on a refusal path"

    assert any("unresolvable: ghosttwo.ghostverb" in seen for seen in r.gather.seen), \
        "the model never read its own ghost back, so the negatives below are quantified over " \
        "a string this run never produced"
    for row in rows:
        assert _detail(row), \
            "a coarsened row recorded no reason at all"
        assert "ghostverb" in _model_authored(row), \
            "the row lost the call's own arguments, so the negatives below are vacuous"
        host = _host_authored(row)
        for text in ("ghostone", "ghosttwo", "ghostthree", "ghostverb", "bogus_extra_arg"):
            assert text not in host, \
                f"{text!r} — model-authored text — is in a host-authored column of a row " \
                "whose `system` the host deliberately withheld"


def test_the_grant_checks_writer_mints_its_own_identity_too(tmp_path):
    """The grant-check writer, not only the schema writer, mints a distinct identity per ghost."""
    rec = VerbRecorder()
    r = _run(tmp_path, run_id="d871-grantpath", verbs=elastic_ok(rec), turns=[
        q("ghostone", "ghostverb", PARAMS), q("ghosttwo", "ghostverb", PARAMS),
        q("ghostthree", "ghostverb", PARAMS), q("elastic", "query", PARAMS), DONE,
    ])

    rows = _above_guard(r)
    assert len(rows) == 3, "the three grant-path rejections did not all leave their rows"
    assert {row["system"] for row in rows} == {""}, "a phantom name reached the table"
    keys = {row["system_key"] for row in rows}
    assert len(keys) == 3, \
        f"the grant check's writer minted no distinct identities: {keys}"
    assert "" not in keys, \
        "a grant-path rejection was recorded unfingerprinted, so it keys as every other one"
    assert len(rec.calls) == 1, "the corrected call never reached the backend"
    assert not _dead_end(r), \
        "three distinct ghost systems ended the lead through the grant check"

    assert any("unresolvable: ghosttwo.ghostverb" in seen for seen in r.gather.seen), \
        "the refusal the model reads stopped naming the system it asked for"
    for row in rows:
        assert _detail(row), \
            "a coarsened grant-path row recorded no reason at all"
        assert "ghostverb" in _model_authored(row), \
            "the row lost the call's own arguments, so the negative below is vacuous"
        host = _host_authored(row)
        for text in ("ghostone", "ghosttwo", "ghostthree", "ghostverb"):
            assert text not in host, \
                f"the grant check put {text!r} — model-authored text — in a host-authored " \
                "column of a row whose `system` it had just withheld"


def test_one_ghost_keys_the_same_through_both_above_guard_writers(tmp_path):
    """One fingerprint across both placements, so a loop alternating between them still trips."""
    rec = VerbRecorder()
    r = _run(tmp_path, run_id="d871-both-writers", verbs=elastic_ok(rec), turns=[
        _bad_args("ghostone"), q("ghostone", "query", PARAMS), _bad_args("ghostone"),
        q("elastic", "query", PARAMS), DONE,
    ])

    rows = _above_guard(r)
    assert len(rows) == 3, "the loop ran past the threshold — the guard stopped counting"
    assert {row["system_key"] for row in rows} == {
        record_query.system_fingerprint("ghostone", "")}, \
        "the two above-guard writers minted different identities for one ghost"
    assert _dead_end(r), "one ghost through both placements stopped bounding the lead"
    assert _trip_row_written(r), \
        "the lead ended on something other than the guard, so the bound above is not the guard's"
    assert rec.calls == [], "the lead ran on past its dead end"


def test_the_grant_checks_writer_is_still_bounded_on_a_repeat(tmp_path):
    rec = VerbRecorder()
    r = _run(tmp_path, run_id="d871-grantpath-repeat", verbs=elastic_ok(rec), turns=[
        q("ghostone", "query", PARAMS), q("ghostone", "query", PARAMS),
        q("ghostone", "query", PARAMS), q("elastic", "query", PARAMS), DONE,
    ])

    rows = _above_guard(r)
    assert len(rows) == 3, "the loop ran past the threshold — the guard stopped counting"
    assert {row["system_key"] for row in rows} == {
        record_query.system_fingerprint("ghostone", "")}, \
        "one name was recorded under more than one identity, so no repeat can ever be seen"
    assert _dead_end(r), "one ghost named three times no longer bounds the lead"
    assert _trip_row_written(r), \
        "the lead ended, but not on the guard"
    assert rec.calls == [], "the lead ran on past its dead end"
    assert "an undeclared system" in _summary(r), \
        "the grant placement's dead end named a system or called the arguments unreadable"
    assert "ghostone" not in _summary(r), \
        "the model's own string crossed into main's context on a refusal path"


def test_only_a_coarsened_row_carries_a_system_key_and_it_is_a_digest(tmp_path):
    rec = VerbRecorder()
    r = _run(tmp_path, run_id="d871-column", verbs=elastic_ok(rec), turns=[
        _bad_args("ghostone", verb="ghostverb"), _bad_args("ghosttwo", verb="ghostverb"),
        _bad_args("ghostone", verb="ghostverb"),
        _bad_args("elastic", verb="ghostverb"), q("elastic", "query", PARAMS), DONE,
    ])

    own = r.own_rows
    keys = [row["system_key"] for row in own]
    assert len(keys) == 5, "the five calls did not all leave their rows"
    assert all(re.fullmatch(r"[0-9a-f]{64}", k) for k in keys[:3]), \
        f"a coarsened row carries no fixed-length hex digest: {keys[:3]}"
    assert keys[0] == keys[2], "one ghost named twice produced two identities"
    assert keys[0] != keys[1], "two different ghosts produced one identity"
    assert keys[3] == keys[4] == "", \
        "a row that kept its dispatched system was fingerprinted anyway"

    assert keys[0] == record_query.system_fingerprint("ghostone", ""), \
        "the writer derives the digest itself instead of spending the owning function"
    assert record_query.system_fingerprint("elastic", "elastic") == "", \
        "a declared system fingerprints itself, which splits its own count"

    for row in r.rows:
        assert isinstance(row["system_key"], str), \
            "a row's identity is not a string, so `str(...)` at the guard is doing the work"
        if row["system"]:
            assert row["system_key"] == "", \
                f"{row['system']!r} kept its system AND took a fingerprint"
    declared = own[3]
    assert declared["system"] == "elastic", \
        "the control row lost its declared system, so it is not the complementary condition"
    assert declared["system_key"] == "", \
        "the control row was coarsened after all, so it is not the complementary condition"
    assert "bogus_extra_arg" in _host_authored(declared), \
        "a row that kept its system stopped recording the model's own argument name"
    for row in own[:3]:
        assert _detail(row), "a coarsened row recorded no reason at all"
        assert "ghostverb" in _model_authored(row), \
            "the row lost the call's own arguments, so the negatives below are vacuous"
        host = _host_authored(row)
        for text in ("ghostone", "ghosttwo", "ghostverb", "bogus_extra_arg"):
            assert text not in host, \
                f"the fourteenth column's row put {text!r} — model-authored text — in a " \
                "host-authored column of a coarsened row"

    digests = {k for k in keys if k}
    assert digests, "no digest was minted, so the negative below is quantified over nothing"
    assert not any(row["system"] in digests for row in r.rows), \
        "a digest reached the `system` column, which becomes a pitfalls handoff path"


def test_calls_with_no_readable_system_at_all_are_still_one_group(tmp_path):
    """Only a readable string is fingerprinted; a non-string `system` argument has none."""
    blank = _run(tmp_path / "blank", run_id="d871-n5", turns=[
        _bad_args(12345), _bad_args(True), _bad_args({"n": 1}), DONE,
    ])
    readable = _run(tmp_path / "readable", run_id="d871-n5-control", turns=[
        _bad_args("ghostone"), _bad_args("ghosttwo"), _bad_args("ghostthree"), DONE,
    ])

    rows = _above_guard(blank)
    assert len(rows) == 3, "the three rejections did not all leave their rows"
    assert {row["system"] for row in rows} == {""}
    assert {row["system_key"] for row in rows} == {""}, \
        "an unreadable system argument was fingerprinted, so each shape is its own group"
    assert _dead_end(blank), "three unreadable calls are one mistake and no longer bounded"
    assert _trip_row_written(blank), \
        "the lead ended on something other than the guard, so the bound above is not the " \
        "guard's"

    control = {row["system_key"] for row in _above_guard(readable)}
    assert len(control) == 3, \
        f"the control minted no distinct digests either, so `blank`'s says nothing: {control}"
    assert "" not in control, \
        f"a readable ghost went unfingerprinted, so `blank`'s says nothing: {control}"
    assert not _dead_end(readable)


def test_an_invisible_system_string_is_folded_and_never_called_an_undeclared_system(tmp_path):
    """The message and the fold of `names_something_readable` agree at the seam (the fold alone
    is pinned in `test_826_deferred_defects`)."""
    r = _run(tmp_path, run_id="d871-invisible", turns=[
        _bad_args("\u200b"), _bad_args("\ufeff"), _bad_args("\u200b\u200b"), DONE,
    ])

    rows = _above_guard(r)
    assert len(rows) == 3, "the three rejections did not all leave their rows"
    assert {row["system_key"] for row in rows} == {""}, \
        "an invisible system string was fingerprinted, so each is its own group and the loop " \
        "they make is bounded by nothing"
    assert _dead_end(r), "three indistinguishable invisible strings stopped being one mistake"
    assert _trip_row_written(r), \
        "the lead ended on something other than the guard, so the bound above is not the guard's"
    assert "an undeclared system" not in _summary(r), \
        "the dead end told MAIN a system was named when the argument held nothing readable"


def test_a_declared_system_is_never_folded_into_that_group(tmp_path):
    rec = VerbRecorder()
    r = _run(tmp_path, run_id="d855-notfolded", verbs=elastic_ok(rec), turns=[
        _bad_args("ghostone"), _bad_args("ghosttwo"),
        _bad_args("elastic"), q("elastic", "query", PARAMS), DONE,
    ])

    rows = r.own_rows
    assert [row["exit_code"] for row in rows] == [64, 64, 64, 0], \
        "the real system's call was refused by a count only the phantoms earned"
    assert len(rec.calls) == 1, "the corrected call never reached the backend"
    summary = (r.run_dir / "gather_summaries" / "l-001.md").read_text(encoding="utf-8")
    assert "Treat this lead as incomplete" not in summary


def test_no_host_authored_column_of_a_coarsened_row_carries_model_text(tmp_path):
    """On a row whose `system` the host withheld, no host-written column echoes model text (#1016)."""
    rec = VerbRecorder()
    first = _run(tmp_path / "a", run_id="d1016-shapes-a", verbs=elastic_ok(rec), turns=[
        q("ghosttwo", "ghostverb", {"native_query": "FROM one"}),
        q(ZERO_WIDTH, "ghostverb", {"native_query": "FROM two"}),
        _bad_args("ghostone", {"native_query": "FROM three"}, verb="ghostverb"),
        _bad_args("elastic", {"native_query": "FROM control a"}, verb="ghostverb",
                  extra_key="elastickeyname"),
        DONE,
    ])
    # `r` is the run holding the ghost-key shape, so the O2 read of `r.gather.seen` below is a
    # statement about THAT call: `ghostkeyname` is spelled here and nowhere else in this lead.
    r = _run(tmp_path / "b", run_id="d1016-shapes-b", verbs=elastic_ok(rec), turns=[
        _bad_args("ghostone", {"native_query": "FROM four"}, verb="ghostverb",
                  extra_key="ghostkeyname"),
        _bad_args([PHANTOM], {"native_query": "FROM five"}, verb="ghostverb"),
        _bad_args([LONG_GHOST_VALUE], {"native_query": "FROM six"}, verb="ghostverb"),
        _bad_args("elastic", {"native_query": "FROM control b"}, verb="ghostverb",
                  extra_key="elastickeyname"),
        DONE,
    ])

    first_rows, rows = _above_guard(first), _above_guard(r)
    assert len(first_rows) == 4, \
        "the first lead's four shapes did not all leave their rows — its negatives are vacuous"
    assert len(rows) == 4, \
        "the second lead's four shapes did not all leave their rows — its negatives are vacuous"
    # Bind each row to the turn that wrote it, so a per-row negative names a KNOWN call. Read
    # off `params`, a column O1 exempts, which is why it is still readable here at all.
    assert [row["params"]["native_query"] for row in first_rows] == [
        "FROM one", "FROM two", "FROM three", "FROM control a",
    ], "the rows are not the first lead's calls in order — the claims below are misaddressed"
    assert [row["params"]["native_query"] for row in rows] == [
        "FROM four", "FROM five", "FROM six", "FROM control b",
    ], "the rows are not the second lead's calls in order — the claims below are misaddressed"
    for ended in (first, r):
        assert not _dead_end(ended), \
            "a lead ended early: a companion guard tripped or the lead outran its retries"

    coarsened = [*first_rows[:3], *rows[:3]]
    control = first_rows[3]
    assert {row["system"] for row in coarsened} == {""}, \
        "a shape was not coarsened at all"
    ghost_key = record_query.system_fingerprint("ghostone", "")
    assert [row["system_key"] for row in coarsened] == [
        record_query.system_fingerprint("ghosttwo", ""), "", ghost_key, ghost_key, "", "",
    ], "the readable-name fold or the two placements' fingerprints changed"

    for kept in (control, rows[3]):
        assert kept["system"] == "elastic", \
            "a control lost its declared system, so it is not the complementary condition"
        assert kept["system_key"] == "", \
            "a control was coarsened after all, so it is not the complementary condition"
        assert "elastickeyname" in _host_authored(kept), \
            "a row that kept its system stopped recording the model's own argument name"

    assert any("ghostkeyname" in seen for seen in r.gather.seen), \
        "on a coarsened call the model stopped reading back the argument name it got wrong"

    for row in coarsened:
        assert _detail(row), \
            "a coarsened row recorded no reason at all"
        assert "ghostverb" in _model_authored(row), \
            "the row lost the call's own arguments, so the negative below is vacuous"
        assert _raw_command_system(row) == row["system"] == "", \
            f"`raw_command` carries system {_raw_command_system(row)!r}, the row {row['system']!r}"

    for row in coarsened[:2]:
        assert "undeclared" in _detail(row), \
            "a coarsened grant-path row no longer says what kind of failure it withheld"
    for row, template in zip(coarsened[2:], (
        # FROM three — the model's extra argument, under the default ghost key
        "argument: Extra inputs are not permitted",
        # FROM four  — same, under a name the model chose
        "argument: Extra inputs are not permitted",
        # FROM five  — `system` was a list: a DECLARED field, so it is printed as itself
        "system: Input should be a valid string",
        # FROM six   — same, a list pydantic cannot print whole
        "system: Input should be a valid string",
    ), strict=True):
        assert template in _detail(row), \
            f"a coarsened schema-path row no longer reads {template!r}"

    hosts = [_host_authored(row) for row in coarsened]
    leaks = [
        (row["params"]["native_query"], text)
        for row, host in zip(coarsened, hosts, strict=True)
        for text in ("ghostone", "ghosttwo", ZERO_WIDTH, PHANTOM, "ghostlongvalue",
                     "ghostverb", "ghostkeyname", "bogus_extra_arg")
        if text in host
    ]
    assert leaks == [], (
        "model-authored text is in a host-authored column of a row whose `system` the host "
        f"withheld — (call, leaked text): {leaks}"
    )


def test_an_empty_system_argument_is_coarsened_like_every_other(tmp_path):
    """A literal `system=""`: the shape a "did the recorded value differ from what the model
    sent?" predicate gets wrong."""
    rec = VerbRecorder()
    r = _run(tmp_path, run_id="d1016-empty", verbs=elastic_ok(rec), turns=[
        _bad_args("", {"native_query": "FROM one"}, verb="ghostverb",
                  extra_key="ghostkeyname"),
        q("", "ghostverb", {"native_query": "FROM two"}),
        DONE,
    ])

    rows = _above_guard(r)
    assert len(rows) == 2, "the two empty-system rejections did not both leave their rows"
    assert [row["system"] for row in rows] == ["", ""], \
        "an empty system argument stopped being recorded as `''`"
    assert [row["system_key"] for row in rows] == ["", ""], \
        "an empty system argument was fingerprinted"

    assert any("ghostkeyname" in seen for seen in r.gather.seen), \
        "the model stopped reading back the argument name it got wrong"
    assert all("ghostverb" in _model_authored(row) for row in rows), \
        "the rows lost the call's own arguments, so the negative below is vacuous"

    hosts = [_host_authored(row) for row in rows]
    leaks = [
        (row["params"]["native_query"], text)
        for row, host in zip(rows, hosts, strict=True)
        for text in ("ghostverb", "ghostkeyname")
        if text in host
    ]
    assert leaks == [], (
        f"an empty `system` argument put model text in a host-authored column: {leaks}"
    )

    # The row still says something: the host may bound that tail, not empty it.
    schema, grant = rows
    assert "Extra inputs are not permitted" in _detail(schema), \
        "the schema placement stopped naming the error type"
    assert "undeclared" in _detail(grant), \
        "the grant placement stopped saying what KIND of failure it withheld the specifics of"


def test_a_row_that_kept_its_system_records_the_rejection_verbatim(tmp_path):
    """The coarsening does not reach rows that kept their system: they record verbatim (#1016)."""
    rec = VerbRecorder()
    r = _run(tmp_path, run_id="d1016-declared", verbs=elastic_ok(rec), turns=[
        _bad_args("elastic", {"native_query": "FROM one"}),
        q("elastic", "nosuchverb", {"native_query": "FROM two"}),
        DONE,
    ])

    rows = _above_guard(r)
    assert len(rows) == 2, "the two declared-system rejections did not both leave their rows"
    schema, grant = rows
    assert [row["system"] for row in rows] == ["elastic", "elastic"], \
        "a rejection against a declared system lost its attribution"
    assert [row["system_key"] for row in rows] == ["", ""], \
        "a declared system was fingerprinted, so its rows were treated as coarsened"

    assert "Extra inputs are not permitted" in schema["payload_digest"], \
        "the schema placement stopped recording pydantic's own text for a declared system"
    assert "bogus_extra_arg" in schema["payload_digest"], \
        "pydantic's text survived but the offending argument name did not"
    assert "[type=extra_forbidden" in schema["payload_digest"], \
        "pydantic's error type bracket is gone from a declared system's digest"
    assert "input_value=" in schema["payload_digest"], \
        "the failing value is gone from a declared system's digest"
    assert "unresolvable: elastic.nosuchverb" in grant["payload_digest"], \
        "the grant placement stopped recording `decision.refusal` for a declared system"

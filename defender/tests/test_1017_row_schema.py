"""#1017 — the queries row's ONE schema, and the read surface that projects all of it.

Three symptoms with one root: the row's column set was spelled by hand at the writer
(`record_query.append_query_row`), at the second writer (`lead_zero._record_manual_row`), at the
read surface (`lead_repository.QueryRow`) and in the judge's raw dump — so a column added at the
writer reached a reader only when someone remembered each list. `system_key` (#871) reached none
of them, and it is half the rejection guard's identity.

What is pinned here, at the unit level (the driven-run half lives in
`tests/e2e/test_1017_query_row_surface.py`, which imports this module's fixtures):

* **D1 / O6** — `record_query.QUERY_ROW_COLUMNS`, a tuple in writer order, is THE declaration
  of the row's fourteen columns.
* **D2 / O1** — `QueryRow`'s field set is that tuple with `payload_path` read as `raw_ref`; the
  two new columns coerce with `as_str` — `_trip`'s own coercion of `system_key` — so a
  pre-#871 table replays through the surface exactly as it ran; keyword-built fixtures keep
  working.
* **D2 / O2** — `QueryRow.record()` is the row AS READ, not a re-projection of the typed fields.
  C16 is the reason: the surface DERIVES `error_class` from `exit_code` when the key is absent,
  the guard's domain predicate reads it verbatim, and a re-projection would replay a trip the
  run never took.
* **S2** — the model-facing renders that reach the rows (`actor_view`, `render_joined_yaml`,
  and since #1032 the questioner's NAMED projection `questioner_leads`) carry neither new
  column; the questioner's carries exactly the key sets `QUESTIONER_LEAD_KEYS` /
  `QUESTIONER_QUERY_KEYS` spell below (#1032 O1). The rest of #1032's obligations live in
  `tests/test_1032_questioner_leads.py`, which imports this module's fixtures.
* **D3** — the surface refuses a link at a lead file's name and at the table's name, and
  tolerates a lead file nested past the parser's limit, the way the judge's own readers did
  before the reads moved here.
"""
from __future__ import annotations

import dataclasses
import json
import os
from pathlib import Path

import pytest

from defender._io import append_jsonl
from defender._run_paths import RunPaths
from defender._text import as_str
from defender.learning import lead_repository
from defender.learning.lead_repository import QueryRow, load_queries
from defender.runtime.circuit_breaker import AGENT_FIXABLE_ERROR_CLASS
from defender.scripts.gather_tools import record_query
from defender.scripts.gather_tools.record_query import (
    ABOVE_GUARD_QUERY_ID,
    QUERY_ROW_COLUMNS,
    in_rejection_domain,
    rejection_trip,
)
from defender.tests.learning.test_loop import _qr

LEAD = "l-001"

#: The fourteen columns the writer records, IN WRITER ORDER — the order `append_query_row`'s
#: dict literal spells them today and the order every row on disk carries. Spelled here as a
#: literal rather than read off the writer, because a test that recovered the expectation from
#: the code under test could not fail.
EXPECTED_COLUMNS = (
    "lead_id", "seq", "system", "verb", "query_id", "params", "raw_command", "payload_path",
    "exit_code", "error_class", "payload_status", "payload_digest", "payload_sha256",
    "system_key",
)

#: #1032 O1 — the questioner's "joined leads" section, per lead and per query, as EXACT key
#: sets. Spelled as literals for the reason `EXPECTED_COLUMNS` is: an expectation recovered
#: from the render under test could not fail. `payload_digest` is in (D3: it is how a model
#: tells an empty answer from a real one, and two renders already show it); `raw_command`,
#: `raw_ref`/`payload_path`, `payload_sha256`, `system_key`, `orphan` and `sentinels` are OUT.
QUESTIONER_LEAD_KEYS = frozenset({"lead_id", "goal", "what_to_summarize", "provenance", "queries"})
QUESTIONER_QUERY_KEYS = frozenset({
    "seq", "system", "verb", "query_id", "params", "exit_code", "error_class",
    "payload_status", "payload_digest",
})

#: A 64-hex digest shaped exactly like `system_fingerprint`'s answer, but searchable: no real
#: name hashes to it, so its presence anywhere is this fixture's doing and nothing else's.
KEY_MARKER = "c0ffee" * 10 + "abcd"
SHA_MARKER = "5ha256" * 10 + "feed"


def _row(seq: int, **overrides) -> dict:
    """One full fourteen-column row, the shape a real writer leaves — every key present so a
    test that DROPS one is stating something about that key and nothing else."""
    row = {
        "lead_id": LEAD, "seq": seq, "system": "elastic", "verb": "query",
        "query_id": "elastic.ad-hoc", "params": {"native_query": f"FROM logs {seq}"},
        "raw_command": f"elastic query 'native_query=FROM logs {seq}'",
        "payload_path": f"gather_raw/{LEAD}/{seq}.json", "exit_code": 0, "error_class": None,
        "payload_status": "ok", "payload_digest": f"{seq + 10} bytes, 1 line(s)",
        "payload_sha256": SHA_MARKER, "system_key": "",
    }
    row.update(overrides)
    return row


def _searchable_row(seq: int, **overrides) -> dict:
    """`_row` with a DISTINCTIVE value in the two columns `_row` leaves generic: `raw_command`
    (`elastic query '...'`) and `payload_path` (`gather_raw/l-001/0.json`) are satisfiable by
    coincidence as negatives, so a render that leaked either would pass a check for the
    fixture's default bytes. The path marker sits in the LEAD-ID segment, the one part of a
    payload path `_run_paths.contained_payload`'s shape admits free text in, so the marker
    survives into `raw_ref` — the column a model-facing leak of the path would carry."""
    marked = {
        "raw_command": f"RAWCMD_MARKER_{seq}",
        "payload_path": f"gather_raw/l-PAYLOADPATHMARKER{seq}/{seq}.json",
    }
    return _row(seq, **{**marked, **overrides})


def _table(run_dir: Path, rows: list[dict]) -> Path:
    """`rows` written as `run_dir`'s queries table, byte for byte as the writer would leave
    them — through the canonical appender, so a row lacking a key is a row LACKING it on disk
    rather than one the fixture spelled with `None`."""
    path = RunPaths(run_dir).executed_queries
    run_dir.mkdir(parents=True, exist_ok=True)
    append_jsonl(path, rows)
    return path


def _lead_file(run_dir: Path, goal: str = "a goal", *, lead_id: str = LEAD,
               provenance: str | None = None) -> None:
    """`lead_id`'s `.lead.json` under `run_dir`, the shape `claim_lead` writes. `provenance` is
    written only when given, the way the writer leaves it: `load_leads` reads its absence as
    model-authored (`None`), and #1032's tests need both shapes on one table."""
    gather = RunPaths(run_dir).gather_raw
    gather.mkdir(parents=True, exist_ok=True)
    data: dict = {"goal": goal, "what_to_summarize": ["auth events"]}
    if provenance is not None:
        data["provenance"] = provenance
    (gather / f"{lead_id}.lead.json").write_text(json.dumps(data), encoding="utf-8")


# ---------------------------------------------------------------------------------------
# D1 / O6 — one declaration of the row's columns, in writer order
# ---------------------------------------------------------------------------------------


def test_the_writer_declares_the_fourteen_columns_once_in_writer_order():
    """D1/O6 — `record_query.QUERY_ROW_COLUMNS` exists, is a tuple (ordered: a set would let
    two writers agree on the keys and disagree on the row's byte order), and names exactly the
    fourteen columns in the order `append_query_row` writes them.

    Observed failing by: the name missing, or a column added to the writer's dict literal
    without reaching the declaration (the two drift the way #877 and #871 did)."""
    assert isinstance(QUERY_ROW_COLUMNS, tuple), \
        "the column declaration is not ordered, so it cannot pin the row's byte order"
    assert QUERY_ROW_COLUMNS == EXPECTED_COLUMNS, \
        "the writer's declared column set differs from the fourteen columns rows carry"
    assert len(set(QUERY_ROW_COLUMNS)) == 14, "a column is declared twice"


# ---------------------------------------------------------------------------------------
# D2 / O1 — the surface projects every column, with the writer's own coercions
# ---------------------------------------------------------------------------------------


def test_the_surface_projects_every_declared_column_with_payload_path_as_raw_ref():
    """D2/O1 — `QueryRow`'s field set is `QUERY_ROW_COLUMNS` with the ONE recorded derivation:
    `payload_path` is read as the containment-checked `raw_ref`. Bound to the writer's own
    declaration rather than to a second list here, so a fifteenth column reaches this test the
    day the writer declares it.

    Observed failing by: a column present in a written row and absent from `QueryRow` — today
    `system_key` and `payload_sha256`, the two the issue names."""
    # The PUBLIC fields: D2 also keeps the parsed record on the row for `record()`, and a
    # retained record is not a projection of a column — however the implementer stores it, an
    # underscore-prefixed slot is the one shape that says so.
    fields = {f.name for f in dataclasses.fields(QueryRow) if not f.name.startswith("_")}
    expected = (set(QUERY_ROW_COLUMNS) - {"payload_path"}) | {"raw_ref"}
    assert fields == expected, \
        f"QueryRow projects {sorted(fields ^ expected)} differently from the writer's columns"
    # The two columns the issue names, by name: the set arithmetic above would also pass on a
    # surface that dropped a column the writer dropped, so the two that motivated the change
    # are pinned outright.
    assert "system_key" in fields, "the rejection guard's identity half is not on the surface"
    assert "payload_sha256" in fields, "the payload's content identity is not on the surface"
    # `_record` stays off the repr AND off equality (#1032 D4 keeps it so): it is the SOURCE
    # of the typed fields, not a fifteenth column, and two rows read from byte-identical
    # records must compare equal by their columns alone. The two columns #1032 un-flagged are
    # deliberately NOT pinned either way — the repr is no model-facing contract any more.
    flags = {f.name: (f.repr, f.compare) for f in dataclasses.fields(QueryRow)}
    assert flags["_record"] == (False, False), \
        f"_record is on the repr or in equality again: {flags['_record']}"


def test_keyword_built_rows_default_the_two_new_columns_to_empty():
    """D2 — the two new fields default to `""` on the constructor, so keyword-built fixtures
    (`tests/learning/test_loop.py::_qr`, driven here through that very helper) keep working
    and mean the value every declared, executed row stores.

    Observed failing by: `_qr` raising on a missing required argument, or a default other
    than the writer's own empty answer."""
    row = _qr("elastic.ad-hoc")
    assert row.system_key == "", "a keyword-built row is fingerprinted by default"
    assert row.payload_sha256 == "", "a keyword-built row claims a payload identity it has not"


@pytest.mark.parametrize(
    ("shape", "written"),
    [
        ("absent", {}),
        ("none", {"system_key": None, "payload_sha256": None}),
        ("present", {"system_key": KEY_MARKER, "payload_sha256": SHA_MARKER}),
        # Not a string at all: `as_str` answers `""` and the surface must agree — for
        # `system_key` it is the ONE coercion `_trip` applies to both sides of the identity
        # comparison; `payload_sha256` has no guard reader and takes the same coercion by
        # design (its one live reader, `repeat_note`'s `_result_identity`, reads any falsy
        # value as "no identity", and no writer stores anything but the hex digest).
        ("non-string", {"system_key": 123, "payload_sha256": 456}),
    ],
)
def test_the_surface_coerces_the_two_columns_exactly_as_the_guard_does(tmp_path, shape, written):
    """D2/O2 — `system_key` and `payload_sha256` read as `""` when the key is absent (a
    pre-#871 / pre-#877 table) or `None`, and verbatim when present — for `system_key` the
    SAME coercion `record_query._trip` applies (`as_str`) to the stored column before
    comparing it with the live call's key, and for `payload_sha256` the same one by design.
    Asserted AGAINST `as_str` over the raw record rather than against a literal, so the two
    readers cannot drift apart: a surface that read absent as `None` would make a pre-#871 row
    stop matching the `""` the live guard passes.

    Observed failing by: a `QueryRow` whose `system_key` differs from `as_str(rec["system_key"])`
    on any of the four shapes."""
    base = _row(0)
    for key in ("system_key", "payload_sha256"):
        base.pop(key)
    rec = {**base, **written}
    _table(tmp_path, [rec])

    rows = load_queries(tmp_path)
    assert len(rows) == 1, f"the {shape} row was dropped by the surface"
    typed = rows[0]
    assert typed.system_key == as_str(rec.get("system_key")), \
        f"{shape}: the surface's system_key coercion disagrees with the guard's"
    assert typed.payload_sha256 == as_str(rec.get("payload_sha256")), \
        f"{shape}: the surface's payload_sha256 coercion disagrees with the guard's"
    assert type(typed.system_key) is str
    assert type(typed.payload_sha256) is str
    # The positive control on the same address: the present shape reads its marker back, so
    # the three `""` answers above are coercions and not a surface that reads nothing.
    if shape == "present":
        assert typed.system_key == KEY_MARKER
        assert typed.payload_sha256 == SHA_MARKER


# ---------------------------------------------------------------------------------------
# D2 / O2 — `record()` is the row as read, never a re-projection (C16)
# ---------------------------------------------------------------------------------------


def test_record_returns_the_parsed_row_as_read_not_a_reprojection(tmp_path):
    """D2/O2 — `QueryRow.record()` returns the parsed JSON record retained on the row: dict
    equality with the raw line, key for key and value for value, on a row carrying every column,
    on a row LACKING the two new columns (no `""` is invented into the record), and on a row
    whose `error_class` key is absent (no derived class is written back into it).

    A replay built from the surface hands the guard exactly what `record_query.lead_rows` hands
    it live; a re-projection of the typed fields would coerce `None` to `""`, derive
    `error_class`, and turn `raw_ref` back into a string — each a byte the guard did not see.

    Observed failing by: `record()` missing, or any key of the returned dict differing from
    the line on disk."""
    full = _row(0, system_key=KEY_MARKER)
    pre_871 = _row(1)
    for key in ("system_key", "payload_sha256"):
        pre_871.pop(key)
    no_class = _row(2, exit_code=64, payload_status="error", payload_digest="exit=64; x")
    no_class.pop("error_class")
    # NON-CANONICAL BYTES in every column the typed view coerces: a re-projection of the typed
    # fields over the retained dict agrees with the raw line on writer-canonical rows and
    # differs on this one (adversary H6) — the record must be the line, coercions and all.
    odd = _row(3, system=None, verb=7, params="not-a-dict", exit_code="64",
               payload_digest=5, payload_status=None)
    odd["seq"] = "3"
    _table(tmp_path, [full, pre_871, no_class, odd])

    rows = load_queries(tmp_path)
    assert [r.record() for r in rows] == [full, pre_871, no_class, odd], \
        "record() is not the row as read"
    assert (rows[3].seq, rows[3].system, rows[3].params, rows[3].exit_code) == (3, "None", {}, 64), \
        "the typed view stopped coercing — the equality above is then a tautology"
    assert "system_key" not in rows[1].record(), \
        "record() invented the coerced `\"\"` into a pre-#871 row — the guard would then read " \
        "a column the run never wrote"
    assert "error_class" not in rows[2].record(), \
        "record() wrote the surface's DERIVED error_class back into the record"
    # The typed view still coerces and derives — that is O1's job, and it is what makes the
    # equality above a discrimination rather than a tautology.
    assert (rows[1].system_key, rows[1].payload_sha256) == ("", "")
    assert rows[2].error_class == AGENT_FIXABLE_ERROR_CLASS


def test_c16_a_replay_over_records_does_not_trip_where_the_run_did_not(tmp_path):
    """D2/O2, C16 executed — two exit-64 `∅.above-repeat-guard` rows written WITHOUT an
    `error_class` key (a table from before the column existed). The guard's domain predicate
    reads `error_class` verbatim, so live it counted NEITHER and `rejection_trip` over the raw
    dicts answers `None`. The surface DERIVES `agent-fixable` for both — right for a reader,
    wrong as a replay input — so a replay over a re-projection of the typed fields trips at the
    third call where the run ran on.

    Both halves are asserted on one table: the typed `error_class` IS the derived value (the
    positive control — the surface still derives), and `rejection_trip` over `record()`s is
    `None`, byte-for-byte what the live guard answered over `lead_rows`.

    Observed failing by: `record()` returning the typed fields re-projected, on which the
    predicate trips."""
    call = {"system": "", "verb": "query", "params": {"native_query": "FROM logs"}}
    old = [
        _row(seq, query_id=ABOVE_GUARD_QUERY_ID, exit_code=64, payload_status="error",
             payload_digest="exit=64; rejected", **call)
        for seq in (0, 1)
    ]
    for rec in old:
        rec.pop("error_class")
        rec.pop("system_key")
    _table(tmp_path, old)
    raw = record_query.lead_rows(tmp_path, LEAD)
    assert [("error_class" in r) for r in raw] == [False, False], \
        "the fixture did not land as two class-less rows, so the claim below is vacuous"

    rows = load_queries(tmp_path)
    assert [r.error_class for r in rows] == [AGENT_FIXABLE_ERROR_CLASS] * 2, \
        "the surface stopped deriving error_class — the typed view is no longer a reader's view"
    # The re-projection C16 warns against, spelled out so the test says what it refutes: it
    # trips, because the derived class puts both rows into the guard's domain.
    reprojected = [{**r.record(), "error_class": r.error_class} for r in rows]
    assert all(in_rejection_domain(r) for r in reprojected)
    assert rejection_trip(reprojected, LEAD, system_key="", **call) is not None, \
        "the fixture no longer distinguishes a re-projection from the record — rewrite it"

    live = rejection_trip(raw, LEAD, system_key="", **call)
    assert live is None, "the live guard trips on a pre-error_class table — the premise is gone"
    assert rejection_trip([r.record() for r in rows], LEAD, system_key="", **call) == live, \
        "a replay through the surface trips where the live run ran on — record() is a " \
        "re-projection, not the row as read"


# ---------------------------------------------------------------------------------------
# S2 — the model-facing renders the surface owns gain neither column
# ---------------------------------------------------------------------------------------


def test_the_model_facing_renders_emit_neither_new_column(tmp_path):
    """S2, and #1032 O1 — every model-facing render of the rows ENUMERATES its fields:
    `actor_view` / `render_actor_view_yaml`, `render_joined_yaml`, and (since #1032 M1) the
    questioner's `lead_repository.questioner_leads`, driven through the shipped path
    `branch/cli._joined_leads` → `_prompt.titled_section`. Each is checked for the two #1017
    MARKER VALUES and KEY NAMES beside the positive control on the same string (the row's
    `query_id` and its `params` marker DO appear, so an empty render cannot satisfy the
    negatives). The questioner's render, the one that used to stringify each
    `JoinedLead.__dict__` whole (`QueryRow.__repr__` through `json.dumps(default=str)`), is
    held to more — in two forms, because the two catch different failures:

    * KEY-SET EQUALITY on every lead dict and every query dict it returns, against
      `QUESTIONER_LEAD_KEYS` / `QUESTIONER_QUERY_KEYS`: a census of the output, which no marker
      check is. A column added to `QueryRow` tomorrow, or `orphan` / `sentinels` carried along,
      fails here without anyone planting a marker for it.
    * MARKER ABSENCE on the rendered section text, with markers in `raw_command` and
      `payload_path` planted by `_searchable_row` (the fixture's defaults are not distinctive —
      M4's own note), plus the key names the old dump carried (`raw_ref`, `raw_command`,
      `payload_path`, `sentinels`, `orphan`). Never the literal `∅`: `json.dumps` escapes it
      (O3's cold-review finding).

    Observed failing by: `questioner_leads` missing from `lead_repository`; a lead or query dict
    with a key outside its set; or any planted value / old key name in the section text —
    today's `__dict__` dump carries `raw_command`, `raw_ref` (the marker'd path), `sentinels`
    and `orphan`, so the marker half is red on today's code even with the two `repr=False`
    fields still hidden."""
    from defender.learning._prompt import titled_section
    from defender.learning.branch.cli import _joined_leads

    _lead_file(tmp_path, "GOAL_MARKER")
    _table(tmp_path, [
        _searchable_row(0, params={"native_query": "PARAMS_MARKER"}, system_key=KEY_MARKER),
        # A sentinel row, keyed: the one class of row whose `system_key` is non-empty live.
        _searchable_row(1, query_id=ABOVE_GUARD_QUERY_ID, system="", exit_code=64,
                        error_class=AGENT_FIXABLE_ERROR_CLASS, payload_status="error",
                        payload_digest="exit=64; rejected", system_key=KEY_MARKER),
    ])
    # The premise: the SURFACE reads every planted marker, so each negative below refutes a
    # render that leaks the column and not a fixture the reader never carried.
    real = load_queries(tmp_path)[0]
    assert (real.raw_command, real.system_key, real.payload_sha256) == \
        ("RAWCMD_MARKER_0", KEY_MARKER, SHA_MARKER), "the surface lost a planted marker"
    assert str(real.raw_ref).endswith("gather_raw/l-PAYLOADPATHMARKER0/0.json"), \
        f"the path marker did not survive containment into raw_ref: {real.raw_ref!r}"

    renders = {
        "render_joined_yaml": lead_repository.render_joined_yaml(tmp_path),
        "render_actor_view_yaml": lead_repository.render_actor_view_yaml(tmp_path),
        "actor_view": json.dumps(lead_repository.actor_view(tmp_path), default=str),
        "questioner_joined_leads": titled_section(
            "The joined leads at the branch point",
            _joined_leads(tmp_path, lead_repository.questioner_leads),
        ),
    }
    for name, text in renders.items():
        assert "elastic.ad-hoc" in text, f"{name} renders no query at all — its negatives are vacuous"
        assert "PARAMS_MARKER" in text, f"{name} lost the params it is for"
        for needle in (KEY_MARKER, SHA_MARKER, "system_key", "payload_sha256"):
            assert needle not in text, f"{name} now carries {needle!r} to a model"

    # The questioner's section: the wider negative set, beside the third positive control.
    section = renders["questioner_joined_leads"]
    assert "GOAL_MARKER" in section, "the questioner's section lost the lead's goal"
    for needle in (
        "RAWCMD_MARKER_0", "RAWCMD_MARKER_1", "PAYLOADPATHMARKER0", "PAYLOADPATHMARKER1",
        "raw_command", "raw_ref", "payload_path", "sentinels", "orphan",
    ):
        assert needle not in section, f"the questioner's section carries {needle!r} to a model"

    # The census: exactly the enumerated keys, on every lead and every query the render returns.
    leads = lead_repository.questioner_leads(tmp_path)
    assert [lead["lead_id"] for lead in leads] == [LEAD], f"the render returned {leads!r}"
    assert leads[0]["queries"], "the lead's real query is missing — the query census is vacuous"
    for lead in leads:
        assert set(lead) == QUESTIONER_LEAD_KEYS, \
            f"lead {lead['lead_id']!r} carries {sorted(set(lead) ^ QUESTIONER_LEAD_KEYS)}"
        for query in lead["queries"]:
            assert set(query) == QUESTIONER_QUERY_KEYS, \
                f"a query dict carries {sorted(set(query) ^ QUESTIONER_QUERY_KEYS)}"


# ---------------------------------------------------------------------------------------
# D3 — the surface refuses a link at a lead file's name, as the judge's own read did
# ---------------------------------------------------------------------------------------


def test_the_surface_refuses_a_link_at_a_lead_files_name(tmp_path):
    """D3 — the judge's per-lead goal used to be read behind its own `artifact_file` gate; with
    the read moved to the surface (`load_leads`), the surface keeps that posture: a SYMLINK at
    `gather_raw/<lead>.lead.json` pointing at a real lead file elsewhere yields no lead, while
    the same file copied in as a regular file (the positive control) yields its goal. The
    directory gate alone would admit the link's target as this run's own lead.

    Observed failing by: the linked run reporting the planted goal."""
    elsewhere = tmp_path / "elsewhere" / "planted.lead.json"
    elsewhere.parent.mkdir()
    elsewhere.write_text(
        json.dumps({"goal": "PLANTED_GOAL", "what_to_summarize": []}), encoding="utf-8")

    linked = tmp_path / "linked"
    RunPaths(linked).gather_raw.mkdir(parents=True)
    (RunPaths(linked).gather_raw / f"{LEAD}.lead.json").symlink_to(elsewhere)
    assert (RunPaths(linked).gather_raw / f"{LEAD}.lead.json").is_symlink()
    assert lead_repository.load_leads(linked) == {}, "the surface followed a link at a lead's name"
    assert lead_repository.joined(linked) == []

    regular = tmp_path / "regular"
    RunPaths(regular).gather_raw.mkdir(parents=True)
    (RunPaths(regular).gather_raw / f"{LEAD}.lead.json").write_text(
        elsewhere.read_text(encoding="utf-8"), encoding="utf-8")
    assert lead_repository.load_leads(regular)[LEAD]["goal"] == "PLANTED_GOAL"

    # A HARD link is a regular file to an `lstat`, which is why the read goes through
    # `read_guarded` (the open's own `fstat` sees the link count) and not `artifact_file`
    # then a read: the same planted file under a lead's name, as a second name for one inode.
    hard = tmp_path / "hard"
    RunPaths(hard).gather_raw.mkdir(parents=True)
    os.link(elsewhere, RunPaths(hard).gather_raw / f"{LEAD}.lead.json")
    assert lead_repository.load_leads(hard) == {}, "the surface read a hard link at a lead's name"


def test_the_surface_tolerates_a_lead_file_nested_past_the_parsers_limit(tmp_path):
    """D3 — the judge read the lead file through `render.json_mapping`, whose tolerance names
    `RecursionError` beside the decode errors; the surface's `load_leads` keeps that class. A
    `.lead.json` of 200,000 nested lists is a `RuntimeError` out of `json.loads`, which no
    reader of `joined()` catches — one such planted file would otherwise end the judge pass
    for every world of the episode. It reads as no lead, beside a healthy one that still joins.

    Observed failing by: `load_leads` raising `RecursionError`."""
    gather = RunPaths(tmp_path).gather_raw
    gather.mkdir(parents=True)
    (gather / "l-999.lead.json").write_text("[" * 200_000 + "]" * 200_000, encoding="utf-8")
    _lead_file(tmp_path, "a goal beside a bomb")
    leads = lead_repository.load_leads(tmp_path)
    assert set(leads) == {LEAD}, f"the nested file was admitted or the healthy one lost: {leads}"
    assert leads[LEAD]["goal"] == "a goal beside a bomb"
    assert [lead.lead_id for lead in lead_repository.joined(tmp_path)] == [LEAD]


def test_the_surface_refuses_a_link_at_the_tables_name_and_reads_an_absent_table_as_none(tmp_path):
    """D3 — the table's `lstat` gate is the surface's own, not the judge's private check ahead
    of it (which threw the lead files' goals away with the rows): a SYMLINK at
    `executed_queries.jsonl` reads as no rows and ONE unreadable record — the count a table the
    reader could not open already reports, and what the capture priming counts — while an
    ABSENT table (the ordinary "no query landed" shape) reads as no rows and nothing
    unreadable, and the lead files join either way.

    Observed failing by: the linked run's rows, or an absent table counted as unreadable."""
    elsewhere = tmp_path / "elsewhere"
    _table(elsewhere, [_row(0, params={"native_query": "LINKED"})])

    linked = tmp_path / "linked"
    _lead_file(linked, "kept")
    RunPaths(linked).executed_queries.symlink_to(RunPaths(elsewhere).executed_queries)
    assert lead_repository.load_queries_report(linked) == ([], 1), \
        "the surface followed a link at the table's name, or counted it as nothing"
    assert [(lead.lead_id, lead.goal, lead.queries)
            for lead in lead_repository.joined(linked)] == [(LEAD, "kept", [])]

    absent = tmp_path / "absent"
    _lead_file(absent, "kept")
    assert lead_repository.load_queries_report(absent) == ([], 0)
    assert [(lead.lead_id, lead.goal, lead.queries)
            for lead in lead_repository.joined(absent)] == [(LEAD, "kept", [])]

    assert len(lead_repository.load_queries(elsewhere)) == 1, \
        "the positive control's regular table did not read"


# ---------------------------------------------------------------------------------------
# D1 / O6 — the row literal exists ONCE, inside the constructor
# ---------------------------------------------------------------------------------------

#: The modules C1's census names as reaching the queries table (the two writer sites and the
#: two `append_query_row` callers), plus the read surface — every place a row literal could
#: hide beside the constructor.
_ROW_MODULES = (
    "scripts/gather_tools/record_query.py",
    "runtime/lead_zero/_capture.py",
    "runtime/query_tool.py",
    "runtime/tools/_bash.py",
    "learning/lead_repository.py",
)


def _row_literals(source: str) -> list[str | None]:
    """The name of the enclosing function for every dict DISPLAY in `source` whose string
    keys include both `lead_id` and `system_key` — the shape of a hand-spelled row."""
    import ast

    _DEFS = (ast.FunctionDef, ast.AsyncFunctionDef)
    tree = ast.parse(source)
    parents: dict[ast.AST, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node
    found: list[str | None] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Dict):
            continue
        keys = {k.value for k in node.keys if isinstance(k, ast.Constant) and isinstance(k.value, str)}
        if not {"lead_id", "system_key"} <= keys:
            continue
        # BOTH def shapes: the census scans `query_tool.py`, whose writers are `async def`,
        # and an owner the climb walked past reads as a module-level literal (`None`).
        owner = node
        while owner in parents and not isinstance(owner, _DEFS):
            owner = parents[owner]
        found.append(owner.name if isinstance(owner, _DEFS) else None)
    return found


def test_the_row_literal_is_spelled_once_inside_the_constructor():
    """D1/O6 — "every writer builds through it": across the writer census and the surface, the
    ONLY dict display keyed by both `lead_id` and `system_key` is the one inside
    `append_query_row`. A second writer that kept its own fourteen-key literal and merely
    asserted it against `QUERY_ROW_COLUMNS` afterwards (adversary H1) agrees on the day it is
    written and drifts on the day a column is added — which is the class of bug D1 exists to
    end, and one no run-time test can see until the drift happens.

    The positive control is the constructor's own literal: exactly one is found, and it is
    `append_query_row`'s — an oracle finding zero literals would be scanning the wrong shape."""
    root = Path(__file__).resolve().parents[1]
    owners = {
        module: _row_literals((root / module).read_text(encoding="utf-8"))
        for module in _ROW_MODULES
    }
    assert owners["scripts/gather_tools/record_query.py"] == ["append_query_row"], \
        f"the constructor's own literal was not found where expected: {owners}"
    for module, found in owners.items():
        if module == "scripts/gather_tools/record_query.py":
            continue
        assert found == [], \
            f"{module} spells a queries row as its own literal (in {found}) instead of " \
            "building through append_query_row"

"""#1017 — the queries row's ONE schema, and the read surface that projects all of it."""
from __future__ import annotations

from defender.tests.support.shared._fixture_uuid import fixture_uuid

from defender.tests.support.shared.contracts._spec1077 import fixture_run as _writer_run_1165

import dataclasses
import json
import os
from pathlib import Path

import yaml

from defender._io import append_jsonl, read_jsonl_rows
from defender.run_repository import RunPaths
from defender.learning import lead_repository
from defender.learning.lead_repository import QueryRow, load_queries
from defender.runtime.circuit_breaker import AGENT_FIXABLE_ERROR_CLASS
from defender.runtime.record_query import (
    QUERY_ROW_COLUMNS,
    in_rejection_domain,
    rejection_trip,
)
from defender.knowledge._query_rules import ABOVE_GUARD_QUERY_ID

LEAD = "l-001"

EXPECTED_COLUMNS = (
    "lead_id", "seq", "system", "verb", "query_id", "params", "raw_command", "payload_path",
    "exit_code", "error_class", "payload_status", "payload_digest", "payload_sha256",
    "system_key",
)

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
    """One full row in every writer column (`EXPECTED_COLUMNS`), the shape a real writer leaves — every key present so a
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
    """`_row` with a DISTINCTIVE value in the two columns `_row` leaves generic."""
    marked = {
        "raw_command": f"RAWCMD_MARKER_{seq}",
        "payload_path": f"gather_raw/l-PAYLOADPATHMARKER{seq}/{seq}.json",
    }
    return _row(seq, **{**marked, **overrides})


def _inherited_state(source: Path):  # noqa: ANN202 — a `RunState` (#1235: not imported at top)
    """A branch sibling's run state after seeding inherited `source`'s table for `LEAD` — the
    one way a run's state holds rows it did not write (#1235 round 2)."""
    from defender.tests.support.runtime.state._fork_snapshot_plant import recorded_snapshot
    from defender.runtime.run_state import RunState

    sibling = source / fixture_uuid("sibling")
    sibling.mkdir()
    state = RunState(sibling, "r1017-sibling")
    source_run = _writer_run_1165(source)
    snapshot = recorded_snapshot(source_run)
    snapshot.restore_files(source_run, _writer_run_1165(state.run_dir), state)
    return state


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


def test_the_surface_projects_every_declared_column_with_payload_path_as_raw_ref():
    """D2/O1 — `QueryRow`'s field set is `QUERY_ROW_COLUMNS` with the ONE recorded derivation:
    `payload_path` is read as the containment-checked `raw_ref`. Bound to the."""
    fields = {f.name for f in dataclasses.fields(QueryRow) if not f.name.startswith("_")}
    expected = (set(QUERY_ROW_COLUMNS) - {"payload_path"}) | {"raw_ref"}
    assert fields == expected, \
        f"QueryRow projects {sorted(fields ^ expected)} differently from the writer's columns"
    assert "system_key" in fields, "the rejection guard's identity half is not on the surface"
    assert "payload_sha256" in fields, "the payload's content identity is not on the surface"
    flags = {f.name: (f.repr, f.compare) for f in dataclasses.fields(QueryRow)}
    assert flags["_record"] == (False, False), \
        f"_record is on the repr or in equality again: {flags['_record']}"


def test_record_returns_the_parsed_row_as_read_not_a_reprojection(tmp_path):
    """D2/O2 — `QueryRow.record()` returns the parsed JSON record retained on the row: dict equality
    with the raw line, key for key and value for value, on a row carrying every."""
    # #1187 (declared change 1): a run id is a canonical UUID — the folder is fixture_uuid(<label>)
    run_dir = tmp_path / fixture_uuid("run")
    run_dir.mkdir()
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
    _table(run_dir, [full, pre_871, no_class, odd])

    rows = load_queries(run_dir)
    assert [r.record() for r in rows] == [full, pre_871, no_class, odd], \
        "record() is not the row as read"
    state = _inherited_state(run_dir)
    assert json.dumps([r.record() for r in rows]) == json.dumps(state.lead_rows(LEAD)), \
        "record() is not what seeding put on the guard's state from these lines"
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
    `error_class` key (a table from before the column existed). The guard's domain predicate."""
    # #1187 (declared change 1): a run id is a canonical UUID — the folder is fixture_uuid(<label>)
    run_dir = tmp_path / fixture_uuid("run")
    run_dir.mkdir()
    call = {"system": "", "verb": "query", "params": {"native_query": "FROM logs"}}
    old = [
        _row(seq, query_id=ABOVE_GUARD_QUERY_ID, exit_code=64, payload_status="error",
             payload_digest="exit=64; rejected", **call)
        for seq in (0, 1)
    ]
    for rec in old:
        rec.pop("error_class")
        rec.pop("system_key")
    _table(run_dir, old)
    raw = _inherited_state(run_dir).lead_rows(LEAD)
    on_file = [r for r in read_jsonl_rows(RunPaths(run_dir).executed_queries)
               if r.get("lead_id") == LEAD]
    assert json.dumps(raw) == json.dumps(on_file), \
        "seeding put rows other than the file's on the state — the guard reads what it did not see"
    assert [("error_class" in r) for r in raw] == [False, False], \
        "the fixture did not land as two class-less rows, so the claim below is vacuous"

    rows = load_queries(run_dir)
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


def test_the_model_facing_renders_emit_neither_new_column(tmp_path):
    """S2, and #1032 O1 — every model-facing render of the rows ENUMERATES its fields: `actor_view`
    / `render_actor_view_yaml`, `render_joined_yaml`, and (since #1032 M1) the."""
    from defender.learning._prompt import titled_section
    from defender.learning.branch.questioner import UNTRUSTED_TAG
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
            lead_repository.questioner_leads(_joined_leads(tmp_path, lead_repository.joined)),
            salt="test1017", tag=UNTRUSTED_TAG,
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

    censuses = {
        "questioner_leads": (
            lead_repository.questioner_leads(lead_repository.joined(tmp_path)),
            QUESTIONER_LEAD_KEYS, QUESTIONER_QUERY_KEYS),
        "render_joined_yaml": (
            yaml.safe_load(renders["render_joined_yaml"])["leads"],
            frozenset({"lead_id", "goal", "what_to_summarize", "queries"}),
            frozenset({"query_id", "verb", "params", "payload_status", "payload_digest"})),
        "actor_view": (
            lead_repository.actor_view(tmp_path)["leads"],
            frozenset({"lead_id", "queries"}), frozenset({"query_id", "params"})),
    }
    for name, (leads, lead_keys, query_keys) in censuses.items():
        assert [lead["lead_id"] for lead in leads] == [LEAD], f"{name} returned {leads!r}"
        assert leads[0]["queries"], \
            f"{name}: the lead's real query is missing — the query census is vacuous"
        for lead in leads:
            assert set(lead) == lead_keys, \
                f"{name}: lead {lead['lead_id']!r} carries {sorted(set(lead) ^ lead_keys)}"
            for query in lead["queries"]:
                assert set(query) == query_keys, \
                    f"{name}: a query dict carries {sorted(set(query) ^ query_keys)}"


def test_the_surface_refuses_a_link_at_a_lead_files_name(tmp_path):
    """D3 — the judge's per-lead goal used to be read behind its own `artifact_file` gate; with the
    read moved to the surface (`load_leads`), the surface keeps that posture: a."""
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

    hard = tmp_path / "hard"
    RunPaths(hard).gather_raw.mkdir(parents=True)
    os.link(elsewhere, RunPaths(hard).gather_raw / f"{LEAD}.lead.json")
    assert lead_repository.load_leads(hard) == {}, "the surface read a hard link at a lead's name"


def test_the_surface_tolerates_a_lead_file_nested_past_the_parsers_limit(tmp_path):
    """D3 — the judge read the lead file through `render.json_mapping`, whose tolerance names
    `RecursionError` beside the decode errors; the surface's `load_leads` keeps that."""
    gather = RunPaths(tmp_path).gather_raw
    gather.mkdir(parents=True)
    (gather / "l-999.lead.json").write_text("[" * 200_000 + "]" * 200_000, encoding="utf-8")
    _lead_file(tmp_path, "a goal beside a bomb")
    leads = lead_repository.load_leads(tmp_path)
    assert set(leads) == {LEAD}, f"the nested file was admitted or the healthy one lost: {leads}"
    assert leads[LEAD]["goal"] == "a goal beside a bomb"
    assert [lead.lead_id for lead in lead_repository.joined(tmp_path)] == [LEAD]


def test_the_surface_refuses_a_link_at_the_tables_name_and_reads_an_absent_table_as_none(tmp_path):
    """D3 — the table's `lstat` gate is the surface's own, not the judge's private check ahead of it
    (which threw the lead files' goals away with the rows): a SYMLINK at."""
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


_ROW_MODULES = (
    "runtime/record_query.py",
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

"""#841 — a `∅.`-prefixed row is not a query the defender ran, and no agent is told it is.

The sentinel namespace (`record_query.RESERVED_QUERY_ID_PREFIX`, #807/#823) records things
that never reached a system: a repeat the guard refused (`∅.repeat-trip`), a call written
above the guard's own placement (`∅.above-repeat-guard`), a reducer shim that failed
(`∅.bash-shim`). They live in `executed_queries.jsonl` because it is the run's only
append-only surface, and `lead_repository` applied no filter — so every consumer of the
two-table schema received them as executed queries.

The `∅.bash-shim` row is why this is not cosmetic: its `params.command` carries up to
`SHIM_COMMAND_MAX_CHARS` (2000) of MODEL-AUTHORED shell text, and the actor, the oracle and
the judge each received it verbatim, framed as something the defender ran.

THE FIX IS A SPLIT IN THE PROJECTION, not a filter in `load_queries`. A blanket filter at the
reader would have unbuilt #823: `collect_general_failures` reaches these rows through the same
`joined` → `extract_from_joined` path, and the pitfalls residue is exactly where a failed
reduce belongs. So `JoinedLead.queries` holds the queries, `JoinedLead.sentinels` holds the
sentinels, and `JoinedLead.rows` remerges them in the table's own seq order for the two readers
that mean "the table" — the offline extraction and the run-inspection HTML.

Both halves are asserted here. A test that only pinned the exclusions would pass just as well
against a `load_queries` filter that silently deletes the pitfalls input.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from defender.learning import lead_repository as lr
from defender.learning.leads import lead_author, lead_extraction
from defender.learning.pipeline.judge import compare
from defender.learning.pipeline.oracle import sample as oracle_sample
from defender.scripts.gather_tools.record_query import (
    ABOVE_GUARD_QUERY_ID,
    BASH_SHIM_QUERY_ID,
    REPEAT_TRIP_QUERY_ID,
    SHIM_COMMAND_MAX_CHARS,
)

# The model-authored shell text a `∅.bash-shim` row carries in `params.command` — the field
# this issue was raised over. Distinctive enough that any prompt or projection carrying it is
# caught by substring alone.
SHIM_COMMAND = "cat gather_raw/l-001/0.json | defender-sql \"SELECT unnest(hits) FROM data\""


def _lead(run: Path, lead_id: str, goal: str = "trace the write", wts=("auth events",)) -> None:
    gd = run / "gather_raw"
    gd.mkdir(parents=True, exist_ok=True)
    (gd / f"{lead_id}.lead.json").write_text(
        json.dumps({"goal": goal, "what_to_summarize": list(wts)})
    )


def _row(  # noqa: PLR0913 — one parameter per row column a case needs to vary
    run: Path, lead_id: str, seq: int, *, query_id: str, params: dict | None = None,
    system: str = "elastic", verb: str = "query", exit_code: int = 0,
    payload: str = '{"hits": [{"_source": {"user": "svc-backup"}}]}',
) -> None:
    """One payload sidecar + one queries-table row, written the way the run writes them.

    The sidecar always EXISTS: `extract_from_joined` drops any row whose `raw_ref` is not a
    file, so a sentinel row written without one would fall out of the pitfalls path for a
    reason that has nothing to do with this issue."""
    run.mkdir(parents=True, exist_ok=True)
    ld = run / "gather_raw" / lead_id
    ld.mkdir(parents=True, exist_ok=True)
    (ld / f"{seq}.json").write_text(payload)
    rec = {
        "lead_id": lead_id,
        "seq": seq,
        "system": system,
        "verb": verb,
        "query_id": query_id,
        "params": params if params is not None else {"native_query": "FROM logs"},
        "raw_command": "python3 elastic_adapter.py query",
        "payload_path": f"gather_raw/{lead_id}/{seq}.json",
        "exit_code": exit_code,
        "error_class": None if exit_code == 0 else "agent-fixable",
        "payload_status": "ok" if exit_code == 0 else "error",
        "payload_digest": (
            "44 bytes, 1 line(s)" if exit_code == 0
            else f"exit={exit_code}; Binder Error: No function matches unnest(JSON)"
        ),
    }
    with (run / "executed_queries.jsonl").open("a") as fh:
        fh.write(json.dumps(rec) + "\n")


@pytest.fixture
def run(tmp_path) -> Path:
    """One run dir carrying BOTH populations on one lead, plus a lead that is nothing but
    sentinels — the shape that separates "drop the row" from "drop the lead"."""
    run = tmp_path / "d841"
    _lead(run, "l-001")
    _lead(run, "l-002", goal="reduce the envelope")
    _row(run, "l-001", 0, query_id="elastic.auth-events-by-host")
    _row(run, "l-001", 1, query_id="elastic.auth-events-by-host")
    _row(run, "l-001", 2, query_id=REPEAT_TRIP_QUERY_ID, exit_code=64)
    _row(
        run, "l-002", 0, query_id=BASH_SHIM_QUERY_ID, verb="bash", exit_code=1,
        params={"command": SHIM_COMMAND},
        # EMPTY, the way `runtime/tools.py` writes a shim row's sidecar: the file must exist
        # or `extract_from_joined` drops the row, but a failed reduce has no evidence to
        # persist and the shim's stdout is attacker-influenced bytes. A realistic-looking
        # payload here would hide what a consumer that reaches for this path actually gets.
        payload="",
    )
    return run


def _only(leads: list, lead_id: str):
    (jl,) = [j for j in leads if j.lead_id == lead_id]
    return jl


# The projection itself


def test_row_names_itself_by_the_writers_own_predicate():
    """`QueryRow.is_sentinel` delegates to `is_reserved_query_id` — the whole PREFIX, not a
    list of literals restated on the read side. A fourth sentinel must partition on the day
    it is defined, not on the day someone remembers this module."""
    def _q(query_id: str) -> lr.QueryRow:
        return lr.QueryRow(
            lead_id="l-001", seq=0, system="elastic", verb="query", query_id=query_id,
            params={}, raw_command="", exit_code=0, error_class=None,
            payload_status="ok", payload_digest="", raw_ref=None,
        )

    for sentinel in (ABOVE_GUARD_QUERY_ID, BASH_SHIM_QUERY_ID, REPEAT_TRIP_QUERY_ID, "∅.future"):
        assert _q(sentinel).is_sentinel, sentinel
    for real in ("elastic.auth-events-by-host", "ad-hoc", "cmdb.hostname-by-ip", ""):
        assert not _q(real).is_sentinel, real


def test_joined_splits_queries_from_observations_and_remerges_by_seq(run):
    jl = _only(lr.joined(run), "l-001")
    assert [q.seq for q in jl.queries] == [0, 1]
    assert [q.query_id for q in jl.sentinels] == [REPEAT_TRIP_QUERY_ID]
    # `.rows` is the table's own order, which is what `query_index` keys `pitfall_id` on.
    assert [q.seq for q in jl.rows] == [0, 1, 2]


def test_a_lead_whose_only_rows_are_sentinels_still_joins(run):
    """The row is reclassified; the LEAD is not dropped. `l-002` opened, ran nothing, and
    failed a reduce — a fact the pitfalls residue reads and the actor must be able to see the
    shape of ("this lead found nothing"), so it must still appear."""
    jl = _only(lr.joined(run), "l-002")
    assert jl.queries == []
    assert [q.query_id for q in jl.sentinels] == [BASH_SHIM_QUERY_ID]
    assert jl.goal == "reduce the envelope"


def test_load_queries_still_returns_every_row(run):
    """The READER is untouched — the split is in the projection. A filter here is the move
    that would silently unbuild #823, so pin that it was not made."""
    assert [r.query_id for r in lr.load_queries(run)] == [
        "elastic.auth-events-by-host", "elastic.auth-events-by-host",
        REPEAT_TRIP_QUERY_ID, BASH_SHIM_QUERY_ID,
    ]


# The three agents that are told "these are the queries the defender ran"


def test_actor_view_hides_sentinels_and_keeps_the_lead(run):
    view = lr.actor_view(run)
    by_lead = {lead["lead_id"]: lead["queries"] for lead in view["leads"]}
    assert set(by_lead) == {"l-001", "l-002"}, "a lead vanished from the actor's gray-box view"
    assert [q["query_id"] for q in by_lead["l-001"]] == ["elastic.auth-events-by-host"] * 2
    assert by_lead["l-002"] == []
    assert SHIM_COMMAND not in lr.render_actor_view_yaml(run)


def test_oracle_lead_prompt_carries_no_sentinel(run):
    """The oracle is asked to "emit the events the story's activity would produce that surface
    through this lead's queries". For a refusal record there are no such events, and for a
    shim row the "query" is model-authored shell text."""
    prompt = oracle_sample.build_lead_user_prompt(
        _only(lr.joined(run), "l-002"), story="the actor staged an exfil",
        sample_text="(no schema sample)", salt="aabbccddeeff0011",
    )
    assert SHIM_COMMAND not in prompt
    assert BASH_SHIM_QUERY_ID not in prompt
    # `_query_lines`' OWN empty rendering, under the `queries:` heading — asserting a bare
    # "(none)" would pass on the `sample_text` this call supplies, whatever the query block
    # said.
    assert "queries:\n  (none)" in prompt

    l1 = oracle_sample.build_lead_user_prompt(
        _only(lr.joined(run), "l-001"), story="s", sample_text="(no schema sample)",
        salt="aabbccddeeff0011",
    )
    assert REPEAT_TRIP_QUERY_ID not in l1
    assert l1.count("id: elastic.auth-events-by-host") == 2


def test_judge_comparison_carries_no_sentinel(run):
    comparisons = {c.lead_id: c for c in compare.build_comparison(run, companion={})}
    assert set(comparisons) == {"l-001", "l-002"}
    l2 = compare._render_lead_file(comparisons["l-002"], run / "gather_raw")
    assert SHIM_COMMAND not in l2
    assert "(no queries executed for this lead)" in l2
    # ...and the sentinel's payload does not come back through `_payload_paths`' fallback.
    # For a lead with no queries at all that fallback names `gather_raw/{lead}/0.json`, which
    # IS the sentinel's own sidecar — written EMPTY by the runtime — so the lead file would
    # say "no queries executed" and then instruct the judge to ground an absence claim in it.
    assert compare._payload_paths(comparisons["l-002"], run / "gather_raw") == []
    assert str(run / "gather_raw" / "l-002" / "0.json") not in l2
    assert "absence claim must cover" not in l2

    l1 = compare._render_lead_file(comparisons["l-001"], run / "gather_raw")
    assert REPEAT_TRIP_QUERY_ID not in l1
    assert l1.count("elastic.auth-events-by-host") == 2
    # The absence primitive tells the judge an absence claim must cover EVERY payload this
    # lead holds, and then hands it a `defender-sql` line per path. A refusal record's payload
    # is an error string, not evidence to search — listing it makes the instruction unsatisfiable
    # and puts the sentinel's bytes back in front of the judge by another door.
    assert compare._payload_paths(comparisons["l-001"], run / "gather_raw") == [
        str(run / "gather_raw" / "l-001" / "0.json"),
        str(run / "gather_raw" / "l-001" / "1.json"),
    ]


def test_judge_coverage_manifest_carries_no_sentinel(run):
    """`render_joined_yaml` is the judge's `coverage_manifest` (judge/run.py) — the same
    claim about the same run, so it must partition the same way."""
    doc = compare.yaml.safe_load(lr.render_joined_yaml(run))
    ids = [q["query_id"] for lead in doc["leads"] for q in lead["queries"]]
    assert ids == ["elastic.auth-events-by-host"] * 2
    assert SHIM_COMMAND not in lr.render_joined_yaml(run)


def test_sentinel_payload_is_not_offered_as_evidence(run):
    """`first_rendered_payload` walks `.queries`, so neither the judge's evidence column nor
    the oracle's schema skeleton can be drawn from a refusal record's payload."""
    assert lr.first_rendered_payload(
        _only(lr.joined(run), "l-002"), lambda raw: raw,
        unreadable="(unreadable — {error})", missing="(missing)",
    ) == "(missing)"


# ...and the readers that legitimately want every row (#823 must survive intact)


def test_extraction_still_yields_every_row_in_table_order(run):
    extracted = lead_extraction.extract_from_joined(lr.joined(run))
    assert [(e.lead_id, e.query_index, e.query_id) for e in extracted] == [
        ("l-001", 0, "elastic.auth-events-by-host"),
        ("l-001", 1, "elastic.auth-events-by-host"),
        ("l-001", 2, REPEAT_TRIP_QUERY_ID),
        ("l-002", 0, BASH_SHIM_QUERY_ID),
    ]


def test_pitfalls_residue_still_collects_the_shim_row(run):
    """#823's whole point, and the reason the filter is not in `load_queries`: the failed
    reduce reaches the pitfalls curator, which edits the surface the gather subagent reads
    before its next attempt.

    Since #870 M5′ that surface is `skills/gather/defender-sql.md` and the collected row's
    `system` is normalized to `""` at collection — a `defender-sql` mistake is the reducer's,
    not the mistake of whichever system's payload the reduce happened to open."""
    extracted = lead_extraction.extract_from_joined(lr.joined(run))
    pitfalls = lead_extraction.collect_general_failures(extracted, run, catalog=[])
    assert [p["query_id"] for p in pitfalls] == [REPEAT_TRIP_QUERY_ID, BASH_SHIM_QUERY_ID]
    shim = pitfalls[-1]
    assert shim["system"] == ""
    assert shim["pitfall_id"] == f"{run.name}:l-002:0"


def test_build_handoff_no_longer_warns_a_contract_violation_at_a_sentinel(run, caplog, capsys):
    """A sentinel is routed elsewhere BY CONSTRUCTION, so reaching `build_handoff` is not a
    runtime contract violation — and the WARN it emitted per row is noise in the log an
    operator reads to find real catalog drift.

    An empty catalog, so the two REAL rows are unresolvable too: the check narrowed to the
    sentinel namespace, it did not lapse, and one assertion in each direction is what says so.
    """
    extracted = lead_extraction.extract_from_joined(lr.joined(run))
    assert lead_author.build_handoff(run, extracted, catalog=[]) == []
    logged = capsys.readouterr()
    emitted = logged.out + logged.err + caplog.text
    assert REPEAT_TRIP_QUERY_ID not in emitted
    assert BASH_SHIM_QUERY_ID not in emitted
    assert "unresolved query_id='elastic.auth-events-by-host'" in emitted


def test_narration_crosscheck_counts_a_sentinel_row_as_reaching_the_table(run):
    """The crosscheck asks whether the narration and the two tables agree about which leads
    exist. A lead that only tripped the guard IS in the table, so it is not a lead the
    narration failed to write down."""
    cc = lr.narration_crosscheck(run, {"l-001", "l-002"})
    assert cc["missing_from_narration"] == []
    assert cc["queries_without_lead"] == []
    assert cc["leads_without_queries"] == []
    assert cc["ok"]


def test_shim_command_bound_is_the_only_thing_between_the_prompt_and_2000_chars(run):
    """A guard on the guard: the projections above are what keep model-authored shell text out
    of the three prompts, and `SHIM_COMMAND_MAX_CHARS` is what bounds it in the table if a
    fourth consumer ever renders `params` whole. Pin that the bound still exists and that the
    row this test writes sits under it, so the fixture never quietly stops being realistic."""
    assert SHIM_COMMAND_MAX_CHARS == 2000
    assert len(SHIM_COMMAND) < SHIM_COMMAND_MAX_CHARS

"""#1032 — the questioner's "joined leads" section is a NAMED projection, not a `__dict__` dump."""
from __future__ import annotations

from defender.tests._spec1077 import fixture_run

from pathlib import Path
import re

import pytest

from defender.run_repository import RunPaths
from defender.learning import lead_repository
from defender.learning._prompt import titled_section
from defender.learning.branch.cli import _joined_leads
from defender.learning.branch.questioner import UNTRUSTED_TAG
from defender.runtime.circuit_breaker import AGENT_FIXABLE_ERROR_CLASS
from defender.scripts.gather_tools.record_query import append_query_row
from defender._query_rules import (
    ABOVE_GUARD_QUERY_ID,
    BASH_SHIM_QUERY_ID,
    REPEAT_TRIP_QUERY_ID,
    RESERVED_QUERY_ID_PREFIX,
)
from defender.tests import _judge_921 as J
from defender.tests import _triplet_947 as T
from defender.tests.live_oracle_1224 import _spec1224 as S
from defender.tests.test_1017_row_schema import (
    KEY_MARKER,
    LEAD,
    QUESTIONER_LEAD_KEYS,
    QUESTIONER_QUERY_KEYS,
    SHA_MARKER,
    _lead_file,
    _searchable_row,
    _table,
)

#: The section title `questioner._capture_sections` renders the leads under — spelled here
SECTION_TITLE = "The joined leads at the branch point"

#: The frame salt the unit tests render `_section` on. `titled_section` frames the body on the
#: message's salt; the marker checks read the body, so any salt serves.
TEST_SALT = "test1032"


def _section(run_dir: Path) -> str:
    """The questioner's leads section as the launcher assembles it — the launcher's
    best-effort read seam, the render over its answer, the section renderer. Every marker check
    in this file is made here, on the bytes a model would be shown."""
    return titled_section(
        SECTION_TITLE,
        lead_repository.questioner_leads(_joined_leads(run_dir, lead_repository.joined)),
        salt=TEST_SALT, tag=UNTRUSTED_TAG)


def _questioner_leads(run_dir: Path) -> list[dict]:
    """The render over the surface's own read of `run_dir` — the two calls the launcher makes,
    minus its stderr arm."""
    return lead_repository.questioner_leads(lead_repository.joined(run_dir))


def _above_guard_row(seq: int, marker: str, **overrides) -> dict:
    """An above-guard rejection row as `wrap_tool_validate` leaves it (the S2 fixture's shape:
    `system` coarsened to `""`, exit 64, `agent-fixable`, a non-empty `system_key`), with an
    ASCII `params` marker — the witness O3 names, since the `∅` in its `query_id` is escaped to
    `\u2205` by `json.dumps` and would be a vacuous negative."""
    return _searchable_row(
        seq, query_id=ABOVE_GUARD_QUERY_ID, system="", exit_code=64,
        error_class=AGENT_FIXABLE_ERROR_CLASS, payload_status="error",
        payload_digest="exit=64; rejected", system_key=KEY_MARKER,
        params={"native_query": marker}, **overrides,
    )


# O3 / D1 — no sentinel row reaches the questioner


def test_o3_no_sentinel_row_reaches_the_questioners_section(tmp_path):
    """O3/D1 — one lead with a real row and two sentinel rows (an above-guard rejection, and a
    `∅.bash-shim` row written through the REAL writer `append_query_row` exactly as the gather
    bash lane writes it, its model-authored shell text in `params.command`), each row carrying
    its own ASCII marker: the real row's marker is in the section, neither sentinel's is, and
    neither sentinel id's ASCII tail is."""
    _lead_file(tmp_path, "GOAL_MARKER")
    _lead_file(tmp_path, "GOAL_ONLY_TRIPS", lead_id="l-002")
    _table(tmp_path, [
        _searchable_row(0, params={"native_query": "REAL_PARAMS_MARKER"}),
        _above_guard_row(1, "ABOVEGUARD_PARAMS_MARKER"),
        _above_guard_row(0, "ONLYTRIPS_PARAMS_MARKER", lead_id="l-002"),
    ])
    shell = "cat gather_raw/l-001/0.json | SHIM_SHELL_MARKER --unnest"
    # The writer allocates its seq from the run's state (#1235). A run holds rows it did not
    # write only as a branch sibling's inherited prefix, so the hand-written table is handed to
    # the state the way seeding hands it (`inherit_rows`, round 2) — no file is read into it.
    from defender._io import read_jsonl_rows
    from defender.runtime.run_state import RunState

    state = RunState(tmp_path, "r1032-questioner")
    state.inherit_rows(read_jsonl_rows(RunPaths(tmp_path).executed_queries))
    append_query_row(
        state, run=fixture_run(state.run_dir), lead_id=LEAD, system="", verb="bash", system_key="",
        query_id=BASH_SHIM_QUERY_ID, params={"command": shell}, raw_command=shell,
        payload_text="", exit_code=1, payload_status="error",
        payload_digest="exit=1; SHIM_STDERR_MARKER",
    )
    # After the shim took seq 2: the repeat-trip row as the guard writes it — REAL system and
    # verb, the model's params — and a sentinel id nothing spells yet.
    _table(tmp_path, [
        _searchable_row(3, query_id=REPEAT_TRIP_QUERY_ID, exit_code=64,
                        error_class=AGENT_FIXABLE_ERROR_CLASS, payload_status="error",
                        payload_digest="exit=64; repeated",
                        params={"native_query": "REPEATTRIP_PARAMS_MARKER"}),
        _searchable_row(4, query_id=f"{RESERVED_QUERY_ID_PREFIX}future-sentinel",
                        params={"native_query": "FUTURESENTINEL_PARAMS_MARKER"}),
    ])
    by_id = {jl.lead_id: jl for jl in lead_repository.joined(tmp_path)}
    assert ([q.seq for q in by_id[LEAD].queries], [q.seq for q in by_id[LEAD].sentinels]) == \
        ([0], [1, 2, 3, 4]), "the join no longer partitions the fixture as one query and four sentinels"
    assert [q.system for q in by_id[LEAD].sentinels][2:] == ["elastic", "elastic"], \
        "the repeat-trip and future sentinels lost their real system — a `system == \"\"` " \
        "filter would no longer be refuted"
    assert (by_id["l-002"].queries, [q.seq for q in by_id["l-002"].sentinels]) == ([], [0])

    text = _section(tmp_path)
    for kept in ("REAL_PARAMS_MARKER", "GOAL_MARKER", "GOAL_ONLY_TRIPS", "elastic.ad-hoc"):
        assert kept in text, f"the section lost {kept!r} — the negatives below are vacuous"
    for dropped in (
        "ABOVEGUARD_PARAMS_MARKER", "ONLYTRIPS_PARAMS_MARKER", "SHIM_SHELL_MARKER",
        "SHIM_STDERR_MARKER", "REPEATTRIP_PARAMS_MARKER", "FUTURESENTINEL_PARAMS_MARKER",
        "above-repeat-guard", "bash-shim", "repeat-trip", "future-sentinel", "sentinels",
        "RAWCMD_MARKER_0", "RAWCMD_MARKER_1", "PAYLOADPATHMARKER0", "PAYLOADPATHMARKER1",
        "raw_command", "raw_ref", "payload_path", "orphan",
    ):
        assert dropped not in text, f"a sentinel row or an unlisted column reached the questioner: {dropped!r}"

    leads = {lead["lead_id"]: lead for lead in _questioner_leads(tmp_path)}
    assert set(leads) == {LEAD, "l-002"}, f"the render returned {sorted(leads)}"
    for lead in leads.values():
        assert set(lead) == QUESTIONER_LEAD_KEYS, f"lead {lead['lead_id']!r} carries other keys"
        for query in lead["queries"]:
            assert set(query) == QUESTIONER_QUERY_KEYS, \
                f"a query dict carries {sorted(set(query) ^ QUESTIONER_QUERY_KEYS)}"
    assert [(q["seq"], q["params"]) for q in leads[LEAD]["queries"]] == \
        [(0, {"native_query": "REAL_PARAMS_MARKER"})], \
        f"the lead's queries are not its one real row: {leads[LEAD]['queries']!r}"
    assert (leads["l-002"]["goal"], leads["l-002"]["queries"]) == ("GOAL_ONLY_TRIPS", []), \
        "a lead whose only rows are sentinels was dropped, or shown a query it never ran"


# O2 — every joined lead, in joined()'s order, with the fields the questioner needs


def _expected_query(seq: int, params: dict, **overrides) -> dict:
    """The nine-key query dict O1 enumerates, for a `_searchable_row(seq, params=...)` — the
    expected value spelled as a literal, so the equality below is against the design and not
    against the render."""
    return {
        "seq": seq, "system": "elastic", "verb": "query", "query_id": "elastic.ad-hoc",
        "params": params, "exit_code": 0, "error_class": None, "payload_status": "ok",
        "payload_digest": f"DIGEST_MARKER_{seq}", **overrides,
    }


def test_o2_every_joined_lead_reaches_the_questioner_in_joineds_order(tmp_path):
    """O2 — five leads on one table, laid out so `joined()`'s order (ran leads by first-seen row,
    then queryless lead files, then orphans) differs from BOTH the table's order and the lexical
    one: `l-003` has rows but no lead file (an orphan, first in the file), `l-002` and `l-001`
    ran, `l-000` has a lead file and no rows, `l-004` has no file and only a sentinel row (an
    orphan the render must keep with no queries)."""
    _lead_file(tmp_path, "GOAL_A", lead_id="l-001")
    _lead_file(tmp_path, "GOAL_B", lead_id="l-002", provenance="PROVENANCE_MARKER")
    _lead_file(tmp_path, "GOAL_QUERYLESS", lead_id="l-000")
    _table(tmp_path, [
        _searchable_row(0, lead_id="l-003", params={"native_query": "NOFILE_PARAMS_MARKER"},
                        payload_digest="DIGEST_MARKER_0"),
        _searchable_row(0, lead_id="l-002", system="splunk", verb="search",
                        query_id="siem.saved-search", params={"saved": "B0"},
                        error_class="PLANTED_CLASS", payload_status="PLANTED_STATUS",
                        payload_digest="DIGEST_MARKER_0"),
        _searchable_row(2, lead_id="l-001", params={"native_query": "A2"},
                        payload_digest="DIGEST_MARKER_2"),
        _searchable_row(1, lead_id="l-001", params={"native_query": "A1"}, exit_code=64,
                        error_class=AGENT_FIXABLE_ERROR_CLASS, payload_status="error",
                        payload_digest="exit=64; A1_FAILED_MARKER"),
        _above_guard_row(0, "A0_SENTINEL_MARKER", lead_id="l-001"),
        _above_guard_row(0, "NOFILE_SENTINEL_MARKER", lead_id="l-004"),
    ])
    joined_order = [jl.lead_id for jl in lead_repository.joined(tmp_path)]
    assert joined_order == ["l-002", "l-001", "l-000", "l-003", "l-004"], \
        "the fixture no longer distinguishes joined()'s order from the table's or the lexical " \
        "one — rewrite it"
    planted = lead_repository.joined(tmp_path)[0].queries[0]
    assert (planted.exit_code, planted.error_class, planted.payload_status) == \
        (0, "PLANTED_CLASS", "PLANTED_STATUS"), \
        "the surface no longer reads a present error_class / payload_status verbatim — the " \
        "re-derivation negative below is gone"

    expected = [
        {"lead_id": "l-002", "goal": "GOAL_B", "what_to_summarize": ["auth events"],
         "provenance": "PROVENANCE_MARKER",
         "queries": [_expected_query(0, {"saved": "B0"}, system="splunk", verb="search",
                                     query_id="siem.saved-search",
                                     error_class="PLANTED_CLASS",
                                     payload_status="PLANTED_STATUS")]},
        {"lead_id": "l-001", "goal": "GOAL_A", "what_to_summarize": ["auth events"],
         "provenance": None,
         "queries": [
             _expected_query(1, {"native_query": "A1"}, exit_code=64,
                    error_class=AGENT_FIXABLE_ERROR_CLASS, payload_status="error",
                    payload_digest="exit=64; A1_FAILED_MARKER"),
             _expected_query(2, {"native_query": "A2"}),
         ]},
        {"lead_id": "l-000", "goal": "GOAL_QUERYLESS", "what_to_summarize": ["auth events"],
         "provenance": None, "queries": []},
        {"lead_id": "l-003", "goal": None, "what_to_summarize": [], "provenance": None,
         "queries": [_expected_query(0, {"native_query": "NOFILE_PARAMS_MARKER"})]},
        {"lead_id": "l-004", "goal": None, "what_to_summarize": [], "provenance": None,
         "queries": []},
    ]
    leads = _questioner_leads(tmp_path)
    assert [lead["lead_id"] for lead in leads] == joined_order, \
        "the questioner's leads are not in joined()'s order, or a lead is missing"
    assert leads == expected
    # Spelled again as sets so a drift in the literal above cannot pass a key the design does
    # not name: the literal IS the key sets, and this says so.
    assert all(set(lead) == QUESTIONER_LEAD_KEYS for lead in expected)
    assert all(set(q) == QUESTIONER_QUERY_KEYS for lead in expected for q in lead["queries"])

    text = _section(tmp_path)
    for kept in ("NOFILE_PARAMS_MARKER", "PROVENANCE_MARKER", "GOAL_QUERYLESS",
                 "A1_FAILED_MARKER", AGENT_FIXABLE_ERROR_CLASS, "siem.saved-search",
                 "PLANTED_CLASS", "l-004"):
        assert kept in text, f"the section lost {kept!r}"
    for dropped in ("orphan", "A0_SENTINEL_MARKER", "NOFILE_SENTINEL_MARKER"):
        assert dropped not in text, f"{dropped!r} reached the questioner"


# O4a — the read surface absorbs a run dir's content; the shipped path shows what survived


def _nested_bomb(run_dir: Path) -> Path:
    """A queries table whose one row's `params` is a JSON array nested 200,000 deep — the one
    content shape on which `joined()` used to RAISE (`RecursionError` out of `json.loads`, which
    the lead-file reader tolerated and the table's did not), so one planted row ended the judge
    pass, the crosscheck and the capture's priming for the whole run."""
    run_dir.mkdir()
    _lead_file(run_dir, "SURVIVES_THE_BOMB")
    table = RunPaths(run_dir).executed_queries
    depth = 200_000
    nested = "[" * depth + "]" * depth
    table.write_text(f'{{"lead_id": "{LEAD}", "seq": 0, "params": {nested}}}\n', encoding="utf-8")
    return table


def test_o4a_the_surface_absorbs_a_run_dirs_content_and_the_shipped_path_shows_what_survived(
    tmp_path, capsys,
):
    """O4a — `joined()` absorbs a missing run dir, a non-JSON table and a directory at the table's
    path as `[]`, a row nested past `_io.JSON_NESTING_LIMIT` as one skipped row, and a numeric
    column past an `int` (`1e400` decodes to `inf`; `int(inf)` is an `OverflowError`, which no
    arm named) as the column's default — each silently, nothing on stderr — and the shipped path
    over it (`_joined_leads` through `questioner_leads`) shows the questioner exactly what
    survived: nothing for the first three, the bomb's lead with `queries: []`, the overflow's
    row at `seq: 0`."""
    healthy = tmp_path / "healthy"
    _lead_file(healthy, "kept")
    _table(healthy, [_searchable_row(0)])
    shown = lead_repository.questioner_leads(_joined_leads(healthy, lead_repository.joined))
    assert [(lead["lead_id"], len(lead["queries"])) for lead in shown] == [(LEAD, 1)], \
        "the healthy run dir renders no lead — the empties below prove nothing"

    garbage = tmp_path / "garbage"
    garbage.mkdir()
    RunPaths(garbage).executed_queries.write_bytes(b"{not json\n\xff\xfe\x00\n[1, 2]\n")
    dir_at_table = tmp_path / "dir-at-table"
    RunPaths(dir_at_table).executed_queries.mkdir(parents=True)
    shapes = {
        "missing run dir": tmp_path / "never-made",
        "non-JSON table": garbage,
        "directory at the table's path": dir_at_table,
    }
    for label, run_dir in shapes.items():
        assert lead_repository.joined(run_dir) == [], f"the surface stopped absorbing a {label}"
        assert lead_repository.questioner_leads(_joined_leads(run_dir, lead_repository.joined)) \
            == [], f"the shipped path shows the questioner something for a {label}"

    bomb = tmp_path / "bomb"
    _nested_bomb(bomb)
    assert lead_repository.load_queries_report(bomb) == ([], 1), \
        "the nested row was not skipped as the one unreadable record"
    shown = lead_repository.questioner_leads(_joined_leads(bomb, lead_repository.joined))
    assert shown == [{"lead_id": LEAD, "goal": "SURVIVES_THE_BOMB",
                      "what_to_summarize": ["auth events"], "provenance": None,
                      "queries": []}], \
        f"the bomb's lead did not survive its row being skipped: {shown!r}"

    overflow = tmp_path / "overflow"
    _lead_file(overflow, "kept")
    RunPaths(overflow).executed_queries.write_text(
        f'{{"lead_id": "{LEAD}", "seq": 1e400, "exit_code": -1e400, "query_id": "q"}}\n',
        encoding="utf-8")
    shown = lead_repository.questioner_leads(_joined_leads(overflow, lead_repository.joined))
    assert [(q["seq"], q["exit_code"], q["query_id"]) for q in shown[0]["queries"]] == \
        [(0, 0, "q")], f"a numeric column past an int was not defaulted: {shown!r}"
    assert capsys.readouterr().err == "", "the read surface's tolerances are no longer silent"


# O4b — the launcher's read seam: the arm, and the passthrough


# M2 — the launcher hands the questioner the named projection, end to end


@pytest.fixture
def launcher_roots(tmp_path, monkeypatch):
    """Both configured roots inside `tmp_path`, as `test_947_triplet_launcher` sets them for
    every launcher scenario: without them `episode_dir_for` answers about the host's real
    episodes root and the episode is written outside `tmp_path`."""
    monkeypatch.setenv(T.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))


def test_m2_the_launcher_hands_the_questioner_the_named_projection(tmp_path, launcher_roots):
    """M2, and O1/O3 at the shipped surface — the real launcher (`cli.main`, every seam from the
    #1224 harness `_spec1224`, a recording `FakeAgent` as the questioner) over a source run
    whose table holds the harness's primed capture, a real row with markers in `params`,
    `raw_command` and `payload_path`, and an above-guard sentinel with its own `params` marker."""
    # #1224: the launcher's pre-flight replays the source run's captured calls through each
    # world's live oracle, over `_spec1224`'s fixture tenant and estate: one captured call,
    # which the scripted oracle serves unchanged so every fact world calibrates.
    answer = {"rows": [{"user": "alice", "event_id": "e-100", "action": "logon"}]}
    est = S.estate(tmp_path)
    _base, src = S.source_run(
        tmp_path, est, calls=[S.Call("idp", "query", S.query_params("user:alice"), answer)])
    _lead_file(src, "GOAL_MARKER")
    _table(src, [
        _searchable_row(1, params={"index": T.EVENTS_PATTERN,
                                   "native_query": "REAL_PARAMS_MARKER"}),
        _above_guard_row(2, "SENTINEL_PARAMS_MARKER"),
    ])
    questioner = S.questioner_for()
    rc = T.mod("learning.branch.cli").main(
        ["--tenant", src.parent.parent.name, src.name, str(T.BRANCH_MESSAGE_ID),
         *T.retired_continuation_argv()],
        spawn=T.FakeSpawn(), questioner=questioner,
        oracle=S.oracle(then=S.submit(answer, S.EMPTY_CLAIM)).model,
        verifier=S.passing_verifier().model, roster=est.roster(),
        judge=J.FakeJudge(default=J.as_reply_text(J.reply_doc(bucket="none", systems=[]))),
        preflight=S.no_preflight, live_tree=T.source_capture(),
    )
    assert rc == 0, "the episode did not complete cleanly"
    assert questioner.prompts, "the questioner was never called"
    prompt = questioner.prompts[0]
    # Anchored on the title AND its FRAME: the host title line directly followed by a frame
    # open tag is the one frame this section is (#1234 A10: the title is host text outside the
    # frame, the body alone inside it), so host text that happened to mention the title, or a
    # reordered frame, cannot move the slice onto another section and turn every negative
    # vacuous. The slice runs to that frame's own close tag, on the message's salt.
    opened = re.compile(rf"\n## {re.escape(SECTION_TITLE)}\n<run-([^>\n]+)-{UNTRUSTED_TAG}>\n")
    found = list(opened.finditer(prompt))
    assert len(found) == 1, "the leads section does not open exactly one frame"
    salt = found[0].group(1)
    close = f"</run-{salt}-{UNTRUSTED_TAG}>"
    section = prompt[found[0].start():prompt.index(close, found[0].end()) + len(close)]

    # `idp.query` is the primed capture's own query id (the source run's one captured call).
    for kept in ("REAL_PARAMS_MARKER", "GOAL_MARKER", "elastic.ad-hoc", "idp.query",
                 T.EVENTS_PATTERN):
        assert kept in section, f"the questioner was not shown {kept!r} — the negatives are vacuous"
    for dropped in (
        "SENTINEL_PARAMS_MARKER", "RAWCMD_MARKER_1", "RAWCMD_MARKER_2",
        "PAYLOADPATHMARKER1", "PAYLOADPATHMARKER2", KEY_MARKER, SHA_MARKER, str(src),
        "raw_ref", "raw_command", "payload_path", "sentinels", "orphan",
        "system_key", "payload_sha256", "above-repeat-guard",
    ):
        assert dropped not in section, f"the questioner was shown {dropped!r}"
    # The prompt's other sections are not this render's; the value markers are unique to the
    # rows, so their absence from the WHOLE prompt says no second path carried them either.
    for dropped in ("SENTINEL_PARAMS_MARKER", "RAWCMD_MARKER_1", "PAYLOADPATHMARKER1"):
        assert dropped not in prompt, f"{dropped!r} reached the prompt outside the leads section"
    # And the section IS the named projection, not a re-rendering of it: the dicts the render
    # returns for this source, rendered the way `_capture_sections` renders them, are the
    # section byte for byte.
    rendered = titled_section(SECTION_TITLE, _questioner_leads(src), salt=salt, tag=UNTRUSTED_TAG)
    assert section == rendered, \
        "the launcher's section is not the render's own output"

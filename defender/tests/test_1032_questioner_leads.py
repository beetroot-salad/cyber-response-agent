"""#1032 — the questioner's "joined leads" section is a NAMED projection, not a `__dict__` dump.

`branch/cli._joined_leads` used to hand `titled_section` each `JoinedLead.__dict__` whole, so
every `QueryRow` reached the questioner's prompt as its Python `repr` — the raw shell command,
the host's absolute payload path (`raw_ref`), and the lead's SENTINEL rows (repeat-guard trips,
above-guard rejections, `∅.bash-shim` rows carrying model-authored shell text) under a
`sentinels` key — while the `repr=False` markers from fc3a4ac9 hid exactly two columns and
nothing else. The design (issue #1032's last comment) replaces it with a fourth named render,
`lead_repository.questioner_leads`, beside `actor_view` / `render_joined_yaml`. The render is
`project_leads` — the ONE walk from the join to model-facing dicts, shared with
`render_joined_yaml` — with the questioner's column tuples; it takes `joined()`'s answer, not
the run dir, so the launcher reads the two tables ONCE (`_joined_leads(source, joined)`, its
best-effort read seam) and projects the list twice, for the sampler and for this section.

What is pinned here, one test per obligation (the key-set census, O1, lives with the other
renders' S2 check in `tests/test_1017_row_schema.py`, whose fixtures this file imports):

* **O3 / D1** — no sentinel row reaches the section, beside the positive control that the same
  lead's real row does; a lead whose only rows are sentinels is KEPT with no queries.
* **O2** — every lead `joined()` returns arrives, in `joined()`'s order, orphans (rows with no
  lead file) included with `goal: None`; queries in `seq` order; `goal`, `provenance`,
  `what_to_summarize` and the four outcome columns present with their values.
* **O4a** — the read surface absorbs everything a run dir's CONTENT can do — a missing run
  dir, a non-JSON table, a directory at the table's path, and a row nested past the parser's
  limit (the one shape it used to raise on) — silently, and the shipped path over it shows the
  questioner what survived.
* **O4b** — the launcher's read seam returns `[]` and prints its stderr line when the surface
  raises (a host fault, now that content cannot make it), pinned on fakes that record what
  they were handed and raise two different classes; and it is a PASSTHROUGH of the surface's
  own list.
* **M2** — the launcher itself hands the questioner the named projection: driven through
  `cli.main` with the #947 seams, the sentinel's marker and the old dump's columns are absent
  from call 1's prompt and the real row's marker is present.

Every negative is paired with a positive control on the same string or structure. Nothing here
asserts on `QueryRow.__repr__` or on the section's JSON formatting — both are #1032's stated
non-obligations.

RED on today's code: every test but the fake-render half of O4b needs `questioner_leads`
(`AttributeError` on the module attribute); the M2 test is red on ASSERTION alone (it names no
new symbol), because today's dump carries the sentinel's params to the prompt. See each test's
"Observed failing by" for what a naive `__dict__`-shaped render would fail on.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from defender._run_paths import RunPaths
from defender.learning import lead_repository
from defender.learning._prompt import titled_section
from defender.learning.branch.cli import _joined_leads
from defender.learning.branch.questioner import UNTRUSTED_TAG
from defender.runtime.circuit_breaker import AGENT_FIXABLE_ERROR_CLASS
from defender.scripts.gather_tools.record_query import (
    ABOVE_GUARD_QUERY_ID,
    BASH_SHIM_QUERY_ID,
    REPEAT_TRIP_QUERY_ID,
    RESERVED_QUERY_ID_PREFIX,
    append_query_row,
)
from defender.tests import _triplet_947 as T
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
#: because the shipped path is `titled_section(<this>, questioner_leads(_joined_leads(...)))`,
#: and the marker checks below are made on that text, not on the render's return value.
SECTION_TITLE = "The joined leads at the branch point"

#: The stderr line `_joined_leads`'s `except` arm prints, as two fixed halves around the
#: exception's repr. Both halves are asserted, so a rewording that kept "could not join" and
#: dropped what the questioner is then shown would not pass.
LINE_HEAD = "[branch] could not join the source's leads ("
LINE_TAIL = "); the questioner is shown none"


def _section(run_dir: Path) -> str:
    """The questioner's leads section as the launcher assembles it — the launcher's
    best-effort read seam, the render over its answer, the section renderer. Every marker check
    in this file is made here, on the bytes a model would be shown."""
    return titled_section(
        SECTION_TITLE,
        lead_repository.questioner_leads(_joined_leads(run_dir, lead_repository.joined)))


def _questioner_leads(run_dir: Path) -> list[dict]:
    """The render over the surface's own read of `run_dir` — the two calls the launcher makes,
    minus its stderr arm."""
    return lead_repository.questioner_leads(lead_repository.joined(run_dir))


def _above_guard_row(seq: int, marker: str, **overrides) -> dict:
    """An above-guard rejection row as `wrap_tool_validate` leaves it (the S2 fixture's shape:
    `system` coarsened to `""`, exit 64, `agent-fixable`, a non-empty `system_key`), with an
    ASCII `params` marker — the witness O3 names, since the `∅` in its `query_id` is escaped
    to `\\u2205` by `json.dumps` and would be a vacuous negative."""
    return _searchable_row(
        seq, query_id=ABOVE_GUARD_QUERY_ID, system="", exit_code=64,
        error_class=AGENT_FIXABLE_ERROR_CLASS, payload_status="error",
        payload_digest="exit=64; rejected", system_key=KEY_MARKER,
        params={"native_query": marker}, **overrides,
    )


# ---------------------------------------------------------------------------------------
# O3 / D1 — no sentinel row reaches the questioner
# ---------------------------------------------------------------------------------------


def test_o3_no_sentinel_row_reaches_the_questioners_section(tmp_path):
    """O3/D1 — one lead with a real row and two sentinel rows (an above-guard rejection, and a
    `∅.bash-shim` row written through the REAL writer `append_query_row` exactly as the gather
    bash lane writes it, its model-authored shell text in `params.command`), each row carrying
    its own ASCII marker: the real row's marker is in the section, neither sentinel's is, and
    neither sentinel id's ASCII tail is. `questioner_leads` returns that lead with exactly one
    query. Beside it, a second lead whose ONLY row is a sentinel is kept — with its goal and no
    queries — the same decision `actor_view` records: the run did open it.

    Two more sentinel shapes sit on the first lead, and they are what pins the RULE rather
    than the two ids above: a `∅.repeat-trip` row, which the guard writes with the REAL
    `system` and `verb` and the model's own `params` (so a filter on `system == ""` or on the
    two literal tails keeps it), and a synthetic `∅.future-sentinel` id no writer spells today
    — `is_sentinel` is the `∅.` prefix (`is_reserved_query_id`), so a sentinel defined
    tomorrow partitions the day it is defined, and the render must follow the predicate, not
    a list. (The adversary's replay of the tests-only commit greened both filters.)

    The section is also held to O1 here — the key-set census and the `raw_command` /
    `payload_path` marker negatives — because this is the one fixture with a bash-shim row,
    and a render that leaked a column only in a sentinel's presence passed the O1 test's
    fixture untouched.

    The premise is asserted first: the surface partitions the five rows as `queries=[0]`,
    `sentinels=[1, 2, 3, 4]` (C10), so the negatives refute a render that reads `.rows` or
    `.sentinels` and not a fixture the join never held.

    Observed failing by: `questioner_leads` missing; a sentinel's marker in the section text
    (today's `__dict__` dump renders them under `sentinels`, and so would a render over
    `jl.rows` filtered on the two known tails or on an empty `system`); the lead returned
    with more than one query; the sentinel-only lead absent; a query dict with a key outside
    the nine; a `raw_command` / path marker in the section."""
    _lead_file(tmp_path, "GOAL_MARKER")
    _lead_file(tmp_path, "GOAL_ONLY_TRIPS", lead_id="l-002")
    _table(tmp_path, [
        _searchable_row(0, params={"native_query": "REAL_PARAMS_MARKER"}),
        _above_guard_row(1, "ABOVEGUARD_PARAMS_MARKER"),
        _above_guard_row(0, "ONLYTRIPS_PARAMS_MARKER", lead_id="l-002"),
    ])
    shell = "cat gather_raw/l-001/0.json | SHIM_SHELL_MARKER --unnest"
    append_query_row(
        tmp_path, lead_id=LEAD, system="", verb="bash", system_key="",
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


# ---------------------------------------------------------------------------------------
# O2 — every joined lead, in joined()'s order, with the fields the questioner needs
# ---------------------------------------------------------------------------------------


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
    """O2 — five leads on one table, laid out so `joined()`'s order (ran leads by first-seen
    row, then queryless lead files, then orphans) differs from BOTH the table's order and the
    lexical one: `l-003` has rows but no lead file (an orphan, first in the file), `l-002` and
    `l-001` ran, `l-000` has a lead file and no rows, `l-004` has no file and only a sentinel
    row (an orphan the render must keep with no queries). `questioner_leads` is compared WHOLE
    against the literal list of dicts — the orphans with `goal: None`, `what_to_summarize:
    []`, `provenance: None`; `l-002`'s `provenance` carried; queries in seq order; every
    outcome column with its value — and its lead order against `joined()`'s own. Through the
    section, the orphan's params marker, the provenance and the queryless lead's goal are all
    present.

    Every VALUE in the literal is one no constant or derivation reproduces, because the
    adversary's replay of the tests-only commit greened three that did: `l-002`'s row is
    `splunk` / `search` / `splunk.saved-search` (the fixture default is `elastic` / `query` /
    `elastic.ad-hoc` everywhere else, and the id's prefix is NOT the system, so a render
    hardcoding those, or deriving `system` or `verb` from `query_id`, fails here); `l-001`'s real rows sit at seq 1 and 2 BEHIND a sentinel at seq 0
    (so `seq` from `enumerate` fails), written 2-before-1 with the FAILED query FIRST in seq
    order (so a "failures last" sort fails); and `l-002`'s row is exit 0 with a planted
    `error_class` / `payload_status` the surface reads verbatim (so re-deriving either from
    `exit_code` — the C16 re-projection this module's own comments warn about — fails).

    Observed failing by: `questioner_leads` missing; a lead missing (an orphan filtered on
    `goal is None`, a queryless or sentinel-only lead filtered on empty `queries`); the order
    re-sorted; a query dict with a key outside O1's nine or a value off the surface's typed
    field; `error_class` / `payload_status` / `payload_digest` not read by name."""
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


# ---------------------------------------------------------------------------------------
# O4a — the read surface absorbs a run dir's content; the shipped path shows what survived
# ---------------------------------------------------------------------------------------


def _nested_bomb(run_dir: Path) -> Path:
    """A queries table whose one row's `params` is a JSON array nested 200,000 deep — the one
    content shape on which `joined()` used to RAISE (`RecursionError` out of `json.loads`,
    which the lead-file reader tolerated and the table's did not), so one planted row ended
    the judge pass, the crosscheck and the capture's priming for the whole run. A lead file
    sits beside it so the tolerance has something to show: the row is skipped, the lead
    survives with no queries."""
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
    """O4a — `joined()` absorbs a missing run dir, a non-JSON table and a directory at the
    table's path as `[]`, and a row nested past the parser's limit as one skipped row — each
    silently, nothing on stderr — and the shipped path over it (`_joined_leads` through
    `questioner_leads`) shows the questioner exactly what survived: nothing for the first
    three, the bomb's lead with `queries: []` for the fourth. The skipped row is not lost
    to the capture's accounting either: `load_queries_report` counts it as the one record
    that could not become a row. The positive control is a healthy run dir beside them, from
    which the same path returns its one lead with its one query.

    The bomb used to be O4b's premise ("the real primitive raises on this table"); it is the
    tolerance's witness now, so a table reader that stops catching the parser's
    `RecursionError` fails here, and fails as the judge would — one row, no leads shown.

    Observed failing by: `joined` raising or printing on any of the four; the bomb's lead
    missing from the shipped path's answer, or its skipped row not counted."""
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
    assert capsys.readouterr().err == "", "the read surface's tolerances are no longer silent"


# ---------------------------------------------------------------------------------------
# O4b — the launcher's read seam: the arm, and the passthrough
# ---------------------------------------------------------------------------------------


def test_o4b_the_launchers_read_seam_absorbs_a_fault_at_the_read_and_says_so(tmp_path, capsys):
    """O4b — `_joined_leads(source, joined)` on a surface that raises returns `[]` and prints
    the existing stderr line with the exception's repr inside it; on a surface that answers it
    returns that answer and prints nothing (the positive control). The surface is a fake that
    RECORDS what it was handed, so the seam's inbound payload is pinned too: the source run dir
    it was given, unchanged.

    The arm is `except Exception`, not one class: nothing a run dir's CONTENT holds reaches it
    any more (O4a), so what it exists for is the host — an `OSError` off a directory the
    walk is refused on — and a second fake raises a `RuntimeError` through the same seam, so
    an arm narrowed to the one class named here is refuted. And the seam is a PASSTHROUGH:
    handed the real surface it returns that surface's own `JoinedLead` list unchanged, so a
    launcher that had the seam re-render behind it has nowhere to hide.

    Observed failing by: `_joined_leads` propagating, or returning `[]` without the line, or
    calling the surface with something other than the source; the arm narrowed to one class;
    the seam transforming the surface's answer."""
    handed: list[Path] = []

    def surface_that_raises(source):
        handed.append(source)
        raise OSError(13, "Permission denied", str(source))

    assert _joined_leads(tmp_path, surface_that_raises) == []
    err = capsys.readouterr().err
    for part in (LINE_HEAD, "PermissionError(", LINE_TAIL):
        assert part in err, f"the arm's line is missing, reworded, or silent on what raised: {err!r}"
    assert handed == [tmp_path], f"the surface was handed {handed!r}, not the source run dir"

    answer = [lead_repository.JoinedLead(lead_id="L0", goal=None, what_to_summarize=[],
                                         queries=[], orphan=True)]

    def surface_that_answers(source):
        handed.append(source)
        return answer

    assert _joined_leads(tmp_path, surface_that_answers) is answer, \
        "the arm changed the surface's answer on the way through"
    assert handed == [tmp_path, tmp_path]
    assert capsys.readouterr().err == "", "the arm printed on a surface that did not raise"

    def surface_that_raises_differently(source):
        raise RuntimeError("a fault no reader names")

    assert _joined_leads(tmp_path, surface_that_raises_differently) == []
    err = capsys.readouterr().err
    for part in (LINE_HEAD, "RuntimeError(", LINE_TAIL):
        assert part in err, f"the arm does not cover a second fault class: {err!r}"

    healthy = tmp_path / "healthy"
    _lead_file(healthy, "kept")
    _table(healthy, [_searchable_row(0)])
    through = _joined_leads(healthy, lead_repository.joined)
    assert through, "the healthy run dir joined to nothing — the passthrough check is vacuous"
    assert through == lead_repository.joined(healthy), \
        "the seam is not a passthrough — it re-rendered or dropped the join surface's answer"
    assert capsys.readouterr().err == ""


# ---------------------------------------------------------------------------------------
# M2 — the launcher hands the questioner the named projection, end to end
# ---------------------------------------------------------------------------------------


@pytest.fixture
def launcher_roots(tmp_path, monkeypatch):
    """Both configured roots inside `tmp_path`, as `test_947_triplet_launcher` sets them for
    every launcher scenario: without them `episode_dir_for` answers about the host's real
    episodes root and the episode is written outside `tmp_path`."""
    monkeypatch.setenv(T.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))


def test_m2_the_launcher_hands_the_questioner_the_named_projection(tmp_path, launcher_roots):
    """M2, and O1/O3 at the shipped surface — the real launcher (`cli.main`, every seam from
    the #947 harness, a recording `FakeAgent` as the questioner) over a source run whose table
    holds the harness's primed capture, a real row with markers in `params`, `raw_command` and
    `payload_path`, and an above-guard sentinel with its own `params` marker. Call 1's prompt is
    what the questioner was HANDED; its leads section — the one frame whose body OPENS on the
    section title, cut at that frame's close — carries the real row's params marker, the goal
    and the query id, and carries
    NONE of: the sentinel's marker, either row's `raw_command` / `payload_path` marker, the two
    #1017 markers, the source run's absolute host path (today's `raw_ref` shows it three times
    — once per row — and nothing else in the prompt does), or the old dump's key names.

    The unit tests above call `questioner_leads` over `_joined_leads(run_dir, joined)`
    themselves; this is the one test that fails if the render exists and `_author` does not
    hand the questioner its answer.

    Observed failing by: the sentinel's marker, a `raw_command` / path marker, the host path,
    or `raw_ref` / `sentinels` / `orphan` in the section the questioner was handed — today's
    dump carries every one of them; or the real row's marker missing from it."""
    _base, src = T.runs_base(tmp_path)
    _lead_file(src, "GOAL_MARKER")
    _table(src, [
        _searchable_row(1, params={"index": T.EVENTS_PATTERN,
                                   "native_query": "REAL_PARAMS_MARKER"}),
        _above_guard_row(2, "SENTINEL_PARAMS_MARKER"),
    ])
    questioner = T.FakeAgent(T.family_doc(), T.world_doc("b"), T.world_doc("c"))
    rc = T.mod("learning.branch.cli").main(
        [str(src), str(T.BRANCH_MESSAGE_ID), "--continuation-prompt", "go"],
        spawn=T.FakeSpawn(), door=T.FakeDoor(), questioner=questioner,
        adapters=T.FakeAdapters(), invoke=T.FakeAgent(*["same"] * 24),
        preflight=T.no_preflight,
    )
    assert rc == 0, "the episode did not complete cleanly"
    assert questioner.prompts, "the questioner was never called"
    prompt = questioner.prompts[0]
    # Anchored on the FRAME, not the title: the frame open tag whose body's first line is the
    # section title is the one frame this section is (titles go inside frames — the reader
    # contract's own claim), so host text that happened to mention the title, or a reordered
    # frame, cannot move the slice onto another section and turn every negative vacuous.
    opened = f"-{UNTRUSTED_TAG}>\n## {SECTION_TITLE}\n"
    assert prompt.count(opened) == 1, "the leads section does not open exactly one frame"
    start = prompt.index(opened) + len(opened)
    section = f"## {SECTION_TITLE}\n" + prompt[start:prompt.index("</run-", start)]

    for kept in ("REAL_PARAMS_MARKER", "GOAL_MARKER", "elastic.ad-hoc", "elastic.query",
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
    rendered = titled_section(SECTION_TITLE, _questioner_leads(src))
    assert section.rstrip("\n") == rendered.rstrip("\n"), \
        "the launcher's section is not the render's own output"

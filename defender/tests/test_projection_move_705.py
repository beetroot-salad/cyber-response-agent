"""#705 — M8: the projections move off `logger.messages` and onto the store.

R14 freezes the consuming-reader list and sets the bar at CONSUMED-FIELD equivalence, one
demand per reader:

  | reader                              | consumes                          | exception   |
  |-------------------------------------|-----------------------------------|-------------|
  | `run_stats.py`                      | trailing `result`, usage, cost    | none        |
  | `_replay_harness.load_turns_from_trace` | assistant `tool_use` name/input | none      |
  | `visualize_runtime`'s footer check  | mtime + event presence            | none        |
  | `runtime.html`'s six data layers    | event stream incl. `message.id`   | one — the coordinate |

Bit-for-bit was rejected as provably unachievable (X2: `_usage_dict` reshapes usage and
subtracts cache from `input_tokens`; the two `seq` counters disagree), and golden files
were rejected because they would bake the two known-unavoidable divergences in anyway.
**Under R8 the analysis read is not truncated**, which removes the second exception FK12
would otherwise have had to state — so three of the four readers assert equivalence with NO
exception, a materially stronger bar than "equivalent except the coordinate" applied
uniformly. Do not write the blanket tolerance.

`gl1` lives here too: R4 moves `transcript.html` onto the store, so model-authored payload
text — attacker-influenced by construction, per `session_store`'s own access table — reaches
a NEW render path whose HTML escaping is not inherited from the log-derived renderer.
"""
from __future__ import annotations

import html
import json
import subprocess
import sys
from pathlib import Path

from defender.tests._by_path import WORKTREE, load_module

import pytest

from defender.scripts.pricing import usage_cost
from defender.tests._session_store_705 import (
    crafted_html_payload,
    jsonl,
    sql,
    store_factory,
    store_mod,
)
from defender.tests.e2e._replay_harness import (
    GOLDEN,
    ReplayFn,
    Turn,
    drive,
    load_turns_from_trace,
    materialize,
)

pytestmark = pytest.mark.e2e

SALT = "0011223344556677"


def _load_run_stats():
    """`scripts/analytics/run_stats.py` — outside `defender/` AND outside
    `specGraph.codeRoots`, so nothing mechanical checks the demand bound to it."""
    return load_module(WORKTREE / "scripts" / "analytics" / "run_stats.py", name="run_stats_705")


def _driven_run(tmp_path: Path, *, run_id: str, turns=None, text: str = "done"):
    """One real driven run with the store attached, returning (run_dir, store, replay)."""
    run_dir = materialize(tmp_path, GOLDEN)
    inv = (GOLDEN / "investigation.md").read_text()
    rep = (GOLDEN / "report.md").read_text()
    scripted = turns if turns is not None else [
        Turn(tool_calls=[("write_file", {"path": str(run_dir / "investigation.md"),
                                         "content": inv})]),
        Turn(tool_calls=[("write_file", {"path": str(run_dir / "report.md"),
                                         "content": rep})]),
        Turn(text=text),
    ]
    replay = ReplayFn(scripted)
    opened: list = []
    drive(run_dir, run_id=run_id, salt=SALT, main=replay,
          store_factory=store_factory(tmp_path, sink=opened))
    return run_dir, opened[0], replay


def _trace_events(run_dir: Path) -> list[dict]:
    """The projection both render drivers read, straight off disk."""
    return [json.loads(line) for line
            in (run_dir / "tool_trace.jsonl").read_text().splitlines() if line.strip()]


def _log_derived_reference(run_dir: Path) -> dict:
    """The projection's expected consumed fields, computed IN THE TEST from the wire log.

    The wire log's response records carry `_usage_dict`'s already-transformed usage, so this
    is the log-derived column the store-derived projection must match — computed here rather
    than read from a golden, which would bake X2's two known divergences in."""
    records = [r for r in jsonl(run_dir / "llm_requests.jsonl")
               if r.get("kind") == "response" and r.get("agent_id", "main") == "main"]
    keys = ("input_tokens", "output_tokens", "cache_read_input_tokens",
            "cache_creation_input_tokens")
    totals = {k: sum(int((r.get("usage") or {}).get(k, 0) or 0) for r in records)
              for k in keys}
    cost = sum(usage_cost(r.get("model") or "", r.get("usage") or {}) for r in records)
    return {"usage": totals, "total_cost_usd": round(cost, 6), "num_turns": len(records)}


# ==========================================================================
# the negative and its positive control
# ==========================================================================

def test_projections_are_built_from_the_store_not_from_logger_messages(tmp_path):
    """`tool_trace.jsonl` and the HTML pages are produced from the store: deleting the wire
    log before the projection runs changes NOTHING about their content.

    Positive control: `test_the_wire_log_is_still_written_and_still_human_readable`
    (`test_store_driver_705.py`) — the log still exists, so this negative is not passing
    because the log stopped being written. G1 refuted O26's census, and R4 grew M8 to all
    of `runtime.html`'s data layers, so every surface the projection could read from is
    bound here, not just `tool_trace.jsonl`."""
    ss = store_mod()
    run_dir, store, _ = _driven_run(tmp_path, run_id="from-store")
    session_id = sql(store, "SELECT session_id FROM session ORDER BY rowid")[0][0]
    with_log = (run_dir / "tool_trace.jsonl").read_text()
    assert with_log.strip(), "the projection produced nothing to compare"

    (run_dir / "llm_requests.jsonl").unlink()
    observe_mod = __import__("defender.runtime.observe", fromlist=["write_trace"])
    observe_mod.write_trace(run_dir, store=store, session_id=session_id, wall_ms=0.0)
    without_log = (run_dir / "tool_trace.jsonl").read_text()

    def _strip_timings(text: str) -> list[dict]:
        events = [json.loads(line) for line in text.splitlines() if line.strip()]
        for event in events:
            event.pop("duration_ms", None)
            event.pop("duration_api_ms", None)
        return events

    assert _strip_timings(without_log) == _strip_timings(with_log), (
        "the projection changed when the wire log was deleted — it is still reading it")
    assert ss.hydrate(store, session_id, role="analysis"), (
        "the store is where the content came from")


# ==========================================================================
# consumed-field equivalence, one demand per frozen reader
# ==========================================================================

def test_the_moved_projection_preserves_the_usage_transform_and_the_cost(tmp_path):
    """The store-derived projection emits `input_tokens` NET of cache reads and writes,
    under the keys `cache_read_input_tokens` and `cache_creation_input_tokens`, so the
    computed `total_cost_usd` is unchanged from the log-derived projection over the same
    run — INCLUDING a run terminated mid-pair, whose terminal response is present in both.
    Consumed fields: NO exception; the coordinate is not among them.

    X2 measured the transform that would be lost: the payload dump keys usage as
    `input_tokens` / `cache_read_tokens` / `cache_write_tokens` with `input_tokens` the RAW
    total, while `_usage_dict` emits the cache keys separately and returns
    `max(0, input - read - write)` — and `usage_cost` keys on the LATTER. Skip the
    transform and every cost silently changes."""
    run_dir, _store, _replay = _driven_run(tmp_path, run_id="usage")
    expected = _log_derived_reference(run_dir)

    events = [json.loads(line) for line in
              (run_dir / "tool_trace.jsonl").read_text().splitlines() if line.strip()]
    result = [e for e in events if e.get("type") == "result"][-1]

    assert set(result["usage"]) == set(expected["usage"]), result["usage"]
    assert result["usage"] == expected["usage"], (
        f"usage transform lost: {result['usage']} != {expected['usage']}")
    assert result["total_cost_usd"] == expected["total_cost_usd"]
    assert any(v for v in expected["usage"].values()), (
        "the fixture recorded no usage at all — the comparison above would be 0 == 0")


def test_the_moved_projection_preserves_the_trailing_result_event(tmp_path):
    """The projection still ends with a `type:"result"` event carrying `duration_ms`,
    `duration_api_ms`, `total_cost_usd`, `num_turns` and the usage totals, at the same
    values the log-derived projection produces over the same run — on a truncated run as on
    a clean one. Consumed fields: NO exception.

    This is the demand truncation would have broken hardest: all five fields change if the
    terminal response is dropped, and under R5's rejected clause the demand was FALSE as
    written against a correct implementation. `run_stats.load_result` is the reader; it is
    driven here, not merely enumerated."""
    run_stats = _load_run_stats()
    run_dir, _store, _replay = _driven_run(tmp_path, run_id="result-event")
    expected = _log_derived_reference(run_dir)

    result = run_stats.load_result(run_dir)
    assert result is not None, "run_stats found no trailing result event"
    assert set(result) >= {"duration_ms", "duration_api_ms", "total_cost_usd",
                           "num_turns", "usage"}, sorted(result)
    assert result["num_turns"] == expected["num_turns"]
    assert result["usage"] == expected["usage"]
    assert result["total_cost_usd"] == expected["total_cost_usd"]

    events = [json.loads(line) for line in
              (run_dir / "tool_trace.jsonl").read_text().splitlines() if line.strip()]
    assert events[-1]["type"] == "result", "the result event must be TRAILING"


def test_the_moved_projection_still_parses_as_replay_harness_turns(tmp_path):
    """`load_turns_from_trace` parses the moved projection into the same scripted `Turn`s
    it produces from a log-derived trace of the same run — same count, same `tool_use` name
    and input per turn — on a truncated run as on a clean one. Consumed fields: NO
    exception; the coordinate is not a consumed field of this reader.

    The test harness is itself a consumer of the projection's format (X5), so a change here
    silently breaks every replay script in the suite."""
    run_dir, _store, replay = _driven_run(tmp_path, run_id="harness-turns")
    turns = load_turns_from_trace(run_dir / "tool_trace.jsonl")

    assert len(turns) == replay.calls, (
        f"{len(turns)} parsed turns for {replay.calls} model turns")
    scripted_names = [[name for name, _args in t.tool_calls] for t in turns]
    assert scripted_names[0] == ["write_file"], scripted_names
    assert scripted_names[1] == ["write_file"], scripted_names
    assert scripted_names[2] == [], "the final text-only turn must parse as text-only"
    assert turns[0].tool_calls[0][1]["path"].endswith("investigation.md"), (
        "the tool_use INPUT must survive, not only the name")


def test_the_moved_projection_preserves_the_runtime_html_event_stream(tmp_path):
    """`runtime.html`'s data layers render from the store-derived event stream with the same
    events, in the same order, as the log-derived stream — with ONE accepted, tested
    exception: `message.id` takes the re-minted `{session_id}/{agent_id}#{seq}` form.

    R14 records the coordinate change as an accepted difference rather than a silent one,
    and `visualize_runtime`'s footer check (the fourth frozen reader) is driven in the same
    page render: the footer's event-presence check must still find its events."""
    from defender.scripts.visualize import visualize_run

    run_dir, store, replay = _driven_run(tmp_path, run_id="runtime-html")
    session_id = sql(store, "SELECT session_id FROM session ORDER BY rowid")[0][0]

    page = visualize_run.render_runtime_page(run_dir)
    assert page.strip(), "runtime.html rendered empty"

    events = [json.loads(line) for line in
              (run_dir / "tool_trace.jsonl").read_text().splitlines() if line.strip()]
    assistant = [e for e in events if e.get("type") == "assistant"]
    assert len(assistant) == replay.calls

    ids = [e["message"]["id"] for e in assistant]
    assert all(i.startswith(f"{session_id}/") for i in ids), (
        f"the re-minted coordinate must carry the session component; got {ids}")
    assert all("#" in i for i in ids), ids

    rendered = visualize_run.render_and_mirror(run_dir)
    assert any(p.name == "runtime.html" for p in rendered) or (run_dir / "runtime.html").is_file()
    footer_page = (run_dir / "runtime.html").read_text()
    assert "result" in footer_page or str(replay.calls) in footer_page, (
        "visualize_runtime's footer check found no events in the moved projection")


def test_tool_trace_is_written_at_most_once_per_run_id_or_fails_loud_on_a_second_write(tmp_path):
    """`tool_trace.jsonl` is written at most once per `run_id`: a second write under the
    same key either preserves the first projection or fails loud — it never silently
    clobbers it.

    G24 (read) established that `observe.write_trace` uses a TRUNCATING `write_text`, not an
    append, and G7 established a second caller exists in the codebase
    (`experiments/…/run_arms.py:158`, outside this PR's structure). No demand states the
    single-invocation-per-`run_id` cardinality today's code happens to have, so a second
    call under a shared `run_id` would clobber with nothing to catch it."""
    observe_mod = __import__("defender.runtime.observe", fromlist=["write_trace"])
    run_dir, store, _replay = _driven_run(tmp_path, run_id="trace-once")
    session_id = sql(store, "SELECT session_id FROM session ORDER BY rowid")[0][0]
    first = (run_dir / "tool_trace.jsonl").read_text()
    assert first.strip(), "the first projection wrote nothing"

    def _events(text: str) -> int:
        return len([line for line in text.splitlines() if line.strip()])

    try:
        observe_mod.write_trace(run_dir, store=store, session_id=session_id, wall_ms=1.0)
    except FileExistsError:
        return  # failing loud on a second write discharges the demand
    second = (run_dir / "tool_trace.jsonl").read_text()
    assert _events(second) >= _events(first), (
        "the second write silently dropped events from the first")


# ==========================================================================
# gl5 / rp1 — the render surface R4 loaded and every reasoning artifact missed
# ==========================================================================

def test_the_two_render_drivers_under_one_run_id_do_not_clobber_each_other(tmp_path):
    """`render_and_mirror` writes `transcript.html` and `runtime.html` with a truncating
    write under ONE `run_id`, and it has two drivers: `run_common.visualize()`'s subprocess
    and `orchestrate._render_transcript`'s in-process call. Driven in turn over one run dir,
    the second render does not silently replace the first's pages with emptier ones — both
    pages still carry the run's own event content after each driver has run, and the two
    drivers agree on how many assistant events the page shows.

    R2's `unique-key` + `serial` form: drive the writers IN TURN and pin that the second
    `w`-open does not lose the first's real content. The positive control is that each
    driver ALONE lands content — a clobber test over two empty pages passes. This is the
    one identity boundary with a truncating writer that phase D left without a uniqueness
    demand while `message`, `wire_log` and `tool_trace` all got one; the rule could not fire
    because the second driver lived only in an `nl:` evidence string (F2)."""
    from defender import run_common
    from defender.scripts.visualize import visualize_run

    marker = "RENDERED-RUN-MARKER-705-b7c8d9"
    run_dir, store, _replay = _driven_run(tmp_path, run_id="two-drivers", text=marker)
    session_id = sql(store, "SELECT session_id FROM session ORDER BY rowid")[0][0]
    assistant_ids = [e["message"]["id"] for e in _trace_events(run_dir)
                     if e.get("type") == "assistant"]
    assert assistant_ids, "the run produced no projection for either driver to render from"

    def pages() -> dict:
        return {name: (run_dir / name).read_text()
                for name in ("transcript.html", "runtime.html")}

    # driver A — the in-process call `_render_transcript` makes
    visualize_run.render_and_mirror(run_dir)
    after_a = pages()
    for name, page in after_a.items():
        assert marker in page, (
            f"positive control: {name} must carry the run's own final turn, or the "
            f"no-clobber assertions below are satisfied by two empty pages")
    assert all(i in after_a["runtime.html"] for i in assistant_ids), (
        "positive control: runtime.html must show every assistant event of the run")

    # driver B — the subprocess hop `run_common.visualize()` takes, over the SAME run_id
    run_common.visualize(run_dir)
    after_b = pages()
    for name, page in after_b.items():
        assert marker in page, (
            f"{name} was clobbered by the second driver under one run_id — a truncating "
            f"write replaced the first driver's real content with a page that no longer "
            f"carries the run")
    assert all(i in after_b["runtime.html"] for i in assistant_ids), (
        "the second render dropped assistant events the first one showed")

    assert _trace_events(run_dir), "the second render dropped the projection it renders from"
    assert sql(store, "SELECT COUNT(*) FROM message WHERE session_id = ?",
               (session_id,))[0][0] > 0, "the store both drivers read is still populated"


@pytest.mark.parametrize("breakage", ["missing-pointer", "stale-store-path"])
def test_the_visualizer_fails_closed_when_it_cannot_resolve_the_store(tmp_path, breakage):
    """A visualizer that cannot resolve the store FAILS CLOSED: the child process exits
    non-zero, and `run_common.visualize()` surfaces that failure to its caller instead of
    writing it to stderr and returning None. The two real breakages are the two that
    actually occur — a run dir carrying no pointer file, and a pointer naming a store that
    is no longer there.

    Symmetry is the point: `store_append_is_fail_closed` and
    `rg4_store_append_failure_stops_the_run_through_a_handled_exit` demand fail-closed on
    the WRITE side, while `auth:P3` (executed) measured the read side doing the opposite —
    `visualize_run.main()` returns 1, `run_common.visualize()` writes it to stderr, and the
    outer process exits 0 regardless. R4 is what makes that bite: all of `runtime.html`'s
    data layers now come from the store, so the child must open it to render at all, and
    `auth:P8` (executed) found run dirs really are relocated by an allowlist copy that
    carries no pointer. Left as it is, `runtime.html` renders stale or not at all on a run
    the operator believes succeeded, with nothing in the suite to show it. Positive control:
    the same call over an intact run dir returns normally and writes both pages."""
    from defender import run_common

    ss = store_mod()
    run_dir, store, _replay = _driven_run(tmp_path, run_id=f"failclosed-{breakage}")

    # positive control — intact, the wrapper renders both pages and does not raise
    run_common.visualize(run_dir)
    for name in ("transcript.html", "runtime.html"):
        assert (run_dir / name).is_file(), f"{name} was not written on the healthy path"
        (run_dir / name).unlink()

    pointer = run_dir / ss.POINTER_FILENAME
    if breakage == "missing-pointer":
        pointer.unlink()
    else:
        body = json.loads(pointer.read_text())
        Path(body["store_path"]).unlink()
        for suffix in ("-wal", "-shm"):
            Path(str(body["store_path"]) + suffix).unlink(missing_ok=True)
        store.close()

    # the child really exits non-zero — the real script, the real argv, the real broken input
    child = subprocess.run(  # noqa: S603 — the argv run_common.visualize() itself builds
        [sys.executable, str(run_common.VISUALIZE_SCRIPT), str(run_dir)],
        capture_output=True, text=True, encoding="utf-8", check=False)
    assert child.returncode != 0, (
        f"the visualizer exited 0 with an unresolvable store ({breakage}); its stdout was "
        f"{child.stdout!r}")

    # and the wrapper surfaces it rather than swallowing it to stderr
    with pytest.raises(run_common.VisualizeFailed) as raised:
        run_common.visualize(run_dir)
    assert str(run_dir) in str(raised.value), (
        "the surfaced failure must name the run dir it could not render")
    assert not (run_dir / "runtime.html").is_file(), (
        "a failed render must not leave a page behind that a reader would trust")


# ==========================================================================
# gl1 — the store-backed render path's escaping
# ==========================================================================

def test_transcript_html_escapes_message_payload_content_reaching_the_store_backed_render(
        tmp_path):
    """Model-authored payload text that is HTML/script-shaped cannot break out of its
    rendered container on the NEW store-backed render path: the crafted markup appears in
    `transcript.html` — and in `runtime.html`, the other page `render_and_mirror` writes —
    only in escaped form, with no live `<script>` element and no `onerror` attribute
    introduced by the payload.

    R4 moves `transcript.html` onto the store, so payload content the model produced —
    fully attacker-influenced, per `session_store`'s own access table — reaches a path whose
    escaping is NOT inherited from the log-derived renderer (FK17's second open surface,
    R16's escaping demand). The POSITIVE CONTROL is that the crafted text is present at all:
    an escaping assertion over a page that never rendered the payload passes vacuously, and
    the negative binds BOTH pages because both are out-edges of the same render."""
    from defender.scripts.visualize import visualize_run

    payload = crafted_html_payload()
    run_dir = materialize(tmp_path, GOLDEN)
    inv = (GOLDEN / "investigation.md").read_text()
    rep = (GOLDEN / "report.md").read_text()
    replay = ReplayFn([
        Turn(tool_calls=[("write_file", {"path": str(run_dir / "investigation.md"),
                                         "content": inv})]),
        Turn(tool_calls=[("write_file", {"path": str(run_dir / "report.md"),
                                         "content": rep})]),
        Turn(text=payload),
    ])
    opened: list = []
    drive(run_dir, run_id="escaping", salt=SALT, main=replay,
          store_factory=store_factory(tmp_path, sink=opened))

    bodies = "".join(row[0] for row in
                     sql(opened[0], "SELECT payload FROM message_payload"))
    assert "window.__pwned" in bodies, (
        "the crafted payload never reached the store — the fixture, not the renderer, "
        "would be what this test measured")

    visualize_run.render_and_mirror(run_dir)
    for page_name in ("transcript.html", "runtime.html"):
        page = (run_dir / page_name).read_text()
        assert html.escape(payload) in page or "&lt;script&gt;" in page, (
            f"{page_name}: positive control — the payload must be RENDERED, escaped, or "
            f"the absence assertions below are vacuous")
        assert "<script>window.__pwned=1</script>" not in page, (
            f"{page_name}: the crafted script element broke out of its container")
        assert "onerror=alert(1)" not in page, (
            f"{page_name}: the crafted event-handler attribute survived unescaped")

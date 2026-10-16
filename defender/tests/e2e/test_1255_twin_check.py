"""#1255 slice E — the twin check (O5): an arm in the control world cannot be told from the
natural continuation of its source, under two host layouts.

The design's "Twin check (O5)", driven end to end through the composition `run.py` uses for an
arm (`_1255_twin`'s docstring says what is production and what is a seam):

1. a NATURAL run of a scripted model (`run.py <alert> --tenant T`) with an injected run clock;
2. a CONTROL-world arm forked from it at a tool-calling main turn — the gather dispatch, a
   response whose tool answers are not in the history (D1) — and driven through
   `run.py --tenant T --episode <ep> --world a` with the same script from the next turn on;
3. at every model request after the fork (main, the re-run gather lead, the three review
   stages) the full request the provider would be sent, and the files that role's gate admits
   at it (decided per file by `permission.decide_read` over the run's compiled MAIN and
   gather policies), must be the same — only the O4 list is normalised (O1, O5): run-clock
   times inside the window from the natural run's reading R at the branch response to R plus
   a run-length bound, and never running backwards; durations; fresh random ids; the order of
   concurrent work. Every other time is compared exactly;
4. the arm's surfaces carry no arm identity (O2); no run's surfaces carry the host layout (O3);
5. the whole pair runs under TWO host layouts — another data root, another tenant name,
   another checkout path (a copy, in its own interpreter) — and each run kind must compare
   equal across them (O3: host layout is one value on one host, so only a second layout can
   catch a leak of it in a form no scanner anticipates).

Today (base 4b3628ed):
* the driver takes no `clock=` (slice D's seam), so no run is clocked: the run-clock test and
  every comparison test fail on that precondition, naming it (red, D) — the twin never
  compares an unclocked pair, where it could not tell a run-clock time from any other;
* the recording half runs: both layouts record a natural run through `run.main`, compose the
  control episode with the launcher's own steps, and launch the arm through `run.main`
  (`test_1255_twin_recording_half_runs_on_todays_code`, a control);
* the arm is REFUSED at its branch point — `branch.validate` rejects a response whose tool call
  is unanswered (D1 reverses this), so the driver ends it as `truncated_by="store"` before its
  first model request. Every arm-side test fails on that precondition, naming it (red, D1);
* the natural run's own surfaces carry the host layout and its run id (the opening prompt's
  `run_dir:`, the workspace map, the gather dispatch's skill paths, the lessons block's
  realpath, the queries table's `call_id`) — the O3 scan of the natural run reaches its
  assertion and rejects today's behaviour. (The two layouts' natural runs also differ there,
  but that comparison waits on the run clock, as above.)

An authoring probe that branched at the gather's tool RETURN instead (legal today, not D1)
showed the comparison naming, on today's code: the continuation prompt part with its
`run_dir:` block (P4), the arm's run folder name in the invlang shim's corpus walk (O2), and
`lessons_loaded.jsonl` missing from the arm (G7).
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("pydantic_ai")

from defender.tests.e2e import _1255_twin as W  # noqa: E402

pytestmark = pytest.mark.e2e

#: The two layouts: label -> tenant name. Distinct names that occur in no checked-in text, so a
#: hit is the layout's and never a coincidence.
LAYOUTS = {"alpha": "twinalpha", "beta": "twinbeta"}


@pytest.fixture(scope="module")
def twin(tmp_path_factory) -> dict[str, dict[str, Any]]:
    """Both layouts' pairs, each recorded once in its own interpreter over its own copy of the
    checkout, run side by side. A layout whose child produced no recording carries
    `harness_error` instead, which every test reports before anything else."""
    tmp = tmp_path_factory.mktemp("twin1255")
    procs = {label: W.start_layout(tmp, label=label, tenant=tenant)
             for label, tenant in LAYOUTS.items()}
    return {label: W.finish_layout(proc, tmp, label) for label, proc in procs.items()}


def _pair(twin: dict[str, dict[str, Any]], layout: str) -> dict[str, Any]:
    pair = twin[layout]
    assert "harness_error" not in pair, pair.get("harness_error")
    assert pair.get("composition_error") is None, (
        f"layout {layout}: the control episode could not be composed from the natural run: "
        f"{pair['composition_error']}")
    return pair


#: The arms of the twin's episode: the control (launched second, beside a sibling) and the
#: null replicate (launched first, before any sibling exists). Both are the natural
#: continuation of the source.
ARMS = {"arm": "control arm", "sibling": "null replicate arm"}


def _clocked(pair: dict[str, Any], layout: str) -> None:
    """The run clock was injected into every run of the pair, so a comparison can tell a
    run-clock time (forgiven inside its window) from any other (compared exactly). Fails —
    rather than comparing an unclocked pair — while the driver takes no `clock=`."""
    assert pair["meta"]["clock_seam"], (
        f"layout {layout}: `driver.run_investigation` takes no `clock=` (the run clock's "
        "source, slice D) — the twin cannot hold run-clock times to their window")
    for key in ("natural", *ARMS):
        rec = pair.get(key)
        if rec is not None:
            assert rec["clock_injected"], f"layout {layout}: the {key} run was handed no clock"
            assert rec["clock_readings"], (
                f"layout {layout}: the {key} run was handed a clock and never read it")


def _arm_reached_the_model(pair: dict[str, Any], layout: str, which: str = "arm",
                           ) -> dict[str, Any]:
    """The arm, once it has made at least one model request — else the failure names where it
    stopped, so a red here reads as "the arm never ran", never as "nothing differed"."""
    arm = pair[which]
    assert arm is not None, f"layout {layout}: no {ARMS[which]} was launched"
    main = [r for r in arm["requests"] if r["role"] == "main"]
    assert main, (
        f"layout {layout}: the {ARMS[which]} never reached its first model request — run.main "
        f"exit {arm['exit_code']!r}, refusal {arm['refusal']!r}, driver summary "
        f"truncated_by={arm['summary'].get('truncated_by')!r} "
        f"exit_reason={arm['summary'].get('exit_reason')!r}. D1: the branch point is a main "
        f"response that called tools (message {pair['branch_message_id']}); the arm resumes "
        "with no user message and the framework runs those calls against its world")
    return arm


def _streams_after_fork(pair: dict[str, Any]) -> set[tuple[str, str | None]]:
    return set(W.streams(W.after_fork(pair["natural"], W.BRANCH_TURN)))


# ---------------------------------------------------------------------------------------
# Controls: the machinery records what it claims to, on today's code.
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("layout", sorted(LAYOUTS))
def test_1255_twin_recording_half_runs_on_todays_code(twin, layout):
    """O5 control: the recording half works, so the twin's eventual red is "the comparison
    differs", never "the harness broke". Under each layout the natural run went through
    `run.main` to its close — every scripted MAIN turn asked, both gather leads asked twice
    each, all three review stages asked, the run folder's read-scope files snapshotted at each
    request — the control episode was composed from it, and the arm went through `run.main`
    to the driver (which returned its summary), after its null replicate sibling did the same
    into the same container."""
    pair = _pair(twin, layout)
    natural = pair["natural"]
    assert natural["exit_code"] == 0, (natural["exit_code"], natural["refusal"])
    assert natural["summary"].get("truncated_by") is None, natural["summary"]
    assert natural["summary"].get("closed_before_cut") is True, (
        "the natural run never closed — the review stages, the report and the review record "
        f"would be absent from every comparison: {natural['summary']}")
    counts = {key: len(reqs) for key, reqs in W.streams(natural["requests"]).items()}
    assert counts.get(("main", None)) == len(W.main_script()), counts
    assert counts.get(("gather", W.LEAD)) == 2, counts
    assert counts.get(("gather", W.CORRELATION_LEAD)) == 2, counts
    for stage in ("support", "ablation", "composer"):
        assert counts.get((f"review:{stage}", None)) == 1, counts
    # the files each role's gate admits: MAIN's last request sees the run's documents (this
    # is also the guard that the gate still admits the folder the twin snapshots by — a gate
    # answering for another spelling of the path would leave every snapshot empty), never the
    # raw payloads; the lead's last gather request sees its own raw payload
    last = [r for r in natural["requests"] if r["role"] == "main"][-1]
    for name in ("investigation.md", "executed_queries.jsonl", f"gather_summaries/{W.LEAD}.md",
                 "report.md"):
        assert name in last["files"], (name, sorted(last["files"]))
    assert "provenance.json" not in last["files"], "MAIN's gate admits provenance.json"
    assert not any(n.startswith("gather_raw/") for n in last["files"]), (
        "MAIN's gate admits a raw payload", sorted(last["files"]))
    lead_last = [r for r in natural["requests"]
                 if r["role"] == "gather" and r["lead"] == W.LEAD][-1]
    assert f"gather_raw/{W.LEAD}/0.json" in lead_last["files"], sorted(lead_last["files"])
    assert all(not r["files"] for r in natural["requests"] if r["role"].startswith("review:")), (
        "a review stage holds no tool, so no file is in its read scope")
    # what the arm is compared over: main, the re-run lead and the review all fall after the
    # fork in the natural run, so a "no difference" is never over an empty stream
    assert _streams_after_fork(pair) >= {("main", None), ("gather", W.LEAD),
                                         ("review:support", None), ("review:ablation", None),
                                         ("review:composer", None)}
    assert ("gather", W.CORRELATION_LEAD) not in _streams_after_fork(pair), (
        "the correlation lead runs before MAIN's first turn; it must not count as after the fork")
    arm = pair["arm"]
    assert arm is not None, "no arm was launched"
    assert arm["exit_code"] == 0, (arm["exit_code"], arm["refusal"])
    assert "truncated_by" in arm["summary"], (
        f"the arm's run.main never reached the driver: {arm['summary']}")
    assert arm["run_dir"], "the arm's run folder was never made"
    assert arm["run_dir"] != natural["run_dir"]
    # the replicate sibling went first, into the same container: the arm's runs folder holds
    # a sibling, as a production arm's does
    sibling = pair["sibling"]
    assert sibling is not None, "no replicate sibling was launched before the arm"
    assert sibling["exit_code"] == 0, (sibling["exit_code"], sibling["refusal"])
    assert "truncated_by" in sibling["summary"], (
        f"the sibling's run.main never reached the driver: {sibling['summary']}")
    assert sibling["run_dir"], "the sibling's run folder was never made"
    assert sibling["run_dir"] != arm["run_dir"]
    assert Path(sibling["run_dir"]).parent == Path(arm["run_dir"]).parent, (
        "the sibling's run folder is not beside the arm's", sibling["run_dir"], arm["run_dir"])


@pytest.mark.parametrize("layout", sorted(LAYOUTS))
def test_1255_twin_runs_on_the_injected_run_clock(twin, layout):
    """P5, O4, O5: every run of the pair — the natural run, the replicate and the control arm —
    is handed the twin's clock source (`driver.run_investigation(clock=…)`) and reads it; the
    natural run's own run-clock times never run backwards (the order rule the arms are held to
    is one a natural run keeps); and R, the natural run's reading at the branch response, opens
    the window the arms are compared in — a window that holds neither the arm's own clock
    source nor the wall clock, so a time read off either is named."""
    import datetime as dt

    pair = _pair(twin, layout)
    _clocked(pair, layout)
    natural = pair["natural"]
    assert W.clock_order_faults(natural, W.start_window(natural), label="natural") == []
    window = W.branch_window(natural)
    assert window is not None
    readings = [dt.datetime.fromisoformat(t) for t in natural["clock_readings"]]
    assert readings[0] <= window.start < readings[-1], (window, readings[0], readings[-1])
    for outside in (W.ARM_CLOCK_START, dt.datetime.now(dt.UTC)):
        assert not window.holds(outside.isoformat()), (window, outside)


def test_1255_twin_layouts_differ_where_only_the_host_sees_them(twin):
    """O3 control: the two layouts really are two host layouts — another data root, another
    tenant folder, another checkout path — and the host's own records show it (H1: host
    records keep host paths). Without this, "the two layouts compare equal" could hold
    because both ran on one layout."""
    a, b = _pair(twin, "alpha"), _pair(twin, "beta")
    ma, mb = a["meta"], b["meta"]
    for key in ("data_root", "tenant", "defender_dir", "repo_root"):
        assert ma[key] != mb[key], (key, ma[key], mb[key])
    for pair, meta in ((a, ma), (b, mb)):
        assert Path(meta["defender_dir"]).name == "defender"
        assert Path(meta["defender_dir"]).parent == Path(meta["repo_root"])
        assert Path(meta["defender_dir"]).resolve() != W.DEFENDER.resolve(), (
            "a layout ran on this checkout rather than on its own copy")
        # the run folder the host made sits under this layout's data root and tenant
        run_dir = Path(pair["natural"]["run_dir"])
        assert run_dir.is_relative_to(Path(meta["data_root"]) / meta["tenant"]), (
            run_dir, meta)


# ---------------------------------------------------------------------------------------
# O1/O5: the arm is the natural continuation.
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("which", sorted(ARMS))
@pytest.mark.parametrize("layout", sorted(LAYOUTS))
def test_1255_twin_control_arm_is_the_natural_continuation(twin, layout, which):
    """O1, O5 (and D1, P2, P4 as they show to the model): forked at the gather dispatch and
    driven with the same script, an arm makes the same model requests as its source did after
    that point — MAIN's, the re-run gather lead's (D1: re-run, never inherited) and the three
    review stages' — each carrying the same messages, tool results and tool definitions, with
    the same gate-admitted files in its run folder at each request. Only the O4 list is
    normalised — run-clock times inside the natural run's branch window, never running
    backwards; every other difference is named with its channel and first differing content.
    Both arms: the null replicate, launched before any sibling exists, and the control arm,
    launched with the replicate beside it — so a difference only one shows is a sibling's."""
    pair = _pair(twin, layout)
    arm = _arm_reached_the_model(pair, layout, which)
    _clocked(pair, layout)
    diffs = W.compare(pair["natural"], arm)
    assert not diffs, (
        f"layout {layout}: the {ARMS[which]} differs from the natural continuation on "
        f"{len(diffs)} channel(s) after the fork:\n" + "\n".join(f"  - {d}" for d in diffs))


@pytest.mark.parametrize("layout", sorted(LAYOUTS))
def test_1255_twin_arm_surfaces_carry_no_arm_identity(twin, layout):
    """O2: nothing the arm's model reads — its requests, the files in its read scope at each
    request, the corpus — carries the arm's identity: its run id, its source run's id, its
    sibling's run id (the replicate launched first into the same container), the episode id or
    token, or either world token — literally or under an obvious encoding (a digest or
    uuid3/uuid5 of it, its bytes in hex or base64, inside a base64/hex run), which the
    comparison's fresh-id rule would otherwise forgive (R-2). (The fork turn and the one-letter
    world labels cannot be scanned for; equality with the natural continuation covers them.)"""
    pair = _pair(twin, layout)
    arm = _arm_reached_the_model(pair, layout)
    tokens = W.identity_tokens(pair, "arm")
    assert {"source run id", "arm run id", "sibling run id", "episode id",
            "episode token"} <= set(tokens), tokens
    # positive control on the same surfaces: the scan reads the arm's real content
    assert W.scan(arm, {"the lead's own summary": W.LEAD_SUMMARY}), (
        "the arm's surfaces do not carry the re-run lead's summary — the scan below would be "
        "over nothing")
    findings = W.scan(arm, tokens, encoded=True)
    assert not findings, (
        f"layout {layout}: arm identity reaches the arm's model:\n"
        + "\n".join(f"  - {f}" for f in findings))


@pytest.mark.parametrize("kind", ["natural", "arm"])
@pytest.mark.parametrize("layout", sorted(LAYOUTS))
def test_1255_twin_no_host_layout_in_any_model_surface(twin, layout, kind):
    """O3 (and P1's fixed names): no run's model-visible surface — any request, any read-scope
    file at it, the corpus — names the data root, the tenant folder, the checkout path, the
    host user's home, or (for the natural run) its own run folder's name. Scanned for the
    exact values the layout's child process ran with."""
    pair = _pair(twin, layout)
    recording = pair["natural"] if kind == "natural" else _arm_reached_the_model(pair, layout)
    tokens = W.host_tokens(pair["meta"])
    if kind == "natural":
        tokens.update(W.identity_tokens(pair, "natural"))
    assert {"data root", "tenant name", "checkout path"} <= set(tokens), tokens
    # positive control on the same surfaces: the alert's evidence is in them
    assert W.scan(recording, {"the alert's rule": "v2-sshd-success-after-failures"})
    findings = W.scan(recording, tokens)
    assert not findings, (
        f"layout {layout}, {kind} run: the host layout reaches the model:\n"
        + "\n".join(f"  - {f}" for f in findings))


# ---------------------------------------------------------------------------------------
# O3 by equality: two host layouts, one model view.
# ---------------------------------------------------------------------------------------


def test_1255_twin_natural_runs_compare_equal_across_host_layouts(twin):
    """O3, P1: the same natural run under two host layouts — another data root, tenant name
    and checkout path — makes the same model requests with the same read-scope files, from its
    first request on, and reads the same corpus. Only the O4 list is normalised, so a host
    value leaking in any form (a path, a name, a length, a hash of either) shows here even
    where no scanner would look for it."""
    a, b = _pair(twin, "alpha"), _pair(twin, "beta")
    _clocked(a, "alpha")
    _clocked(b, "beta")
    diffs = W.compare_layouts(
        a["natural"], b["natural"], sides=("alpha", "beta"),
        windows=(W.start_window(a["natural"]), W.start_window(b["natural"])))
    assert not diffs, (
        f"the natural run differs between the two host layouts on {len(diffs)} channel(s):\n"
        + "\n".join(f"  - {d}" for d in diffs))


def test_1255_twin_control_arms_compare_equal_across_host_layouts(twin):
    """O3, O2: the control arm under two host layouts makes the same model requests with the
    same read-scope files — the arm's host-side identity (episode folder, container, source
    path) differs between the layouts and must reach neither model."""
    a, b = _pair(twin, "alpha"), _pair(twin, "beta")
    arm_a = _arm_reached_the_model(a, "alpha")
    arm_b = _arm_reached_the_model(b, "beta")
    _clocked(a, "alpha")
    _clocked(b, "beta")
    diffs = W.compare_layouts(
        arm_a, arm_b, sides=("alpha", "beta"),
        windows=(W.branch_window(a["natural"]), W.branch_window(b["natural"])))
    assert not diffs, (
        f"the control arm differs between the two host layouts on {len(diffs)} channel(s):\n"
        + "\n".join(f"  - {d}" for d in diffs))

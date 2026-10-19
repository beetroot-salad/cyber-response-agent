"""Compare natural continuations and control arms under distinct host layouts."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("pydantic_ai")

from defender.tests.e2e import _1255_twin as W  # noqa: E402

pytestmark = pytest.mark.e2e

LAYOUTS = {"alpha": "twinalpha", "beta": "twinbeta"}


@pytest.fixture(scope="module")
def twin(tmp_path_factory) -> dict[str, dict[str, Any]]:
    """Both layouts' pairs, each recorded once in its own interpreter over its own copy of the checkout, run side by side."""
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


ARMS = {"arm": "control arm", "sibling": "null replicate arm"}


def _clocked(pair: dict[str, Any], layout: str) -> None:
    """Every run consumed the required injected clock."""
    for key in ("natural", *ARMS):
        rec = pair.get(key)
        if rec is not None:
            assert rec["clock_readings"], f"layout {layout}: the {key} run never read its clock"


def _arm_reached_the_model(pair: dict[str, Any], layout: str, which: str = "arm",
                           ) -> dict[str, Any]:
    """Require an arm request and report its launch or driver failure otherwise."""
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


@pytest.mark.parametrize("layout", sorted(LAYOUTS))
def test_1255_twin_records_every_role_and_read_scope(twin, layout):
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
    a, b = _pair(twin, "alpha"), _pair(twin, "beta")
    ma, mb = a["meta"], b["meta"]
    for key in ("data_root", "tenant", "defender_dir", "repo_root"):
        assert ma[key] != mb[key], (key, ma[key], mb[key])
    for pair, meta in ((a, ma), (b, mb)):
        assert Path(meta["defender_dir"]).name == "defender"
        assert Path(meta["defender_dir"]).parent == Path(meta["repo_root"])
        assert Path(meta["defender_dir"]).resolve() != W.DEFENDER.resolve(), (
            "a layout ran on this checkout rather than on its own copy")
        run_dir = Path(pair["natural"]["run_dir"])
        assert run_dir.is_relative_to(Path(meta["data_root"]) / meta["tenant"]), (
            run_dir, meta)


@pytest.mark.parametrize("which", sorted(ARMS))
@pytest.mark.parametrize("layout", sorted(LAYOUTS))
def test_1255_twin_control_arm_is_the_natural_continuation(twin, layout, which):
    pair = _pair(twin, layout)
    arm = _arm_reached_the_model(pair, layout, which)
    _clocked(pair, layout)
    diffs = W.compare(pair["natural"], arm, fork_turn=pair["branch_message_id"])
    assert not diffs, (
        f"layout {layout}: the {ARMS[which]} differs from the natural continuation on "
        f"{len(diffs)} channel(s) after the fork:\n" + "\n".join(f"  - {d}" for d in diffs))


@pytest.mark.parametrize("layout", sorted(LAYOUTS))
def test_1255_twin_arm_surfaces_carry_no_arm_identity(twin, layout):
    pair = _pair(twin, layout)
    arm = _arm_reached_the_model(pair, layout)
    tokens = W.identity_tokens(pair, "arm")
    assert {"source run id", "arm run id", "sibling run id", "episode id",
            "episode token", "fork turn (uuid int)",
            f"world label {W.CONTROL} with the fork turn (uuid int)"} <= set(tokens), tokens
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
    pair = _pair(twin, layout)
    recording = pair["natural"] if kind == "natural" else _arm_reached_the_model(pair, layout)
    tokens = W.host_tokens(pair["meta"])
    if kind == "natural":
        tokens.update(W.identity_tokens(pair, "natural"))
    assert {"data root", "tenant name", "checkout path"} <= set(tokens), tokens
    assert W.scan(recording, {"the alert's rule": "v2-sshd-success-after-failures"})
    findings = W.scan(recording, tokens)
    assert not findings, (
        f"layout {layout}, {kind} run: the host layout reaches the model:\n"
        + "\n".join(f"  - {f}" for f in findings))


@pytest.mark.parametrize("kind", ["natural", "arm"])
def test_1255_twin_runs_compare_equal_across_host_layouts(twin, kind):
    a, b = _pair(twin, "alpha"), _pair(twin, "beta")
    _clocked(a, "alpha")
    _clocked(b, "beta")
    if kind == "natural":
        records = a[kind], b[kind]
        windows = W.start_window(a[kind]), W.start_window(b[kind])
    else:
        records = _arm_reached_the_model(a, "alpha"), _arm_reached_the_model(b, "beta")
        windows = W.branch_window(a["natural"]), W.branch_window(b["natural"])
    diffs = W.compare_layouts(*records, sides=("alpha", "beta"), windows=windows)
    assert not diffs, (
        f"{kind} differs across host layouts on {len(diffs)} channel(s):\n"
        + "\n".join(f"  - {d}" for d in diffs))

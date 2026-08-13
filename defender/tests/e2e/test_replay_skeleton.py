"""Golden-replay e2e scripts — deterministic + hermetic.

These replay the artifact-write subset of REAL vendored runs through the real
`driver.run_investigation` loop and diff the produced run dir against the golden
(`fixtures-e2e/golden-v2sshd/`, `fixtures-e2e/golden-sshpivot-ab3/`). They prove
the HAPPY path of the whole-runtime seam: the write path, invlang validation, the
role-dependent Bash gate, and the two-table gather capture all fire end-to-end.

The replay *machinery* (ReplayFn/DenyProbe/Turn/drive/materialize/…) lives in
`_replay_harness.py`; this module is just the scripts. The driver's error
handling + the gate-as-feedback recovery loop are in `test_replay_error_paths.py`.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from defender.tests.e2e._replay_harness import (
    AB3_ORIG_RUN_DIR,
    GOLDEN,
    GOLDEN_AB3,
    DenyProbe,
    FakeVerbs,
    ReplayFn,
    Turn,
    drive,
    load_turns_from_trace,
    materialize,
    normalize,
)
from defender._io import read_jsonl_rows
from defender._run_paths import RunPaths
from defender.runtime import permission, tools as runtime_tools
from defender.runtime.agent_definition import compile_policy_for
from defender.runtime.challenge_gate import review_trace_path
from defender.runtime.close_tool import CAUSE_EVIDENCE_CANNOT_DISCRIMINATE
from defender.runtime.driver import GATHER_DEF, MAIN_DEF
from defender.runtime.lead_zero import RESERVED_LEAD_IDS
from defender.runtime.review_roles import REVIEW_AGENT_ID_PREFIX
from defender.skills.invlang.validate import validate_companion
from defender.tests import _review_bundle

pytestmark = pytest.mark.e2e


# The replays below draft `malicious` and the gate reviews it. They commit it again — the
# harness binds a hermetic review bundle whose composer finds `holds` (see `_replay_harness`,
# `review_stages`), so the reviewer runs end-to-end here rather than the replay asserting
# whatever shape a live provider call happens to fail in.


def test_replay_golden_v2sshd(tmp_path):
    run_id = "replay-v2sshd"
    run_dir = materialize(tmp_path, GOLDEN)

    inv_text = (GOLDEN / "investigation.md").read_text()

    # #774/R1: report.md is no longer model-writable — re-recorded against the close tool
    # (disposition inconclusive, so it commits immediately with no gate work at all).
    # #810: investigation.md is landed by `append_block`, main's only writer. Onto an empty
    # run dir the append IS the create, which is why the golden still reconstructs whole.
    replay = ReplayFn([
        Turn(tool_calls=[("append_block", {"text": inv_text})]),
        Turn(tool_calls=[("close_investigation", {"disposition": "inconclusive"})]),
        Turn(text="Investigation complete."),
    ])
    drive(run_dir, run_id=run_id, main=replay)

    assert replay.calls == 3, f"expected 3 model turns, got {replay.calls}"

    produced_inv = (run_dir / "investigation.md").read_text()
    assert normalize(produced_inv, run_dir=run_dir, run_id=run_id) == \
           normalize(inv_text, run_dir=run_dir, run_id=run_id)
    assert validate_companion(produced_inv, None) == []

    m = re.search(r"^disposition:\s*(\w+)", (run_dir / "report.md").read_text(), re.M)
    assert m is not None
    assert m.group(1) == "inconclusive"

    assert (run_dir / "tool_trace.jsonl").is_file()
    assert RunPaths(run_dir).wire_log.is_file()


def test_replay_full_run_ab3(tmp_path, monkeypatch):
    """Increment (a): replay a FULL real gather run (ab3-B, 10 turns) — bash,
    read_file, write_file AND gather dispatch — through the real driver loop.

    Scope: this is a MAIN-LOOP e2e test, so `gather` is faked at its return
    boundary (it's a separately-tested unit — test_gather_capture owns its
    internals; re-driving it would couple this test to it). Everything else is
    real: the bash/read/write tools and the permission
    gate's decide_bash / decide_read / decide_write / invlang paths all fire. We
    assert the authored artifact (investigation.md) reconstructs byte-for-byte and
    re-validates clean through the live gate. The two-table / gather_raw capture
    belongs to the nested-gather replay (test_nested_gather_capture).
    """
    run_id = "replay-ab3"
    run_dir = materialize(tmp_path, GOLDEN_AB3)

    turns = load_turns_from_trace(
        GOLDEN_AB3 / "tool_trace.jsonl",
        old_run_dir=AB3_ORIG_RUN_DIR, new_run_dir=str(run_dir),
        as_appends=True,   # the golden predates #810; MAIN's writer is append_block now
    )
    replay = ReplayFn(turns)

    async def _fake_run_gather(deps, gather_factory, request_limit, request, verb_grant=None,
                               stamp_terminator=None):
        # `stamp_terminator` is the gather-session terminator seam (#826 item 1). This fake
        # replaces the whole frame, so it stamps nothing — a replayed dispatch has no
        # terminator to record, and every arm that would call it is one this fake skips.
        return f"[replayed gather summary: lead={request.lead_id} system={request.system}]"

    monkeypatch.setattr(  # lint-monkeypatch: ok — boundary fake (see comment above)
        runtime_tools, "_run_gather", _fake_run_gather,
    )

    # #774/R1: the golden trace's report.md write is re-recorded as a close_investigation
    # call. It reaches a confident (malicious) disposition, which the gate reviews — three
    # lenses and a composer, all four bound to the harness's hermetic bundle.
    drive(run_dir, run_id=run_id, main=replay)

    assert replay.calls == len(turns), \
        f"replayed {replay.calls}/{len(turns)} turns (early stop = an unexpected gate deny)"

    produced = (run_dir / "investigation.md").read_text()
    golden = (GOLDEN_AB3 / "investigation.md").read_text()
    assert normalize(produced, run_dir=run_dir, run_id=run_id) == \
           normalize(golden, run_dir=run_dir, run_id=run_id)

    assert validate_companion(produced, None) == []

    report = (run_dir / "report.md").read_text()
    m = re.search(r"^disposition:\s*(\w+)", report, re.M)
    assert m is not None
    assert m.group(1) == "malicious", (
        "a review that ran and found the close sound must leave the drafted disposition alone"
    )
    assert "failure_kind:" not in report, (
        "the frontmatter names a machinery failure on a run where every stage answered"
    )

    # The reviewer really ran, rather than the close committing past a gate that never
    # dispatched: four stages, four traces, each carrying its round.
    for role in ("support", "ablation", "composer"):
        rows = read_jsonl_rows(review_trace_path(run_dir, role))
        assert rows, f"the {role} stage left no trace row"
        assert rows[0].get("ok") is True, f"the {role} stage did not answer"
    # WHICH bundle answered, asked POSITIVELY. A live stage no longer leaves a file of its
    # own to look for (since #787 it writes through the run's logger under a `review:` agent
    # id), and the wire log cannot stand in for that file: under
    # `override_allow_model_requests(False)` a live stage raises INSIDE the model request, so
    # `_log_request`'s `logger.log` never runs and no `review:` record is written whether or
    # not the live path was taken. What only the injected bundle can produce is its own canned
    # reading, on disk, in the lens traces — a live stage there would carry a provider error.
    for lens in ("support", "ablation"):
        trace = review_trace_path(run_dir, lens).read_text(encoding="utf-8")
        assert _review_bundle.LENS_READING in trace, (
            f"the {lens} reading is not the harness's — the run reached the provider-backed "
            "bundle, not the injected one"
        )
    # Kept as a belt on the hermetic override itself: if a review call ever DID reach a
    # provider, this is where the evidence would land.
    wire_log = RunPaths(run_dir).wire_log
    assert wire_log.is_file(), (
        "the wire log is not where this belt is looking — a missing file reads as zero live "
        "records, so the assertion below would pass without measuring anything"
    )
    live = [
        r for r in read_jsonl_rows(wire_log)
        if str(r.get("agent_id", "")).startswith(REVIEW_AGENT_ID_PREFIX)
    ]
    assert not live, (
        "a live stage reached a provider: the run is no longer hermetic "
        f"({len(live)} review wire records)"
    )

    assert (run_dir / "tool_trace.jsonl").is_file()


def test_a_gap_the_review_cannot_measure_overrides_the_confident_close(tmp_path):
    """The gate's other arm, end to end: the composer finds a gap and can name no measurement
    that would settle it, so the drafted `malicious` never reaches disk.

    The pair with `test_replay_full_run_ab3` is the whole point — same machinery, same
    confident draft, one bundle apart. A suite in which every review answers `holds` cannot
    tell a reviewer that ran from a close that reached no reviewer at all, which is exactly
    what the replays were unable to distinguish while the seam defaulted to a live bundle."""
    run_id = "replay-gap"
    run_dir = materialize(tmp_path, GOLDEN_AB3)
    inv_text = (GOLDEN_AB3 / "investigation.md").read_text()

    replay = ReplayFn([
        Turn(tool_calls=[("append_block", {"text": inv_text})]),
        Turn(tool_calls=[("close_investigation", {"disposition": "malicious"})]),
        Turn(text="Investigation complete."),
    ])
    drive(run_dir, run_id=run_id, main=replay,
          review_stages=_review_bundle.bundle(composer=_review_bundle.composer_reply(
              "gap", review="the pivot rests on one inference no lead measured", ask=None,
          )))

    report = (run_dir / "report.md").read_text()
    m = re.search(r"^disposition:\s*(\w+)", report, re.M)
    assert m is not None
    assert m.group(1) == "inconclusive", (
        "the drafted `malicious` reached disk past a review that found a gap"
    )
    assert CAUSE_EVIDENCE_CANNOT_DISCRIMINATE in report
    assert "failure_kind:" not in report, (
        "an override the review DECIDED is recorded as the review machinery failing"
    )


#: #810 retired the ("write-escape", "write_file", …) arm: main has no verb that takes a
#: caller-supplied write path, so the escape it drove cannot be EXPRESSED any more, let alone
#: denied. The property it pinned is stronger now and is asserted directly by
#: `test_main_cannot_name_a_write_path_at_all` below — a deny bounce would be the wrong oracle
#: for it, since there is no longer a call to bounce. That was also the only arm carrying an
#: `escape_name`, so the column went with it rather than staying as a slot every arm passes
#: `None` to and no assertion ever reads.
@pytest.mark.parametrize(("label", "tool_name", "args_fn", "reason_substr"), [
    ("adapter-from-main", "bash",
     lambda rd: {"command": "defender-elastic query foo"},
     "not runnable from bash"),
    ("read-escape", "read_file",
     lambda rd: {"path": "/etc/passwd"},
     "outside them"),
    ("raw-read-from-main", "read_file",
     lambda rd: {"path": str(rd / "gather_raw" / "l-001" / "0.json")},
     "must not read gather_raw"),
    ("shell-from-main", "bash",
     lambda rd: {"command": "curl http://example.invalid/x"},
     "only the defender-* shims"),
])
def test_main_loop_deny_bounces(tmp_path, label, tool_name, args_fn, reason_substr):
    run_id = f"deny-{label}"
    run_dir = materialize(tmp_path, GOLDEN_AB3)

    probe = DenyProbe(tool_name, args_fn(run_dir))
    drive(run_dir, run_id=run_id, main=probe)

    assert probe.calls >= 2, "deny did not bounce the agent back into the loop"

    assert reason_substr in probe.seen[-1]


def test_main_cannot_name_a_write_path_at_all(tmp_path):
    """The successor to the retired `write-escape` deny bounce (#810).

    That arm drove `write_file` at a path outside the run dir and asserted the allowlist
    refused it. Main no longer HAS a verb that accepts a write path: `append_block` is bound
    to `<run_dir>/investigation.md` in the handler, so a model that wants to write elsewhere
    has nothing to say it with. Unreachable beats denied — but only if it is actually
    unreachable, so this asserts both halves: no path-taking writer is registered, and the
    one writer that is lands on the transcript and creates nothing else."""
    run_id = "no-write-path"
    run_dir = materialize(tmp_path, GOLDEN_AB3)

    assert MAIN_DEF.tools.append is True
    assert MAIN_DEF.tools.write is False, (
        "main holds the path-taking write lane again; the escape is expressible"
    )

    before = {p.name for p in run_dir.parent.iterdir()}
    replay = ReplayFn([
        Turn(tool_calls=[("append_block", {"text": "+ probe\n"})]),
        Turn(tool_calls=[("close_investigation", {"disposition": "inconclusive"})]),
        Turn(text="done"),
    ])
    drive(run_dir, run_id=run_id, main=replay)

    assert (run_dir / "investigation.md").read_text() == "+ probe\n"
    assert {p.name for p in run_dir.parent.iterdir()} == before, (
        "the append created something outside the run dir"
    )


def test_role_flip_data_access_is_role_dependent():
    """The crown-jewel contrast, asserted directly: data-source access is ROLE-DEPENDENT —
    gather may reach a system, main may not.

    #611 moved WHERE that role-dependence lives. It used to be the bash lane (main denied the
    adapter command, gather ran it captured); now NO role runs an adapter from bash — the reader
    lane denies the command for BOTH roles — and the role distinction is the typed `query` tool:
    it is declared on GATHER_DEF and not on MAIN_DEF, so 'which agent may reach a data source'
    stays policy-as-data on the AgentDefinition (visible to compile_policy / `defender-policy
    explain`), exactly where the deleted capability bit used to be audited."""
    cmd = "defender-elastic query foo"
    run, dfn = Path("/run"), Path("/dfn")
    assert not permission.decide_bash(
        cmd, policy=compile_policy_for(MAIN_DEF, run_dir=run, defender_dir=dfn)).allow
    assert not permission.decide_bash(
        cmd, policy=compile_policy_for(GATHER_DEF, run_dir=run, defender_dir=dfn)).allow
    assert GATHER_DEF.tools.query is True
    assert MAIN_DEF.tools.query is False



_PAYLOAD = [{"@timestamp": "2026-01-01T00:00:00Z", "user.name": "dev.dana",
             "event.action": "ssh_login"}]


def _elastic_verbs() -> FakeVerbs:
    def query(ctx, *, native_query: str) -> list[dict]:
        return _PAYLOAD

    return FakeVerbs({"elastic": {"query": query}})


def test_nested_gather_capture(tmp_path):
    run_id = "nested-gather"
    run_dir = materialize(tmp_path, GOLDEN_AB3)

    main_replay = ReplayFn([
        Turn(tool_calls=[("gather", {
            "lead_id": "l-001", "system": "elastic",
            "goal": "check sshd auth history", "what_to_summarize": ["auth events"]})]),
        Turn(tool_calls=[("close_investigation", {"disposition": "malicious"})]),
        Turn(text="Investigation complete."),
    ])
    gather_replay = ReplayFn([
        Turn(tool_calls=[("query", {
            "system": "elastic", "verb": "query",
            "params": {"native_query": "FROM logs-auth | WHERE user.name == \"dev.dana\""},
            "query_id": "elastic.sshd-auth-history",
        })]),
        Turn(text="Summary: 1 sshd auth event for dev.dana."),
    ])

    drive(run_dir, run_id=run_id, main=main_replay, gather=gather_replay,
          verbs=_elastic_verbs())

    assert main_replay.calls == 3
    assert gather_replay.calls == 2

    lead_row = run_dir / "gather_raw" / "l-001.lead.json"
    assert lead_row.is_file()
    assert "check sshd auth history" in lead_row.read_text()

    # lead-0 (#808) resolves against GOLDEN_AB3 ahead of MAIN's own turn and lands its
    # own (l-000) row in this same table — scope to the model-driven lead this scenario
    # is actually about.
    rows = [r for r in read_jsonl_rows(run_dir / "executed_queries.jsonl")
            if r["lead_id"] not in RESERVED_LEAD_IDS]
    assert len(rows) == 1
    row = rows[0]
    assert row["lead_id"] == "l-001"
    assert row["system"] == "elastic"
    assert row["exit_code"] == 0

    payload = run_dir / row["payload_path"]
    assert payload.is_file()
    assert "dev.dana" in payload.read_text()

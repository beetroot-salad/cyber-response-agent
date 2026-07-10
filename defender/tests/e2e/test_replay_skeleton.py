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

import json
import re
from pathlib import Path

import pytest

from defender.tests.e2e._replay_harness import (
    AB3_ORIG_RUN_DIR,
    GOLDEN,
    GOLDEN_AB3,
    DenyProbe,
    FakeAdapterSubprocess,
    ReplayFn,
    Turn,
    drive,
    load_turns_from_trace,
    materialize,
    normalize,
)
from defender.runtime import permission, tools as runtime_tools
from defender.runtime.agent_definition import compile_policy_for
from defender.runtime.driver import GATHER_DEF, MAIN_DEF
from defender.scripts.gather_tools import record_query
from defender.skills.invlang.validate import validate_companion

pytestmark = pytest.mark.e2e


def test_replay_golden_v2sshd(tmp_path):
    run_id, salt = "replay-v2sshd", "deadbeefcafe0000"
    run_dir = materialize(tmp_path, GOLDEN, run_id=run_id, salt=salt)

    inv_text = (GOLDEN / "investigation.md").read_text()
    rep_text = (GOLDEN / "report.md").read_text()

    # The artifact-write subset of the run: write investigation.md (exercises
    # decide_write + invlang validation on REAL content), write report.md, then
    # end. No bash/gather, so a single script suffices.
    replay = ReplayFn([
        Turn(tool_calls=[("write_file",
                          {"path": str(run_dir / "investigation.md"), "content": inv_text})]),
        Turn(tool_calls=[("write_file",
                          {"path": str(run_dir / "report.md"), "content": rep_text})]),
        Turn(text="Investigation complete."),
    ])
    drive(run_dir, run_id=run_id, salt=salt, main=replay)

    # 1. The loop replayed our script exactly (3 model requests).
    assert replay.calls == 3, f"expected 3 model turns, got {replay.calls}"

    # 2. investigation.md was written byte-for-byte (the write path is faithful) AND
    #    independently re-validates clean through the live invlang gate. The byte
    #    compare alone is near-tautological (write_file is verbatim); the explicit
    #    validate_companion is the load-bearing check that the golden passes the
    #    REAL validator — without it, stubbing the validator to a pass-through would
    #    still leave this test green.
    produced_inv = (run_dir / "investigation.md").read_text()
    assert normalize(produced_inv, run_dir=run_dir, salt=salt, run_id=run_id) == \
           normalize(inv_text, run_dir=run_dir, salt=salt, run_id=run_id)
    assert validate_companion(produced_inv, None) == []

    # 3. report.md present + disposition parses (the learning-loop's headline).
    m = re.search(r"^disposition:\s*(\w+)", (run_dir / "report.md").read_text(), re.M)
    assert m is not None
    assert m.group(1) == "inconclusive"

    # 4. Deterministic side-effects fired: observe projected the trace; the live
    #    request log exists.
    assert (run_dir / "tool_trace.jsonl").is_file()
    assert (run_dir / "llm_requests.jsonl").is_file()


def test_replay_full_run_ab3(tmp_path, monkeypatch):
    """Increment (a): replay a FULL real gather run (ab3-B, 10 turns) — bash,
    read_file, write_file AND gather dispatch — through the real driver loop.

    Scope: this is a MAIN-LOOP e2e test, so `gather` is faked at its return
    boundary (it's a separately-tested unit — test_runtime_gather /
    test_gather_capture own its internals; re-driving it would couple this test to
    them). Everything else is real: the bash/read/write tools and the permission
    gate's decide_bash / decide_read / decide_write / invlang paths all fire. We
    assert the authored artifact (investigation.md) reconstructs byte-for-byte and
    re-validates clean through the live gate. The two-table / gather_raw capture
    belongs to the nested-gather replay (test_nested_gather_capture).
    """
    run_id, salt = "replay-ab3", "0011223344556677"
    run_dir = materialize(tmp_path, GOLDEN_AB3, run_id=run_id, salt=salt)

    # Reconstruct the main-agent script from the vendored trace, rewriting the
    # recorded run-dir paths to this temp run dir.
    turns = load_turns_from_trace(
        GOLDEN_AB3 / "tool_trace.jsonl",
        old_run_dir=AB3_ORIG_RUN_DIR, new_run_dir=str(run_dir),
    )
    replay = ReplayFn(turns)

    # Fake `gather` at its boundary: a dispatched lead returns a summary string
    # without re-driving the nested agent. Signature mirrors tools._run_gather.
    # The nested gather + its capture path are exercised by test_nested_gather_
    # capture; this test deliberately isolates the MAIN loop.
    async def _fake_run_gather(deps, gather_factory, request_limit, request):
        return f"[replayed gather summary: lead={request.lead_id} system={request.system}]"

    # Boundary fake of the gather subagent's return contract — isolates the MAIN
    # loop; the nested gather + capture path are covered by test_nested_gather_capture.
    monkeypatch.setattr(  # lint-monkeypatch: ok — boundary fake (see comment above)
        runtime_tools, "_run_gather", _fake_run_gather,
    )

    drive(run_dir, run_id=run_id, salt=salt, main=replay)

    # 1. The whole trace replayed — no early termination from an unexpected deny.
    assert replay.calls == len(turns), \
        f"replayed {replay.calls}/{len(turns)} turns (early stop = an unexpected gate deny)"

    # 2. investigation.md reconstructed byte-for-byte through the real write path
    #    + invlang validation on every intermediate write.
    produced = (run_dir / "investigation.md").read_text()
    golden = (GOLDEN_AB3 / "investigation.md").read_text()
    assert normalize(produced, run_dir=run_dir, salt=salt, run_id=run_id) == \
           normalize(golden, run_dir=run_dir, salt=salt, run_id=run_id)

    # 3. The reconstruction is independently invlang-valid (the live gate accepted it).
    assert validate_companion(produced, None) == []

    # 4. report.md disposition reconstructed; trace projected.
    m = re.search(r"^disposition:\s*(\w+)", (run_dir / "report.md").read_text(), re.M)
    assert m is not None
    assert m.group(1) == "malicious"
    assert (run_dir / "tool_trace.jsonl").is_file()


# --- deny-tail scripts (synthesized; spec-anchored) ------------------------
# These verdicts NEVER appear in an organic run — a well-behaved agent doesn't
# try to run an adapter from the main loop or write outside the run dir. So they
# can't be mined; the golden is the SPEC verdict (deny), asserted once here. They
# guard the security boundary, so a future change that flips them must be a loud,
# reviewed event — not a silent re-record.

@pytest.mark.parametrize(("label", "tool_name", "args_fn", "reason_substr", "escape_name"), [
    # D1 — the breach: the main loop must NOT run a data-source adapter directly
    # (that's the exfil lane; the gather subagent is the only data-access role).
    ("adapter-from-main", "bash",
     lambda rd: {"command": "defender-elastic query foo"},
     "data-source CLIs directly", None),
    # D6 — a write escaping the run dir must be refused. Main's write_allow is its
    # run-dir subtree only (the flat deny-by-default write allowlist), so a path outside
    # it is not in the agent's declared paths.
    ("write-escape", "write_file",
     lambda rd: {"path": str(rd.parent / "ESCAPE_OUTSIDE_RUNDIR.txt"), "content": "x"},
     "declared paths", "ESCAPE_OUTSIDE_RUNDIR.txt"),
    # A read resolving outside the allowlisted roots (run dir + defender corpus +
    # the agent's declared policy read_roots) is refused — the deny-by-default read
    # allowlist, asserted at the driver seam.
    ("read-escape", "read_file",
     lambda rd: {"path": "/etc/passwd"},
     "outside them", None),
    # The main loop must not read a gather_raw payload directly: the gather
    # summary is authoritative, raw evidence stays behind the subagent boundary.
    ("raw-read-from-main", "read_file",
     lambda rd: {"path": str(rd / "gather_raw" / "l-001" / "0.json")},
     "must not read gather_raw", None),
    # Arbitrary shell from the main loop (not a defender-* shim / read-only viewer)
    # fails closed — no curl/rm/python3 escape hatch.
    ("shell-from-main", "bash",
     lambda rd: {"command": "curl http://example.invalid/x"},
     "only the defender-* shims", None),
])
def test_main_loop_deny_bounces(tmp_path, label, tool_name, args_fn,
                                reason_substr, escape_name):
    run_id, salt = f"deny-{label}", "8899aabbccddeeff"
    run_dir = materialize(tmp_path, GOLDEN_AB3, run_id=run_id, salt=salt)

    probe = DenyProbe(tool_name, args_fn(run_dir))
    drive(run_dir, run_id=run_id, salt=salt, main=probe)

    # 1. The deny BOUNCED the agent (ModelRetry → re-prompt), not crashed it: the
    #    model was called again after the offending turn.
    assert probe.calls >= 2, "deny did not bounce the agent back into the loop"

    # 2. The spec deny reason reached the model as retry feedback (the in-process
    #    twin of the claude -p exit-2). Proves the driver wired role/run_dir into
    #    the gate — the unit test of decide_* can't see this.
    assert reason_substr in probe.seen[-1]

    # 3. The breach did not happen: a write-escape never created the file outside
    #    the run dir.
    if escape_name is not None:
        assert not (run_dir.parent / escape_name).exists()


def test_role_flip_adapter_is_role_dependent():
    """The crown-jewel contrast, asserted directly: the SAME adapter command is
    DENIED from the main loop (wired-and-bounced by test_main_loop_deny_bounces
    above) but ALLOWED for the gather subagent. Full GATHER-role e2e wiring is the
    nested-gather replay; this pins the role-dependence the driver must thread."""
    cmd = "defender-elastic query foo"
    # compile_policy_for is per-run since #535; the adapter deny/allow is role-driven, not root-driven,
    # so synthetic absolute roots suffice for this contrast.
    run, dfn = Path("/run"), Path("/dfn")
    assert not permission.decide_bash(
        cmd, policy=compile_policy_for(MAIN_DEF, run_dir=run, defender_dir=dfn)).allow
    assert permission.decide_bash(
        cmd, policy=compile_policy_for(GATHER_DEF, run_dir=run, defender_dir=dfn)).allow


# --- nested-gather replay: drives the two-table capture path ---------------
# Unlike test_replay_full_run_ab3 (gather faked at its boundary), this runs a
# REAL nested gather subagent so the capture path executes end-to-end:
# _run_gather -> record_lead.claim_lead (leads table) -> the gather agent's
# adapter bash -> decide_bash(GATHER) -> _capture_adapter -> record_query.capture
# (queries table + gather_raw payload). The only fake below the model is the
# adapter SUBPROCESS — FakeAdapterSubprocess returns a canned payload, so the run
# stays hermetic while the real capture/record code runs.

def test_nested_gather_capture(tmp_path, monkeypatch):
    run_id, salt = "nested-gather", "1122334455667788"
    run_dir = materialize(tmp_path, GOLDEN_AB3, run_id=run_id, salt=salt)

    report_md = ("---\ncase_id: nested-gather\ndisposition: malicious\n"
                 "confidence: low\n---\nSynthetic nested-gather capture test.\n")

    # Main loop: dispatch ONE gather lead, then write report, then end.
    main_replay = ReplayFn([
        Turn(tool_calls=[("gather", {
            "lead_id": "l-001", "system": "elastic",
            "goal": "check sshd auth history", "what_to_summarize": ["auth events"]})]),
        Turn(tool_calls=[("write_file", {"path": str(run_dir / "report.md"), "content": report_md})]),
        Turn(text="Investigation complete."),
    ])
    # The nested gather agent: run one standalone adapter query (captured), then
    # return a measurements summary.
    gather_replay = ReplayFn([
        Turn(tool_calls=[("bash", {"command": "defender-elastic query sshd-auth-history"})]),
        Turn(text="Summary: 1 sshd auth event for dev.dana."),
    ])

    # Stub ONLY the adapter subprocess inside record_query (isolated to that module)
    # so the real capture/record code runs while staying hermetic — the adapter's
    # external-process IO has no in-process seam.
    monkeypatch.setattr(  # lint-monkeypatch: ok — boundary: adapter subprocess IO
        record_query, "subprocess", FakeAdapterSubprocess,
    )

    drive(run_dir, run_id=run_id, salt=salt, main=main_replay, gather=gather_replay)

    # Both loops ran (main dispatched, nested gather executed its query + summary).
    assert main_replay.calls == 3
    assert gather_replay.calls == 2

    # LEADS table: claim_lead wrote the lead sidecar with the dispatch goal.
    lead_row = run_dir / "gather_raw" / "l-001.lead.json"
    assert lead_row.is_file()
    assert "check sshd auth history" in lead_row.read_text()

    # QUERIES table: the adapter call was captured as a row bound to system=elastic.
    qlines = (run_dir / "executed_queries.jsonl").read_text().splitlines()
    assert len(qlines) == 1
    row = json.loads(qlines[0])
    assert row["lead_id"] == "l-001"
    assert row["system"] == "elastic"
    assert row["exit_code"] == 0

    # gather_raw payload persisted by-ref at the path the row names.
    payload = run_dir / row["payload_path"]
    assert payload.is_file()
    assert "dev.dana" in payload.read_text()

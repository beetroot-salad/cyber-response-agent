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
    FakeVerbs,
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
from defender.skills.invlang.validate import validate_companion

pytestmark = pytest.mark.e2e


def test_replay_golden_v2sshd(tmp_path):
    run_id, salt = "replay-v2sshd", "deadbeefcafe0000"
    run_dir = materialize(tmp_path, GOLDEN)

    inv_text = (GOLDEN / "investigation.md").read_text()
    rep_text = (GOLDEN / "report.md").read_text()

    replay = ReplayFn([
        Turn(tool_calls=[("write_file",
                          {"path": str(run_dir / "investigation.md"), "content": inv_text})]),
        Turn(tool_calls=[("write_file",
                          {"path": str(run_dir / "report.md"), "content": rep_text})]),
        Turn(text="Investigation complete."),
    ])
    drive(run_dir, run_id=run_id, salt=salt, main=replay)

    assert replay.calls == 3, f"expected 3 model turns, got {replay.calls}"

    produced_inv = (run_dir / "investigation.md").read_text()
    assert normalize(produced_inv, run_dir=run_dir, salt=salt, run_id=run_id) == \
           normalize(inv_text, run_dir=run_dir, salt=salt, run_id=run_id)
    assert validate_companion(produced_inv, None) == []

    m = re.search(r"^disposition:\s*(\w+)", (run_dir / "report.md").read_text(), re.M)
    assert m is not None
    assert m.group(1) == "inconclusive"

    assert (run_dir / "tool_trace.jsonl").is_file()
    assert (run_dir / "llm_requests.jsonl").is_file()


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
    run_id, salt = "replay-ab3", "0011223344556677"
    run_dir = materialize(tmp_path, GOLDEN_AB3)

    turns = load_turns_from_trace(
        GOLDEN_AB3 / "tool_trace.jsonl",
        old_run_dir=AB3_ORIG_RUN_DIR, new_run_dir=str(run_dir),
    )
    replay = ReplayFn(turns)

    async def _fake_run_gather(deps, gather_factory, request_limit, request):
        return f"[replayed gather summary: lead={request.lead_id} system={request.system}]"

    monkeypatch.setattr(  # lint-monkeypatch: ok — boundary fake (see comment above)
        runtime_tools, "_run_gather", _fake_run_gather,
    )

    drive(run_dir, run_id=run_id, salt=salt, main=replay)

    assert replay.calls == len(turns), \
        f"replayed {replay.calls}/{len(turns)} turns (early stop = an unexpected gate deny)"

    produced = (run_dir / "investigation.md").read_text()
    golden = (GOLDEN_AB3 / "investigation.md").read_text()
    assert normalize(produced, run_dir=run_dir, salt=salt, run_id=run_id) == \
           normalize(golden, run_dir=run_dir, salt=salt, run_id=run_id)

    assert validate_companion(produced, None) == []

    m = re.search(r"^disposition:\s*(\w+)", (run_dir / "report.md").read_text(), re.M)
    assert m is not None
    assert m.group(1) == "malicious"
    assert (run_dir / "tool_trace.jsonl").is_file()



@pytest.mark.parametrize(("label", "tool_name", "args_fn", "reason_substr", "escape_name"), [
    ("adapter-from-main", "bash",
     lambda rd: {"command": "defender-elastic query foo"},
     "not runnable from bash", None),
    ("write-escape", "write_file",
     lambda rd: {"path": str(rd.parent / "ESCAPE_OUTSIDE_RUNDIR.txt"), "content": "x"},
     "declared paths", "ESCAPE_OUTSIDE_RUNDIR.txt"),
    ("read-escape", "read_file",
     lambda rd: {"path": "/etc/passwd"},
     "outside them", None),
    ("raw-read-from-main", "read_file",
     lambda rd: {"path": str(rd / "gather_raw" / "l-001" / "0.json")},
     "must not read gather_raw", None),
    ("shell-from-main", "bash",
     lambda rd: {"command": "curl http://example.invalid/x"},
     "only the defender-* shims", None),
])
def test_main_loop_deny_bounces(tmp_path, label, tool_name, args_fn,
                                reason_substr, escape_name):
    run_id, salt = f"deny-{label}", "8899aabbccddeeff"
    run_dir = materialize(tmp_path, GOLDEN_AB3)

    probe = DenyProbe(tool_name, args_fn(run_dir))
    drive(run_dir, run_id=run_id, salt=salt, main=probe)

    assert probe.calls >= 2, "deny did not bounce the agent back into the loop"

    assert reason_substr in probe.seen[-1]

    if escape_name is not None:
        assert not (run_dir.parent / escape_name).exists()


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
    run_id, salt = "nested-gather", "1122334455667788"
    run_dir = materialize(tmp_path, GOLDEN_AB3)

    report_md = ("---\ncase_id: nested-gather\ndisposition: malicious\n"
                 "confidence: low\n---\nSynthetic nested-gather capture test.\n")

    main_replay = ReplayFn([
        Turn(tool_calls=[("gather", {
            "lead_id": "l-001", "system": "elastic",
            "goal": "check sshd auth history", "what_to_summarize": ["auth events"]})]),
        Turn(tool_calls=[("write_file", {"path": str(run_dir / "report.md"), "content": report_md})]),
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

    drive(run_dir, run_id=run_id, salt=salt, main=main_replay, gather=gather_replay,
          verbs=_elastic_verbs())

    assert main_replay.calls == 3
    assert gather_replay.calls == 2

    lead_row = run_dir / "gather_raw" / "l-001.lead.json"
    assert lead_row.is_file()
    assert "check sshd auth history" in lead_row.read_text()

    qlines = (run_dir / "executed_queries.jsonl").read_text().splitlines()
    assert len(qlines) == 1
    row = json.loads(qlines[0])
    assert row["lead_id"] == "l-001"
    assert row["system"] == "elastic"
    assert row["exit_code"] == 0

    payload = run_dir / row["payload_path"]
    assert payload.is_file()
    assert "dev.dana" in payload.read_text()

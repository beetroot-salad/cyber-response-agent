"""Golden-replay e2e scripts — deterministic + hermetic."""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from defender.tests.support.runtime.state._1255_view import model_path

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
from defender.run_repository import RunPaths
from defender.runtime import permission, tools as runtime_tools
from defender.runtime.agent_definition import compile_policy_for
from defender.runtime.close_tool import CAUSE_EVIDENCE_CANNOT_DISCRIMINATE
from defender.runtime.driver import GATHER_DEF, MAIN_DEF
from defender.tests.support.tenancy import _tenants1106
from defender.runtime.lead_zero import RESERVED_LEAD_IDS
from defender.runtime.review_roles import REVIEW_AGENT_ID_PREFIX
from defender.runtime.run_end import sidecar_path
from defender.skills.invlang.validate import validate_companion
from defender.tests.support.runtime.permissions import _review_bundle

pytestmark = pytest.mark.e2e


def test_replay_golden_v2sshd(tmp_path):
    run_id = "replay-v2sshd"
    run_dir = materialize(tmp_path, GOLDEN, run_id=run_id)

    inv_text = (GOLDEN / "investigation.md").read_text()

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
    read_file, write_file AND gather dispatch — through the real driver loop."""
    run_id = "replay-ab3"
    run_dir = materialize(tmp_path, GOLDEN_AB3, run_id=run_id)

    turns = load_turns_from_trace(
        GOLDEN_AB3 / "tool_trace.jsonl",
        old_run_dir=AB3_ORIG_RUN_DIR, new_run_dir=model_path(run_dir, run_dir=run_dir),
        as_appends=True,   # the golden predates #810; MAIN's writer is append_block now
    )
    replay = ReplayFn(turns)

    async def _fake_run_gather(deps, gather_factory, request_limit, request, verb_grant=None,
                               stamp_terminator=None, *, catalog=None):
        return f"[replayed gather summary: lead={request.lead_id} system={request.system}]"

    monkeypatch.setattr(  # lint-monkeypatch: ok — boundary fake (see comment above)
        runtime_tools, "_run_gather", _fake_run_gather,
    )

    # #1108 P4 (A8): the golden carries the agent content it reads; the run is a tenant whose
    # agent half is that tree, published for real, so its recorded `cat /agent/lessons/X.md`
    # reads are answered by the golden's own lessons, observed below in what MAIN was handed.
    drive(run_dir, run_id=run_id, main=replay, agent=GOLDEN_AB3 / "agent")

    assert replay.calls == len(turns), \
        f"replayed {replay.calls}/{len(turns)} turns (early stop = an unexpected gate deny)"
    handed = replay.seen[-1]
    for lesson in sorted((GOLDEN_AB3 / "agent" / "lessons").glob("*.md")):
        assert lesson.read_text(encoding="utf-8").strip() in handed, (
            f"MAIN's recorded `cat /agent/lessons/{lesson.name}` came back without the golden's "
            "lesson: the run did not read its tenant's agent tree")

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
        rows = read_jsonl_rows(RunPaths(run_dir).review_trace(role))
        assert rows, f"the {role} stage left no trace row"
        assert rows[0].get("ok") is True, f"the {role} stage did not answer"
    for lens in ("support", "ablation"):
        trace = RunPaths(run_dir).review_trace(lens).read_text(encoding="utf-8")
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
    that would settle it, so the drafted `malicious` never reaches disk."""
    run_id = "replay-gap"
    run_dir = materialize(tmp_path, GOLDEN_AB3, run_id=run_id)
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
    # #923: the gate's overrule commits `unresolved` — the host's own verdict — not
    # `inconclusive`, which is now reserved for the model's own close.
    assert m.group(1) == "unresolved", (
        "the drafted `malicious` reached disk past a review that found a gap"
    )
    assert CAUSE_EVIDENCE_CANNOT_DISCRIMINATE in report
    assert "failure_kind:" not in report, (
        "an override the review DECIDED is recorded as the review machinery failing"
    )


@pytest.mark.parametrize(("label", "tool_name", "args_fn", "reason_substr"), [
    ("adapter-from-main", "bash",
     lambda rd: {"command": "defender-elastic query foo"},
     "not runnable from bash"),
    ("read-escape", "read_file",
     lambda rd: {"path": "/etc/passwd"},
     "outside them"),
    ("raw-read-from-main", "read_file",
     lambda rd: {"path": model_path(rd / "gather_raw" / "l-001" / "0.json", run_dir=rd)},
     "must not read gather_raw"),
    ("shell-from-main", "bash",
     lambda rd: {"command": "curl http://example.invalid/x"},
     "only the defender-* shims"),
])
def test_main_loop_deny_bounces(tmp_path, label, tool_name, args_fn, reason_substr):
    run_id = f"deny-{label}"
    run_dir = materialize(tmp_path, GOLDEN_AB3, run_id=run_id)

    probe = DenyProbe(tool_name, args_fn(run_dir))
    drive(run_dir, run_id=run_id, main=probe)

    assert probe.calls >= 2, "deny did not bounce the agent back into the loop"

    assert reason_substr in probe.seen[-1]


def test_main_cannot_name_a_write_path_at_all(tmp_path):
    run_id = "no-write-path"
    run_dir = materialize(tmp_path, GOLDEN_AB3, run_id=run_id)

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
    # #1235 F2: the run -> case link is also a host sidecar beside the run dir.
    from defender.run_repository import RunPaths
    host_sidecars = {sidecar_path(run_dir).name, RunPaths(run_dir).session_pointer().name,
                     RunPaths(run_dir).scrub_verdict().name}
    assert {p.name for p in run_dir.parent.iterdir()} == before | host_sidecars, (
        "the append created something outside the run dir and the host's own sidecars"
    )


def test_role_flip_data_access_is_role_dependent():
    """The crown-jewel contrast, asserted directly: data-source access is ROLE-DEPENDENT —
    gather may reach a system, main may not."""
    cmd = "defender-elastic query foo"
    run, dfn = Path("/run"), Path("/dfn")
    assert not permission.decide_bash(
        cmd, policy=compile_policy_for(MAIN_DEF, run_dir=run, defender_dir=dfn)).allow
    assert not permission.decide_bash(
        cmd, policy=compile_policy_for(
            _tenants1106.fixture_gather_def(), run_dir=run, defender_dir=dfn)).allow
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
    run_dir = materialize(tmp_path, GOLDEN_AB3, run_id=run_id)

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

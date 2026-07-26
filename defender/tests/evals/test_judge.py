"""Pins for the two-pass judge (#711).

Everything here runs against a stubbed call seam. The judge's *judgement* can only be
measured by running it (`audit_judge.py`); what these tests pin is the plumbing around
it — above all the input split, which is the design's load-bearing claim: the label pass
must never see the story or the projection, because its output is the measurement a
projection is later graded against.
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from defender.evals.oracle_golden import audit_judge, judge

CASES = judge.GOLDEN_DIR / "cases"
CASE = CASES / "case-003-suppression-devws"


def _call(*responses: str, resolved: str | None = None):
    """A stub call seam cycling through canned text, recording what it was sent."""
    sent = []

    def call(instructions: str, user: str, model: str, effort: str) -> judge.CallResult:
        sent.append({"instructions": instructions, "user": user,
                     "model": model, "effort": effort})
        return judge.CallResult(text=responses[(len(sent) - 1) % len(responses)],
                                model=resolved or model, effort=effort, cost_usd=0.01)

    call.sent = sent  # type: ignore[attr-defined]
    return call


LABEL_OK = """
delta_kind: suppressed
heterogeneous: false
evidence: |
  The C-14d control returns 444 auth documents over a live window; the operation
  window returns none.
"""

VERDICT_OK = """
faithful: true
rationale: |
  The projection emits the suppression marker, which the measurement supports.
"""


# --------------------------------------------------------------- the input split

def test_the_label_pass_is_shown_neither_the_story_nor_a_projection():
    """The whole point of two passes. A label pass that has read a confident projection
    tags to match it, and the calibration in audit_judge.py — hand labels derived
    without one — stops being like-for-like."""
    inputs = judge.load_lead_inputs(CASE, "l-001")
    user = judge.label_user_prompt(inputs)
    assert "<story>" not in user
    assert "<projection>" not in user
    assert "<measurement>" not in user
    story_sentence = inputs.story.splitlines()[0].strip()
    assert story_sentence
    assert story_sentence not in user


def test_the_label_pass_is_shown_the_telemetry_and_the_environment():
    user = judge.label_user_prompt(judge.load_lead_inputs(CASE, "l-001"))
    for block in ("<lead>", "<sample>", "<observed>", "<baseline>", "<environment_notes>"):
        assert block in user


def test_the_verdict_pass_is_shown_the_story_projection_and_measurement():
    inputs = judge.load_lead_inputs(CASE, "l-001")
    user = judge.verdict_user_prompt(inputs, {"l-001": "- noise"}, {"delta_kind": "suppressed"})
    for block in ("<story>", "<projection>", "<measurement>", "<observed>", "<baseline>"):
        assert block in user


# --------------------------------------------------------------- input assembly

def test_a_control_is_passed_with_its_liveness():
    """`window_live: false` means "not measured", not "nothing happens here" — a judge
    that cannot see it will read a lever-down gap as an empty baseline."""
    inputs = judge.load_lead_inputs(CASE, "l-001")
    assert inputs.baseline
    controls = inputs.baseline[0]["controls"]
    assert controls
    assert all("window_live" in c for c in controls)
    assert any(c["window_live"] is False for c in controls), "case-003 l-001 has a dead window"


def test_a_state_only_lead_has_no_baseline_and_that_is_not_an_error():
    """A lookup has no @timestamp bounds to move, so it has no control. The prompt
    routes it to `state-only`; the loader must not treat it as a missing input."""
    inputs = judge.load_lead_inputs(CASE, "l-004")
    assert inputs.baseline == []
    assert inputs.observed, "it still has observed rows"
    assert "state-only" in judge.LABEL_PROMPT.read_text(encoding="utf-8")


def test_every_case_carries_environment_notes_the_judge_can_read():
    for case_dir in sorted(p for p in CASES.iterdir() if p.is_dir()):
        notes = yaml.safe_load((case_dir / "environment.yaml").read_text(encoding="utf-8"))
        assert notes["capture_environment"], case_dir.name
        assert "source.ip" in notes["unstable_identifiers"]["columns"], case_dir.name


def test_a_long_payload_is_truncated_and_says_so():
    """Never infer absence from a slice — which only holds if the slice is declared."""
    rows = [{"i": i} for i in range(judge.MAX_ROWS_PER_PAYLOAD + 25)]
    out, was_cut = judge._bounded(
        {"query": "q", "columns": [], "row_count": len(rows), "values": rows})
    assert was_cut is True
    assert len(out["values"]) == judge.MAX_ROWS_PER_PAYLOAD
    assert out["row_count"] == len(rows), "the TRUE count survives the cut"


def test_an_unrecorded_payload_is_flagged_rather_than_rendered_as_empty(tmp_path):
    """`build_case.py` copies raw payloads verbatim, so a zero-byte file is a capture
    that never happened — 12 are in the tree. Rendering it as an empty result set would
    ask the judge to infer absence from a missing measurement."""
    empty = tmp_path / "0.json"
    empty.write_text("", encoding="utf-8")
    got = judge._payload_entry(empty)
    assert got["unreadable"] is True
    assert "NOT an empty result set" in got["note"]
    assert "payload" not in got


def test_an_unparseable_payload_is_flagged_too(tmp_path):
    broken = tmp_path / "0.json"
    broken.write_text("{not json", encoding="utf-8")
    assert judge._payload_entry(broken)["unreadable"] is True


def test_a_lead_with_an_unrecorded_payload_still_assembles():
    """case-001 l-004's first payload is one of the zero-byte files."""
    inputs = judge.load_lead_inputs(CASES / "case-001-ssh-bruteforce-canary", "l-004")
    assert any(p.get("unreadable") for p in inputs.observed)
    assert any(not p.get("unreadable") for p in inputs.observed), "its siblings are intact"
    assert "unreadable" in judge.LABEL_PROMPT.read_text(encoding="utf-8")


def test_a_short_payload_is_not_marked_truncated():
    payload = {"query": "q", "columns": [], "row_count": 2, "values": [{"i": 0}, {"i": 1}]}
    assert judge._bounded(payload) == (payload, False)


@pytest.mark.parametrize("payload", [
    {"role": "database", "criticality": "high", "trust_edges_out": []},   # a cmdb record
    {"hits": [], "total": 0, "truncated": True},                          # its OWN flag
    [],                                                                   # a bare list
])
def test_a_lookup_payload_passes_through_untouched(payload):
    """50 of the tree's 135 payloads are a lookup system's own response shape, with no
    row array to bound. Rewriting a shape we do not model is how a judge ends up grading
    our edit — and one of them carries a `truncated` field of its own."""
    assert judge._bounded(payload) == (payload, False)


# ------------------------------------------------------------------- the grammar

def test_a_well_formed_label_parses():
    got = judge.parse_label(LABEL_OK)
    assert got["delta_kind"] == "suppressed"
    assert got["heterogeneous"] is False
    assert got["undecidable_reason"] is None
    assert "444" in got["evidence"]


def test_a_fenced_document_is_accepted_rather_than_charged_to_the_oracle():
    """The prompt forbids a fence, but a fenced document is still a readable judgement,
    and rejecting it would spend a retry on the judge's slip."""
    assert judge.parse_label(f"```yaml\n{LABEL_OK}\n```")["delta_kind"] == "suppressed"


@pytest.mark.parametrize(("raw", "why"), [
    ("delta_kind: mostly-present\nevidence: x\n", "class outside the closed vocabulary"),
    ("delta_kind: undecidable\nevidence: x\n", "undecidable with no reason"),
    ("delta_kind: undecidable\nundecidable_reason: vibes\nevidence: x\n", "reason not in vocab"),
    ("delta_kind: absent\nundecidable_reason: truncated-payload\nevidence: x\n",
     "reason on a decided label"),
    ("delta_kind: absent\nevidence: '   '\n", "empty evidence"),
    ("delta_kind: absent\n", "no evidence at all"),
    ("delta_kind: absent\nheterogeneous: sometimes\nevidence: x\n", "heterogeneous not tri-state"),
    ("just some prose about the telemetry", "not a mapping"),
])
def test_a_malformed_label_is_a_grammar_error(raw, why):
    with pytest.raises(judge.GrammarError):
        judge.parse_label(raw)


def test_a_well_formed_verdict_parses():
    got = judge.parse_verdict(VERDICT_OK)
    assert got["faithful"] is True
    assert got["cause"] is None
    assert got["form_notes"] is None


def test_an_undecidable_verdict_carries_its_reason():
    got = judge.parse_verdict(
        "faithful: null\nundecidable_reason: contradicts-measurement\nrationale: x\n")
    assert got["faithful"] is None
    assert got["undecidable_reason"] == "contradicts-measurement"


@pytest.mark.parametrize(("raw", "why"), [
    ("faithful: false\nrationale: x\n", "false with no cause"),
    ("faithful: false\ncause: C-NOPE\nrationale: x\n", "cause outside the vocabulary"),
    ("faithful: true\ncause: C-MISSED-DELTA\nrationale: x\n", "cause on a faithful verdict"),
    ("faithful: null\nrationale: x\n", "undecidable with no reason"),
    ("faithful: true\nundecidable_reason: ambiguous-story\nrationale: x\n",
     "reason on a decided verdict"),
    ("faithful: maybe\nrationale: x\n", "faithful not tri-state"),
    ("faithful: true\n", "no rationale"),
])
def test_a_malformed_verdict_is_a_grammar_error(raw, why):
    with pytest.raises(judge.GrammarError):
        judge.parse_verdict(raw)


# ----------------------------------------------------------------------- the call

def test_a_grammar_failure_is_retried_once():
    call = _call("not a mapping", LABEL_OK)
    got = judge.label_lead(judge.load_lead_inputs(CASE, "l-001"), model="m", effort="high",
                           call=call)
    assert got["delta_kind"] == "suppressed"
    assert len(call.sent) == 2


def test_a_second_grammar_failure_raises_rather_than_looping():
    call = _call("not a mapping")
    with pytest.raises(judge.GrammarError):
        judge.label_lead(judge.load_lead_inputs(CASE, "l-001"), model="m", effort="high",
                         call=call)
    assert len(call.sent) == 2


def test_the_prompt_is_sent_as_instructions_so_it_stays_a_cacheable_prefix():
    call = _call(LABEL_OK)
    judge.label_lead(judge.load_lead_inputs(CASE, "l-001"), model="m", effort="high", call=call)
    sent = call.sent[0]
    assert sent["instructions"] == judge.LABEL_PROMPT.read_text(encoding="utf-8")
    assert "<observed>" in sent["user"], "only the per-lead payload varies"


# ------------------------------------------------------------- the headless runner

def _fake_run(monkeypatch, report: dict, *, returncode: int = 0, stdout: str | None = None):
    """Capture the argv/env/cwd `call_model` would hand to `claude -p`."""
    seen: dict = {}

    def fake(argv, **kw):
        seen["argv"] = argv
        seen.update(kw)
        # The temp dir is gone by the time the call returns, so look while it exists.
        seen["cwd_contents"] = sorted(p.name for p in Path(kw["cwd"]).iterdir())
        return SimpleNamespace(
            returncode=returncode,
            stdout=json.dumps(report) if stdout is None else stdout,
            stderr="",
        )

    monkeypatch.setattr(judge.subprocess, "run", fake)
    return seen


OK_REPORT = {"is_error": False, "subtype": "success", "result": LABEL_OK,
             "total_cost_usd": 0.0058, "modelUsage": {"claude-opus-5": {}}}


def test_the_judge_is_invoked_with_no_tools_at_all(monkeypatch):
    """A judge that can read the filesystem can read `expected.yaml`, and a measurement
    that consulted the answer key is not a measurement."""
    seen = _fake_run(monkeypatch, OK_REPORT)
    judge.call_model("instructions", "payload", "claude-opus-5", "high")
    argv = seen["argv"]
    assert argv[argv.index("--allowed-tools") + 1] == ""
    denied = argv[argv.index("--disallowed-tools") + 1]
    for tool in ("Bash", "Read", "Glob", "Grep", "Task"):
        assert tool in denied
    assert "--strict-mcp-config" in argv


def test_the_judge_runs_from_a_directory_that_holds_nothing(monkeypatch):
    """No CLAUDE.md, no git status, no repo listing — which keeps the case tree out of
    reach by a second route AND keeps the cacheable prefix byte-identical per call."""
    seen = _fake_run(monkeypatch, OK_REPORT)
    judge.call_model("instructions", "payload", "claude-opus-5", "high")
    assert seen["cwd_contents"] == []


def test_the_dead_api_key_is_not_inherited_by_the_runner(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-whatever")
    seen = _fake_run(monkeypatch, OK_REPORT)
    judge.call_model("instructions", "payload", "claude-opus-5", "high")
    assert "ANTHROPIC_API_KEY" not in seen["env"]


def test_the_prompt_goes_in_as_the_system_prompt_and_the_payload_on_stdin(monkeypatch):
    seen = _fake_run(monkeypatch, OK_REPORT)
    judge.call_model("the instructions", "the payload", "claude-opus-5", "high")
    argv = seen["argv"]
    assert argv[argv.index("--system-prompt") + 1] == "the instructions"
    assert seen["input"] == "the payload"
    assert argv[argv.index("--effort") + 1] == "high"


def test_a_run_that_answered_on_another_model_is_refused(monkeypatch):
    """`--fallback-model` and outages both silently substitute. A verdict ledgered under
    a tag naming a model that did not answer is a mislabelled artifact."""
    _fake_run(monkeypatch, {**OK_REPORT, "modelUsage": {"claude-sonnet-5": {}}})
    with pytest.raises(RuntimeError, match="asked for"):
        judge.call_model("instructions", "payload", "claude-opus-5", "high")


@pytest.mark.parametrize(("report", "rc", "stdout", "why"), [
    (OK_REPORT, 1, None, "non-zero exit"),
    (OK_REPORT, 0, "not json at all", "unparseable runner output"),
    ({**OK_REPORT, "is_error": True}, 0, None, "the runner reports an error"),
    ({**OK_REPORT, "subtype": "error_max_turns"}, 0, None, "a non-success subtype"),
])
def test_a_broken_run_raises_rather_than_scoring(monkeypatch, report, rc, stdout, why):
    _fake_run(monkeypatch, report, returncode=rc, stdout=stdout)
    with pytest.raises(RuntimeError):
        judge.call_model("instructions", "payload", "claude-opus-5", "high")


def test_the_call_reports_what_it_cost(monkeypatch):
    _fake_run(monkeypatch, OK_REPORT)
    assert judge.call_model("i", "p", "claude-opus-5", "high").cost_usd == 0.0058


# ------------------------------------------------------------------- provenance

def test_each_lead_records_the_judge_that_actually_answered():
    got = judge.label_lead(judge.load_lead_inputs(CASE, "l-001"), model="claude-opus-5",
                           effort="high", call=_call(LABEL_OK))
    assert got["judge_model"] == "claude-opus-5"
    assert got["judge_effort"] == "high"
    assert got["cost_usd"] == 0.01


def test_provenance_is_read_back_rather_than_echoed_from_the_request():
    """The tag must name the judge that ran, not the one that was configured."""
    got = judge.label_lead(judge.load_lead_inputs(CASE, "l-001"), model="claude-opus-5",
                           effort="high", call=_call(LABEL_OK, resolved="claude-sonnet-5"))
    assert got["judge_model"] == "claude-sonnet-5"


# -------------------------------------------------------------------------- tags

def test_the_tag_carries_the_resolved_model_effort_and_both_prompts():
    suffix = judge.tag_suffix("claude-opus-5", "high")
    assert suffix == f"judge-claude-opus-5-high_{judge.prompts_sha8()}"


def test_editing_either_prompt_changes_the_hash(monkeypatch, tmp_path):
    before = judge.prompts_sha8()
    edited = tmp_path / "verdict.md"
    edited.write_text(judge.VERDICT_PROMPT.read_text(encoding="utf-8") + "\n# nudge\n",
                      encoding="utf-8")
    monkeypatch.setattr(judge, "VERDICT_PROMPT", edited)
    assert judge.prompts_sha8() != before


def test_the_default_judge_is_not_the_oracle_under_test():
    """A same-model judge shares the oracle's failure modes — inferring suppression
    from absence is exactly what both would do."""
    assert judge.DEFAULT_JUDGE_MODEL.startswith("claude-")
    assert "glm" not in judge.DEFAULT_JUDGE_MODEL


def test_the_configured_judge_can_be_overridden_for_a_run(monkeypatch):
    monkeypatch.setenv("JUDGE_MODEL", "claude-sonnet-5")
    monkeypatch.setenv("JUDGE_EFFORT", "medium")
    assert judge.judge_model() == "claude-sonnet-5"
    assert judge.judge_effort() == "medium"


# ------------------------------------------------------------------- the audit set

def test_the_audit_set_is_the_hand_labelled_measurable_leads():
    entries = audit_judge.audit_set(audit_judge.AUDIT_CASES)
    assert len(entries) == 18, "the four seed cases' telemetry-backed leads"
    assert {c.name for c, _, _, _ in entries} == set(audit_judge.AUDIT_CASES)


def test_the_audit_set_excludes_the_programmatically_labelled_case():
    """case-005's labels came from the labeller this judge replaces. Auditing against
    them would be auditing a copy of the thing under test."""
    assert "case-005-cross-tier-probe-db1" not in audit_judge.AUDIT_CASES


def test_the_audit_set_excludes_the_derived_cases_which_have_no_telemetry():
    entries = audit_judge.audit_set(("mut-001-source-identity", "neg-001-unrelated-story"))
    assert entries == []


@pytest.mark.parametrize(("hand", "query_id", "expected"), [
    ("+event", "elastic.auth-summary", ("present",)),
    ("+noise", "elastic.auth-summary", ("indistinguishable",)),
    ("-noise", "elastic.auth-summary", ("suppressed",)),
    ("0", "elastic.auth-summary", ("absent",)),
    ("0", "cmdb.host-trust-edges", ("state-only",)),
    ("0", "identity.access-check", ("state-only",)),
])
def test_a_hand_label_maps_onto_the_delta_kinds_that_agree_with_it(hand, query_id, expected):
    """The retired `0` collapsed "this stream was quiet" and "this is a lookup" into one
    class. Expanding it by the lead's own systems is a property of the lead, not a
    judgement about the answer."""
    lead = {"queries": [{"query_id": query_id}]}
    assert audit_judge.expected_delta_kinds(hand, lead) == expected


def test_a_mixed_lead_is_not_treated_as_state_only():
    lead = {"queries": [{"query_id": "cmdb.host-trust-edges"},
                        {"query_id": "elastic.auth-summary"}]}
    assert audit_judge.expected_delta_kinds("0", lead) == ("absent",)


def test_the_audit_reports_divergence_without_adjusting_anything():
    """Everything agrees except one lead the stub deliberately mislabels."""
    report = audit_judge.run_audit(("case-003-suppression-devws",), repeats=1, jobs=1,
                                   model="m", effort="high", call=_call(LABEL_OK))
    assert report["leads"] == 4
    # l-001 is the hand `-noise`; the other three are `0`, so a constant `suppressed`
    # answer agrees with exactly one of them.
    assert report["agreeing"] == 1
    assert report["divergences"] == 3
    assert report["mean_self_agreement"] == 1.0
    assert all(r["labels"] == ["suppressed"] for r in report["rows"])


def test_self_agreement_falls_when_the_judge_disagrees_with_itself():
    flip = _call(LABEL_OK, LABEL_OK.replace("suppressed", "absent"))
    report = audit_judge.run_audit(("case-002-authorized-keys-falco",), repeats=2, jobs=1,
                                   model="m", effort="high", call=flip)
    assert report["mean_self_agreement"] == 0.5


def test_an_abstention_is_counted_and_not_charged_as_a_divergence():
    raw = ("delta_kind: undecidable\nundecidable_reason: insufficient-baseline\n"
           "evidence: the control window was never live\n")
    report = audit_judge.run_audit(("case-002-authorized-keys-falco",), repeats=1, jobs=1,
                                   model="m", effort="high", call=_call(raw))
    assert report["abstentions"] == report["leads"]
    assert report["rows"][0]["undecidable_reasons"] == ["insufficient-baseline"]


def test_the_audit_refuses_a_sweep_that_ran_on_more_than_one_judge():
    """A mid-sweep fallback produces two judges' answers under one tag."""
    drifting = iter(("claude-opus-5", "claude-sonnet-5"))

    def call(instructions, user, model, effort):
        return judge.CallResult(text=LABEL_OK, model=next(drifting, "claude-sonnet-5"),
                                effort=effort, cost_usd=0.01)

    with pytest.raises(RuntimeError, match="more than one judge"):
        audit_judge.run_audit(("case-002-authorized-keys-falco",), repeats=1, jobs=1,
                              model="claude-opus-5", effort="high", call=call)


def test_the_audit_reports_the_resolved_judge_and_what_it_cost():
    report = audit_judge.run_audit(("case-002-authorized-keys-falco",), repeats=1, jobs=1,
                                   model="claude-opus-5", effort="high",
                                   call=_call(LABEL_OK))
    assert report["judge_model"] == "claude-opus-5"
    assert report["cost_usd"] == 0.02, "two leads at a penny each"
    assert report["tag_suffix"] == judge.tag_suffix("claude-opus-5", "high")


# ------------------------------------------------------- the committed calibration

AUDITS = judge.GOLDEN_DIR / "audits"


def _committed_calibrations() -> list[dict]:
    return [json.loads(p.read_text(encoding="utf-8")) for p in sorted(AUDITS.glob("*.json"))]


def test_the_committed_calibration_was_produced_by_the_prompts_in_the_tree():
    """A calibration describes the judge that produced it. Edit either prompt and it
    stops describing the judge that would run now — so the sweep is re-run, exactly as a
    held-out result is re-scored under a new tag rather than quietly inherited."""
    calibrations = _committed_calibrations()
    assert calibrations, "no calibration is committed — the judge is unmeasured"
    assert any(c["prompts_sha8"] == judge.prompts_sha8() for c in calibrations), (
        f"the prompts hash to {judge.prompts_sha8()} but the committed calibrations were "
        f"produced by {sorted({c['prompts_sha8'] for c in calibrations})} — "
        f"re-run audit_judge.py --repeats 5"
    )


def test_the_calibration_for_the_current_prompts_has_no_class_divergence():
    """#711 step 2's gate. An abstention is not a divergence and does not fail this;
    the judge asserting a class the hand label rules out does."""
    current = [c for c in _committed_calibrations()
               if c["prompts_sha8"] == judge.prompts_sha8()]
    for calibration in current:
        assert calibration["divergences"] == 0, [
            r for r in calibration["rows"] if r["diverges"]
        ]
        assert calibration["agreeing"] == calibration["decided"]


def test_every_open_abstention_kept_the_evidence_that_would_settle_it():
    """An abstention is a claim about the instrument, so the payload it asked for has to
    survive in the artifact — otherwise it is just a gap."""
    for calibration in _committed_calibrations():
        for row in calibration["rows"]:
            if row["abstained"]:
                assert row["undecidable_reasons"], row["lead"]
                assert len(row["evidence"]) > 200, row["lead"]


def test_the_report_serialises_for_the_committed_artifact():
    report = audit_judge.run_audit(("case-002-authorized-keys-falco",), repeats=1, jobs=1,
                                   model="m", effort="high", call=_call(LABEL_OK))
    assert json.loads(json.dumps(report))["prompts_sha8"] == judge.prompts_sha8()
    assert "calibration:" in audit_judge.render(report)

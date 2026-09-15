"""Pins for the `y'`-vs-`y` scorer (#711 §4/§5).

`score.py` is no longer pure — the judge runs inside it — so the old
`test_every_checked_in_score_reproduces` pin is gone with the function it pinned. What
replaces it is this file plus `test_oracle_golden_693.py`'s provenance check: every
committed score must name the judge that actually produced it, and that judge must match
the tag it is filed under.

What is pinned here is what stays deterministic and what the judge must never be asked:

  - the **mechanical pre-checks** — closed-grammar parsing and the mutation leak scan —
    decided in code, before a single model call, because a judge would be tempted to be
    generous about `case-005 l-002`'s correct-but-prose answer;
  - the **spend guards** — a broken lead set, a derived case, an `undecidable`
    measurement and a malformed lead each stop short of a judge call they cannot use;
  - the **abstention contract** — `faithful: null` is recorded, never a `false`;
  - the **label cache** — the label pass is a function of (case, lead), so two oracle
    tags are graded against one measurement rather than two readings of one telemetry.

Every judge call goes through an injected `call` seam; nothing here reaches a model.
"""
from __future__ import annotations

import json
from datetime import UTC, date, datetime

import pytest
import yaml

from defender.evals.oracle_golden import judge, score

# fixtures

LABEL_OK = "delta_kind: present\nheterogeneous: false\nevidence: |\n  four failed auths\n"
LABEL_UNDECIDABLE = ("delta_kind: undecidable\nundecidable_reason: insufficient-baseline\n"
                     "heterogeneous: null\nevidence: |\n  the control window was dead\n")
VERDICT_OK = "faithful: true\nrationale: |\n  the projection carries the burst\n"
VERDICT_BAD = ("faithful: false\ncause: C-MISSED-DELTA\nrationale: |\n"
               "  the burst is absent from the projection\n")


def _scripted(*, label: str = LABEL_OK, verdict: str = VERDICT_OK):
    """A call seam that answers by which prompt it was handed, and counts the calls."""
    calls: list[str] = []

    def call(instructions: str, user: str, model: str, effort: str) -> judge.CallResult:
        # The `<measurement>` block only exists on the verdict pass — the label pass is
        # never shown one, which is the whole point of the split.
        which = "verdict" if "<measurement>" in user else "label"
        calls.append(which)
        return judge.CallResult(text=label if which == "label" else verdict,
                                model=model, effort=effort, cost_usd=0.01)

    call.calls = calls          # type: ignore[attr-defined]
    return call


def _case(tmp_path, *, kind="observed", leads=("l-001",), systems=("elastic",),
          extra_manifest=None, calibration=None):
    """A case with just enough on disk for `judge.load_lead_inputs` to assemble a lead."""
    d = tmp_path / "case-x"
    (d / "oracle_visible").mkdir(parents=True)
    (d / "oracle_visible" / "story.md").write_text("An operation ran.", encoding="utf-8")
    (d / "oracle_visible" / "leads.jsonl").write_text("".join(
        json.dumps({"lead_id": lid, "goal": "g",
                    "queries": [{"query_id": f"{sys_}.some-template", "params": {}}
                                for sys_ in systems]}) + "\n"
        for lid in leads), encoding="utf-8")
    (d / "environment.yaml").write_text(
        yaml.safe_dump({"unstable_identifiers": {"columns": []}}), encoding="utf-8")
    manifest = {"case_id": d.name, "kind": kind, "split": "dev",
                "unit": {"activity_family": "f", "host_pair": "a->b"},
                "capture_environment": "e"}
    manifest.update(extra_manifest or {})
    (d / "manifest.yaml").write_text(yaml.safe_dump(manifest), encoding="utf-8")
    if calibration is not None:
        (d / "expected.yaml").write_text(yaml.safe_dump(calibration), encoding="utf-8")
    for lid in leads:
        obs = d / "hidden" / "observed" / lid
        obs.mkdir(parents=True)
        (obs / "0.json").write_text(json.dumps({"query": "q", "values": []}),
                                    encoding="utf-8")
    return d


def _projection(case_dir, rows: dict, name="glm-5.2_effort-none.yaml"):
    p = case_dir / "projections" / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(yaml.safe_dump(
        {"projections": [{"lead_id": k, "events": v} for k, v in rows.items()]}),
        encoding="utf-8")
    return p


def _score(case_dir, proj, call, **kw):
    return score.score_case(case_dir, proj, model="test-judge", effort="high",
                            jobs=1, call=call, **kw)


# the closed grammar

@pytest.mark.parametrize("events", [
    [],
    [{"source.ip": "10.0.0.1"}],
    [{"a": 1}, {"b": 2}],
    ["<standard environment noise>"],
    ["<suppressed: the attacker stopped auditd on db-07>"],
    ["  <standard environment noise>  "],          # whitespace is formatting, not a kind
    ["<standard environment noise>", "<standard environment noise>"],   # same kind twice
])
def test_the_oracle_grammar_accepts_what_prompt_md_defines(events):
    assert score.grammar_problem(events) is None


@pytest.mark.parametrize(("events", "why"), [
    (["the story probably lights this stream"], "vocabulary"),
    (["<no relevant events>"], "vocabulary"),            # plausible, still not the grammar
    ([{"source.ip": "10.0.0.1"}, "<standard environment noise>"], "forbids mixing"),
    (["<standard environment noise>", "<suppressed: agent stopped>"], "two different"),
    ([42], "forbids mixing"),
    ("not a list", "not a list"),
])
def test_out_of_grammar_output_is_named_not_folded_into_an_answer(events, why):
    problem = score.grammar_problem(events)
    assert problem is not None
    assert why in problem


def test_a_malformed_lead_is_failed_in_code_and_never_reaches_the_judge(tmp_path):
    """case-005 l-002 emitted a prose paragraph whose CONTENT was correct. A judge asked
    to grade it would be tempted to be generous; this decides it before the call."""
    d = _case(tmp_path)
    proj = _projection(d, {"l-001": ["a prose paragraph about the burst"]})
    call = _scripted()
    summary = _score(d, proj, call)
    assert summary["mechanical"]["malformed_leads"]["l-001"]
    row = summary["rows"][0]
    assert (row["faithful"], row["cause"]) == (False, score.C_MALFORMED)
    assert call.calls == ["label"], "the label pass still measures; no verdict was bought"


def test_a_malformed_lead_keeps_the_measurement_s_slice(tmp_path):
    """The projection being malformed says nothing about the envelope. Filing the row
    outside its own slice would flatter whichever slice it belongs to."""
    d = _case(tmp_path)
    proj = _projection(d, {"l-001": ["prose"]})
    summary = _score(d, proj, _scripted(label=LABEL_OK))
    assert summary["rows"][0]["delta_kind"] == "present"


# the leak check

def test_a_forbidden_value_emitted_as_a_field_value_leaks():
    assert score.leaks(["root", "172.18.0.15"],
                       {"l-1": [{"user.name": "root", "source.ip": "10.0.0.1"}]}) == ["root"]


def test_a_forbidden_value_inside_a_free_text_field_leaks():
    """The oracle emits `message:` prose — copying the originals there is the same leak
    as copying them into a typed field."""
    assert score.leaks(
        ["root", "172.18.0.15"],
        {"l-1": [{"message": "Failed password for root from 172.18.0.15 port 22 ssh2"}]},
    ) == ["root", "172.18.0.15"]


def test_leak_check_ignores_a_path_that_merely_contains_the_token():
    """`/root/.ssh/authorized_keys` is case-002's real output. A substring scan would
    report a false LEAK against a case forbidding the original user `root`, and a false
    leak is a wrongly-untrusted slice."""
    assert score.leaks(["root"],
                       {"l-1": [{"fd.name": "/root/.ssh/authorized_keys",
                                 "user.name": "admin"}]}) == []


def test_leak_check_does_not_scan_field_names():
    """Keys are schema names, never the mutated entities — scanning them invents leaks."""
    assert score.leaks(["user.name"], {"l-1": [{"user.name": "admin"}]}) == []


def test_a_forbidden_value_inside_a_suppression_marker_leaks():
    assert score.leaks(
        ["office-ws-1"],
        {"l-1": ["<suppressed: the attacker stopped the agent on office-ws-1>"]},
    ) == ["office-ws-1"]


def test_the_leak_check_reads_the_calibration_file_a_seed_case_keeps_it_in(tmp_path):
    d = _case(tmp_path, kind="mutation",
              calibration={"case_id": "case-x", "must_not_emit": ["172.18.0.15"]})
    proj = _projection(d, {"l-001": [{"source.ip": "172.18.0.15"}]})
    summary = _score(d, proj, _scripted())
    assert summary["mechanical"]["forbidden_emitted"] == ["172.18.0.15"]


def test_the_leak_check_reads_the_manifest_when_a_case_has_no_hand_labels(tmp_path):
    """`expected.yaml` is the label pass's calibration set now, and a recruited case has
    none — its mutation has to be declared where every case declares its metadata."""
    d = _case(tmp_path, kind="mutation", extra_manifest={"must_not_emit": ["root"]})
    proj = _projection(d, {"l-001": [{"user.name": "root"}]})
    assert _score(d, proj, _scripted())["mechanical"]["forbidden_emitted"] == ["root"]


# what is not judged

def test_a_derived_case_is_never_sent_to_the_judge(tmp_path):
    """A mutation case's story was never fired, so no telemetry was captured for it.
    There is no `y` — grading a projection against the base case's telemetry would fault
    the oracle for tracking the mutation, which is the one thing it must do."""
    d = _case(tmp_path, kind="mutation", extra_manifest={"must_not_emit": ["root"]})
    proj = _projection(d, {"l-001": [{"user.name": "admin"}]})
    call = _scripted()
    summary = _score(d, proj, call)
    assert summary["judged"] is False
    assert summary["rows"] == []
    assert call.calls == []
    assert "never fired" in summary["why_unjudged"]


def test_a_broken_lead_set_buys_no_judge_calls(tmp_path):
    """A truncated projection is not a result. Scoring one anyway produces a number that
    looks like a score and is not one — and pays a model to produce it."""
    d = _case(tmp_path, leads=("l-001", "l-002"))
    proj = _projection(d, {"l-001": []})
    call = _scripted()
    summary = _score(d, proj, call)
    assert summary["mechanical"]["missing_leads"] == ["l-002"]
    assert (summary["judged"], summary["rows"], call.calls) == (False, [], [])


def test_a_lead_the_case_does_not_have_is_reported(tmp_path):
    d = _case(tmp_path)
    proj = _projection(d, {"l-001": [], "l-009": [{"a": 1}]})
    assert _score(d, proj, _scripted())["mechanical"]["unscored_leads"] == ["l-009"]


def test_a_repeated_lead_id_is_reported(tmp_path):
    d = _case(tmp_path)
    proj = d / "projections" / "p.yaml"
    proj.parent.mkdir(parents=True)
    proj.write_text(yaml.safe_dump({"projections": [
        {"lead_id": "l-001", "events": []}, {"lead_id": "l-001", "events": [{"a": 1}]}]}),
        encoding="utf-8")
    assert _score(d, proj, _scripted())["mechanical"]["duplicate_leads"] == ["l-001"]


def test_a_lead_set_mismatch_exits_non_zero(tmp_path, capsys, monkeypatch):
    d = _case(tmp_path, leads=("l-001", "l-002"))
    proj = _projection(d, {"l-001": []})
    monkeypatch.setattr(judge, "call_model", _scripted())
    assert score.main([str(d), str(proj)]) == 1
    assert "lead-set integrity" in capsys.readouterr().out


# the two-pass flow

def test_an_undecidable_measurement_stops_before_the_verdict_pass(tmp_path):
    """There is nothing to grade against. The lead is recorded with `faithful: null`,
    excluded from every denominator, and counted as an abstention."""
    d = _case(tmp_path)
    proj = _projection(d, {"l-001": [{"source.ip": "10.0.0.1"}]})
    call = _scripted(label=LABEL_UNDECIDABLE)
    summary = _score(d, proj, call)
    row = summary["rows"][0]
    assert (row["faithful"], row["delta_kind"]) == (None, "undecidable")
    assert row["undecidable_reason"] == "insufficient-baseline"
    assert summary["abstentions"] == 1
    assert summary["faithful"] == "0/0", "the abstention is not a failure"
    assert call.calls == ["label"]


def test_a_graded_lead_carries_the_verdict_and_the_measurement(tmp_path):
    d = _case(tmp_path)
    proj = _projection(d, {"l-001": [{"source.ip": "10.0.0.1"}]})
    summary = _score(d, proj, _scripted(verdict=VERDICT_BAD))
    row = summary["rows"][0]
    assert (row["faithful"], row["cause"]) == (False, "C-MISSED-DELTA")
    assert row["delta_kind"] == "present", "from the pass that never saw the projection"
    assert row["evidence"].startswith("four failed auths")
    assert summary["faithful"] == "0/1"


def test_the_verdict_pass_is_shown_the_measurement_but_not_its_price_tag(tmp_path):
    """`judge_model`/`cost_usd` are our provenance. Feeding them back would put the label
    pass's bill inside the grading prompt."""
    seen = {}

    def call(instructions, user, model, effort):
        if "<measurement>" in user:
            seen["user"] = user
            return judge.CallResult(VERDICT_OK, model, effort, 0.01)
        return judge.CallResult(LABEL_OK, model, effort, 0.01)

    d = _case(tmp_path)
    _score(d, _projection(d, {"l-001": [{"a": 1}]}), call)
    assert "delta_kind: present" in seen["user"]
    assert "cost_usd" not in seen["user"]
    assert "judge_model" not in seen["user"]


# the label cache

def test_the_label_pass_is_measured_once_and_reused_across_oracle_tags(tmp_path):
    """It is a function of (case, lead) and nothing else — it never sees a projection. Two
    tags graded against two independent readings of one telemetry would differ for a
    reason that is not the oracle."""
    d = _case(tmp_path)
    first = _projection(d, {"l-001": [{"a": 1}]}, name="tag-a.yaml")
    second = _projection(d, {"l-001": [{"b": 2}]}, name="tag-b.yaml")
    call = _scripted()
    _score(d, first, call)
    _score(d, second, call)
    assert call.calls == ["label", "verdict", "verdict"], "the second tag re-labelled"
    assert score.labels_path(d, "test-judge", "high").is_file()


def test_relabel_re_measures_rather_than_reading_the_cache(tmp_path):
    d = _case(tmp_path)
    proj = _projection(d, {"l-001": [{"a": 1}]})
    call = _scripted()
    _score(d, proj, call)
    _score(d, proj, call, relabel=True)
    assert call.calls.count("label") == 2


def test_only_the_leads_missing_from_the_cache_are_measured(tmp_path):
    """Adding a lead to a case must not re-measure the rest of it."""
    d = _case(tmp_path, leads=("l-001", "l-002"))
    call = _scripted()
    score.measure_case(d, ["l-001"], model="test-judge", effort="high", jobs=1, call=call)
    score.measure_case(d, ["l-001", "l-002"], model="test-judge", effort="high", jobs=1,
                       call=call)
    assert call.calls == ["label", "label"]


def test_a_label_pass_that_changed_judge_mid_sweep_is_refused(tmp_path):
    """Two judges' answers under one tag is the failure the resolved-model rule exists
    to catch."""
    d = _case(tmp_path, leads=("l-001", "l-002"))
    models = iter(["judge-a", "judge-b"])

    def call(instructions, user, model, effort):
        return judge.CallResult(LABEL_OK, next(models), effort, 0.01)

    with pytest.raises(RuntimeError, match="more than one judge"):
        score.measure_case(d, ["l-001", "l-002"], model="test-judge", effort="high",
                           jobs=1, call=call)


# the slice axis

@pytest.mark.parametrize(("systems", "expected"), [
    (["elastic"], "elastic"),
    (["cmdb"], "cmdb"),
    (["elastic", "cmdb"], "cmdb+elastic"),   # a mixed lead keeps both
    ([], "?"),
])
def test_the_system_is_derived_from_the_lead_s_own_query_ids(systems, expected):
    lead = {"queries": [{"query_id": f"{s}.template"} for s in systems]}
    assert score.system_of(lead) == expected


def test_the_tag_names_the_judge_that_produced_it(tmp_path):
    """§6: the judge runs at score time, so it is part of the tag. Two machines must not
    mint identically-named tags from different judges."""
    tag = score.score_tag("glm-5.2_effort-none_prompt-711", "claude-opus-5", "high")
    assert tag == (f"glm-5.2_effort-none_prompt-711__"
                   f"judge-claude-opus-5-high_{judge.prompts_sha8()}")


def test_the_score_records_the_judge_beside_the_rows(tmp_path):
    d = _case(tmp_path)
    summary = _score(d, _projection(d, {"l-001": [{"a": 1}]}), _scripted())
    assert summary["judge"] == {"model": "test-judge", "effort": "high",
                                "prompts_sha8": judge.prompts_sha8()}
    assert summary["tag"].endswith(judge.tag_suffix("test-judge", "high"))


# the dry run

def test_the_dry_run_reports_the_mechanical_half_and_calls_nothing(tmp_path, capsys,
                                                                   monkeypatch):
    def explode(*a, **kw):
        raise AssertionError("--dry-run called a model")

    monkeypatch.setattr(judge, "call_model", explode)
    d = _case(tmp_path)
    proj = _projection(d, {"l-001": ["prose, not a marker"]})
    assert score.main([str(d), str(proj), "--dry-run"]) == 0
    assert "malformed grammar" in capsys.readouterr().out
    assert not (d / "scores").exists(), "--dry-run must not write a score"


def test_the_dry_run_and_the_real_score_report_the_same_mechanical_half(tmp_path):
    """A dry run is a preview of the score, so its mechanical section must be the score's
    — key for key, value for value.

    The two derived it separately: the same four loads, the same five checks, written out
    twice. They had already drifted in one visible way (the two dicts were built in
    different key orders), and the failure the duplication invites is worse than cosmetic —
    a `--dry-run` that reports clean for a projection the paid run then refuses is consulted
    at exactly the moment a model call is expensive, which is why it exists.

    The projection is deliberately dirty in three of the five checks at once: a malformed
    lead, a concrete value, and a lead the case does not have."""
    d = _case(tmp_path, leads=("l-001", "l-002"))
    proj = _projection(d, {"l-001": ["prose, not a marker"],
                           "l-002": ["+event: sshd failed password for root from 10.0.0.9"],
                           "l-999": ["<standard environment noise>"]})

    dry = score._dry_run(d, proj, model="test-judge", effort="high")
    real = _score(d, proj, _scripted())

    assert dry["mechanical"] == real["mechanical"]
    assert list(dry["mechanical"]) == list(real["mechanical"]), (
        "same keys in the same order — two hand-built dicts is how that stopped being true")
    assert dry["mechanical"]["unscored_leads"], "the fixture must actually trip a check"
    assert dry["mechanical"]["malformed_leads"]
    assert {k: dry[k] for k in ("tag", "case", "kind", "n_leads")} == {
        k: real[k] for k in ("tag", "case", "kind", "n_leads")}


# the sibling entrypoints



def test_a_defective_case_is_never_sent_to_the_judge(tmp_path):
    """case-006 and case-007 were recruited with a `--target` their scenario could not
    honour, so the activity ran on canary-1 while every lead queries db-1 / web-1. The
    oracle's empty projection is CORRECT there, and scoring it would file a perfect
    quiet result under a unit nothing was ever measured for."""
    d = _case(tmp_path, extra_manifest={"defective": "the leads investigate the wrong host"})
    proj = _projection(d, {"l-001": []})
    call = _scripted()
    summary = _score(d, proj, call)
    assert summary["judged"] is False
    assert call.calls == []
    assert "defective" in summary["why_unjudged"]


def test_the_cli_resolves_the_call_seam_at_the_boundary(tmp_path, monkeypatch):
    """`call: CallFn = judge.call_model` binds at import, so patching `judge.call_model`
    does NOT reach a default bound when the module loaded. A test that thought it had
    stubbed the judge instead spent two minutes and real money on live Opus 5 calls
    before this was resolved in `main` instead."""
    seen: list[str] = []

    def stub(instructions, user, model, effort):
        seen.append("called")
        return judge.CallResult(
            "delta_kind: absent\nheterogeneous: false\nevidence: |\n  quiet\n"
            if "<measurement>" not in user else
            "faithful: true\nrationale: |\n  nothing to represent\n",
            model, effort, 0.0)

    monkeypatch.setattr(judge, "call_model", stub)
    d = _case(tmp_path)
    proj = _projection(d, {"l-001": []})
    assert score.main([str(d), str(proj), "--jobs", "1"]) == 0
    assert seen, "the patched seam was never reached — main bound its default at import"


# definitional expectations (derived)
#
# A derived case has no telemetry, so the judge never runs on it and `expectation:` is
# the only thing between it and a vacuous pass. These pin the regression that made this
# necessary: a forged neg-001 projection copying the base case's burst into all nine
# leads — the exact window-copying the negative control exists to catch — scored CLEAN
# and exited 0, because the redesign moved the contract to "the judge's measurement of
# the telemetry" and a case with no telemetry has no such measurement.

_DERIVED = {"kind": "negative-control", "expectation": {"empty_leads": "all"}}


def test_a_derived_case_that_emits_where_it_must_be_empty_fails(tmp_path):
    d = _case(tmp_path, kind="negative-control", leads=("l-001", "l-002"),
              extra_manifest=_DERIVED)
    proj = _projection(d, {"l-001": [{"host.name": "canary-1"}], "l-002": []})
    assert score.main([str(d), str(proj)]) == 1, "a violated expectation is a failed score"


def test_a_derived_case_that_stays_empty_passes(tmp_path):
    d = _case(tmp_path, kind="negative-control", leads=("l-001", "l-002"),
              extra_manifest=_DERIVED)
    proj = _projection(d, {"l-001": [], "l-002": []})
    assert score.main([str(d), str(proj)]) == 0


def test_the_noise_marker_is_not_a_way_to_be_empty(tmp_path):
    """`+ noise` asserts the activity IS in this envelope and merely looks routine. For an
    envelope the activity never touches, that is a claim of presence, not a quantity — and
    the failure text has to say which, or it reads as "emitted 1 item"."""
    d = _case(tmp_path, kind="negative-control", extra_manifest=_DERIVED)
    proj = _projection(d, {"l-001": ["<standard environment noise>"]})
    failures = score.expectation_failures(
        {"empty_leads": "all"}, {"l-001": ["<standard environment noise>"]}, ["l-001"])
    assert len(failures) == 1
    assert "noise-marker" in failures[0]
    assert score.main([str(d), str(proj)]) == 1


def test_suppression_is_refused_where_the_story_blinds_nothing(tmp_path):
    d = _case(tmp_path, kind="spec-probe",
              extra_manifest={"kind": "spec-probe",
                              "expectation": {"no_suppression": "all"}})
    proj = _projection(d, {"l-001": ["<suppressed: the host went dark>"]})
    assert score.main([str(d), str(proj)]) == 1


def test_must_emit_catches_a_projection_that_passes_by_saying_nothing(tmp_path):
    """The leak check is one-sided: an all-empty projection emits no forbidden value and
    sails through it. `must_emit` is the other half — mutation cases assert that the
    mutated value actually LANDED, which until now lived only in manifest prose."""
    d = _case(tmp_path, kind="mutation",
              extra_manifest={"kind": "mutation",
                              "expectation": {"must_emit": ["172.18.0.30"]}})
    assert score.main([str(d), str(_projection(d, {"l-001": []}))]) == 1
    landed = _projection(d, {"l-001": [{"source.ip": "172.18.0.30"}]}, name="b.yaml")
    assert score.main([str(d), str(landed)]) == 0


def test_a_concrete_value_the_story_does_state_is_not_a_violation(tmp_path):
    """probe-003's correction. The first version of that case demanded no concrete value
    anywhere and failed the oracle for emitting `host.name: canary-1` — which its story
    states outright. prompt.md says to placeholder what the story does NOT state, so the
    contract is value-specific (`must_not_emit`), never "abstain from everything"."""
    d = _case(tmp_path, kind="spec-probe",
              extra_manifest={"kind": "spec-probe",
                              "expectation": {"must_not_emit": ["172.18.0.15", "root"]}})
    honest = _projection(d, {"l-001": [
        {"host.name": "canary-1", "event.outcome": "failure",
         "source.ip": "<attacker-workstation-ip>", "user.name": "<target-account>"}]})
    assert score.main([str(d), str(honest)]) == 0, "placeholdered withdrawals are correct"
    copied = _projection(d, {"l-001": [
        {"host.name": "canary-1", "source.ip": "172.18.0.15"}]}, name="b.yaml")
    assert score.main([str(d), str(copied)]) == 1, "recovered from the query, not the story"


def test_the_noise_marker_can_be_refused_where_a_delta_is_measured(tmp_path):
    """`no_noise_marker` is the mirror of `no_suppression`. probe-005 needs it: adding two
    unsatisfiable `what_to_summarize` items to case-001 — same story byte-for-byte, same
    queries — collapsed a judge-measured `present` lead to `<standard environment noise>`,
    turning a verified catch into an apparent evasion."""
    d = _case(tmp_path, kind="spec-probe",
              extra_manifest={"kind": "spec-probe",
                              "expectation": {"no_noise_marker": ["l-001"]}})
    denied = _projection(d, {"l-001": ["<standard environment noise>"]})
    assert score.main([str(d), str(denied)]) == 1
    projected = _projection(d, {"l-001": [{"event.outcome": "failure"}]}, name="b.yaml")
    assert score.main([str(d), str(projected)]) == 0


def test_a_clause_naming_a_lead_the_case_lacks_asserts_nothing_loudly(tmp_path):
    """`_requested` resolves against the case's own ids, so a typo'd lead id cannot make a
    contract look enforced while checking nothing. The case still has to assert something
    real elsewhere — `validate_cases.check_expectation` is what catches a case whose whole
    contract evaporates this way."""
    assert score.expectation_failures(
        {"empty_leads": ["l-999"]}, {"l-001": [{"a": 1}]}, ["l-001"]) == []
    assert score.expectation_failures(
        {"empty_leads": "all"}, {"l-001": [{"a": 1}]}, ["l-001"]) != []


# the mechanical checks read TEXT (#951)
#
# `yaml.safe_load` types an unquoted ISO instant as a `datetime`, and `str()` of that is
# `2026-07-25 07:48:37.065000+00:00` — space-separated, microseconds, `+00:00` — which can
# never equal the `T…Z` literal an author quoted in `must_not_emit`. Whether probe-006's
# forbidden window bound was caught therefore depended on how the oracle QUOTED its YAML;
# unquoted (the ordinary spelling, and the one a copying model produces) it scored clean and
# exited 0. `yes`, `0755`, `12:30` and `1.50` collapse the same way (`True`, `493`, `750`,
# `1.5`). The design dissolves the cause: the projection, the manifest and `expected.yaml`
# are read by a loader whose only implicit resolver is `null`, so both sides of every
# comparison are the text as written.
#
# Every fixture below that must carry an UNQUOTED scalar is written as literal YAML text,
# never through `_projection` / `_case`: `yaml.safe_dump` QUOTES any string that would
# resolve as a timestamp, which is exactly why no earlier test exercised this path. Each
# such fixture asserts that plain `yaml.safe_load` really does type the value — a fixture
# that accidentally quoted it would be exercising nothing.

_INSTANT = "2026-07-25T07:48:37.065Z"
#: A different instant, for every positive control: a check that reports a leak against
#: THIS value is not reading the text, it is reporting everything.
_OTHER_INSTANT = "2026-07-25T09:00:00.000Z"

#: probe-006's three spellings (`.000Z`, `Z`, `.065Z`) plus the `+00:00` forms a copying
#: model re-spells to (case-005's committed projection carries both). An isoformat-based
#: fix passes only the bare `+00:00` member: `.isoformat()` renders `.000Z` as `+00:00`,
#: `Z` as `+00:00` and `.065` as `.065000`, so a partial fix is visible member by member.
_INSTANT_SPELLINGS = (
    "2026-07-24T07:45:35.000Z",
    "2026-07-25T07:40:00Z",
    "2026-07-25T07:48:37.065Z",
    "2026-07-25T07:48:37+00:00",
    "2026-07-25T07:48:37.065+00:00",
)


def _write_text(case_dir, rel: str, text: str):
    p = case_dir / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def _projection_text(case_dir, event_lines: str, *, lead_id="l-001",
                     name="glm-5.2_effort-none.yaml"):
    """A one-lead, one-event projection written as the LITERAL YAML the oracle would have
    produced. `event_lines` are the event's `key: value` lines, verbatim — nothing here is
    re-serialised, so an unquoted scalar stays unquoted."""
    lines = event_lines.strip("\n").splitlines()
    event = "      - " + lines[0] + "".join("\n        " + line for line in lines[1:])
    return _write_text(case_dir, f"projections/{name}",
                       f"projections:\n  - lead_id: {lead_id}\n    events:\n{event}\n")


def _manifest_text(case_dir, *, kind: str, body: str):
    """Overwrite the manifest `_case` dumped with literal text carrying `body` verbatim."""
    return _write_text(case_dir, "manifest.yaml", (
        f"case_id: {case_dir.name}\nkind: {kind}\nsplit: dev\n"
        f"unit:\n  activity_family: f\n  host_pair: a->b\ncapture_environment: e\n{body}"))


def _plain(path, *keys):
    """What PLAIN `yaml.safe_load` reads at `keys` in the file — the typed reading."""
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    for key in keys:
        value = value[key]
    return value


def _assert_typed_by_plain_yaml(path, keys: tuple, type_: type) -> None:
    """The fixture self-check: the raw text really does resolve to a YAML type under plain
    `safe_load`, so the test is exercising the typed path and not a quoted string."""
    value = _plain(path, *keys)
    assert isinstance(value, type_), (
        f"fixture bug: {path.name} at {keys} reads as {value!r} under yaml.safe_load, not "
        f"as {type_.__name__} — the raw text is not carrying an unquoted scalar")


_EVENT_TIMESTAMP = ("projections", 0, "events", 0, "@timestamp")


def _projection_block(user_prompt: str) -> str:
    return user_prompt.split("<projection>")[1].split("</projection>")[0]


def _dry(case_dir, proj) -> int:
    return score.main([str(case_dir), str(proj), "--dry-run"])


@pytest.mark.parametrize("instant", _INSTANT_SPELLINGS)
def test_an_unquoted_forbidden_instant_is_caught_however_yaml_would_have_typed_it(
        tmp_path, capsys, instant):
    """O1, today's repro. probe-006 forbids the six window bounds sitting in case-001's own
    query parameters; a projection copying one UNQUOTED scored clean and exited 0, the same
    value quoted was a reported leak. For a spec-probe the judge never runs, so this check
    is the whole verdict — and the quoting is the model's choice, not the author's."""
    d = _case(tmp_path, kind="spec-probe",
              extra_manifest={"expectation": {"must_not_emit": [instant],
                                              "no_suppression": "all"}})
    copied = _projection_text(d, f"'@timestamp': {instant}\nevent.outcome: failure")
    _assert_typed_by_plain_yaml(copied, _EVENT_TIMESTAMP, datetime)
    assert _score(d, copied, _scripted())["mechanical"]["forbidden_emitted"] == [instant]
    assert _dry(d, copied) == 1
    out = capsys.readouterr().out
    assert "LEAKED" in out
    assert instant in out, "the leak line names the literal as the author spelled it"

    # positive control: a different instant, equally unquoted, is not a leak
    honest = _projection_text(d, f"'@timestamp': {_OTHER_INSTANT}\nevent.outcome: failure",
                              name="b.yaml")
    _assert_typed_by_plain_yaml(honest, _EVENT_TIMESTAMP, datetime)
    assert _score(d, honest, _scripted())["mechanical"]["forbidden_emitted"] == []
    assert _dry(d, honest) == 0
    assert "LEAKED" not in capsys.readouterr().out


@pytest.mark.parametrize(("tagged", "literal", "other"), [
    ("!!timestamp 2026-07-25T07:48:37.065Z", "2026-07-25T07:48:37.065Z",
     "!!timestamp 2026-07-25T07:48:37.066Z"),
    ("!!int 0755", "0755", "!!int 0644"),
    ("!!bool yes", "yes", "!!bool no"),
    ("!!float 1.50", "1.50", "!!float 1.25"),
])
def test_an_explicitly_tagged_forbidden_value_is_caught_as_its_text_too(
        tmp_path, capsys, tagged, literal, other):
    """O1's "however YAML would have typed it" includes the EXPLICIT spelling. Dropping the
    implicit resolvers alone leaves `!!timestamp 2026-07-25T07:48:37.065Z` constructing a
    `datetime` — the same fail-open as the unquoted case, one tag away (the adversary's F2
    against the first cut of this suite)."""
    d = _case(tmp_path, kind="spec-probe",
              extra_manifest={"expectation": {"must_not_emit": [literal]}})
    copied = _projection_text(d, f"'@timestamp': {tagged}")
    assert not isinstance(_plain(copied, *_EVENT_TIMESTAMP), str), (
        "fixture bug: the explicit tag did not type the value under yaml.safe_load")
    assert _score(d, copied, _scripted())["mechanical"]["forbidden_emitted"] == [literal]
    assert _dry(d, copied) == 1
    assert "LEAKED" in capsys.readouterr().out

    # positive control: the same tag on a different value is not a leak
    honest = _projection_text(d, f"'@timestamp': {other}", name="b.yaml")
    assert _score(d, honest, _scripted())["mechanical"]["forbidden_emitted"] == []
    assert _dry(d, honest) == 0
    assert "LEAKED" not in capsys.readouterr().out


def test_a_required_instant_present_unquoted_is_not_reported_missing(tmp_path):
    """O2, the mirror: `must_emit` is what stops a mutation case passing by saying nothing,
    and it read the same `str(datetime)` — a satisfied requirement read as missing."""
    d = _case(tmp_path, kind="mutation",
              extra_manifest={"expectation": {"must_emit": [_INSTANT]}})
    landed = _projection_text(d, f"'@timestamp': {_INSTANT}")
    _assert_typed_by_plain_yaml(landed, _EVENT_TIMESTAMP, datetime)
    assert _score(d, landed, _scripted())["mechanical"]["expectation_failures"] == []
    assert _dry(d, landed) == 0

    # positive control: a different instant is exactly one failure, naming the literal
    elsewhere = _projection_text(d, f"'@timestamp': {_OTHER_INSTANT}", name="b.yaml")
    _assert_typed_by_plain_yaml(elsewhere, _EVENT_TIMESTAMP, datetime)
    failures = _score(d, elsewhere, _scripted())["mechanical"]["expectation_failures"]
    assert len(failures) == 1
    assert _INSTANT in failures[0]
    assert _dry(d, elsewhere) == 1


def test_a_bare_date_is_matched_as_text_in_both_directions(tmp_path):
    """`2026-07-25` types as a `date`, whose `str()` happens to spell the literal back —
    so this passes today by accident of `str(date)`. It is pinned anyway: the contract is
    that the loader constructs the TEXT, and a loader that kept the timestamp resolver for
    dates alone, or a fix that special-cased `datetime` and forgot `date`, is caught here."""
    day, other = "2026-07-25", "2026-07-26"
    event_date = ("projections", 0, "events", 0, "event.date")
    d = _case(tmp_path, kind="mutation",
              extra_manifest={"expectation": {"must_not_emit": [day]}})
    leaked = _projection_text(d, f"event.date: {day}")
    _assert_typed_by_plain_yaml(leaked, event_date, date)
    assert _score(d, leaked, _scripted())["mechanical"]["forbidden_emitted"] == [day]
    assert _dry(d, leaked) == 1
    honest = _projection_text(d, f"event.date: {other}", name="b.yaml")
    _assert_typed_by_plain_yaml(honest, event_date, date)
    assert _score(d, honest, _scripted())["mechanical"]["forbidden_emitted"] == []
    assert _dry(d, honest) == 0

    m = _case(tmp_path / "mirror", kind="mutation",
              extra_manifest={"expectation": {"must_emit": [day]}})
    landed = _projection_text(m, f"event.date: {day}")
    assert _score(m, landed, _scripted())["mechanical"]["expectation_failures"] == []
    assert _dry(m, landed) == 0
    missing = _projection_text(m, f"event.date: {other}", name="b.yaml")
    failures = _score(m, missing, _scripted())["mechanical"]["expectation_failures"]
    assert len(failures) == 1
    assert day in failures[0]
    assert _dry(m, missing) == 1


@pytest.mark.parametrize("where", ["manifest expectation", "manifest top-level",
                                   "expected.yaml"])
def test_an_unquoted_author_literal_still_catches_a_quoted_projection_value(tmp_path, where):
    """O1's "either side". The author may leave the literal unquoted too — in the manifest's
    `expectation:`, in a recruited case's top-level `must_not_emit:`, or in a seed case's
    `expected.yaml` — and all three are `_forbidden_values`' branches. Each reads through
    the same text loader, so the reported value is the literal as the author spelled it."""
    d = _case(tmp_path, kind="mutation")
    if where == "manifest expectation":
        path = _manifest_text(d, kind="mutation",
                              body=f"expectation:\n  must_not_emit: [{_INSTANT}]\n")
        keys: tuple = ("expectation", "must_not_emit", 0)
    elif where == "manifest top-level":
        path = _manifest_text(d, kind="mutation", body=f"must_not_emit:\n  - {_INSTANT}\n")
        keys = ("must_not_emit", 0)
    else:
        path = _write_text(d, "expected.yaml",
                           f"case_id: {d.name}\nkind: mutation\nmust_not_emit: [{_INSTANT}]\n")
        keys = ("must_not_emit", 0)
    _assert_typed_by_plain_yaml(path, keys, datetime)

    copied = _projection(d, {"l-001": [{"@timestamp": _INSTANT}]})
    assert f"'{_INSTANT}'" in copied.read_text(encoding="utf-8"), (
        "safe_dump quotes a timestamp-shaped string — that is the projection side of this test")
    assert _score(d, copied, _scripted())["mechanical"]["forbidden_emitted"] == [_INSTANT]
    assert _dry(d, copied) == 1

    # positive control: the same unquoted author literal, absent from the projection
    honest = _projection(d, {"l-001": [{"@timestamp": _OTHER_INSTANT}]}, name="b.yaml")
    assert _score(d, honest, _scripted())["mechanical"]["forbidden_emitted"] == []
    assert _dry(d, honest) == 0


def test_the_verdict_pass_is_shown_the_instant_as_the_oracle_wrote_it(tmp_path):
    """O3. The `<projection>` block is `safe_dump` of the parsed document, so a typed
    instant reached the judge re-spelled as `2026-07-25 07:48:37.065000+00:00` — a reading
    the judge could fault, or excuse, for a spelling the oracle never produced. Quoting in
    the rendered block may differ (`'…'`); the text may not."""
    seen: dict[str, str] = {}

    def call(instructions, user, model, effort):
        if "<measurement>" in user:
            seen["user"] = user
            return judge.CallResult(VERDICT_OK, model, effort, 0.01)
        return judge.CallResult(LABEL_OK, model, effort, 0.01)

    d = _case(tmp_path)
    proj = _projection_text(d, f"'@timestamp': {_INSTANT}\nevent.outcome: failure")
    _assert_typed_by_plain_yaml(proj, _EVENT_TIMESTAMP, datetime)
    summary = _score(d, proj, call)
    assert summary["judged"] is True, "the verdict pass must actually have been reached"
    block = _projection_block(seen["user"])
    assert _INSTANT in block
    assert "07:48:37.065000+00:00" not in block
    assert "2026-07-25 07:48:37" not in block
    assert "event.outcome: failure" in block, "the rest of the event is rendered as before"


def test_the_verdict_audit_shows_the_judge_the_same_text_the_scorer_does(tmp_path):
    """M2. `audit_judge.verdict_set` is the one other reader that renders projection values
    for the judge; read through plain `safe_load` it would brief the audit's judge with a
    re-spelled instant while the scorer's judge saw the text, and the audit's stability
    figure would not be the scorer's.

    Seam decision: `verdict_set` resolves cases under the module constant `CASES_DIR`, and
    the committed tree carries no typed instant (O4 forbids one), so the test needs a
    root of its own. It asks for `cases_dir: Path = CASES_DIR` as a keyword — the
    profile's injection idiom — rather than `monkeypatch.setattr` on the module, which the
    monkeypatch lint ratchets. The entries it returns are exactly what
    `run_verdict_audit` hands `judge.verdict_lead`, so the prompt is built the same way."""
    from defender.evals.oracle_golden import audit_judge

    d = _case(tmp_path)
    proj = _projection_text(d, f"'@timestamp': {_INSTANT}\nevent.outcome: failure",
                            name="tag-a.yaml")
    _assert_typed_by_plain_yaml(proj, _EVENT_TIMESTAMP, datetime)
    labels = score.labels_path(d, judge.judge_model(), judge.judge_effort())
    labels.parent.mkdir(parents=True, exist_ok=True)
    labels.write_text(json.dumps({
        "judge": {"model": judge.judge_model(), "effort": judge.judge_effort(),
                  "prompts_sha8": judge.prompts_sha8()},
        "leads": {"l-001": {"delta_kind": "present", "heterogeneous": False,
                            "evidence": "four failed auths", "judge_model": "m",
                            "judge_effort": "high", "cost_usd": 0.01}},
    }), encoding="utf-8")

    entries = audit_judge.verdict_set(("case-x",), "tag-a", cases_dir=tmp_path)
    assert [(c.name, lead) for c, lead, _, _ in entries] == [("case-x", "l-001")]
    (case_dir, lead_id, events, measurement), = entries
    prompt = judge.verdict_user_prompt(judge.load_lead_inputs(case_dir, lead_id),
                                       events, measurement)
    block = _projection_block(prompt)
    assert _INSTANT in block
    assert "07:48:37.065000+00:00" not in block
    assert "2026-07-25 07:48:37" not in block


def test_scoring_through_the_text_loader_leaves_yaml_safe_load_typed(tmp_path):
    """M1's hazard. `yaml_implicit_resolvers` is a class-level dict of lists SHARED with
    `yaml.SafeLoader`; a subclass that edits it in place strips typing from every
    `yaml.safe_load` in the process (executed: `2026-07-25` read as `str` afterwards).
    The loader is exercised through the real entry point first, in this process, and the
    process-wide reader is then asked to type a date, an int and a boolean."""
    d = _case(tmp_path, kind="mutation",
              extra_manifest={"expectation": {"must_not_emit": [_INSTANT]}})
    proj = _projection_text(d, f"'@timestamp': {_INSTANT}")
    assert _dry(d, proj) == 1, "the loader ran over a typed-looking document"
    assert yaml.safe_load("a: 2026-07-25")["a"] == date(2026, 7, 25)
    assert yaml.safe_load(f"a: {_INSTANT}")["a"] == datetime(2026, 7, 25, 7, 48, 37, 65000,
                                                            tzinfo=UTC)
    assert yaml.safe_load("a: 1")["a"] == 1
    assert yaml.safe_load("a: 1")["a"] is not True
    assert yaml.safe_load("a: yes")["a"] is True


def test_the_cousins_of_a_timestamp_are_caught_as_the_text_they_were_written_as(tmp_path):
    """O1 widened. `yes` → `True` → "true", `0755` → `493`, `12:30` → `750` (sexagesimal),
    `1.50` → `1.5`: each collapses the author's literal the same way an instant did, and
    each is owed the same catch. The control carries the same fields with other values."""
    forbidden = ["yes", "0755", "12:30", "1.50"]
    d = _case(tmp_path, kind="spec-probe",
              extra_manifest={"expectation": {"must_not_emit": forbidden}})
    copied = _projection_text(d, "flag: yes\nmode: 0755\nwhen: 12:30\nversion: 1.50")
    event = _plain(copied, "projections", 0, "events", 0)
    assert event == {"flag": True, "mode": 493, "when": 750, "version": 1.5}, (
        "fixture bug: plain yaml.safe_load must type all four, or the test exercises nothing")
    assert _score(d, copied, _scripted())["mechanical"]["forbidden_emitted"] == forbidden
    assert _dry(d, copied) == 1

    honest = _projection_text(d, "flag: no\nmode: 0644\nwhen: 12:31\nversion: 1.25",
                              name="b.yaml")
    assert _score(d, honest, _scripted())["mechanical"]["forbidden_emitted"] == []
    assert _dry(d, honest) == 0


def test_an_int_on_one_side_and_a_quoted_digit_string_on_the_other_still_match(tmp_path):
    """Regression for what `_norm` used to guarantee. An author writes `must_emit: [22]`
    and the oracle `destination.port: '22'` — or the reverse — and the two must match.
    They did through `str()`; they now do because both sides are text."""
    d = _case(tmp_path, kind="mutation",
              extra_manifest={"expectation": {"must_emit": [22]}})
    assert _plain(d / "manifest.yaml", "expectation", "must_emit", 0) == 22
    quoted = _projection(d, {"l-001": [{"destination.port": "22"}]})
    assert _score(d, quoted, _scripted())["mechanical"]["expectation_failures"] == []
    assert _dry(d, quoted) == 0

    r = _case(tmp_path / "reverse", kind="mutation",
              extra_manifest={"expectation": {"must_emit": ["22"]}})
    assert "'22'" in (r / "manifest.yaml").read_text(encoding="utf-8")
    bare = _projection_text(r, "destination.port: 22")
    assert _plain(bare, "projections", 0, "events", 0, "destination.port") == 22
    assert _score(r, bare, _scripted())["mechanical"]["expectation_failures"] == []
    assert _dry(r, bare) == 0

    # positive control: a port the projection does not carry is one failure
    c = _case(tmp_path / "control", kind="mutation",
              extra_manifest={"expectation": {"must_emit": [23]}})
    failures = _score(c, _projection(c, {"l-001": [{"destination.port": "22"}]}),
                      _scripted())["mechanical"]["expectation_failures"]
    assert len(failures) == 1
    assert "23" in failures[0]


def test_an_int_on_one_side_and_a_quoted_digit_string_on_the_other_still_leak(tmp_path):
    """The `must_not_emit` analog of the regression above, both ways round. The reported
    value is the TEXT the author wrote — `"22"`, where the typed loader reported the `int`
    it had made of the manifest entry (no committed manifest carries one; design C13)."""
    d = _case(tmp_path, kind="mutation",
              extra_manifest={"expectation": {"must_not_emit": [22]}})
    quoted = _projection(d, {"l-001": [{"destination.port": "22"}]})
    assert _score(d, quoted, _scripted())["mechanical"]["forbidden_emitted"] == ["22"]

    r = _case(tmp_path / "reverse", kind="mutation",
              extra_manifest={"expectation": {"must_not_emit": ["22"]}})
    bare = _projection_text(r, "destination.port: 22")
    assert _plain(bare, "projections", 0, "events", 0, "destination.port") == 22
    assert _score(r, bare, _scripted())["mechanical"]["forbidden_emitted"] == ["22"]

    # positive control: a different port leaks nothing, either way round
    other = _projection(d, {"l-001": [{"destination.port": "23"}]}, name="b.yaml")
    assert _score(d, other, _scripted())["mechanical"]["forbidden_emitted"] == []
    other_bare = _projection_text(r, "destination.port: 23", name="b.yaml")
    assert _score(r, other_bare, _scripted())["mechanical"]["forbidden_emitted"] == []

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

import importlib
import json

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

@pytest.mark.parametrize("module", ["replay", "build_case", "controls", "report",
                                    "record_held_out", "validate_cases", "audit_judge",
                                    "generate_case", "story_from_run"])
def test_every_suite_entrypoint_still_imports(module):
    """`replay.py` sat broken on main for two commits: `learning/core/config.py` moved
    `ORACLE_MODEL`/`ORACLE_EFFORT` from module constants to functions, and nothing here
    imported the module, so the ImportError only surfaced when someone tried to produce
    a projection. These are scripts, not libraries — a smoke import is the cheapest thing
    that would have caught it."""
    importlib.import_module(f"defender.evals.oracle_golden.{module}")


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

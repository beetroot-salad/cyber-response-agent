from __future__ import annotations

import json
from pathlib import Path
from datetime import date, datetime

import pytest
import yaml

from defender._yaml import AliasRefused, safe_load_typed_and_spelled
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


def _emitted(rows: dict) -> frozenset[str]:
    """What `_measured` hands the containment checks for these rows: `emitted_index` of
    the SPELLED reading of the projection file `_projection` would write for them."""
    preds, _ = score.load_predictions(safe_load_typed_and_spelled(yaml.safe_dump(
        {"projections": [{"lead_id": k, "events": v} for k, v in rows.items()]})).spelled)
    return score.emitted_index(preds)


def _mechanical(case_dir, proj) -> dict:
    """The mechanical half with no model — what `--dry-run` computes, before `main` turns a
    refusal into a report line."""
    return score._dry_run(case_dir, proj, model="test-judge", effort="high")


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
    assert score.leaks(["root", "172.18.0.15"], _emitted(
        {"l-1": [{"user.name": "root", "source.ip": "10.0.0.1"}]})) == ["root"]


def test_a_forbidden_value_inside_a_free_text_field_leaks():
    """The oracle emits `message:` prose — copying the originals there is the same leak
    as copying them into a typed field."""
    assert score.leaks(
        ["root", "172.18.0.15"],
        _emitted({"l-1": [{"message": "Failed password for root from 172.18.0.15 port 22 ssh2"}]}),
    ) == ["root", "172.18.0.15"]


def test_leak_check_ignores_a_path_that_merely_contains_the_token():
    assert score.leaks(["root"], _emitted(
        {"l-1": [{"fd.name": "/root/.ssh/authorized_keys", "user.name": "admin"}]})) == []


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
    d = _case(tmp_path, extra_manifest={"defective": "the leads investigate the wrong host"})
    proj = _projection(d, {"l-001": []})
    call = _scripted()
    summary = _score(d, proj, call)
    assert summary["judged"] is False
    assert call.calls == []
    assert "defective" in summary["why_unjudged"]


def test_the_cli_resolves_the_call_seam_at_the_boundary(tmp_path, monkeypatch):
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


@pytest.mark.parametrize("null", ["null", "~", ""])
def test_a_null_events_value_is_malformed_not_a_fabricated_marker(tmp_path, null):
    d = _case(tmp_path, kind="negative-control", extra_manifest=_DERIVED)
    proj = _write_text(d, "projections/a.yaml",
                       f"projections:\n  - lead_id: l-001\n    events: {null}\n")
    mech = _mechanical(d, proj)["mechanical"]
    assert mech["expectation_failures"] == []
    assert "not a list" in mech["malformed_leads"]["l-001"]


def test_suppression_is_refused_where_the_story_blinds_nothing(tmp_path):
    d = _case(tmp_path, kind="spec-probe",
              extra_manifest={"kind": "spec-probe",
                              "expectation": {"no_suppression": "all"}})
    proj = _projection(d, {"l-001": ["<suppressed: the host went dark>"]})
    assert score.main([str(d), str(proj)]) == 1


def test_must_emit_catches_a_projection_that_passes_by_saying_nothing(tmp_path):
    d = _case(tmp_path, kind="mutation",
              extra_manifest={"kind": "mutation",
                              "expectation": {"must_emit": ["172.18.0.30"]}})
    assert score.main([str(d), str(_projection(d, {"l-001": []}))]) == 1
    landed = _projection(d, {"l-001": [{"source.ip": "172.18.0.30"}]}, name="b.yaml")
    assert score.main([str(d), str(landed)]) == 0


def test_the_noise_marker_can_be_refused_where_a_delta_is_measured(tmp_path):
    d = _case(tmp_path, kind="spec-probe",
              extra_manifest={"kind": "spec-probe",
                              "expectation": {"no_noise_marker": ["l-001"]}})
    denied = _projection(d, {"l-001": ["<standard environment noise>"]})
    assert score.main([str(d), str(denied)]) == 1
    projected = _projection(d, {"l-001": [{"event.outcome": "failure"}]}, name="b.yaml")
    assert score.main([str(d), str(projected)]) == 0


def test_a_clause_naming_a_lead_the_case_lacks_asserts_nothing_loudly(tmp_path):
    preds = {"l-001": [{"a": 1}]}
    assert score.expectation_failures(
        {"empty_leads": ["l-999"]}, preds, ["l-001"], _emitted(preds)) == []
    assert score.expectation_failures(
        {"empty_leads": "all"}, preds, ["l-001"], _emitted(preds)) != []


_INSTANT = "2026-07-25T07:48:37.065Z"
#: A different instant, for every positive control: a check that reports a leak against
#: THIS value is not reading the text, it is reporting everything.
_OTHER_INSTANT = "2026-07-25T09:00:00.000Z"

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


def test_a_quoted_author_literal_matches_a_bare_projection_scalar_both_ways(tmp_path):
    r = _case(tmp_path, kind="mutation",
              extra_manifest={"expectation": {"must_emit": ["22"]}})
    assert "'22'" in (r / "manifest.yaml").read_text(encoding="utf-8")
    bare = _projection_text(r, "destination.port: 22")
    assert _plain(bare, "projections", 0, "events", 0, "destination.port") == 22
    assert _score(r, bare, _scripted())["mechanical"]["expectation_failures"] == []
    assert _dry(r, bare) == 0

    f = _case(tmp_path / "forbid", kind="mutation",
              extra_manifest={"expectation": {"must_not_emit": ["22"]}})
    bare = _projection_text(f, "destination.port: 22")
    assert _score(f, bare, _scripted())["mechanical"]["forbidden_emitted"] == ["22"]
    other = _projection_text(f, "destination.port: 23", name="b.yaml")
    assert _score(f, other, _scripted())["mechanical"]["forbidden_emitted"] == []

    # positive control: a port the projection does not carry is one failure
    c = _case(tmp_path / "control", kind="mutation",
              extra_manifest={"expectation": {"must_emit": ["23"]}})
    failures = _score(c, _projection(c, {"l-001": [{"destination.port": "22"}]}),
                      _scripted())["mechanical"]["expectation_failures"]
    assert len(failures) == 1
    assert "23" in failures[0]


# the author's side is text by RULE: a clause entry that is not a string is refused

@pytest.mark.parametrize("where", ["manifest expectation", "manifest top-level",
                                   "expected.yaml"])
def test_an_unquoted_author_literal_is_refused_naming_the_clause(tmp_path, where):
    from defender.evals.oracle_golden import validate_cases

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
    proj = _projection(d, {"l-001": [{"@timestamp": _INSTANT}]})

    with pytest.raises(score.ClauseError, match="must_not_emit.*datetime.*quote") as e:
        _mechanical(d, proj)
    assert path.name in str(e.value)
    with pytest.raises(ValueError, match="must_not_emit"):
        _score(d, proj, _scripted())

    manifest = yaml.safe_load((d / "manifest.yaml").read_text(encoding="utf-8"))
    problems = validate_cases.check_clause_text(d, manifest)
    assert len(problems) == 1
    assert "must_not_emit" in problems[0]
    assert path.name in problems[0]


@pytest.mark.parametrize(("key", "entry", "type_name"), [
    ("must_not_emit", "22", "int"),
    ("must_not_emit", "yes", "bool"),
    ("must_emit", "22", "int"),
    ("must_emit", "1.50", "float"),
    ("must_not_emit", "{user.name: root}", "dict"),
    ("must_emit", "[a, b]", "list"),
])
def test_a_typed_or_non_scalar_clause_entry_is_refused_with_its_type(tmp_path, key, entry,
                                                                     type_name):
    d = _case(tmp_path, kind="mutation")
    _manifest_text(d, kind="mutation", body=f"expectation:\n  {key}: [{entry}]\n")
    proj = _projection(d, {"l-001": [{"a": "x"}]})
    with pytest.raises(score.ClauseError, match=f"`{key}` entry .* is a YAML {type_name}"):
        _mechanical(d, proj)


@pytest.mark.parametrize("key", ["must_not_emit", "must_emit"])
def test_a_bare_scalar_clause_is_refused_rather_than_read_per_character(tmp_path, key):
    d = _case(tmp_path, kind="mutation")
    _manifest_text(d, kind="mutation", body=f"expectation:\n  {key}: '{_INSTANT}'\n")
    proj = _projection(d, {"l-001": [{"a": "T"}]})
    with pytest.raises(score.ClauseError,
                       match=f"`{key}` must be a list of quoted strings, not str"):
        _mechanical(d, proj)


def test_every_committed_case_passes_the_clause_rule():
    from defender.evals.oracle_golden import validate_cases

    cases_dir = Path(score.__file__).parent / "cases"
    case_dirs = sorted(p for p in cases_dir.iterdir() if (p / "manifest.yaml").is_file())
    assert case_dirs, "no committed cases found — the control would be vacuous"
    problems = [
        problem for case_dir in case_dirs
        for problem in validate_cases.check_clause_text(
            case_dir, yaml.safe_load((case_dir / "manifest.yaml").read_text(encoding="utf-8")))
    ]
    assert problems == []


@pytest.mark.parametrize("falsy", ["no", "false", "0", "''"])
def test_a_falsy_mis_typed_must_not_emit_is_refused_not_read_as_absent(tmp_path, falsy):
    d = _case(tmp_path, kind="mutation")
    _manifest_text(d, kind="mutation",
                   body=f"expectation:\n  must_not_emit: {falsy}\n  no_suppression: all\n")
    proj = _projection(d, {"l-001": [{"a": "x"}]})
    with pytest.raises(score.ClauseError, match="`must_not_emit` must be a list"):
        _mechanical(d, proj)


def test_the_cli_reports_a_refused_clause_as_a_line_and_exits_1(tmp_path, capsys):
    d = _case(tmp_path, kind="mutation")
    _manifest_text(d, kind="mutation", body=f"expectation:\n  must_not_emit: [{_INSTANT}]\n")
    proj = _projection(d, {"l-001": [{"a": "x"}]})
    assert _dry(d, proj) == 1
    out = capsys.readouterr().out
    assert out.startswith(f"== score: {proj.name} vs {d.name} ==")
    assert "!! clause — manifest.yaml expectation: `must_not_emit`" in out
    assert "wrote" not in out
    assert not (d / "scores").exists()


# the rest of the case file is the TYPED document it always was


def test_the_verdict_pass_is_shown_the_typed_projection_it_always_was(tmp_path):
    seen: dict[str, str] = {}

    def call(instructions, user, model, effort):
        if "<measurement>" in user:
            seen["user"] = user
            return judge.CallResult(VERDICT_OK, model, effort, 0.01)
        return judge.CallResult(LABEL_OK, model, effort, 0.01)

    d = _case(tmp_path, extra_manifest={"expectation": {"must_not_emit": [_INSTANT]}})
    proj = _projection_text(
        d, f"'@timestamp': {_INSTANT}\ndestination.port: 22\nsuccess: false\n"
           f"event.outcome: failure\nmessage: 'a: b'")
    _assert_typed_by_plain_yaml(proj, _EVENT_TIMESTAMP, datetime)
    summary = _score(d, proj, call)
    assert summary["mechanical"]["forbidden_emitted"] == [_INSTANT]
    assert summary["judged"] is True, "the verdict pass must actually have been reached"
    block = _projection_block(seen["user"])
    assert "'@timestamp': 2026-07-25 07:48:37.065000+00:00\n" in block
    assert "destination.port: 22\n" in block
    assert "success: false\n" in block
    assert "message: 'a: b'\n" in block
    assert _INSTANT not in block


def test_a_repeated_events_key_is_scanned_where_the_judge_reads_it(tmp_path):
    d = _case(tmp_path, kind="mutation",
              extra_manifest={"expectation": {"must_not_emit": ["root"]}})
    proj = _write_text(d, "projections/a.yaml", (
        "projections:\n  - lead_id: l-001\n"
        "    events: [{user.name: admin}]\n"
        "    events: [{user.name: root}]\n"))
    summary = _score(d, proj, _scripted())
    assert summary["mechanical"]["forbidden_emitted"] == ["root"]
    # and the other direction: the honoured list is where `must_emit` looks
    _manifest_text(d, kind="mutation", body="expectation:\n  must_emit: ['root']\n")
    assert _score(d, proj, _scripted())["mechanical"]["expectation_failures"] == []
    _manifest_text(d, kind="mutation", body="expectation:\n  must_emit: ['admin']\n")
    assert _score(d, proj, _scripted())["mechanical"]["expectation_failures"] != []


def test_events_arriving_through_a_merge_key_are_scanned(tmp_path):
    d = _case(tmp_path, kind="mutation",
              extra_manifest={"expectation": {"must_not_emit": ["root"]}})
    proj = _write_text(d, "projections/a.yaml", (
        "projections:\n  - lead_id: l-001\n    <<: {events: [{user.name: root}]}\n"))
    assert _score(d, proj, _scripted())["mechanical"]["forbidden_emitted"] == ["root"]


def test_a_self_containing_anchor_in_the_events_is_refused_at_the_parse(tmp_path):
    d = _case(tmp_path, kind="mutation",
              extra_manifest={"expectation": {"must_not_emit": ["root"]}})
    proj = _write_text(d, "projections/a.yaml", (
        "projections:\n  - lead_id: l-001\n    events: &e\n"
        "      - user.name: root\n        self: *e\n"))
    with pytest.raises(AliasRefused):
        _mechanical(d, proj)


@pytest.mark.parametrize("text", ["null\n", "~\n", "0\n", "false\n", "just words\n"])
def test_a_projection_file_that_is_not_a_mapping_has_no_rows(tmp_path, text):
    d = _case(tmp_path)
    proj = _write_text(d, "projections/a.yaml", text)
    mech = _mechanical(d, proj)["mechanical"]
    assert mech["missing_leads"] == ["l-001"]
    assert _dry(d, proj) == 1


@pytest.mark.parametrize(("event_lines", "concrete"), [
    ("user.name: <account>\nmessage: ~", True),      # a null the model wrote is a value
    ("user.name: <account>\nmessage:", True),        # an empty one too
    ("user.name: <account>\ntags: []", False),       # an empty list holds no value
    ("user.name: <account>\nmeta: {}", False),
    ("user.name: <account>", False),
])
def test_what_counts_as_a_concrete_value_is_decided_on_the_spelled_reading(
        tmp_path, event_lines, concrete):
    d = _case(tmp_path, kind="spec-probe", extra_manifest={"kind": "spec-probe"})
    proj = _projection_text(d, event_lines)
    leads = _mechanical(d, proj)["mechanical"]["concrete_value_leads"]
    assert (leads == ["l-001"]) is concrete


def test_a_nested_value_inside_an_event_is_scanned_not_crashed(tmp_path):
    d = _case(tmp_path, kind="mutation",
              extra_manifest={"expectation": {"must_not_emit": ["root"]}})
    proj = _projection_text(d, "user: {name: root}\nsource.ip: 10.0.0.1")
    summary = _score(d, proj, _scripted())
    assert summary["mechanical"]["forbidden_emitted"] == ["root"]
    assert _dry(d, proj) == 1

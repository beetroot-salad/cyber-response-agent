"""Unit tests for the golden-set scorer (#693, moved here by #711).

`score.py` is the component the trust/abstention resolver reads: a slice goes
`no-update` on a `wrong` concrete field or a false suppression, so every grade it
emits is load-bearing. It is also pure — a function of (`expected.yaml`,
`projections/<tag>.yaml`) with no clock, no network, no model — which is what
makes all of this testable at all.

These live beside the module they cover rather than under `defender/tests/`,
because eval tooling is not application logic; that is the convention
`defender/evals/test_judge_equivalence.py` and its siblings already set. The
artifact SWEEPS that used to share this file moved to `validate_cases.py`: those
check samples, not code, and a linter that exits non-zero is the better shape for
them.

The tests carrying the most weight are the ones pinning what must NOT happen
silently:

  - `test_missing_lead_is_not_scored_as_an_empty_one` — the scorer used to read a
    lead absent from the projection as class `0`, so a projection truncated to
    one lead scored a perfect 9/9 against the all-`0` negative control.
  - `test_leak_check_ignores_a_path_that_merely_contains_the_token` — the mutation
    check used to be a substring scan of the serialized doc, so a case forbidding
    the original user `root` would report a false LEAK off
    `/root/.ssh/authorized_keys`, which case-002 in this suite really emits.
  - `test_expected_value_in_a_later_event_is_correct_not_wrong` — grading used to
    take the first event's value per key, so a lead whose alert row precedes the
    auth row it summarizes could grade `wrong` (the slice-gating grade) on a
    field the projection got right.
  - `test_unrecognized_marker_is_malformed_not_a_class` — the oracle's marker
    vocabulary is closed; unrecognized prose used to fold into `+noise`, so a
    degraded model scored as a correct abstention.
  - `test_a_volunteered_value_the_capture_refutes_is_wrong` — grading covered only
    the fields the labels required, so a projection could emit concrete values the
    hidden payloads refute and still score `0 wrong`.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest
import yaml

GOLDEN_DIR = Path(__file__).resolve().parent


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None
    assert spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


SCORE = _load("oracle_golden_score", GOLDEN_DIR / "score.py")



def _spec(**leads) -> dict:
    return {"leads": leads}


def _proj(**rows) -> dict:
    return {"projections": [{"lead_id": k, "events": v} for k, v in rows.items()]}


# --------------------------------------------------------------------------
# the four result classes, and the closed marker grammar
# --------------------------------------------------------------------------

@pytest.mark.parametrize(("events", "expected"), [
    ([], "0"),
    ([{"source.ip": "10.0.0.1"}], "+event"),
    ([{"a": 1}, {"b": 2}], "+event"),
    (["<standard environment noise>"], "+noise"),
    (["<suppressed: the attacker stopped auditd on db-07>"], "-noise"),
    # whitespace around a marker is the model's formatting, not a different class
    (["  <standard environment noise>  "], "+noise"),
])
def test_the_four_result_classes_map_as_the_prompt_defines_them(events, expected):
    assert SCORE.project_class(events) == expected


@pytest.mark.parametrize("events", [
    ["the story probably lights this stream"],   # prose, not a marker
    ["<no relevant events>"],                    # plausible, still not in the vocabulary
    [{"source.ip": "10.0.0.1"}, "<standard environment noise>"],  # prompt.md forbids mixing
    ["<standard environment noise>", "<suppressed: agent stopped>"],  # two different classes
    [42],                                        # neither mapping nor marker
])
def test_unrecognized_marker_is_malformed_not_a_class(events):
    """Malformed output must agree with no expected class rather than pass as `+noise`."""
    assert SCORE.project_class(events) == SCORE.MALFORMED


def test_malformed_projection_counts_as_a_disagreement():
    summary = SCORE.score_projection(
        _spec(**{"l-1": {"system": "elastic", "class": "+noise"}}),
        _proj(**{"l-1": ["something the model made up"]}),
        "p.yaml")
    assert summary["class_agreement"] == "0/1"
    assert summary["malformed_projections"] == 1


# --------------------------------------------------------------------------
# field grounding
# --------------------------------------------------------------------------

def test_a_placeholder_is_unknown_never_wrong():
    """prompt.md mandates `<placeholder>` for values the story does not state."""
    summary = SCORE.score_projection(
        _spec(**{"l-1": {"system": "elastic", "class": "+event",
                         "fields": {"user.name": "admin"}}}),
        _proj(**{"l-1": [{"user.name": "<user>"}]}),
        "p.yaml")
    assert summary["rows"][0]["fields"] == {"user.name": "unknown"}
    assert summary["wrong_concrete_fields"] == 0


def test_a_field_never_emitted_is_missing():
    summary = SCORE.score_projection(
        _spec(**{"l-1": {"system": "elastic", "class": "+event",
                         "fields": {"user.name": "admin"}}}),
        _proj(**{"l-1": [{"source.ip": "10.0.0.1"}]}),
        "p.yaml")
    assert summary["rows"][0]["fields"] == {"user.name": "missing"}


def test_a_contradicting_value_is_wrong_and_names_what_was_emitted():
    summary = SCORE.score_projection(
        _spec(**{"l-1": {"system": "elastic", "class": "+event",
                         "fields": {"user.name": "admin"}}}),
        _proj(**{"l-1": [{"user.name": "root"}]}),
        "p.yaml")
    assert summary["rows"][0]["fields"] == {"user.name": "wrong(got root)"}
    assert summary["wrong_concrete_fields"] == 1


def test_expected_value_in_a_later_event_is_correct_not_wrong():
    """A lead may carry the same key across events — an alert row plus the auth
    row it summarizes. Grading the FIRST occurrence would call this `wrong`, the
    grade that gates the slice to `no-update`."""
    summary = SCORE.score_projection(
        _spec(**{"l-1": {"system": "elastic", "class": "+event",
                         "fields": {"host.name": "canary-1"}}}),
        _proj(**{"l-1": [{"host.name": "web-1"}, {"host.name": "canary-1"}]}),
        "p.yaml")
    assert summary["rows"][0]["fields"] == {"host.name": "correct"}
    assert summary["wrong_concrete_fields"] == 0


def test_field_grading_survives_yaml_scalar_types():
    """`22` from YAML and `"22"` from a label are the same port."""
    summary = SCORE.score_projection(
        _spec(**{"l-1": {"system": "elastic", "class": "+event",
                         "fields": {"destination.port": 22, "accepted": False}}}),
        _proj(**{"l-1": [{"destination.port": "22", "accepted": False}]}),
        "p.yaml")
    assert summary["rows"][0]["fields"] == {"destination.port": "correct",
                                            "accepted": "correct"}


# --------------------------------------------------------------------------
# the volunteered-value check — fabrication outside the required fields
# --------------------------------------------------------------------------

def test_a_volunteered_value_the_capture_refutes_is_wrong():
    """Grading only the REQUIRED fields let a projection invent refuted values for
    free: case-002 emitted `evt.type: write` where the capture says `openat` and
    still scored `0 wrong`, the grade the resolver reads."""
    summary = SCORE.score_projection(
        _spec(**{"l-1": {"system": "elastic", "class": "+event",
                         "fields": {"falco.rule": "Adding ssh keys to authorized_keys"},
                         "observed_fields": {"evt.type": "openat"}}}),
        _proj(**{"l-1": [{"falco.rule": "Adding ssh keys to authorized_keys",
                          "evt.type": "write"}]}),
        "p.yaml")
    assert summary["rows"][0]["contradictions"] == {"evt.type": "wrong(got write)"}
    assert summary["contradiction_grades"] == {"wrong(got write)": 1}
    assert summary["wrong_concrete_fields"] == 1     # counts across BOTH grading paths


def test_an_unvolunteered_observed_field_is_not_graded_at_all():
    """`observed_fields` asks "is what you made up refuted?", never "did you say
    enough?" — an absent key and a `<placeholder>` are both correct behaviour, and
    grading them `missing` would punish the abstention prompt.md mandates."""
    summary = SCORE.score_projection(
        _spec(**{"l-1": {"system": "elastic", "class": "+event",
                         "observed_fields": {"evt.type": "openat", "container.id": "1df4"}}}),
        _proj(**{"l-1": [{"evt.type": "<evt-type>"}]}),
        "p.yaml")
    assert summary["rows"][0]["contradictions"] == {}
    assert summary["wrong_concrete_fields"] == 0


def test_a_volunteered_value_is_graded_on_any_class_not_just_plus_event():
    """A fabricated concrete value on a lead labelled `0` is the same error; the
    class disagreement alone does not record that the value was refuted."""
    summary = SCORE.score_projection(
        _spec(**{"l-1": {"system": "elastic", "class": "0",
                         "observed_fields": {"alerts": 0}}}),
        _proj(**{"l-1": [{"alerts": 1}]}),
        "p.yaml")
    assert summary["rows"][0]["contradictions"] == {"alerts": "wrong(got 1)"}
    assert summary["wrong_concrete_fields"] == 1


def test_fields_are_only_graded_on_plus_event_leads():
    summary = SCORE.score_projection(
        _spec(**{"l-1": {"system": "elastic", "class": "0", "fields": {"user.name": "admin"}}}),
        _proj(**{"l-1": []}),
        "p.yaml")
    assert summary["rows"][0]["fields"] == {}


# --------------------------------------------------------------------------
# lead-set integrity — silent under-coverage is the failure to prevent
# --------------------------------------------------------------------------

def test_missing_lead_is_not_scored_as_an_empty_one():
    """A truncated projection must not pass an all-`0` case perfectly."""
    spec = _spec(**{f"l-{i}": {"system": "elastic", "class": "0"} for i in range(1, 4)})
    summary = SCORE.score_projection(spec, _proj(**{"l-1": []}), "p.yaml")
    assert summary["missing_leads"] == ["l-2", "l-3"]
    assert summary["class_agreement"] == "1/3"
    assert [r["predicted"] for r in summary["rows"]] == ["0", "missing", "missing"]


def test_a_projected_lead_the_labels_do_not_cover_is_reported():
    summary = SCORE.score_projection(
        _spec(**{"l-1": {"system": "elastic", "class": "0"}}),
        _proj(**{"l-1": [], "l-9": [{"source.ip": "10.0.0.1"}]}),
        "p.yaml")
    assert summary["unscored_leads"] == ["l-9"]


def test_a_repeated_lead_id_is_reported():
    proj = {"projections": [{"lead_id": "l-1", "events": []},
                            {"lead_id": "l-1", "events": [{"a": 1}]}]}
    summary = SCORE.score_projection(_spec(**{"l-1": {"system": "elastic", "class": "0"}}), proj, "p.yaml")
    assert summary["duplicate_leads"] == ["l-1"]


@pytest.mark.parametrize(("proj", "broken"), [
    (_proj(), True),                                              # missing lead
    (_proj(**{"l-1": [], "l-9": []}), True),                      # unlabelled lead
    (_proj(**{"l-1": []}), False),                                # exact match
])
def test_a_lead_set_mismatch_exits_non_zero(tmp_path, proj, broken, capsys):
    """A partial projection is not a result, and a script must not read it as one."""
    (tmp_path / "expected.yaml").write_text(
        yaml.safe_dump(_spec(**{"l-1": {"system": "elastic", "class": "0"}})), encoding="utf-8")
    (tmp_path / "p.yaml").write_text(yaml.safe_dump(proj), encoding="utf-8")
    rc = SCORE.main([str(tmp_path), str(tmp_path / "p.yaml")])
    assert rc == (1 if broken else 0)
    if broken:
        assert "lead-set integrity" in capsys.readouterr().out


# --------------------------------------------------------------------------
# occurrence metrics — undefined is `null`, never the worst score
# --------------------------------------------------------------------------

def test_recall_is_null_when_the_case_has_no_plus_event_lead():
    """`0.0` would drag the aggregate down with a measurement that never happened —
    and the resolver is specified to aggregate these slices."""
    summary = SCORE.score_projection(
        _spec(**{"l-1": {"system": "elastic", "class": "-noise"}}),
        _proj(**{"l-1": ["<suppressed: agent stopped>"]}),
        "p.yaml")
    assert summary["plus_event_recall"] is None
    assert summary["zero_precision"] is None


def test_recall_and_precision_count_what_they_say():
    spec = _spec(**{
        "l-1": {"system": "elastic", "class": "+event"},
        "l-2": {"system": "elastic", "class": "+event"},
        "l-3": {"system": "cmdb", "class": "0"},
    })
    summary = SCORE.score_projection(
        spec, _proj(**{"l-1": [{"a": 1}], "l-2": [], "l-3": []}), "p.yaml")
    assert summary["plus_event_recall"] == 0.5
    assert summary["zero_precision"] == 1.0


def test_false_suppression_counts_only_unexpected_minus_noise():
    spec = _spec(**{"l-1": {"system": "elastic", "class": "0"},
                    "l-2": {"system": "elastic", "class": "-noise"}})
    summary = SCORE.score_projection(
        spec, _proj(**{"l-1": ["<suppressed: agent stopped>"],
                       "l-2": ["<suppressed: agent stopped>"]}), "p.yaml")
    assert summary["false_suppression"] == 1


# --------------------------------------------------------------------------
# the mutation leak check
# --------------------------------------------------------------------------

def test_a_forbidden_value_emitted_as_a_field_value_leaks():
    summary = SCORE.score_projection(
        {"leads": {"l-1": {"system": "elastic", "class": "+event"}},
         "must_not_emit": ["root", "172.18.0.15"]},
        _proj(**{"l-1": [{"user.name": "root", "source.ip": "10.0.0.1"}]}),
        "p.yaml")
    assert summary["forbidden_emitted"] == ["root"]


def test_a_forbidden_value_inside_a_free_text_field_leaks():
    """The oracle emits `message:` prose — copying the original values there is
    the same leak as copying them into a typed field."""
    summary = SCORE.score_projection(
        {"leads": {"l-1": {"system": "elastic", "class": "+event"}},
         "must_not_emit": ["root", "172.18.0.15"]},
        _proj(**{"l-1": [{"message": "Failed password for root from 172.18.0.15 port 22 ssh2"}]}),
        "p.yaml")
    assert summary["forbidden_emitted"] == ["root", "172.18.0.15"]


def test_leak_check_ignores_a_path_that_merely_contains_the_token():
    """`/root/.ssh/authorized_keys` is case-002's real output. A substring scan
    would report a false LEAK against a case forbidding the original user `root`,
    and a false leak is a wrongly-untrusted slice."""
    summary = SCORE.score_projection(
        {"leads": {"l-1": {"system": "elastic", "class": "+event"}},
         "must_not_emit": ["root"]},
        _proj(**{"l-1": [{"fd.name": "/root/.ssh/authorized_keys", "user.name": "admin"}]}),
        "p.yaml")
    assert summary["forbidden_emitted"] == []


def test_leak_check_does_not_scan_field_names():
    """Keys are schema names, never the mutated entities — scanning them only
    invents leaks."""
    summary = SCORE.score_projection(
        {"leads": {"l-1": {"system": "elastic", "class": "+event"}},
         "must_not_emit": ["user.name"]},
        _proj(**{"l-1": [{"user.name": "admin"}]}),
        "p.yaml")
    assert summary["forbidden_emitted"] == []


def test_a_forbidden_value_inside_a_suppression_marker_leaks():
    summary = SCORE.score_projection(
        {"leads": {"l-1": {"system": "elastic", "class": "-noise"}},
         "must_not_emit": ["office-ws-1"]},
        _proj(**{"l-1": ["<suppressed: the attacker stopped the agent on office-ws-1>"]}),
        "p.yaml")
    assert summary["forbidden_emitted"] == ["office-ws-1"]




# --------------------------------------------------------------------------
# partially-placeholdered values — found by the #711 held-out captures
# --------------------------------------------------------------------------

def test_a_value_with_an_embedded_placeholder_is_not_a_concrete_claim():
    """prompt.md mandates a placeholder for what the story does not state, and a
    projection obeying it often states PART of a value and abstains on the rest.
    Grading `"SSH-2.0-OpenSSH_<openssh-version>"` as `wrong` because it is not the
    literal captured build punishes that abstention — and `wrong` gates a slice to
    `no-update`. Two such values really occurred in case-005 and case-009."""
    summary = SCORE.score_projection(
        _spec(**{"l-1": {"system": "elastic", "class": "+event",
                         "observed_fields": {"zeek.ssh.client": "SSH-2.0-OpenSSH_8.9p1"}}}),
        _proj(**{"l-1": [{"zeek.ssh.client": "SSH-2.0-OpenSSH_<openssh-version>"}]}),
        "p.yaml")
    assert summary["rows"][0]["contradictions"] == {}
    assert summary["wrong_concrete_fields"] == 0


def test_a_required_field_emitted_with_an_embedded_placeholder_is_unknown():
    summary = SCORE.score_projection(
        _spec(**{"l-1": {"system": "elastic", "class": "+event",
                         "fields": {"message": "Failed password for root from 10.0.0.1"}}}),
        _proj(**{"l-1": [{"message": "Failed password for root from <source-ip>"}]}),
        "p.yaml")
    assert summary["rows"][0]["fields"] == {"message": "unknown"}
    assert summary["wrong_concrete_fields"] == 0


def test_a_fully_concrete_fabrication_is_still_wrong():
    """The fix must not blunt the check it shares code with: a value carrying no
    placeholder at all is still a claim, and case-002's `evt.type: write` must
    still grade `wrong`."""
    summary = SCORE.score_projection(
        _spec(**{"l-1": {"system": "elastic", "class": "+event",
                         "observed_fields": {"evt.type": "openat"}}}),
        _proj(**{"l-1": [{"evt.type": "write"}]}),
        "p.yaml")
    assert summary["wrong_concrete_fields"] == 1

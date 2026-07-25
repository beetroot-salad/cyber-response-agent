"""Tests for the oracle-calibration golden set and its scorer (#693).

`score.py` is the component the trust/abstention resolver is specified to read:
a slice goes `no-update` on a `wrong` concrete field or a false suppression, so
every grade it emits is load-bearing. It is also pure — a function of
(`expected.yaml`, `projections/<tag>.yaml`) with no clock, no network, no model
— which is what makes all of this testable at all, and what lets
`test_every_checked_in_score_reproduces` pin the committed artifacts against
scorer drift.

The tests that carry the most weight are the ones pinning what must NOT happen
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

`test_no_story_states_the_expected_result` guards the other direction: a story is
an oracle INPUT, and the seed negative control announced in its own story that a
faithful oracle "must therefore return `0` for every lead". The hidden/visible
split cannot catch an answer leaked inside oracle_visible/.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest
import yaml

DEFENDER_DIR = Path(__file__).resolve().parents[1]
GOLDEN_DIR = DEFENDER_DIR / "evals" / "oracle_golden"
CASES_DIR = GOLDEN_DIR / "cases"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None
    assert spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


SCORE = _load("oracle_golden_score", GOLDEN_DIR / "score.py")

CASE_DIRS = sorted(p for p in CASES_DIR.iterdir() if p.is_dir())


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
# the suite's own artifacts
# --------------------------------------------------------------------------

def test_there_are_cases_to_check():
    """Every sweep below would pass vacuously against an empty cases/ tree."""
    assert CASE_DIRS


@pytest.mark.parametrize("case_dir", CASE_DIRS, ids=lambda p: p.name)
def test_every_case_has_the_files_the_readme_promises(case_dir):
    for rel in ("manifest.yaml", "expected.yaml",
                "oracle_visible/story.md", "oracle_visible/leads.jsonl"):
        assert (case_dir / rel).is_file(), f"{case_dir.name} is missing {rel}"


@pytest.mark.parametrize("case_dir", CASE_DIRS, ids=lambda p: p.name)
def test_manifest_and_expected_agree_on_the_case_identity(case_dir):
    manifest = yaml.safe_load((case_dir / "manifest.yaml").read_text(encoding="utf-8"))
    expected = yaml.safe_load((case_dir / "expected.yaml").read_text(encoding="utf-8"))
    assert manifest["case_id"] == case_dir.name
    assert expected["case_id"] == case_dir.name
    assert manifest["kind"] == expected["kind"]


@pytest.mark.parametrize("case_dir", CASE_DIRS, ids=lambda p: p.name)
def test_an_observed_case_carries_the_hidden_ground_truth_it_was_labelled_from(case_dir):
    manifest = yaml.safe_load((case_dir / "manifest.yaml").read_text(encoding="utf-8"))
    if manifest["kind"] != "observed":
        pytest.skip("derived cases re-run the oracle over a base case's captured leads")
    assert (case_dir / "hidden" / "controls.yaml").is_file()
    assert list((case_dir / "hidden" / "observed").iterdir())


@pytest.mark.parametrize("case_dir", CASE_DIRS, ids=lambda p: p.name)
def test_every_labelled_lead_has_an_oracle_visible_envelope(case_dir):
    expected = yaml.safe_load((case_dir / "expected.yaml").read_text(encoding="utf-8"))
    rows = [json.loads(x) for x
            in (case_dir / "oracle_visible" / "leads.jsonl").read_text(encoding="utf-8").splitlines()
            if x.strip()]
    assert {r["lead_id"] for r in rows} == set(expected["leads"])


# Vocabulary that only an eval author writes — the scoring frame, not the
# operation. A story mentioning any of it is telling the oracle what it is being
# tested on, or what to answer.
_EVAL_TELLS = ("oracle", "negative control", "golden", "projection", "every lead",
               "each lead", "expected result", "+event", "+noise", "-noise",
               "result class", "standard environment noise", "suppressed:")


@pytest.mark.parametrize("case_dir", CASE_DIRS, ids=lambda p: p.name)
def test_no_story_states_the_expected_result(case_dir):
    """A story is an ORACLE INPUT — the one file the hidden/visible split cannot
    protect, because it is deliberately visible. The seed negative control's story
    announced that it WAS a negative control and that the oracle "must therefore
    return `0` for every lead", which is the scoring answer written into the
    prompt. Rationale belongs in expected.yaml / manifest.yaml, which the oracle
    never reads."""
    story = (case_dir / "oracle_visible" / "story.md").read_text(encoding="utf-8").lower()
    assert not [tell for tell in _EVAL_TELLS if tell in story], (
        f"{case_dir.name}/oracle_visible/story.md leaks the evaluation frame to the "
        f"oracle: {[t for t in _EVAL_TELLS if t in story]}")


def _score_pairs():
    for case_dir in CASE_DIRS:
        for proj in sorted((case_dir / "projections").glob("*.yaml")):
            yield case_dir, proj


@pytest.mark.parametrize(("case_dir", "proj_path"), list(_score_pairs()),
                         ids=lambda p: p.name)
def test_every_checked_in_score_reproduces(case_dir, proj_path):
    """The committed `scores/<tag>.json` must be the output of the committed
    `score.py` over the committed `projections/<tag>.yaml`. Three of the seed
    artifacts had been produced by an earlier scorer and no longer matched its
    schema; nothing caught it, because scoring is cheap and nothing re-ran it."""
    stored = case_dir / "scores" / f"{proj_path.stem}.json"
    assert stored.is_file(), f"no scores/ artifact for {case_dir.name}/{proj_path.name}"
    spec = yaml.safe_load((case_dir / "expected.yaml").read_text(encoding="utf-8"))
    proj = yaml.safe_load(proj_path.read_text(encoding="utf-8"))
    summary = SCORE.score_projection(spec, proj, proj_path.name)
    assert json.dumps(summary, indent=2) + "\n" == stored.read_text(encoding="utf-8"), (
        f"{stored.relative_to(DEFENDER_DIR)} is stale — "
        f"re-run score.py --json over {proj_path.name}")


@pytest.mark.parametrize(("case_dir", "proj_path"), list(_score_pairs()),
                         ids=lambda p: p.name)
def test_no_checked_in_projection_has_a_lead_set_mismatch(case_dir, proj_path):
    assert SCORE.main([str(case_dir), str(proj_path)]) == 0


def test_replay_never_names_the_hidden_tree_outside_its_docstring():
    """The one hard rule is structural: `replay.py` sources every input from
    `oracle_visible/`. A literal reaching into `hidden/` would make a projection
    scoreable against data it was allowed to read, so pin it here rather than
    trusting review to notice."""
    import ast
    tree = ast.parse((GOLDEN_DIR / "replay.py").read_text(encoding="utf-8"))
    # Identify docstrings by NODE, not by value: ast.get_docstring() returns the
    # cleaned text, which never equals the raw Constant a value-comparison would
    # match — a sweep keyed on that silently exempts nothing and passes vacuously.
    docstring_nodes = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef)):
            continue
        first = next(iter(node.body), None)
        if (isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)):
            docstring_nodes.add(id(first.value))
    code_literals = [n.value for n in ast.walk(tree)
                     if isinstance(n, ast.Constant) and isinstance(n.value, str)
                     and id(n) not in docstring_nodes]
    assert any("oracle_visible" in s for s in code_literals), (
        "the sweep found no path literals at all — the assertion below is vacuous")
    assert not [s for s in code_literals if "hidden" in s], (
        "replay.py must not reference the hidden/ tree in code")

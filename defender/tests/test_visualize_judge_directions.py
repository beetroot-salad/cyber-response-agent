"""Tests for the direction-parameterized judge transcript (#716).

The view used to fork per direction: six renderers that hardcoded the artifact names
`Direction` already declares, with the adversarial half treated as mandatory and the
benign half as optional. It now loops over `Direction`, and section presence follows the
disposition that selected the direction — so a `malicious` run stops claiming the
adversarial loop "did not run or aborted" when it was simply never selected.
"""
from __future__ import annotations

import importlib.util
import inspect
import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[1] / "scripts" / "visualize"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import pytest

from defender.learning.core.config import DISPOSITION_ENUM
from defender.learning.core.directions import BY_NAME, directions_for, raw_fallback_name


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, _SCRIPTS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    # Register before exec: `@dataclass` resolves annotations through
    # `sys.modules[cls.__module__]`, which is None for an unregistered module.
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


vj = _load("visualize_judge")
vp = _load("visualize_primitives")

_ADVERSARIAL, _BENIGN = vj.ADVERSARIAL_VIEW, vj.BENIGN_VIEW


@pytest.fixture(autouse=True)
def _hermetic_state_dir(tmp_path, monkeypatch):
    """Section presence now reads the learning run dir, so point it at tmp for every test —
    otherwise a real run under `defender/learning/runs/` decides the assertions."""
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path))


def _learn_dir(tmp_path, run_id: str) -> Path:
    d = tmp_path / "runs" / run_id
    d.mkdir(parents=True)
    return d

_JUDGE = {
    "outcome": "survived",
    "outcome_rationale": "actor reached the trust peer unobserved",
    "encounter_analysis": "no lead covered lateral movement",
    "defender_findings": [
        {
            "type": "lead-set",
            "subject_anchor": "a",
            "subject_topic": "t",
            "finding": "f",
            "citations": [],
        }
    ],
}

_ENV_OBS = [
    {
        "alert_rule_ids": ["v2-falco-suspicious-network-tool"],
        "relevance_criteria": "web-tier host running nc -z toward a trust peer",
        "fact": "svc.monitoring performs scheduled nc -z reachability probes",
        "entities": [{"type": "identity", "class": "service-account"}],
    }
]

_BENIGN_JUDGE = {
    "outcome": "survived",
    "outcome_rationale": "escalated an authorized monitoring probe",
    "confidence": "high",
    "encounter_analysis": "routine sweep would have been flagged as recon",
    "defender_findings": [
        {
            "type": "lead-quality",
            "subject_anchor": "svc.monitoring",
            "subject_topic": "service-account authorization",
            "finding": "lacked the standing fact about svc.monitoring sweeps",
            "citations": [],
        }
    ],
    "environment_observations": _ENV_OBS,
}


# --- the view table is driven off Direction ---------------------------------------

def test_views_cover_every_direction():
    """The drift guard this refactor exists for: a `Direction` with no `DirectionView`
    would silently vanish from the judge page instead of failing loudly."""
    assert [v.direction.name for v in vj.VIEWS] == list(BY_NAME)
    assert all(v.direction is BY_NAME[v.direction.name] for v in vj.VIEWS)


def test_every_disposition_selects_at_least_one_direction():
    """The other half of the drift guard: a typo'd or omitted entry in
    `Direction.dispositions` would drop a leg from BOTH the loop's dispatch and the page,
    with nothing failing."""
    declared = {d for direction in BY_NAME.values() for d in direction.dispositions}
    assert declared == DISPOSITION_ENUM
    for disposition in DISPOSITION_ENUM:
        assert directions_for(disposition), disposition


# --- ids come off the direction name, through one mechanism -----------------------

def test_anchor_ids_are_derived_from_the_direction_name():
    """`suffix`, `label` and the finding prefix used to be hand-written per view, so a third
    direction had to restate three strings it could typo into a collision (#716)."""
    assert (_ADVERSARIAL.suffix, _ADVERSARIAL.label) == ("", "")
    assert (_BENIGN.suffix, _BENIGN.label) == ("-benign", " (benign)")
    for view in vj.VIEWS:
        for base in ("sec-actor", "sec-judge", "sec-oracle", "finding", "env-obs"):
            assert view.anchor(base) == f"{base}{view.suffix}"


def test_exactly_one_direction_owns_the_unsuffixed_ids():
    """Two unsuffixed directions would emit duplicate `sec-judge` / `finding-0` ids on one
    page, and no renderer would notice."""
    assert [v.direction.name for v in vj.VIEWS if not v.suffix] == [vj.UNSUFFIXED_DIRECTION]


def test_no_direction_id_collides_with_another():
    ids = [
        v.anchor(base)
        for v in vj.VIEWS
        for base in ("sec-actor", "sec-judge", "sec-oracle", "finding", "env-obs")
    ]
    assert len(set(ids)) == len(ids)


def test_card_renderers_have_no_default_anchor_prefix():
    """The prefix has ONE home (`DirectionView.anchor`). A signature default would be a
    second one, silently keeping the old value for any caller that omits the argument."""
    for fn in (vj.render_judge_finding, vj.render_env_observation):
        param = inspect.signature(fn).parameters["anchor_prefix"]
        assert param.default is inspect.Parameter.empty


def test_sections_render_the_artifact_names_direction_declares(tmp_path):
    learn = _learn_dir(tmp_path, "case-1")
    for view in vj.VIEWS:
        d = view.direction
        (learn / d.story_name).write_text(f"story for {d.name}")
        (learn / d.telemetry_name).write_text(f"telemetry for {d.name}")

    for view in vj.VIEWS:
        d = view.direction
        actor = vj.render_judge_actor_section("case-1", view)
        assert d.story_name in actor
        assert f"story for {d.name}" in actor
        oracle = vj.render_judge_oracle_section("case-1", view)
        assert d.telemetry_name in oracle
        assert f"telemetry for {d.name}" in oracle
        assert d.judge_name in vj.render_judge_judge_section(None, view)


def test_oracle_section_finds_the_raw_fallback(tmp_path):
    learn = _learn_dir(tmp_path, "case-1")
    raw_name = vj.raw_fallback_name(_BENIGN.direction.telemetry_name)
    (learn / raw_name).write_text("unstripped fence")
    html = vj.render_judge_oracle_section("case-1", _BENIGN)
    assert "raw fallback" in html
    assert "unstripped fence" in html


# --- disposition decides which directions appear ---------------------------------

def test_malicious_disposition_omits_the_adversarial_direction():
    """The bug: on `malicious` the adversarial direction is never selected
    (`Direction.dispositions`), yet the page used to render it as an aborted loop."""
    views = vj.active_views("case-1", "malicious")
    assert [v.direction.name for v in views] == ["benign"]


def test_benign_disposition_omits_the_benign_direction():
    assert [v.direction.name for v in vj.active_views("case-1", "benign")] == ["adversarial"]


def test_inconclusive_disposition_renders_both():
    assert [v.direction.name for v in vj.active_views("case-1", "inconclusive")] == [
        "adversarial", "benign",
    ]


def test_unreadable_disposition_falls_back_to_every_direction():
    """No report.md / bad frontmatter leaves nothing to gate on — render everything with
    its missing-artifact placeholder rather than an empty page."""
    assert vj.active_views("case-1", "?") == vj.VIEWS
    assert vj.active_views("case-1", "") == vj.VIEWS


def test_missing_artifacts_still_placeholder_when_the_direction_was_selected():
    html = vj.render_judge_judge_section(None, _ADVERSARIAL)
    assert "learning loop did not run or aborted" in html
    assert 'id="sec-judge"' in html


def test_disposition_is_normalized_the_way_the_loop_normalizes_it():
    """A zero-width character clinging to the keyword decides nothing (#722): the loop
    strips it before dispatching, so the page must strip it before deciding which
    directions ran — otherwise it renders the never-selected leg as an aborted loop."""
    for disposition in ("malicious​", " malicious ", "malicious﻿"):
        assert [v.direction.name for v in vj.active_views("case-1", disposition)] == ["benign"]
        assert [d.name for d in directions_for(disposition)] == ["benign"]


# --- ...and artifacts on disk override it ----------------------------------------

def test_a_direction_that_left_artifacts_renders_even_when_unselected(tmp_path):
    """`report.md` is mutable and the learning run dir accumulates. A run learned under
    `inconclusive` — both legs ran — whose disposition is later corrected to `malicious`
    still holds the adversarial judge doc. Gating on selection alone would drop its outcome
    and findings from the page while the Raw bundle went on showing that leg's `*.raw.txt`."""
    learn = _learn_dir(tmp_path, "case-1")
    (learn / BY_NAME["adversarial"].judge_name).write_text("outcome: survived\n")
    assert [v.direction.name for v in vj.active_views("case-1", "malicious")] == [
        "adversarial", "benign",
    ]


def test_every_artifact_a_direction_writes_counts_as_presence(tmp_path):
    """Any one of them is evidence the leg ran — the judge doc is not the only thing the
    page would otherwise hide (the actor story and the oracle telemetry render too)."""
    adversarial = BY_NAME["adversarial"]
    for i, name in enumerate(adversarial.artifact_names()):
        run_id = f"case-{i}"
        (_learn_dir(tmp_path, run_id) / name).write_text("x")
        assert [v.direction.name for v in vj.active_views(run_id, "malicious")] == [
            "adversarial", "benign",
        ], name


def test_artifact_names_are_the_ones_the_direction_declares():
    """Presence must not grow a name list of its own — that is the drift #716 is about."""
    for direction in BY_NAME.values():
        names = direction.artifact_names()
        assert set(names) >= {
            direction.story_name,
            direction.telemetry_name,
            direction.judge_name,
            raw_fallback_name(direction.telemetry_name),
            raw_fallback_name(direction.judge_name),
        }
        for optional in (direction.archetype_name, direction.menu_name):
            assert (optional in names) == (optional is not None)


def test_an_empty_learning_run_dir_leaves_the_unselected_direction_off(tmp_path):
    _learn_dir(tmp_path, "case-1")
    assert [v.direction.name for v in vj.active_views("case-1", "malicious")] == ["benign"]


# --- the finding count the TOC and the headline link -------------------------------

def test_finding_count_matches_the_cards_the_section_emits():
    assert vj.judge_finding_count(_JUDGE) == 1
    assert vj.judge_finding_count({}) == 0
    assert vj.judge_finding_count({"defender_findings": None}) == 0


def test_finding_count_survives_a_non_list_defender_findings():
    """The section guards `isinstance(findings, list)`; the TOC and the headline must use
    the same guard, or a scalar `defender_findings` crashes the whole page render and a
    string emits one dead `#finding-i` link per character."""
    for bad in (3, "none", {"a": 1}):
        assert vj.judge_finding_count({"defender_findings": bad}) == 0
        assert "Findings (0)" in vj.render_judge_judge_section(
            {"defender_findings": bad}, _ADVERSARIAL,
        )
    assert 'href="#finding-' not in vj.render_judge_toc([(_ADVERSARIAL, 0)])


# --- rendering, both directions ---------------------------------------------------

def test_judge_section_renders_outcome_and_findings():
    html = vj.render_judge_judge_section(_BENIGN_JUDGE, _BENIGN)
    assert 'id="sec-judge-benign"' in html
    assert 'id="sec-judge-benign-outcome"' in html
    assert 'id="finding-benign-0"' in html
    assert "escalated an authorized monitoring probe" in html


def test_adversarial_environment_observations_now_render():
    """`validate_judge_doc` accepts `environment_observations` on the adversarial doc and
    judge/malicious.md asks for them; the benign-only renderer used to drop them."""
    html = vj.render_judge_judge_section(
        {**_JUDGE, "environment_observations": _ENV_OBS}, _ADVERSARIAL,
    )
    assert 'id="sec-judge-env"' in html
    assert "svc.monitoring performs scheduled nc -z reachability probes" in html
    assert "identity/service-account" in html


def test_benign_environment_observations_still_render():
    html = vj.render_judge_judge_section(_BENIGN_JUDGE, _BENIGN)
    assert 'id="sec-judge-benign-env"' in html
    assert "v2-falco-suspicious-network-tool" in html


def test_env_observation_anchors_do_not_collide_across_directions():
    both = vj.render_judge_judge_section(
        {**_JUDGE, "environment_observations": _ENV_OBS}, _ADVERSARIAL,
    ) + vj.render_judge_judge_section(_BENIGN_JUDGE, _BENIGN)
    assert 'id="env-obs-0"' in both
    assert 'id="env-obs-benign-0"' in both


def test_env_observation_card_handles_missing_entities():
    html = vj.render_env_observation(0, {
        "alert_rule_ids": ["r1"],
        "relevance_criteria": "c",
        "fact": "f",
    }, anchor_prefix=_ADVERSARIAL.anchor("env-obs"))
    assert 'id="env-obs-0"' in html
    assert "env-obs-ents" not in html


def test_actor_section_renders_archetype_only_where_the_direction_declares_it(tmp_path):
    learn = _learn_dir(tmp_path, "case-1")
    (learn / _ADVERSARIAL.direction.story_name).write_text("adversarial story")
    (learn / _ADVERSARIAL.direction.archetype_name).write_text("smash-and-grab")
    (learn / _ADVERSARIAL.direction.menu_name).write_text("T1021")
    (learn / _BENIGN.direction.story_name).write_text("routine sweep story")

    adversarial = vj.render_judge_actor_section("case-1", _ADVERSARIAL)
    assert "smash-and-grab" in adversarial
    assert "MITRE technique menu (sampled)" in adversarial

    benign = vj.render_judge_actor_section("case-1", _BENIGN)
    assert 'id="sec-actor-benign"' in benign
    assert "routine sweep story" in benign
    assert "archetype" not in benign
    assert "MITRE technique menu" not in benign


def test_actor_section_placeholder_names_the_missing_story():
    html = vj.render_judge_actor_section("nope", _BENIGN)
    assert "no actor_benign_story.md" in html


# --- TOC --------------------------------------------------------------------------

def test_toc_emits_one_block_per_rendered_direction():
    toc = vj.render_judge_toc([(_ADVERSARIAL, 2), (_BENIGN, 1)])
    assert 'href="#finding-1"' in toc
    assert 'href="#finding-benign-0"' in toc
    assert "sec-actor-benign" in toc
    assert "sec-judge-benign-env" in toc
    assert "sec-judge-env" in toc


def test_toc_omits_a_direction_the_page_did_not_render():
    toc = vj.render_judge_toc([(_BENIGN, 1)])
    assert 'href="#sec-actor"' not in toc
    assert 'href="#sec-judge-outcome"' not in toc
    assert "sec-actor-benign" in toc


def test_toc_links_only_the_section_when_a_selected_direction_has_no_judge_doc():
    """The placeholder section carries no sub-anchors, so the TOC must not link them."""
    toc = vj.render_judge_toc([(_ADVERSARIAL, None)])
    assert 'href="#sec-judge"' in toc
    for sub in ("outcome", "findings", "env", "encounter"):
        assert f'href="#sec-judge-{sub}"' not in toc


def test_toc_marks_a_direction_with_no_findings():
    toc = vj.render_judge_toc([(_ADVERSARIAL, 0)])
    assert "(none)" in toc
    assert 'href="#finding-0"' not in toc


# --- unchanged surfaces -----------------------------------------------------------

def test_adversarial_finding_anchor_unchanged():
    html = vj.render_judge_finding(0, {
        "type": "lead-set",
        "subject_anchor": "a",
        "subject_topic": "t",
        "finding": "f",
        "citations": [],
    }, anchor_prefix=_ADVERSARIAL.anchor("finding"))
    assert 'id="finding-0"' in html


def test_load_judge_doc_reads_the_direction_name(tmp_path):
    learn = _learn_dir(tmp_path, "case-1")
    (learn / BY_NAME["benign"].judge_name).write_text("outcome: survived\n")
    assert vp.load_judge_doc("case-1", BY_NAME["benign"]) == {"outcome": "survived"}
    assert vp.load_judge_doc("case-1", BY_NAME["adversarial"]) is None


def test_learning_run_dir_honors_state_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path / "state"))
    assert vp._learning_run_dir("case-9") == (tmp_path / "state").resolve() / "runs" / "case-9"


def test_learning_run_dir_defaults_in_repo(monkeypatch):
    monkeypatch.delenv("DEFENDER_LEARNING_STATE_DIR", raising=False)
    assert vp._learning_run_dir("case-9") == vp.REPO_ROOT / "defender" / "learning" / "runs" / "case-9"

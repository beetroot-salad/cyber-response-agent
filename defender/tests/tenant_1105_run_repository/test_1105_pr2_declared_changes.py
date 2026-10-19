"""#1105 PR 2 — the declared changes (rev 5.1 part 2 "Declared changes", as amended by the owner's
fork decisions 6100061869: J3 removes the judge's same-alert union; J8 makes `--tenant` required at
every migrated CLI and drops the tracer's `--runs-dir`; old episodes — no `_tenant.json` in their
`runs/` — are refused).

PR 2 is a refactor; each change here is FORCED and declared. Every test is RED at base `301f196c`
for the reason its docstring states, and goes green when the change lands. Where the change is
not itself an argument shape, the test drives the edge through `_spec1105_pr2`'s builders
(today's shape, re-pointed by PR 2), so it is red for its behavioural reason alone; only the
tests whose change IS the edge's arguments call the declared shape (`new_*_argv`) directly.

| Test                                                          | Change | Red at base because                                   |
|---------------------------------------------------------------|--------|-------------------------------------------------------|
| test_dc0_the_door_no_longer_serves_the_tenant_taking_lookups  | 0      | the door serves `open_run` & co.                       |
| test_dc1_the_launcher_takes_a_tenant_and_a_source_run_id_only | 1      | the launcher takes a path (`--tenant` unrecognised)    |
| test_dc1_a_source_under_a_linked_runs_folder_is_refused       | 1, 11  | `tenant_of_run_dir` compares resolved paths: it passes |
| test_dc2_the_judges_prompt_carries_no_sibling_view_or_tally   | J3     | VIEW 4 / TRIAL SPREAD name the same-alert prior run    |
| test_dc3_a_world_label_equal_to_a_natural_run_id_grades        | 3, J3  | the label probe over `<T>/runs` refuses (G17)          |
| test_dc4_the_episode_page_takes_a_tenant_and_an_episode_id    | 4, J8  | the page CLI takes a folder path                       |
| test_dc4_the_page_judges_the_container_record_first           | 4, G20 | #1187 O8: another tenant's episode id is absent        |
| test_dc4_the_page_roster_is_the_manifests_arms_and_no_stray   | 4, J3  | every `runs/` dir gets a section (`stray_run_dir`)     |
| test_dc5_an_arm_entry_that_is_a_link_is_never_archived        | 5      | verify joins `runs/<ep>-<label>` by hand and follows it|
| test_dc6_the_launcher_starts_siblings_by_tenant_episode_label | 6      | the argv is `--resume <family.yaml>`                   |
| test_dc6_run_py_refuses_resume_and_takes_the_episode_id       | 6, G18 | `--resume` is the sibling's edge; `--episode` unknown  |
| test_dc6_a_sibling_over_an_absent_container_is_refused        | 6, G5  | #1187 O4b: the roster, not a record, proves RUNS       |
| test_dc6_the_sibling_judges_the_container_before_the_manifest | 6, G19 | #1187 O4b: the roster is judged before the manifest    |
| test_dc7_the_run_page_takes_a_tenant_and_a_run_id             | 7, J8  | the run page CLI takes a folder path                   |
| test_dc7_the_run_page_refuses_a_linked_run_folder             | 7, 11  | `Run.at` follows the link and renders into its target  |
| test_dc8_a_natural_run_enqueues_its_address_not_its_folder    | 8      | the row is `{case_id, run_dir}`                        |
| test_dc8_the_drain_rehydrates_the_row_in_its_own_tenant       | 8, G21 | a row with no `run_dir` is quarantined "unreadable"    |
| test_dc8_the_claim_admits_only_the_new_row_shape              | 8, O9  | the old shape is served; the new one quarantined       |
| test_dc8_a_row_that_cannot_be_reached_is_artifact_missing     | 8, 11  | such rows are "unreadable: run_dir…" today             |
| test_dc8_a_drain_with_no_data_root_leaves_its_rows_queued     | 8      | the drain never reads the data root; it dead-letters   |
| test_dc9_the_launchers_manifest_names_its_source_by_id_only   | 9      | the writer emits `source_run_dir`                      |
| test_dc9_a_manifest_without_source_run_dir_resumes            | 9      | `_check_scalars` requires it                           |
| test_dc9_an_old_manifests_source_run_dir_is_never_read        | 9, A   | the sibling's source alert is read from that path      |
| test_dc10_j8_every_migrated_cli_requires_the_tenant[*]        | J8     | none of the six CLIs knows `--tenant`                  |
| test_dc10_the_tracer_walks_the_tenants_runs_and_refuses_a_stray | 10, J3, J8 | `--runs-dir`/the dead state-root walk; strays skipped |
| test_dc10_workspace_map_takes_a_tenant_and_a_run_id           | 10, J8 | the CLI takes a folder path                            |

#1187 (design rev 2) retired two rows: `test_dc4_a_container_with_no_record_refuses_the_page`
(R1: no container record is written or judged; a recordless arm container is every episode's —
the page over one is pinned by `ids_1187/test_1187_roster_consumers.py::test_page_links_each_arm_by_its_roster_id_never_a_composed_name`)
and `test_dc6_a_sibling_needs_the_episodes_base` (declared change 5 / O9: nothing reads
`DEFENDER_EPISODES_BASE`; pinned by
`ids_1187/test_1187_roster_sibling.py::test_the_sibling_needs_no_episodes_variable_and_ignores_a_decoy`).
Each flipped test names its #1187 declared change in its own docstring.

SETTLED (the spine's ruling on #1105, its newest comment): under J3 the judge's world-label
collision probe (`family._check_world_labels`' `runs_base` arm — G17) is REMOVED: it guarded
`resolve_run_bundle`, which has no production caller (E-27). The reserved-label and label-grammar
refusals stay. The episode page's arm roster comes from the manifest's runnable labels, each arm
opened by id through the episode view; an entry in the episode's `runs/` that is no manifest arm
is no longer shown (the `ROSTER_STRAY_RUN_DIR` rows go). Pinned by `test_dc3_…` and
`test_dc4_the_page_roster_…`.

NOT PINNED (ambiguous or no observable): `Run.reader()` (it survives only if the page's per-world
reads still need it); the profile half of declared change 13 (`run_page_mirror`, the
`tenant_runs_record` reader list); fork S (no observable change; G16 is the guard). The lead
author's `--tenant T <run_id>` path and change 13's usage prose are pinned by
`test_1105_pr2_tighten.py` (F9, F10), with the red-team pass's other closures.

EXISTING TESTS A DECLARED CHANGE WILL EDIT (behavioural assertions, not just call sites; this
commit edits none of them). Declared change 12's signature families adapt on top of these.

  F1  the fence's end state (`test_1105_pr2_tighten::test_f1_…`): tenant_1105_run_repository/
      test_1105_layout_lint.py::test_1105_layout_lint_is_clean_on_the_tree_and_every_allow_list_entry_is_load_bearing
      (pins PR 1's 18 entries; D7″ empties them) and
      ::test_1105_layout_lint_table_equals_the_importer_population_and_an_unlisted_module_gets_no_exemption
      (pins `NON_LAYOUT`, which lacks `RunAbsent` / `RunAddress`); test_1120_owner_lint_reaches_runs_base.py
      (pins the literal `runs_base = tenant.runs` / `runs_base = tenant.tenant.runs` lines and
      `_episode_tenant` as the launcher's tenant factory, which D-create (a) and row 16 remove).
  0   tenant_1105_run_repository/test_1105_run_repository_package.py (the door's `__all__` pin)
      and PR 1's lookup tests (test_1105_run_lookup.py, test_1105_spec_holes.py,
      test_1105_review_followups.py, test_1105_claims_followups.py): move onto the methods.
  1   tenant_1078_pass_a/test_1078_launcher.py::test_s7_j26_symlinked_tenant_folder_accepted
      (shape 2 flips); the launch fixtures' source id `_triplet_947.SOURCE_RUN_ID`
      (`20260728T161845Z-fresh-case`) is not case-stable, so `RunId.parse` refuses it — every
      launcher/sibling test on it (`_spec1224.launch`, `_spec1078.launch_argv`,
      `test_1025_stage_timing._launch`, …) needs a case-folded source id.
  J3  test_921_render.py::test_921_judge_input_carries_per_lead_chain_coverage_siblings_lessons_spread,
      ::test_921_sibling_union_is_the_runs_base_trials_sharing_the_alert_id,
      ::test_921_first_run_alert_coverage_view_states_the_empty_union,
      ::test_921_the_sibling_union_excludes_the_source_run_and_unclosed_siblings;
      test_1047_unmoved_readers.py::test_sibling_union_still_short_circuits_when_the_gradable_set_is_empty,
      ::test_the_sibling_prior_walks_a_runs_base_that_now_holds_run_end_records;
      tenant_1078_pass_a/test_1078_consumers.py::test_d4_render_union_threaded,
      ::test_judge_sibling_union_after_the_switch.
  3   test_921_family_facts.py::test_921_a_world_label_colliding_with_a_real_run_id_is_refused_at_manifest_load
      (G17's pin: the label now grades); `_judge_921.grade`'s required `runs_base=` and the
      `runs_base=` its callers thread (the judge reads only the episode it is handed).
  4/J3 roster  test_1025_page_worlds.py::test_1025_a_run_directory_whose_name_is_not_episode_dash_label
      (the stray's section), ::test_1025_the_worlds_and_leads_headings_count_exactly_the_sections_under_them
      (counts the stray's section, names the `bad name!` dir),
      ::test_1025_world_or_lead_directory_name_carries_attribute_or_tag_breaking_characters
      (counts the hostile run dir's "unnameable entry");
      test_1025_page_contract.py::test_1025_every_class_the_page_emits_has_a_rule_in_the_css_it_ships
      (its `unnameable` class comes from the `bad name!` dir);
      test_1025_page_decided_once.py::test_1025_a_runs_directory_wearing_a_worlds_label_is_sectioned_once
      (the off-roster line naming the shadowing dir);
      test_1025_page_decided_at_the_source.py::test_1025_the_draw_read_totals_count_every_directory_the_world_sections_count
      (a `runs/`-only world's section).
  4   test_1133_entry_points.py::test_*doors_keep_their_path_signatures (:16);
      test_1133_o4.py::test_o4_8_2_render_episode_refuses_a_missing_episode_dir_and_does_not_recreate_it
      (moves to `runs.episode`); test_1025_page_contract.py::test_1025_cli_argument_names_an_existing_regular_file_not_a_directory
      and ::test_1025_the_standalone_script_runs_with_no_pythonpath_from_any_cwd (passes `<dir>`);
      the `_episode_1025.run_dir` fixture (14 importers) gains `runs/_tenant.json`.
  6   tenant_1078_pass_a/test_1078_run_main.py::test_o5_sibling_tenant_from_record,
      ::test_d3_materialize_seam_tenant (sibling half), ::test_o5_forged_stamp_ignored,
      ::test_o5_disagreeing_tenant_refused, ::test_o5_resume_without_tenant_refused,
      ::test_resume_flag_combined_with_run_id_and_tenant,
      ::test_launch_whose_source_row_disappears_before_the_siblings_start,
      ::test_data_root_moves_after_runs_exist; (its resume-manifest test was retired by #1187
      declared change 5 — now ids_1187/test_1187_roster_sibling.py::test_the_sibling_needs_no_episodes_variable_and_ignores_a_decoy);
      test_947_triplet_sibling.py::test_a_sibling_resumes_through_its_requested_tenant and
      ::test_947_run_py_screens_the_source_alert_before_reading_it (absent container, `--resume`);
      tenant_1078_pass_a/test_1078_materialize.py's sibling-runs-base test (expected the absent
      container created; retired by #1187 R2 — now ids_1187/test_1187_roster_sibling.py::test_an_arm_is_created_only_at_an_id_the_roster_holds); test_1133_o4.py::test_the_sibling_door_refuses_a_resume_manifest_not_named_family_yaml
      (G18, moot); the other `"--resume"` files (11).
  7   e2e/test_1110_run_page_record_e2e.py::test_1110_the_standalone_re_render_logs_under_the_tenant_the_runs_stamp_names
      (the log names the request's tenant) and every other test there that runs the standalone
      re-render with a folder path (the red-team pass saw six red; the O4 store-precondition
      pin stays green); the other `visualize_run.main` files (3).
  8   learning/test_loop.py::test_lead_author_drain_marks_artifact_missing,
      ::test_lead_author_drain_dead_letters_an_unservable_marker; test_869_reporting.py (its
      dead letter carries `run_dir`); the `enqueue_curation(` (11) and `.claim("case_id"` (5)
      files.
  J8  test_trace_lesson.py, test_corpus_hardening_586.py and test_corpus_fold_584.py (every
      `--runs-dir` call); test_n9 (`--tenant` required);
      test_1120's `resolve_data_root` census (gains the drain and each J8 edge).
"""
from __future__ import annotations

from defender.tests._spec1077 import fixture_run as _run_handle_1165

import copy
import importlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from defender.tests import _episode_1025 as E
from defender.tests._fixture_uuid import fixture_uuid
from defender.tests.tenant_1105_run_repository import _spec1105 as H
from defender.tests.tenant_1105_run_repository import _spec1105_pr2 as P


@pytest.fixture(autouse=True)
def _roots(tmp_path, monkeypatch):
    P.roots(tmp_path, monkeypatch)


def _episode_names() -> set[str]:
    """Every entry under any tenant's `<data root>/<T>/episodes/` — #1187 Layout A, where every
    launch claims its episode (O9: no configured episodes root)."""
    root = P.data_root()
    return {str(p.relative_to(root)) for p in root.glob("*/episodes/*")}


def _the_launched_episode() -> Path:
    """The one episode the launch made under `<data root>/<LAUNCH_TENANT>/episodes/` (#1187: the
    launcher mints its id, so a test finds it rather than composing it)."""
    made = P.launched_episodes()
    assert len(made) == 1, f"expected the launch's one episode under <T>/episodes: {made}"
    return made[0]


def _launched(got: P.Launched) -> bool:
    return got.raised is None and got.rc == 0 and got.questioner.calls > 0


def _refused_unspent(got: P.Launched) -> bool:
    """Refused (an operator exit or a non-zero status) before the question-writer was paid."""
    return (got.raised is not None or got.rc not in (0, None)) and got.questioner.calls == 0


def _sample(tmp_path: Path, tenant_id: str) -> E.Episode:
    """`_episode_1025`'s sample episode at `<data root>/<tenant_id>/episodes/<uuid>/` (#1187
    Layout A), as RUNS leaves it: the arm roster naming every world, each arm at its roster id.
    No container record (R1)."""
    return E.sample_episode(tmp_path, root=P.episodes(tenant_id))


def _corrupt_manifest(ep: Path) -> None:
    (ep / "family.yaml").write_text("episode_id: [this is not a manifest\n", encoding="utf-8")


def _tenant_episode(tenant_id: str) -> tuple[Path, str]:
    """#1187's layout (decision 1, declared change 5): `<data root>/<tenant_id>/episodes/<uuid>/`
    holding a manifest the family model loads (`_triplet_947.family_doc`, worlds a, b, c) that
    names that uuid (R5), and the arm roster `arms.json` naming every manifest world — no
    container record anywhere. Returns `(folder, episode id)`."""
    from defender.tests import _triplet_947 as T
    from defender.tests.ids_1187 import _spec1187 as S

    episode_id = S.new_id()
    ep = S.make_episode(P.data_root(), tenant_id, episode_id, labels=T.WORLDS, roster=True)
    T.write_family(ep, T.family_doc(episode_id=episode_id, source_run_id=S.new_id()))
    return ep, episode_id


def _tenant_episode_names(tenant_id: str) -> set[str]:
    """The entries of `<data root>/<tenant_id>/episodes/` (#1187: the only place an episode is
    created, declared changes 3 and 5)."""
    from defender.tests.ids_1187 import _spec1187 as S

    root = S.episodes_dir(P.data_root(), tenant_id)
    return {p.name for p in root.iterdir()} if root.is_dir() else set()


def _roster_by_hand(ep: Path) -> dict[str, str]:
    """What #1187's `start_runs` leaves (R2): the arm roster `arms.json` naming every manifest
    world with a fresh UUID, and each arm the fixture already holds at `runs/<episode>-<label>/`
    (with its sidecar) moved to `runs/<roster id>/`. Returns the roster. An episode the shared
    fixture already built as RUNS leaves it (its roster written, its arms at their ids) is
    returned as it is."""
    from defender import _yaml
    from defender.tests.ids_1187 import _spec1187 as S

    if (ep / P.T.ROSTER_NAME).is_file():
        return S.read_roster(ep)
    doc = _yaml.safe_load((ep / "family.yaml").read_text(encoding="utf-8"))
    roster = {w["world_id"]: S.new_id() for w in doc["worlds"]}
    runs = ep / "runs"
    runs.mkdir(exist_ok=True)
    for label, arm_id in roster.items():
        composed = runs / f"{P.EPISODE_ID}-{label}"
        if composed.is_dir():
            composed.rename(runs / arm_id)
        for sidecar in runs.glob(f"{P.EPISODE_ID}-{label}.*"):
            sidecar.rename(runs / f"{arm_id}{sidecar.name[len(composed.name):]}")
    S.write_roster(ep, roster)
    return roster


# ==========================================================================================
# 0 — PR 1's Tenant-taking lookups leave the door.
# ==========================================================================================

def test_dc0_the_door_no_longer_serves_the_tenant_taking_lookups(tmp_path):
    """Declared change 0 (decision C; F-13): `open_run(T, …)`, `list_run_ids(T)`,
    `run_exists(T, …)` and `bound_runs(T)` leave the package's door — a production caller
    outside the package can no longer pass a `Tenant` beside an id (O1(e)). The repository's
    methods answer in their place (positive control: `runs.open` opens the run `open_run`
    opened). RED at base: the door serves all four, and `Tenant` has no `runs_repository`."""
    door = importlib.import_module("defender.run_repository")
    for name in ("open_run", "list_run_ids", "run_exists", "bound_runs"):
        assert isinstance(H.raised(getattr, door, name), AttributeError), (
            f"the door still serves {name}")
        assert name not in door.__all__
    root = tmp_path / "data"
    root.mkdir()
    t = H.tenant(root, H.T_ID)
    H.runs_folder(t)
    # #1187 (declared change 1): a run id is a canonical UUID, so the positive control opens
    # one (an old `r1` would be refused for its shape before the repository answers).
    rid = fixture_uuid("pr2-dc0-r1")
    H.make_run(t.runs, rid)
    assert Path(t.runs_repository().open(door.RunId.parse(rid)).run_dir) == Path(t.runs) / rid


# ==========================================================================================
# 1 — the launcher's edge: `--tenant T <source_run_id>`.
# ==========================================================================================

def test_dc1_the_launcher_takes_a_tenant_and_a_source_run_id_only(tmp_path):
    """Declared change 1 / J8: `branch --tenant T <source_run_id> <message>` launches T's run
    (the episode is made and its siblings start). The tenant comes from the request (S2): the
    same id under another real tenant that has no such run is refused before the questioner.
    And the edge takes ids only (O1(d)): the source's PATH where its id belongs is refused before
    the questioner, with no episode. RED at base: the launcher does not know `--tenant`.

    #1187 declared changes 3 and 5 (O9): the episode the launch makes is one fresh
    canonical-UUID folder under `<T>/episodes/` — not `<source id>-n<message>` under
    `DEFENDER_EPISODES_BASE` — and neither refusal makes one there (nor anywhere). (Name kept.)"""
    from defender.tests.ids_1187 import _spec1187 as S

    est, src = P.launch_source(tmp_path)
    P.second_tenant(P.data_root(), "beta")

    ok = P.drive_launch(est, P.new_launch_argv(P.LAUNCH_TENANT, src.name))
    assert _launched(ok), f"--tenant T <run id> did not launch: rc={ok.rc} {ok.message!r}"
    made = sorted(_tenant_episode_names(P.LAUNCH_TENANT))
    assert len(made) == 1, f"the launch made {made} under <T>/episodes"
    assert S.is_canonical_uuid(made[0]), f"the episode is named {made[0]!r}, not a uuid"
    assert (S.episodes_dir(P.data_root(), P.LAUNCH_TENANT) / made[0] / "family.yaml").is_file()
    assert ok.spawn.worlds, "no sibling was started"

    before = (_episode_names(), _tenant_episode_names(P.LAUNCH_TENANT),
              _tenant_episode_names("beta"))
    other = P.drive_launch(est, P.new_launch_argv("beta", src.name))
    assert _refused_unspent(other), "another tenant's request reached T's run"
    as_path = P.drive_launch(est, P.new_launch_argv(P.LAUNCH_TENANT, str(src)))
    assert _refused_unspent(as_path), "the launcher took a path where it takes a run id"
    assert (_episode_names(), _tenant_episode_names(P.LAUNCH_TENANT),
            _tenant_episode_names("beta")) == before


def test_dc1_a_source_under_a_linked_runs_folder_is_refused(tmp_path):
    """Declared changes 1 and 11 (R51-14): T's natural runs folder `<T>/runs` is a link to a
    real folder holding the source run and T's record. `runs.open` holds `<T>/runs` no-follow,
    so the launch is refused before the questioner, with no episode. The positive control
    puts the real folder back at `<T>/runs`: the same launch runs.

    The source carries no session store (still branchable: imported, replayed or pruned
    sources are, `_check_branch_point`), because a source WITH one is already refused today by
    G16's store compare (the store derived from the resolved folder is not the recorded one).
    RED at base: `tenant_of_run_dir` compares resolved paths, so the linked storeless source
    launches."""
    est, src = P.launch_source(tmp_path)
    from defender.run_repository import RunPaths

    RunPaths(src).session_pointer().unlink()
    runs = src.parent
    moved = tmp_path / "runs-elsewhere"
    runs.rename(moved)
    os.symlink(moved, runs)
    before = _episode_names()

    refused = P.drive_launch(est, P.launch_argv(P.LAUNCH_TENANT, src))
    assert _refused_unspent(refused), "a source under a linked runs folder launched"
    assert _episode_names() == before

    os.unlink(runs)
    moved.rename(runs)
    control = P.drive_launch(est, P.launch_argv(P.LAUNCH_TENANT, src))
    assert _launched(control), f"the control did not launch: {control.message!r}"


# ==========================================================================================
# J3 — the judge's same-alert union is removed.
# ==========================================================================================

def test_dc2_the_judges_prompt_carries_no_sibling_view_or_tally(tmp_path):
    """Fork decision J3 (6100061869): the "siblings" view and its tally leave the judge's
    prompt; the judge reads only the episode it is handed. A prior finished run of the SAME
    alert sits in T's runs folder (alert id `v2-cross-tier-ssh-pivot`, the worlds' own, and a
    report). The episode is launched and graded: every prompt the judge was handed carries the
    judged world's own report view (positive control: the capture is real), and none carries
    the sibling-trials view, the trial spread, or the prior run's id. RED at base: VIEW 4 lists
    the prior run and TRIAL SPREAD tallies it."""
    est, src = P.launch_source(tmp_path)
    prior = src.parent / "20260101t000000z-prior-trial"
    prior.mkdir()
    (prior / "alert.json").write_text(json.dumps({"alert_id": P.J.ALERT_ID}), encoding="utf-8")
    (prior / "report.md").write_text(P.T.report_text("benign"), encoding="utf-8")

    got = P.drive_launch(est, P.launch_argv(P.LAUNCH_TENANT, src))
    assert _launched(got), f"the launch did not run: {got.message!r}"
    prompts = got.judge.prompts
    assert prompts, "the judge was never asked"
    from defender.learning.judge.layout import FOCUS_VIEW_TITLES

    # #1234 M3/A10: the focus world's report view is titled, in host text, by its world label.
    assert any(f" — {FOCUS_VIEW_TITLES['report']}" in p for p in prompts)
    for prompt in prompts:
        assert "SIBLING TRIALS" not in prompt, "the prompt still carries the sibling view"
        assert "TRIAL SPREAD" not in prompt, "the prompt still carries the trial spread"
        assert prior.name not in prompt, "a same-alert prior run reached the judge"


def test_dc3_a_world_label_equal_to_a_natural_run_id_grades(tmp_path, caplog):
    """Declared change 3 / J3 as settled (the spine's ruling on #1105): the judge's world-label
    collision probe over `<T>/runs` (G17) is removed — it guarded `resolve_run_bundle`, which
    has no production caller (E-27); the judge reads only the episode it is handed.

    T's natural runs folder holds a finished run whose id is `b`, which is also a world label
    of the family the launcher authors (worlds a, b, c). The launch reaches its judge pass and
    the episode GRADES: the judge is asked, and `judge.yaml` carries a row for `b` and for `c`.
    POSITIVE CONTROL, same episode, through the judge's own entry point (`P.grade`): a manifest
    world wearing a reserved label (`family`) or a label off the run-id grammar (`x y`) is still
    refused at manifest load, naming the label — the label gate is live; only the probe over
    `<T>/runs` left. RED at base: `_check_world_labels` finds `<T>/runs/b` and raises
    `JudgeRefused` ("collides with a real run"), the launcher logs it, and nothing is graded."""
    import yaml

    from defender.tests import _judge_921 as J

    est, src = P.launch_source(tmp_path)
    natural = H.make_run(src.parent, "b")
    (natural / "report.md").write_text(P.T.report_text("benign"), encoding="utf-8")

    got = P.drive_launch(est, P.launch_argv(P.LAUNCH_TENANT, src))
    assert _launched(got), f"the launch did not run: {got.message!r}"
    judge_failures = [r.getMessage() for r in caplog.records if "judge pass failed" in r.getMessage()]
    assert got.judge.prompts, (
        f"the judge was never asked — a world label equal to a natural run id under <T>/runs "
        f"refused the grade: {judge_failures}")
    ep = _the_launched_episode()
    graded = J.world_rows(J.judge_record(ep))
    assert {"b", "c"} <= set(graded), f"the episode's worlds were not graded: {sorted(graded)}"
    assert natural.is_dir()

    manifest = ep / "family.yaml"
    good = manifest.read_bytes()
    for bad in ("family", "x y"):
        doc = yaml.safe_load(good)
        # A deep copy: a shared node would be dumped as a YAML alias, which the manifest
        # reader refuses before any label is judged.
        seat = copy.deepcopy(next(w for w in doc["worlds"] if w.get("world_id") == "c"))
        doc["worlds"].append({**seat, "world_id": bad})
        manifest.write_text(yaml.safe_dump(doc), encoding="utf-8")
        with pytest.raises(J.refusals()) as refused:
            P.grade(ep, P.LAUNCH_TENANT)
        # Quoted: the bare word `family` is also in every `family.yaml` refusal.
        assert repr(bad) in str(refused.value), (
            f"the label gate did not refuse {bad!r} by name: {refused.value}")
        assert not (ep / "judge.yaml").exists()


# ==========================================================================================
# 4 — the episode page: `--tenant T <episode_id>`, its container record judged first.
# ==========================================================================================

def test_dc4_the_episode_page_takes_a_tenant_and_an_episode_id(tmp_path, d9_tenant, monkeypatch):
    """Declared change 4 / J8: `visualize_episode.py --tenant T <episode_id>` renders the
    episode (positive). RED at base: the CLI takes one folder path ("usage").

    #1187 declared change 5 (O9): the episode is `<T>/episodes/<uuid>/` and the page reads no
    `DEFENDER_EPISODES_BASE`. With the variable set (the suite's roots), unset, or naming
    another folder that holds a decoy copy at the same id, the page renders the tenant's own
    episode, and never writes into the decoy. An episode that exists only under the variable's
    folder is not the tenant's: refused, nothing written there. (Name kept.)"""
    import shutil

    from defender.tests import _triplet_947 as T
    from defender.tests.ids_1187 import _spec1187 as S

    ep, episode_id = _tenant_episode(d9_tenant)
    page = ep / E.PAGE_NAME
    # The variable set, to a folder that is not the tenant's (the suite's roots set none, O9).
    monkeypatch.setenv(P.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    ok = P.drive_cli(P.page_main(), P.new_page_argv(d9_tenant, episode_id))
    assert ok.rc == 0, f"--tenant T <episode id> did not render: {ok.said}"
    assert page.is_file()

    page.unlink()
    monkeypatch.delenv(P.EPISODES_BASE_ENV, raising=False)
    unset = P.drive_cli(P.page_main(), P.new_page_argv(d9_tenant, episode_id))
    assert unset.rc == 0, f"the page needed the retired variable: {unset.said}"
    assert page.is_file()

    page.unlink()
    elsewhere = tmp_path / "another-root"
    shutil.copytree(ep, elsewhere / episode_id)
    monkeypatch.setenv(P.EPISODES_BASE_ENV, str(elsewhere))
    decoyed = P.drive_cli(P.page_main(), P.new_page_argv(d9_tenant, episode_id))
    assert decoyed.rc == 0, decoyed.said
    assert page.is_file(), "the tenant's own episode was not the one rendered"
    assert not (elsewhere / episode_id / E.PAGE_NAME).exists(), "the page wrote into the decoy"

    only_there = S.new_id()
    shutil.copytree(ep, elsewhere / only_there)
    # The copied rendered page is fixture input, not evidence that the stray CLI wrote one.
    (elsewhere / only_there / E.PAGE_NAME).unlink()
    T.write_family(elsewhere / only_there,
                   T.family_doc(episode_id=only_there, source_run_id=S.new_id()))
    stray = P.drive_cli(P.page_main(), P.new_page_argv(d9_tenant, only_there))
    assert stray.rc not in (0, None) or stray.raised is not None, (
        "an episode outside <T>/episodes was rendered")
    assert not (elsewhere / only_there / E.PAGE_NAME).exists()


def test_dc4_the_page_judges_the_container_record_first(tmp_path, d9_tenant):
    """Declared change 4 / G20 / S1: the page opens the episode view before `_load_episode`
    reads anything. RED at base: the page checks no tenant, and reads the manifest first.

    #1187 declared changes 6 and 8 (R1, O8): no container record is judged — the episode's
    tenant is where it lives. Tenant `beta`'s episode, asked for by T's id, is refused: T's
    repository finds nothing under `<T>/episodes`, no `learning.html` is written, and nothing of
    beta's episode changes — even with beta's manifest corrupt, the refusal is not the
    manifest's (it never names `family.yaml`: nothing of beta's was read). Positive controls on
    the same episode through the same channel: beta's own request over the corrupt manifest
    refuses FOR the manifest (naming `family.yaml`), and with the manifest restored beta's page
    renders. (Name kept.)"""
    P.second_tenant(P.data_root(), "beta")
    ep, episode_id = _tenant_episode("beta")
    page = ep / E.PAGE_NAME
    good_manifest = (ep / "family.yaml").read_bytes()
    before = P.tree(ep)

    foreign = P.drive_cli(P.page_main(), P.new_page_argv(d9_tenant, episode_id))
    assert foreign.rc not in (0, None) or foreign.raised is not None, (
        "another tenant's episode was rendered")
    assert not page.exists()
    assert P.tree(ep) == before, "T's request changed beta's episode"

    _corrupt_manifest(ep)
    first = P.drive_cli(P.page_main(), P.new_page_argv(d9_tenant, episode_id))
    assert first.rc not in (0, None) or first.raised is not None
    assert "family.yaml" not in first.said, (
        f"T's request read beta's manifest before refusing: {first.said!r}")

    own_corrupt = P.drive_cli(P.page_main(), P.new_page_argv("beta", episode_id))
    assert own_corrupt.rc not in (0, None) or own_corrupt.raised is not None
    assert "family.yaml" in own_corrupt.said, (
        f"control: beta's own request did not reach its manifest: {own_corrupt.said!r}")
    (ep / "family.yaml").write_bytes(good_manifest)
    ok = P.drive_cli(P.page_main(), P.new_page_argv("beta", episode_id))
    assert ok.rc == 0, ok.said
    assert page.is_file(), ok.said


def test_dc4_the_page_roster_is_the_manifests_arms_and_no_stray(tmp_path, d9_tenant):
    """Declared change 4 / J3 as settled (the spine's ruling on #1105): the page's arm roster
    comes from the manifest's runnable labels, each arm opened by id through the episode view;
    an entry in the episode's `runs/` that is no manifest arm is no longer shown (the
    `ROSTER_STRAY_RUN_DIR` rows go).

    The episode's `runs/` (its record naming T) holds, beside the three arms, a directory whose
    name is not `<episode>-<label>` (`stray_run_dir`) and one that decomposes to a label no
    manifest world carries (`<episode>-orphan`). The page renders; POSITIVE CONTROL: every
    runnable manifest label has its world section and its arm's run-page link. Neither stray
    has a section, a link or its name on the page, no line reads "not declared in the
    manifest", and both are left on disk. RED at base: `_build_roster` sections every `runs/`
    directory — `world-stray_run_dir` ("not declared in the manifest") and `world-orphan`.

    #1187 declared change 15: each arm's link is to the id the episode's arm roster
    (`arms.json`) holds for its label, never the composed `runs/<episode>-<label>/`; a third
    stray, a UUID-named folder no roster entry names, is not shown either. The test plants
    what `start_runs` leaves (`_roster_by_hand`: the roster, each arm moved to its roster id),
    then a DECOY complete arm at each composed `runs/<episode>-<label>/`, so a page that
    composes links the decoy and fails. The episode is the shared fixture's, at
    `<T>/episodes/<uuid>/` with no container record (`_sample`)."""
    from defender.tests.ids_1187 import _spec1187 as S

    ep = _sample(tmp_path, d9_tenant)
    roster = _roster_by_hand(ep.dir)
    for label in E.WORLDS:
        E.run_dir(ep.dir, label)
        decoy = ep.dir / "runs" / f"{P.EPISODE_ID}-{label}"
        (decoy / "gather_raw").mkdir(parents=True, exist_ok=True)
        (decoy / "runtime.html").write_text("<!doctype html><title>decoy</title>",
                                            encoding="utf-8")
    strays = ("stray_run_dir", f"{P.EPISODE_ID}-orphan", S.new_id())
    for name in strays:
        (ep.dir / "runs" / name / "gather_raw").mkdir(parents=True)

    ok = P.drive_cli(P.page_main(), P.page_argv(d9_tenant, ep.dir))
    assert ok.rc == 0, f"the page was not rendered: {ok.said}"
    page = E.read_page(ep)
    for label in E.WORLDS:
        assert f"world-{label}" in page.by_id, f"the manifest arm {label} has no section"
        assert f"runs/{roster[label]}/runtime.html" in page.hrefs, (
            f"the manifest arm {label} has no run-page link at its roster id: {page.hrefs}")
        assert not any(f"runs/{P.EPISODE_ID}-{label}/" in href for href in page.hrefs), (
            f"the manifest arm {label} is linked at its composed decoy: {page.hrefs}")
    shown = sorted(i for i in page.ids_with("world-")
                   if i not in {f"world-{label}" for label in E.WORLDS})
    assert shown == [], f"a stray runs/ entry was sectioned: {shown}"
    for name in strays:
        assert not any(name in href for href in page.hrefs), f"{name} is linked"
        assert name not in page.text, f"{name} is shown on the page"
        assert (ep.dir / "runs" / name).is_dir()
    assert "not declared in the manifest" not in page.text


# ==========================================================================================
# 5 — verify opens each arm through the view.
# ==========================================================================================

class _LinkingSibling(P.J.FakeSibling):
    """`FakeSibling` whose arm `b` is materialised OUTSIDE the container, with a link left at
    its name: the one arm-entry shape a host (never a box: seccomp, B-03) can leave. #1187: the
    arm's name is the id the episode's roster holds for `b`."""

    def __init__(self, *, outside: Path) -> None:
        super().__init__()
        self.outside = outside

    def __call__(self, argv, *, env=None, **kw):
        rc = super().__call__(argv, env=env, **kw)
        if self.episode_dir is None:
            return rc
        arm_id = P.T.read_roster(self.episode_dir).get("b")
        if arm_id is None:
            return rc
        arm = self.episode_dir / "runs" / arm_id
        if arm.is_dir() and not arm.is_symlink():
            target = self.outside / arm.name
            shutil.move(str(arm), str(target))
            (target / "report.md").write_text(
                P.T.report_text("benign", extra="OUTSIDE-THE-CONTAINER"), encoding="utf-8")
            os.symlink(target, arm)
        return rc


def test_dc5_an_arm_entry_that_is_a_link_is_never_archived(tmp_path, monkeypatch):
    """Declared change 5: verify opens each finished arm with `view.open(view.arm_id(label))`,
    whose entry rule refuses anything but a real directory. An arm whose entry is a link to a
    run folder outside the container is never archived from its target: no world's archive
    carries the target's bytes — however verify surfaces the refusal (the design leaves that to
    J3, so nothing about the launch's exit or the other arms is asserted). The positive
    control is a clean launch under fresh roots: arm `b`'s report IS archived at
    `worlds/b/report.md`, so the channel this test watches is the one the archive writes.
    RED at base: verify joins `runs/<ep>-<label>` by hand and the archive copies through the
    link."""
    est, src = P.launch_source(tmp_path)
    outside = tmp_path / "outside-arms"
    outside.mkdir()
    linking = _LinkingSibling(outside=outside)
    got = P.drive_launch(est, P.launch_argv(P.LAUNCH_TENANT, src), spawn=linking)
    assert got.questioner.calls > 0, f"the launch never ran: {got.message!r}"
    ep = _the_launched_episode()
    assert linking.faults == [], linking.faults
    assert any(p.is_symlink() for p in (ep / "runs").iterdir()), (
        "the double left no link at arm b's name: the scene this test is about was not built")
    archived = [p for p in (ep / "worlds").rglob("*") if p.is_file()] if (
        ep / "worlds").is_dir() else []
    leaked = [p for p in archived if b"OUTSIDE-THE-CONTAINER" in p.read_bytes()]
    assert leaked == [], f"the link's target was archived: {leaked}"

    control_root = tmp_path / "control"
    control_root.mkdir()
    monkeypatch.setenv(P.DATA_ROOT_ENV, str(tmp_path / "control-data"))
    P.roots(control_root, monkeypatch)
    est2, src2 = P.launch_source(control_root)
    clean = P.drive_launch(est2, P.launch_argv(P.LAUNCH_TENANT, src2))
    assert _launched(clean), f"the control did not launch: {clean.message!r}"
    assert (_the_launched_episode() / "worlds" / "b" / "report.md").is_file()


# ==========================================================================================
# 6 — the sibling: `run.py --tenant T --episode <ep> --world L`.
# ==========================================================================================

def test_dc6_the_launcher_starts_siblings_by_tenant_episode_label(tmp_path):
    """Declared change 6 (D5″ row 8): each sibling's argv is `--tenant T --episode <episode_id>
    --world L` — the address's tenant and episode plus the label — with no `--resume` and no
    path anywhere after `run.py` (O1(c)). Asserted on the spawn seam's captured argv: one start
    per world label. RED at base: the argv is `--resume <episode>/family.yaml --world L
    --tenant T`.

    #1187 declared changes 3 and 5: the `--episode` every sibling is handed is the episode the
    launch claimed — one fresh canonical UUID, the name of the one folder the launch made under
    `<T>/episodes/` — never the derived `<source id>-n<message>`. (Name kept.)"""
    from defender.tests.ids_1187 import _spec1187 as S

    est, src = P.launch_source(tmp_path)
    got = P.drive_launch(est, P.launch_argv(P.LAUNCH_TENANT, src))
    assert _launched(got), f"the launch did not run: {got.message!r}"
    made = sorted(_tenant_episode_names(P.LAUNCH_TENANT))
    assert len(made) == 1, f"the launch made {made} under <T>/episodes"
    seen = []
    for launch in got.spawn.launches:
        argv = launch["argv"]
        tail = argv[next(i for i, a in enumerate(argv) if a.endswith("run.py")) + 1:]
        assert "--resume" not in tail, f"a sibling was started with --resume: {tail}"
        assert not any("/" in tok for tok in tail), f"a sibling's argv carries a path: {tail}"
        flags = dict(zip(tail[::2], tail[1::2], strict=False))
        assert flags.get("--tenant") == P.LAUNCH_TENANT, tail
        assert S.is_canonical_uuid(flags.get("--episode")), f"--episode is no uuid: {tail}"
        assert flags.get("--episode") == made[0], f"--episode is not the claimed folder: {tail}"
        seen.append(flags.get("--world"))
    assert sorted(seen) == ["a", "b", "c"]


def test_dc6_run_py_refuses_resume_and_takes_the_episode_id(tmp_path):
    """Declared change 6 (F-10; G18 replaced): `run.py --resume <family.yaml> …` is refused as
    a usage error with nothing spent; `--episode` passes the owner's id grammar before anything
    opens (a separator, `..`: refused, nothing spent). The positive control is the declared
    argv for the same episode: the sibling runs its arm. RED at base: `--resume` is the
    sibling's edge, and `--episode` is unknown.

    #1187 declared changes 2, 10 and 15 (R1, R2, O4b): the episode reached RUNS when its arm
    roster names the label — no container record — and the arm is made at the roster's id for
    `b`, never at `runs/<episode>-b`. (Name kept.)"""
    src, ep = P.sibling_scene(tmp_path, roster=False)
    roster = _start_runs_by_hand(ep)
    resume = ["--resume", str(ep / "family.yaml"), "--world", "b", "--tenant", P.SIBLING_TENANT]
    rec = P.SiblingRecorder()
    rc, refused, _err = P.drive_run_py(resume, rec)
    assert refused is not None, "--resume was accepted"
    assert refused.code not in (0, None), "--resume was accepted"
    assert rec.order == []

    for bad in ("../escape", "a/b"):
        bad_rec = P.SiblingRecorder()
        rc, refused, _err = P.drive_run_py(P.new_sibling_argv(P.SIBLING_TENANT, bad, "b"), bad_rec)
        assert refused is not None, f"--episode {bad!r} was opened"
        assert bad_rec.order == [], f"--episode {bad!r} was opened"

    ok = P.SiblingRecorder()
    rc, refused, err = P.drive_run_py(P.new_sibling_argv(P.SIBLING_TENANT, ep.name, "b"), ok)
    assert refused is None, f"the declared argv was refused: {P.refusal_text(refused)} {err}"
    assert rc == 0, f"the declared argv was refused: {P.refusal_text(refused)} {err}"
    assert ok.run_dir == ep / "runs" / roster["b"], f"the arm is at {ok.run_dir}"


def _start_runs_by_hand(ep: Path) -> dict[str, str]:
    """What the launcher's `start_runs` leaves at the start of RUNS (#1187 R2): `runs/`, then
    the arm roster naming every manifest world with a fresh UUID. Returns the roster."""
    from defender import _yaml
    from defender.tests.ids_1187 import _spec1187 as S

    doc = _yaml.safe_load((ep / "family.yaml").read_text(encoding="utf-8"))
    roster = {w["world_id"]: S.new_id() for w in doc["worlds"]}
    (ep / "runs").mkdir(exist_ok=True)
    S.write_roster(ep, roster)
    return roster


def test_dc6_a_sibling_over_an_absent_container_is_refused(tmp_path):
    """Declared change 6 / G5 / R51-02: an episode that never reached RUNS binds no arm, so a
    sibling over it is refused — before the preflight and the lifecycle — and NO container is
    made. RED at base: run setup creates the container for whoever asks.

    #1187 declared change 10 (O4b): the proof that the episode reached RUNS is the host-written
    arm roster, not a container record. The positive control is the same episode once RUNS has
    started — `runs/` and a roster naming `b`, no `_tenant.json` anywhere: the sibling runs,
    its arm at the roster's id inside the container."""
    src, ep = P.sibling_scene(tmp_path, roster=False)
    assert not (ep / "runs").exists()
    rec = P.SiblingRecorder()
    rc, refused, _err = P.drive_run_py(P.sibling_argv(P.SIBLING_TENANT, ep, "b"), rec)
    assert refused is not None, "a sibling ran over an episode that never reached RUNS"
    assert rec.order == [], f"the sibling spent before refusing: {rec.order}"
    assert not (ep / "runs").exists(), "the refused sibling made the container"

    roster = _start_runs_by_hand(ep)
    ok = P.SiblingRecorder()
    rc, refused, err = P.drive_run_py(P.sibling_argv(P.SIBLING_TENANT, ep, "b"), ok)
    assert refused is None, f"the control was refused: {P.refusal_text(refused)} {err}"
    assert rc == 0, f"the control was refused: {P.refusal_text(refused)} {err}"
    assert ok.run_dir == ep / "runs" / roster["b"], f"the arm is at {ok.run_dir}"


def test_dc6_the_sibling_judges_the_container_before_the_manifest(tmp_path):
    """Declared change 6 / G19 / S-c1 amended: the sibling's view is judged right after
    acceptance, BEFORE the manifest. RED at base: the manifest is read (and refused) first.

    #1187 declared change 10 (O4b): what is judged is the arm roster, not a container record.
    The manifest carries a field the family loader refuses BY NAME, so the name reaches the
    refusal if and only if the manifest was read. With no roster naming `b` (the roster names
    only the other worlds), the refusal does not carry it. Positive controls on the same
    episode: the roster naming `b`, the poisoned manifest refuses for that field; the manifest
    restored, the sibling runs."""
    from defender import _yaml
    from defender.tests.ids_1187 import _spec1187 as S

    poison = "zz_dc6_never_read_before_the_roster"
    src, ep = P.sibling_scene(tmp_path, roster=False)
    good = (ep / "family.yaml").read_bytes()
    roster = _start_runs_by_hand(ep)
    S.write_roster(ep, {k: v for k, v in roster.items() if k != "b"})
    doc = _yaml.safe_load(good.decode("utf-8"))
    (ep / "family.yaml").write_text(_yaml.safe_dump({**doc, poison: "read"}), encoding="utf-8")

    rec = P.SiblingRecorder()
    _rc, refused, err = P.drive_run_py(P.sibling_argv(P.SIBLING_TENANT, ep, "b"), rec)
    said = f"{P.refusal_text(refused)}\n{err}"
    assert refused is not None
    assert rec.order == []
    assert poison not in said, f"the manifest was read before the roster: {said!r}"

    S.write_roster(ep, roster)
    mrec = P.SiblingRecorder()
    _rc, refused, err = P.drive_run_py(P.sibling_argv(P.SIBLING_TENANT, ep, "b"), mrec)
    assert refused is not None
    assert poison in f"{P.refusal_text(refused)}\n{err}", (
        "past the roster, the manifest's refusal should name the poisoned field")
    assert mrec.order == []

    (ep / "family.yaml").write_bytes(good)
    ok = P.SiblingRecorder()
    rc, refused, err = P.drive_run_py(P.sibling_argv(P.SIBLING_TENANT, ep, "b"), ok)
    assert refused is None, f"the control was refused: {P.refusal_text(refused)} {err}"
    assert rc == 0, f"the control was refused: {P.refusal_text(refused)} {err}"


# ==========================================================================================
# 7 — the run page: `--tenant T [--episode ep] <run_id>`.
# ==========================================================================================

def _run_page_child(argv: list[str]) -> subprocess.CompletedProcess:
    """The run page CLI as the operator runs it (a process), JSON log lines on stderr."""
    from defender import run_common

    script = run_common.DEFENDER_DIR / "scripts" / "visualize" / "visualize_run.py"
    return subprocess.run(  # noqa: S603 — this interpreter, the renderer script, ids
        [sys.executable, str(script), *argv[1:]], capture_output=True, text=True,
        encoding="utf-8", check=False, env={**os.environ, "DEFENDER_LOG_FORMAT": "json"})


def test_dc7_the_run_page_takes_a_tenant_and_a_run_id(tmp_path):
    """Declared change 7 / J8: `visualize_run.py --tenant T <run_id>` renders T's run, and
    every log line names the REQUEST's tenant — not the one the run's box-writable stamp names
    (here rewritten to another tenant). With `--episode ep`, the arm renders from its episode's
    container (#1187: the arm is named by the id the episode's roster holds for its label, not
    `<ep>-<label>`). RED at base: the CLI takes a folder path ("usage")."""
    src, ep = P.sibling_scene(tmp_path)
    stamp = src / "provenance.json"
    doc = json.loads(stamp.read_text(encoding="utf-8"))
    stamp.write_text(json.dumps({**doc, "tenant_id": "beta"}), encoding="utf-8")

    child = _run_page_child(P.new_run_page_argv(P.SIBLING_TENANT, src.name))
    assert child.returncode == 0, f"--tenant T <run id> did not render: {child.stderr[-600:]!r}"
    assert (src / "runtime.html").is_file()
    lines = [json.loads(line) for line in child.stderr.splitlines() if line.startswith("{")]
    named = [line.get("tenant_id") for line in lines if line.get("tenant_id") is not None]
    assert named, f"the log does not file the re-render under the request's tenant: {named!r}"
    assert set(named) == {P.SIBLING_TENANT}, (
        f"the log does not file the re-render under the request's tenant: {named!r}")

    # The arm as a real sibling leaves it: its case pointer names the source's store (a sibling
    # forks into the source's database), so the page's store precondition (M1, pinned by
    # e2e/test_1110::…o4…store_cannot_be_resolved…) holds for it as for any run — `--episode`
    # gets no pass on it.
    from defender.runtime import session_store

    arm = P.T.sibling_run_dir(ep / "runs", "b")
    session_store.write_case_pointer(_run_handle_1165(arm), case_id=P.T.SOURCE_CASE_ID,
                                     store_path=session_store.resolve_store_path(_run_handle_1165(src)))
    got = P.drive_cli(P.run_page_main(), P.new_run_page_argv(
        P.SIBLING_TENANT, arm.name, episode_id=ep.name))
    assert got.rc == 0, f"--episode ep <arm id> did not render: {got.said}"
    assert (arm / "runtime.html").is_file()


def test_dc7_the_run_page_refuses_a_linked_run_folder(tmp_path):
    """Declared changes 7 and 11 (B-28): T's run name `<T>/runs/<id>` is a link to a real run
    folder elsewhere. The run page opens through `runs.open`, which never follows it: a
    non-zero exit and nothing written into the target. The positive control renders the real
    folder. RED at base: `Run.at` follows the link and writes `runtime.html` into its target."""
    src, _ep = P.sibling_scene(tmp_path)
    # #1187 declared change 1: the link's name is a uuid, so the id rule admits it and the
    # refusal is the link's (O8), never the id grammar's.
    target = tmp_path / "elsewhere" / fixture_uuid("dc7-linked")
    shutil.copytree(src, target)
    link = src.parent / target.name
    os.symlink(target, link)
    before = P.tree(target)

    got = P.drive_cli(P.run_page_main(), P.run_page_argv(P.SIBLING_TENANT, link))
    assert got.rc not in (0, None) or got.raised is not None, "the run page followed a linked run"
    assert P.tree(target) == before, "the run page wrote into the link's target"

    ok = P.drive_cli(P.run_page_main(), P.run_page_argv(P.SIBLING_TENANT, src))
    assert ok.rc == 0, ok.said
    assert (src / "runtime.html").is_file(), ok.said


# ==========================================================================================
# 8 — curation rows are `{case_id, tenant_id, run_id}`.
# ==========================================================================================

def test_dc8_a_natural_run_enqueues_its_address_not_its_folder(tmp_path, d9_tenant):
    """Declared change 8 (D-stored; decision 7): a natural run through `run.py <alert> --tenant
    T` — the real run setup, the real reap scan, the real enqueue — queues exactly
    `{case_id, tenant_id: T, run_id: <its id>}`: a natural run's `RunAddress`, no path. RED at
    base: the row is `{case_id, run_dir}`."""
    from defender.runtime import scrub

    alert = H.alert_file(tmp_path / "in")
    rec = P.SiblingRecorder()

    def scrubbed_lifecycle(**kwargs):
        rec.order.append("lifecycle")
        rec.lifecycle_kwargs = kwargs
        scrub.scrub(Path(kwargs["run"].run_dir))
        return {"output": "ok", "requests": 0, "truncated_by": None}

    seams = {k: v for k, v in rec.seams().items() if k != "enqueue"}
    seams["lifecycle"] = scrubbed_lifecycle
    from defender import run as run_py

    rc = run_py.main([str(alert), "--tenant", d9_tenant], **seams)
    assert rc == 0
    run_dir = rec.run_dir
    assert run_dir is not None
    assert run_dir.parent == P.data_root() / d9_tenant / "runs"
    from defender.learning.core.config import loop_paths

    queue = Path(loop_paths().state_root) / "author-queue"
    rows = [json.loads(p.read_text(encoding="utf-8")) for p in sorted(queue.glob("*.json"))]
    assert len(rows) == 1, rows
    row = rows[0]
    assert set(row) == {"case_id", "tenant_id", "run_id"}, f"the row is {row!r}"
    assert row["tenant_id"] == d9_tenant
    assert row["run_id"] == run_dir.name
    assert not any(str(run_dir) in str(v) for v in row.values())


#: The drain scene's run ids (#1187, declared change 1: a run id is a canonical UUID — a row
#: naming an old `r1` is off grammar and quarantined before the drain's own-tenant rehydration
#: is reached). `RID_R1` is held by BOTH tenants, so serving the wrong tenant's folder is visible.
RID_R1 = fixture_uuid("pr2-dc8-r1")
R_OLD = fixture_uuid("pr2-dc8-r-old")
ONLY_IN_U = fixture_uuid("pr2-dc8-only-in-u")
NOPE = fixture_uuid("pr2-dc8-nope")
LINKED = fixture_uuid("pr2-dc8-linked")


def _drain_scene(tmp_path: Path):
    """Two real tenants under the data root, each with a natural runs folder holding `RID_R1`, and
    the drain's paths (a git work tree and a state root)."""
    root = P.data_root()
    t = H.tenant(root, H.T_ID)
    u = H.tenant(root, H.U_ID)
    for tenant in (t, u):
        H.runs_folder(tenant)
        H.make_run(tenant.runs, RID_R1)
    return t, u, P.loop_paths(tmp_path)


def test_dc8_the_drain_rehydrates_the_row_in_its_own_tenant(tmp_path):
    """Declared change 8 / G21: the drain accepts each row's `tenant_id` and opens `run_id` in
    THAT tenant's repository, then serves the lead author that run. Two tenants each hold a run
    `RID_R1`; the rows for each are served with their own folder, never the other's. RED at base:
    a row with no `run_dir` is quarantined as "unreadable" and nothing is served."""
    t, u, paths = _drain_scene(tmp_path)
    P.queue_row(paths, "case-t", {"case_id": "case-t", "tenant_id": H.T_ID, "run_id": RID_R1})
    P.queue_row(paths, "case-u", {"case_id": "case-u", "tenant_id": H.U_ID, "run_id": RID_R1})
    lane = P.Lane()
    P.drain(paths, lane)
    assert sorted(lane.run_dirs) == sorted([Path(t.runs) / RID_R1, Path(u.runs) / RID_R1]), (
        f"served {lane.run_dirs}")
    assert P.dead_letter(paths, "case-t") is None
    assert P.dead_letter(paths, "case-u") is None


def test_dc8_the_claim_admits_only_the_new_row_shape(tmp_path):
    """Declared change 8 / O9: the claim checks the row's shape only — `tenant_id` and `run_id`
    present and on their grammars. A row missing `tenant_id`, one whose `run_id` or `tenant_id`
    is off grammar, and an OLD row `{case_id, run_dir}` naming a real run folder (no code
    serves the old shape; the deploy note clears them) each take today's "unreadable…"
    quarantine and are never served. The positive control, a well-formed row in the same
    tick, is served. RED at base: the old row is served and the new one quarantined."""
    t, _u, paths = _drain_scene(tmp_path)
    old_run = H.make_run(t.runs, R_OLD)
    P.queue_row(paths, "good", {"case_id": "good", "tenant_id": H.T_ID, "run_id": RID_R1})
    bad = {
        "no-tenant": {"case_id": "no-tenant", "run_id": RID_R1},
        "bad-run": {"case_id": "bad-run", "tenant_id": H.T_ID, "run_id": f"../{RID_R1}"},
        "bad-tenant": {"case_id": "bad-tenant", "tenant_id": "Not A Tenant", "run_id": RID_R1},
        "old-shape": {"case_id": "old-shape", "run_dir": str(old_run)},
    }
    for case_id, body in bad.items():
        P.queue_row(paths, case_id, body)
    lane = P.Lane()
    P.drain(paths, lane)
    assert lane.run_dirs == [Path(t.runs) / RID_R1], f"served {lane.run_dirs}"
    for case_id in bad:
        letter = P.dead_letter(paths, case_id)
        assert letter is not None, f"{case_id}: {letter!r}"
        assert str(letter.get("failed", "")).startswith("unreadable"), f"{case_id}: {letter!r}"


def test_dc8_a_row_that_cannot_be_reached_is_artifact_missing(tmp_path):
    """Declared changes 8 and 11 / G21 (S9, as the owner amended it on PR #1236): a well-formed
    row whose run is GONE — absent in its tenant, or present only in ANOTHER tenant — is
    quarantined at once as "artifact-missing" and never served. A row that cannot be reached
    right now — its tenant refused (no such tenant), its run folder a link (never followed) —
    is not: it is a counted transient attempt, re-queued (`test_1105_pr2_review_fixes.py` pins
    the retry ceiling). The positive control in the same tick: U's own row is served with U's
    folder. RED at base: such rows have no `run_dir` and take "unreadable" instead."""
    t, u, paths = _drain_scene(tmp_path)
    H.make_run(u.runs, ONLY_IN_U)
    os.symlink(Path(t.runs) / RID_R1, Path(t.runs) / LINKED)
    gone = {
        "absent": {"case_id": "absent", "tenant_id": H.T_ID, "run_id": NOPE},
        "crossed": {"case_id": "crossed", "tenant_id": H.T_ID, "run_id": ONLY_IN_U},
    }
    not_now = {
        "ghost": {"case_id": "ghost", "tenant_id": "ghost", "run_id": RID_R1},
        "linked": {"case_id": "linked", "tenant_id": H.T_ID, "run_id": LINKED},
    }
    for case_id, body in {**gone, **not_now}.items():
        P.queue_row(paths, case_id, body)
    P.queue_row(paths, "own", {"case_id": "own", "tenant_id": H.U_ID, "run_id": ONLY_IN_U})
    lane = P.Lane()
    P.drain(paths, lane)
    assert lane.run_dirs == [Path(u.runs) / ONLY_IN_U], f"served {lane.run_dirs}"
    for case_id in gone:
        letter = P.dead_letter(paths, case_id)
        assert letter is not None, f"{case_id}: {letter!r}"
        assert letter.get("failed") == "artifact-missing", f"{case_id}: {letter!r}"
    for case_id in not_now:
        assert P.dead_letter(paths, case_id) is None, f"{case_id} was dead-lettered at once"
        assert P.still_queued(paths, case_id), f"{case_id} was not re-queued"


def test_dc8_a_drain_with_no_data_root_leaves_its_rows_queued(tmp_path, monkeypatch):
    """Declared change 8: the drain resolves the data root once per tick; with none it refuses
    the tick — the lead author is never called and the row is neither served nor dead-lettered
    (it waits, queued or in its claim slot, for a tick that can serve it). The positive
    control restores the root: the same row is served. RED at base: the drain reads no data
    root and dead-letters the address row as "unreadable"."""
    t, _u, paths = _drain_scene(tmp_path)
    root = os.environ[P.DATA_ROOT_ENV]
    P.queue_row(paths, "case-t", {"case_id": "case-t", "tenant_id": H.T_ID, "run_id": RID_R1})
    monkeypatch.delenv(P.DATA_ROOT_ENV)
    lane = P.Lane()
    H.raised(P.drain, paths, lane)
    assert lane.handed == [], "the drain served a row with no data root"
    assert P.dead_letter(paths, "case-t") is None
    assert P.still_queued(paths, "case-t")

    monkeypatch.setenv(P.DATA_ROOT_ENV, root)
    P.drain(paths, lane)
    assert lane.run_dirs == [Path(t.runs) / RID_R1]


# ==========================================================================================
# 9 — the manifest: `source_run_dir` no longer written; tolerated, never read.
# ==========================================================================================

def test_dc9_the_launchers_manifest_names_its_source_by_id_only(tmp_path):
    """Declared change 9: the launcher's `family.yaml` names the source by `source_run_id`
    alone; `source_run_dir` is no longer written (O1(c): a manifest written after PR 2 carries
    no run-folder path). RED at base: the writer emits `source_run_dir: <path>`."""
    est, src = P.launch_source(tmp_path)
    got = P.drive_launch(est, P.launch_argv(P.LAUNCH_TENANT, src))
    assert _launched(got), f"the launch did not run: {got.message!r}"
    from defender import _yaml

    doc = _yaml.safe_load((_the_launched_episode() / "family.yaml").read_text(encoding="utf-8"))
    assert doc.get("source_run_id") == src.name
    assert "source_run_dir" not in doc, f"the manifest still names a path: {doc.get('source_run_dir')!r}"
    assert str(src) not in json.dumps(doc, default=str)


def test_dc9_a_manifest_without_source_run_dir_resumes(tmp_path):
    """Declared change 9: `_check_scalars` stops requiring `source_run_dir`. A sibling over a
    manifest that carries only `source_run_id` resumes: its arm's alert is the source run's.
    RED at base: the manifest is refused ("source_run_dir must be a non-empty string")."""
    doc = P.T.family_doc(source_run_id=P.SOURCE_RUN_ID)
    doc.pop("source_run_dir")
    src, ep = P.sibling_scene(tmp_path, doc=doc)
    rec = P.SiblingRecorder()
    rc, refused, err = P.drive_run_py(P.sibling_argv(P.SIBLING_TENANT, ep, "b"), rec)
    assert refused is None, f"refused: {P.refusal_text(refused)} {err}"
    assert rc == 0, f"refused: {P.refusal_text(refused)} {err}"
    assert (rec.run_dir / "alert_input" / "alert.json").read_bytes() == (src / "alert_input" / "alert.json").read_bytes()


def test_dc9_an_old_manifests_source_run_dir_is_never_read(tmp_path):
    """Decision A / declared change 9: an old manifest carrying `source_run_dir` still loads,
    and its value steers nothing — the source is `source_run_id` in the tenant's natural
    container. Here the old field names a DECOY run of the same tenant with a different alert,
    and then a path that does not exist: each time the sibling resumes and its arm's alert is
    the `source_run_id` run's. RED at base: the sibling reads its source alert from
    `source_run_dir` (the decoy's alert; then refused for the missing path)."""
    base, src = P.T.runs_base(tmp_path, source_run_id=P.SOURCE_RUN_ID)
    decoy = base / fixture_uuid("dc9-decoy")  # #1187 dc1: a run id is a uuid
    shutil.copytree(src, decoy)
    (decoy / "alert.json").write_text('{"rule": {"id": "the-decoy-alert"}}\n', encoding="utf-8")

    for i, named in enumerate((str(decoy), str(tmp_path / "no-such-run"))):
        sub = tmp_path / f"scene{i}"
        sub.mkdir()
        episode_id = fixture_uuid(f"dc9-scene-{i}")  # #1187 dc3: an episode id is a uuid
        _s, ep = P.sibling_scene(sub, episode_id=episode_id,
                                 doc=P.family_doc(src, source_run_dir=named,
                                                  episode_id=episode_id))
        rec = P.SiblingRecorder()
        rc, refused, err = P.drive_run_py(P.sibling_argv(P.SIBLING_TENANT, ep, "b"), rec)
        assert refused is None, f"{named}: refused {P.refusal_text(refused)} {err}"
        assert rc == 0, f"{named}: refused {P.refusal_text(refused)} {err}"
        assert (rec.run_dir / "alert_input" / "alert.json").read_bytes() == (src / "alert_input" / "alert.json").read_bytes(), (
            f"the old field steered the source to {named}")


# ==========================================================================================
# 10 / J8 — the lead author, the tracer and `workspace_map` take `--tenant T`.
# ==========================================================================================

def _launcher_main():
    from defender.learning.branch import cli

    return cli.main


def _lead_author_main():
    from defender.learning.leads import lead_author

    return lead_author.main


def _tracer_main():
    from defender.learning.ops import trace_lesson

    return trace_lesson.main


def _workspace_map_main():
    from defender.scripts import workspace_map

    return workspace_map.main


#: #1187 declared change 1: a uuid no run holds, so only `--tenant`'s absence is refused.
ABSENT_ID = fixture_uuid("pr2-absent")

#: Each migrated CLI with an otherwise-complete id-taking argv, minus `--tenant`.
_J8_CASES = {
    "launcher": (_launcher_main, [ABSENT_ID, "59", "--continuation-prompt", "go"]),
    "lead_author": (_lead_author_main, [ABSENT_ID]),
    "tracer": (_tracer_main, ["--all"]),
    "run_page": (P.run_page_main, ["visualize_run.py", ABSENT_ID]),
    "episode_page": (P.page_main, [P.EPISODE_ID]),
    "workspace_map": (_workspace_map_main, ["workspace_map.py", ABSENT_ID]),
}


@pytest.mark.parametrize("cli", sorted(_J8_CASES))
def test_dc10_j8_every_migrated_cli_requires_the_tenant(cli, tmp_path, d9_tenant):
    """Fork decision J8: `--tenant` is REQUIRED, with no default, at the launcher, the lead
    author, the tracer, the run page, the episode page and `workspace_map` (S2: the tenant
    comes from the request). Each, given an otherwise complete id-taking command line without
    it, refuses non-zero and says `--tenant`. RED at base: none of the six knows `--tenant`."""
    main, argv = _J8_CASES[cli]
    if cli == "tracer":
        (tmp_path / "lessons").mkdir()
        argv = [*argv, "--lessons-dir", str(tmp_path / "lessons")]
    got = P.drive_cli(main(), argv)
    assert got.rc not in (0, None) or got.raised is not None, f"{cli} ran without --tenant"
    assert "--tenant" in got.said, f"{cli}'s refusal does not name --tenant: {got.said!r}"


def _lesson(lessons: Path, stem: str) -> None:
    lessons.mkdir(exist_ok=True)
    (lessons / f"{stem}.md").write_text(
        f"---\nname: {stem}\ndescription: d\ncreated_at: 2026-06-04\n---\nbody\n",
        encoding="utf-8")


def test_dc10_the_tracer_walks_the_tenants_runs_and_refuses_a_stray(tmp_path, d9_tenant):
    """Declared change 10 / J3 / J8: `trace_lesson --tenant T --all` walks T's natural runs
    folder (`<T>/runs`, no longer the dead `<state root>/runs` default): a run there that
    loaded lesson L counts. `--runs-dir` is gone (a usage error). The tracer applies the
    repository's listing rule (rev 4.1 H4): a stray file in `<T>/runs` fails it loudly, naming
    the stray. RED at base: the tracer does not know `--tenant`.

    #1187 declared changes 1, 6 and 7: the run the tracer counts is UUID-named in a container
    holding no `_tenant.json` (an old run folder, or the record, would itself stop the tracer,
    naming the one-time command). (Name kept.)"""
    import uuid

    from defender.learning.ops import trace_lesson

    lessons = tmp_path / "lessons"
    _lesson(lessons, "L")
    runs = P.data_root() / d9_tenant / "runs"
    runs.mkdir(parents=True, exist_ok=True)
    run = runs / str(uuid.uuid4())
    run.mkdir()
    from defender.tests._alert_plant import plant_alert
    plant_alert(run)
    (run / "report.md").write_text("---\ndisposition: benign\n---\nbody\n", encoding="utf-8")
    (run / "lessons_loaded.jsonl").write_text(
        json.dumps({"lesson_name": "L", "ts": "2026-06-05T00:00:00+00:00"}) + "\n",
        encoding="utf-8")

    ok = P.drive_cli(trace_lesson.main, ["--tenant", d9_tenant, "--all",
                                         "--lessons-dir", str(lessons)])
    assert ok.rc == 0, ok.said
    assert ok.out.splitlines() == ["L\td\t1\t0"], ok.out

    gone = P.drive_cli(trace_lesson.main, ["--tenant", d9_tenant, "--all", "--lessons-dir",
                                           str(lessons), "--runs-dir", str(runs)])
    assert gone.rc not in (0, None) or gone.raised is not None, "--runs-dir was accepted"

    (runs / "stray.txt").write_text("x\n", encoding="utf-8")
    stray = H.raised(P.drive_cli, trace_lesson.main,
                     ["--tenant", d9_tenant, "--all", "--lessons-dir", str(lessons)])
    if stray is None:
        got = P.drive_cli(trace_lesson.main, ["--tenant", d9_tenant, "--all",
                                              "--lessons-dir", str(lessons)])
        assert got.rc not in (0, None) or got.raised is not None, "a stray was skipped silently"
        assert "stray.txt" in got.said, got.said
    else:
        assert "stray.txt" in str(stray), repr(stray)


def test_dc10_workspace_map_takes_a_tenant_and_a_run_id(tmp_path, d9_tenant):
    """Declared change 10 / J8: `workspace_map.py --tenant T <run_id>` prints the map of T's run
    — the same text the library call (`workspace_map(run.run_dir, …)`, which the running
    investigation keeps, N-a) gives for that folder — and refuses a path where the id belongs.
    RED at base: the CLI takes a folder path ("usage").

    #1187 declared changes 1 and 6: the run id is a UUID (an old id is refused by every
    `--tenant T <id>` command line) and T's container holds no `_tenant.json`. (Name kept.)"""
    import uuid

    from defender._paths import adapters_under
    from defender.runtime.verbs import read_roster
    from defender.scripts import workspace_map as wm

    runs = P.data_root() / d9_tenant / "runs"
    run = H.make_run(runs, str(uuid.uuid4()))
    expected = wm.workspace_map(run, systems=tuple(read_roster(adapters_under(wm.DEFENDER_DIR)).accepted))

    ok = P.drive_cli(wm.main, ["workspace_map.py", "--tenant", d9_tenant, run.name])
    assert ok.rc == 0, ok.said
    assert ok.out == expected

    as_path = P.drive_cli(wm.main, ["workspace_map.py", "--tenant", d9_tenant, str(run)])
    assert as_path.rc not in (0, None) or as_path.raised is not None, "a path was taken as an id"

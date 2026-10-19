"""#1187 slice B2 — the arm roster's CONSUMERS: every reader that needs an arm's id or label
reads it from the host-written roster (`<T>/episodes/<ep>/arms.json`), never composes
`<episode_id>-<label>` (O4); the manifest's `episode_id` is checked against its folder in the one
loader (R5); `latest` is refused (R4); the archive writes no `worlds/<label>/run_dir` pointer
(R8); the redaction set is built from the roster (S-red). Design rev 2, issue #1187 comments
6192137519 / 6192137980; declared behaviour changes 9, 10 (manifest half), 12 and 15.

Every scene is planted on the real filesystem in the new layout (`_spec1187.make_episode`): the
episode under `<data root>/<T>/episodes/<uuid>/`, a LOADABLE manifest (`_triplet_947.family_doc`,
`_spec1224.family_v2`) rewritten to that uuid, the roster, and arm folders named by the roster's
ids. Where a composed name could be read by mistake, a DECOY folder `runs/<ep>-<label>/` sits
beside the real arm, so a reader that composes is caught by what it shows. Faults are real: a
torn roster, a roster whose labels are not the manifest's, two labels on one id, an old id, a
link at `arms.json`, a manifest naming another episode.

Entry points driven: the episode page CLI (`visualize_episode.main`, via `_spec1105_pr2.drive_cli`),
the branch launcher (`learning/branch/cli.main`, via `drive_launch`, its sibling a spawn double that
materialises each arm at the roster's id), VERIFY's arm opener (`cli._finished_arms`), the archive
(`archive.archive_episode`), the comparator reader (`episode.delta_o`), the sibling (`run.main`, its
lifecycle a probe that builds the REAL world registry through `run._drive_investigation`), the
judge's door (`runs.episode_files`), and the manifest loader itself.

`DEFENDER_EPISODES_BASE` points at an empty decoy folder in every test (O9): a reader that still
consulted it would find nothing there (or, where a test links the asked name into it, would find
and render the episode instead of refusing).

Review round 1 repairs driven through the REAL launcher: a pre-flight that does not accept writes
no roster and its hand-run sibling is refused (F1); the roster names every manifest world while
an unservable one is not started (F2); the episode lands under `<T>/episodes` with the variable
unset or a decoy, and `<T>/runs` is unchanged (F6, F12); acceptance counts `<T>/episodes` as
box-mounted (S-acc); an old source id is refused (F10). R5 at VERIFY and the judge (F8), and a
cross-tenant page request (F11).

Seams coined here (not on the interface sheet), reported to the orchestrator:
- `episode.delta_o(view, *, invoke=)` — the comparator reads the episode through the WALKED
  view (`runs.episode(ep)`, an `EpisodeRuns`) and takes the arm ids from that view's roster; no
  path re-binds the folder (recheck S2) and no caller hands the ids in (repair round 1, F7).
- `episode.verdicts(view)` — the archived worlds' dispositions, read through the same walked
  view (review-3 F32 ruling: the view forms are the only forms; no `Path` overload of
  `verdicts`, `delta_o` or `cli.preflight_replay(view.episode, ...)`).
- The manifest loader's refusal of a mismatched `episode_id` is `_family.FamilyError` (every
  manifest refusal of the loader is one today), and its message names both ids.
- A refused roster's reason names the roster's file name (`arms.json`), on the page and in
  VERIFY's refusal, as the manifest's refusals name `family.yaml`.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from defender.tests import _episode_1025 as E
from defender.tests import _judge_921 as J
from defender.tests import _triplet_947 as T
from defender.tests.ids_1187 import _spec1187 as R
from defender.tests.live_oracle_1224 import _spec1224 as S
from defender.tests.tenant_1105_run_repository import _spec1105_pr2 as P

#: The tenant every page / VERIFY / door scene is planted under (`_spec1187.tenant`'s default).
TENANT = R.H5.T_ID
#: The manifest's worlds: `a` the control, `b` and `c` the siblings (`_triplet_947.family_doc`).
LABELS = ("a", "b", "c")
#: The source run every manifest names (a UUID, as every run id after #1187).
SOURCE_ID = "5d0c3f7e-2a91-4b6e-8f14-9c7a2e5b3d60"
#: World `b`'s axis: manifest text the page renders whatever the arms' state.
AXIS_B = "AXIS-1187-B whether a second login to web-1 came from 10.0.0.9"
#: The outcome record's reason: an episode-level record the page renders whatever the arms'.
OUTCOME_REASON = "OUTCOME-1187 pre-flight calibrated every world against the live estate"
#: The redaction filter's marker (`learning.branch.redaction._TOKEN_MARK`).
MARK = "[a run id]"
#: An id no family knows: the filter's positive control.
UNRELATED_UUID = "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d"


@pytest.fixture(autouse=True)
def _decoy_episodes_base(tmp_path, monkeypatch):
    """`DEFENDER_EPISODES_BASE` names an empty folder outside the data root (O9: nothing reads
    it after #1187): an episode is found only at `<T>/episodes/<ep>`."""
    decoy = tmp_path / "decoy-episodes-base"
    decoy.mkdir()
    monkeypatch.setenv(R.EPISODES_BASE_ENV, str(decoy))


# ==========================================================================================
# Scene builders (new layout, loadable manifest, roster, arms named by roster id)
# ==========================================================================================

def _worlds(*, null_world: bool = False) -> list[dict]:
    """`a` the control, `b` (axis `AXIS_B`) and `c`; with `null_world`, also `d`, the `role:
    null` replicate a hand run starts (it has a roster id like every manifest world)."""
    worlds = [T.base_world(),
              T.world_doc("b", axis=AXIS_B, facts=[T.fact("f-b")]),
              T.world_doc("c", role="C", axis="axis of c", facts=[T.fact("f-c")])]
    if null_world:
        worlds.append(T.world_doc("d", role=None, axis="axis of d", facts=[T.fact("f-d")]))
    return worlds


def _doc(episode_id: str, *, null_world: bool = False) -> dict:
    """A loadable manifest (`_triplet_947.family_doc`) naming `episode_id` and `SOURCE_ID`."""
    return T.family_doc(worlds=_worlds(null_world=null_world), episode_id=episode_id,
                        source_run_id=SOURCE_ID)


def _labels(doc: dict) -> list[str]:
    return [w["world_id"] for w in doc["worlds"]]


def _episode(data_root: Path, *, roster: Any = True,
             null_world: bool = False) -> tuple[Path, str, dict | None]:
    """A fresh UUID episode under `TENANT` (`_episode_at`), its manifest `_doc`."""
    episode_id = R.new_id()
    return _episode_at(data_root, episode_id, _doc(episode_id, null_world=null_world), roster)


def _episode_at(data_root: Path, episode_id: str, doc: dict,
                roster: Any) -> tuple[Path, str, dict | None]:
    """`<data root>/<TENANT>/episodes/<episode_id>/` holding the loadable manifest `doc` and —
    `roster=True` — a fresh roster `{label: uuid}` for every manifest world (a mapping writes
    that mapping; `None` writes none). Returns `(folder, id, roster)`."""
    R.tenant(data_root)
    mapping = {label: R.new_id() for label in _labels(doc)} if roster is True else roster
    ep = R.make_episode(data_root, TENANT, episode_id, labels=_labels(doc),
                        roster=mapping if mapping is not None else False)
    T.write_family(ep, doc)
    return ep, episode_id, mapping


def _arm(ep: Path, name: str) -> Path:
    """A finished arm folder `<ep>/runs/<name>`: its alert, a `tool_trace.jsonl` ending in a
    result event, and the `runtime.html` its run page leaves."""
    rd = R.make_run(ep / "runs", name)
    E.write_tool_trace(rd, [E.result_event()])
    (rd / "runtime.html").write_text("<!doctype html><title>arm</title>", encoding="utf-8")
    return rd


def _outcome(ep: Path) -> None:
    """Pre-flight's `accepted` outcome record, through the production writer."""
    E.write_outcome(ep, "accepted", reason=OUTCOME_REASON, family_stamp=False)


def _page(episode_id: str, tenant_id: str = TENANT) -> P.CliResult:
    """The episode page CLI, `visualize_episode.py --tenant T <episode_id>`."""
    return P.drive_cli(P.page_main(), P.new_page_argv(tenant_id, episode_id))


def _arm_hrefs(page: E.Page) -> list[str]:
    return [h for h in page.hrefs if h.endswith("runtime.html")]


# ==========================================================================================
# R5 — the manifest's episode_id is its folder's name, checked in the one loader
# ==========================================================================================

def _loadable(which: str, episode_id: str) -> dict:
    """A real loadable manifest from an existing fixture, rewritten to `episode_id`."""
    if which == "triplet_947":
        return T.family_doc(episode_id=episode_id, source_run_id=SOURCE_ID)
    return S.family_v2(episode_id=episode_id, source_run_id=SOURCE_ID)


@pytest.mark.parametrize("which", ["triplet_947", "spec1224"])
def test_r5_the_loader_reads_a_manifest_whose_episode_id_is_its_folders(tmp_path, which):
    """R5 positive control: a manifest whose `episode_id` is the id its reader expects (the
    folder's name) loads through both loader doors — `load_family` gives the `Family`,
    `load_manifest_document` the mapping — each naming that id."""
    from defender._io import bind
    from defender.runtime.branch._family import load_family, load_manifest_document

    episode_id = R.new_id()
    ep = tmp_path / "episodes" / episode_id
    T.write_family(ep, _loadable(which, episode_id))
    with bind(ep) as view:
        family = load_family(view, expected_episode_id=episode_id)
        document = load_manifest_document(view, expected_episode_id=episode_id)
    assert family.episode_id == episode_id
    assert document["episode_id"] == episode_id


#: The manifest's `episode_id` for each mismatch case, from the folder's id: a fresh UUID, an
#: old id, and the folder's own id with ONE hex digit changed — the first, one in the middle
#: group, the last (adversary F11: a comparison of the first group alone passes the last two).
_MISMATCHES = {
    "another_uuid": lambda folder_id: R.new_id(),
    "old_id": lambda folder_id: R.OLD_MINTED_ID,
    "near_miss_first_digit": lambda folder_id: R.near_miss_id(folder_id, 0),
    "near_miss_middle_digit": lambda folder_id: R.near_miss_id(folder_id, 14),
    "near_miss_last_digit": lambda folder_id: R.near_miss_id(folder_id, -1),
}


@pytest.mark.parametrize("named", sorted(_MISMATCHES))
@pytest.mark.parametrize("which", ["triplet_947", "spec1224"])
def test_r5_the_loader_refuses_a_manifest_naming_another_episode(tmp_path, which, named):
    """R5 / declared change 10 (manifest half): the folder is `<A>`, the manifest says
    `episode_id: <B>` — another UUID, an old id, or `<A>` itself with one hex digit changed
    (first, middle, last: a mismatch only a whole-id comparison sees, adversary F11). Both
    loader doors refuse (`FamilyError`), naming both ids; neither hands back a document.
    Positive control: `test_r5_the_loader_reads_a_manifest_whose_episode_id_is_its_folders`."""
    from defender._io import bind
    from defender.runtime.branch._family import FamilyError, load_family, load_manifest_document

    folder_id = R.new_id()
    manifest_id = _MISMATCHES[named](folder_id)
    ep = tmp_path / "episodes" / folder_id
    T.write_family(ep, _loadable(which, manifest_id))
    for door in (load_family, load_manifest_document):
        with bind(ep) as view:
            err = R.raised(door, view, expected_episode_id=folder_id)
        assert R.is_a(err, FamilyError), f"{door.__name__} over a mismatched manifest: {err!r}"
        text = R.message(err)
        assert manifest_id in text, f"{door.__name__}'s refusal does not name {manifest_id}: {text}"
        assert folder_id in text, f"{door.__name__}'s refusal does not name {folder_id}: {text}"


@pytest.mark.parametrize("which", ["triplet_947", "spec1224"])
def test_r5_the_loader_refuses_a_one_digit_near_miss_at_every_position(tmp_path, which):
    """R5 (adversary F11), the sweep: for EACH of the 32 hex digits of the folder's id, a
    manifest naming the folder's id with just that digit changed is refused by both loader doors
    (`FamilyError`). A comparison of any proper part of the id — a prefix, a group, a suffix, a
    sample of positions — skips some digit, and the manifest differing there loads. Positive
    control: `test_r5_the_loader_reads_a_manifest_whose_episode_id_is_its_folders`."""
    from defender._io import bind
    from defender.runtime.branch._family import FamilyError, load_family, load_manifest_document

    folder_id = R.new_id()
    ep = tmp_path / "episodes" / folder_id
    loaded = []
    for digit in range(R.UUID_HEX_DIGITS):
        manifest_id = R.near_miss_id(folder_id, digit)
        T.write_family(ep, _loadable(which, manifest_id))
        for door in (load_family, load_manifest_document):
            with bind(ep) as view:
                err = R.raised(door, view, expected_episode_id=folder_id)
            if not R.is_a(err, FamilyError):
                loaded.append(f"digit {digit} ({manifest_id}) via {door.__name__}: {err!r}")
    assert loaded == [], "a manifest naming a near-miss id was not refused:\n  " + (
        "\n  ".join(loaded))


def test_r5_the_expected_episode_id_is_a_required_keyword(tmp_path):
    """R5 (review U2): the expected id is a REQUIRED keyword with no default, so no reader can
    skip the check by leaving it out — a call without it is a `TypeError`, as is one passing it
    positionally. Control: the keyword form loads (same view, same manifest)."""
    from defender._io import bind
    from defender.runtime.branch._family import load_family, load_manifest_document

    episode_id = R.new_id()
    ep = tmp_path / "episodes" / episode_id
    T.write_family(ep, _loadable("triplet_947", episode_id))
    for door in (load_family, load_manifest_document):
        with bind(ep) as view:
            bare = R.raised(door, view)
            positional = R.raised(door, view, episode_id)
            keyword = R.raised(door, view, expected_episode_id=episode_id)
        assert isinstance(bare, TypeError), f"{door.__name__}(view) was accepted: {bare!r}"
        assert isinstance(positional, TypeError), (
            f"{door.__name__}(view, <id>) was accepted positionally: {positional!r}")
        assert keyword is None, f"{door.__name__}(view, expected_episode_id=) refused: {keyword!r}"


def test_r5_pre_flight_refuses_a_manifest_naming_another_episode(tmp_path, monkeypatch,
                                                                  data_root):
    """R5 / declared change 10 ("Every manifest reader refuses that mismatch") at PRE-FLIGHT,
    the one manifest reader the design's R5 list does not name (adversary deck #1042b replay:
    a policy pinned on one surface only — pre-flight loads the family with `load_family`, so a
    caller passing the manifest's own id as the expected one skips the check here unseen).
    `cli.preflight_replay(view.episode, ...)`, handed the walked view of `<A>` whose manifest
    names `<A>` with its last hex digit changed, refuses naming both ids before its oracle is
    asked, and writes no outcome record. Positive control, same call: the manifest naming its
    own folder is calibrated (the oracle asked, `outcome.yaml` written). RED at base: the
    episode is looked up under the episodes variable."""
    from defender.learning.branch import cli

    P.roots(tmp_path, monkeypatch)
    monkeypatch.delenv(R.EPISODES_BASE_ENV, raising=False)
    est, src = P.launch_source(tmp_path, source_run_id=R.new_id())
    source = T.open_source(src)
    (src.parent / "_tenant.json").unlink(missing_ok=True)
    rows = [S.captured(c.system, c.verb, c.params, c.payload) for c in P.source_calls()]
    episode_id = R.new_id()
    other = R.near_miss_id(episode_id)

    def doc(named: str) -> dict:
        return S.family_v2(episode_id=named, source_run_id=src.name, source_run_dir=str(src))

    ep = S.episode_v2(tmp_path, doc=doc(episode_id), root=R.episodes_dir(data_root,
                                                                          P.LAUNCH_TENANT),
                      episode_id=episode_id, base_rows=rows)
    T.write_family(ep, doc(other))
    runs = R.tenant(data_root, P.LAUNCH_TENANT).runs_repository()

    def preflight(oracle) -> BaseException | None:
        with runs.episode(episode_id) as view:
            return R.raised(cli.preflight_replay, view.episode, source=source,
                            roster=est.roster(), tenant=est.run_tenant(), oracle=oracle.model,
                            verifier=S.passing_verifier().model)

    unasked = S.oracle(then=S.submit(P.BASE_ANSWER, S.EMPTY_CLAIM))
    err = preflight(unasked)
    assert err is not None, "pre-flight calibrated an episode whose manifest names another"
    assert not isinstance(err, (TypeError, AttributeError, NameError)), f"machinery: {err!r}"
    text = R.message(err)
    assert other in text, f"the refusal does not name the manifest's id {other}: {text}"
    assert episode_id in text, f"the refusal does not name the folder's id {episode_id}: {text}"
    assert unasked.requests == 0, "pre-flight asked its oracle over a mismatched manifest"
    assert not (ep / "outcome.yaml").exists(), "pre-flight recorded an outcome for it"

    T.write_family(ep, doc(episode_id))
    asked = S.oracle(then=S.submit(P.BASE_ANSWER, S.EMPTY_CLAIM))
    assert preflight(asked) is None, "control: pre-flight over its own manifest refused"
    assert asked.requests > 0, "control: pre-flight never asked its oracle"
    assert (ep / "outcome.yaml").is_file(), "control: pre-flight wrote no outcome record"


def test_r5_the_episode_page_refuses_a_manifest_naming_another_episode(data_root):
    """R5 through a real reader: the page over folder `<A>` whose manifest says `<B>` exits 1,
    names the mismatch, and writes no page. `<B>` is `<A>` with its LAST hex digit changed
    (adversary F11: a reader comparing a prefix or a group passes a random second UUID's
    mismatch only by luck, and this one never). Positive control on the same channel: the
    manifest rewritten to `<A>` renders."""
    ep, episode_id, _roster = _episode(data_root)
    other = R.near_miss_id(episode_id)
    T.write_family(ep, _doc(other))
    refused = _page(episode_id)
    assert refused.rc == 1, f"the page rendered over a mismatched manifest: {refused.said}"
    assert other in refused.said, refused.said
    assert episode_id in refused.said, refused.said
    assert not (ep / E.PAGE_NAME).exists()

    T.write_family(ep, _doc(episode_id))
    ok = _page(episode_id)
    assert ok.rc == 0, f"the control did not render: {ok.said}"
    assert (ep / E.PAGE_NAME).is_file()


# ==========================================================================================
# Flow 4 — the episode page reads its arms from the roster
# ==========================================================================================

def test_page_links_each_arm_by_its_roster_id_never_a_composed_name(data_root):
    """O4 / Flow 4 / declared change 15: the page's arms are `view.arms(view.arm_ids())`. Arms
    `a`, `c` and the `role: null` replicate `d` sit at their roster ids, and each world section
    links `runs/<roster id>/runtime.html`. DECOYS `runs/<ep>-a/` and `runs/<ep>-b/` (complete
    run folders with a `runtime.html`) sit beside them, and `b` has no folder at its roster id:
    no href on the page names a composed folder, and `b` reads "run directory absent"."""
    ep, episode_id, roster = _episode(data_root, null_world=True)
    for label in ("a", "c", "d"):
        _arm(ep, roster[label])
    for label in ("a", "b"):
        _arm(ep, f"{episode_id}-{label}")

    got = _page(episode_id)
    assert got.rc == 0, f"the page was not rendered: {got.said}"
    page = E.read_page(ep)
    for label in ("a", "c", "d"):
        expected = f"runs/{roster[label]}/runtime.html"
        assert expected in page.anchors_in(f"world-{label}"), (
            f"world {label}'s arm is not linked by its roster id: {page.anchors_in(f'world-{label}')}")
    composed = [h for h in page.hrefs if f"{episode_id}-" in h]
    assert composed == [], f"the page linked a composed <ep>-<label> folder: {composed}"
    assert "run directory absent" in page.text_of("world-b"), page.text_of("world-b")


@pytest.mark.parametrize("runs_folder", ["none", "empty", "with_arms"],
                         ids=["no_runs", "empty_runs_without_roster", "runs_without_roster"])
def test_page_without_a_roster_renders_no_world_section_and_no_arm_link(data_root, runs_folder):
    """Flow 4: manifest present, roster absent — the episode never reached RUNS. `start_runs`
    makes `runs/` first, then the roster, so a crash between the two leaves an EMPTY `runs/`
    and no roster (`empty_runs_without_roster`, review round 2, F27); `runs/` holding arm
    folders and no roster is the harder decoy (a page that keyed on `runs/` or its entries
    would link them). The page renders (exit 0) with no world section and no arm link, and the
    manifest's own text and the outcome record still show. Positive control on the same page:
    once the roster is written, the world sections appear."""
    ep, episode_id, _none = _episode(data_root, roster=None)
    mapping = {label: R.new_id() for label in LABELS}
    if runs_folder == "empty":
        (ep / "runs").mkdir()
    elif runs_folder == "with_arms":
        for arm_id in mapping.values():
            _arm(ep, arm_id)
    _outcome(ep)

    got = _page(episode_id)
    assert got.rc == 0, f"a pre-RUNS episode did not render: {got.said}"
    page = E.read_page(ep)
    assert page.ids_with("world-") == [], f"world sections without a roster: {page.ids_with('world-')}"
    assert _arm_hrefs(page) == [], f"arm links without a roster: {_arm_hrefs(page)}"
    assert AXIS_B in page.text, "the manifest's worlds guide did not render"
    assert OUTCOME_REASON in page.text, "the outcome record did not render"

    R.write_roster(ep, mapping)
    again = _page(episode_id)
    assert again.rc == 0, again.said
    assert "world-b" in E.read_page(ep).by_id, "the control failed: a roster gave no world section"


def _refused_roster(kind: str, ep: Path, good: dict[str, str], tmp_path: Path) -> None:
    """Plant the refused roster `kind` at `<ep>/arms.json`, derived from the good one."""
    text = json.dumps(good, indent=2, sort_keys=True)
    if kind == "torn":
        R.write_roster(ep, raw=R.torn(text))
    elif kind == "missing_label":
        R.write_roster(ep, {k: v for k, v in good.items() if k != "c"})
    elif kind == "extra_label":
        R.write_roster(ep, {**good, "z": R.new_id()})
    elif kind == "shared_id":
        R.write_roster(ep, {**good, "b": good["c"]})
    elif kind == "old_id":
        R.write_roster(ep, {**good, "b": R.OLD_MINTED_ID})
    elif kind == "link":
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir(exist_ok=True)
        R.write_roster(elsewhere, good)
        (ep / R.ROSTER_NAME).unlink(missing_ok=True)
        os.symlink(elsewhere / R.ROSTER_NAME, ep / R.ROSTER_NAME)
    else:
        raise AssertionError(kind)


REFUSED_ROSTERS = ["torn", "missing_label", "extra_label", "shared_id", "old_id", "link"]


@pytest.mark.parametrize("kind", REFUSED_ROSTERS)
def test_page_shows_a_refused_roster_as_the_arms_state_and_renders_the_rest(data_root, tmp_path,
                                                                           kind):
    """Flow 4 (recheck S1): a roster the reader refuses — torn, its labels not exactly the
    manifest's worlds, two labels on one id, an id off the UUID rule, a link — is shown as a
    `refused` state for the arms, with the reason (naming `arms.json`); no arm is linked though
    every good id has a folder; the rest of the page (the manifest's worlds guide, the outcome
    record) renders, exit 0. Positive control on the same page: the good roster written back
    links every arm and no roster refusal shows."""
    ep, episode_id, good = _episode(data_root)
    for arm_id in good.values():
        _arm(ep, arm_id)
    _outcome(ep)
    _refused_roster(kind, ep, good, tmp_path)

    got = _page(episode_id)
    assert got.rc == 0, f"a refused roster failed the whole page: {got.said}"
    page = E.read_page(ep)
    assert R.ROSTER_NAME in page.text, f"no reason naming {R.ROSTER_NAME}: {page.text[:2000]}"
    assert "refused" in page.text, f"no refused state for the arms: {page.text[:2000]}"
    assert _arm_hrefs(page) == [], f"arms linked through a refused roster: {_arm_hrefs(page)}"
    assert AXIS_B in page.text, "the manifest's worlds guide did not render"
    assert OUTCOME_REASON in page.text, "the outcome record did not render"

    (ep / R.ROSTER_NAME).unlink()
    R.write_roster(ep, good)
    control = _page(episode_id)
    assert control.rc == 0, control.said
    page = E.read_page(ep)
    assert R.ROSTER_NAME not in page.text, "the control still shows a roster refusal"
    for label, arm_id in good.items():
        assert f"runs/{arm_id}/runtime.html" in page.anchors_in(f"world-{label}"), label


@pytest.mark.parametrize("asked", ["latest_link", "old_id_folder"])
def test_page_refuses_latest_and_any_non_uuid_episode_id(data_root, asked):
    """R4 / declared change 9: `latest` — here a real link `<T>/episodes/latest` to a real
    episode — and an old id naming a real folder whose manifest agrees are refused as bad ids,
    before any path is built: exit 1, the id named, no page written in the target. The decoy
    episodes base holds the same name, linked to the same target, so a reader that still looks
    the name up there (today's) finds and renders it rather than refusing for absence. Positive
    control: the real episode by its UUID renders."""
    ep, episode_id, roster = _episode(data_root)
    if asked == "latest_link":
        bad = "latest"
        os.symlink(ep, R.episodes_dir(data_root, TENANT) / bad, target_is_directory=True)
        target = ep
    else:
        bad = R.OLD_MINTED_ID
        target, _id, _roster = _episode_at(data_root, bad, _doc(bad), roster)
    os.symlink(target, Path(os.environ[R.EPISODES_BASE_ENV]) / bad, target_is_directory=True)

    refused = _page(bad)
    assert refused.rc == 1, f"{bad!r} was accepted as an episode id: {refused.said}"
    assert bad in refused.said, refused.said
    assert not (target / E.PAGE_NAME).exists(), "a page was written through a bad id"

    ok = _page(episode_id)
    assert ok.rc == 0, f"the control did not render: {ok.said}"
    assert (ep / E.PAGE_NAME).is_file()


def test_the_page_for_one_tenant_never_renders_another_tenants_episode(data_root):
    """O8 at the page CLI (review F11): `visualize_episode.py --tenant <A> <B's episode id>`
    exits 1 and writes no page — B's episode exists only under `<B>/episodes`, and A's request
    composes only A's paths. The decoy episodes base holds the same id, linked to B's folder, so
    a page that still looks ids up there would render B's episode for A. Positive control:
    `--tenant <B>` with the same id renders inside B's folder."""
    other = "beta"
    R.tenant(data_root)
    R.tenant(data_root, other)
    episode_id = R.new_id()
    roster = {label: R.new_id() for label in LABELS}
    ep = R.make_episode(data_root, other, episode_id, labels=LABELS, roster=roster)
    T.write_family(ep, _doc(episode_id))
    for arm_id in roster.values():
        _arm(ep, arm_id)
    os.symlink(ep, Path(os.environ[R.EPISODES_BASE_ENV]) / episode_id, target_is_directory=True)

    refused = _page(episode_id, TENANT)
    assert refused.rc == 1, f"tenant {TENANT} rendered {other}'s episode: {refused.said}"
    assert not (ep / E.PAGE_NAME).exists(), "a page was written into another tenant's episode"

    ok = _page(episode_id, other)
    assert ok.rc == 0, f"the control did not render: {ok.said}"
    assert (ep / E.PAGE_NAME).is_file()


# ==========================================================================================
# Flow 2 steps 7-9 — VERIFY, the archive, the judge and the page after RUNS
# ==========================================================================================

def test_verify_opens_each_finished_arm_by_its_roster_id(data_root):
    """Flow 2 step 7 (recheck X4): VERIFY opens only the finished arms, each by its ROSTER id.
    `a` has its arm at its roster id; `b`'s roster id has no folder (not started, as today's
    missing arm: `RunAbsent`) while a DECOY `runs/<ep>-b/` sits there; `c` has a complete arm
    at its roster id but did not finish, so it is not opened at all."""
    from defender.learning.branch import cli
    from defender.run_repository import Run, RunAbsent

    ep, episode_id, roster = _episode(data_root)
    _arm(ep, roster["a"])
    _arm(ep, f"{episode_id}-b")
    _arm(ep, roster["c"])
    runs = R.tenant(data_root).runs_repository()
    with runs.episode(episode_id) as view:
        arms = cli._finished_arms(view, ["a", "b"])
    assert set(arms) == {"a", "b"}, f"VERIFY opened {sorted(arms)}"
    assert isinstance(arms["a"], Run), f"a: {arms['a']!r}"
    assert Path(arms["a"].run_dir) == ep / "runs" / roster["a"]
    assert isinstance(arms["b"], RunAbsent), (
        f"b, whose roster id has no folder, was answered {arms['b']!r} (the decoy composed?)")


def test_verify_refuses_outright_on_a_refused_roster(data_root):
    """Flow 4: "VERIFY and a sibling refuse outright on the same fault" — a torn roster is
    not read as "no arms" or as a partial roster: opening the finished arms refuses, naming
    `arms.json`. Positive control: the good roster opens `a` by its id."""
    from defender.learning.branch import cli
    from defender.run_repository import Run

    ep, episode_id, good = _episode(data_root)
    _arm(ep, good["a"])
    runs = R.tenant(data_root).runs_repository()

    def verify() -> dict:
        with runs.episode(episode_id) as view:
            return cli._finished_arms(view, ["a"])

    R.write_roster(ep, raw=R.torn(json.dumps(good)))
    err = R.raised(verify)
    assert err is not None, "VERIFY read a torn roster"
    assert not isinstance(err, (TypeError, AttributeError, NameError)), f"machinery: {err!r}"
    assert R.ROSTER_NAME in R.message(err), f"the refusal does not name the roster: {err!r}"

    R.write_roster(ep, good)
    assert isinstance(verify()["a"], Run), "the control failed: a good roster did not open a"


def test_verify_refuses_a_manifest_naming_another_episode(data_root):
    """R5 / declared change 10 at VERIFY (review F8): VERIFY's arm opener reads the roster,
    whose labels are checked against the manifest's worlds — read through the one loader, which
    is handed the folder's id. Over an episode whose manifest names ANOTHER uuid, opening the
    finished arms refuses, naming both ids (the arm `a` sits at its roster id, so nothing else
    is wrong). The other uuid differs from the folder's only in its last hex digit (adversary
    F11). Positive control, same view and channel: the manifest rewritten to name its own folder
    opens `a` by its roster id."""
    from defender.learning.branch import cli
    from defender.run_repository import Run

    ep, episode_id, roster = _episode(data_root)
    _arm(ep, roster["a"])
    other = R.near_miss_id(episode_id)
    T.write_family(ep, _doc(other))
    runs = R.tenant(data_root).runs_repository()

    def verify() -> dict:
        with runs.episode(episode_id) as view:
            return cli._finished_arms(view, ["a"])

    err = R.raised(verify)
    assert err is not None, "VERIFY opened arms under a manifest naming another episode"
    assert not isinstance(err, (TypeError, AttributeError, NameError)), f"machinery: {err!r}"
    text = R.message(err)
    assert other in text, f"the refusal does not name the manifest's id {other}: {text}"
    assert episode_id in text, f"the refusal does not name the folder's id {episode_id}: {text}"

    T.write_family(ep, _doc(episode_id))
    opened = verify()
    assert isinstance(opened["a"], Run), f"the control failed: {opened!r}"
    assert Path(opened["a"].run_dir) == ep / "runs" / roster["a"]


def test_r8_the_archive_writes_no_run_dir_pointer(data_root):
    """R8 / declared change 12: archiving an arm copies its artifacts into `worlds/<label>/`
    and writes no `worlds/<label>/run_dir` pointer (nothing reads it; the roster supersedes it).
    Positive control on the same world folder: its report is archived."""
    archive = T.mod("learning.branch.archive")
    ep, episode_id, roster = _episode(data_root)
    # The finished arm and its scrub-verdict sidecar, at the roster's id for `b`.
    T.sibling_run_dir(ep / "runs", "b", arm_id=roster["b"])
    runs = R.tenant(data_root).runs_repository()
    with runs.episode(episode_id) as view:
        archive.archive_episode(view.episode, {"b": ep / "runs" / roster["b"]})
    world = ep / "worlds" / "b"
    assert (world / "report.md").is_file(), "the control failed: nothing was archived"
    assert not os.path.lexists(world / "run_dir"), "the archive wrote the run_dir pointer"


class RosterSibling:
    """The launcher's spawn seam: a sibling that RAN (`_judge_921.FakeSibling`'s run folder,
    report, scrub verdict and ledger), its arm materialised by `FakeSibling` itself at the
    ROSTER's id for its label — the roster read back as plain JSON from
    `<data root>/<T>/episodes/<ep>/arms.json`, as the sibling reads it before anything else.
    `exits` scripts a label's exit code (the arm is still left complete). A launch with no
    roster, or whose roster does not name its label, is recorded in `faults`, exit 97, and
    materialises nothing."""

    def __init__(self, data_root: Path, *, exits: dict[str, int]) -> None:
        self.data_root = Path(data_root)
        self.exits = dict(exits)
        self.launches: list[dict[str, str]] = []
        self.faults: list[str] = []

    @staticmethod
    def _flags(argv: list[str]) -> dict[str, str]:
        out: dict[str, str] = {}
        for i, token in enumerate(argv[:-1]):
            if token in ("--tenant", "--episode", "--world"):
                out[token] = argv[i + 1]
        return out

    def __call__(self, argv: list[str], *, env: dict[str, str] | None = None, **_kw: Any) -> int:
        flags = self._flags(list(argv))
        self.launches.append(flags)
        tenant, episode, label = (flags.get(k) for k in ("--tenant", "--episode", "--world"))
        if tenant is None or episode is None or label is None:
            self.faults.append(f"a sibling started without --tenant/--episode/--world: {argv}")
            return 97
        ep = R.episodes_dir(self.data_root, tenant) / episode
        if not (ep / R.ROSTER_NAME).is_file():
            self.faults.append(f"sibling {label}: no roster at {ep / R.ROSTER_NAME}")
            return 97
        if R.read_roster(ep).get(label) is None:
            self.faults.append(f"sibling {label}: the roster does not name it")
            return 97
        return J.FakeSibling(data_root=self.data_root, exits=self.exits)(list(argv), env=env)

    @property
    def worlds(self) -> list[str]:
        return [f["--world"] for f in self.launches if "--world" in f]


def test_a_launch_verifies_finished_arms_by_roster_id_archives_no_pointer_and_pages_by_id(
        tmp_path, monkeypatch, data_root):
    """Flow 2 steps 6-9, driven through the REAL launcher: RUNS writes the roster before the
    first sibling; each sibling (a spawn double) leaves its arm at the roster's id; `c` exits
    non-zero though its arm is complete. VERIFY archives the finished worlds from their roster
    folders and not `c`, writes no `run_dir` pointer (R8), and the page the launcher renders
    links the arms by roster id (step 9)."""
    P.roots(tmp_path, monkeypatch)
    source_id = R.new_id()
    est, src = P.launch_source(tmp_path, source_run_id=source_id)
    # The natural container in #1187's shape: no `_tenant.json` (R1).
    (src.parent / "_tenant.json").unlink(missing_ok=True)
    spawn = RosterSibling(data_root, exits={"c": 3})

    got = P.drive_launch(est, P.new_launch_argv(P.LAUNCH_TENANT, source_id), spawn=spawn)
    assert spawn.launches, f"no sibling was started: rc={got.rc} {got.message!r}"
    assert spawn.faults == [], spawn.faults
    assert "c" in spawn.worlds, spawn.worlds
    assert len(spawn.worlds) >= 2, spawn.worlds
    episodes = [p for p in R.episodes_dir(data_root, P.LAUNCH_TENANT).iterdir() if p.is_dir()]
    assert len(episodes) == 1, f"expected one episode under <T>/episodes: {episodes}"
    ep = episodes[0]
    roster = R.read_roster(ep)
    finished = [label for label in spawn.worlds if label != "c"]
    for label in finished:
        world = ep / "worlds" / label
        assert (world / "report.md").is_file(), f"finished world {label} was not archived"
        assert not os.path.lexists(world / "run_dir"), f"world {label}: a run_dir pointer"
    assert (ep / "runs" / roster["c"]).is_dir(), "the control failed: c left no arm"
    assert not (ep / "worlds" / "c" / "report.md").exists(), "VERIFY opened an unfinished arm"

    page = ep / E.PAGE_NAME
    assert page.is_file(), "the launcher rendered no page"
    parsed = E.Page.parse(page.read_text(encoding="utf-8"))
    for label in finished:
        assert f"runs/{roster[label]}/runtime.html" in parsed.anchors_in(f"world-{label}"), label


# ------------------------------------------------------------------------------------------
# The launcher's RUNS step, driven end to end (review round 1: F1, F2, F6, F12)
# ------------------------------------------------------------------------------------------

#: The manifest's poison (`test_1187_roster_sibling`'s technique): a top-level field the family
#: loader refuses BY NAME, so it reaches a refusal's text exactly when the manifest was read.
SENTINEL = "zz_spec1187_never_read_before_the_gate"
#: World `c`'s fact statement in the unservable scene: the marker its pre-flight requests carry.
MARK_C = "MARK-1187-C carol read the vault from 10.0.0.9"


def _launch_scene(tmp_path: Path, monkeypatch: Any) -> tuple[Any, Path]:
    """The launch fixture tenant (`_spec1105_pr2.launch_source`) with one branchable source run
    at a UUID id, in #1187's shape (no `_tenant.json` in `<T>/runs`, R1), every configured root
    inside `tmp_path`. Returns `(estate, source run dir)`."""
    P.roots(tmp_path, monkeypatch)
    est, src = P.launch_source(tmp_path, source_run_id=R.new_id())
    (src.parent / "_tenant.json").unlink(missing_ok=True)
    return est, src


def _episodes_made(data_root: Path) -> list[Path]:
    """Every entry under the launch tenant's `<T>/episodes` (none when it does not exist)."""
    root = R.episodes_dir(data_root, P.LAUNCH_TENANT)
    return sorted(root.iterdir()) if root.is_dir() else []


def _manifest_of(ep: Path) -> dict:
    """The manifest the launcher wrote, read back as plain YAML."""
    from defender import _yaml

    return _yaml.safe_load((ep / R.MANIFEST_NAME).read_text(encoding="utf-8"))


def _hand_sibling(episode_id: str, label: str) -> tuple[int | None, Any, str, Any]:
    """`run.py --tenant <launch tenant> --episode <episode_id> --world <label>`, the real
    `run.main` with `SiblingRecorder`'s spend seams: `(rc, SystemExit or None, said, rec)`."""
    rec = P.SiblingRecorder()
    rc, refused, err = P.drive_run_py(P.new_sibling_argv(P.LAUNCH_TENANT, episode_id, label), rec)
    return rc, refused, f"{P.refusal_text(refused)}\n{err}", rec


class OracleFailingC:
    """Pre-flight's oracle seam (`oracle=`), routed by the world a request is about: a request
    whose inbound text carries `MARK_C` (world `c`'s fact) is answered by an oracle whose every
    turn ends without a submission (a failed calibration, M03=A); every other request by one
    serving the base answer unchanged. It decides nothing itself; `hits` counts each route."""

    __name__ = "OracleFailingC"

    def __init__(self) -> None:
        self.failing = S.oracle(then=S.text_only("no served answer fits this world"))
        self.passing = S.oracle(then=S.submit(P.BASE_ANSWER, S.EMPTY_CLAIM))
        self.hits = {"c": 0, "other": 0}
        self._model: Any = None

    @property
    def model(self) -> Any:
        if self._model is None:
            from pydantic_ai.models.function import FunctionModel

            self._model = FunctionModel(self, model_name=S.double_model_name("oracle"))
        return self._model

    def __call__(self, messages: list[Any], info: Any) -> Any:
        text = S._messages_text(messages) + "\n" + (getattr(info, "instructions", None) or "")
        route = "c" if MARK_C in text else "other"
        self.hits[route] += 1
        return (self.failing if route == "c" else self.passing)(messages, info)


@pytest.mark.parametrize("verdict", ["unusable", "refused"])
def test_a_launch_whose_preflight_does_not_accept_writes_no_roster_and_its_sibling_is_refused(
        tmp_path, monkeypatch, data_root, verdict):
    """R2 / O4b / Flow 2 step 6 (review F1): the roster is written at the START of RUNS, after
    pre-flight passes. A real launch whose pre-flight does not accept the family — `unusable`
    (the verifier fails every fact world) or `refused` (no world carries a fact) — leaves one
    episode at `<T>/episodes/<uuid>` holding the manifest (written at QUESTIONER) and pre-flight's
    outcome record, and NO `arms.json` and no `runs/`; no sibling is started. Then a sibling
    started by hand against that very episode (`run.py --tenant T --episode <ep> --world b`) is
    refused before the manifest is read (it is poisoned) and before anything is spent, and makes
    nothing. Positive controls on the same channels: the outcome record says pre-flight ran and
    did not accept; once `runs/` and a roster naming every manifest world are written by hand
    (what `start_runs` leaves), the same sibling gets past the gate — its refusal now names the
    poison, so the channel sees a manifest read. RED at base: the launcher refuses the
    recordless natural container before claiming any episode."""
    monkeypatch.setenv(S.KNOB_RETRY_CAP, "1")
    est, src = _launch_scene(tmp_path, monkeypatch)
    spawn = RosterSibling(data_root, exits={})
    if verdict == "unusable":
        seams: dict[str, Any] = {"verifier": S.failing_verifier().model}
    else:
        factless = S.family_v2(worlds=[S.control_world("a"), S.world_v2("b", facts=[]),
                                       S.world_v2("c", role="C", facts=[])])
        seams = {"questioner": P.CountingQuestioner(S.questioner_for(factless))}

    got = P.drive_launch(est, P.new_launch_argv(P.LAUNCH_TENANT, src.name), spawn=spawn, **seams)
    made = _episodes_made(data_root)
    assert len(made) == 1, (
        f"expected one episode under <T>/episodes, found {made}: rc={got.rc} {got.message!r}")
    ep = made[0]
    assert R.is_canonical_uuid(ep.name), f"the episode folder is not a uuid: {ep.name!r}"
    assert (ep / R.MANIFEST_NAME).is_file(), "the manifest (written at QUESTIONER) is missing"
    outcome = S.read_outcome(ep)
    assert outcome is not None, "control: pre-flight wrote no outcome record"
    assert outcome["outcome"] == verdict, (
        f"control: pre-flight should have ruled the family {verdict}: {outcome!r}")
    assert not os.path.lexists(ep / R.ROSTER_NAME), "a roster was written before RUNS"
    assert not os.path.lexists(ep / "runs"), "runs/ was made for an episode that never ran"
    assert spawn.launches == [], f"a sibling was started: {spawn.launches}"

    doc = _manifest_of(ep)
    T.write_family(ep, {**doc, SENTINEL: "read"})
    before = R.tree(data_root)
    rc, refused, said, rec = _hand_sibling(ep.name, "b")
    assert refused is not None, f"the hand-run sibling ran: rc {rc}"
    assert rc is None, f"the hand-run sibling ran: rc {rc}"
    assert SENTINEL not in said, f"the manifest was read before the gate: {said!r}"
    assert R.EPISODES_BASE_ENV not in said, f"refused for the retired variable: {said!r}"
    assert rec.order == [], f"the sibling spent before refusing: {rec.order}"
    assert R.tree(data_root) == before, "the refused sibling wrote under the data root"

    (ep / "runs").mkdir()
    R.write_roster(ep, {w["world_id"]: R.new_id() for w in doc["worlds"]})
    rc, refused, said, rec = _hand_sibling(ep.name, "b")
    assert refused is not None, f"the poisoned manifest was not read past the gate: rc {rc}"
    assert SENTINEL in said, f"past the gate the refusal should name {SENTINEL}: {said!r}"
    assert rec.order == [], f"the manifest refusal came after a spend: {rec.order}"


def test_a_launch_rosters_every_manifest_world_and_starts_only_the_servable_ones(
        tmp_path, monkeypatch, data_root):
    """R2 / recheck X1 / Flow 2 step 6 (review F2): `start_runs` takes EVERY manifest world
    label; the launcher spawns only the runnable, servable subset (`cli.py:1602-1603`). World
    `c`'s pre-flight fails (`OracleFailingC`), so the family is accepted with `c` unservable.
    The roster names a, b AND c — exactly the manifest's worlds, three distinct canonical UUIDs
    — while only a and b are started, and VERIFY archives a and b from their roster folders. A
    roster holding only the spawned labels would be refused by every reader (its label set is
    not the manifest's). Controls: the outcome record names `c` unservable, and `c`'s oracle
    route was asked. (A `role: null` replicate never reaches the launcher: the questioner assigns
    every authored seat a role letter, `questioner/__init__.py:70-71`, :478-480.) RED at base:
    the launcher refuses the recordless natural container before claiming any episode."""
    monkeypatch.setenv(S.KNOB_RETRY_CAP, "1")
    est, src = _launch_scene(tmp_path, monkeypatch)
    doc = S.family_v2(worlds=[
        S.control_world("a"), S.world_v2("b", facts=[S.fact("f1")]),
        S.world_v2("c", role="C", facts=[S.fact("f2", MARK_C, ("carol", "vault", "10.0.0.9"))])])
    oracle = OracleFailingC()
    spawn = RosterSibling(data_root, exits={})

    got = P.drive_launch(est, P.new_launch_argv(P.LAUNCH_TENANT, src.name), spawn=spawn,
                         questioner=P.CountingQuestioner(S.questioner_for(doc)),
                         oracle=oracle.model)
    made = _episodes_made(data_root)
    assert len(made) == 1, (
        f"expected one episode under <T>/episodes, found {made}: rc={got.rc} {got.message!r}")
    ep = made[0]
    outcome = S.read_outcome(ep)
    assert outcome is not None, "control: pre-flight wrote no outcome record"
    assert outcome["outcome"] == "accepted", outcome
    assert [u["world"] for u in outcome["unservable_worlds"]] == ["c"], (
        f"control: c should be unservable: {outcome['unservable_worlds']}")
    assert oracle.hits["c"] > 0, "control: c's pre-flight never asked its oracle"
    assert spawn.faults == [], spawn.faults

    labels = {w["world_id"] for w in _manifest_of(ep)["worlds"]}
    assert labels == {"a", "b", "c"}, labels
    roster = R.read_roster(ep)
    assert set(roster) == labels, f"the roster names {sorted(roster)}, the manifest {sorted(labels)}"
    assert all(R.is_canonical_uuid(v) for v in roster.values()), roster
    assert len(set(roster.values())) == len(roster), f"two labels share an id: {roster}"
    assert sorted(spawn.worlds) == ["a", "b"], f"started {spawn.worlds}"
    for label in ("a", "b"):
        assert (ep / "worlds" / label / "report.md").is_file(), f"{label} was not archived"
    assert not (ep / "worlds" / "c" / "report.md").exists(), "the unservable world was archived"


@pytest.mark.parametrize("variable", ["unset", "decoy"])
def test_a_launch_lands_its_episode_under_its_tenant_whatever_the_episodes_variable_says(
        tmp_path, monkeypatch, data_root, variable):
    """O9 / declared change 5 at the launcher (review F6), and O10 (review F12). With
    `DEFENDER_EPISODES_BASE` unset, or naming a decoy folder holding old-shaped episodes, a real
    launch completes (rc 0): its one episode is `<T>/episodes/<uuid>`, holding its manifest and
    roster; the decoy is byte-identical; and `<T>/runs` holds exactly the entries it held before
    (an episode adds nothing to the natural container). Neither case has a `<T>/episodes` folder
    before the launch, so the first launch must make it — and acceptance, which now counts
    `<T>/episodes` among the trees a box mounts, must not refuse its absence. Positive control:
    the siblings ran, each from the roster. RED at base: the launcher refuses the recordless
    natural container."""
    est, src = _launch_scene(tmp_path, monkeypatch)
    decoy: Path | None = None
    if variable == "unset":
        monkeypatch.delenv(R.EPISODES_BASE_ENV, raising=False)
    else:
        decoy = R.plant_old_episodes_root(tmp_path / "decoy-episodes")
        monkeypatch.setenv(R.EPISODES_BASE_ENV, str(decoy))
    decoy_before = R.tree(decoy) if decoy is not None else None
    episodes = R.episodes_dir(data_root, P.LAUNCH_TENANT)
    if episodes.is_dir() and not any(episodes.iterdir()):
        episodes.rmdir()
    assert not os.path.lexists(episodes), "the scene must start with no <T>/episodes"
    natural_before = sorted(os.listdir(src.parent))
    spawn = RosterSibling(data_root, exits={})

    got = P.drive_launch(est, P.new_launch_argv(P.LAUNCH_TENANT, src.name), spawn=spawn)
    assert got.rc == 0, f"the launch did not complete: rc={got.rc} {got.message!r} {got.raised!r}"
    made = _episodes_made(data_root)
    assert len(made) == 1, f"expected one episode under <T>/episodes: {made}"
    ep = made[0]
    assert R.is_canonical_uuid(ep.name), f"the episode folder is not a uuid: {ep.name!r}"
    assert (ep / R.MANIFEST_NAME).is_file(), "the launched episode holds no manifest"
    assert (ep / R.ROSTER_NAME).is_file(), "the launched episode holds no roster"
    assert spawn.faults == [], spawn.faults
    assert sorted(spawn.worlds) == ["a", "b", "c"], f"control: the siblings ran: {spawn.worlds}"
    if decoy is not None:
        assert R.tree(decoy) == decoy_before, "the launch touched the decoy episodes base"
    assert sorted(os.listdir(src.parent)) == natural_before, (
        f"the launch changed <T>/runs (O10): {sorted(os.listdir(src.parent))}")


def test_the_launcher_refuses_an_old_source_id_before_anything_is_spent(
        tmp_path, monkeypatch, data_root):
    """O2 / declared change 1 at the launcher (review F10): `branch --tenant T <old id> <turn>`
    refuses the id — naming it — before anything is spent (the questioner is never called) and
    claims no episode, although a real, branchable source run sits at `<T>/runs/<old id>`.
    Positive control, same tenant and channel: a source at a UUID id, in #1187's shape, passes
    the id rule — the questioner is called. The fixture plants no container record (#1187's
    shape, `_triplet_947.runs_base`), so after #1187 only the id rule can refuse the old source.
    At base the refused half is green for an unrelated reason (the missing record refuses
    first, naming the source id) and the control is RED (the same missing record refuses the
    UUID source)."""
    P.roots(tmp_path, monkeypatch)
    est, _old_src = P.launch_source(tmp_path, source_run_id=R.OLD_MINTED_ID)
    asked = P.CountingQuestioner()

    got = P.drive_launch(est, P.new_launch_argv(P.LAUNCH_TENANT, R.OLD_MINTED_ID),
                         spawn=RosterSibling(data_root, exits={}), questioner=asked)
    assert R.OLD_MINTED_ID in got.message, f"the refusal does not name the id: {got.message!r}"
    assert asked.calls == 0, "the questioner was called for an old source id"
    assert _episodes_made(data_root) == [], "an episode was claimed for an old source id"

    # The control's source lives under a data root of its own: a second fixture source in the
    # SAME root shares `_triplet_947.seed_source_session`'s one store and case, whose row loop
    # then never reaches the branch point (it spins). Same tenant id, same launcher, same channel.
    control_root = tmp_path / "control-data-root"
    control_root.mkdir()
    monkeypatch.setenv(R.DATA_ROOT_ENV, str(control_root))
    est, src = P.launch_source(tmp_path / "control", source_run_id=R.new_id())
    (src.parent / "_tenant.json").unlink(missing_ok=True)
    control = P.CountingQuestioner()
    ok = P.drive_launch(est, P.new_launch_argv(P.LAUNCH_TENANT, src.name),
                        spawn=RosterSibling(control_root, exits={}), questioner=control)
    assert control.calls > 0, f"control: a UUID source was refused: {ok.message!r}"


class RolePreflight:
    """The launcher's role-model preflight seam (`preflight=`), RECORDING each call and
    answering 0 (the neutral answer `_spec1224.no_preflight` gives), so a launch that reaches
    it goes on. `calls` holds the model each call named."""

    def __init__(self) -> None:
        self.calls: list[str | None] = []

    def __call__(self, model: str | None = None, *_args: Any, **_kw: Any) -> int:
        self.calls.append(model)
        return 0


def _sans_paths(text: str) -> str:
    """`text` with every absolute path token removed: the refusal's paths (the settings, the
    mounted tree) carry the tenant id as a component, so "names the tenant" is read off what is
    left."""
    import re

    return re.sub(r"/\S*", "<path>", text)


def test_the_launcher_refuses_a_settings_half_inside_its_episodes_folder(
        tmp_path, monkeypatch, data_root):
    """S-acc (review F6; the retired `test_1107_branch.py::test_s7_mf13_*`'s guard): the
    launcher accepts its tenant with `<T>/episodes` among the trees a box mounts (every arm
    container lives under it), computed from the tenant, never read from the environment (unset
    here). `<T>/episodes` planted as a link to the tenant's own `knowledge/` puts the settings
    half inside it: the launch is refused at acceptance — the refusal names the tenant (outside
    any path), the settings, and that a box mounts the tree — before anything is spent (the
    role-model preflight and the questioner are never called), no sibling starts, no episode
    folder appears under `<T>/episodes`, and the knowledge folder is untouched. Positive
    control, same scene and seams: the link removed, the launch passes acceptance (the role
    preflight and the questioner are called) and completes. RED at base: the launcher adds no
    `<T>/episodes` to acceptance (it reads the variable, unset here)."""
    est, src = _launch_scene(tmp_path, monkeypatch)
    monkeypatch.delenv(R.EPISODES_BASE_ENV, raising=False)
    tenant_dir = R.tenant_dir(data_root, P.LAUNCH_TENANT)
    episodes = tenant_dir / "episodes"
    if episodes.is_dir() and not any(episodes.iterdir()):
        episodes.rmdir()
    os.symlink(tenant_dir / "knowledge", episodes, target_is_directory=True)
    knowledge_before = R.tree(tenant_dir / "knowledge")
    listed_before = sorted(os.listdir(episodes))
    asked = P.CountingQuestioner()
    role = RolePreflight()
    spawn = RosterSibling(data_root, exits={})

    got = P.drive_launch(est, P.new_launch_argv(P.LAUNCH_TENANT, src.name), spawn=spawn,
                         questioner=asked, preflight=role)
    assert got.rc != 0, f"the launch was not refused: rc={got.rc}"
    assert "settings" in got.message, f"not acceptance's settings refusal: {got.message!r}"
    assert "a box mounts" in got.message, f"not acceptance's settings refusal: {got.message!r}"
    assert P.LAUNCH_TENANT in _sans_paths(got.message), (
        f"the refusal does not name the tenant {P.LAUNCH_TENANT!r}: {got.message!r}")
    assert R.EPISODES_BASE_ENV not in got.message, got.message
    assert role.calls == [], f"the role preflight was spent before acceptance refused: {role.calls}"
    assert asked.calls == 0, "the questioner was called before acceptance refused"
    assert spawn.launches == [], spawn.launches
    assert sorted(os.listdir(episodes)) == listed_before, (
        f"an episode folder appeared under <T>/episodes: {sorted(os.listdir(episodes))}")
    assert [n for n in os.listdir(episodes) if R.is_canonical_uuid(n)] == [], (
        "an episode folder exists under <T>/episodes")
    assert R.tree(tenant_dir / "knowledge") == knowledge_before, "the knowledge folder changed"

    os.unlink(episodes)
    control = P.CountingQuestioner()
    control_role = RolePreflight()
    ok = P.drive_launch(est, P.new_launch_argv(P.LAUNCH_TENANT, src.name),
                        spawn=RosterSibling(data_root, exits={}), questioner=control,
                        preflight=control_role)
    assert control_role.calls != [], f"control: the role preflight was never reached: {ok.message!r}"
    assert control.calls > 0, f"the control launch was refused at acceptance: {ok.message!r}"
    assert ok.rc == 0, f"the control launch did not complete: {ok.message!r} {ok.raised!r}"
    assert len(_episodes_made(data_root)) == 1, (
        f"control: the launch made no one episode under <T>/episodes: {_episodes_made(data_root)}")


def test_the_judge_door_opens_an_episode_whose_arm_container_has_no_record(data_root):
    """Flow 4 / S-iso: the judge's door `runs.episode_files(ep)` is the walk with no record
    judged — an episode whose `runs/` holds its arms and no `_tenant.json` opens, the handle on
    `<T>/episodes/<ep>`. Control on the same door: an id with no folder under `<T>/episodes`
    is refused (G23)."""
    ep, episode_id, roster = _episode(data_root)
    for arm_id in roster.values():
        _arm(ep, arm_id)
    runs = R.tenant(data_root).runs_repository()
    opened: list[Path] = []

    def door(asked: str) -> None:
        with runs.episode_files(asked) as episode:
            opened.append(Path(episode.dir))

    err = R.raised(door, episode_id)
    assert err is None, f"the judge's door refused a recordless arm container: {err!r}"
    assert opened == [ep], opened
    assert R.raised(door, R.new_id()) is not None, "an absent episode opened"
    assert opened == [ep], f"the door opened something for an absent id: {opened}"


def test_the_judge_gate_holds_a_label_to_its_own_rule_not_its_composed_name():
    """#1187 declared change 4 and census C1 row `judge/family.py:372-379
    world_label_names_directory` ("loses its run-id half and keeps the label's own rule"),
    judge side (round 2, adversary F1: nothing pinned the judge's own gate, so a renamed copy
    of the `<episode_id>-<label>` check survived). A valid 200-character label is admitted
    under a UUID episode id — its composed name would be 237 bytes, over the old 206-byte
    bound — and so is 230; the label's OWN rule still refuses a label that does not start with
    an ASCII alphanumeric (`-a`, `_a`, `.a`: each makes a valid COMPOSED name, `<uuid>-a`, so a
    check kept on the composed name alone admits them), the empty label, a traversal and a
    label with a separator. The label-only call follows declared change 4: an arm id is
    independent of the label, so the gate needs only the label. NOT observable here: a
    refusal's wording. `is_valid_run_id` has no length bound
    and a UUID prefix is always a valid start, so the composed half never changed an answer;
    only the census (`test_1187_ids`) sees a surviving composer. The label validity guard
    is unchanged; the label-only API is RED at base, which still requires the episode id."""
    from defender.learning.judge import family

    for long in ("w" * 200, "w" * 230):
        assert family.world_label_names_directory(long), (
            f"a valid {len(long)}-character label was refused for its composed name")
    assert family.world_label_names_directory("b")
    for bad in ("-a", "_a", ".a", "", "../x", "a/b", "..", "a\x00b"):
        assert not family.world_label_names_directory(bad), (
            f"{bad!r} was admitted: the label's own rule no longer applies")


def test_the_judge_refuses_a_manifest_naming_another_episode(tmp_path, data_root):
    """R5 / declared change 10 at the judge (review F8): `grade_episode(runs, <ep>)` — the
    judge's one entry, whose door is `runs.episode_files` — over an episode whose manifest names
    ANOTHER uuid — the folder's own with its last hex digit changed (adversary F11) — refuses
    (`JudgeRefused`), naming both ids; the judge model is asked nothing and
    no `judge.yaml` is written. Positive control on the same entry: the manifest naming its own
    folder gets past the manifest read — with no outcome record the pass records the episode as
    not graded (`judge.yaml` written), still asking the model nothing."""
    from defender.learning.judge import JudgeRefused, grade_episode
    from defender.tests import _state1135

    ep, episode_id, _roster = _episode(data_root)
    other = R.near_miss_id(episode_id)
    T.write_family(ep, _doc(other))
    runs = R.tenant(data_root).runs_repository()
    judge = P.quiet_judge()
    state = _state1135.state_over(tmp_path / "judge-state")

    err = R.raised(grade_episode, runs, episode_id, judge=judge, state=state)
    assert R.is_a(err, JudgeRefused), f"grade over a mismatched manifest: {err!r}"
    text = R.message(err)
    assert other in text, f"the refusal does not name the manifest's id {other}: {text}"
    assert episode_id in text, f"the refusal does not name the folder's id {episode_id}: {text}"
    assert not os.path.lexists(ep / "judge.yaml"), "a grade was recorded for a mismatched manifest"
    assert judge.prompts == [], "the judge was asked over a mismatched manifest"

    T.write_family(ep, _doc(episode_id))
    grade_episode(runs, episode_id, judge=judge, state=state)
    assert (ep / "judge.yaml").is_file(), "the control failed: the pass recorded nothing"
    assert judge.prompts == [], "an episode with no outcome record was graded by the model"


# ==========================================================================================
# S-red — the redaction set is the roster's
# ==========================================================================================

def _family(episode_id: str) -> Any:
    return T.sym("runtime.branch._family", "parse_family")(_doc(episode_id))


def _arm_ids(roster: dict[str, str]) -> dict[str, Any]:
    from defender.run_repository import RunId

    return {label: RunId.parse(text) for label, text in roster.items()}


def _token(episode_id: str) -> str:
    """A UUID episode's token, as the design states it (R2-03): its hyphens rendered as dots."""
    return episode_id.replace("-", ".")


def test_family_identities_is_the_episode_its_tokens_and_every_roster_arm_id():
    """S-red / declared change 15: `family_identities(family, arm_ids)` is exactly the episode
    id, its token, every world token, and every ROSTER arm id — no `<ep>-<label>` composition,
    no source run id."""
    from defender.runtime.branch._family import family_identities

    episode_id = R.new_id()
    roster = {label: R.new_id() for label in LABELS}
    token = _token(episode_id)
    expected = {episode_id, token, *(f"{token}.{label}" for label in LABELS), *roster.values()}
    known = {str(member) for member in family_identities(_family(episode_id), _arm_ids(roster))}
    assert known == expected, (
        f"missing {sorted(expected - known)}; unexpected {sorted(known - expected)}")


def test_family_identities_requires_the_arm_ids():
    """The arm ids are an argument with no default: a caller cannot build the set without the
    roster and silently leave every arm out."""
    from defender.runtime.branch._family import family_identities

    family = _family(R.new_id())
    assert isinstance(R.raised(family_identities, family), TypeError), (
        "family_identities(family) was accepted without the roster's arm ids")


def test_a_roster_arm_id_is_redacted_and_an_unrelated_uuid_is_not():
    """S-red through the filter: a sibling's roster arm id in fault text — lower case or upper —
    is replaced by the marker; an unrelated UUID in the same text passes untouched (the filter
    removes what the family knows, not whatever looks like an id)."""
    from defender.learning.branch.redaction import redact_model_visible
    from defender.runtime.branch._family import family_identities

    episode_id = R.new_id()
    roster = {label: R.new_id() for label in LABELS}
    known = family_identities(_family(episode_id), _arm_ids(roster))
    detail = (f"run {roster['c']} refused; sibling {roster['b'].upper()} served; "
              f"index {UNRELATED_UUID} unavailable")
    assert redact_model_visible(detail, known) == (
        f"run {MARK} refused; sibling {MARK} served; index {UNRELATED_UUID} unavailable")


def test_the_comparator_prompt_never_carries_a_roster_arm_id(data_root):
    """S-red through the comparator reader (review F7): `delta_o` reads the episode through the
    WALKED view (`runs.episode(ep)`) and takes the arm ids from that view's roster — no path
    re-binds the folder (recheck S2), and no caller hands the ids in, so none can forget them.
    World `b` served a payload naming sibling `c`'s roster arm id (a random UUID nothing but the
    roster spells) and an unrelated UUID. The prompt the comparator sent carries the marker, not
    the arm id, and the unrelated UUID survives (the payload did reach the prompt). R5 on the
    same reader: the manifest rewritten to name another episode (the folder's id with its last
    hex digit changed, adversary F11) refuses before the comparator is asked."""
    from defender.runtime.branch._family import FamilyError

    ep, episode_id, roster = _episode(data_root)
    _outcome(ep)
    J.comparable_family_stamp(ep)
    for label in LABELS:
        T.archived_world(ep, label)
    T.base_capture(ep, [T.captured_row(key="k1")])
    leaked = {"hits": [{"_id": "x", "note": f"seen by {roster['c']} near {UNRELATED_UUID}"}]}
    (ep / "served" / f"{_token(episode_id)}.b.jsonl").write_text(
        json.dumps(T.captured_row(key="k1", payload=leaked)) + "\n", encoding="utf-8")
    delta_o = T.sym("learning.branch.episode", "delta_o")
    runs = R.tenant(data_root).runs_repository()

    agent = T.FakeAgent("mutation")
    with runs.episode(episode_id) as view:
        out = delta_o(view, invoke=agent)
    assert out["b"]["k1"] == "mutation"
    assert agent.prompts, "the comparator was never asked"
    assert roster["c"] not in agent.prompts[0], "a roster arm id reached the comparator prompt"
    assert MARK in agent.prompts[0]
    assert UNRELATED_UUID in agent.prompts[0], "the payload never reached the prompt"

    T.write_family(ep, _doc(R.near_miss_id(episode_id)))
    unasked = T.FakeAgent("mutation")
    with runs.episode(episode_id) as view:
        err = R.raised(delta_o, view, invoke=unasked)
    assert R.is_a(err, FamilyError), f"delta_o over a mismatched manifest: {err!r}"
    assert unasked.prompts == [], "the comparator was asked over a mismatched manifest"


def test_the_episode_readers_take_the_walked_view_and_no_path(data_root):
    """Ruling (review-3 F32, orchestrator): the episode's readers take the WALKED view only —
    `episode.verdicts(view)` (coined here, the shape of `delta_o(view, *, invoke=)`) answers
    each archived world's disposition keyed by label, read through the view
    `runs.episode(<ep>)` handed out; there is no `Path` overload of `verdicts`, `delta_o` or
    `cli.preflight_replay` (a bare path carries no tenant, so it cannot go through the tenant's
    walk — S-iso, recheck S2). Positive control: the same episode through its view answers
    every world. The path form is refused (any exception: no answer is read through a path),
    and the comparator is never asked through one.

    RED at base: `verdicts` and `delta_o` take the episode folder's path (`bind(Path(...))`)."""
    ep, episode_id, _roster = _episode(data_root)
    _outcome(ep)
    J.comparable_family_stamp(ep)
    want = {"a": "benign", "b": "malicious", "c": "false-positive"}
    for label, disposition in want.items():
        T.archived_world(ep, label, disposition=disposition)
    T.base_capture(ep, [T.captured_row(key="k1")])
    episode_mod = T.mod("learning.branch.episode")
    runs = R.tenant(data_root).runs_repository()

    with runs.episode(episode_id) as view:
        got = episode_mod.verdicts(view)
    assert got == want, f"verdicts through the walked view: {got!r}"

    assert R.raised(episode_mod.verdicts, ep) is not None, "verdicts answered through a bare path"
    asked = T.FakeAgent("mutation")
    assert R.raised(episode_mod.delta_o, ep, invoke=asked) is not None, (
        "delta_o answered through a bare path")
    assert asked.prompts == [], "the comparator was asked through a bare path"


class RegistryProbe:
    """The sibling's `lifecycle=` seam: runs the REAL drive function `run._drive_investigation`
    over exactly what `run.main` hands its lifecycle (the run, its world, held episode, settled
    oracle side and source), with the driver itself replaced by a recorder — so the world
    registry `run.py` builds for this sibling is the production one, and nothing models or
    boxes. Records the registry's `branch_identities()`."""

    def __init__(self) -> None:
        self.known: frozenset[str] | None = None

    def __call__(self, **kw: Any) -> dict[str, Any]:
        from defender import run as run_py
        from defender.run_repository import RunPaths

        seen: dict[str, Any] = {}
        inner = dict(kw)
        inner["model_name"] = inner.pop("model")
        run_py._drive_investigation(
            alert_path=RunPaths(kw["run"].run_dir).alert, box=None,
            investigate=lambda **got: seen.update(got) or {}, **inner)
        self.known = frozenset(str(m) for m in seen["verbs"].branch_identities())
        return {"output": "probe", "requests": 0, "truncated_by": None}


def test_the_siblings_query_tool_knows_every_roster_arm_id(tmp_path, monkeypatch, data_root):
    """S-red through the query tool's binding: a sibling started as `run.py --tenant T
    --episode <ep> --world b` builds its world registry (the query tool's `known_ids`, #1257),
    and that registry's identities are exactly every ROSTER arm id — its own and its siblings'
    — plus the episode id and its tokens; no composed `<ep>-<label>` (declared change 15)."""
    P.roots(tmp_path, monkeypatch)
    source_id = R.new_id()
    _base, src = T.runs_base(tmp_path, source_run_id=source_id)
    tenant_id = src.parent.parent.name
    episode_id = R.new_id()
    doc = P.family_doc(src, episode_id=episode_id, source_run_id=source_id)
    ep = T.episode(tmp_path, doc=doc, root=R.episodes_dir(data_root, tenant_id),
                   episode_id=episode_id)
    # The natural container in #1187's shape: no `_tenant.json` (R1).
    (src.parent / "_tenant.json").unlink(missing_ok=True)
    roster = {w["world_id"]: R.new_id() for w in doc["worlds"]}
    (ep / "runs").mkdir()
    R.write_roster(ep, roster)

    probe = RegistryProbe()
    rec = P.SiblingRecorder()
    rc, refused, err = P.drive_run_py(P.new_sibling_argv(tenant_id, episode_id, "b"), rec,
                                      lifecycle=probe)
    assert probe.known is not None, (
        f"the sibling never built its registry: rc={rc} {P.refusal_text(refused)} {err[-2000:]}")
    token = _token(episode_id)
    expected = {episode_id, token, *(f"{token}.{label}" for label in roster), *roster.values()}
    assert probe.known == expected, (
        f"missing {sorted(expected - probe.known)}; unexpected {sorted(probe.known - expected)}")
    assert f"{episode_id}-c" not in probe.known

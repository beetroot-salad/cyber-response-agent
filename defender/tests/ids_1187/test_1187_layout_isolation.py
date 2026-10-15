"""#1187 slice B1 (layout and tenant isolation) — the repository's walk after #1187.

Design rev 2 (#1187 comments 6192137519 / 6192137980): every tenant's runs and episodes live
under its own folder, and every level below `<T>` is opened without following links (S-iso):

    <data root>/<T>/runs/<run uuid>/              natural runs (+ sidecars); no record
    <data root>/<T>/episodes/<ep uuid>/            an episode
    <data root>/<T>/episodes/<ep uuid>/runs/<arm>  its arms

Obligations pinned here (the roster and the sibling gate are `test_1187_roster_sibling.py`'s):

| Obligation | Scenario | Entry | Test |
|---|---|---|---|
| O10, R1, dc 6 | `create` makes `<T>/runs`, writes no `_tenant.json` | `runs.create`, run setup | `test_create_*`, `test_run_setup_*` |
| O10, R1, dc 6 | open / list / all_runs with no record present | `runs.open/list/all_runs` | `test_a_container_with_no_record_*` |
| O10, dc 6 | `_tenant.json` / `_episodes` in `<T>/runs` refuse the listing | `runs.list/all_runs` | `test_the_listing_refuses_*` |
| O10 | an arm id is absent from the natural container | `runs.open` | `test_an_arm_id_is_absent_*` |
| O8, G1/G7, G20/G23, new | a link at each level refuses; positive control per level | repository | `test_a_link_at_*` |
| O8, S-iso step 2, R2-01 | `<T>` itself swapped for a link to B's folder after acceptance: every door refuses | every repository door | `test_a_tenant_folder_swapped_for_a_link_after_acceptance_*` |
| O8, R2-01 (base guard) | `<T>` a link at acceptance time: acceptance refuses | `accept_tenant` | `test_a_link_at_the_tenant_folder_is_refused_at_acceptance_*` |
| Data model, Seq. §4, S3 | the roster's name is `_episode_paths`'; the kinds TSV rows | `_episode_paths`, `run-records-kinds.tsv` | `test_the_arm_rosters_name_*`, `test_the_kinds_table_*`, `test_no_production_module_*` |
| O9, dc 3, G15 | `create_episode` claims `<T>/episodes/<uuid>`, reads no env, no `-r2` | `runs.create_episode` | `test_create_episode_*` |
| O9, dc 5 | no `episodes_root` refusal; env decoy ignored | `runs.episode`, `episode_files` | `test_the_episodes_variable_*` |
| O8 | A's repository asked for B's episode reads nothing of B's | `runs.episode`, `episode_files` | `test_another_tenants_episode_*` |
| R6, dc 13 | a pinned id is not refused by an `_episodes` claim | `runs.create(pinned=True)` | `test_a_pinned_id_*` |

R6 PICK: `runs.create(id, pinned=True)` reads no `_episodes` claim (D-del deletes the reader), so it
hands out the run whether or not an `_episodes` record claiming that id is present; the LISTING
refuses the same container, because `_episodes` is off the natural container's rules (O10).

Fixture ids are `RunId.parse(new uuid)` (today's rule admits a lowercase uuid4, P-01), so a test
reaches its own assertion today; only the tests that pin minting call `RunId.mint()`.
`TenantRefused` is imported from `defender._tenant` (the run repository's door does not serve it
at base). Every refusal is paired with a positive control through the same call in the same test.
"""
from __future__ import annotations

import ast
import os
import shutil
import stat
from pathlib import Path, PurePosixPath

import pytest

from defender import _yaml
from defender.tests import _by_path
from defender.tests import _triplet_947 as T
from defender.tests.ids_1187 import _spec1187 as S

A_ID = "acme"
B_ID = "beta"
DEFENDER = Path(__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
def _no_episodes_variable(monkeypatch):
    """#1187 retires `DEFENDER_EPISODES_BASE` (O9): no test here sets it unless it is the test's
    subject, so an inherited value can never decide a result."""
    monkeypatch.delenv(S.EPISODES_BASE_ENV, raising=False)


# ------------------------------------------------------------------------------------------
# Local builders (pure filesystem over `_spec1187`) and observation helpers.
# ------------------------------------------------------------------------------------------

def _rid(text: str):
    from defender.run_repository import RunId

    return RunId.parse(text)


def _refusals():
    """The repository's two refusal classes (S-iso: a link refuses with either, naming the
    level). Today's `EpisodeRefused` (a `ValueError` about the episodes variable) is neither."""
    from defender._tenant import TenantRefused
    from defender.run_repository import RunRefused

    return (TenantRefused, RunRefused)


def _is_refusal(err: BaseException | None) -> bool:
    return err is not None and isinstance(err, _refusals())


def _manifest(episode_id: str) -> str:
    """A manifest the family model loads (`_triplet_947.family_doc`: worlds a, b, c), naming
    `episode_id` — for any path that reads the manifest's worlds (the roster's readers)."""
    return _yaml.safe_dump(T.family_doc(episode_id=episode_id, source_run_id=S.new_id()))


def _tenant_scene(root: Path, tenant_id: str) -> dict:
    """`tenant_id` accepted under `root`, with one natural run at `<T>/runs/<uuid>` and one
    post-RUNS episode at `<T>/episodes/<uuid>` (a loadable manifest, a roster naming a, b, c,
    and an arm folder per roster id). No record anywhere."""
    t = S.tenant(root, tenant_id)
    run_id = S.new_id()
    S.make_run(S.natural_runs(root, tenant_id), run_id, alert=f'{{"alert": "{tenant_id}"}}\n')
    ep_id = S.new_id()
    roster = {label: S.new_id() for label in ("a", "b", "c")}
    ep = S.make_episode(root, tenant_id, ep_id, manifest=_manifest(ep_id), roster=roster,
                        arms=True)
    return {"tenant": t, "run_id": run_id, "episode_id": ep_id, "episode": ep,
            "roster": roster}


def _two_tenants(root: Path) -> tuple[dict, dict]:
    """A (`acme`, set up first through the real `create_tenant`) and B (`beta`), each with its
    own natural run and post-RUNS episode, under one data root."""
    return _tenant_scene(root, A_ID), _tenant_scene(root, B_ID)


def _aside(path: Path, scratch: Path) -> Path:
    """Move the real `path` out of the way (to `scratch`), so a link can stand at its name."""
    scratch.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(path), str(scratch))
    return scratch


def _restore(link: Path, aside: Path) -> None:
    """Remove the link at `link` and put the real folder back."""
    os.unlink(link)
    shutil.move(str(aside), str(link))


def _real_dir(path: Path) -> bool:
    try:
        return stat.S_ISDIR(os.lstat(path).st_mode)
    except FileNotFoundError:
        return False


def _records_under(folder: Path) -> list[str]:
    """Every `_tenant.json` under `folder`, links not followed."""
    return sorted(str(p) for p in Path(folder).rglob("_tenant.json"))


# ==========================================================================================
# The natural container: no record written, read or required (R1; O10; flow 1).
# ==========================================================================================

def test_create_makes_the_runs_folder_and_writes_no_tenant_record(data_root):
    """Flow 1 step 3 / R1 / declared change 6: `runs.create(id)` walks `<T>` -> `runs`
    no-follow, makes `<T>/runs` when absent, and writes NO `_tenant.json`; the run it hands
    out lives at `<T>/runs/<id>` and its folder is made by the run, not by `create`. First with
    a parsed UUID (so the record assertion is reached today), then with `RunId.mint()`, the
    flow's own id (the mint's grammar is `test_1187_ids.py`'s). RED at base: `create` mints
    `_tenant.json` (and `RunId.mint` takes a label)."""
    from defender.run_repository import RunId

    t = S.tenant(data_root, A_ID)
    runs_dir = S.natural_runs(data_root, A_ID)
    assert not os.path.lexists(runs_dir)
    runs = t.runs_repository()

    parsed = _rid(S.new_id())
    run = runs.create(parsed)
    assert _real_dir(runs_dir), "create did not make <T>/runs as a real directory"
    assert Path(run.run_dir) == runs_dir / str(parsed)
    assert str(run.tenant_id) == A_ID
    assert os.listdir(runs_dir) == [], (
        f"create wrote into <T>/runs beyond making it: {sorted(os.listdir(runs_dir))}")

    minted = RunId.mint()
    assert Path(runs.create(minted).run_dir) == runs_dir / str(minted)
    assert os.listdir(runs_dir) == []
    assert _records_under(S.tenant_dir(data_root, A_ID)) == []


def test_run_setup_writes_no_tenant_record_for_a_minted_or_a_pinned_run(
        tmp_path, data_root):
    """Flow 1 through run setup itself (`run_common.materialize_run`, the function `run.py`
    calls): a minted run and a pinned UUID each land in `<T>/runs`, and neither writes a
    `_tenant.json` (R1, declared change 6). The minted id's grammar is `test_1187_ids.py`'s.
    RED at base: run setup ensures the record."""
    from defender import run_common
    from defender.tests.tenant_1105_run_repository import _spec1105 as H5

    t = S.tenant(data_root, A_ID)
    runs_dir = S.natural_runs(data_root, A_ID)
    alert = H5.alert_file(tmp_path / "in")

    minted = run_common.materialize_run(alert, None, tenant=t)
    assert Path(minted.run_dir).parent == runs_dir
    assert _records_under(runs_dir) == [], "run setup wrote a _tenant.json"

    pinned_id = S.new_id()
    pinned = run_common.materialize_run(alert, pinned_id, tenant=t)
    assert Path(pinned.run_dir) == runs_dir / pinned_id
    assert _records_under(S.tenant_dir(data_root, A_ID)) == [], "run setup wrote a _tenant.json"
    assert sorted(p.name for p in runs_dir.iterdir() if p.is_dir()) == sorted(
        [Path(minted.run_dir).name, pinned_id])


def test_a_container_with_no_record_opens_lists_and_hands_out_every_run(data_root):
    """R1: the natural container's `_tenant.json` is neither required nor read. With UUID run
    folders and their sidecars and NO record, `open`, `list` and `all_runs` answer every run
    (the positive control the listing refusals below are paired with). RED at base: a container
    with no record is `RunUnreachable` / `TenantRefused`."""
    t = S.tenant(data_root, A_ID)
    runs_dir = S.natural_runs(data_root, A_ID)
    first, second = sorted([S.new_id(), S.new_id()])
    S.make_run(runs_dir, first, sidecars=True)
    S.make_run(runs_dir, second)
    runs = t.runs_repository()

    assert Path(runs.open(_rid(first)).run_dir) == runs_dir / first
    assert [str(i) for i in runs.list()] == [first, second]
    assert [Path(r.run_dir).name for r in runs.all_runs()] == [first, second]
    assert not os.path.lexists(runs_dir / "_tenant.json"), "a read wrote a record"


@pytest.mark.parametrize("entry", ["_tenant.json", "_episodes"])
def test_the_listing_refuses_a_tenant_record_or_an_episodes_folder(data_root, entry):
    """O10 / declared change 6 / R6: the natural container holds only UUID run folders and
    their sidecars, so `_tenant.json` (a record naming THIS tenant, today's well-formed one)
    and `_episodes` each make the listing refuse with `RunRefused` (the message naming the
    one-time command is slice C's assertion). Positive control: the entry removed, the same
    listing answers the run. RED at base: the listing skips both by name (P-04)."""
    from defender.run_repository import RunRefused
    from defender.tests.tenant_1105_run_repository import _spec1105 as H5

    t = S.tenant(data_root, A_ID)
    runs_dir = S.natural_runs(data_root, A_ID)
    run_id = S.new_id()
    S.make_run(runs_dir, run_id)
    if entry == "_tenant.json":
        planted = H5.plant_tenant_record(runs_dir, A_ID)
    else:
        planted = runs_dir / "_episodes"
        planted.mkdir()
        (planted / "placeholder.json").write_text("{}\n", encoding="utf-8")
    runs = t.runs_repository()

    for call in (runs.list, runs.all_runs):
        err = S.raised(call)
        assert isinstance(err, RunRefused), (
            f"{call.__name__}() over a container holding {entry} gave {err!r}")
    assert os.path.lexists(planted), "the refused listing removed the entry"

    if planted.is_dir():
        shutil.rmtree(planted)
    else:
        planted.unlink()
    assert [str(i) for i in runs.list()] == [run_id]
    assert [Path(r.run_dir).name for r in runs.all_runs()] == [run_id]


def test_an_arm_id_is_absent_from_the_natural_container_and_opens_through_its_episode(
        data_root):
    """O10: an arm never shows up in the natural container. `runs.open(<arm id>)` is
    `RunAbsent` (nothing at that name in `<T>/runs`), the listing does not carry it, and
    `<T>/runs` is unchanged by the episode's existence. Positive controls: the same arm id
    opens through its episode view at `<T>/episodes/<ep>/runs/<arm id>`, and the natural run
    opens. RED at base: the record-less container is `RunUnreachable` and `runs.episode` reads
    the episodes variable."""
    from defender.run_repository import RunAbsent

    a = _tenant_scene(data_root, A_ID)
    runs_dir = S.natural_runs(data_root, A_ID)
    before = S.tree(runs_dir)
    runs = a["tenant"].runs_repository()
    arm = a["roster"]["b"]

    err = S.raised(runs.open, _rid(arm))
    assert isinstance(err, RunAbsent), f"runs.open(<arm id>) gave {err!r}"
    assert arm not in [str(i) for i in runs.list()]
    assert S.tree(runs_dir) == before, "the natural container changed"

    assert Path(runs.open(_rid(a["run_id"])).run_dir) == runs_dir / a["run_id"]
    with runs.episode(a["episode_id"]) as view:
        assert Path(view.open(_rid(arm)).run_dir) == a["episode"] / "runs" / arm


# ==========================================================================================
# O8 / S-iso: a link at every level below <T> refuses — with the link aimed at ANOTHER
# tenant's real folder holding real entries — and the real folder opens.
# ==========================================================================================

def test_a_link_at_the_natural_runs_folder_is_refused_and_the_real_folder_opens(
        tmp_path, data_root):
    """O8 / G1, G7: `<A>/runs` is a link to B's real natural container (holding B's run). Every
    natural call of A's repository refuses (`TenantRefused`/`RunRefused`) naming `<A>/runs`,
    hands out nothing of B's, and writes nothing into B's tree. Positive control: A's real
    folder back, A's run opens and lists. Expected at base: the refusal half holds (the last
    level is judged no-follow today); the control is red (no record in A's container)."""
    a, b = _two_tenants(data_root)
    link = S.natural_runs(data_root, A_ID)
    target = S.natural_runs(data_root, B_ID)
    aside = _aside(link, tmp_path / "aside" / "runs")
    S.replace_with_link(link, target)
    b_before = S.tree(S.tenant_dir(data_root, B_ID))
    runs = a["tenant"].runs_repository()

    probes = {
        "list": lambda: runs.list(),
        "all_runs": lambda: runs.all_runs(),
        "open(B's run)": lambda: runs.open(_rid(b["run_id"])),
        "create": lambda: runs.create(_rid(S.new_id())),
    }
    for what, probe in probes.items():
        err = S.raised(probe)
        assert _is_refusal(err), f"{what} through a linked <A>/runs gave {err!r}"
    named = S.message(S.raised(runs.list))
    assert str(link) in named, f"the refusal does not name the level {link}: {named!r}"
    assert S.tree(S.tenant_dir(data_root, B_ID)) == b_before, "A's calls changed B's tree"
    assert link.is_symlink(), "the link was replaced"

    _restore(link, aside)
    assert Path(runs.open(_rid(a["run_id"])).run_dir) == link / a["run_id"]
    assert [str(i) for i in runs.list()] == [a["run_id"]]


def test_a_link_at_the_episodes_folder_is_refused_and_the_real_folder_opens(
        tmp_path, data_root):
    """O8, new guard row: `<A>/episodes` is a link to B's real episodes folder. Asked for B's
    episode by id, A's `episode` and `episode_files` refuse naming `<A>/episodes`, and
    `create_episode` refuses and makes nothing through the link (S-iso: never `hold_new`'s
    link-following `makedirs`). B's tree is unchanged. Positive control: A's real folder back,
    A's own episode opens and its arm opens. RED at base: the episode is looked up under the
    episodes variable, and `create_episode` does not exist."""
    a, b = _two_tenants(data_root)
    link = S.episodes_dir(data_root, A_ID)
    target = S.episodes_dir(data_root, B_ID)
    aside = _aside(link, tmp_path / "aside" / "episodes")
    S.replace_with_link(link, target)
    b_before = S.tree(S.tenant_dir(data_root, B_ID))
    runs = a["tenant"].runs_repository()

    probes = {
        "episode(B's ep)": lambda: runs.episode(b["episode_id"]),
        "episode_files(B's ep)": lambda: runs.episode_files(b["episode_id"]),
        "create_episode": lambda: runs.create_episode(),
    }
    for what, probe in probes.items():
        err = S.raised(probe)
        assert _is_refusal(err), f"{what} through a linked <A>/episodes gave {err!r}"
    named = S.message(S.raised(runs.episode, b["episode_id"]))
    assert str(link) in named, f"the refusal does not name the level {link}: {named!r}"
    assert S.tree(S.tenant_dir(data_root, B_ID)) == b_before, "A's calls changed B's tree"
    assert link.is_symlink(), "the link was replaced"

    _restore(link, aside)
    with runs.episode(a["episode_id"]) as view:
        arm = a["roster"]["a"]
        assert Path(view.open(_rid(arm)).run_dir) == a["episode"] / "runs" / arm


def test_a_link_at_an_episode_folder_is_refused_and_the_real_folder_opens(tmp_path, data_root):
    """O8, new guard row (and R2-01: `Episode.open` follows every level today): A's episode
    name `<A>/episodes/<epA>` is a link to B's real episode folder (manifest, roster, arms).
    A's `episode(epA)` and `episode_files(epA)` refuse naming that path; nothing of B's is
    handed out or changed. Positive control: the real folder back, it opens. RED at base."""
    a, b = _two_tenants(data_root)
    link = a["episode"]
    aside = _aside(link, tmp_path / "aside" / "episode")
    S.replace_with_link(link, b["episode"])
    b_before = S.tree(S.tenant_dir(data_root, B_ID))
    runs = a["tenant"].runs_repository()

    for what, probe in {"episode": runs.episode, "episode_files": runs.episode_files}.items():
        err = S.raised(probe, a["episode_id"])
        assert _is_refusal(err), f"{what}(<linked epA>) gave {err!r}"
    named = S.message(S.raised(runs.episode, a["episode_id"]))
    assert str(link) in named, f"the refusal does not name the level {link}: {named!r}"
    assert S.tree(S.tenant_dir(data_root, B_ID)) == b_before, "A's calls changed B's tree"

    _restore(link, aside)
    with runs.episode(a["episode_id"]) as view:
        arm = a["roster"]["c"]
        assert Path(view.open(_rid(arm)).run_dir) == link / "runs" / arm
    handle = runs.episode_files(a["episode_id"])
    try:
        assert Path(handle.dir) == link
    finally:
        handle.close()


def test_a_link_at_an_arm_container_is_refused_and_the_real_folder_opens(tmp_path, data_root):
    """O8 / G20, G25: A's arm container `<epA>/runs` is a link to B's real arm container. A's
    view hands out none of B's arms: `open` of B's arm id refuses, `arms([...])` answers a
    refusal for it, `create` refuses and makes nothing in B's container. (Opening the view
    itself may refuse, or record the container unreadable for the page: either way nothing of
    B's comes back.) Positive control: the real container back, A's arm opens. RED at base:
    `runs.episode` reads the episodes variable."""
    a, b = _two_tenants(data_root)
    link = a["episode"] / "runs"
    aside = _aside(link, tmp_path / "aside" / "arm-container")
    S.replace_with_link(link, b["episode"] / "runs")
    b_before = S.tree(S.tenant_dir(data_root, B_ID))
    runs = a["tenant"].runs_repository()
    b_arm = _rid(b["roster"]["a"])

    opened = S.raised(runs.episode, a["episode_id"])
    if opened is not None:
        assert _is_refusal(opened), f"episode(epA) over a linked runs/ gave {opened!r}"
    else:
        with runs.episode(a["episode_id"]) as view:
            err = S.raised(view.open, b_arm)
            assert _is_refusal(err), f"view.open(B's arm) through a linked runs/ gave {err!r}"
            assert str(link) in S.message(err), (
                f"the refusal does not name the level {link}: {S.message(err)!r}")
            answers: list = []

            def _arms() -> None:
                with view.arms([b_arm]) as handout:
                    answers.append(handout[b_arm])

            whole = S.raised(_arms)
            answer = whole if whole is not None else answers[0]
            assert _is_refusal(answer), f"arms() handed out {answer!r} through the link"
            made = S.raised(view.create, _rid(a["roster"]["a"]))
            assert _is_refusal(made), f"view.create through a linked runs/ gave {made!r}"
    assert S.tree(S.tenant_dir(data_root, B_ID)) == b_before, "A's calls changed B's tree"

    _restore(link, aside)
    with runs.episode(a["episode_id"]) as view:
        arm = a["roster"]["a"]
        assert Path(view.open(_rid(arm)).run_dir) == link / arm


def test_a_link_at_a_runs_own_name_is_refused_and_the_real_folder_opens(tmp_path, data_root):
    """O8: a link at a run's own name — A's natural run `<A>/runs/<rA>` aimed at B's run, and
    A's arm `<epA>/runs/<armA>` aimed at B's arm — is never followed: `open` refuses with a
    plain `RunRefused` (not absent: something is there), the natural listing refuses, and
    nothing of B's changes. Positive control: each real folder back, it opens. Expected at
    base: the refusals hold for the natural run (no record: `RunUnreachable`); the controls
    are red."""
    from defender.run_repository import RunAbsent, RunRefused

    a, b = _two_tenants(data_root)
    natural = S.natural_runs(data_root, A_ID) / a["run_id"]
    arm = a["episode"] / "runs" / a["roster"]["b"]
    natural_aside = _aside(natural, tmp_path / "aside" / "natural")
    arm_aside = _aside(arm, tmp_path / "aside" / "arm")
    S.replace_with_link(natural, S.natural_runs(data_root, B_ID) / b["run_id"])
    S.replace_with_link(arm, b["episode"] / "runs" / b["roster"]["b"])
    b_before = S.tree(S.tenant_dir(data_root, B_ID))
    runs = a["tenant"].runs_repository()

    err = S.raised(runs.open, _rid(a["run_id"]))
    assert isinstance(err, RunRefused), f"open(<linked run>) gave {err!r}"
    assert not isinstance(err, RunAbsent), f"open(<linked run>) read as absent: {err!r}"
    for call in (runs.list, runs.all_runs):
        listed = S.raised(call)
        assert isinstance(listed, RunRefused), f"{call.__name__}() over a linked run gave {listed!r}"
    opened = S.raised(runs.episode, a["episode_id"])
    assert opened is None, f"the episode itself was refused for a link inside it: {opened!r}"
    with runs.episode(a["episode_id"]) as view:
        arm_err = S.raised(view.open, _rid(a["roster"]["b"]))
        assert isinstance(arm_err, RunRefused), f"view.open(<linked arm>) gave {arm_err!r}"
        assert not isinstance(arm_err, RunAbsent), f"<linked arm> read as absent: {arm_err!r}"
    assert S.tree(S.tenant_dir(data_root, B_ID)) == b_before, "A's calls changed B's tree"

    _restore(natural, natural_aside)
    _restore(arm, arm_aside)
    assert Path(runs.open(_rid(a["run_id"])).run_dir) == natural
    with runs.episode(a["episode_id"]) as view:
        assert Path(view.open(_rid(a["roster"]["b"])).run_dir) == arm


# ------------------------------------------------------------------------------------------
# `<T>` itself (S-iso step 2; R2-01; review round 2, F21).
# ------------------------------------------------------------------------------------------

def _b_ids(b: dict) -> dict[str, str]:
    """B's ids that none of A's refusals may show: its natural run, its episode, its arms."""
    return {"B's run": b["run_id"], "B's episode": b["episode_id"],
            **{f"B's arm {label}": arm for label, arm in b["roster"].items()}}


def test_a_link_at_the_tenant_folder_is_refused_at_acceptance_and_the_real_folder_accepts(
        tmp_path, data_root):
    """O8 / R2-01, the acceptance half: with `<A>` itself a link to B's real tenant folder
    BEFORE a request, the observable is acceptance's refusal — `accept_tenant(root, "acme")`
    hands out no `Tenant` (`TenantRefused`, naming a path under `<A>`: today the row read
    through the link names `beta`, not `acme`) and B's tree is unchanged. The repository is
    never reached, so the repository's own `<T>` step is pinned by the swap test below.
    Positive control: A's real folder back, the same call accepts `acme` at `<A>`. GREEN at
    base — a guard that must keep holding (`test_1106_tenant_dir` pins the same refusal over
    its own fixture)."""
    from defender import _tenant
    from defender.tests.tenant_1105_run_repository import _spec1105 as H5

    _two_tenants(data_root)
    link = S.tenant_dir(data_root, A_ID)
    aside = _aside(link, tmp_path / "aside" / "tenant")
    S.replace_with_link(link, S.tenant_dir(data_root, B_ID))
    b_before = S.tree(S.tenant_dir(data_root, B_ID))

    err = S.raised(_tenant.accept_tenant, data_root, A_ID, defender_dir=H5.DEFENDER)
    assert isinstance(err, _tenant.TenantRefused), f"acceptance through a linked <A> gave {err!r}"
    assert str(link) in S.message(err), f"the refusal does not name <A>: {S.message(err)!r}"
    assert S.tree(S.tenant_dir(data_root, B_ID)) == b_before, "acceptance changed B's tree"

    _restore(link, aside)
    accepted = _tenant.accept_tenant(data_root, A_ID, defender_dir=H5.DEFENDER)
    assert str(accepted.id) == A_ID
    assert Path(accepted.dir) == link


def test_a_tenant_folder_swapped_for_a_link_after_acceptance_refuses_every_repository_door(
        tmp_path, data_root):
    """O8 / S-iso step 2 ("the repository holds `<data root>/<T>` no-follow, then opens `runs`,
    `episodes`, `<ep>`, `runs` and the run or arm entry, each off its parent's handle") /
    R2-01 (today a link at `<T>` itself is followed when `<T>/runs` is held). A is accepted
    while its folder is real; THEN `<A>` is replaced by a link to B's real tenant folder (A's
    real folder set aside) and A's repository is taken. Every door — `list()`, `all_runs()`,
    `open(<B's run id>)`, `create(<fresh id>)`, `create_episode()`, `episode(<B's episode
    id>)`, `episode_files(<B's episode id>)` — refuses (`TenantRefused` / `RunRefused`; a
    repository that refuses as it is taken counts for every door), names `<A>`, hands out
    nothing, writes nothing into B's tree, and shows none of B's ids but the one the call
    itself asked for (its run, its episode, its arms). Positive control, the same repository:
    A's real folder back, every door answers for A, and B's run and episode, asked of A's real
    folder, are absent.

    The plausible wrong walk this rejects: start at `<T>/runs` (held no-follow, each level
    below off its parent) with `<T>` itself resolved by path — through the link it lists,
    opens and creates in B's tree.

    Expected at base: the natural reads refuse, but for B's container holding no
    `_tenant.json`, not for the link; `create` FOLLOWS the link and mints a `_tenant.json`
    naming `acme` into B's container (R2-01 executed, B's tree changes); the episode doors are
    missing or read the episodes variable; the control is red (no record in A's container)."""
    from defender.run_repository import RunAbsent

    a, b = _two_tenants(data_root)
    link = S.tenant_dir(data_root, A_ID)
    b_dir = S.tenant_dir(data_root, B_ID)
    aside = _aside(link, tmp_path / "aside" / "tenant")
    S.replace_with_link(link, b_dir)
    b_ids = _b_ids(b)
    faults: list[str] = []
    refusals: dict[str, tuple[BaseException | None, str | None]] = {}

    taken: list = []
    b_before = S.tree(b_dir)
    at_take = S.raised(lambda: taken.append(a["tenant"].runs_repository()))
    if at_take is not None:
        refusals["runs_repository()"] = (at_take, None)
    else:
        runs = taken[0]
        probes = {
            "list()": (lambda: runs.list(), None),
            "all_runs()": (lambda: runs.all_runs(), None),
            "open(B's run)": (lambda: runs.open(_rid(b["run_id"])), b["run_id"]),
            "create(fresh id)": (lambda: runs.create(_rid(S.new_id())), None),
            "create_episode()": (lambda: runs.create_episode(), None),
            "episode(B's episode)": (lambda: runs.episode(b["episode_id"]), b["episode_id"]),
            "episode_files(B's episode)": (
                lambda: runs.episode_files(b["episode_id"]), b["episode_id"]),
        }
        for what, (probe, asked) in probes.items():
            before = S.tree(b_dir)
            refusals[what] = (S.raised(probe), asked)
            if S.tree(b_dir) != before:
                faults.append(f"{what} through a linked <A> changed B's tree")
    for what, (err, asked) in refusals.items():
        if not _is_refusal(err):
            faults.append(f"{what} through a linked <A> gave {err!r}")
            continue
        said = S.message(err)
        if str(link) not in said:
            faults.append(f"{what}'s refusal does not name <A> ({link}): {said!r}")
        faults.extend(f"{what}'s refusal shows {name} {value}: {said!r}"
                      for name, value in b_ids.items() if value != asked and value in said)
    if S.tree(b_dir) != b_before:
        faults.append("A's calls through the link changed B's tree")
    if not link.is_symlink():
        faults.append("the link at <A> was replaced")
    assert faults == [], "a linked <A> was followed or refused wrongly:\n  " + "\n  ".join(faults)

    _restore(link, aside)
    runs = taken[0] if taken else a["tenant"].runs_repository()
    a_runs = S.natural_runs(data_root, A_ID)
    b_before = S.tree(b_dir)
    assert [str(i) for i in runs.list()] == [a["run_id"]]
    assert [Path(r.run_dir).name for r in runs.all_runs()] == [a["run_id"]]
    assert Path(runs.open(_rid(a["run_id"])).run_dir) == a_runs / a["run_id"]
    fresh = S.new_id()
    assert Path(runs.create(_rid(fresh)).run_dir) == a_runs / fresh
    with runs.create_episode() as claimed:
        claimed_id = claimed.episode_id
    assert _real_dir(S.episodes_dir(data_root, A_ID) / claimed_id)
    with runs.episode(a["episode_id"]) as view:
        got = {label: str(arm) for label, arm in (view.arm_ids() or {}).items()}
    assert got == a["roster"], f"A's episode answered another roster: {got}"
    handle = runs.episode_files(a["episode_id"])
    try:
        assert Path(handle.dir) == a["episode"]
    finally:
        handle.close()
    absent = S.raised(runs.open, _rid(b["run_id"]))
    assert isinstance(absent, RunAbsent), f"A's open(<B's run id>) gave {absent!r}"
    assert S.raised(runs.episode, b["episode_id"]) is not None, "A's episode(<B's ep>) opened"
    assert S.tree(b_dir) == b_before, "A's calls through its real folder changed B's tree"


# ==========================================================================================
# Episodes: claimed under <T>/episodes by one exclusive create; no environment (O9, dc 3, 5).
# ==========================================================================================

@pytest.mark.parametrize("variable", ["unset", "bogus", "existing-elsewhere"])
def test_create_episode_claims_a_uuid_folder_under_the_tenant_and_reads_no_environment(
        tmp_path, data_root, monkeypatch, variable):
    """O9 / G15 / declared change 5: `runs.create_episode()` mints a UUID and claims
    `<T>/episodes/<uuid>/`, making `<T>/episodes` (absent before) off the held `<T>`. The
    result is the same whether `DEFENDER_EPISODES_BASE` is unset, names a folder that does not
    exist, or names a real folder elsewhere — nothing is created or changed there, no record
    is written, and the natural container is untouched (O10). RED at base: no
    `create_episode`."""
    t = S.tenant(data_root, A_ID)
    runs_dir = S.natural_runs(data_root, A_ID)
    S.make_run(runs_dir, S.new_id())
    elsewhere = tmp_path / "elsewhere-episodes"
    if variable == "existing-elsewhere":
        elsewhere.mkdir()
        (elsewhere / "keep.txt").write_text("not an episode\n", encoding="utf-8")
    if variable != "unset":
        monkeypatch.setenv(S.EPISODES_BASE_ENV, str(elsewhere))
    elsewhere_before = S.tree(elsewhere)
    runs_before = S.tree(runs_dir)
    episodes = S.episodes_dir(data_root, A_ID)
    assert not os.path.lexists(episodes)

    with t.runs_repository().create_episode() as view:
        episode_id = view.episode_id

    assert S.is_canonical_uuid(episode_id), f"the claimed id is not a uuid: {episode_id!r}"
    assert _real_dir(episodes), "<T>/episodes was not made as a real directory"
    assert os.listdir(episodes) == [episode_id]
    assert _real_dir(episodes / episode_id)
    assert S.tree(elsewhere) == elsewhere_before, "the episodes variable's folder was touched"
    assert os.path.lexists(elsewhere) == (variable == "existing-elsewhere")
    assert S.tree(runs_dir) == runs_before, "claiming an episode changed <T>/runs"
    assert _records_under(S.tenant_dir(data_root, A_ID)) == []


def test_two_episodes_get_two_fresh_uuid_folders_and_never_a_retry_suffix(data_root):
    """Declared change 3 / N3: a second claim is a fresh UUID episode, never `<id>-r2`; both
    folders stand side by side under `<T>/episodes`. RED at base: no `create_episode`.

    NOT PINNED (deferred, no seam): "an entry already at the minted name refuses, with no
    retry". The id is minted inside `create_episode` from random bits, and the design names no
    minting seam; forcing a collision would need `monkeypatch.setattr` on `uuid`, which the
    suite's lint forbids. This test passes for a claim made with `makedirs(exist_ok=True)` or
    with a retry loop at the claim, so the adversary check that remains is exactly those two:
    the claim must be ONE exclusive create (`mkdir` off the held `<T>/episodes`, `EEXIST` a
    refusal) with no second attempt. Owner: `write-code-from-tests`' adversary and its code
    review, at the implementation stage (review round 2, F26)."""
    t = S.tenant(data_root, A_ID)
    runs = t.runs_repository()

    with runs.create_episode() as first:
        one = first.episode_id
    with runs.create_episode() as second:
        two = second.episode_id

    assert one != two
    for episode_id in (one, two):
        assert S.is_canonical_uuid(episode_id), f"{episode_id!r} is not a canonical uuid"
        assert not episode_id.endswith("-r2"), f"{episode_id!r} is a retry name"
    assert sorted(os.listdir(S.episodes_dir(data_root, A_ID))) == sorted([one, two])


@pytest.mark.parametrize("variable", [
    "unset", "inside-data-root", "containing-data-root", "the-tenants-episodes", "decoy"])
def test_the_episodes_variable_changes_nothing_and_no_episodes_root_refusal_fires(
        tmp_path, data_root, monkeypatch, variable):
    """O9 / declared change 5: `<T>/episodes` sits inside the data root, and none of the
    retired `episodes_root` refusals fires — whatever `DEFENDER_EPISODES_BASE` says (unset;
    inside the data root; containing it; naming `<T>/episodes` itself; or a decoy folder
    elsewhere holding a folder of the same episode id with ANOTHER roster). `runs.episode`
    reads T's own roster, `episode_files` hands out T's own folder, and the decoy is untouched.
    RED at base: the variable is read and each placement but the decoy is refused; the decoy
    would be opened instead of T's episode."""
    a = _tenant_scene(data_root, A_ID)
    decoy = tmp_path / "decoy-episodes"
    decoy_roster = {label: S.new_id() for label in ("a", "b", "c")}
    S.make_episode(decoy.parent, decoy.name, a["episode_id"],
                   manifest=_manifest(a["episode_id"]), roster=decoy_roster)
    decoy = decoy / "episodes"
    decoy_before = S.tree(decoy)
    places = {
        "inside-data-root": data_root / "inside",
        "containing-data-root": data_root.parent,
        "the-tenants-episodes": S.episodes_dir(data_root, A_ID),
        "decoy": decoy,
    }
    if variable in places:
        monkeypatch.setenv(S.EPISODES_BASE_ENV, str(places[variable]))
    runs = a["tenant"].runs_repository()

    opened = S.raised(runs.episode, a["episode_id"])
    assert opened is None, f"runs.episode refused with the variable {variable}: {opened!r}"
    assert S.EPISODES_BASE_ENV not in S.message(opened)
    handle = runs.episode_files(a["episode_id"])
    try:
        assert Path(handle.dir) == a["episode"], f"episode_files handed out {handle.dir}"
    finally:
        handle.close()
    with runs.episode(a["episode_id"]) as view:
        got = {label: str(arm) for label, arm in (view.arm_ids() or {}).items()}
    assert got == a["roster"], f"the view read another roster: {got}"
    assert S.tree(decoy) == decoy_before, "the decoy episodes folder was touched"


# ==========================================================================================
# O8: A's repository, asked for B's episode by id, reads nothing of B's (the page's and the
# judge's doors are `runs.episode` and `runs.episode_files`).
# ==========================================================================================

def test_another_tenants_episode_is_absent_to_this_tenants_repository(data_root):
    """O8 / S-iso ("`<A>/episodes/<B's ep>` does not exist") / G20, G23: B's episode exists
    only under `<B>/episodes`. A's `episode(epB)` and `episode_files(epB)` refuse as absent
    (the door's absent refusal: `FileNotFoundError`, or a repository refusal), hand out
    nothing, and leave B's tree unchanged. Positive controls through the same calls: B's
    repository opens it and reads its roster; A's repository opens A's own. RED at base: the
    lookup goes through the episodes variable (unset here), so the control is refused."""
    a, b = _two_tenants(data_root)
    b_before = S.tree(S.tenant_dir(data_root, B_ID))
    runs_a = a["tenant"].runs_repository()

    for what, probe in {"episode": runs_a.episode, "episode_files": runs_a.episode_files}.items():
        err = S.raised(probe, b["episode_id"])
        assert err is not None, f"A's {what}(epB) opened B's episode"
        assert isinstance(err, (FileNotFoundError, *_refusals())), (
            f"A's {what}(epB) gave {err!r}, not an absent episode")
        assert S.EPISODES_BASE_ENV not in S.message(err), (
            f"A's {what}(epB) refused for the retired variable: {S.message(err)!r}")
    assert S.tree(S.tenant_dir(data_root, B_ID)) == b_before, "A's calls changed B's tree"
    assert not os.path.lexists(S.episodes_dir(data_root, A_ID) / b["episode_id"])

    runs_b = b["tenant"].runs_repository()
    with runs_b.episode(b["episode_id"]) as view:
        got = {label: str(arm) for label, arm in (view.arm_ids() or {}).items()}
    assert got == b["roster"]
    handle = runs_b.episode_files(b["episode_id"])
    try:
        assert Path(handle.dir) == b["episode"]
    finally:
        handle.close()
    with runs_a.episode(a["episode_id"]) as view:
        assert Path(view.open(_rid(a["roster"]["a"])).run_dir) == (
            a["episode"] / "runs" / a["roster"]["a"])


# ==========================================================================================
# R6 / declared change 13: no `_episodes` claim is read by `create`.
# ==========================================================================================

def test_a_pinned_id_is_not_refused_by_an_episodes_claim_and_the_listing_refuses(data_root):
    """R6 (D-del) / declared change 13: `runs.create(id, pinned=True)` reads no `_episodes`
    record. With a well-formed PR 1 record in `<T>/runs/_episodes/` claiming exactly that id,
    `create` still hands out the run at `<T>/runs/<id>` and leaves the record untouched; the
    same container's LISTING refuses (`RunRefused`: `_episodes` is off the natural container's
    rules, O10). RED at base: the pinned id is refused as claimed."""
    from defender.run_repository import RunRefused
    from defender.tests.tenant_1105_run_repository import _spec1105 as H5

    t = S.tenant(data_root, A_ID)
    runs_dir = S.natural_runs(data_root, A_ID)
    pinned = S.new_id()
    record = H5.plant_record(runs_dir, "e1", A_ID, S.new_id(), {"a": pinned})
    record_bytes = record.read_bytes()
    runs = t.runs_repository()

    run = runs.create(_rid(pinned), pinned=True)
    assert Path(run.run_dir) == runs_dir / pinned
    assert record.read_bytes() == record_bytes, "create touched the _episodes record"
    assert not os.path.lexists(runs_dir / "_tenant.json"), "create wrote a _tenant.json"
    assert isinstance(S.raised(runs.all_runs), RunRefused), (
        "the listing accepted a container holding _episodes")


# ==========================================================================================
# The roster's name and the kinds table (Data model; Sequencing §4; recheck S3; review F22).
# ==========================================================================================

#: The kinds registry the design's docs step edits (`defender/docs/run-records-kinds.tsv`).
KINDS_TSV = DEFENDER / "docs" / "run-records-kinds.tsv"


def _kinds_rows() -> list[dict[str, str]]:
    """The kinds table as dicts keyed by its header, read off the file itself."""
    lines = KINDS_TSV.read_text(encoding="utf-8").splitlines()
    header = lines[0].split("\t")
    return [dict(zip(header, line.split("\t"), strict=False)) for line in lines[1:]
            if line.strip()]


def test_the_arm_rosters_name_is_owned_by_the_episode_layout(tmp_path):
    """Data model ("The name is owned by `_episode_paths.LAYOUT`, like every episode-folder
    name") / recheck S3 / interface sheet: `_episode_paths.ARM_ROSTER_NAME` is `arms.json`,
    `LAYOUT.arm_roster` is that name relative to the episode folder (as `LAYOUT.family` is
    `family.yaml`), and an episode's bound paths carry it as `EpisodePaths(ep).arm_roster`
    beside `.family` (the accessor `test_1077_name_owners`' kinds-to-accessor table keys on;
    coined here, reported). Positive control: the same owner answers the manifest's name in
    all three forms. RED at base: the owner names no roster."""
    from defender import _episode_paths as P

    episode_dir = tmp_path / "episodes" / S.new_id()
    assert P.FAMILY_NAME == S.MANIFEST_NAME, "control: not the episode layout's owner"
    assert P.LAYOUT.family == PurePosixPath(S.MANIFEST_NAME)
    assert P.EpisodePaths(episode_dir).family == episode_dir / S.MANIFEST_NAME

    assert P.ARM_ROSTER_NAME == S.ROSTER_NAME == "arms.json"
    assert P.LAYOUT.arm_roster == PurePosixPath(S.ROSTER_NAME)
    assert P.EpisodePaths(episode_dir).arm_roster == episode_dir / S.ROSTER_NAME


def test_the_kinds_table_has_the_roster_row_and_drops_the_record_rows():
    """Sequencing §4 (review U6, recheck S3): `run-records-kinds.tsv` gains one row for the arm
    roster — kind `arm_roster` (coined here after the layout's accessor), table 4 (the episode
    folder's records), path `arms.json`; the `episode_runs` row's path becomes `runs/<uuid>/`
    (an arm's folder carries no label, O3); the `tenant` (`_tenant.json`, R1) and
    `episode_runs_record` (`_episodes/<episode_id>.json`, R6) rows go with their records.
    Positive control, same reader: the `family` row is at `family.yaml` in table 4. RED at
    base: no roster row, the old `episode_runs` path, both old rows present."""
    table = _kinds_rows()
    rows = {row["kind"]: row for row in table}
    assert rows["family"]["path"] == S.MANIFEST_NAME, f"control: not the kinds table: {KINDS_TSV}"
    assert rows["family"]["table"] == "4"

    at_roster = [row["kind"] for row in table if row.get("path") == S.ROSTER_NAME]
    assert at_roster == ["arm_roster"], f"rows at {S.ROSTER_NAME}: {at_roster}"
    assert rows["arm_roster"]["table"] == "4", rows["arm_roster"]
    assert rows["episode_runs"]["path"] == "runs/<uuid>/", rows["episode_runs"]
    gone = sorted({"tenant", "episode_runs_record"} & set(rows))
    assert gone == [], f"rows #1187 retires are still in the table: {gone}"


def _roster_name_spellings(root: Path) -> list[str]:
    """`<rel>:<line>` of every string literal holding `arms.json` — a docstring excepted — in
    the Python source under `root` (`defender/`, or a planted tree), outside the name's owner
    `_episode_paths.py`. The listing is `_astlib.source_files` with `tests/` dropped, as
    `test_1187_openers`' census."""
    astlib = _by_path.import_lint_lib("_astlib")
    hits: list[str] = []
    for rel in astlib.source_files(root, (".venv", "__pycache__", "node_modules", "tests")):
        if rel == "_episode_paths.py":
            continue
        _text, tree = astlib.read_and_parse(root / rel, rel)
        with astlib.scan_guard(rel):
            docstrings = {
                id(node.body[0].value) for node in ast.walk(tree)
                if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef,
                                     ast.AsyncFunctionDef))
                and node.body and isinstance(node.body[0], ast.Expr)
                and isinstance(node.body[0].value, ast.Constant)}
            hits.extend(f"{rel}:{node.lineno}" for node in ast.walk(tree)
                        if isinstance(node, ast.Constant) and isinstance(node.value, str)
                        and S.ROSTER_NAME in node.value and id(node) not in docstrings)
    return sorted(hits)


def test_no_production_module_spells_the_rosters_name_but_its_owner(tmp_path):
    """Data model / review F22: the roster's name has one owner, so no other production module
    spells `arms.json` in a string literal — the repository's reader and the page reach it
    through `_episode_paths` (the named wrong implementation: the literal spelled in
    `run_repository/_lookup.py` and again in the page). Positive control, the same scanner over
    a planted tree: a plain literal and an f-string part outside the owner are reported, the
    owner's own constant and a docstring mention are not. GREEN at base, vacuously (no module
    spells it yet); it bites once the roster exists."""
    hits = _roster_name_spellings(DEFENDER)
    assert hits == [], f"{S.ROSTER_NAME} is spelled outside its owner at: {hits}"

    planted = tmp_path / "planted"
    files = {
        "_episode_paths.py": f'ARM_ROSTER_NAME = "{S.ROSTER_NAME}"\n',
        "run_repository/_lookup.py": f'ROSTER = "{S.ROSTER_NAME}"\n',
        "scripts/visualize/page.py": (
            f'def roster(ep):\n    """Reads {S.ROSTER_NAME}."""\n'
            f'    return f"{{ep}}/{S.ROSTER_NAME}"\n'),
        "clean.py": f'"""Mentions {S.ROSTER_NAME} in a docstring only."""\nX = "family.yaml"\n',
    }
    for rel, text in files.items():
        (planted / rel).parent.mkdir(parents=True, exist_ok=True)
        (planted / rel).write_text(text, encoding="utf-8")
    assert _roster_name_spellings(planted) == [
        "run_repository/_lookup.py:1", "scripts/visualize/page.py:3"]

"""#1187 slice B1 (the roster and the sibling gate) — the host-written arm roster and the
sibling's start check that replaces `container_required` and the container record.

Design rev 2 (#1187 comments 6192137519 / 6192137980), R2: the launcher writes
`<T>/episodes/<ep>/arms.json` once, at the start of RUNS (`view.start_runs(labels)`: `runs/`
first, then the roster, one fresh UUID per manifest world). The roster's presence is the fact
"this episode reached RUNS". Its readers (`view.arm_id`, `view.arm_ids`) parse every id with
`RunId.parse` and refuse duplicate ids and a label set other than the manifest's worlds. A
sibling (`run.py --tenant T --episode <ep> --world <label>`) is refused right after acceptance —
before the manifest, `_case_input`, the settings and the paid pre-flight — unless the episode
exists under `<T>/episodes` (walked no-follow) and its roster names `<label>` (O4b, G5/G19).

| Obligation | Scenario | Entry | Test |
|---|---|---|---|
| R2, dc 10 | `start_runs` makes `runs/`, then one UUID per label | `view.start_runs` | `test_start_runs_*` |
| R2 | a second `start_runs` refuses; roster byte-identical | `view.start_runs` | `test_a_second_start_runs_*` |
| G25 | a link / file at `runs/` refuses before any roster | `view.start_runs` | `test_a_link_or_a_file_at_runs_*` |
| R2, O4 | `arm_id` / `arm_ids` read the roster; unknown label absent; `runs/` with no roster is pre-RUNS (F27) | `view.arm_id(s)`, `view.create` | `test_the_arm_ids_*` |
| R2 | `create` refuses an id the roster does not hold | `view.create` | `test_an_arm_is_created_only_*` |
| R2 / S1 | torn, duplicate, non-UUID, label-set faults, a link: refused | `view.arm_id(s)` | `test_a_roster_that_*` |
| F25 | hostile bytes (deep, oversize, BOM, repeated key, off-rule label, non-string id): refused on one bounded line; the gate never crashes | `view.arm_id(s)`, `runs.episode(ep, roster_label=)` | `test_a_roster_that_*` |
| F25 | a refusal quoting a caller's hostile label stays one bounded line | `view.arm_id`, `runs.episode(ep, roster_label=)` | `test_a_refusal_quoting_a_callers_label_*` |
| O4b, G5/G19 | the view's sibling form refuses without a roster naming the label (incl. `runs/` with no roster) | `runs.episode(ep, roster_label=)` | `test_the_sibling_form_of_the_view_*` |
| O4b, G5/G19, O8, O3, O10 | the sibling gate: pre-RUNS, `runs/` with no roster, label missing, torn roster, another tenant's episode, a linked episode | `run.py` (`run.main`) | `test_the_sibling_is_refused_*` |
| D4, S-red, R1b | an arm stamps its world token as `world_id`; a natural run stamps none | `run.py`, run setup | `test_an_arm_stamps_its_world_token_*` |
| O9, dc 5 | the sibling ignores a decoy episodes variable | `run.py` | `test_the_sibling_needs_no_*` |
| R5, dc 10 | the manifest names another uuid: refused after the gate, before any spend | `run.py` | `test_the_sibling_refuses_a_manifest_naming_*` |
| S-acc | a settings half inside `<ep>/runs` (a link to `knowledge/`): acceptance refuses | `run.py` | `test_the_sibling_refuses_a_settings_half_*` |
| O2, dc 1 | `--episode <old id>` over a real folder of that name: refused as a bad id | `run.py` | `test_the_sibling_refuses_an_old_episode_id_*` |

HOW "BEFORE THE MANIFEST" IS OBSERVED. In every sibling scene the manifest carries one extra
top-level field, `zz_spec1187_never_read_before_the_gate`. The family loader refuses an unknown
field by naming it (`_family.parse_family`), so the field's name reaches the refusal text if and
only if the manifest was read. The refused case must not show it; the positive control — the
same scene once the gate passes, the poison still in place — must show it (so the channel can
see a manifest read), and with the manifest restored the sibling runs its arm. The settings,
`_case_input` and the pre-flight all follow the manifest read in `run.main`; the pre-flight is
observed directly (`SiblingRecorder.order`), and nothing may be written under the data root.

Fixture ids are fresh UUIDs (admitted by today's `RunId`, P-01). `TenantRefused` is imported
from `defender._tenant` (the run repository's door does not serve it at base).
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
from pathlib import Path

import pytest

from defender import _yaml
from defender.tests import _triplet_947 as T
from defender.tests.ids_1187 import _spec1187 as S

A_ID = "acme"
B_ID = "beta"
LABELS = ("a", "b", "c")
#: The world every sibling scene starts.
LABEL = "b"
#: The manifest's poison: a top-level field the family loader refuses BY NAME.
SENTINEL = "zz_spec1187_never_read_before_the_gate"
RUNS_BASE_ENV = "DEFENDER_RUNS_BASE"


@pytest.fixture(autouse=True)
def _roots(tmp_path, monkeypatch):
    """`_spec1105_pr2.roots` minus the episodes variable, which #1187 retires (O9): the operator
    runs base pre-flight exports and the learning state root, both under `tmp_path`."""
    from defender.tests import _state1135

    monkeypatch.delenv(S.EPISODES_BASE_ENV, raising=False)
    monkeypatch.setenv(RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    _state1135.set_state_dir(monkeypatch, tmp_path / "learning-state")


# ------------------------------------------------------------------------------------------
# Builders and observation helpers.
# ------------------------------------------------------------------------------------------

def _p():
    """`_spec1105_pr2` (the sibling driver and its recorder), imported where it is used."""
    from defender.tests.tenant_1105_run_repository import _spec1105_pr2 as P

    return P


def _rid(text: str):
    from defender.run_repository import RunId

    return RunId.parse(text)


def _refusals():
    from defender._tenant import TenantRefused
    from defender.run_repository import RunRefused

    return (TenantRefused, RunRefused)


def _is_refusal(err: BaseException | None) -> bool:
    return err is not None and isinstance(err, _refusals())


def _real_dir(path: Path) -> bool:
    try:
        return stat.S_ISDIR(os.lstat(path).st_mode)
    except FileNotFoundError:
        return False


def _manifest(episode_id: str) -> str:
    """A manifest the family model loads (`_triplet_947.family_doc`: worlds a, b, c)."""
    return _yaml.safe_dump(T.family_doc(episode_id=episode_id, source_run_id=S.new_id()))


def _episode(root: Path, tenant_id: str, *, roster=False, arms: bool = False) -> tuple[str, Path]:
    """`(episode id, folder)`: a loadable manifest at `<T>/episodes/<uuid>/`, with the roster
    `roster` (`False`: none — the episode never reached RUNS; a mapping: written verbatim)."""
    episode_id = S.new_id()
    ep = S.make_episode(root, tenant_id, episode_id, manifest=_manifest(episode_id),
                        labels=LABELS, roster=roster, arms=arms)
    return episode_id, ep


def _texts(mapping) -> dict[str, str]:
    """A `{label: RunId}` answer as `{label: text}`."""
    return {label: str(run_id) for label, run_id in mapping.items()}


# ==========================================================================================
# Writing the roster: `view.start_runs(labels)` (R2; G25).
# ==========================================================================================

def test_start_runs_makes_runs_then_writes_one_fresh_uuid_per_label(data_root):
    """R2 / declared change 10's host half: `start_runs(labels)` makes `<ep>/runs/` (a real,
    empty directory: no `_tenant.json`) and writes `arms.json` holding exactly the labels it was
    given, each mapped to a canonical lowercase UUID, all distinct; it returns the same mapping
    as `RunId`s, and nothing else lands in the episode folder (no staged leftover). Read back,
    `arm_ids()` and `arm_id(label)` answer the written ids. The launcher's order is exercised
    too: an episode claimed by `create_episode` takes its roster the same way. RED at base:
    no `start_runs`."""
    t = S.tenant(data_root, A_ID)
    runs = t.runs_repository()
    episode_id, ep = _episode(data_root, A_ID)
    assert not os.path.lexists(ep / "runs")

    with runs.episode(episode_id) as view:
        assert view.arm_ids() is None, "an episode with no roster answered arm ids"
        answered = view.start_runs(list(LABELS))

    assert _real_dir(ep / "runs"), "start_runs did not make runs/ as a real directory"
    assert os.listdir(ep / "runs") == [], f"runs/ holds {sorted(os.listdir(ep / 'runs'))}"
    written = S.read_roster(ep)
    assert sorted(written) == sorted(LABELS), f"the roster's labels are {sorted(written)}"
    assert all(S.is_canonical_uuid(v) for v in written.values()), written
    assert len(set(written.values())) == len(LABELS), f"two labels share an id: {written}"
    assert _texts(answered) == written, "start_runs returned other ids than it wrote"
    assert sorted(os.listdir(ep)) == sorted([S.MANIFEST_NAME, S.ROSTER_NAME, "runs"])

    with runs.episode(episode_id) as view:
        assert _texts(view.arm_ids()) == written
        assert str(view.arm_id(LABEL)) == written[LABEL]

    with runs.create_episode() as claimed:
        fresh = S.episodes_dir(data_root, A_ID) / claimed.episode_id
        (fresh / S.MANIFEST_NAME).write_text(_manifest(claimed.episode_id), encoding="utf-8")
        second = _texts(claimed.start_runs(list(LABELS)))
    assert S.read_roster(fresh) == second
    assert not set(second.values()) & set(written.values()), "two episodes share an arm id"


def test_a_second_start_runs_refuses_and_leaves_the_roster_byte_identical(data_root):
    """R2: the roster is written once. A second `start_runs` — on the same view, on a fresh view,
    and over a roster planted by hand — refuses (a repository refusal) and leaves the roster's
    bytes and `runs/` exactly as they were. The first call is the positive control. RED at
    base: no `start_runs`."""
    t = S.tenant(data_root, A_ID)
    runs = t.runs_repository()
    episode_id, ep = _episode(data_root, A_ID)

    with runs.episode(episode_id) as view:
        view.start_runs(list(LABELS))
        roster_bytes = (ep / S.ROSTER_NAME).read_bytes()
        again = S.raised(view.start_runs, list(LABELS))
        assert _is_refusal(again), f"a second start_runs on the same view gave {again!r}"
    with runs.episode(episode_id) as view:
        fresh = S.raised(view.start_runs, ["a", "b", "c", "d"])
        assert _is_refusal(fresh), f"a second start_runs on a fresh view gave {fresh!r}"
    assert (ep / S.ROSTER_NAME).read_bytes() == roster_bytes, "the roster was rewritten"
    assert os.listdir(ep / "runs") == []

    planted_id, planted = _episode(data_root, A_ID, roster={k: S.new_id() for k in LABELS})
    planted_bytes = (planted / S.ROSTER_NAME).read_bytes()
    with runs.episode(planted_id) as view:
        err = S.raised(view.start_runs, list(LABELS))
    assert _is_refusal(err), f"start_runs over a planted roster gave {err!r}"
    assert (planted / S.ROSTER_NAME).read_bytes() == planted_bytes


#: The roster write the child below makes: `start_runs` on episode `argv[3]` of tenant
#: `argv[2]` under the data root `argv[1]`. With a limit (`argv[4]` bytes, non-zero), the kernel
#: KILLS the child at the first write past that size — `SIGXFSZ` restored to its default action
#: (Python starts with it ignored, which would turn the kill into an `EFBIG` the writer could
#: clean up after) and `RLIMIT_FSIZE` set only after every import and the view's own open, so
#: nothing but `start_runs`' own writes meets the limit. A real SIGKILL-class death mid-write,
#: through the real primitive (adversary F8).
_START_RUNS_CHILD = """
import errno, os, resource, signal, sys
from pathlib import Path
from defender._tenant import TenantRefused
from defender.run_repository import RunRefused
from defender.tests.ids_1187 import _spec1187 as S
root, tenant_id, episode_id, limit = Path(sys.argv[1]), sys.argv[2], sys.argv[3], int(sys.argv[4])
runs = S.tenant(root, tenant_id).runs_repository()
with runs.episode(episode_id) as view:
    if limit:
        signal.signal(signal.SIGXFSZ, signal.SIG_DFL)
        resource.setrlimit(resource.RLIMIT_FSIZE, (limit, resource.RLIM_INFINITY))
    if sys.argv[5] == "unavailable":
        def unavailable(event, args):
            if event == "open" and len(args) >= 3 and args[2] & os.O_TMPFILE == os.O_TMPFILE:
                print("ATOMIC_UNAVAILABLE", flush=True)
                raise OSError(errno.EOPNOTSUPP, "injected unsupported anonymous create")
        sys.addaudithook(unavailable)
    try:
        view.start_runs(["a", "b", "c"])
    except (TenantRefused, RunRefused):
        print("REFUSED", flush=True)
    else:
        print("STARTED", flush=True)
"""
#: Far below any roster of three UUIDs (about 130 bytes), so the write is cut mid-way.
_WRITE_LIMIT = 16


def _start_runs_in_a_child(data_root: Path, episode_id: str, *, limit: int,
                           unavailable: bool = False):
    """`_START_RUNS_CHILD` as a real process of this interpreter over this checkout."""
    import subprocess
    import sys

    from defender.tests.tenant_1105_run_repository import _spec1105 as H5

    env = {**os.environ, "PYTHONPATH": os.pathsep.join(
        filter(None, [str(H5.WORKTREE), os.environ.get("PYTHONPATH")])),
        "PYTHONDONTWRITEBYTECODE": "1", S.DATA_ROOT_ENV: str(data_root)}
    return subprocess.run(  # noqa: S603 — this interpreter, a fixed script
        [sys.executable, "-c", _START_RUNS_CHILD, str(data_root), A_ID, episode_id, str(limit),
         "unavailable" if unavailable else "supported"],
        capture_output=True, text=True, encoding="utf-8", check=False, env=env,
        cwd=str(H5.WORKTREE), timeout=300)


def test_a_roster_write_killed_mid_write_leaves_no_roster(data_root):
    """Data model, the roster's write (adversary F8; an unseamed rule the handoff left to the
    implementation stage): the roster is written "through `_io`'s atomic create lane:
    exclusive, `O_TMPFILE`, write, fsync, then `linkat` ... never through the named `O_EXCL`
    fallback, which can leave a torn file on SIGKILL", so its presence keeps meaning "this
    episode reached RUNS". A child running `start_runs` is KILLED by the kernel mid-write (a
    file-size limit far below the roster, `SIGXFSZ` at its default action): it dies by that
    signal, and afterwards no `arms.json` name exists and nothing but the manifest and `runs/`
    is in the episode folder — the episode reads as never having reached RUNS (`arm_ids()` is
    `None`, the sibling's gate refuses as `TenantRefused`), never as a torn roster every reader
    refuses for ever. A named `O_EXCL` write leaves the torn prefix under the roster's own name.
    Positive control, same child with no limit: it exits 0 and writes the roster naming a, b, c.
    Skipped only where the episode's filesystem has no `O_TMPFILE` (the lane cannot exist
    there; the strict unsupported-lane refusal is pinned separately below). RED at base: no
    `start_runs`."""
    import errno
    import signal

    from defender._tenant import TenantRefused

    t = S.tenant(data_root, A_ID)
    runs = t.runs_repository()
    episode_id, ep = _episode(data_root, A_ID)
    try:
        fd = os.open(ep, os.O_TMPFILE | os.O_WRONLY, 0o600)
    except OSError as e:
        if e.errno not in (errno.EOPNOTSUPP, errno.EISDIR, errno.EINVAL):
            raise
        pytest.skip(f"no O_TMPFILE on the episode's filesystem ({e}): the atomic lane is absent")
    os.close(fd)

    killed = _start_runs_in_a_child(data_root, episode_id, limit=_WRITE_LIMIT)
    assert killed.returncode == -signal.SIGXFSZ, (
        f"the child was not killed mid-write by the file-size limit (rc {killed.returncode}): "
        f"{killed.stderr[-1500:]}")
    torn = (ep / S.ROSTER_NAME).read_bytes()[:200] if os.path.lexists(
        ep / S.ROSTER_NAME) else None
    assert torn is None, f"a roster write killed mid-write left {S.ROSTER_NAME}: {torn!r}"
    leftover = sorted(set(os.listdir(ep)) - {S.MANIFEST_NAME, "runs"})
    assert leftover == [], f"a roster write killed mid-write left {leftover} in the episode"
    with runs.episode(episode_id) as view:
        assert view.arm_ids() is None, "a killed roster write reads as a roster"
    gate = S.raised(_open_and_close, runs, episode_id, roster_label=LABEL)
    assert isinstance(gate, TenantRefused), f"the gate after a killed roster write gave {gate!r}"

    control_id, control = _episode(data_root, A_ID)
    done = _start_runs_in_a_child(data_root, control_id, limit=0)
    assert done.returncode == 0, f"control: the child failed: {done.stderr[-1500:]}"
    assert sorted(S.read_roster(control)) == sorted(LABELS), "control: no roster was written"


def test_an_unavailable_atomic_roster_lane_refuses_without_a_named_fallback(data_root):
    """S-roster's chosen write lane is anonymous create, write, fsync, then linkat; a named
    exclusive-create fallback is forbidden even if the filesystem lacks O_TMPFILE. An external
    child audit hook makes the actual anonymous-open attempt raise EOPNOTSUPP. start_runs
    must refuse with no named roster or temporary file. With the fault absent, the same
    child writes the complete roster. No production seam or assertion about private helpers.
    """
    S.tenant(data_root, A_ID)
    episode_id, ep = _episode(data_root, A_ID)
    failed = _start_runs_in_a_child(data_root, episode_id, limit=0, unavailable=True)
    assert failed.returncode == 0, failed.stderr[-1500:]
    assert "ATOMIC_UNAVAILABLE" in failed.stdout.splitlines(), failed.stdout
    assert "REFUSED" in failed.stdout.splitlines(), failed.stdout
    assert not os.path.lexists(ep / S.ROSTER_NAME), "unsupported lane left a named roster"
    assert sorted(set(os.listdir(ep)) - {S.MANIFEST_NAME, "runs"}) == []

    done = _start_runs_in_a_child(data_root, episode_id, limit=0)
    assert done.returncode == 0, done.stderr[-1500:]
    assert "STARTED" in done.stdout.splitlines(), done.stdout
    assert sorted(S.read_roster(ep)) == sorted(LABELS)


@pytest.mark.parametrize("occupant", ["link-to-another-tenants-arms", "regular-file"])
def test_a_link_or_a_file_at_runs_refuses_before_any_roster_is_written(
        tmp_path, data_root, occupant):
    """G25 (after #1187): `start_runs` makes `runs/` no-follow first, so a link at `<ep>/runs`
    (aimed at ANOTHER tenant's real arm container, holding an arm) or a regular file there
    refuses BEFORE the roster is written: no `arms.json`, the occupant untouched, nothing
    written into the other tenant's tree. (Opening the view may itself refuse, which also
    writes no roster.) Positive control: the occupant removed, `start_runs` writes the roster.
    RED at base: no `start_runs`."""
    t = S.tenant(data_root, A_ID)
    S.tenant(data_root, B_ID)
    _b_id, b_ep = _episode(data_root, B_ID, roster={k: S.new_id() for k in LABELS}, arms=True)
    episode_id, ep = _episode(data_root, A_ID)
    if occupant == "regular-file":
        (ep / "runs").write_text("not a container\n", encoding="utf-8")
    else:
        S.replace_with_link(ep / "runs", b_ep / "runs")
    b_before = S.tree(S.tenant_dir(data_root, B_ID))
    occupant_before = S.tree(ep)
    runs = t.runs_repository()

    opened = S.raised(runs.episode, episode_id)
    if opened is not None:
        assert _is_refusal(opened), f"episode() over a {occupant} at runs/ gave {opened!r}"
    else:
        with runs.episode(episode_id) as view:
            err = S.raised(view.start_runs, list(LABELS))
        assert _is_refusal(err), f"start_runs over a {occupant} at runs/ gave {err!r}"
    assert not os.path.lexists(ep / S.ROSTER_NAME), "a roster was written past a bad runs/"
    assert S.tree(ep) == occupant_before, "the episode folder changed"
    assert S.tree(S.tenant_dir(data_root, B_ID)) == b_before, "the other tenant's tree changed"

    os.unlink(ep / "runs")
    with runs.episode(episode_id) as view:
        view.start_runs(list(LABELS))
    assert sorted(S.read_roster(ep)) == sorted(LABELS)
    assert _real_dir(ep / "runs")


# ==========================================================================================
# Reading the roster: `arm_id`, `arm_ids`, and `create` held to it (R2; O4).
# ==========================================================================================

def test_the_arm_ids_are_the_rosters_and_an_unknown_label_is_absent(data_root):
    """O4 / R2: `arm_ids()` is `None` for an episode that never reached RUNS (and `arm_id`
    then names no arm); with a roster, `arm_ids()` is the roster and `arm_id(label)` is the
    roster's id for that label, never `<ep>-<label>`; a label the roster does not name is
    `RunAbsent`. The crash window between `start_runs`'s two steps — `runs/` made, no roster
    written (review round 2, F27) — is "never reached RUNS" too: `arm_ids()` is `None`, `arm_id`
    names no arm, and `create` makes nothing in the empty `runs/`. RED at base: `arm_id`
    composes `<ep>-<label>`, `arm_ids` does not exist, and the episode is looked up under the
    episodes variable."""
    from defender.run_repository import RunAbsent

    t = S.tenant(data_root, A_ID)
    runs = t.runs_repository()
    bare_id, _bare = _episode(data_root, A_ID)
    with runs.episode(bare_id) as view:
        assert view.arm_ids() is None
        assert _is_refusal(S.raised(view.arm_id, LABEL)), "an arm id was named with no roster"

    gap_id, gap = _episode(data_root, A_ID, arms=True)
    assert _real_dir(gap / "runs")
    assert not os.path.lexists(gap / S.ROSTER_NAME)
    with runs.episode(gap_id) as view:
        assert view.arm_ids() is None, "runs/ with no roster answered arm ids"
        assert _is_refusal(S.raised(view.arm_id, LABEL)), "an arm id was named with no roster"
        made = S.raised(view.create, _rid(S.new_id()))
        assert _is_refusal(made), f"an arm was created in the crash window: {made!r}"
    assert os.listdir(gap / "runs") == [], "a refused create made something in runs/"

    roster = {label: S.new_id() for label in LABELS}
    episode_id, _ep = _episode(data_root, A_ID, roster=roster)
    with runs.episode(episode_id) as view:
        assert _texts(view.arm_ids()) == roster
        for label in LABELS:
            arm = view.arm_id(label)
            assert str(arm) == roster[label]
            assert str(arm) != f"{episode_id}-{label}"
        unknown = S.raised(view.arm_id, "z")
        assert isinstance(unknown, RunAbsent), f"arm_id('z') gave {unknown!r}"


def test_an_arm_is_created_only_at_an_id_the_roster_holds(data_root):
    """R2 ("`create` also refuses an id the roster does not hold") / G5: with no roster, or for
    a fresh id the roster does not name, `view.create` refuses and makes nothing under
    `runs/`; for the roster's own id it hands out the arm at `<ep>/runs/<id>` — a name with
    no label and no episode id in it (O3). RED at base."""
    t = S.tenant(data_root, A_ID)
    runs = t.runs_repository()
    episode_id, ep = _episode(data_root, A_ID)

    with runs.episode(episode_id) as view:
        early = S.raised(view.create, _rid(S.new_id()))
        assert _is_refusal(early), f"an arm was created before RUNS: {early!r}"
        ids = _texts(view.start_runs(list(LABELS)))
        stranger = S.raised(view.create, _rid(S.new_id()))
        assert _is_refusal(stranger), f"an id outside the roster was created: {stranger!r}"
        assert os.listdir(ep / "runs") == [], "a refused create made something"
        arm = view.create(_rid(ids[LABEL]))
    assert Path(arm.run_dir) == ep / "runs" / ids[LABEL]
    assert S.is_canonical_uuid(Path(arm.run_dir).name)
    assert episode_id not in Path(arm.run_dir).name


#: Faults the roster's reader refuses. The first eight are the design's own rules (R2, recheck
#: S1); the rest are hostile bytes a host-written JSON file must still fail closed on, as the
#: retired episode-record reader did (`d3_reader_content_rules`, `d3_record_cap`,
#: `d3_record_labels_are_untrusted_text`; review round 2, F25).
ROSTER_FAULTS = ("torn", "not-an-object", "duplicate-ids", "non-uuid-id", "uppercase-uuid",
                 "extra-label", "missing-label", "link",
                 "deep-nesting", "oversize", "bom", "duplicate-key", "label-off-rule", "int-id",
                 "list-id", "lone-surrogate-label")
#: A label no roster, and no caller, may make a refusal print raw: a line break, an ANSI escape,
#: a C1 control (U+009B, the 8-bit CSI), a line separator, and 20,000 more characters.
HOSTILE_LABEL = "a\n\x1b[2Jforged row\x9b\u2028" + "x" * 20000 + "HOSTILE-TAIL"
#: Labels a caller can hand over that no UTF-8 encoder takes (deck #677 replay, adversary F12):
#: what `run.py --world $'\xff'` carries after argv's surrogateescape decode, and a lone high
#: surrogate inside a label. A refusal that MEASURES its label with `.encode("utf-8")` raises
#: `UnicodeEncodeError` instead of refusing.
SURROGATE_LABELS = ("\udcff", "a\ud800b")
#: The longest refusal text a hostile roster or label may produce (it quotes at most a bounded
#: excerpt of anything it shows — `_shown.quoted` keeps 120 characters).
MESSAGE_BOUND = 2000
#: How deep the `deep-nesting` roster nests one value: past `_io.JSON_NESTING_LIMIT` and past
#: the interpreter's recursion limit, so a bare `json.loads` raises `RecursionError`.
DEEP = 20000


def _unbounded(said: str) -> list[str]:
    """Why a refusal text is not one bounded, printable line ([] when it is): a raw line break,
    a C0 / DEL / C1 control or a Unicode line separator, a length past `MESSAGE_BOUND`, or the
    hostile label's tail."""
    why = []
    raw = sorted({f"U+{ord(c):04X}" for c in said
                  if ord(c) < 0x20 or 0x7F <= ord(c) < 0xA0 or c in "\u2028\u2029"})
    if raw:
        why.append(f"raw control characters {raw}")
    lone = sorted({f"U+{ord(c):04X}" for c in said if 0xD800 <= ord(c) <= 0xDFFF})
    if lone:
        why.append(f"lone surrogates {lone} (not printable; no UTF-8 encoder takes them)")
    if len(said) > MESSAGE_BOUND:
        why.append(f"{len(said)} characters (bound {MESSAGE_BOUND})")
    if "HOSTILE-TAIL" in said:
        why.append("the hostile label's tail")
    return why


def _fingerprint(folder: Path) -> dict[str, tuple]:
    """Every entry under `folder`, links not followed: a regular file by its size and sha256
    (streamed, so an oversize roster is never held in memory), a link by its target, anything
    else by its kind. Two calls compare equal iff nothing was created, removed or rewritten."""
    out: dict[str, tuple] = {}
    for dirpath, dirnames, filenames in os.walk(folder, followlinks=False):
        for name in dirnames + filenames:
            path = Path(dirpath) / name
            st = os.lstat(path)
            rel = path.relative_to(folder).as_posix()
            if stat.S_ISLNK(st.st_mode):
                out[rel] = ("link", os.readlink(path))
            elif stat.S_ISREG(st.st_mode):
                digest = hashlib.sha256()
                with open(path, "rb") as handle:
                    for chunk in iter(lambda: handle.read(1 << 20), b""):
                        digest.update(chunk)
                out[rel] = ("file", st.st_size, digest.hexdigest())
            else:
                out[rel] = ("dir" if stat.S_ISDIR(st.st_mode) else "other",)
    return out


def _ids_json(pairs: list[tuple[str, object]]) -> str:
    """A JSON object spelled pair by pair, so a key may repeat (`json.dumps` cannot)."""
    body = ", ".join(f"{json.dumps(key)}: {json.dumps(value)}" for key, value in pairs)
    return "{" + body + "}\n"


def _deep_text(good: dict[str, str], _text: str) -> str:
    """The good roster with `a`'s id nested `DEEP` arrays down (about 40 KB in all)."""
    deep = "[" * DEEP + json.dumps(good["a"]) + "]" * DEEP
    rest = "".join(f", {json.dumps(k)}: {json.dumps(v)}" for k, v in good.items() if k != "a")
    return '{"a": ' + deep + rest + "}\n"


#: Each text-planted fault: `(good roster, its text) -> the faulty roster's text or bytes`.
ROSTER_TEXTS = {
    "torn": lambda good, text: S.torn(text),
    "not-an-object": lambda good, text: json.dumps(list(LABELS)) + "\n",
    "duplicate-ids": lambda good, text: _ids_json(list({**good, "b": good["a"]}.items())),
    "missing-label": lambda good, text: _ids_json([(k, v) for k, v in good.items() if k != "c"]),
    "extra-label": lambda good, text: _ids_json([*good.items(), ("d", S.new_id())]),
    "non-uuid-id": lambda good, text: _ids_json(list({**good, "a": S.OLD_MINTED_ID}.items())),
    "uppercase-uuid": lambda good, text: _ids_json(
        list({**good, "a": S.SAMPLE_UUID.upper()}.items())),
    "deep-nesting": _deep_text,
    # The good roster behind a UTF-8 byte-order mark: not strict UTF-8 JSON, which the host
    # never writes (a `utf-8-sig` or a bytes-sniffing decode would accept it).
    "bom": lambda good, text: b"\xef\xbb\xbf" + text.encode("utf-8"),
    # `a` twice: a last-wins decode yields a consistent roster ({a, b, c}, distinct UUIDs), so
    # only a reader that refuses a repeated key refuses it.
    "duplicate-key": lambda good, text: _ids_json([*good.items(), ("a", S.new_id())]),
    # A label off the label rule (so off the manifest's worlds too) that is hostile text: what
    # this pins is that the refusal quoting it stays one bounded line.
    "label-off-rule": lambda good, text: _ids_json(
        [(k, v) for k, v in good.items() if k != "a"] + [(HOSTILE_LABEL, good["a"])]),
    "int-id": lambda good, text: _ids_json(list({**good, "a": 5}.items())),
    "list-id": lambda good, text: _ids_json(list({**good, "a": [good["a"]]}.items())),
    # `a`'s entry under the key `"\ud800"` (a JSON escape, so the file itself is plain ASCII):
    # decoded, a lone surrogate no UTF-8 encoder takes (adversary F12) — off the label rule and
    # off the manifest's worlds; what this pins is that the reader refuses rather than raising
    # while it measures or quotes the label.
    "lone-surrogate-label": lambda good, text: _ids_json(
        [("\ud800", good["a"])] + [(k, v) for k, v in good.items() if k != "a"]),
}


def _write_oversize(ep: Path, text: str) -> None:
    """The GOOD roster padded with JSON whitespace to one byte past `_io.READ_LIMIT`, the most
    any whole-file read through `_io` takes (#1174): a reader that read it whole would decode a
    valid roster, so only a bounded read refuses it. Written in 1 MiB pieces."""
    from defender import _io

    with open(ep / S.ROSTER_NAME, "wb") as handle:
        head = text.encode("utf-8")
        handle.write(head)
        remaining = _io.READ_LIMIT + 1 - len(head)
        pad = b" " * (1 << 20)
        while remaining > 0:
            handle.write(pad[:remaining])
            remaining -= len(pad)
    assert (ep / S.ROSTER_NAME).stat().st_size == _io.READ_LIMIT + 1


def _plant_roster_fault(fault: str, ep: Path, good: dict[str, str], tmp_path: Path) -> None:
    """Replace `<ep>/arms.json` (holding `good`) with the faulty roster `fault`."""
    text = (ep / S.ROSTER_NAME).read_text(encoding="utf-8")
    if fault == "link":
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        S.write_roster(elsewhere, good)
        (ep / S.ROSTER_NAME).unlink()
        os.symlink(elsewhere / S.ROSTER_NAME, ep / S.ROSTER_NAME)
    elif fault == "oversize":
        _write_oversize(ep, text)
    else:
        S.write_roster(ep, raw=ROSTER_TEXTS[fault](good, text))


@pytest.mark.parametrize("fault", ROSTER_FAULTS)
def test_a_roster_that_is_torn_inconsistent_or_a_link_is_refused(tmp_path, data_root, fault):
    """R2 / S1: the roster's reader parses the JSON, every id with `RunId.parse`, refuses two
    labels on one id, and refuses a label set that is not exactly the manifest's worlds, so a
    torn or partial roster cannot pass as a subset; a roster that is a link (to a good roster
    elsewhere) is never followed. Each fault: `arm_ids()` and `arm_id(label)` refuse (a
    repository refusal; `RunAbsent` counts, being a `RunRefused`), each refusal one bounded,
    printable line, and the episode unchanged. Positive control: the same episode with the good
    roster answers it.

    Hostile bytes (review round 2, F25) — the design states the reader's rules, not these
    limits; they are pinned on the orchestrator's instruction, after the retired record
    reader's: a value nested past the decoder's depth (a refusal, never a raw
    `RecursionError`); the good roster padded past `_io.READ_LIMIT` (a bounded read refuses
    it; a whole read would accept it); a UTF-8 BOM (not strict UTF-8 JSON); a repeated key (a
    last-wins decode would accept it); a label off the rule that is hostile text (it also breaks
    the manifest-set rule — what it pins is the refusal's quoting); an id that is a number or a
    list; a label that is a lone surrogate (adversary F12: a refusal that measures it with
    `.encode("utf-8")` raises `UnicodeEncodeError` instead). The sibling's gate
    (`runs.episode(ep, roster_label="a")`) reads the same file: it may open (it checks presence
    and the label, review F14) or refuse, but never fails any other way. RED at base: `arm_ids`
    does not exist."""
    t = S.tenant(data_root, A_ID)
    runs = t.runs_repository()
    good = {label: S.new_id() for label in LABELS}
    episode_id, ep = _episode(data_root, A_ID, roster=good)
    good_text = (ep / S.ROSTER_NAME).read_text(encoding="utf-8")
    try:
        _plant_roster_fault(fault, ep, good, tmp_path)
        before = _fingerprint(ep)

        with runs.episode(episode_id) as view:
            whole = S.raised(view.arm_ids)
            assert _is_refusal(whole), f"arm_ids() over a {fault} roster gave {whole!r}"
            one = S.raised(view.arm_id, "a")
            assert _is_refusal(one), f"arm_id('a') over a {fault} roster gave {one!r}"
        for what, err in (("arm_ids()", whole), ("arm_id('a')", one)):
            assert _unbounded(S.message(err)) == [], (
                f"{what}'s refusal over a {fault} roster is not one bounded line: "
                f"{_unbounded(S.message(err))}")
        gate = S.raised(_open_and_close, runs, episode_id, roster_label="a")
        assert gate is None or _is_refusal(gate), (
            f"the sibling's gate over a {fault} roster failed otherwise: {gate!r}")
        assert _unbounded(S.message(gate)) == [], (
            f"the gate's refusal over a {fault} roster: {_unbounded(S.message(gate))}")
        assert _fingerprint(ep) == before, "a refused read changed the episode"
    finally:
        (ep / S.ROSTER_NAME).unlink(missing_ok=True)

    S.write_roster(ep, raw=good_text)
    with runs.episode(episode_id) as view:
        assert _texts(view.arm_ids()) == good
        assert str(view.arm_id("a")) == good["a"]


def _open_and_close(runs, episode_id: str, **kwargs) -> None:
    """Open `runs.episode(episode_id, **kwargs)` and close it again (a refusal propagates)."""
    with runs.episode(episode_id, **kwargs):
        pass


def test_a_refusal_quoting_a_callers_label_stays_one_bounded_line(data_root):
    """Review round 2, F25 (the two new refusals that quote a CALLER's label): `view.arm_id(L)`
    for a label the roster does not name is `RunAbsent`, and the sibling form
    `runs.episode(ep, roster_label=L)` is refused, and with `L` the hostile label (a line
    break, an ANSI escape, a C1 control, a line separator, 20,000 more characters) each refusal
    is one bounded, printable line. The same for a label no UTF-8 encoder takes — argv's
    surrogateescape form of `--world $'\\xff'`, and a lone surrogate inside a label (adversary
    F12): a refusal, never the `UnicodeEncodeError` of a measuring `.encode`. Positive control,
    same calls: `a`, which the roster names, answers the roster's id. RED at base: the episode
    is looked up under the episodes variable (unset), and `roster_label` is not a keyword."""
    from defender.run_repository import RunAbsent

    t = S.tenant(data_root, A_ID)
    runs = t.runs_repository()
    good = {label: S.new_id() for label in LABELS}
    episode_id, _ep = _episode(data_root, A_ID, roster=good)

    for hostile in (HOSTILE_LABEL, *SURROGATE_LABELS):
        shown = ascii(hostile[:24])
        with runs.episode(episode_id) as view:
            absent = S.raised(view.arm_id, hostile)
            assert isinstance(absent, RunAbsent), f"arm_id({shown}) gave {absent!r}"
            assert str(view.arm_id("a")) == good["a"]
        assert _unbounded(S.message(absent)) == [], (
            f"arm_id's refusal quoting the caller's label {shown}: "
            f"{_unbounded(S.message(absent))}")

        gate = S.raised(_open_and_close, runs, episode_id, roster_label=hostile)
        assert _is_refusal(gate), f"the gate for the unnamed label {shown} gave {gate!r}"
        assert _unbounded(S.message(gate)) == [], (
            f"the gate's refusal quoting the caller's label {shown}: "
            f"{_unbounded(S.message(gate))}")
    with runs.episode(episode_id, roster_label="a") as view:
        assert str(view.arm_id("a")) == good["a"]


@pytest.mark.parametrize("roster_state",
                         ["absent", "runs-without-roster", "label-missing", "torn"])
def test_the_sibling_form_of_the_view_refuses_unless_the_roster_names_the_label(
        data_root, roster_state):
    """O4b at the repository (the pinned spelling `runs.episode(ep, roster_label=label)`, which
    replaces PR 2's `container_required`): the view refuses with `TenantRefused` when the
    episode has no roster — with no `runs/` (`absent`), or with the empty `runs/` a crash
    between `start_runs`' two steps leaves (`runs-without-roster`, review round 2, F27: the
    gate keys on the roster, never on `runs/`) — or its roster does not name the label, and
    with a repository refusal
    when the roster is torn — before the manifest is read (the manifest here is poisoned, so a
    read would refuse naming the poison instead). Positive control: the roster naming every
    world (and the manifest restored, since `arm_id` checks the roster against the manifest's
    worlds), the same call opens and `arm_id(label)` is the roster's id.

    "Before the manifest" is observed twice: by the poison, which only a parse through the
    family model reports, and by the KERNEL — inotify on the manifest file reports no read at
    all during the refused call (adversary F9: a gate that reads the manifest raw, outside the
    family model, to peek at its worlds is invisible to the poison). The control's `arm_id`,
    which checks the roster against the manifest's worlds, shows the same channel sees a read.
    RED at base: the episode is looked up under the episodes variable (and `roster_label` is not
    a keyword)."""
    from defender._tenant import TenantRefused

    t = S.tenant(data_root, A_ID)
    runs = t.runs_repository()
    episode_id, ep = _episode(data_root, A_ID)
    doc = T.family_doc(episode_id=episode_id, source_run_id=S.new_id())
    T.write_family(ep, {**doc, SENTINEL: "read"})
    roster = {label: S.new_id() for label in LABELS}
    if roster_state != "absent":
        (ep / "runs").mkdir()
    if roster_state == "label-missing":
        S.write_roster(ep, {k: v for k, v in roster.items() if k != LABEL})
    elif roster_state == "torn":
        S.write_roster(ep, raw=S.torn(json.dumps(roster, indent=2)))
    before = S.tree(ep)

    with S.FileReads(ep / S.MANIFEST_NAME) as watch:
        err = S.raised(runs.episode, episode_id, roster_label=LABEL)
        seen = watch.events()
    if roster_state == "torn":
        assert _is_refusal(err), f"a torn roster gave {err!r}"
    else:
        assert isinstance(err, TenantRefused), f"roster {roster_state}: {err!r}"
    assert SENTINEL not in S.message(err), f"the manifest was read first: {S.message(err)!r}"
    assert "read" not in seen, (
        f"the manifest was read before the gate refused ({roster_state}; the kernel saw {seen})")
    assert S.EPISODES_BASE_ENV not in S.message(err), f"refused for the variable: {err!r}"
    assert S.tree(ep) == before, "the refused view changed the episode"

    if os.path.lexists(ep / S.ROSTER_NAME):
        (ep / S.ROSTER_NAME).unlink()
    (ep / "runs").mkdir(exist_ok=True)
    S.write_roster(ep, roster)
    T.write_family(ep, doc)
    with S.FileReads(ep / S.MANIFEST_NAME) as watch:
        with runs.episode(episode_id, roster_label=LABEL) as view:
            assert str(view.arm_id(LABEL)) == roster[LABEL]
        assert watch.reads() > 0, (
            "control: the channel saw no read of the manifest where `arm_id` checks the roster "
            "against the manifest's worlds")


# ==========================================================================================
# The sibling gate through the real `run.py` (O4b; G5/G19; O8; O3).
# ==========================================================================================

class _Scene:
    """One post-QUESTIONER episode of tenant `owner` in the new layout: the source run at
    `<owner>/runs/<uuid>` (a plain run folder with its alert; no `_tenant.json` — the sibling
    only opens it by id, its lifecycle is the recorder's), the episode at
    `<owner>/episodes/<uuid>` holding the launcher's manifest (`_triplet_947.family_doc`, naming
    the source by id), an empty primed `served/base.jsonl` and the source alert's copy — and,
    until `start_runs_by_hand`, no `runs/` and no roster (pre-RUNS). `owner` must be the first
    tenant of `root` (it is made through the real `create_tenant`)."""

    def __init__(self, tmp_path: Path, root: Path, owner: str) -> None:
        self.root = root
        self.owner = owner
        self.source_id = S.new_id()
        self.episode_id = S.new_id()
        S.tenant(root, owner)
        self.source = S.make_run(S.natural_runs(root, owner), self.source_id,
                                 alert='{"rule": {"id": "v2-cross-tier-ssh-pivot"}}\n')
        self.doc = T.family_doc(source_run_dir=str(self.source), source_run_id=self.source_id,
                                episode_id=self.episode_id)
        self.ep = T.episode(tmp_path, doc=self.doc, root=S.episodes_dir(root, owner),
                            episode_id=self.episode_id)
        self.roster = {w["world_id"]: S.new_id() for w in self.doc["worlds"]}

    def poison(self) -> None:
        T.write_family(self.ep, {**self.doc, SENTINEL: "read"})

    def restore(self) -> None:
        T.write_family(self.ep, self.doc)

    def start_runs_by_hand(self, roster: dict | None = None, *, raw: str | None = None) -> None:
        """What `start_runs` leaves: `runs/`, then the roster (default: every manifest world)."""
        (self.ep / "runs").mkdir(exist_ok=True)
        if raw is not None:
            S.write_roster(self.ep, raw=raw)
        else:
            S.write_roster(self.ep, self.roster if roster is None else roster)


def _sibling(tenant_id: str, episode_id: str):
    """Drive the real `run.main` as a sibling: `(rc, SystemExit or None, said, recorder)`."""
    P = _p()
    rec = P.SiblingRecorder()
    rc, refused, err = P.drive_run_py(P.new_sibling_argv(tenant_id, episode_id, LABEL), rec)
    return rc, refused, f"{P.refusal_text(refused)}\n{err}", rec


SIBLING_CASES = ("pre-runs", "runs-without-roster", "label-not-in-roster", "torn-roster",
                 "another-tenants-episode", "linked-episode")


@pytest.mark.parametrize("case", SIBLING_CASES)
def test_the_sibling_is_refused_before_the_manifest_unless_its_roster_names_it(
        tmp_path, data_root, case):
    """O4b / G5, G19 / O8 / declared change 10 (sibling half). `run.py --tenant R --episode
    <ep> --world b` is refused right after acceptance — the poisoned manifest unread, nothing
    spent (`SiblingRecorder.order` empty), nothing written under the data root, no arm made —
    when:

    * `pre-runs`: the episode never reached RUNS (no `runs/`, no roster: pre-flight refused,
      aborted, or the launcher crashed before RUNS);
    * `runs-without-roster`: the launcher crashed between `start_runs`' two steps — an empty
      `runs/`, no roster (review round 2, F27: a gate keyed on `runs/` would pass it);
    * `label-not-in-roster`: the roster does not name `b`;
    * `torn-roster`: the roster is cut mid-way (a refused roster read refuses the sibling);
    * `another-tenants-episode`: R = `acme` names `beta`'s episode, which exists only under
      `<beta>/episodes` (S-iso: `<acme>/episodes/<ep>` does not exist);
    * `linked-episode`: R = `acme`, and `<acme>/episodes/<ep>` is a link to `beta`'s real,
      post-RUNS episode folder (O8: the walk never follows it).

    "Before the manifest" is observed by the poison AND by the kernel: inotify on the manifest
    file reports no read during the refused run (adversary F9: a raw read outside the family
    model never trips the poison).

    Positive controls, same scene: once the gate's condition holds (the roster fixed, or the
    owning tenant `beta` asking) and with the poison still in place, the refusal NAMES the
    poison and the kernel reports the read — the manifest is read right after the gate; with
    the manifest restored the sibling
    runs (exit 0) and its arm is `<ep>/runs/<roster id for b>`: a canonical UUID holding neither
    the label nor the episode id (O3). Every refused text is also clear of
    `DEFENDER_EPISODES_BASE` (O9). RED at base: the sibling reads the episodes variable, so
    the controls (and the variable check) fail."""
    scene = _Scene(tmp_path, data_root, B_ID)
    requester = B_ID
    if case in ("another-tenants-episode", "linked-episode"):
        S.tenant(data_root, A_ID)
        requester = A_ID
        scene.start_runs_by_hand()
        if case == "linked-episode":
            S.episodes_dir(data_root, A_ID).mkdir(parents=True)
            S.replace_with_link(S.episodes_dir(data_root, A_ID) / scene.episode_id, scene.ep)
    elif case == "runs-without-roster":
        (scene.ep / "runs").mkdir()
    elif case == "label-not-in-roster":
        scene.start_runs_by_hand({k: v for k, v in scene.roster.items() if k != LABEL})
    elif case == "torn-roster":
        scene.start_runs_by_hand(raw=S.torn(json.dumps(scene.roster, indent=2)))
    scene.poison()
    before = S.tree(data_root)

    with S.FileReads(scene.ep / S.MANIFEST_NAME) as watch:
        rc, refused, said, rec = _sibling(requester, scene.episode_id)
        seen = watch.events()
    assert refused is not None, f"the sibling ran ({case}): rc {rc}"
    assert rc is None, f"the sibling ran ({case}): rc {rc}"
    assert SENTINEL not in said, f"the manifest was read before the gate ({case}): {said!r}"
    assert "read" not in seen, (
        f"the manifest was read before the gate refused ({case}; the kernel saw {seen})")
    assert S.EPISODES_BASE_ENV not in said, f"refused for the retired variable: {said!r}"
    assert rec.order == [], f"the sibling spent before refusing ({case}): {rec.order}"
    assert S.tree(data_root) == before, f"the refused sibling wrote under the data root ({case})"

    if requester == B_ID:
        if os.path.lexists(scene.ep / S.ROSTER_NAME):
            (scene.ep / S.ROSTER_NAME).unlink()
        scene.start_runs_by_hand()
    with S.FileReads(scene.ep / S.MANIFEST_NAME) as watch:
        rc, refused, said, rec = _sibling(B_ID, scene.episode_id)
        assert watch.reads() > 0, (
            f"control ({case}): the channel saw no read of the manifest past the gate")
    assert refused is not None, f"the poisoned manifest was not read ({case}): rc {rc}"
    assert SENTINEL in said, (
        f"past the gate, the manifest's refusal should name {SENTINEL} ({case}): {said!r}")
    assert rec.order == [], f"the manifest refusal came after a spend: {rec.order}"

    scene.restore()
    natural_before = sorted(os.listdir(S.natural_runs(data_root, B_ID)))
    P = _p()
    ok = P.SiblingRecorder()
    rc, refused, err = P.drive_run_py(P.new_sibling_argv(B_ID, scene.episode_id, LABEL), ok)
    assert refused is None, (
        f"the control sibling was refused ({case}): {P.refusal_text(refused)} {err}")
    assert rc == 0, f"the control sibling exited {rc} ({case}): {err}"
    assert ok.run_dir == scene.ep / "runs" / scene.roster[LABEL], f"the arm is at {ok.run_dir}"
    name = Path(ok.run_dir).name
    assert S.is_canonical_uuid(name), f"the arm's folder name is not a uuid: {name!r}"
    assert scene.episode_id not in name
    assert sorted(os.listdir(S.natural_runs(data_root, B_ID))) == natural_before, (
        "the arm (or a sidecar of it) landed in the natural container (O10)")


def _run_control(scene: _Scene, case: str) -> None:
    """The positive control every gate test ends on: `scene` restored (its real manifest, its
    roster naming every world), the sibling for `b` runs (exit 0) and its arm is
    `<ep>/runs/<roster id for b>`."""
    P = _p()
    ok = P.SiblingRecorder()
    rc, refused, err = P.drive_run_py(P.new_sibling_argv(B_ID, scene.episode_id, LABEL), ok)
    assert refused is None, (
        f"the control sibling was refused ({case}): {P.refusal_text(refused)} {err}")
    assert rc == 0, f"the control sibling exited {rc} ({case}): {err}"
    assert ok.run_dir == scene.ep / "runs" / scene.roster[LABEL], f"the arm is at {ok.run_dir}"


def test_the_sibling_refuses_a_manifest_naming_another_episode_before_any_spend(
        tmp_path, data_root):
    """R5 / declared change 10 at the sibling (review F8): a post-RUNS episode (its roster names
    `b`) whose manifest's `episode_id` is ANOTHER uuid — the folder's own with its last hex digit
    changed (adversary F11). `run.py --tenant T --episode <ep> --world
    b` passes the roster gate, then the one manifest loader — handed the folder's id — refuses,
    naming both ids, before the settings, `_case_input` and the paid pre-flight
    (`SiblingRecorder.order` empty); no arm is made under `runs/` and nothing is written under
    the data root. Positive control: the manifest restored, the same sibling runs its arm at the
    roster's id. RED at base: the sibling reads the episodes variable (unset here)."""
    scene = _Scene(tmp_path, data_root, B_ID)
    scene.start_runs_by_hand()
    other = S.near_miss_id(scene.episode_id)
    T.write_family(scene.ep, {**scene.doc, "episode_id": other})
    before = S.tree(data_root)

    rc, refused, said, rec = _sibling(B_ID, scene.episode_id)
    assert refused is not None, f"the sibling ran over a mismatched manifest: rc {rc}"
    assert rc is None, f"the sibling ran over a mismatched manifest: rc {rc}"
    text = _p().refusal_text(refused)
    assert other in text, f"the refusal does not name the manifest's id {other}: {text!r}"
    assert scene.episode_id in text, f"the refusal does not name the folder's id: {text!r}"
    assert rec.order == [], f"the sibling spent before refusing: {rec.order}"
    assert os.listdir(scene.ep / "runs") == [], "an arm was made under a mismatched manifest"
    assert S.tree(data_root) == before, "the refused sibling wrote under the data root"

    scene.restore()
    _run_control(scene, "manifest-names-another-episode")


def test_the_sibling_refuses_a_settings_half_inside_its_arm_container(tmp_path, data_root):
    """S-acc (review F6): a sibling accepts its tenant with its arm container
    `<T>/episodes/<ep>/runs` among the trees a box mounts — computed from the tenant and the
    episode id, never from the environment (unset here) — BEFORE the roster gate (Flow 3 steps
    2-3). `<ep>/runs` planted as a link to the tenant's own `knowledge/` puts the settings half
    inside it: the sibling is refused at acceptance — the refusal names the settings and that a
    box mounts the tree — before the manifest is read (poisoned) and before anything is spent;
    nothing is written. Positive control: the real `runs/` back and the manifest restored, the
    same sibling runs its arm. RED at base: the sibling reads the episodes variable."""
    scene = _Scene(tmp_path, data_root, B_ID)
    scene.start_runs_by_hand()
    (scene.ep / "runs").rmdir()
    os.symlink(S.tenant_dir(data_root, B_ID) / "knowledge", scene.ep / "runs",
               target_is_directory=True)
    scene.poison()
    before = S.tree(data_root)

    rc, refused, said, rec = _sibling(B_ID, scene.episode_id)
    assert refused is not None, f"the sibling ran: rc {rc}"
    assert rc is None, f"the sibling ran: rc {rc}"
    text = _p().refusal_text(refused)
    assert "settings" in text, f"not acceptance's settings refusal: {text!r}"
    assert "a box mounts" in text, f"not acceptance's settings refusal: {text!r}"
    assert SENTINEL not in said, f"the manifest was read before acceptance refused: {said!r}"
    assert S.EPISODES_BASE_ENV not in said, f"refused for the retired variable: {said!r}"
    assert rec.order == [], f"the sibling spent before refusing: {rec.order}"
    assert S.tree(data_root) == before, "the refused sibling wrote under the data root"

    os.unlink(scene.ep / "runs")
    (scene.ep / "runs").mkdir()
    scene.restore()
    _run_control(scene, "settings-inside-arm-container")


def test_the_sibling_refuses_an_old_episode_id_before_anything_is_read(tmp_path, data_root):
    """O2 / declared change 1 at the sibling (review F10): `--episode <old id>` is refused as a
    bad id, naming it, although a real post-RUNS episode folder of that very name — its manifest
    naming it, its roster naming `b` — sits at `<T>/episodes/<old id>`: the manifest (poisoned)
    is never read, nothing is spent or written, and the refusal is not about the retired
    variable. Positive control: the same folder under its UUID, manifest restored, runs the arm.
    RED at base: today's episode-id rule admits the old id, and the sibling reads the variable."""
    scene = _Scene(tmp_path, data_root, B_ID)
    scene.start_runs_by_hand()
    old = S.OLD_MINTED_ID
    old_ep = scene.ep.parent / old
    scene.ep.rename(old_ep)
    T.write_family(old_ep, {**scene.doc, "episode_id": old, SENTINEL: "read"})
    before = S.tree(data_root)

    rc, refused, said, rec = _sibling(B_ID, old)
    assert refused is not None, f"the sibling ran under an old id: rc {rc}"
    assert rc is None, f"the sibling ran under an old id: rc {rc}"
    assert old in _p().refusal_text(refused), f"the refusal does not name {old}: {said!r}"
    assert SENTINEL not in said, f"the manifest was read under an old id: {said!r}"
    assert S.EPISODES_BASE_ENV not in said, f"refused for the retired variable: {said!r}"
    assert rec.order == [], f"the sibling spent before refusing: {rec.order}"
    assert S.tree(data_root) == before, "the refused sibling wrote under the data root"

    old_ep.rename(scene.ep)
    scene.restore()
    _run_control(scene, "old-episode-id")


def test_the_sibling_needs_no_episodes_variable_and_ignores_a_decoy(tmp_path, data_root,
                                                                     monkeypatch):
    """O9 / declared change 5: the sibling derives its episode from its tenant. With
    `DEFENDER_EPISODES_BASE` naming a decoy folder that holds an episode of the same id (and a
    roster naming `b`), the sibling still runs in `<T>/episodes/<ep>` and the decoy is
    untouched; unset, it runs the same way. RED at base: the variable decides where the
    episode is."""
    scene = _Scene(tmp_path, data_root, B_ID)
    scene.start_runs_by_hand()
    decoy_root = tmp_path / "decoy-episodes"
    shutil.copytree(scene.ep, decoy_root / scene.episode_id, symlinks=True)
    S.write_roster(decoy_root / scene.episode_id, {k: S.new_id() for k in scene.roster})
    decoy_before = S.tree(decoy_root)
    monkeypatch.setenv(S.EPISODES_BASE_ENV, str(decoy_root))

    P = _p()
    ok = P.SiblingRecorder()
    rc, refused, err = P.drive_run_py(P.new_sibling_argv(B_ID, scene.episode_id, LABEL), ok)
    assert refused is None, f"refused with a decoy set: {P.refusal_text(refused)} {err}"
    assert rc == 0, f"exited {rc} with a decoy set: {err}"
    assert ok.run_dir == scene.ep / "runs" / scene.roster[LABEL]
    assert S.tree(decoy_root) == decoy_before, "the decoy episode was touched"


def test_an_arm_stamps_its_world_token_as_world_id_and_a_natural_run_stamps_none(
        tmp_path, data_root):
    """D4 / S-red / review round 2, F23: an arm's provenance stamp still carries its world
    token as `world_id` — #1187 drops `world_id` from NATURAL runs only (R1b, declared change
    11; data model "`world_id` is dropped from natural runs"), and leaves the arm's as it is.
    The token is the design's rule, written here from the design, not from production: the
    episode token is the episode's UUID with its hyphens rendered as dots (R2-03; a canonical
    UUID holds no `_` or `.` to escape), and the world token is `<episode token>.<label>`.

    Contrast first, through the same file: a natural run made by run setup (the function
    `run.py` calls) stamps no `world_id`. Then the sibling (`run.py --tenant T --episode <ep>
    --world b`, the REAL run setup behind `SiblingRecorder`) runs its arm after RUNS, and the
    arm's `provenance.json` names `<episode token>.b` — never the label alone, the arm's UUID
    or the episode id. RED at base: run setup copies the tenant record's `base_world_id` into
    the natural stamp (and the sibling reads the episodes variable)."""
    from defender import run_common
    from defender.tests.tenant_1105_run_repository import _spec1105 as H5

    scene = _Scene(tmp_path, data_root, B_ID)
    t = S.tenant(data_root, B_ID)
    natural = run_common.materialize_run(H5.alert_file(tmp_path / "in"), None, tenant=t)
    natural_stamp = json.loads(
        (Path(natural.run_dir) / "provenance.json").read_text(encoding="utf-8"))
    assert natural_stamp.get("world_id") is None, (
        f"a natural run stamps no world id; it says {natural_stamp.get('world_id')!r}")

    scene.start_runs_by_hand()
    P = _p()
    ok = P.SiblingRecorder()
    rc, refused, err = P.drive_run_py(P.new_sibling_argv(B_ID, scene.episode_id, LABEL), ok)
    assert refused is None, f"the sibling was refused: {P.refusal_text(refused)} {err}"
    assert rc == 0, f"the sibling exited {rc}: {err}"
    assert ok.run_dir == scene.ep / "runs" / scene.roster[LABEL], f"the arm is at {ok.run_dir}"
    arm_stamp = json.loads((ok.run_dir / "provenance.json").read_text(encoding="utf-8"))
    token = scene.episode_id.replace("-", ".")
    assert arm_stamp.get("world_id") == f"{token}.{LABEL}", (
        f"the arm's world_id is {arm_stamp.get('world_id')!r}, not its world token "
        f"{token}.{LABEL}")

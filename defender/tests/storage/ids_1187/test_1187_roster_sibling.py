"""Arm creation and sibling admission trust only complete, validated tenant-scoped rosters."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
from pathlib import Path

import pytest

from defender import _yaml
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.storage.ids_1187 import _spec1187 as S
from defender.tests.storage.tenant_1105_run_repository import _spec1105_pr2 as P
from defender.run_repository import RunId, RunRefused
from defender.tenancy._tenant import TenantRefused

A_ID = S.H5.T_ID
B_ID = S.H5.U_ID
LABELS = ("a", "b", "c")
#: The world every sibling scene starts.
LABEL = "b"
WORLD_IDS = tuple(T.fixture_world_id(label) for label in LABELS)
WORLD_ID = T.fixture_world_id(LABEL)
#: The manifest's poison: a top-level field the family loader refuses BY NAME.
SENTINEL = "zz_spec1187_never_read_before_the_gate"
RUNS_BASE_ENV = "DEFENDER_RUNS_BASE"


@pytest.fixture(autouse=True)
def _roots(tmp_path, monkeypatch):
    """Configure tenant roots without the retired external episodes-root variable."""
    from defender.tests.support.learning.core import _state1135

    monkeypatch.delenv(S.EPISODES_BASE_ENV, raising=False)
    monkeypatch.setenv(RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    _state1135.set_state_dir(monkeypatch, tmp_path / "learning-state")
# Builders and observation helpers.


def _is_refusal(err: BaseException | None) -> bool:
    return isinstance(err, (TenantRefused, RunRefused))


def _real_dir(path: Path) -> bool:
    try:
        return stat.S_ISDIR(os.lstat(path).st_mode)
    except FileNotFoundError:
        return False


def _manifest(episode_id: str) -> str:
    """A manifest the family model loads (`_triplet_947.family_doc`: worlds a, b, c)."""
    return _yaml.safe_dump(T.family_doc(episode_id=episode_id, source_run_id=S.new_id()))


def _episode(root: Path, tenant_id: str, *, roster=False, arms: bool = False) -> tuple[str, Path]:
    """Create a loadable tenant-scoped episode, with its roster when requested."""
    episode_id = S.new_id()
    ep = S.make_episode(root, tenant_id, episode_id, manifest=_manifest(episode_id),
                        labels=LABELS, roster=roster, arms=arms)
    return episode_id, ep


def _texts(mapping) -> dict[str, str]:
    """A `{label: RunId}` answer as `{label: text}`."""
    return {label: str(run_id) for label, run_id in mapping.items()}
# Writing the roster: `view.start_runs(world_uuids)` (R2; G25).

def test_start_runs_makes_runs_then_writes_one_fresh_arm_uuid_per_world(data_root):
    t = S.tenant(data_root, A_ID)
    runs = t.runs_repository()
    episode_id, ep = _episode(data_root, A_ID)
    assert not os.path.lexists(ep / "runs")

    with runs.episode(episode_id) as view:
        assert view.arm_ids() is None, "an episode with no roster answered arm ids"
        answered = view.start_runs(list(WORLD_IDS))

    assert _real_dir(ep / "runs"), "start_runs did not make runs/ as a real directory"
    assert os.listdir(ep / "runs") == [], f"runs/ holds {sorted(os.listdir(ep / 'runs'))}"
    written = S.read_roster(ep)
    assert sorted(written) == sorted(WORLD_IDS), f"the roster's labels are {sorted(written)}"
    assert all(S.is_canonical_uuid(v) for v in written.values()), written
    assert len(set(written.values())) == len(LABELS), f"two labels share an id: {written}"
    assert _texts(answered) == written, "start_runs returned other ids than it wrote"
    assert sorted(os.listdir(ep)) == sorted([S.MANIFEST_NAME, S.ROSTER_NAME, "runs"])

    with runs.episode(episode_id) as view:
        assert _texts(view.arm_ids()) == written
        assert str(view.arm_id(WORLD_ID)) == written[WORLD_ID]

    with runs.create_episode() as claimed:
        fresh = S.episodes_dir(data_root, A_ID) / claimed.episode_id
        (fresh / S.MANIFEST_NAME).write_text(_manifest(claimed.episode_id), encoding="utf-8")
        second = _texts(claimed.start_runs(list(WORLD_IDS)))
    assert S.read_roster(fresh) == second
    assert not set(second.values()) & set(written.values()), "two episodes share an arm id"


def test_a_seventy_thousand_character_label_has_a_readable_uuid_roster_and_child(tmp_path, data_root):
    scene = _Scene(tmp_path, data_root, A_ID)
    label = "w" * 70_000
    scene.doc["worlds"][1]["label"] = label
    T.write_family(scene.ep, scene.doc)
    world_ids = [world["world_id"] for world in scene.doc["worlds"]]
    runs = S.tenant(data_root, A_ID).runs_repository()
    with runs.episode(scene.episode_id) as view:
        written = _texts(view.start_runs(world_ids))
    assert set(written) == set(world_ids)
    assert S.read_roster(scene.ep) == written
    assert (scene.ep / S.ROSTER_NAME).stat().st_size < 1024
    assert label.encode() not in (scene.ep / S.ROSTER_NAME).read_bytes()
    with runs.episode(scene.episode_id) as view:
        assert _texts(view.arm_ids()) == written
        assert str(view.arm_id(world_ids[1])) == written[world_ids[1]]
    natural_before = S.tree(S.natural_runs(data_root, A_ID))
    rec = P.SiblingRecorder()
    rc, refused, err = P.drive_run_py(P.new_sibling_argv(A_ID, scene.episode_id, label), rec)
    assert refused is None, f"{P.refusal_text(refused)} {err}"
    assert rc == 0, err
    assert rec.run_dir == scene.ep / "runs" / written[world_ids[1]]
    assert S.tree(S.natural_runs(data_root, A_ID)) == natural_before


@pytest.mark.parametrize("fault", ["label-key", "foreign-uuid", "missing-world",
                                  "duplicate-arm", "duplicate-world"])
def test_uuid_roster_requires_the_complete_manifest_binding(data_root, fault):
    runs = S.tenant(data_root, A_ID).runs_repository()
    episode_id, ep = _episode(data_root, A_ID)
    world_ids = [world["world_id"] for world in _yaml.safe_load(
        (ep / S.MANIFEST_NAME).read_text())["worlds"]]
    good = {world_id: S.new_id() for world_id in world_ids}
    broken = dict(good)
    if fault in ("label-key", "foreign-uuid"):
        broken["b" if fault == "label-key" else S.new_id()] = broken.pop(world_ids[1])
    elif fault == "missing-world":
        del broken[world_ids[1]]
    elif fault == "duplicate-arm":
        broken[world_ids[1]] = broken[world_ids[0]]
    if fault == "duplicate-world":
        S.write_roster(ep, raw=_ids_json([*good.items(), (world_ids[1], S.new_id())]))
    else:
        S.write_roster(ep, broken)
    before = S.tree(ep)
    with runs.episode(episode_id) as view:
        assert _is_refusal(S.raised(view.arm_ids)), fault
        assert _is_refusal(S.raised(view.arm_id, world_ids[1])), fault
    assert S.tree(ep) == before, "reading a bad roster changed the episode"
    S.write_roster(ep, good)
    with runs.episode(episode_id) as view:
        assert _texts(view.arm_ids()) == good
        assert str(view.arm_id(world_ids[1])) == good[world_ids[1]]


@pytest.mark.parametrize("count", [799, 800])
def test_start_runs_only_publishes_a_roster_the_reader_can_reopen(data_root, count):
    runs = S.tenant(data_root, A_ID).runs_repository()
    doc = T.family_doc(worlds=[T.base_world(), *[
        T.world_doc(f"w{index}", role=None, facts=[]) for index in range(count - 1)]])
    episode_id = S.new_id()
    doc["episode_id"] = episode_id
    ep = S.make_episode(data_root, A_ID, episode_id, manifest=_yaml.safe_dump(doc), roster=False)
    before = S.tree(ep)
    world_ids = [world["world_id"] for world in doc["worlds"]]
    with runs.episode(episode_id) as view:
        if count == 800:
            refused = S.raised(view.start_runs, world_ids)
            assert isinstance(refused, RunRefused), refused
            assert "roster" in str(refused).lower(), refused
            assert S.tree(ep) == before
            assert not (ep / "runs").exists()
            assert not (ep / S.ROSTER_NAME).exists()
        else:
            written = _texts(view.start_runs(world_ids))
            assert (ep / S.ROSTER_NAME).stat().st_size == 65_521
            assert _texts(view.arm_ids()) == written
            assert set(written) == set(world_ids)


def test_a_second_start_runs_refuses_and_leaves_the_roster_byte_identical(data_root):
    t = S.tenant(data_root, A_ID)
    runs = t.runs_repository()
    episode_id, ep = _episode(data_root, A_ID)

    with runs.episode(episode_id) as view:
        view.start_runs(list(WORLD_IDS))
        roster_bytes = (ep / S.ROSTER_NAME).read_bytes()
        again = S.raised(view.start_runs, list(WORLD_IDS))
        assert _is_refusal(again), f"a second start_runs on the same view gave {again!r}"
    with runs.episode(episode_id) as view:
        fresh = S.raised(view.start_runs, list(WORLD_IDS))
        assert _is_refusal(fresh), f"a second start_runs on a fresh view gave {fresh!r}"
    assert (ep / S.ROSTER_NAME).read_bytes() == roster_bytes, "the roster was rewritten"
    assert os.listdir(ep / "runs") == []

    planted_id, planted = _episode(data_root, A_ID, roster={k: S.new_id() for k in WORLD_IDS})
    planted_bytes = (planted / S.ROSTER_NAME).read_bytes()
    with runs.episode(planted_id) as view:
        err = S.raised(view.start_runs, list(WORLD_IDS))
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
from defender.tenancy._tenant import TenantRefused
from defender.run_repository import RunRefused
from defender.tests.storage.ids_1187 import _spec1187 as S
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.storage.tenant_1105_run_repository import _spec1105_pr2 as P
from defender.run_repository import RunId, RunRefused
from defender.tenancy._tenant import TenantRefused
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
        view.start_runs([T.fixture_world_id(label) for label in ("a", "b", "c")])
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

    from defender.tests.storage.tenant_1105_run_repository import _spec1105 as H5

    env = {**os.environ, "PYTHONPATH": os.pathsep.join(
        filter(None, [str(H5.WORKTREE), os.environ.get("PYTHONPATH")])),
        "PYTHONDONTWRITEBYTECODE": "1", S.DATA_ROOT_ENV: str(data_root)}
    return subprocess.run(  # noqa: S603 — this interpreter, a fixed script
        [sys.executable, "-c", _START_RUNS_CHILD, str(data_root), A_ID, episode_id, str(limit),
         "unavailable" if unavailable else "supported"],
        capture_output=True, text=True, encoding="utf-8", check=False, env=env,
        cwd=str(H5.WORKTREE), timeout=300)


@pytest.mark.parametrize("failure", ["killed-mid-write", "atomic-lane-unavailable"])
def test_a_failed_atomic_roster_write_leaves_no_named_fallback(data_root, failure):
    import errno
    import signal

    runs = S.tenant(data_root, A_ID).runs_repository()
    episode_id, ep = _episode(data_root, A_ID)
    killed = failure == "killed-mid-write"
    if killed:
        try:
            fd = os.open(ep, os.O_TMPFILE | os.O_WRONLY, 0o600)
        except OSError as err:
            if err.errno not in (errno.EOPNOTSUPP, errno.EISDIR, errno.EINVAL):
                raise
            pytest.skip(f"no O_TMPFILE on the episode's filesystem: {err}")
        os.close(fd)
    failed = _start_runs_in_a_child(data_root, episode_id,
                                    limit=_WRITE_LIMIT if killed else 0, unavailable=not killed)
    assert failed.returncode == (-signal.SIGXFSZ if killed else 0), failed.stderr[-1500:]
    if not killed:
        assert "ATOMIC_UNAVAILABLE" in failed.stdout.splitlines(), failed.stdout
        assert "REFUSED" in failed.stdout.splitlines(), failed.stdout
    assert not os.path.lexists(ep / S.ROSTER_NAME), "a failed write left a named roster"
    assert sorted(set(os.listdir(ep)) - {S.MANIFEST_NAME, "runs"}) == []
    with runs.episode(episode_id) as view:
        assert view.arm_ids() is None, "a failed write reads as a roster"
    gate = S.raised(_open_and_close, runs, episode_id, require_roster=True)
    assert isinstance(gate, TenantRefused), gate

    # A killed writer is compared with a fresh episode; an unsupported lane must retry in place.
    control_id, control = _episode(data_root, A_ID) if killed else (episode_id, ep)
    done = _start_runs_in_a_child(data_root, control_id, limit=0)
    assert done.returncode == 0, done.stderr[-1500:]
    assert "STARTED" in done.stdout.splitlines(), done.stdout
    assert sorted(S.read_roster(control)) == sorted(WORLD_IDS)


@pytest.mark.parametrize("occupant", ["link-to-another-tenants-arms", "regular-file"])
def test_a_link_or_a_file_at_runs_refuses_before_any_roster_is_written(
        tmp_path, data_root, occupant):
    t = S.tenant(data_root, A_ID)
    S.tenant(data_root, B_ID)
    _b_id, b_ep = _episode(data_root, B_ID, roster={k: S.new_id() for k in WORLD_IDS}, arms=True)
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
            err = S.raised(view.start_runs, list(WORLD_IDS))
        assert _is_refusal(err), f"start_runs over a {occupant} at runs/ gave {err!r}"
    assert not os.path.lexists(ep / S.ROSTER_NAME), "a roster was written past a bad runs/"
    assert S.tree(ep) == occupant_before, "the episode folder changed"
    assert S.tree(S.tenant_dir(data_root, B_ID)) == b_before, "the other tenant's tree changed"

    os.unlink(ep / "runs")
    with runs.episode(episode_id) as view:
        view.start_runs(list(WORLD_IDS))
    assert sorted(S.read_roster(ep)) == sorted(WORLD_IDS)
    assert _real_dir(ep / "runs")
# Reading the roster: `arm_id`, `arm_ids`, and `create` held to it (R2; O4).

def test_the_arm_ids_are_the_rosters_and_an_unknown_label_is_absent(data_root):
    from defender.run_repository import RunAbsent

    t = S.tenant(data_root, A_ID)
    runs = t.runs_repository()
    bare_id, _bare = _episode(data_root, A_ID)
    with runs.episode(bare_id) as view:
        assert view.arm_ids() is None
        assert _is_refusal(S.raised(view.arm_id, WORLD_ID)), "an arm id was named with no roster"

    gap_id, gap = _episode(data_root, A_ID, arms=True)
    assert _real_dir(gap / "runs")
    assert not os.path.lexists(gap / S.ROSTER_NAME)
    with runs.episode(gap_id) as view:
        assert view.arm_ids() is None, "runs/ with no roster answered arm ids"
        assert _is_refusal(S.raised(view.arm_id, WORLD_ID)), "an arm id was named with no roster"
        made = S.raised(view.create, RunId.parse(S.new_id()))
        assert _is_refusal(made), f"an arm was created in the crash window: {made!r}"
    assert os.listdir(gap / "runs") == [], "a refused create made something in runs/"

    roster = {label: S.new_id() for label in WORLD_IDS}
    episode_id, _ep = _episode(data_root, A_ID, roster=roster)
    with runs.episode(episode_id) as view:
        assert _texts(view.arm_ids()) == roster
        for label in WORLD_IDS:
            arm = view.arm_id(label)
            assert str(arm) == roster[label]
            assert str(arm) != f"{episode_id}-{label}"
        unknown = S.raised(view.arm_id, "z")
        assert isinstance(unknown, RunAbsent), f"arm_id('z') gave {unknown!r}"


def test_an_arm_is_created_only_at_an_id_the_roster_holds(data_root):
    t = S.tenant(data_root, A_ID)
    runs = t.runs_repository()
    episode_id, ep = _episode(data_root, A_ID)

    with runs.episode(episode_id) as view:
        early = S.raised(view.create, RunId.parse(S.new_id()))
        assert _is_refusal(early), f"an arm was created before RUNS: {early!r}"
        ids = _texts(view.start_runs(list(WORLD_IDS)))
        stranger = S.raised(view.create, RunId.parse(S.new_id()))
        assert _is_refusal(stranger), f"an id outside the roster was created: {stranger!r}"
        assert os.listdir(ep / "runs") == [], "a refused create made something"
        arm = view.create(RunId.parse(ids[WORLD_ID]))
    assert Path(arm.run_dir) == ep / "runs" / ids[WORLD_ID]
    assert S.is_canonical_uuid(Path(arm.run_dir).name)
    assert episode_id not in Path(arm.run_dir).name


#: Reject malformed roster contents, invalid identities, aliasing, and hostile input sizes.
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
    """Report control characters or excess length in a refusal message."""
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
    """Fingerprint tree entries without following links, including file size and content digest."""
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
    deep = "[" * DEEP + json.dumps(good[T.fixture_world_id("a")]) + "]" * DEEP
    rest = "".join(f", {json.dumps(k)}: {json.dumps(v)}" for k, v in good.items() if k != "a")
    return '{"a": ' + deep + rest + "}\n"


#: Each text-planted fault: `(good roster, its text) -> the faulty roster's text or bytes`.
ROSTER_TEXTS = {
    "torn": lambda good, text: S.torn(text),
    "not-an-object": lambda good, text: json.dumps(list(WORLD_IDS)) + "\n",
    "duplicate-ids": lambda good, text: _ids_json(list({**good, T.fixture_world_id("b"): good[T.fixture_world_id("a")]}.items())),
    "missing-label": lambda good, text: _ids_json([(k, v) for k, v in good.items() if k != T.fixture_world_id("c")]),
    "extra-label": lambda good, text: _ids_json([*good.items(), (S.new_id(), S.new_id())]),
    "non-uuid-id": lambda good, text: _ids_json(list({**good, T.fixture_world_id("a"): S.OLD_MINTED_ID}.items())),
    "uppercase-uuid": lambda good, text: _ids_json(
        list({**good, T.fixture_world_id("a"): S.SAMPLE_UUID.upper()}.items())),
    "deep-nesting": _deep_text,
    # The good roster behind a UTF-8 byte-order mark: not strict UTF-8 JSON, which the host
    # never writes (a `utf-8-sig` or a bytes-sniffing decode would accept it).
    "bom": lambda good, text: b"\xef\xbb\xbf" + text.encode("utf-8"),
    # `a` twice: a last-wins decode yields a consistent roster ({a, b, c}, distinct UUIDs), so
    # only a reader that refuses a repeated key refuses it.
    "duplicate-key": lambda good, text: _ids_json([*good.items(), (T.fixture_world_id("a"), S.new_id())]),
    # A label off the label rule (so off the manifest's worlds too) that is hostile text: what
    # this pins is that the refusal quoting it stays one bounded line.
    "label-off-rule": lambda good, text: _ids_json(
        [(k, v) for k, v in good.items() if k != T.fixture_world_id("a")] + [(HOSTILE_LABEL, good[T.fixture_world_id("a")])]),
    "int-id": lambda good, text: _ids_json(list({**good, T.fixture_world_id("a"): 5}.items())),
    "list-id": lambda good, text: _ids_json(list({**good, T.fixture_world_id("a"): [good[T.fixture_world_id("a")]]}.items())),
    # `a`'s entry under the key `"\ud800"` (a JSON escape, so the file itself is plain ASCII):
    # decoded, a lone surrogate no UTF-8 encoder takes (adversary F12) — off the label rule and
    # off the manifest's worlds; what this pins is that the reader refuses rather than raising
    # while it measures or quotes the label.
    "lone-surrogate-label": lambda good, text: _ids_json(
        [("\ud800", good[T.fixture_world_id("a")])] + [(k, v) for k, v in good.items() if k != T.fixture_world_id("a")]),
}


def _write_oversize(ep: Path, text: str) -> None:
    """Pad a valid roster one byte beyond the bounded reader limit."""
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
    t = S.tenant(data_root, A_ID)
    runs = t.runs_repository()
    good = {label: S.new_id() for label in WORLD_IDS}
    episode_id, ep = _episode(data_root, A_ID, roster=good)
    good_text = (ep / S.ROSTER_NAME).read_text(encoding="utf-8")
    try:
        _plant_roster_fault(fault, ep, good, tmp_path)
        before = _fingerprint(ep)

        with runs.episode(episode_id) as view:
            whole = S.raised(view.arm_ids)
            assert _is_refusal(whole), f"arm_ids() over a {fault} roster gave {whole!r}"
            one = S.raised(view.arm_id, T.fixture_world_id("a"))
            assert _is_refusal(one), f"arm_id('a') over a {fault} roster gave {one!r}"
        for what, err in (("arm_ids()", whole), ("arm_id('a')", one)):
            assert _unbounded(S.message(err)) == [], (
                f"{what}'s refusal over a {fault} roster is not one bounded line: "
                f"{_unbounded(S.message(err))}")
        gate = S.raised(_open_and_close, runs, episode_id, require_roster=True)
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
        assert str(view.arm_id(T.fixture_world_id("a"))) == good[T.fixture_world_id("a")]


def _open_and_close(runs, episode_id: str, *, world_id=None, **kwargs) -> None:
    """Open `runs.episode(episode_id, **kwargs)` and close it again (a refusal propagates)."""
    with runs.episode(episode_id, **kwargs) as view:
        if world_id is not None:
            view.arm_id(world_id)


def test_a_refusal_quoting_a_callers_label_stays_one_bounded_line(data_root):
    from defender.run_repository import RunAbsent

    t = S.tenant(data_root, A_ID)
    runs = t.runs_repository()
    good = {label: S.new_id() for label in WORLD_IDS}
    episode_id, _ep = _episode(data_root, A_ID, roster=good)

    for hostile in (HOSTILE_LABEL, *SURROGATE_LABELS):
        shown = ascii(hostile[:24])
        with runs.episode(episode_id) as view:
            absent = S.raised(view.arm_id, hostile)
            assert isinstance(absent, RunAbsent), f"arm_id({shown}) gave {absent!r}"
            assert str(view.arm_id(T.fixture_world_id("a"))) == good[T.fixture_world_id("a")]
        assert _unbounded(S.message(absent)) == [], (
            f"arm_id's refusal quoting the caller's label {shown}: "
            f"{_unbounded(S.message(absent))}")

        gate = S.raised(_open_and_close, runs, episode_id, world_id=hostile, require_roster=True)
        assert _is_refusal(gate), f"the gate for the unnamed label {shown} gave {gate!r}"
        assert _unbounded(S.message(gate)) == [], (
            f"the gate's refusal quoting the caller's label {shown}: "
            f"{_unbounded(S.message(gate))}")
    with runs.episode(episode_id, require_roster=True) as view:
        assert str(view.arm_id(T.fixture_world_id("a"))) == good[T.fixture_world_id("a")]


@pytest.mark.parametrize("roster_state",
                         ["absent", "runs-without-roster", "invalid-world-key", "torn"])
def test_the_sibling_form_of_the_view_refuses_unless_the_roster_names_the_label(
        data_root, roster_state):
    from defender.tenancy._tenant import TenantRefused

    t = S.tenant(data_root, A_ID)
    runs = t.runs_repository()
    episode_id, ep = _episode(data_root, A_ID)
    doc = T.family_doc(episode_id=episode_id, source_run_id=S.new_id())
    T.write_family(ep, {**doc, SENTINEL: "read"})
    roster = {label: S.new_id() for label in WORLD_IDS}
    if roster_state != "absent":
        (ep / "runs").mkdir()
    if roster_state == "invalid-world-key":
        S.write_roster(ep, {**roster, "b": roster[WORLD_ID]})
    elif roster_state in ("torn", "invalid-world-key"):
        S.write_roster(ep, raw=S.torn(json.dumps(roster, indent=2)))
    before = S.tree(ep)

    with S.FileReads(ep / S.MANIFEST_NAME) as watch:
        err = S.raised(runs.episode, episode_id, require_roster=True)
        seen = watch.events()
    if roster_state in ("torn", "invalid-world-key"):
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
        with runs.episode(episode_id, require_roster=True) as view:
            assert str(view.arm_id(WORLD_ID)) == roster[WORLD_ID]
        assert watch.reads() > 0, (
            "control: the channel saw no read of the manifest where `arm_id` checks the roster "
            "against the manifest's worlds")
# The sibling gate through the real `run.py` (O4b; G5/G19; O8; O3).

class _Scene:
    """Create an accepted tenant, branchable source run, and post-questioner episode."""

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
    rec = P.SiblingRecorder()
    rc, refused, err = P.drive_run_py(P.new_sibling_argv(tenant_id, episode_id, LABEL), rec)
    return rc, refused, f"{P.refusal_text(refused)}\n{err}", rec


SIBLING_CASES = ("pre-runs", "runs-without-roster", "invalid-world-key", "torn-roster",
                 "another-tenants-episode", "linked-episode")


@pytest.mark.parametrize("case", SIBLING_CASES)
def test_the_sibling_is_refused_before_the_manifest_unless_its_roster_names_it(
        tmp_path, data_root, case):
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
    elif case == "invalid-world-key":
        scene.start_runs_by_hand({**scene.roster, "b": scene.roster[WORLD_ID]})
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
    _run_control(scene, case)


def test_a_child_refuses_a_missing_world_uuid_after_resolving_its_label(tmp_path, data_root):
    scene = _Scene(tmp_path, data_root, B_ID)
    scene.start_runs_by_hand({wid: arm for wid, arm in scene.roster.items() if wid != WORLD_ID})
    before = S.tree(data_root)
    with S.FileReads(scene.ep / S.MANIFEST_NAME) as watch:
        rc, refused, said, rec = _sibling(B_ID, scene.episode_id)
        assert watch.reads() > 0, "world binding was not read through the manifest"
    assert refused is not None, said
    assert rc is None, said
    assert rec.order == [], "a missing world binding spent before refusing"
    assert S.tree(data_root) == before, "a refused child changed the host tree"
    S.write_roster(scene.ep, scene.roster)
    _run_control(scene, "repaired missing world UUID")


def _run_control(scene: _Scene, case: str):
    """Exercise the real sibling with its valid manifest, checking arm placement and isolation."""
    natural = S.natural_runs(scene.root, scene.owner)
    before = sorted(os.listdir(natural))
    ok = P.SiblingRecorder()
    rc, refused, err = P.drive_run_py(P.new_sibling_argv(scene.owner, scene.episode_id, LABEL), ok)
    assert refused is None, f"{case}: {P.refusal_text(refused)} {err}"
    assert rc == 0, f"{case}: {rc}: {err}"
    assert ok.run_dir == scene.ep / "runs" / scene.roster[WORLD_ID], ok.run_dir
    assert S.is_canonical_uuid(Path(ok.run_dir).name), ok.run_dir
    assert scene.episode_id not in Path(ok.run_dir).name
    assert sorted(os.listdir(natural)) == before, "an arm or sidecar landed in natural runs"
    return ok


@pytest.mark.parametrize("case", ["mismatched-manifest", "settings-in-arms", "old-episode-id"])
def test_the_sibling_refuses_invalid_identity_or_settings_before_spend(tmp_path, data_root, case):
    scene = _Scene(tmp_path, data_root, B_ID)
    scene.start_runs_by_hand()
    requested = scene.episode_id
    if case == "mismatched-manifest":
        other = S.near_miss_id(scene.episode_id)
        T.write_family(scene.ep, {**scene.doc, "episode_id": other})
    elif case == "settings-in-arms":
        (scene.ep / "runs").rmdir()
        os.symlink(S.tenant_dir(data_root, B_ID) / "knowledge", scene.ep / "runs",
                   target_is_directory=True)
        scene.poison()
    else:
        requested = S.OLD_MINTED_ID
        scene.ep.rename(scene.ep.parent / requested)
        T.write_family(scene.ep.parent / requested,
                       {**scene.doc, "episode_id": requested, SENTINEL: "read"})
    before = S.tree(data_root)
    rc, refused, said, rec = _sibling(B_ID, requested)
    assert refused is not None, f"{case}: the sibling ran: {rc}"
    assert rc is None, rc
    assert rec.order == [], f"{case}: spent before refusal: {rec.order}"
    assert S.tree(data_root) == before, f"{case}: refused sibling wrote under the data root"
    text = P.refusal_text(refused)
    if case == "mismatched-manifest":
        assert other in text, text
        assert scene.episode_id in text, text
        assert os.listdir(scene.ep / "runs") == []
    else:
        assert SENTINEL not in said, "the manifest was read before admission refused"
        assert S.EPISODES_BASE_ENV not in said
        if case == "settings-in-arms":
            assert "settings" in text, text
            assert "a box mounts" in text, text
            os.unlink(scene.ep / "runs")
            (scene.ep / "runs").mkdir()
        else:
            assert requested in text, text
            (scene.ep.parent / requested).rename(scene.ep)
    scene.restore()
    _run_control(scene, case)


def test_the_sibling_needs_no_episodes_variable_and_ignores_a_decoy(tmp_path, data_root,
                                                                     monkeypatch):
    scene = _Scene(tmp_path, data_root, B_ID)
    scene.start_runs_by_hand()
    decoy_root = tmp_path / "decoy-episodes"
    shutil.copytree(scene.ep, decoy_root / scene.episode_id, symlinks=True)
    S.write_roster(decoy_root / scene.episode_id, {k: S.new_id() for k in scene.roster})
    decoy_before = S.tree(decoy_root)
    monkeypatch.setenv(S.EPISODES_BASE_ENV, str(decoy_root))

    _run_control(scene, "decoy-variable")
    assert S.tree(decoy_root) == decoy_before, "the decoy episode was touched"


def test_natural_and_arm_stamps_carry_no_world_lineage(
        tmp_path, data_root):
    from defender import run_common
    from defender.tests.storage.tenant_1105_run_repository import _spec1105 as H5

    scene = _Scene(tmp_path, data_root, B_ID)
    t = S.tenant(data_root, B_ID)
    natural = run_common.materialize_run(H5.alert_file(tmp_path / "in"), tenant=t)
    natural_stamp = json.loads(
        (Path(natural.run_dir) / "provenance.json").read_text(encoding="utf-8"))
    assert natural_stamp.get("world_id") is None, (
        f"a natural run stamps no world id; it says {natural_stamp.get('world_id')!r}")

    scene.start_runs_by_hand()
    ok = _run_control(scene, "arm-provenance")
    arm_stamp = json.loads((ok.run_dir / "provenance.json").read_text(encoding="utf-8"))
    # #1255 keeps natural and arm provenance alike; #1187 R1b removes the container's lineage.
    assert arm_stamp.get("world_id") is None, arm_stamp
    for stamp in (natural_stamp, arm_stamp):
        assert stamp.get("parent_run_id") is None, stamp
        assert stamp.get("fork_turn") is None, stamp


def test_1279_o5_an_arm_announces_its_rosters_id_first_on_stdout(tmp_path, data_root):
    """O5: an arm's `run_id=` line carries the id its roster published, before the box."""
    scene = _Scene(tmp_path, data_root, B_ID)
    scene.start_runs_by_hand()
    rec = P.SiblingRecorder()

    ran = P.drive_run_py_stdout(P.new_sibling_argv(B_ID, scene.episode_id, LABEL), rec)

    assert ran.refusal is None, (P.refusal_text(ran.refusal), ran.err)
    assert ran.rc == 0, (ran.rc, ran.err)
    line = f"run_id={scene.roster[WORLD_ID]}\n"
    assert ran.out.splitlines(keepends=True)[:1] == [line], ran.out
    assert ran.seen["preflight"] == "", f"stdout before setup: {ran.seen['preflight']!r}"
    assert ran.seen["lifecycle"] == line, ran.seen["lifecycle"]
    assert Path(rec.run_dir) == scene.ep / "runs" / scene.roster[WORLD_ID]


def _assert_one_line_exit(refusal: BaseException | None) -> None:
    """A `sys.exit(str)` refusal: one stderr line, no traceback (as test_1105_run_setup's
    `_one_line_exit`, which the odd-occupant refusals asserted before they moved here)."""
    assert isinstance(refusal, SystemExit), refusal
    assert isinstance(refusal.code, str), refusal
    assert len(refusal.code.splitlines()) == 1, f"the refusal is not one line: {refusal.code!r}"


def _occupy(kind: str, existing: Path, outside: Path) -> None:
    """Put what a prior setup, a prior run or an attacker could have left at the arm's id."""
    if kind == "setup-only":
        (existing / "gather_raw").mkdir(parents=True)
    elif kind == "empty-dir":
        existing.mkdir()
    elif kind == "ran":
        (existing / "gather_raw").mkdir(parents=True)
        (existing / "report.md").write_text("a run was here\n", encoding="utf-8")
    elif kind == "regular-file":
        existing.write_text("not a run dir\n", encoding="utf-8")
    else:
        outside.mkdir()
        existing.symlink_to(outside, target_is_directory=True)


@pytest.mark.parametrize("kind", ["setup-only", "empty-dir", "ran", "regular-file",
                                  "link-to-a-dir"])
def test_1279_o8_setup_refuses_an_existing_run_dir_at_the_arms_id_and_resumes_nothing(
        tmp_path, data_root, kind):
    """O8: anything already at the roster's arm id is refused, not resumed or followed."""
    scene = _Scene(tmp_path, data_root, B_ID)
    scene.start_runs_by_hand()
    existing = scene.ep / "runs" / scene.roster[WORLD_ID]
    outside = tmp_path / "outside"
    _occupy(kind, existing, outside)
    before = S.tree(scene.ep / "runs")
    outside_before = S.tree(outside) if outside.exists() else None

    ran = P.drive_run_py_stdout(P.new_sibling_argv(B_ID, scene.episode_id, LABEL),
                                rec := P.SiblingRecorder())

    said = f"{P.refusal_text(ran.refusal)}\n{ran.err}"
    assert ran.refusal is not None, f"setup went on over a {kind}: rc {ran.rc} {rec.order}"
    assert scene.roster[WORLD_ID] in said, f"the refusal does not name the arm: {said!r}"
    _assert_one_line_exit(ran.refusal)
    assert "lifecycle" not in rec.order, rec.order
    assert ran.out == "", f"a refused setup announced an id: {ran.out!r}"
    assert S.tree(scene.ep / "runs") == before, "the refused setup changed the runs folder"
    if outside_before is not None:
        assert S.tree(outside) == outside_before, "the refused setup wrote through the link"
        assert existing.is_symlink()


#: Every reserved sidecar suffix, spelled out: the sidecar tests run over THIS list, and the
#: coverage test below pins it to the layout's, so a suffix added there cannot be missed silently.
ALL_SIDECAR_SUFFIXES = (".run-end.json", ".scrub-verdict.json", ".accounting_failures.json",
                        ".ticket-write.json", ".session-pointer.json", ".call-join.jsonl",
                        ".ticket-comments.jsonl")


def test_1279_o8_the_sidecar_tests_cover_every_reserved_suffix():
    """O8: the suffixes the sidecar tests run over are exactly the layout's reserved ones."""
    from defender.run_repository._layout import _SIDECAR_SUFFIXES

    assert sorted(ALL_SIDECAR_SUFFIXES) == sorted(_SIDECAR_SUFFIXES), (
        "the layout reserves a different set of sidecar suffixes: update ALL_SIDECAR_SUFFIXES")


@pytest.mark.parametrize("suffix", ALL_SIDECAR_SUFFIXES)
def test_1279_o8_setup_refuses_a_sidecar_at_the_arms_id_before_making_the_dir(
        tmp_path, data_root, suffix):
    """O8: a sidecar beside the arm's id (a prior run's trace) is refused; nothing is cleared."""
    scene = _Scene(tmp_path, data_root, B_ID)
    scene.start_runs_by_hand()
    arm = scene.roster[WORLD_ID]
    sidecar = scene.ep / "runs" / f"{arm}{suffix}"
    sidecar.write_text("{}\n", encoding="utf-8")
    # Other ids' sidecars, every suffix, sit in the same base: the refusal is for THIS id's
    # sidecar, not for any sidecar (a glob would refuse the control below too).
    for neighbour in (S.new_id(), S.new_id()):
        for other in ALL_SIDECAR_SUFFIXES:
            (scene.ep / "runs" / f"{neighbour}{other}").write_text("{}\n", encoding="utf-8")
    before = S.tree(scene.ep / "runs")

    ran = P.drive_run_py_stdout(P.new_sibling_argv(B_ID, scene.episode_id, LABEL),
                                rec := P.SiblingRecorder())

    said = f"{P.refusal_text(ran.refusal)}\n{ran.err}"
    assert ran.refusal is not None, f"setup went on past a {suffix} sidecar: rc {ran.rc}"
    assert arm in said, f"the refusal does not name the arm: {said!r}"
    _assert_one_line_exit(ran.refusal)
    assert "lifecycle" not in rec.order, rec.order
    assert ran.out == "", f"a refused setup announced an id: {ran.out!r}"
    assert not os.path.lexists(scene.ep / "runs" / arm), "the run dir was made past a sidecar"
    assert S.tree(scene.ep / "runs") == before, "the refused setup changed the runs folder"

    sidecar.unlink()
    ok = _run_control(scene, f"sidecar-{suffix}")
    assert ok.run_dir.name == arm


@pytest.mark.parametrize("suffix", [ALL_SIDECAR_SUFFIXES[0], ALL_SIDECAR_SUFFIXES[-1]])
@pytest.mark.parametrize("kind", ["directory", "dangling-link", "link-to-file", "link-to-dir"])
def test_1279_o8_setup_refuses_any_entry_at_an_arms_sidecar_name_links_and_dirs_included(
        tmp_path, data_root, kind, suffix):
    """O8: a link (dangling or not) or a dir at the arm's sidecar name is refused, as a file is."""
    from defender.tests.support.storage import _setup_faults_1279 as F

    scene = _Scene(tmp_path, data_root, B_ID)
    scene.start_runs_by_hand()
    arm = scene.roster[WORLD_ID]
    runs = scene.ep / "runs"
    F.plant_entry(kind, runs / f"{arm}{suffix}", tmp_path / "elsewhere")
    before = sorted(os.listdir(runs))

    ran = P.drive_run_py_stdout(P.new_sibling_argv(B_ID, scene.episode_id, LABEL),
                                rec := P.SiblingRecorder())

    said = f"{P.refusal_text(ran.refusal)}\n{ran.err}"
    assert ran.refusal is not None, f"setup went on past a {kind} at the {suffix} name: rc {ran.rc}"
    assert f"{arm}{suffix}" in said, f"the refusal does not name the sidecar: {said!r}"
    assert "lifecycle" not in rec.order, rec.order
    assert not os.path.lexists(runs / arm), "the run dir was made past a sidecar"
    assert sorted(os.listdir(runs)) == before, "the refused setup changed the runs folder"
    assert os.path.islink(runs / f"{arm}{suffix}") == (kind != "directory")

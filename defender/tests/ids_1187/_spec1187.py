"""Shared machinery for #1187's tests-before-code commit. NO test functions.

#1187 (design rev 2, issue comments 6192137519 and 6192137980) makes every run, arm and
episode id a random UUID and moves every tenant's episodes under its own folder:

    <data root>/<T>/runs/<run uuid>/                      natural runs (+ sidecars)
    <data root>/<T>/episodes/<ep uuid>/                   an episode (family.yaml, ...)
    <data root>/<T>/episodes/<ep uuid>/arms.json          the host-written arm roster
    <data root>/<T>/episodes/<ep uuid>/runs/<arm uuid>/   its arms

No `_tenant.json` anywhere, no `DEFENDER_EPISODES_BASE`, no `<ep>-<label>` id.

The builders here are PURE FILESYSTEM: they import nothing from production, so they collect and
run before any of #1187 exists. They plant the on-disk states the design names, including the
faults (a torn or mismatched roster, a link at any level, old-id entries), so each test file
asserts what the production entry point does with them. Tenants themselves are set up and
accepted through the real `_spec1105.tenant` (today's `create_tenant` / `accept_tenant`).

Underscore-prefixed so pytest does not collect it. Owned by the orchestrator (and the repair
author it hands it to); slice authors ask for changes rather than edit it.
"""
from __future__ import annotations

import json
import os
import uuid
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from defender.tests.tenant_1105_run_repository import _spec1105 as H5

#: The arm roster's file name in the episode folder (pinned by the contract; the production
#: owner is `defender._episode_paths.ARM_ROSTER_NAME`).
ROSTER_NAME = "arms.json"
#: The manifest's file name (`_episode_paths.FAMILY_NAME` today, unchanged).
MANIFEST_NAME = "family.yaml"
#: The one-time command, as every refusal that sends the operator to it must spell it.
COMMAND = "defender/ops/retire_legacy_runs.py"
COMMAND_MODULE = "defender.ops.retire_legacy_runs"
RUNS_LEGACY = "runs-legacy"
EPISODES_LEGACY = "episodes-legacy"
DATA_ROOT_ENV = "DEFENDER_DATA_ROOT"
EPISODES_BASE_ENV = "DEFENDER_EPISODES_BASE"

#: Ids the design names as off the new grammar (O2's observable list), plus near misses.
OLD_MINTED_ID = "20260101t000000z-x"
OLD_PINNED_ID = "live-lever-up-20260930-sudo"
SAMPLE_UUID = "af3ba774-355d-4dbc-b8b6-3becc9d3e7a1"
NON_CANONICAL_IDS = (
    OLD_MINTED_ID,
    OLD_PINNED_ID,
    SAMPLE_UUID.upper(),
    "{" + SAMPLE_UUID + "}",
    SAMPLE_UUID.replace("-", ""),
    "urn:uuid:" + SAMPLE_UUID,
    SAMPLE_UUID + "-a",
    " " + SAMPLE_UUID,
    SAMPLE_UUID + "\n",
    "latest",
    "",
    "..",
)

#: The known sidecar suffixes beside a run folder (`_layout._SIDECAR_SUFFIXES`, via #1105).
SIDECAR_SUFFIXES = H5.SIDECAR_SUFFIXES


def new_id() -> str:
    """A fresh canonical lowercase uuid4, as the test's own fixture id (never production's)."""
    return str(uuid.uuid4())


#: How many hex digits canonical UUID text carries (the `near_miss_id` positions).
UUID_HEX_DIGITS = 32


def near_miss_id(text: str, digit: int = -1) -> str:
    """`text` (canonical UUID text) with ONE hex digit changed — its `digit`-th hex digit,
    hyphens not counted (the last by default) — so the result is canonical UUID text too and
    shares every other character. A mismatch only a whole-id comparison sees: a reader that
    compares a prefix, one group or a suffix of two ids passes it whenever the changed digit is
    one it skips (adversary F11)."""
    chars = list(text)
    at = [i for i, c in enumerate(chars) if c != "-"][digit]
    chars[at] = "0" if chars[at] != "0" else "1"
    out = "".join(chars)
    if not is_canonical_uuid(out) or out == text:  # pragma: no cover — 32 hex digits round-trip
        raise ValueError(f"{out!r} is not a canonical near miss of {text!r}")
    return out


def is_canonical_uuid(text: object) -> bool:
    """Is `text` canonical lowercase UUID text? The test-side oracle, written from the
    design's rule (O2), not from production's."""
    if not isinstance(text, str):
        return False
    try:
        return str(uuid.UUID(text)) == text
    except ValueError:
        return False


# ------------------------------------------------------------------------------------------
# Tenants and folders
# ------------------------------------------------------------------------------------------

def tenant(data_root: Path, tenant_id: str = H5.T_ID) -> Any:
    """`tenant_id` set up under `data_root` and accepted by the real `accept_tenant`."""
    return H5.tenant(Path(data_root), tenant_id)


def tenant_dir(data_root: Path, tenant_id: str) -> Path:
    return Path(data_root) / tenant_id


def natural_runs(data_root: Path, tenant_id: str) -> Path:
    return tenant_dir(data_root, tenant_id) / "runs"


def episodes_dir(data_root: Path, tenant_id: str) -> Path:
    return tenant_dir(data_root, tenant_id) / "episodes"


def make_run(container: Path, run_id: str | None = None, *,
             alert: str = '{"alert": "seed"}\n', sidecars: bool = False) -> Path:
    """A real run folder `<container>/<run_id>` holding an `alert.json` (and, with
    `sidecars`, the known sidecar files beside it). Makes `container`. Plants no record."""
    run_id = new_id() if run_id is None else run_id  # lint-default: ok — a fresh random id per call cannot be a signature default
    Path(container).mkdir(parents=True, exist_ok=True)
    run_dir = H5.make_run(Path(container), run_id, alert=alert)
    if sidecars:
        H5.plant_sidecars(Path(container), run_id, staged=False)
    return run_dir


def manifest_text(episode_id: str, labels: Iterable[str], *,
                  source_run_id: str | None = None, extra: str = "") -> str:
    """A MINIMAL manifest naming `episode_id` and one world per label — NOT loadable by the
    family model (no reader that parses a manifest accepts it). Only for tests that
    exercise the roster / id check, not the family model's full grammar: tests that need a
    loadable family use the existing fixtures (`_triplet_947`, `_spec1224`) and rewrite their
    `episode_id`."""
    worlds = "".join(f"  - world_id: {label}\n" for label in labels)
    src = source_run_id if source_run_id is not None else new_id()
    return (f"episode_id: {episode_id}\nsource_run_id: {src}\nworlds:\n{worlds}{extra}")


def make_episode(data_root: Path, tenant_id: str, episode_id: str | None = None, *,
                 manifest: str | None = None, labels: Iterable[str] = ("a", "b"),
                 roster: Mapping[str, str] | None | bool = True,
                 arms: bool = False) -> Path:
    """`<T>/episodes/<episode_id>/`, the episode folder in the new layout.

    - `manifest`: the manifest's text verbatim; default `manifest_text(episode_id, labels)`.
    - `roster`: `True` writes a fresh roster `{label: new uuid}` for `labels`; a mapping writes
      that mapping; `False`/`None` writes none (the episode never reached RUNS). A roster is
      always written AFTER an empty real `runs/` is made, as `start_runs` writes it (design:
      "`runs/` first, then the roster"), so no scene holds a roster with no `runs/` — a state
      `start_runs` never leaves (review round 2, F27).
    - `arms`: also make `runs/` and one arm folder per roster entry. With no roster, `arms`
      makes an EMPTY `runs/`: the crash window between `start_runs`'s two steps (F27).
    Returns the episode folder."""
    episode_id = new_id() if episode_id is None else episode_id  # lint-default: ok — a fresh random id per call cannot be a signature default
    labels = list(labels)
    ep = episodes_dir(data_root, tenant_id) / episode_id
    ep.mkdir(parents=True, exist_ok=True)
    (ep / MANIFEST_NAME).write_text(
        manifest if manifest is not None else manifest_text(episode_id, labels),
        encoding="utf-8")
    mapping: Mapping[str, str] | None
    if roster is True:
        mapping = {label: new_id() for label in labels}
    elif roster is False or roster is None:
        mapping = None
    else:
        mapping = roster
    if mapping is not None:
        (ep / "runs").mkdir(exist_ok=True)
        write_roster(ep, mapping)
        if arms:
            for arm_id in mapping.values():
                make_run(ep / "runs", arm_id)
    elif arms:
        (ep / "runs").mkdir(exist_ok=True)
    return ep


def write_roster(episode_dir: Path, mapping: Mapping[str, str] | None = None, *,
                 raw: str | bytes | None = None) -> Path:
    """`<episode_dir>/arms.json` holding `mapping` as JSON, or `raw` verbatim (a torn,
    corrupt or hostile roster). Overwrites."""
    path = Path(episode_dir) / ROSTER_NAME
    body: str | bytes = json.dumps(dict(mapping or {}), indent=2, sort_keys=True) + "\n" \
        if raw is None else raw
    if isinstance(body, bytes):
        path.write_bytes(body)
    else:
        path.write_text(body, encoding="utf-8")
    return path


def read_roster(episode_dir: Path) -> dict[str, str]:
    """The roster as the TEST reads it back (plain JSON), for asserting what was written."""
    return json.loads((Path(episode_dir) / ROSTER_NAME).read_text(encoding="utf-8"))


def roster_for_arms(episode_dir: Path, arms: Mapping[str, Path]) -> dict[str, str]:
    """The arm roster of an episode an older fixture built (`_episode_1025.sample_episode`
    leaves its arms at `runs/<episode_id>-<label>`), as `{label: arm id}`. If the episode holds
    `arms.json` already (a fixture adapted to #1187), that roster, untouched. Otherwise a fresh
    UUID per label of `arms` (`{label: the arm folder the fixture made}`, one per manifest
    world): each arm folder that exists is renamed to `<episode>/runs/<its id>`, with its known
    sidecars (`<name><suffix>`), and the roster is written. Pure filesystem — so a page test
    over the older fixture reaches its own assertion about roster-id links (review F9)."""
    episode_dir = Path(episode_dir)
    if (episode_dir / ROSTER_NAME).is_file():
        return read_roster(episode_dir)
    runs = episode_dir / "runs"
    roster = {label: new_id() for label in arms}
    for label, arm in arms.items():
        arm = Path(arm)
        if arm.is_dir() and not arm.is_symlink():
            os.rename(arm, runs / roster[label])
        for suffix in SIDECAR_SUFFIXES:
            sidecar = arm.parent / f"{arm.name}{suffix}"
            if os.path.lexists(sidecar):
                os.rename(sidecar, runs / f"{roster[label]}{suffix}")
    write_roster(episode_dir, roster)
    return roster


def torn(text: str) -> str:
    """`text` cut mid-way: a roster a crash or a hand edit truncated."""
    return text[: max(1, len(text) // 2)]


# ------------------------------------------------------------------------------------------
# Links and old entries
# ------------------------------------------------------------------------------------------

#: The levels below `<T>` that O8 says are opened without following links, by name.
LINK_LEVELS = ("runs", "episodes", "episode", "arm_container", "run")


def replace_with_link(path: Path, target: Path) -> Path:
    """Move the real `path` aside to `target` (if it exists) and leave a symlink at `path`
    pointing at `target`. Returns `path`. The caller arranges `target` to be another tenant's
    or an outside folder."""
    path, target = Path(path), Path(target)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not path.is_symlink() and target.exists():
        raise FileExistsError(f"{target} exists; move the real {path} aside yourself first")
    if path.exists() and not path.is_symlink():
        target.parent.mkdir(parents=True, exist_ok=True)
        os.replace(path, target)
    else:
        target.mkdir(parents=True, exist_ok=True)
    os.symlink(target, path)
    return path


def plant_old_natural_entries(data_root: Path, tenant_id: str) -> dict[str, Path]:
    """The pre-#1187 entries a natural container holds today: an old minted run with its
    sidecars, an old pinned run, `_tenant.json` and an `_episodes` folder. Returns them by
    kind. Every one of them is off the new rules. NOTE: `_episodes/placeholder.json` is `{}`,
    which TODAY's record reader rejects as malformed; a test listing this container at base
    meets that unrelated refusal first (moot once R6 deletes the reader)."""
    runs = natural_runs(data_root, tenant_id)
    runs.mkdir(parents=True, exist_ok=True)
    out = {
        "old_minted": make_run(runs, OLD_MINTED_ID, sidecars=True),
        "old_pinned": make_run(runs, OLD_PINNED_ID),
        "tenant_record": H5.plant_tenant_record(runs, tenant_id),
    }
    episodes_record = runs / "_episodes"
    episodes_record.mkdir(exist_ok=True)
    (episodes_record / "placeholder.json").write_text("{}\n", encoding="utf-8")
    out["episodes_record"] = episodes_record
    for suffix in SIDECAR_SUFFIXES:
        out[f"sidecar{suffix}"] = runs / f"{OLD_MINTED_ID}{suffix}"
    return out


def plant_old_episodes_root(root: Path, names: Iterable[str] = (
        "fresh-authkeys-20260909-n124", "live-996-old-sshd-1-n233")) -> Path:
    """An old shared episodes root (today's `DEFENDER_EPISODES_BASE`) holding old episodes
    shaped like the two on the dev box: a manifest, and `runs/` with `<ep>-<label>` arms and no
    `_tenant.json`."""
    root = Path(root)
    for name in names:
        ep = root / name
        (ep / "runs").mkdir(parents=True, exist_ok=True)
        (ep / MANIFEST_NAME).write_text(f"episode_id: {name}\n", encoding="utf-8")
        for label in ("a", "b"):
            make_run(ep / "runs", f"{name}-{label}")
    return root


# ------------------------------------------------------------------------------------------
# Observation
# ------------------------------------------------------------------------------------------

def tree(root: Path) -> dict[str, tuple[str, bytes | str | None]]:
    """Every entry under `root` (links not followed): relative path -> (kind, content or link
    target). For "nothing changed" and "these bytes moved intact" assertions."""
    return H5.tree_state(Path(root))


def identities(root: Path, names: Iterable[str] | None = None) -> dict[str, tuple[int, int]]:
    """`{relative path: (st_dev, st_ino)}` of every entry under `root` whose top-level name is
    one of `names` (every entry, by default), the entries below them included, links not
    followed. A rename keeps both numbers; a copy — even a byte-identical one — makes new
    inodes. For "moved by rename, never copied" assertions (adversary F3), beside `tree`'s
    bytes."""
    root = Path(root)
    wanted = None if names is None else frozenset(names)
    out: dict[str, tuple[int, int]] = {}
    if not root.is_dir():
        return out
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in (*dirnames, *filenames):
            path = Path(dirpath) / name
            rel = path.relative_to(root)
            if wanted is not None and rel.parts[0] not in wanted:
                continue
            st = os.lstat(path)
            out[rel.as_posix()] = (st.st_dev, st.st_ino)
    return out


#: inotify's event bits this suite watches for (`<sys/inotify.h>`).
IN_ACCESS = 0x00000001
IN_OPEN = 0x00000020


class FileReads:
    """What the KERNEL saw happen to one file while the block ran: each `IN_OPEN` and
    `IN_ACCESS` (a read that returned bytes) inotify reports on `path`, whoever made it —
    production code reading through `_io`, a raw `open`, or any other route (adversary F9: a
    sentinel that fires only through one parser misses a read through another). Linux only;
    `available()` says whether this box has it.

    Watch a file AFTER its last rewrite (the watch is on the inode a later replace would leave
    behind), and drain `events()` before anything else reads it — the test's own reads count
    too. A context manager: leaving it closes the inotify descriptor."""

    def __init__(self, path: Path) -> None:
        import ctypes

        self.path = Path(path)
        libc = ctypes.CDLL(None, use_errno=True)
        self._fd = libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
        if self._fd < 0:
            raise OSError(ctypes.get_errno(), "inotify_init1 failed")
        wd = libc.inotify_add_watch(self._fd, os.fsencode(self.path), IN_ACCESS | IN_OPEN)
        if wd < 0:
            errno_ = ctypes.get_errno()
            os.close(self._fd)
            raise OSError(errno_, f"inotify_add_watch({self.path}) failed")
        self._seen: list[str] = []

    @staticmethod
    def available() -> bool:
        """Can this box watch a file (Linux, inotify present)?"""
        import ctypes
        import sys

        if not sys.platform.startswith("linux"):
            return False
        try:
            libc = ctypes.CDLL(None, use_errno=True)
            fd = libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
        except (OSError, AttributeError):
            return False
        if fd < 0:
            return False
        os.close(fd)
        return True

    def events(self) -> list[str]:
        """Every event so far, oldest first, as `"open"` / `"read"`."""
        import struct

        while True:
            try:
                buf = os.read(self._fd, 65536)
            except BlockingIOError:
                break
            at = 0
            while at < len(buf):
                _wd, mask, _cookie, length = struct.unpack_from("iIII", buf, at)
                at += 16 + length
                if mask & IN_OPEN:
                    self._seen.append("open")
                if mask & IN_ACCESS:
                    self._seen.append("read")
        return list(self._seen)

    def reads(self) -> int:
        """How many reads of the file returned bytes so far."""
        return self.events().count("read")

    def close(self) -> None:
        if self._fd >= 0:
            os.close(self._fd)
            self._fd = -1

    def __enter__(self) -> FileReads:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


raised = H5.raised
is_a = H5.is_a
message = H5.message

"""Shared fixtures and observation helpers for #1187."""
from __future__ import annotations

import json
import os
import sys
import uuid
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from defender.tests.storage.tenant_1105_run_repository import _spec1105 as H5
from defender.tests.support.shared._fixture_uuid import is_fixture_uuid_shape as is_canonical_uuid

tree = H5.tree_state

#: The arm roster's file name in the episode folder (pinned by the contract; the production
#: owner is `defender.records._episode_paths.ARM_ROSTER_NAME`).
ROSTER_NAME = "arms.json"
#: The manifest's file name (`_episode_paths.FAMILY_NAME` today, unchanged).
MANIFEST_NAME = "family.yaml"
#: The one-time command, as every refusal that sends the operator to it must spell it.
COMMAND = "defender/cli/retire_legacy_runs.py"
COMMAND_MODULE = "defender.cli.retire_legacy_runs"
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
    """Change one hexadecimal digit while preserving canonical UUID syntax."""
    chars = list(text)
    at = [i for i, c in enumerate(chars) if c != "-"][digit]
    chars[at] = "0" if chars[at] != "0" else "1"
    out = "".join(chars)
    if not is_canonical_uuid(out) or out == text:  # pragma: no cover — 32 hex digits round-trip
        raise ValueError(f"{out!r} is not a canonical near miss of {text!r}")
    return out


# Tenants and folders

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
    """A real run folder `<container>/<run_id>` holding an `alert.json` (and, with `sidecars`, the known sidecar files beside it)."""
    run_id = new_id() if run_id is None else run_id  # lint-default: ok — a fresh random id per call cannot be a signature default
    Path(container).mkdir(parents=True, exist_ok=True)
    run_dir = H5.make_run(Path(container), run_id, alert=alert)
    if sidecars:
        H5.plant_sidecars(Path(container), run_id, staged=False)
    return run_dir


def manifest_text(episode_id: str, labels: Iterable[str], *,
                  source_run_id: str | None = None, extra: str = "") -> str:
    """A complete persisted manifest, including each label's distinct world UUID."""
    from defender import _yaml
    from defender.tests.support.learning.branch import _triplet_947 as T

    worlds = [T.world_doc(label, world_id=new_id(), role="A" if index == 0 else None,
                          axis=None, facts=[]) for index, label in enumerate(labels)]
    src = source_run_id if source_run_id is not None else new_id()
    return _yaml.safe_dump(T.family_doc(episode_id=episode_id, source_run_id=src, worlds=worlds)) + extra


def make_episode(data_root: Path, tenant_id: str, episode_id: str | None = None, *,
                 manifest: str | None = None, labels: Iterable[str] = ("a", "b"),
                 roster: Mapping[str, str] | None | bool = True,
                 arms: bool = False) -> Path:
    """`<T>/episodes/<episode_id>/`, the episode folder in the new layout."""
    episode_id = new_id() if episode_id is None else episode_id  # lint-default: ok — a fresh random id per call cannot be a signature default
    labels = list(labels)
    ep = episodes_dir(data_root, tenant_id) / episode_id
    ep.mkdir(parents=True, exist_ok=True)
    (ep / MANIFEST_NAME).write_text(
        manifest if manifest is not None else manifest_text(episode_id, labels),
        encoding="utf-8")
    mapping: Mapping[str, str] | None
    if roster is True:
        from defender.tests.support.learning.branch._triplet_947 import world_id

        mapping = {world_id(ep, label): new_id() for label in labels}
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
    """`<episode_dir>/arms.json` holding `mapping` as JSON, or `raw` verbatim (a torn, corrupt or hostile roster)."""
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
    """Reuse an existing roster or rename legacy fixture arms to fresh UUIDs and record them."""
    episode_dir = Path(episode_dir)
    if (episode_dir / ROSTER_NAME).is_file():
        return read_roster(episode_dir)
    runs = episode_dir / "runs"
    from defender.tests.support.learning.branch._triplet_947 import world_id

    roster = {world_id(episode_dir, label): new_id() for label in arms}
    for label, arm in arms.items():
        arm = Path(arm)
        if arm.is_dir() and not arm.is_symlink():
            os.rename(arm, runs / roster[world_id(episode_dir, label)])
        for suffix in SIDECAR_SUFFIXES:
            sidecar = arm.parent / f"{arm.name}{suffix}"
            if os.path.lexists(sidecar):
                os.rename(sidecar, runs / f"{roster[world_id(episode_dir, label)]}{suffix}")
    write_roster(episode_dir, roster)
    return roster


def torn(text: str) -> str:
    """`text` cut mid-way: a roster a crash or a hand edit truncated."""
    return text[: max(1, len(text) // 2)]
# Links and old entries

#: The levels below `<T>` that O8 says are opened without following links, by name.
LINK_LEVELS = ("runs", "episodes", "episode", "arm_container", "run")


def replace_with_link(path: Path, target: Path) -> Path:
    """Move the real `path` aside to `target` (if it exists) and leave a symlink at `path` pointing at `target`."""
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
    """Create legacy run IDs, sidecars, tenant metadata, and episode claims for retirement."""
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
    """Populate the retired shared episodes root with legacy episode folders."""
    root = Path(root)
    for name in names:
        ep = root / name
        (ep / "runs").mkdir(parents=True, exist_ok=True)
        (ep / MANIFEST_NAME).write_text(f"episode_id: {name}\n", encoding="utf-8")
        for label in ("a", "b"):
            make_run(ep / "runs", f"{name}-{label}")
    return root
# Observation



def identities(root: Path, names: Iterable[str] | None = None) -> dict[str, tuple[int, int]]:
    """Map relative paths to device and inode identities, optionally filtering top-level names."""
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
# Observe process opens directly so calls outside an injected seam remain visible.

_PATH_EVENTS = frozenset({"open", "os.mkdir"})
_RECORDERS: list[PathOpens] = []
_HOOKED: list[bool] = []


def _audit(event: str, args: tuple) -> None:
    if event in _PATH_EVENTS and _RECORDERS and args and isinstance(
            args[0], (str, bytes, os.PathLike)):
        path = os.fsdecode(args[0])
        if os.path.isabs(path):
            for recorder in _RECORDERS:
                recorder.seen.append(path)


class PathOpens:
    """Record absolute paths opened during the block using the process audit hook."""

    def __init__(self) -> None:
        self.seen: list[str] = []

    def __enter__(self) -> PathOpens:
        if not _HOOKED:
            sys.addaudithook(_audit)
            _HOOKED.append(True)
        _RECORDERS.append(self)
        return self

    def __exit__(self, *_exc: object) -> None:
        _RECORDERS.remove(self)

    def below(self, folder: Path, allow: Iterable[Path] = ()) -> list[str]:
        prefix = os.fspath(folder).rstrip("/") + "/"
        allowed = [os.fspath(a).rstrip("/") for a in allow]
        return sorted({p for p in self.seen if p.startswith(prefix)
                       and not any(p == a or p.startswith(a + "/") for a in allowed)})


#: inotify's event bits this suite watches for (`<sys/inotify.h>`).
IN_ACCESS = 0x00000001
IN_OPEN = 0x00000020


class FileReads:
    """Observe file opens and accesses through kernel inotify events."""

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

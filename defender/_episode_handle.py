"""The file-backed `Episode` handle (#1133): every write into an episode tree goes through it,
and it writes only through a folder the rooted core holds open (`_io.Held`, #1111).

A door opens the handle once and holds it for its own duration: `Episode.open(episode_dir)`
for an episode that exists (its spelling followed, as `bind` follows it), `Episode.create`
for the one door that makes it (judged from its parent, never followed). Both are context
managers. Every verb then works relative to the held folder, so the episode dir is never
resolved by name again and a verb never makes it.

Records and folders are handed out by `_episode_paths.LAYOUT`'s relative names, the only place
those names are spelled. A record answers `.path` plus exactly the verbs its row in
`RECORD_VERBS` grants — one class per verb set, so a verb the row does not grant is absent from
the class; a folder answers `.path` and `.ensure()`. Each verb is one call on the held folder.

`view()` is a `Bound` over the same held folder, for a pass that reads the tree it writes (the
judge). Readers that bind the episode dir on their own keep their `_io.bind`. The archive's
copy lane (`learning/branch/archive.py`) is the declared exception and does not go through here.

The owner also has the episodes root and the episode id (#1105 PR 2, D-ep): `episodes_root`
(the one reader of `DEFENDER_EPISODES_BASE`, with its refusals), `refuse_bad_episode_id`, and
the id-taking doors `Episode.open_in(data_root, episode_id)` / `Episode.create_in(...)`, each
refusing a bad id or an unusable root (`EpisodeRefused`) before anything is read. The owner
never reads inside the episode's `runs/`: that container and its arms are the runs repository's
episode view (`tenant.runs_repository().episode(episode_id)`), built on this handle. The one
hand-out of the container's path is `box_mounted_container`, for a sibling's acceptance.
"""
from __future__ import annotations

import os
from pathlib import Path, PurePosixPath
from typing import Any

from defender import _io as _real_io
from defender._episode_paths import LAYOUT, _check_label, check_minted_token
from defender._git import REPO_ROOT
from defender._run_id import episode_id_fault

#: Where episodes live. No default: deriving it from the runs base would put `episodes/` inside
#: the tree corpus walkers descend and inside the checkout provenance is stamped from.
EPISODES_BASE_ENV = "DEFENDER_EPISODES_BASE"


class EpisodeRefused(ValueError):
    """The episode owner refused an episode id or the configured episodes root, before anything
    under the root was read. The message is operator-ready; each door adds its own prefix."""


def episodes_root(data_root: Path) -> Path:
    """The configured root every episode directory is a child of, resolved.

    Must be outside the data root (every tenant's tree lives there, so walkers indexing a
    tenant's runs or episodes would count it) and outside the checkout (or an untracked episode
    dir makes every sibling's provenance stamp dirty, so no family can complete). Being
    configured also keeps it independent of the data root. `data_root` is the one the request's
    tenant was (or is about to be) accepted under.
    """
    raw = os.environ.get(EPISODES_BASE_ENV)
    if not raw:
        raise EpisodeRefused(
            f"{EPISODES_BASE_ENV} is not set — an episode's directory is a CONFIGURED "
            "location, and there is deliberately no default: derived from the data root it "
            "would be walked by every consumer that indexes a tenant's runs, and derived from "
            "the checkout it would dirty the tree every sibling stamps itself against. Name a "
            "directory outside both")
    # Resolved even when it does not exist yet (every first launch): an unresolved relative path
    # has `.parents == (Path("."),)`, so neither refusal below would fire.
    root = Path(raw)
    candidate = root.resolve()
    data_root = Path(data_root).resolve()
    for forbidden, why in (
        (data_root, "the data root — every tenant's tree lives there, so an episode inside it "
                    "would be indexed as a tenant's own runs or episodes"),
        (REPO_ROOT, "the checkout — an untracked directory there is what a sibling's own "
                    "provenance stamp reports as a dirty tree"),
    ):
        forbidden = Path(forbidden).resolve()
        if candidate == forbidden or forbidden in candidate.parents:
            raise EpisodeRefused(f"{EPISODES_BASE_ENV}={root} resolves inside {why}")
    # A base containing the data root (its parent, say) is refused too; one containing the
    # checkout is not.
    if candidate in data_root.parents:
        raise EpisodeRefused(
            f"{EPISODES_BASE_ENV}={root} contains the data root {data_root} — keep "
            "episodes and tenants' trees apart")
    # The resolved path the refusals judged: paths built from it reach child processes, which
    # would re-resolve a relative one against their own cwd.
    return candidate


def refuse_bad_episode_id(episode_id: object) -> str:  # lint-dup: ok — one rule, two error classes: `_family` raises `FamilyError` for a manifest; the episode owner raises `EpisodeRefused` before any path is built (both state the rule once, in `_run_id.episode_id_fault`)
    """`episode_id`, when it can name a directory of its own under the episodes root — a run id
    with room left for a sibling (`_run_id.episode_id_fault`, the one statement of the rule) —
    else `EpisodeRefused`, before any path is built from it."""
    if type(episode_id) is not str:
        raise EpisodeRefused(f"an episode id must be text, not {type(episode_id).__name__}")
    if (why := episode_id_fault(episode_id)) is not None:
        raise EpisodeRefused(f"episode id {episode_id!r} is not usable: {why} — it names a "
                             "directory and half of every sibling's run id")
    return episode_id


def episode_dir(data_root: Path, episode_id: str) -> Path:
    """Where episode `episode_id` lives: one path component under the configured episodes root.
    The id is judged first, since a separator in it would put the episode outside the root or
    onto another's. Asking for it reads nothing under the root."""
    episode_id = refuse_bad_episode_id(episode_id)
    return episodes_root(data_root) / episode_id

#: Every record the handle hands out, keyed by its address (a bare name is an attribute of the
#: episode, `world.<name>` one of `episode.world(label)`), mapped to the verbs its row grants.
#: `write` replaces (stage + rename), `create` is exclusive, `append` appends, `delete` removes a
#: plain file.
#: No record reads: reading is the view's (`episode.view().read(LAYOUT.<record>)`).
RECORD_VERBS: dict[str, tuple[str, ...]] = {
    "family": ("write",),
    "family_stamp": ("write",),
    "review": ("write",),
    "samples": ("write",),
    "judge": ("write",),
    "timing": ("write",),
    "learning_html": ("write",),
    "served_base": ("create",),
    "served_world": ("append",),
    "priming_lock": ("create", "delete"),
    "wire_log": ("write",),
    "world.draw": ("write", "delete"),
    "world.run_dir_pointer": ("write",),
    "world_record": ("create",),
    "outcome": ("create",),
    "not_comparable": ("write",),
}

#: Every folder the handle hands out, keyed the same way.
FOLDERS: tuple[str, ...] = ("served", "runs", "worlds", "world.dir", "world.draws")


class EpisodeRecord:
    """One episode record: its name relative to the episode dir. The verbs come from the
    mixins its class is composed of, one class per `RECORD_VERBS` verb set."""

    def __init__(self, held: _real_io.Held, episode_dir: Path, rel: PurePosixPath) -> None:
        self._held = held
        self._dir = episode_dir
        self._rel = rel

    @property
    def path(self) -> Path:
        """For messages and argv; asking for it touches nothing."""
        return self._dir / self._rel


class _Write(EpisodeRecord):
    def write(self, text: str | bytes) -> None:
        self._held.write(self._rel, text, mode="replace")


class _Create(EpisodeRecord):
    def create(self, text: str | bytes) -> None:
        self._held.write(self._rel, text, mode="create")


class _Append(EpisodeRecord):
    def append(self, text: str | bytes) -> None:
        self._held.write(self._rel, text, mode="append")


class _Delete(EpisodeRecord):
    def delete(self) -> bool:
        return self._held.unlink(self._rel)


# One class per verb set in `RECORD_VERBS`.
class WriteRecord(_Write):
    pass


class WriteDeleteRecord(_Write, _Delete):
    pass


class CreateRecord(_Create):
    pass


class CreateDeleteRecord(_Create, _Delete):
    pass


class AppendRecord(_Append):
    pass


class EpisodeFolder:
    """One episode folder: `.path`, and `.ensure()` to make it (and any missing folder above
    it, below the episode dir) without following a link."""

    def __init__(self, held: _real_io.Held, episode_dir: Path, rel: PurePosixPath) -> None:
        self._held = held
        self._dir = episode_dir
        self._rel = rel

    @property
    def path(self) -> Path:
        return self._dir / self._rel

    def ensure(self) -> None:
        self._held.mkdir(self._rel)  # lint-unguarded-tree-write: ok — `Held.mkdir`, the rooted core's no-follow walk off the held episode dir, not a `Path.mkdir`


class EpisodeWorld:
    """One archived world's records and folders, `worlds/<label>/`. The label passes the
    minting check (case-stable), as `EpisodePaths.world` requires of a writer."""

    def __init__(self, episode: Episode, label: str) -> None:
        self._episode = episode
        self._label = _check_label(label)

    @property
    def dir(self) -> EpisodeFolder:
        return self._episode._folder(LAYOUT.world(self._label).dir)

    @property
    def draws(self) -> EpisodeFolder:
        return self._episode._folder(LAYOUT.world(self._label).draws)

    def draw(self, n: int) -> WriteDeleteRecord:
        return WriteDeleteRecord(*self._episode._at(LAYOUT.world(self._label).draw(n)))

    @property
    def run_dir_pointer(self) -> WriteRecord:
        return WriteRecord(*self._episode._at(LAYOUT.world(self._label).run_dir_pointer))


class Episode:
    """The file-backed episode handle: one held folder, the episode dir. Built only by
    `Episode.open` / `Episode.create`."""

    def __init__(self, held: _real_io.Held, episode_dir: Path, *, _door: object) -> None:
        if _door is not _DOOR:
            raise TypeError("an Episode is built by Episode.open or Episode.create")
        self._held = held
        self.dir = episode_dir

    @classmethod
    def open(cls, episode_dir: Path, *, io: Any = _real_io) -> Episode:
        """Hold an existing episode dir, following its own spelling. A missing dir is
        `FileNotFoundError`, a non-directory `NotADirectoryError`; nothing is made."""
        episode_dir = Path(episode_dir)
        return cls(io.hold(episode_dir), episode_dir, _door=_DOOR)

    @classmethod
    def create(cls, episode_dir: Path, *, io: Any = _real_io, exclusive: bool = False) -> Episode:
        """Make (or adopt) the episode dir, judged from its parent — a link, file or FIFO at
        its name is refused — and hold it. The episodes root's entry for it is synced.
        `exclusive` adopts nothing: an entry already at the name is `FileExistsError` (#1224
        N17, a launch's claim)."""
        episode_dir = Path(episode_dir)
        if exclusive:
            held = io.hold_new(episode_dir.parent, episode_dir.name, exclusive=True)
        else:
            held = io.hold_new(episode_dir.parent, episode_dir.name)
        return cls(held, episode_dir, _door=_DOOR)

    @classmethod
    def open_in(cls, data_root: Path, episode_id: str, *, io: Any = _real_io) -> Episode:
        """`open`, by id: the episode `episode_id` under the configured episodes root for
        `data_root`. A bad id or an unusable root is `EpisodeRefused` before anything is read;
        a missing episode is `FileNotFoundError` and a non-directory at its name
        `NotADirectoryError`, nothing made (#1133 O4.8.2)."""
        return cls.open(episode_dir(data_root, episode_id), io=io)

    @classmethod
    def create_in(cls, data_root: Path, episode_id: str, *, io: Any = _real_io,
                  exclusive: bool = True) -> Episode:
        """`create`, by id, under the configured episodes root for `data_root`: the launch's
        exclusive claim (#1224 N17) unless `exclusive` is False. The id and the root are judged
        first (`EpisodeRefused`); the root is made when absent."""
        return cls.create(episode_dir(data_root, episode_id), io=io, exclusive=exclusive)

    def close(self) -> None:
        self._held.close()

    def __enter__(self) -> Episode:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def view(self) -> _real_io.Bound:
        """A reader over the held folder. It owns nothing; once this handle is closed it
        answers `Bad file descriptor`."""
        return self._held.view()

    def _at(self, rel: PurePosixPath) -> tuple[_real_io.Held, Path, PurePosixPath]:
        return self._held, self.dir, rel

    def _folder(self, rel: PurePosixPath) -> EpisodeFolder:
        return EpisodeFolder(*self._at(rel))

    # -- episode-root records ----------------------------------------------------------------

    @property
    def family(self) -> WriteRecord:
        return WriteRecord(*self._at(LAYOUT.family))

    @property
    def family_stamp(self) -> WriteRecord:
        return WriteRecord(*self._at(LAYOUT.family_stamp))

    @property
    def review(self) -> WriteRecord:
        return WriteRecord(*self._at(LAYOUT.review))

    @property
    def samples(self) -> WriteRecord:
        return WriteRecord(*self._at(LAYOUT.samples))

    @property
    def judge(self) -> WriteRecord:
        return WriteRecord(*self._at(LAYOUT.judge))

    @property
    def timing(self) -> WriteRecord:
        return WriteRecord(*self._at(LAYOUT.timing))

    @property
    def outcome(self) -> CreateRecord:
        """`outcome.yaml`, pre-flight's episode outcome (#1224): created once, never rewritten."""
        return CreateRecord(*self._at(LAYOUT.outcome))

    @property
    def not_comparable(self) -> WriteRecord:
        """`not_comparable.yaml`: why `verify_family` withheld the family stamp."""
        return WriteRecord(*self._at(LAYOUT.not_comparable))

    @property
    def learning_html(self) -> WriteRecord:
        return WriteRecord(*self._at(LAYOUT.learning_html))

    @property
    def served_base(self) -> CreateRecord:
        return CreateRecord(*self._at(LAYOUT.served_base))

    @property
    def priming_lock(self) -> CreateDeleteRecord:
        return CreateDeleteRecord(*self._at(LAYOUT.priming_lock))

    def served_world(self, token: str) -> AppendRecord:
        """`served/<token>.jsonl`, a world's replay ledger; the token's label must be
        case-stable (the minting check)."""
        return AppendRecord(*self._at(LAYOUT.served_world(check_minted_token(token))))

    def world_record(self, label: str) -> CreateRecord:
        """`world_records/<label>.yaml`, written once (#1224): a second write is refused, so a
        resumed sibling never rewrites its world's record."""
        return CreateRecord(*self._at(LAYOUT.world_record(label)))

    def wire_log(self, name: str) -> WriteRecord:
        """`wire_logs/<name>`, by the full file name `WIRE_LOG_NAMES` gives."""
        return WriteRecord(*self._at(LAYOUT.wire_log(name)))

    # -- folders -----------------------------------------------------------------------------

    @property
    def served(self) -> EpisodeFolder:
        return self._folder(LAYOUT.served)

    @property
    def _runs(self) -> EpisodeFolder:
        """`runs/`, the siblings' container. Private (#1105 PR 2, F-13): the container and its
        arms are the runs repository's episode view, which is built on this handle."""
        return self._folder(LAYOUT.runs)

    @property
    def box_mounted_container(self) -> Path:
        """The container's path, for a sibling's acceptance only (`box_mounted`): the box mounts
        it, so the tenant's settings must lie under none of it. Asking reads nothing."""
        return self._runs.path

    @property
    def worlds(self) -> EpisodeFolder:
        return self._folder(LAYOUT.worlds)

    def world(self, label: str) -> EpisodeWorld:
        return EpisodeWorld(self, label)


_DOOR = object()


__all__ = ["EPISODES_BASE_ENV", "FOLDERS", "RECORD_VERBS", "Episode", "EpisodeFolder",
           "EpisodeRecord", "EpisodeRefused", "EpisodeWorld", "episode_dir", "episodes_root",
           "refuse_bad_episode_id"]

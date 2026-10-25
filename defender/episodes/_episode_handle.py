"""The file-backed `Episode` handle (#1133): every write into an episode tree goes through it,
and it writes only through a folder the rooted core holds open (`_io.Held`, #1111)."""
from __future__ import annotations

from pathlib import Path, PurePosixPath
from typing import Any

from defender import _io as _real_io
from defender.episodes._episode_paths import (
    LAYOUT, EpisodeRefused, _check_world_id, refuse_bad_episode_id,
)

#: Every record the handle hands out, keyed by its address (a bare name is an attribute of the
#: episode, `world.<name>` one of `episode.world(world_id)`), mapped to the verbs its row grants.
#: `write` replaces (stage + rename), `create` is exclusive, `append` appends, `delete` removes a
#: plain file.
#: No record reads: reading is the view's (`episode.view().read(LAYOUT.<record>)`).
RECORD_VERBS: dict[str, tuple[str, ...]] = {
    "family": ("create",),
    "family_stamp": ("write",),
    "review": ("write",),
    "samples": ("write",),
    "judge": ("write",),
    "timing": ("write",),
    "learning_html": ("write",),
    "served_base": ("create",),
    "served_unrecorded": ("create",),
    "served_world": ("append",),
    "priming_lock": ("create", "delete"),
    "wire_log": ("write",),
    "world.draw": ("write", "delete"),
    "family_draw": ("write", "delete"),
    "world_record": ("create",),
    "outcome": ("create",),
    "not_comparable": ("write",),
}

#: Every folder the handle hands out, keyed the same way.
FOLDERS: tuple[str, ...] = ("served", "runs", "worlds", "world.dir", "world.draws", "family_draws")


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
    """One archived world's records and folders, `worlds/<world UUID>/`.

    The UUID passes the same admission rule as `EpisodePaths.world`.
    """

    def __init__(self, episode: Episode, world_id: str) -> None:
        self._episode = episode
        self._world_id = _check_world_id(world_id)

    @property
    def dir(self) -> EpisodeFolder:
        return self._episode._folder(LAYOUT.world(self._world_id).dir)

    @property
    def draws(self) -> EpisodeFolder:
        return self._episode._folder(LAYOUT.world(self._world_id).draws)

    def draw(self, n: int) -> WriteDeleteRecord:
        return WriteDeleteRecord(*self._episode._at(LAYOUT.world(self._world_id).draw(n)))


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
    def family(self) -> CreateRecord:
        return CreateRecord(*self._at(LAYOUT.family))

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
    def source_alert(self) -> CreateRecord:
        """The source run's alert as launch copied it in (#1222 A1): created once."""
        return CreateRecord(*self._at(LAYOUT.source_alert))

    @property
    def source_record(self) -> CreateRecord:
        """The record of that alert, copied beside it: created once."""
        return CreateRecord(*self._at(LAYOUT.source_record))

    @property
    def knowledge_pin(self) -> CreateRecord:
        """The family's knowledge commit (`episodes._knowledge_pin`): created once, at launch."""
        return CreateRecord(*self._at(LAYOUT.knowledge_pin))

    @property
    def learning_html(self) -> WriteRecord:
        return WriteRecord(*self._at(LAYOUT.learning_html))

    @property
    def served_base(self) -> CreateRecord:
        return CreateRecord(*self._at(LAYOUT.served_base))

    @property
    def served_unrecorded(self) -> CreateRecord:
        """The primer's skip record (#1255 D6), created once beside the base."""
        return CreateRecord(*self._at(LAYOUT.served_unrecorded))

    @property
    def priming_lock(self) -> CreateDeleteRecord:
        return CreateDeleteRecord(*self._at(LAYOUT.priming_lock))

    def served_world(self, world_id: str) -> AppendRecord:
        """A world UUID's replay ledger, independent of its descriptive label."""
        return AppendRecord(*self._at(LAYOUT.served_world(_check_world_id(world_id))))

    def world_record(self, world_id: str) -> CreateRecord:
        """`world_records/<world UUID>.yaml`, written once (#1224): a second write is refused, so a
        resumed sibling never rewrites its world's record."""
        return CreateRecord(*self._at(LAYOUT.world_record(world_id)))

    def wire_log(self, name: str) -> WriteRecord:
        """`wire_logs/<name>`, by the full file name `WIRE_LOG_NAMES` gives."""
        return WriteRecord(*self._at(LAYOUT.wire_log(name)))

    def family_draw(self, n: int) -> WriteDeleteRecord:
        return WriteDeleteRecord(*self._at(LAYOUT.family_draw(n)))

    @property
    def family_draws(self) -> EpisodeFolder:
        return self._folder(LAYOUT.family_draws)

    # -- folders -----------------------------------------------------------------------------

    @property
    def served(self) -> EpisodeFolder:
        return self._folder(LAYOUT.served)

    @property
    def _runs(self) -> EpisodeFolder:
        """`runs/`, the siblings' container. Private (#1105 PR 2, F-13): the container and its
        arms are the runs repository's episode view, which is built on this handle."""
        return self._folder(LAYOUT.runs)

    def _held_folder(self) -> _real_io.Held:
        """The held episode folder itself, for the runs repository's episode view, which is
        built on this handle (#1187 S-iso): it holds `runs/` off it and writes the arm roster
        through it, so neither is ever reached by a path. Asking does no I/O; the handle still
        owns (and closes) the folder."""
        return self._held

    @property
    def box_mounted_container(self) -> Path:
        """The container's path, for a sibling's acceptance only (`box_mounted`): the box mounts
        it, so the tenant's settings must lie under none of it. Asking reads nothing."""
        return self._runs.path

    @property
    def worlds(self) -> EpisodeFolder:
        return self._folder(LAYOUT.worlds)

    def world(self, world_id: str) -> EpisodeWorld:
        return EpisodeWorld(self, world_id)


_DOOR = object()


__all__ = ["FOLDERS", "RECORD_VERBS", "Episode", "EpisodeFolder", "EpisodeRecord",
           "EpisodeRefused", "EpisodeWorld", "refuse_bad_episode_id"]

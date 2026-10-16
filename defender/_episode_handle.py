"""The file-backed `Episode` handle (#1133): every write into an episode tree goes through it,
and it writes only through a folder the rooted core holds open (`_io.Held`, #1111).

A door opens the handle once and holds it for its own duration. An episode is reached by id
through its tenant's runs repository (`runs.episode(episode_id)`, `runs.create_episode()`,
`runs.episode_files(episode_id)`, #1187 S-iso): the repository walks `<T>/episodes/<id>` from
the tenant's folder, every level no-follow, and wraps the folder it holds (`Episode._walked`).
`Episode.open(episode_dir)` (its spelling followed, as `bind` follows it) and `Episode.create`
(judged from its parent, never followed) remain for a folder handed in whole; no production
caller outside the repository uses them. All are context managers. Every verb then works
relative to the held folder, so the episode dir is never resolved by name again and a verb
never makes it.

Records and folders are handed out by `_episode_paths.LAYOUT`'s relative names, the only place
those names are spelled. A record answers `.path` plus exactly the verbs its row in
`RECORD_VERBS` grants — one class per verb set, so a verb the row does not grant is absent from
the class; a folder answers `.path` and `.ensure()`. Each verb is one call on the held folder.

`view()` is a `Bound` over the same held folder, for a pass that reads the tree it writes (the
judge). Readers that bind the episode dir on their own keep their `_io.bind`. The archive's
copy lane (`learning/branch/archive.py`) is the declared exception and does not go through here.

`refuse_bad_episode_id` is the episode id's rule (`_run_id.episode_id_fault`: canonical
lowercase UUID text), refused as `EpisodeRefused` before any path is built from the id. The
owner never reads inside the episode's `runs/`: that container, its arms and the arm roster
(`arms.json`, `LAYOUT.arm_roster`) are the runs repository's episode view
(`tenant.runs_repository().episode(episode_id)`), built on this handle through its two private
steps (`_hold_runs`, `_create_complete`). The one hand-out of the container's path is
`box_mounted_container`.
"""
from __future__ import annotations

from pathlib import Path, PurePosixPath
from typing import Any

from defender import _io as _real_io
from defender._episode_paths import LAYOUT, _check_label, check_minted_token
from defender._run_id import episode_id_fault


class EpisodeRefused(ValueError):
    """The episode owner refused an episode id, before any path was built from it. The message
    is operator-ready; each door adds its own prefix."""


def refuse_bad_episode_id(episode_id: object) -> str:  # lint-dup: ok — one rule, two error classes: `_family` raises `FamilyError` for a manifest; the episode owner raises `EpisodeRefused` before any path is built (both state the rule once, in `_run_id.episode_id_fault`)
    """`episode_id`, when it may name an episode folder under `<T>/episodes` — canonical
    lowercase UUID text (`_run_id.episode_id_fault`, the one statement of the rule) — else
    `EpisodeRefused`, before any path is built from it."""
    if type(episode_id) is not str:
        raise EpisodeRefused(f"an episode id must be text, not {type(episode_id).__name__}")
    if (why := episode_id_fault(episode_id)) is not None:
        raise EpisodeRefused(why)
    return episode_id

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


class Episode:
    """The file-backed episode handle: one held folder, the episode dir. Built only by its
    doors: `Episode.open` / `Episode.create`, and the runs repository's walk (`_walked`)."""

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
    def _walked(cls, held: _real_io.Held, episode_dir: Path) -> Episode:
        """The handle over the episode folder the runs repository holds: walked from the
        tenant's folder, every level no-follow (#1187 S-iso), so this door resolves nothing.
        `episode_dir` names it in messages and argv only. Private: the repository is the one
        door of an episode by id."""
        return cls(held, Path(episode_dir), _door=_DOOR)

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
    def source_alert(self) -> CreateRecord:
        """The source run's alert as launch copied it in (#1222 A1): created once."""
        return CreateRecord(*self._at(LAYOUT.source_alert))

    @property
    def source_record(self) -> CreateRecord:
        """The record of that alert, copied beside it: created once."""
        return CreateRecord(*self._at(LAYOUT.source_record))

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

    def _hold_runs(self, *, io: Any, create: bool = False) -> _real_io.Held:
        """`runs/` held off this episode's own handle and never followed (`io.hold_under`; made
        first when `create`): a link or a non-directory there is the step's refusal. The runs
        repository's one way into its arm container (#1187 S-iso); the caller closes it."""
        return io.hold_under(self._held, LAYOUT.runs.as_posix(), create=create)

    def _create_complete(self, rel: PurePosixPath, text: str, *, io: Any) -> None:
        """Create the record `rel` once, through the complete-or-absent lane only
        (`io.create_complete`: never the named fallback a crash can leave torn). The runs
        repository's write of the arm roster (#1187 R2), whose presence is itself a fact."""
        io.create_complete(self._held, rel, text)

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


__all__ = ["FOLDERS", "RECORD_VERBS", "Episode", "EpisodeFolder", "EpisodeRecord",
           "EpisodeRefused", "EpisodeWorld", "refuse_bad_episode_id"]

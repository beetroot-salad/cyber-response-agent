"""The file-backed `Episode` handle (#1133): every write into an episode tree goes through it,
and it writes only through the rooted core in `_io` (#1111).

`Episode(episode_dir, io=)` hands out records and folders by `_episode_paths.LAYOUT`'s relative
names, the only place those names are spelled. Every call is `io.rooted_*(episode_dir, <name>)`:
the episode dir is the trust root, its own spelling followed; nothing below it ever is. A
record answers `.path` plus only the verbs its row in `RECORD_VERBS` grants; a folder answers
`.path` and `.ensure()`.

Reads of a whole pass (the judge, the page) keep their one `_io.bind(episode_dir)` each; the
handle's `read` is for the records a writer reads back. The archive's copy lane
(`learning/branch/archive.py`) is the declared exception and does not go through here.
"""
from __future__ import annotations

from collections.abc import Callable
from pathlib import Path, PurePosixPath
from typing import Any

from defender import _io as _real_io
from defender._episode_paths import LAYOUT, _check_label, check_minted_token

#: Every record the handle hands out, keyed by its address (a bare name is an attribute of the
#: episode, `world.<name>` one of `episode.world(label)`), mapped to the verbs its row grants.
#: `write` replaces (stage + rename), `create` is exclusive, `append` / `append_durable` append
#: (the latter synced before it returns), `delete` removes a plain file, `read` answers
#: `(text | None, reason | None)`.
RECORD_VERBS: dict[str, tuple[str, ...]] = {
    "family": ("read", "write"),
    "family_stamp": ("write",),
    "review": ("read", "write"),
    "samples": ("write",),
    "judge": ("write",),
    "timing": ("write",),
    "staged": ("create", "append_durable"),
    "learning_html": ("write",),
    "served_base": ("create",),
    "served_world": ("append",),
    "priming_lock": ("create", "delete"),
    "wire_log": ("write",),
    "world.draw": ("write", "delete"),
    "world.run_dir_pointer": ("write",),
}

#: Every folder the handle hands out, keyed the same way.
FOLDERS: tuple[str, ...] = ("served", "runs", "worlds", "world.dir", "world.draws")


class EpisodeRecord:
    """One episode record: its name relative to the episode dir, and the verbs its row grants.
    A verb the row does not grant is absent, not a raising stub."""

    # The verbs, declared for the type checker only: each is bound per instance in `__init__`
    # when the record's row grants it, and is otherwise absent (no class attribute).
    read: Callable[[], tuple[str | None, str | None]]
    write: Callable[[str | bytes], None]
    create: Callable[[str | bytes], None]
    append: Callable[[str | bytes], None]
    append_durable: Callable[[str | bytes], None]
    delete: Callable[[], bool]

    def __init__(self, root: Path, rel: PurePosixPath, verbs: tuple[str, ...], *,
                 io: Any) -> None:
        self._root = root
        self._rel = rel
        self._io = io
        for verb in verbs:
            setattr(self, verb, getattr(self, f"_{verb}"))

    @property
    def path(self) -> Path:
        """For messages and argv; asking for it touches nothing."""
        return self._root / self._rel

    def _make_holding_folder(self) -> None:
        self._io.rooted_mkdir(self._root, self._rel.parent)

    def _read(self) -> tuple[str | None, str | None]:
        return self._io.rooted_read(self._root, self._rel)

    def _write(self, text: str | bytes) -> None:
        self._make_holding_folder()
        self._io.rooted_write(self._root, self._rel, text, mode="replace")

    def _create(self, text: str | bytes) -> None:
        self._make_holding_folder()
        self._io.rooted_write(self._root, self._rel, text, mode="create")

    def _append(self, text: str | bytes) -> None:
        self._make_holding_folder()
        self._io.rooted_write(self._root, self._rel, text, mode="append")

    def _append_durable(self, text: str | bytes) -> None:
        self._make_holding_folder()
        self._io.rooted_write(self._root, self._rel, text, mode="append", durable=True)

    def _delete(self) -> bool:
        return self._io.rooted_unlink(self._root, self._rel)


class EpisodeFolder:
    """One episode folder: `.path`, and `.ensure()` to make it (and any missing folder above
    it, below the episode dir) without following a link."""

    def __init__(self, root: Path, rel: PurePosixPath, *, io: Any) -> None:
        self._root = root
        self._rel = rel
        self._io = io

    @property
    def path(self) -> Path:
        return self._root / self._rel

    def ensure(self) -> None:
        self._io.rooted_mkdir(self._root, self._rel)


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

    def draw(self, n: int) -> EpisodeRecord:
        return self._episode._record("world.draw", LAYOUT.world(self._label).draw(n))

    @property
    def run_dir_pointer(self) -> EpisodeRecord:
        return self._episode._record("world.run_dir_pointer", LAYOUT.world(self._label).run_dir_pointer)


class Episode:
    """The file-backed episode handle, rooted at one episode dir."""

    def __init__(self, episode_dir: Path, *, io: Any = _real_io) -> None:
        self.dir = Path(episode_dir)
        self._io = io

    def _record(self, key: str, rel: PurePosixPath) -> EpisodeRecord:
        return EpisodeRecord(self.dir, rel, RECORD_VERBS[key], io=self._io)

    def _folder(self, rel: PurePosixPath) -> EpisodeFolder:
        return EpisodeFolder(self.dir, rel, io=self._io)

    def create_dir(self) -> None:
        """Make the episode dir, judged from its parent: a link or non-directory at the episode
        dir's own name is refused (the creation doors: the manifest, the staging record, the
        review merge). Every other access follows the episode dir's spelling."""
        self._io.rooted_mkdir(self.dir.parent, self.dir.name)

    # -- episode-root records ----------------------------------------------------------------

    @property
    def family(self) -> EpisodeRecord:
        return self._record("family", LAYOUT.family)

    @property
    def family_stamp(self) -> EpisodeRecord:
        return self._record("family_stamp", LAYOUT.family_stamp)

    @property
    def review(self) -> EpisodeRecord:
        return self._record("review", LAYOUT.review)

    @property
    def samples(self) -> EpisodeRecord:
        return self._record("samples", LAYOUT.samples)

    @property
    def judge(self) -> EpisodeRecord:
        return self._record("judge", LAYOUT.judge)

    @property
    def timing(self) -> EpisodeRecord:
        return self._record("timing", LAYOUT.timing)

    @property
    def staged(self) -> EpisodeRecord:
        return self._record("staged", LAYOUT.staged)

    @property
    def learning_html(self) -> EpisodeRecord:
        return self._record("learning_html", LAYOUT.learning_html)

    @property
    def served_base(self) -> EpisodeRecord:
        return self._record("served_base", LAYOUT.served_base)

    @property
    def priming_lock(self) -> EpisodeRecord:
        return self._record("priming_lock", LAYOUT.priming_lock)

    def served_world(self, token: str) -> EpisodeRecord:
        """`served/<token>.jsonl`, a world's replay ledger; the token's label must be
        case-stable (the minting check)."""
        return self._record("served_world", LAYOUT.served_world(check_minted_token(token)))

    def wire_log(self, name: str) -> EpisodeRecord:
        """`wire_logs/<name>`, by the full file name `WIRE_LOG_NAMES` gives."""
        return self._record("wire_log", LAYOUT.wire_log(name))

    # -- folders -----------------------------------------------------------------------------

    @property
    def served(self) -> EpisodeFolder:
        return self._folder(LAYOUT.served)

    @property
    def runs(self) -> EpisodeFolder:
        """`runs/`, the siblings' runs base. The handle never addresses inside a run."""
        return self._folder(LAYOUT.runs)

    @property
    def worlds(self) -> EpisodeFolder:
        return self._folder(LAYOUT.worlds)

    def world(self, label: str) -> EpisodeWorld:
        return EpisodeWorld(self, label)


__all__ = ["FOLDERS", "RECORD_VERBS", "Episode", "EpisodeFolder", "EpisodeRecord",
           "EpisodeWorld"]

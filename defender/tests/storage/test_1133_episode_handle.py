from __future__ import annotations

import errno
import os
import stat
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

from defender import _io
from defender.episodes._episode_paths import LAYOUT
from defender.tests.support.storage import _spec1133 as S

EPISODE_ID = "ep-1133"


def payload(key: str, tag: str) -> str | bytes:
    """What a write verb is handed: text, or bytes for the rendered page (`learning_html`
    writes bytes)."""
    text = f"{key} {tag}\n"
    return text.encode("utf-8") if key == "learning_html" else text


def as_bytes(p: str | bytes) -> bytes:
    return p if isinstance(p, bytes) else p.encode("utf-8")


class Tree:
    """An episodes root holding one episode dir, and a host folder outside the episode where a
    planted link points and a hard link's other name lives."""

    def __init__(self, tmp: Path) -> None:
        self.tmp = tmp
        self.episodes = tmp / "episodes"
        self.ep = self.episodes / EPISODE_ID
        self.ep.mkdir(parents=True)
        self.host = tmp / "host"
        self.host.mkdir()


@pytest.fixture
def tree(tmp_path: Path) -> Tree:
    return Tree(tmp_path)


@pytest.fixture
def opened(tree: Tree):
    """The tree's episode, opened with the real core; closed after the test."""
    episode = S.open_episode(tree.ep)
    try:
        yield episode
    finally:
        episode.close()


def verb_call(rec: Any, verb: str, key: str, tag: str) -> Any:
    if verb == "delete":
        return lambda: rec.delete()
    return lambda: getattr(rec, verb)(payload(key, tag))


def _record_matrix():
    for key, verbs in S.RECORD_VERBS.items():
        try:
            rel = S.expected_record_rel(key)
        except AttributeError:
            for verb in verbs:
                yield pytest.param(key, verb, S.LEAF_PLANTS[0], None, id=f"{key}.{verb}-unnamed")
            continue
        for verb in verbs:
            for kind in S.LEAF_PLANTS:
                yield pytest.param(key, verb, kind, None, id=f"{key}.{verb}-{kind}")
            for folder in S.holding_folders(rel):
                for kind in S.FOLDER_PLANTS:
                    yield pytest.param(key, verb, kind, folder,
                                       id=f"{key}.{verb}-{kind}@{folder}")


def _assert_landed(path: Path, key: str, verb: str, tag: str, *, prior: bytes = b"") -> None:
    assert not path.is_symlink(), f"{key}.{verb}: a link stands at {path}"
    assert path.is_file(), f"{key}.{verb}: nothing plain at {path}"
    got = path.read_bytes()
    if verb == "append":
        assert got == prior + as_bytes(payload(key, tag)), f"{key}.{verb} did not append"
    else:
        assert got == as_bytes(payload(key, tag)), f"{key}.{verb} did not land whole"
    assert os.lstat(path).st_nlink == 1, f"{key}.{verb} left a file with two names"


def _positive_controls(rec: Any, key: str, verb: str, path: Path) -> None:
    """The same verb on the same address: with nothing there, then with a plain file there."""
    if verb == "delete":
        assert rec.delete() is False, f"control: {key}.delete of nothing did not answer False"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("plain\n", encoding="utf-8")
        assert rec.delete() is True, f"control: {key}.delete of a plain file did not answer True"
        assert not os.path.lexists(path), f"control: {key}.delete left the plain file"
        return
    verb_call(rec, verb, key, "landed")()
    _assert_landed(path, key, verb, "landed")
    if verb == "create":
        before = path.read_bytes()
        with pytest.raises(FileExistsError) as taken:
            verb_call(rec, verb, key, "again")()
        assert not getattr(taken.value, "write_guarded_alias", False), (
            f"{key}.create over a plain file is the ordinary write-once collision, unmarked")
        assert path.read_bytes() == before, f"{key}.create over a plain file changed it"
        return
    prior = path.read_bytes()
    verb_call(rec, verb, key, "again")()
    _assert_landed(path, key, verb, "again", prior=prior)


@pytest.mark.parametrize(("key", "verb", "kind", "site"), list(_record_matrix()))
def test_o2_d7_a_record_verb_into_a_plant_is_refused_and_changes_nothing(
        tree, opened, key, verb, kind, site):
    rec = S.resolve(opened, key)
    rel = S.expected_record_rel(key)
    path = tree.ep / rel
    planted = S.plant(tree.ep, rel, site, kind, host=tree.host)
    before = S.census(tree.tmp)

    raised = S.raised_by(verb_call(rec, verb, key, "refused"), fifo=planted.fifo)
    S.assert_refusal(raised, "symlink" if kind == "dangling" else kind,
                     where=f"{key}.{verb}{f' @{site}' if site else ''}")
    assert S.census(tree.tmp) == before, f"{key}.{verb} into a {kind} plant changed the tree"

    planted.remove()
    _positive_controls(rec, key, verb, path)


def _folder_matrix():
    for key in S.FOLDERS:
        for site in S.folder_and_parents(S.expected_folder_rel(key)):
            for kind in S.FOLDER_PLANTS:
                yield pytest.param(key, kind, site, id=f"{key}-{kind}@{site}")


@pytest.mark.parametrize(("key", "kind", "site"), list(_folder_matrix()))
def test_o2_d7_a_folders_ensure_through_a_plant_is_refused_and_changes_nothing(
        tree, opened, key, kind, site):
    folder = S.resolve(opened, key)
    rel = S.expected_folder_rel(key)
    planted = S.plant_folder(tree.ep, rel, site, kind, host=tree.host)
    before = S.census(tree.tmp)

    S.assert_refusal(S.raised_by(folder.ensure, fifo=planted.fifo), kind,
                     where=f"{key}.ensure @{site}")
    assert S.census(tree.tmp) == before, f"{key}.ensure through a {kind} changed the tree"

    planted.remove()
    folder.ensure()
    target = tree.ep / rel
    assert stat.S_ISDIR(os.lstat(target).st_mode), f"control: {key}.ensure made no real folder"
    (target / "marker").write_text("kept\n", encoding="utf-8")
    folder.ensure()
    assert (target / "marker").read_text(encoding="utf-8") == "kept\n"


@pytest.mark.parametrize("kind", ["folder_link_outside", "folder_link_inside", "folder_file",
                                  "folder_fifo", "dangling_dir_link"])
def test_n_g_create_refuses_a_plant_at_the_episode_dirs_own_name(tmp_path, kind):
    episodes = tmp_path / "episodes"
    episodes.mkdir()
    host = tmp_path / "host"
    host.mkdir()
    ep = episodes / EPISODE_ID
    if kind == "dangling_dir_link":
        ep.symlink_to(host / "not-yet", target_is_directory=True)
        planted, row = S.Planted("folder_link_outside", ep), "folder_link_outside"
    else:
        planted = S.plant_folder(episodes, PurePosixPath(EPISODE_ID), PurePosixPath(EPISODE_ID),
                                 kind, host=host)
        row = kind
    before = S.census(tmp_path)

    raised = S.raised_by(lambda: S.create_episode(ep).close(), fifo=planted.fifo)
    S.assert_refusal(raised, row, where=f"Episode.create over a {kind}")
    assert S.census(tmp_path) == before, f"Episode.create over a {kind} changed the tree"

    planted.remove()
    with S.create_episode(ep) as episode:
        episode.family.create("family: made\n")
    assert stat.S_ISDIR(os.lstat(ep).st_mode)
    with S.create_episode(ep) as episode:
        assert episode.view().read(LAYOUT.family).text == "family: made\n", (
            "a real dir was not adopted")

    fresh = tmp_path / "fresh-root" / EPISODE_ID
    with S.create_episode(fresh) as episode:
        episode.family.create("family: fresh\n")
    assert (fresh / "family.yaml").read_text(encoding="utf-8") == "family: fresh\n"
    assert not fresh.is_symlink()


def test_n_g_open_follows_the_episode_dirs_own_spelling_and_create_does_not(tmp_path):
    real = tmp_path / "real" / EPISODE_ID
    real.mkdir(parents=True)
    alias = tmp_path / "alias-ep"
    alias.symlink_to(real, target_is_directory=True)
    with S.open_episode(alias) as episode:
        episode.family.create("family: through the root's spelling\n")
        assert episode.view().read(LAYOUT.family).text == "family: through the root's spelling\n"
        episode.served.ensure()
    assert (real / "family.yaml").read_text(encoding="utf-8") == (
        "family: through the root's spelling\n")
    assert (real / "served").is_dir()
    assert alias.is_symlink(), "the episode dir's own link was replaced"

    with pytest.raises(OSError, match=S.CORE_REFUSAL):
        S.create_episode(alias)


@pytest.mark.parametrize(("kind", "exc"), [
    ("missing", FileNotFoundError), ("missing-parent", FileNotFoundError),
    ("dangling-link", FileNotFoundError), ("file", NotADirectoryError),
    ("fifo", NotADirectoryError)])
def test_o6_open_refuses_a_missing_dir_or_a_non_directory_and_makes_nothing(
        tmp_path, kind, exc):
    ep = tmp_path / "episodes" / EPISODE_ID
    fifo = None
    if kind != "missing-parent":
        ep.parent.mkdir()
    if kind == "dangling-link":
        ep.symlink_to(tmp_path / "nowhere", target_is_directory=True)
    elif kind == "file":
        ep.write_bytes(S.HOST_BYTES)
    elif kind == "fifo":
        os.mkfifo(ep)
        fifo = ep
    before = S.census(tmp_path)

    raised = S.raised_by(lambda: S.open_episode(ep).close(), fifo=fifo)

    assert isinstance(raised, exc), f"Episode.open over a {kind}: {raised!r}"
    assert S.census(tmp_path) == before, f"Episode.open over a {kind} created something"
    if os.path.lexists(ep):
        ep.unlink()
    ep.mkdir(parents=True, exist_ok=True)
    with S.open_episode(ep) as episode:
        episode.family.create("family: control\n")


def _write_verbs():
    for key, verbs in S.RECORD_VERBS.items():
        for verb in verbs:
            if verb in S.WRITE_MODE:
                yield pytest.param(key, verb, id=f"{key}.{verb}")


@pytest.mark.parametrize(("key", "verb"), list(_write_verbs()))
def test_o6_a_handle_whose_dir_was_removed_refuses_every_write_verb_and_never_recreates_it(
        tree, key, verb):
    episode = S.open_episode(tree.ep)
    try:
        rec = S.resolve(episode, key)
        tree.ep.rmdir()
        raised = S.raised_by(verb_call(rec, verb, key, "removed"))
        assert isinstance(raised, OSError), f"{key}.{verb} on a removed episode: {raised!r}"
        assert not os.path.lexists(tree.ep), f"{key}.{verb} recreated the removed episode dir"
    finally:
        episode.close()
    tree.ep.mkdir()
    with S.open_episode(tree.ep) as episode:
        verb_call(S.resolve(episode, key), verb, key, "control")()


@pytest.mark.parametrize("key", list(S.FOLDERS))
def test_o6_a_handle_whose_dir_was_removed_refuses_every_ensure(tree, key):
    episode = S.open_episode(tree.ep)
    try:
        folder = S.resolve(episode, key)
        tree.ep.rmdir()
        raised = S.raised_by(folder.ensure)
        assert isinstance(raised, OSError), f"{key}.ensure on a removed episode: {raised!r}"
        assert not os.path.lexists(tree.ep), f"{key}.ensure recreated the removed episode dir"
    finally:
        episode.close()


@pytest.mark.parametrize(("key", "verb"), list(_write_verbs()))
def test_o6_a_handle_whose_dir_was_renamed_writes_into_the_moved_folder(tree, key, verb):
    """The episode is held, not remembered: after its dir is renamed, a write verb lands in the
    moved folder at the record's name, and nothing appears at the old spelling."""
    moved = tree.episodes / "moved"
    with S.open_episode(tree.ep) as episode:
        rec = S.resolve(episode, key)
        tree.ep.rename(moved)
        verb_call(rec, verb, key, "moved")()
    assert not os.path.lexists(tree.ep), f"{key}.{verb} wrote at the old spelling"
    assert (moved / S.expected_record_rel(key)).read_bytes() == as_bytes(payload(key, "moved"))


def test_o3_the_view_is_a_bound_with_the_readers_surface_reading_through_the_same_handle(tree):
    moved = tree.episodes / "moved"
    with S.open_episode(tree.ep) as episode:
        view = episode.view()
        assert isinstance(view, _io.Bound), f"view() is {type(view).__name__}"
        public = {n for n in dir(view) if not n.startswith("_")}
        assert public == {"read", "read_bytes", "read_jsonl", "entries", "under", "close"}, sorted(public)
        tree.ep.rename(moved)
        episode.review.write("review: after the rename\n")
        assert view.read(LAYOUT.review).text == "review: after the rename\n"
        assert view.read_bytes(LAYOUT.review).data == b"review: after the rename\n"
        view.close()
        episode.samples.write("samples: still held\n")
    assert (moved / LAYOUT.samples).read_text(encoding="utf-8") == "samples: still held\n"


def test_d1_a_write_after_close_raises_ebadf_and_lands_nowhere(tree):
    """Once the episode is closed its records do not reopen it: a write raises
    `OSError(EBADF)` and nothing is written anywhere."""
    episode = S.open_episode(tree.ep)
    review = episode.review
    episode.close()
    before = S.census(tree.tmp)
    closed = S.raised_by(lambda: review.write("review: after close\n"))
    assert isinstance(closed, OSError), f"a write after close raised {closed!r}"
    assert closed.errno == errno.EBADF, closed
    assert S.census(tree.tmp) == before


@pytest.mark.parametrize("dir_state", ["fresh", "adopted"])
def test_d1_episode_create_fsyncs_the_episodes_root(tree, dir_state):
    fresh = tree.episodes / "ep-durable"
    if dir_state == "adopted":
        fresh.mkdir()
    spy = S.OsSpy()
    rec_io = S.RecordingIo(os_=spy)
    with S.create_episode(fresh, io=rec_io):
        at_create = list(spy.fsyncs)
    assert any(s.ino == S.inode(tree.episodes) and s.is_dir and not s.getfl & S.O_PATH
               for s in at_create), (
        f"Episode.create did not fsync the episodes root on a directory handle: {at_create}")


@pytest.mark.parametrize(("key", "verb"), list(_write_verbs()))
def test_d1_a_records_write_verb_takes_str_or_bytes_only(tree, opened, key, verb):
    """No iterable text: a list or a generator handed to a write verb is a `TypeError` before
    anything is written or made."""
    rec = S.resolve(opened, key)
    for value in (["a line\n"], (line for line in ["a line\n"])):
        before = S.census(tree.tmp)
        with pytest.raises(TypeError):
            getattr(rec, verb)(value)
        assert S.census(tree.tmp) == before, f"{key}.{verb} of an iterable made something"


_BAD_NAMES = [
    pytest.param(lambda ep: ep.world("B").draw(0).write("x"), id="label-not-case-stable-draw"),
    pytest.param(lambda ep: ep.world("B").draw(0).delete(), id="label-not-case-stable-delete"),
    pytest.param(lambda ep: ep.world("B").dir.ensure(), id="label-dir-ensure"),
    pytest.param(lambda ep: ep.world("B").draws.ensure(), id="label-draws-ensure"),
    pytest.param(lambda ep: ep.world("a/b").draw(0).write("x"), id="label-two-components"),
    pytest.param(lambda ep: ep.world("..").dir.ensure(), id="label-dotdot"),
    pytest.param(lambda ep: ep.served_world("e1133.B").append(""), id="token-not-case-stable"),
    # Rev 3's patch: the WHOLE token is judged, not only the text after its last dot.
    pytest.param(lambda ep: ep.served_world("Control").append(""),
                 id="token-dotless-not-case-stable"),
    pytest.param(lambda ep: ep.served_world("E1133.b").append(""),
                 id="token-head-not-case-stable"),
    pytest.param(lambda ep: ep.served_world("e1133/b").append(""), id="token-two-components"),
    pytest.param(lambda ep: ep.served_world("..").append(""), id="token-dotdot"),
    pytest.param(lambda ep: ep.wire_log("a/b.jsonl").write("x"), id="wire-log-two-components"),
    pytest.param(lambda ep: ep.wire_log("../escape.jsonl").write("x"), id="wire-log-climbs"),
    pytest.param(lambda ep: ep.wire_log("..").write("x"), id="wire-log-dotdot"),
    pytest.param(lambda ep: ep.world(S.WORLD_ID).draw(-1).write("x"), id="draw-negative"),
    pytest.param(lambda ep: ep.world(S.WORLD_ID).draw("0").write("x"), id="draw-string"),
    pytest.param(lambda ep: ep.world(S.WORLD_ID).draw(True).write("x"), id="draw-bool"),
    pytest.param(lambda ep: ep.world(S.WORLD_ID).draw(-1).delete(), id="draw-negative-delete"),
]


@pytest.mark.parametrize("call", _BAD_NAMES)
def test_d1_a_bad_component_is_a_value_error_before_any_held_call(tree, call):
    rec_io = S.RecordingIo()
    with S.open_episode(tree.ep, io=rec_io) as episode:
        before = S.census(tree.tmp)
        with pytest.raises(ValueError, match=S.NAME_REFUSAL):
            call(episode)
        assert rec_io.calls == [], f"the held root was called before the name check: {rec_io.calls}"
        assert S.census(tree.tmp) == before

"""#1133 rev 3 (D7'') — the obligations rev 3 adds, each through its real entry point.

Rev 3 removes four causes of PR #1143's review findings rather than patching them (the design
amendment "rev 3" on #1133; every name the suite calls is gathered in `_spec1133`'s docstring):

- **R1, reads belong to the view.** `Held.read` and the records' `read` are gone: `Held`'s public
  surface is `write` / `mkdir` / `unlink` / `view` / `close`, and a record is read with
  `episode.view().read(LAYOUT.<record>)` — present, absent or refused. The view reads through a
  private dup taken under the lock `close` takes, so a close landing mid-read never redirects
  it (the E-race shape: the freed number is taken by a decoy with `dup2`). `merge_review` over a
  REFUSED review record is `StagingRefused` and writes nothing (absent and unparseable still
  merge from `{}`); in `teardown` the refusal rides on the raised `StagingRefused` with the
  unverified names, and the aborting launcher's log line stops claiming the names are in the
  record; in `verify_family`'s archive-refused path the archive's exception stays the one raised,
  the merge's refusal attached as a note; after a completed family a refused merge raises.
  `delta_o` reads everything through one `bind`: an absent or refused base is `LedgerError`
  ("no primed base"), a refused world file `EpisodeError`, an absent one `{}`, a refused
  `review.yaml` at the incomplete gate `EpisodeError`; with no archived worlds it answers `{}`
  before the base is read. `load_family(view)` names `family.yaml`, never an absolute path.
- **R2, the leaf refusal is its own class.** `_io.NotPlainEntry(OSError)` keeps its errno and
  alias mark, and a linked folder on the way is NOT it. Placed at the doors, with the link
  planted after the relevant `ensure`: at the judge's stale-draw removal (S1) a `judge/` folder
  linked mid-pass stops the pass; at the priming claim and at the primed base a `served/` linked
  after `served.ensure()` / the listing is the folder refusal, not "another launcher is priming"
  / "already holds a primed base".
- **R3, one primer, one write.** `prime_base(source_run_dir, episode, *, allow_empty=False)`
  lists `served/` first: anything named `base.jsonl` is "already holds a primed base" before the
  capture is read (a FIFO at the capture's payload sidecar makes the read observable) and without
  opening the base. Zero rows are refused by default and primed empty with `allow_empty=True`, in
  one create. A retry through `prepare_episode` over an existing base is that `LedgerError`,
  never a raw `FileExistsError`.
- **R4, one leaf writer; a durable write never makes a folder.** An encode failure in a durable
  append leaves no descriptor open; a durable append into a missing holding folder is
  `FileNotFoundError` and makes nothing.
- **Patches.** The minting check judges the WHOLE token (`Control` is refused by
  `check_minted_token`, `Ledger.for_world`, `scratch_ledger`); `--resume` with no held episode is
  `SystemExit` (driven through `run._resume_target`: `run.main` always holds one).

Every plant is a real filesystem entry, every fault a real primitive or the entry point's own
seam (`io=`, `os_=`, `judge=`, `prime=`); every negative has a positive control on the same
address. Nothing is monkeypatched (the `roots` fixture steers configured roots through the
environment, the resolvers' own seam).

Red on the rev-2 tree (PR #1143's head), each for its own reason: `Held` still has `read` and the
records still answer it; the view takes no dup (the decoy's bytes come back); `merge_review` over
a refused record raises the replace's `OSError` or overwrites undecodable bytes; `delta_o`
answers `{}` over a missing or linked base and world file and skips the gate over a linked
review; `load_family` wants an `Episode` (a `Bound` has no `family`); there is no
`_io.NotPlainEntry` and ELOOP is contained by errno (a linked folder read as a planted leaf);
`prime_base` reads the capture before the "already primed" check, has no `allow_empty`, and the
launcher's downgrade creates the base a second time; a durable append leaks its fd on an encode
failure and makes missing folders; a dot-less token skips the case check; `_resume_target`
answers `None` for `--resume` without an episode.
"""
from __future__ import annotations

import errno
import json
import logging
import os
import stat
import threading
import time
from pathlib import Path, PurePosixPath
from typing import Any

import pytest
import yaml

from defender import _io
from defender._episode_paths import LAYOUT
from defender.tests import _judge_921 as J
from defender.tests import _spec1133 as S
from defender.tests import _triplet_947 as T
from defender.tests.test_947_capture_prime import append_call, call_row, source_run

EPISODE_ID = "ep-1133"
#: A staged cluster name, as the staging step records one.
STAGED_NAME = "wv-e1133.b-logs-x"
#: Bytes that are not UTF-8: a plain file holding them is a refused text read.
UNDECODABLE = b"\xff\xfe review bytes, not text\n"
#: A string no UTF-8 encoder accepts (a lone surrogate).
UNENCODABLE = "a row \udcff that cannot be encoded\n"


@pytest.fixture
def roots(tmp_path, monkeypatch):
    """The configured roots inside `tmp_path` (environment steering, the resolvers' own seam):
    the runs base, the episodes root and the learning state root the judge's queue lands in."""
    monkeypatch.setenv(T.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    monkeypatch.setenv(J.STATE_DIR_ENV, str(tmp_path / "learning-state"))


@pytest.fixture
def host(tmp_path: Path) -> Path:
    """A host folder outside every episode: where an outside link points."""
    h = tmp_path / "host"
    h.mkdir()
    return h


def bare_episode(tmp_path: Path) -> Path:
    ep = tmp_path / "episodes" / EPISODE_ID
    ep.mkdir(parents=True)
    return ep


def view_reason(ep: Path, rel: PurePosixPath) -> str:
    """What the view says of `rel` right now (its refusal reason), read through a fresh `bind`
    so the expectation comes from the reader itself, not a hand-copied sentence."""
    with _io.bind(ep) as view:
        rec = view.read(rel)
    assert rec.text is None, f"the fixture's {rel} reads as text: {rec!r}"
    assert not rec.absent, f"the fixture's {rel} reads as absent: {rec!r}"
    assert rec.reason, f"the fixture's {rel} is refused with no reason: {rec!r}"
    return rec.reason


def plant_record(at: Path, kind: str, *, host: Path) -> S.Planted:
    """`kind` at a record's own name: a leaf plant, or `undecodable` (a plain, single-linked
    file whose bytes are not UTF-8 — refused by a text read, replaced by a naive merge)."""
    if kind == "undecodable":
        at.parent.mkdir(parents=True, exist_ok=True)
        at.write_bytes(UNDECODABLE)
        return S.Planted("file", at)
    return S.plant_leaf(at, kind, host=host, body=b"host: bytes\n")


def link_folder(at: Path, *, reach: str, ep: Path, host: Path, keep: dict[str, bytes]) -> Path:
    """Replace the folder at `at` (or nothing) with a symlink to a real folder, outside the
    episode or elsewhere inside it, holding `keep`. Answers the folder the link reaches."""
    target = (host if reach == "outside" else ep) / f"elsewhere-{at.name}"
    target.mkdir()
    for name, body in keep.items():
        (target / name).write_bytes(body)
    if at.is_dir() and not at.is_symlink():
        for child in at.iterdir():
            child.unlink()
        at.rmdir()
    at.symlink_to(target, target_is_directory=True)
    return target


def mod(dotted: str) -> Any:
    return T.mod(dotted)


# =======================================================================================
# R1 — the handle writes; the view reads
# =======================================================================================

def test_r1_held_has_no_read_and_its_surface_is_the_writers_view_and_close(tmp_path):
    """`Held.read` is removed: the held root's public surface is exactly `write`, `mkdir`,
    `unlink`, `view`, `close` (on the class and the instance), and its view's is the readers'.
    Control: the view reads what the handle wrote."""
    root = tmp_path / "root"
    root.mkdir()
    assert not hasattr(_io.Held, "read"), "`Held.read` is still there: reads belong to the view"
    with S.hold(root) as held:
        assert S.public_names(held) == S.HELD_SURFACE, sorted(S.public_names(held))
        assert S.public_names(held.view()) == S.VIEW_SURFACE
        held.write("rec.txt", "written\n", mode="create")
        assert held.view().read("rec.txt").text == "written\n"


@pytest.mark.parametrize("key", ["family", "review"])
@pytest.mark.parametrize("kind", S.LEAF_PLANTS)
def test_r1_a_record_is_read_through_the_view_present_absent_or_refused(tmp_path, key, kind):
    """Records are write-only: `family` and `review` answer no `read`. A record is read with
    `episode.view().read(LAYOUT.<record>)`: a plant at its name (a live or dangling link, a hard
    link, a FIFO, a directory) is REFUSED — no text, not absent, a reason — promptly, and the
    tree is unchanged. Control on the same address: absent, then a plain file's text."""
    ep = bare_episode(tmp_path)
    host = tmp_path / "host"
    host.mkdir()
    rel = S.expected_record_rel(key)
    with S.open_episode(ep) as episode:
        planted = S.plant_leaf(ep / rel, kind, host=host)
        before = S.census(tmp_path)
        got = S.in_time(lambda: episode.view().read(rel), fifo=planted.fifo)
        assert got.text is None, f"the view read through a {kind} at {rel}: {got!r}"
        assert not got.absent, f"a {kind} at {rel} read as absent: {got!r}"
        assert got.reason, f"a {kind} at {rel} was refused with no reason: {got!r}"
        assert S.census(tmp_path) == before, f"reading a {kind} at {rel} changed the tree"

        planted.remove()
        assert episode.view().read(rel).absent, "control: an absent record did not read absent"
        getattr(episode, key).write(f"{key}: plain\n")
        assert episode.view().read(rel).text == f"{key}: plain\n"
        assert not hasattr(getattr(episode, key), "read"), (
            f"the {key} record still answers `read`: records are write-only (R1)")


def _view_matrix():
    rec = PurePosixPath("fa/fb/rec.jsonl")
    for kind in S.LEAF_PLANTS:
        yield pytest.param(kind, None, id=f"read-{kind}")
    for site in S.holding_folders(rec):
        for kind in S.FOLDER_PLANTS:
            yield pytest.param(kind, site, id=f"read-{kind}@{site}")


@pytest.mark.parametrize(("kind", "site"), list(_view_matrix()))
def test_r1_the_views_read_of_a_plant_is_refused_promptly_and_changes_nothing(
        tmp_path, kind, site):
    """The read rows of the held-root matrix, moved to the view (rev 3 has no `Held.read`): a
    link (live or dangling), hard link, FIFO or directory at the name, or a link, file or FIFO at
    a holding folder, is a refused read — never text, never a wedge on the FIFO — and the tree is
    unchanged. `read_jsonl` answers no rows over it. Control on the same address: the plant
    removed, absent; then a plain file's text and rows."""
    root = tmp_path / "root"
    root.mkdir()
    host = tmp_path / "host"
    host.mkdir()
    rel = PurePosixPath("fa/fb/rec.jsonl")
    with S.hold(root) as held:
        view = held.view()
        planted = S.plant(root, rel, site, kind, host=host)
        before = S.census(tmp_path)
        got = S.in_time(lambda: view.read(rel), fifo=planted.fifo)
        assert got.text is None, f"the view read through a {kind}: {got!r}"
        assert not got.absent, f"a {kind} read as absent: {got!r}"
        assert got.reason, f"a {kind} is refused with no reason: {got!r}"
        rows, _bad, rec = S.in_time(lambda: view.read_jsonl(rel), fifo=planted.fifo)
        assert rows == [], f"read_jsonl through a {kind} answered rows: {rows!r}"
        assert rec.reason, f"read_jsonl through a {kind} is not refused: {rec!r}"
        assert S.census(tmp_path) == before

        planted.remove()
        assert view.read(rel).absent
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text('{"k": 1}\n', encoding="utf-8")
        assert view.read(rel).text == '{"k": 1}\n'
        assert view.read_jsonl(rel)[0] == [{"k": 1}]


# ---- the view under a close race (the E-race shape) --------------------------------------

_RACE_OPS = ("read-top", "read-deep", "read_jsonl", "entries-root", "entries-under")


def _race_trees(tmp_path: Path) -> tuple[Path, Path]:
    """A root and a DECOY of the same shape, each marking its own bytes and names."""
    trees = []
    for who in ("root", "decoy"):
        top = tmp_path / who
        (top / "fa").mkdir(parents=True)
        (top / "rec.txt").write_text(f"{who.upper()}\n", encoding="utf-8")
        (top / "fa" / "rec.jsonl").write_text(json.dumps({"who": who}) + "\n", encoding="utf-8")
        (top / f"{who}-marker").write_text("", encoding="utf-8")
        (top / "fa" / f"{who}-only").write_text("", encoding="utf-8")
        trees.append(top)
    return trees[0], trees[1]


def _race_op(view: Any, op: str) -> Any:
    return {
        "read-top": lambda: view.read("rec.txt"),
        "read-deep": lambda: view.read("fa/rec.jsonl"),
        "read_jsonl": lambda: view.read_jsonl("fa/rec.jsonl"),
        "entries-root": lambda: view.entries(),
        "entries-under": lambda: view.under("fa").entries(),
    }[op]()


def _answered_root(op: str, got: Any) -> None:
    if op == "read-top":
        assert got.text == "ROOT\n", f"the in-flight read answered {got!r}, not the root's bytes"
    elif op == "read-deep":
        assert got.text == json.dumps({"who": "root"}) + "\n", f"the in-flight read: {got!r}"
    elif op == "read_jsonl":
        assert got[0] == [{"who": "root"}], f"the in-flight read_jsonl answered {got!r}"
    elif op == "entries-root":
        assert got.entries is not None, f"the in-flight listing was refused: {got!r}"
        assert "root-marker" in got.entries, f"the in-flight listing is not the root's: {got!r}"
        assert "decoy-marker" not in got.entries, f"the listing is the decoy's: {got!r}"
    else:
        assert got.files() == ["rec.jsonl", "root-only"], (
            f"the in-flight listing of fa/ is not the root's: {got!r}")


def _refused_as_closed(op: str, got: Any) -> None:
    rec = got[2] if op == "read_jsonl" else got
    payload = rec.entries if op.startswith("entries") else rec.text
    assert payload is None, f"a {op} after close answered {got!r}"
    assert rec.reason == os.strerror(errno.EBADF), (
        f"a {op} after close is not refused as a closed descriptor: {got!r}")


@pytest.mark.parametrize("op", _RACE_OPS)
def test_r1_a_view_read_in_flight_when_close_lands_answers_the_root_never_the_reused_number(
        tmp_path, op):
    """R1 (C24): the view read `_handle.fd` twice with no lock. Now every `Bound` read works off
    a private dup taken under the handle's lock. `close()` lands mid-read — fired through the
    `os_` seam just before the read's first relative operation — returns promptly, and releases
    the root's descriptor; that number is then taken by a DECOY folder of the same shape
    (`dup2`), as the next open in a live process would take it. The read still answers the
    ROOT's bytes or names, never the decoy's; the reused number still names the decoy afterwards.

    Then a read after `close()` answers refused (`Bad file descriptor`) — never the decoy that
    now sits on the old number, never an exception."""
    root, decoy = _race_trees(tmp_path)
    spy = S.OsSpy()
    held = S.hold(root, os_=spy)
    view = held.view()
    [root_fd] = S.open_fds_on(root)
    state: dict[str, Any] = {}

    def close_mid_read(_op: str, _args: tuple, _kwargs: dict) -> None:
        spy.hook = None
        state["closed_promptly"] = S.run_in_thread(held.close, timeout=1.0)
        if not state["closed_promptly"]:
            return
        state["open_after_close"] = S.open_fds_on(root)
        if root_fd not in state["open_after_close"]:
            fd = os.open(decoy, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            if fd != root_fd:
                os.dup2(fd, root_fd, inheritable=False)
                os.close(fd)
            state["decoy_on"] = root_fd

    spy.hook = close_mid_read
    try:
        got = _race_op(view, op)
        assert "closed_promptly" in state, f"the view's {op} made no relative operation"
        assert state["closed_promptly"], "close() waited for the read in flight"
        assert "decoy_on" in state, (
            f"close() released nothing while a read ran: {state.get('open_after_close')}")
        _answered_root(op, got)
        assert S.inode(decoy) == (os.fstat(root_fd).st_dev, os.fstat(root_fd).st_ino), (
            "something closed or replaced the reused descriptor number")

        _refused_as_closed(op, S.in_time(lambda: _race_op(view, op)))
    finally:
        if "decoy_on" in state:
            os.close(state["decoy_on"])
        held.close()


@pytest.mark.parametrize("op", _RACE_OPS)
def test_r1_a_close_landing_as_the_view_takes_its_dup_never_redirects_the_read(tmp_path, op):
    """The view's dup and the close are one critical section (`_Handle.dup()` and
    `_Handle.close()` take one lock). Just as the read asks for its dup (the `os_` seam's `dup`,
    handed the root's number), `close()` starts on another thread with a grace period. Had the
    read taken the root's number outside `close`'s lock, that close would finish within the
    grace period and free the number the read is about to dup — which a DECOY then takes. The
    read must still answer the ROOT, and the close completes once the read holds its dup."""
    root, decoy = _race_trees(tmp_path)
    spy = S.OsSpy()
    held = S.hold(root, os_=spy)
    view = held.view()
    state: dict[str, Any] = {}

    def close_at_dup(fd: int) -> None:
        closer = threading.Thread(target=held.close, daemon=True)
        closer.start()
        closer.join(0.5)
        state["closer"] = closer
        if not closer.is_alive():
            taken = os.open(decoy, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            if taken != fd:
                os.dup2(taken, fd, inheritable=False)
                os.close(taken)
            state["decoy_on"] = fd

    spy.before_dup = close_at_dup
    try:
        got = _race_op(view, op)
        assert "closer" in state, f"the view's {op} took no dup of the root through its os_ seam"
        state["closer"].join(S.DEADLINE)
        assert not state["closer"].is_alive(), "close() never completed once the read had its dup"
        _answered_root(op, got)
    finally:
        if "decoy_on" in state:
            os.close(state["decoy_on"])
        held.close()


# ---- merge_review over a refused record ---------------------------------------------------

REFUSED_REVIEWS = ("symlink", "dangling", "hardlink", "fifo", "directory", "undecodable")


@pytest.mark.parametrize("kind", REFUSED_REVIEWS)
def test_r1_merge_review_over_a_refused_record_is_staging_refused_and_writes_nothing(
        tmp_path, host, kind):
    """`merge_review(episode, key, block)` reads `review.yaml` through the episode's view. A
    REFUSED record — a link (live or dangling), a hard link, a FIFO, a directory, or a plain file
    whose bytes are not UTF-8 — is `StagingRefused` naming the view's reason, and nothing is
    written: the record is never replaced by the merge (today undecodable bytes are silently
    overwritten with a fresh document). Control on the same address: a plain mapping merges,
    keeping every other key."""
    staging = mod("learning.branch.staging")
    ep = bare_episode(tmp_path)
    planted = plant_record(ep / LAYOUT.review, kind, host=host)
    reason = view_reason(ep, LAYOUT.review)
    before = S.census(tmp_path)

    with S.open_episode(ep) as episode:
        raised = S.raised_by(lambda: staging.merge_review(episode, "episode", {"outcome": "x"}),
                             fifo=planted.fifo)
    assert isinstance(raised, staging.StagingRefused), (
        f"merge_review over a {kind} review record: {raised!r}")
    assert reason in str(raised), f"the refusal does not name the view's reason ({reason!r}): {raised}"
    assert S.census(tmp_path) == before, f"merge_review over a {kind} changed the tree"

    planted.remove()
    (ep / LAYOUT.review).write_text(yaml.safe_dump({"worlds": {"b": {"decision": "accepted"}}}),
                                    encoding="utf-8")
    with S.open_episode(ep) as episode:
        staging.merge_review(episode, "episode", {"outcome": "x"})
    assert yaml.safe_load((ep / LAYOUT.review).read_text(encoding="utf-8")) == {
        "worlds": {"b": {"decision": "accepted"}}, "episode": {"outcome": "x"}}


@pytest.mark.parametrize("state", ["absent", "not-yaml", "not-a-mapping", "empty"])
def test_r1_merge_review_starts_from_nothing_over_an_absent_or_unparseable_record(
        tmp_path, state):
    """Controls for the refusal above: an ABSENT record starts from `{}`, and so does a present
    one that is not parseable as a YAML mapping (as on main) — the merge lands as a plain,
    single-linked record holding only the merged block."""
    staging = mod("learning.branch.staging")
    ep = bare_episode(tmp_path)
    review = ep / LAYOUT.review
    if state != "absent":
        review.write_text({"not-yaml": "episode: [unclosed\n", "not-a-mapping": "- a\n- b\n",
                           "empty": ""}[state], encoding="utf-8")
    with S.open_episode(ep) as episode:
        staging.merge_review(episode, "teardown", {"ok": True})
    assert yaml.safe_load(review.read_text(encoding="utf-8")) == {"teardown": {"ok": True}}
    assert stat.S_ISREG(os.lstat(review).st_mode)
    assert os.lstat(review).st_nlink == 1


class StuckDoor:
    """The staging door, faked: every delete returns, but the name is still there after."""

    def __init__(self) -> None:
        self.deleted: list[str] = []

    def delete(self, name: str) -> None:
        self.deleted.append(name)

    def exists(self, name: str) -> bool:
        return True


def _staged_episode(ep: Path) -> None:
    with S.open_episode(ep) as episode:
        episode.staged.create("# staged names\n")
        mod("learning.branch.staging").record_staged(
            episode, {"name": STAGED_NAME, "kind": "index", "world": "b"})


@pytest.mark.parametrize("kind", ["plain", "symlink", "undecodable"])
def test_r1_a_teardown_failure_over_a_refused_review_carries_the_names_and_the_refusal(
        tmp_path, host, kind):
    """`teardown` records its unverified names in the review record, then raises. When that
    record is REFUSED (a link, undecodable bytes), the refused merge does not hide the teardown
    failure: the raised `StagingRefused` carries both the unverified names and the merge's
    refusal, and the record is left as it was.

    Control on the same address (`plain`): the names are merged into the review record under
    `teardown`, and the raised `StagingRefused` names them."""
    staging = mod("learning.branch.staging")
    ep = bare_episode(tmp_path)
    _staged_episode(ep)
    review = ep / LAYOUT.review
    if kind == "plain":
        review.write_text(yaml.safe_dump({"worlds": {"b": {"decision": "accepted"}}}),
                          encoding="utf-8")
    else:
        plant_record(review, kind, host=host)
        reason = view_reason(ep, LAYOUT.review)
    before = S.census(tmp_path)
    door = StuckDoor()

    with S.open_episode(ep) as episode:
        raised = S.raised_by(lambda: staging.teardown(episode, door=door))

    assert door.deleted == [STAGED_NAME], door.deleted
    assert isinstance(raised, staging.StagingRefused), f"teardown over a {kind} review: {raised!r}"
    assert STAGED_NAME in str(raised), f"the teardown failure lost its names: {raised}"
    if kind == "plain":
        doc = yaml.safe_load(review.read_text(encoding="utf-8"))
        assert doc["worlds"] == {"b": {"decision": "accepted"}}
        assert doc["teardown"]["names"] == [STAGED_NAME], doc
        return
    assert reason in str(raised), (
        f"the teardown failure does not carry the review record's refusal ({reason!r}): {raised}")
    assert S.census(tmp_path) == before, f"teardown wrote over a {kind} review record"


@pytest.mark.parametrize("kind", ["plain", "undecodable"])
def test_r1_an_aborting_teardown_over_a_refused_review_does_not_say_the_names_are_in_it(
        tmp_path, caplog, kind):
    """While an abort is in flight the launcher logs a teardown failure instead of raising it,
    and says where the unverified names are. With the review record REFUSED they are not in it:
    the line carries the names and does not claim they are "in the review record". Control on
    the same address (`plain`): the names were merged, and the line says so."""
    cli = mod("learning.branch.cli")
    ep = bare_episode(tmp_path)
    _staged_episode(ep)
    review = ep / LAYOUT.review
    if kind == "plain":
        review.write_text("worlds: {}\n", encoding="utf-8")
    else:
        review.write_bytes(UNDECODABLE)
    caplog.set_level(logging.ERROR)

    with S.open_episode(ep) as episode:
        cli._teardown_without_masking(episode, StuckDoor(), aborting=True)

    lines = [r.getMessage() for r in caplog.records
             if r.levelno >= logging.ERROR and "teardown" in r.getMessage()]
    assert len(lines) == 1, f"the aborting teardown's failure was not logged once: {lines}"
    [line] = lines
    assert STAGED_NAME in line, f"the logged failure does not carry the names: {line}"
    if kind == "plain":
        assert "review record" in line, line
        assert yaml.safe_load(review.read_text(encoding="utf-8"))["teardown"]["names"] == [
            STAGED_NAME]
    else:
        assert "are in the review record" not in line, (
            f"the line claims the names are in a review record that was refused: {line}")
        assert review.read_bytes() == UNDECODABLE


def _siblings(ep: Path) -> list[Path]:
    return [T.sibling_run_dir(ep / "runs", w) for w in T.WORLDS]


@pytest.mark.parametrize("kind", ["symlink", "undecodable"])
def test_r1_an_archive_refusal_stays_the_raised_one_with_a_refused_merge_attached_as_a_note(
        tmp_path, host, kind):
    """`verify_family` records `incomplete` before re-raising an archive refusal. With the
    review record REFUSED, that merge is refused too: the ARCHIVE's exception stays the one
    raised (the same type and message as with a plain record), the merge's refusal is attached
    to it as a note, and the record is left as it was (declared: readers then find no recorded
    outcome).

    Control on the same address, the same archive refusal: with a plain record the same
    exception is raised and the record carries `incomplete`."""
    cli = mod("learning.branch.cli")
    staging = mod("learning.branch.staging")
    ep = T.episode(tmp_path)
    dirs = _siblings(ep)
    (ep / "worlds").mkdir()
    link_folder(ep / "worlds" / "a", reach="inside", ep=ep, host=host, keep={"keep": b"kept\n"})
    review = ep / LAYOUT.review
    plant_record(review, kind, host=host)
    reason = view_reason(ep, LAYOUT.review)
    before = S.census(review.parent / "elsewhere-a"), (
        os.readlink(review) if review.is_symlink() else review.read_bytes())

    with S.open_episode(ep) as episode:
        raised = S.raised_by(lambda: cli.verify_family(episode, dirs,
                                                       source=T.provenance_record()))
    assert raised is not None, "verify_family did not raise over a refused archive"
    assert not isinstance(raised, staging.StagingRefused), (
        f"the merge's refusal displaced the archive's: {raised!r}")
    S.assert_refusal(S.refusal_in(raised), "folder_link_inside",
                     where="the archive under a refused review record")
    notes = getattr(raised, "__notes__", [])
    assert any(reason in note for note in notes), (
        f"the refused merge ({reason!r}) is not attached to the archive's exception: {notes}")
    assert (S.census(review.parent / "elsewhere-a"),
            os.readlink(review) if review.is_symlink() else review.read_bytes()) == before

    if review.is_symlink() or review.is_file():
        review.unlink()
    review.write_text("worlds: {}\n", encoding="utf-8")
    with S.open_episode(ep) as episode:
        control = S.raised_by(lambda: cli.verify_family(episode, dirs,
                                                        source=T.provenance_record()))
    assert type(control) is type(raised), f"the archive raised {control!r}, not {raised!r}"
    assert str(control) == str(raised), f"the archive raised {control!r}, not {raised!r}"
    assert yaml.safe_load(review.read_text(encoding="utf-8"))["episode"]["outcome"] == (
        "incomplete")


@pytest.mark.parametrize("kind", ["plain", "symlink", "undecodable"])
def test_r1_a_completed_familys_outcome_over_a_refused_review_ends_as_a_refusal(
        tmp_path, host, kind):
    """Elsewhere (`_record_episode_outcome` after a completed family) a refused merge raises:
    `verify_family` over clean siblings, with the review record refused, is `StagingRefused`
    naming the reason, and the record is left as it was (today undecodable bytes are replaced
    and the family reads as accepted). Control on the same address (`plain`): the outcome
    `accepted` is merged into the record."""
    cli = mod("learning.branch.cli")
    staging = mod("learning.branch.staging")
    ep = T.episode(tmp_path)
    dirs = _siblings(ep)
    review = ep / LAYOUT.review
    if kind == "plain":
        review.write_text("worlds: {}\n", encoding="utf-8")
    else:
        plant_record(review, kind, host=host)
        reason = view_reason(ep, LAYOUT.review)
    before = os.readlink(review) if review.is_symlink() else review.read_bytes()

    with S.open_episode(ep) as episode:
        raised = S.raised_by(lambda: cli.verify_family(episode, dirs,
                                                       source=T.provenance_record()))
    if kind == "plain":
        assert raised is None, raised
        assert yaml.safe_load(review.read_text(encoding="utf-8"))["episode"]["outcome"] == (
            "accepted")
        return
    assert isinstance(raised, staging.StagingRefused), (
        f"a completed family's outcome over a {kind} review record: {raised!r}")
    assert reason in str(raised), raised
    assert (os.readlink(review) if review.is_symlink() else review.read_bytes()) == before


# ---- delta_o: one bind for the pass ------------------------------------------------------

def _delta_episode(tmp_path: Path) -> Path:
    """An accepted episode with a base world `a` and a world `b`, both archived; the base
    captures k1 and k2, and `b` served k1 the same and k2 differently."""
    doc = T.family_doc(worlds=[T.base_world(), T.world_doc("b")])
    ep = T.episode(tmp_path, doc=doc)
    for label in ("a", "b"):
        T.archived_world(ep, label)
    T.base_capture(ep, [T.captured_row(key="k1"), T.captured_row(key="k2")])
    _world_file(ep, "b").write_text(
        json.dumps(T.captured_row(key="k1")) + "\n"
        + json.dumps(T.captured_row(key="k2", payload={"hits": [{"_id": "other"}]})) + "\n",
        encoding="utf-8")
    return ep


def _world_file(ep: Path, label: str) -> Path:
    return ep / LAYOUT.served_world(T.world_token(label))


def episode_mod() -> Any:
    return mod("learning.branch.episode")


@pytest.mark.parametrize("base", ["absent", "symlink", "fifo"])
def test_r1_delta_o_with_no_archived_worlds_is_empty_before_the_base_is_read(tmp_path, host,
                                                                             base):
    """No archived worlds is `{}`, answered before the base is read (as on main): with no
    worlds, an absent or refused base — which is "no primed base" once there are worlds —
    changes nothing. Pinned to keep holding."""
    ep = T.episode(tmp_path)
    at = ep / LAYOUT.served_base
    at.unlink()
    fifo = None
    if base != "absent":
        fifo = S.plant_leaf(at, base, host=host).fifo
    assert S.in_time(lambda: episode_mod().delta_o(ep), fifo=fifo) == {}


@pytest.mark.parametrize("kind", ["absent", "symlink", "dangling", "hardlink", "fifo",
                                  "directory"])
def test_r1_delta_o_refuses_an_absent_or_refused_base_as_no_primed_base(tmp_path, host, kind):
    """With archived worlds, the base is read through the pass's one bind
    (`read_jsonl(LAYOUT.served_base)`): an absent base, or one the open refuses (a link, a hard
    link, a FIFO, a directory), is `LedgerError` ("no primed base"), restoring main's refusal —
    today it answers every world as if the base had captured nothing. Control on the same
    address: a plain base classifies `b`'s keys."""
    ledger = mod("learning.branch.ledger")
    ep = _delta_episode(tmp_path)
    at = ep / LAYOUT.served_base
    good = at.read_bytes()
    at.unlink()
    planted = None if kind == "absent" else S.plant_leaf(at, kind, host=host, body=good)
    before = S.census(ep)

    raised = S.raised_by(lambda: episode_mod().delta_o(ep),
                         fifo=planted.fifo if planted else None)
    assert isinstance(raised, ledger.LedgerError), f"delta_o over a {kind} base: {raised!r}"
    assert "no primed base" in str(raised), raised
    assert S.census(ep) == before

    if planted is not None:
        planted.remove()
    at.write_bytes(good)
    out = episode_mod().delta_o(ep)
    assert out["b"]["k1"] == "same", out
    assert "k2" in out["b"], out


@pytest.mark.parametrize("kind", ["symlink", "dangling", "hardlink", "fifo", "directory"])
def test_r1_delta_o_refuses_a_refused_world_file_naming_it(tmp_path, host, kind):
    """Each world's served file is read through the same bind
    (`read_jsonl(LAYOUT.served_world(token))`): one the open refuses (a link, a hard link, a
    FIFO, a directory) is `EpisodeError` naming it (declared: main read a link there as "served
    nothing"). The control rows are the next test's."""
    ep = _delta_episode(tmp_path)
    at = _world_file(ep, "b")
    good = at.read_bytes()
    at.unlink()
    planted = S.plant_leaf(at, kind, host=host, body=good)

    raised = S.raised_by(lambda: episode_mod().delta_o(ep), fifo=planted.fifo)
    assert isinstance(raised, episode_mod().EpisodeError), (
        f"delta_o over a {kind} world file: {raised!r}")
    assert at.name in str(raised), f"the refusal does not name {at.name}: {raised}"


@pytest.mark.parametrize("state", ["absent", "undecodable", "plain"])
def test_r1_delta_o_reads_an_absent_world_file_as_serving_nothing(tmp_path, state):
    """Controls for the refusal above, on the same address: an ABSENT world file is `{}` for that
    world (it served nothing), and undecodable bytes are not a refusal on the JSONL lane (it
    reads with replacement: the good row still classifies); a plain file classifies."""
    ep = _delta_episode(tmp_path)
    at = _world_file(ep, "b")
    if state == "absent":
        at.unlink()
    elif state == "undecodable":
        at.write_bytes(b"\xff\xfe not a row\n" + json.dumps(T.captured_row(key="k1")).encode()
                       + b"\n")
    out = episode_mod().delta_o(ep)
    if state == "absent":
        assert out["b"] == {}, out
    else:
        assert out["b"]["k1"] == "same", out


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo", "undecodable"])
def test_r1_delta_os_incomplete_gate_refuses_a_refused_review_record(tmp_path, host, kind):
    """The incomplete-outcome gate (`_recorded_outcome`, shared with `verdicts`) treats a
    REFUSED `review.yaml` — a link, a hard link, a FIFO, undecodable bytes — as `EpisodeError`,
    not as "no outcome recorded" (declared: today a link there skips the gate). Controls on the
    same address: an absent record and an unparseable one gate nothing; a recorded `incomplete`
    refuses."""
    ep = _delta_episode(tmp_path)
    review = ep / LAYOUT.review
    planted = plant_record(review, kind, host=host)

    raised = S.raised_by(lambda: episode_mod().delta_o(ep), fifo=planted.fifo)
    assert isinstance(raised, episode_mod().EpisodeError), (
        f"delta_o past a {kind} review record: {raised!r}")

    planted.remove()
    assert episode_mod().delta_o(ep)["b"]["k1"] == "same"
    review.write_text("episode: [unclosed\n", encoding="utf-8")
    assert episode_mod().delta_o(ep)["b"]["k1"] == "same"
    review.write_text(yaml.safe_dump({"episode": {"outcome": "incomplete", "reason": "r"}}),
                      encoding="utf-8")
    with pytest.raises(episode_mod().EpisodeError):
        episode_mod().delta_o(ep)


@pytest.mark.parametrize("via", ["bind", "episode-view", "delta_o"])
@pytest.mark.parametrize("state", ["absent", "symlink", "undecodable"])
def test_r1_load_family_through_a_view_names_family_yaml_never_a_path(tmp_path, host, via,
                                                                      state):
    """The manifest readers take a view: `load_family(view)` — the episode's own
    `episode.view()`, or a reader's own `bind` (`delta_o`'s one bind among them). An absent or
    refused manifest is `FamilyError`; a `Bound` holds no path, so the message names the record
    (`family.yaml`) and no absolute path. Control on the same address: a plain manifest loads."""
    fam = mod("runtime.branch._family")
    ep = _delta_episode(tmp_path)
    manifest = ep / LAYOUT.family
    good = manifest.read_bytes()
    manifest.unlink()
    planted = None if state == "absent" else plant_record(manifest, state, host=host)

    def load() -> Any:
        if via == "delta_o":
            return episode_mod().delta_o(ep)
        if via == "bind":
            with _io.bind(ep) as view:
                return fam.load_family(view)
        with S.open_episode(ep) as episode:
            return fam.load_family(episode.view())

    raised = S.raised_by(load)
    assert isinstance(raised, fam.FamilyError), f"{via} over a {state} manifest: {raised!r}"
    assert str(LAYOUT.family) in str(raised), f"the refusal does not name family.yaml: {raised}"
    assert str(tmp_path) not in str(raised), f"the refusal names an absolute path: {raised}"

    if planted is not None:
        planted.remove()
    manifest.write_bytes(good)
    got = load()
    if via == "delta_o":
        assert got["b"]["k1"] == "same"
    else:
        assert got.episode_id == T.EPISODE_ID


# =======================================================================================
# R2 — the core's leaf refusal is its own exception class
# =======================================================================================

def test_r2_not_plain_entry_is_an_oserror_and_the_errno_classifier_is_gone():
    """`_io.NotPlainEntry` subclasses `OSError`, so every existing catcher keeps catching it;
    `is_not_plain_refusal` (the errno classifier that read a linked folder as a planted leaf)
    is removed."""
    cls = S.not_plain_entry()
    assert issubclass(cls, OSError)
    assert not hasattr(_io, "is_not_plain_refusal"), (
        "`_io.is_not_plain_refusal` is still there: containment catches the class (R2)")


@pytest.mark.parametrize("lane", ["held", "rooted_write", "write_guarded"])
@pytest.mark.parametrize("kind", S.LEAF_PLANTS)
def test_r2_a_plant_at_the_name_is_not_plain_entry_keeping_its_errno_and_mark(
        tmp_path, lane, kind):
    """The leaf refusal — `_refuse_unless_plain_stat` and `_open_refusal`'s link and non-plain
    rows — is `NotPlainEntry`, with today's errno (ELOOP; EMLINK for a hard link) and
    `write_guarded_alias` mark (so `hooks/budget_enforcer.py` keeps counting it): on the held
    root, on `rooted_write` (the `Run` lane) and on the path seam `write_guarded`. Control on the
    same address: the plant removed, the write lands."""
    root = tmp_path / "root"
    (root / "fa").mkdir(parents=True)
    host = tmp_path / "host"
    host.mkdir()
    rel = "fa/rec.txt"
    planted = S.plant_leaf(root / rel, kind, host=host)

    def write(text: str) -> None:
        if lane == "held":
            with S.hold(root) as held:
                held.write(rel, text, mode="replace")
        elif lane == "rooted_write":
            _io.rooted_write(root, rel, text, mode="replace")
        else:
            _io.write_guarded(root / rel, text, mode="replace")

    raised = S.raised_by(lambda: write("refused\n"), fifo=planted.fifo)
    S.assert_refusal(raised, "symlink" if kind == "dangling" else kind,
                     where=f"{lane} into a {kind}")
    planted.remove()
    write("landed\n")
    assert (root / rel).read_text(encoding="utf-8") == "landed\n"


@pytest.mark.parametrize("kind", ["folder_link_outside", "folder_link_inside", "folder_file",
                                  "folder_fifo"])
def test_r2_a_linked_or_non_directory_folder_on_the_way_is_not_the_leaf_class(tmp_path, kind):
    """A linked or non-directory FOLDER on the way stays a plain `OSError(ELOOP)` /
    `NotADirectoryError` from the walk — never `NotPlainEntry`, so containment keyed on the
    class does not swallow it. Control on the same address: a real folder takes the write."""
    cls = S.not_plain_entry()
    root = tmp_path / "root"
    root.mkdir()
    host = tmp_path / "host"
    host.mkdir()
    rel = PurePosixPath("fa/rec.txt")
    planted = S.plant_folder(root, rel, PurePosixPath("fa"), kind, host=host)
    with S.hold(root) as held:
        raised = S.raised_by(lambda: held.write(str(rel), "x\n", mode="replace"),
                             fifo=planted.fifo)
        assert raised is not None, f"a {kind} on the way was not refused"
        assert not isinstance(raised, cls), f"a {kind} on the way raised the leaf class: {raised!r}"
        S.assert_refusal(raised, kind, where=f"Held.write through a {kind}")
        planted.remove()
        held.write(str(rel), "x\n", mode="replace")
    assert (root / rel).read_text(encoding="utf-8") == "x\n"


# ---- R2 at the judge's stale-draw removal (S1) -------------------------------------------

class SwappingJudge:
    """The judge seam: a malformed reply for `judge:b:0` (after `act()` runs once, a plant made
    mid-pass), a good reply for every other call; each agent id recorded."""

    def __init__(self, act: Any = None) -> None:
        self.good = J.as_reply_text(J.reply_doc())
        self.bad = J.as_reply_text(J.reply_doc(), malformed="lookalike-bucket")
        self.act = act
        self.agent_ids: list[str] = []

    def __call__(self, prompt: str, *, role: Any = None, agent_id: str = "judge",
                 **kw: Any) -> str:
        self.agent_ids.append(agent_id)
        if agent_id == "judge:b:0":
            if self.act is not None:
                act, self.act = self.act, None
                act()
            return self.bad
        return self.good

    def called_for(self, label: str) -> list[str]:
        return [a for a in self.agent_ids if a.startswith(f"judge:{label}:")]


def _grade(tmp_path: Path, ep: Path, judge: Any) -> Any:
    try:
        return J.mod("learning.judge").grade_episode(
            ep, judge=judge, runs_base=tmp_path / "defender-runs", draws=2)
    except Exception as refused:  # noqa: BLE001 — the refusal is the observation
        return refused


@pytest.mark.parametrize("reach", ["outside", "inside"])
def test_r2_a_judge_folder_linked_after_its_ensure_stops_the_pass_at_the_stale_draw_removal(
        tmp_path, roots, host, reach):
    """At the judge (S1), a `judge/` folder linked AFTER `draws.ensure()` — swapped in by the
    judge seam's first call for world `b`, whose reply is malformed — makes the stale-draw
    removal (`world.draw(0).delete()`) raise the walk's FOLDER refusal, a plain `OSError(ELOOP)`
    that is not `NotPlainEntry`, which stops the pass: `JudgeRefused`, draw 1 never paid for,
    the stale draw the link reaches not removed, the link left. Today the errno classifier
    contains it as a planted leaf and the loop pays for draw 1 before the write refuses.

    Control on the same address: the link removed, a regrade pays for both draws and writes
    them into a real `judge/`. (A `judge/` linked BEFORE the pass is that world's setup fault at
    `draws.ensure()`: `test_1133_entry_points`.)"""
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []})
    judge_dir = ep / "worlds" / "b" / "judge"
    stale = b"findings: [{bucket: stale}]\n"
    reached: dict[str, Path] = {}

    def swap() -> None:
        reached["dir"] = link_folder(judge_dir, reach=reach, ep=ep, host=host,
                                     keep={"0.yaml": stale})

    judge = SwappingJudge(act=swap)
    got = _grade(tmp_path, ep, judge)

    assert "dir" in reached, "the pass never reached world b's first draw"
    assert isinstance(got, J.mod("learning.judge").JudgeRefused), (
        f"a judge/ folder linked mid-pass did not stop the pass: {got!r}")
    S.assert_refusal(S.refusal_in(got), f"folder_link_{reach}",
                     where="the stale-draw removal through a linked judge/")
    assert judge.called_for("b") == ["judge:b:0"], (
        f"the pass went on past a linked judge/ folder: {judge.called_for('b')}")
    assert (reached["dir"] / "0.yaml").read_bytes() == stale, "a draw was removed through the link"
    assert judge_dir.is_symlink(), "the link at judge/ was removed"

    judge_dir.unlink()
    (ep / LAYOUT.judge).unlink(missing_ok=True)
    judge = SwappingJudge()
    got = _grade(tmp_path, ep, judge)
    assert not isinstance(got, BaseException), f"the control pass was refused: {got!r}"
    assert judge.called_for("b") == ["judge:b:0", "judge:b:1"]
    assert sorted(p.name for p in judge_dir.iterdir()) == ["1.yaml"]


# ---- R2 at the priming claim and the primed base -----------------------------------------

def _swap_served_before(ep: Path, rel: PurePosixPath, *, reach: str, host: Path,
                        state: dict[str, Any]) -> Any:
    """A `RecordingHeld` `before` hook: just before the held root delegates the `write` of
    `rel`, `served/` (real, made by the `ensure` or present for the listing) is swapped for a
    link to a real folder elsewhere."""
    def before(method: str, args: tuple, kwargs: dict) -> None:
        name = args[0] if args else kwargs.get("name")
        if method == "write" and S.as_rel(name) == rel and "reached" not in state:
            state["reached"] = link_folder(ep / "served", reach=reach, ep=ep, host=host,
                                           keep={})
    return before


@pytest.mark.parametrize("reach", ["outside", "inside"])
def test_r2_a_served_folder_linked_after_its_ensure_is_the_folder_refusal_at_the_claim(
        tmp_path, host, reach):
    """At priming, `served.ensure()` refuses a `served/` linked beforehand (plain ELOOP). One
    swapped in AFTER it — here just before the claim's create is delegated, through a recording
    `Held` behind the episode's `io=` seam (`prepare_episode` has none, so its claim body
    `cli._prime_once` is driven on that episode) — is the core's FOLDER refusal at the claim,
    raised as is: not "another launcher is priming" (today's errno classifier reads it as an
    occupied claim). The primer never runs and the linked folder gains no claim.

    Controls on the same address: a symlink planted at the claim's own name is the leaf class
    and IS "another launcher is priming"; with nothing planted the primer runs and the claim is
    released."""
    cli = mod("learning.branch.cli")
    ledger = mod("learning.branch.ledger")
    ep = bare_episode(tmp_path)
    state: dict[str, Any] = {}
    ran: list[Any] = []

    def prime(_source: Path, _episode: Any) -> Any:
        ran.append(True)
        return mod("learning.branch.capture").PrimeReport(primed=1)

    io = S.RecordingIo(before=_swap_served_before(ep, LAYOUT.priming_lock, reach=reach,
                                                  host=host, state=state))
    with S.open_episode(ep, io=io) as episode:
        raised = S.raised_by(lambda: cli._prime_once(episode, EPISODE_ID, tmp_path / "src",
                                                     prime))
    assert "reached" in state, "the claim was never created through the held root"
    assert not isinstance(raised, ledger.LedgerError), (
        f"a served/ linked after its ensure was read as an occupied claim: {raised!r}")
    S.assert_refusal(raised, f"folder_link_{reach}", where="the claim through a linked served/")
    assert ran == [], "the primer ran past a refused claim"
    assert list(state["reached"].iterdir()) == [], "the claim was made through the link"

    (ep / "served").unlink()
    (ep / "served").mkdir()
    (ep / LAYOUT.priming_lock).symlink_to(host / "claim-target")
    with S.open_episode(ep) as episode, pytest.raises(
            ledger.LedgerError, match="another launcher is priming"):
        cli._prime_once(episode, EPISODE_ID, tmp_path / "src", prime)
    (ep / LAYOUT.priming_lock).unlink()
    with S.open_episode(ep) as episode:
        cli._prime_once(episode, EPISODE_ID, tmp_path / "src", prime)
    assert ran == [True]
    assert not os.path.lexists(ep / LAYOUT.priming_lock)


@pytest.mark.parametrize("reach", ["outside", "inside"])
def test_r2_a_served_folder_linked_after_the_listing_is_the_folder_refusal_at_the_base(
        tmp_path, host, reach):
    """At the primed base, a `served/` swapped for a link AFTER the listing found no base —
    just before the base's create is delegated, through a recording `Held` — is the core's
    FOLDER refusal, raised as is: not "already holds a primed base" (today's errno classifier
    reads a linked folder as a planted base), and the linked folder gains no base.

    Control on the same address: nothing swapped, the base is primed."""
    capture = mod("learning.branch.capture")
    ledger = mod("learning.branch.ledger")
    run_dir = _one_call_source(tmp_path)
    ep = bare_episode(tmp_path)
    (ep / "served").mkdir()
    state: dict[str, Any] = {}

    io = S.RecordingIo(before=_swap_served_before(ep, LAYOUT.served_base, reach=reach,
                                                  host=host, state=state))
    with S.open_episode(ep, io=io) as episode:
        raised = S.raised_by(lambda: capture.prime_base(run_dir, episode))
    assert "reached" in state, "the base was never created through the held root"
    assert not isinstance(raised, ledger.LedgerError), (
        f"a served/ linked after the listing was read as an existing base: {raised!r}")
    S.assert_refusal(raised, f"folder_link_{reach}", where="the base through a linked served/")
    assert list(state["reached"].iterdir()) == [], "the base was written through the link"

    (ep / "served").unlink()
    (ep / "served").mkdir()
    with S.open_episode(ep) as episode:
        assert capture.prime_base(run_dir, episode).primed == 1


# =======================================================================================
# R3 — one primer, one write
# =======================================================================================

def _one_call_source(tmp_path: Path) -> Path:
    run_dir = source_run(tmp_path)
    append_call(run_dir, call_row("l-001", 0, "cmdb", "get-host", {"host": "canary-1"}),
                json.dumps({"owner": "estate", "role": "canary"}))
    return run_dir


def _empty_source(tmp_path: Path) -> Path:
    run_dir = source_run(tmp_path)
    (run_dir / "executed_queries.jsonl").write_text("", encoding="utf-8")
    return run_dir


def fifo_sidecar(run_dir: Path) -> tuple[Path, bytes]:
    """Turn the one captured call's payload sidecar into a FIFO, which the capture read opens
    (`_captured_call` -> `read_text_soft` blocks on it). Answers the FIFO and the payload it
    stood for."""
    sidecar = run_dir / "gather_raw" / "l-001" / "0.json"
    payload = sidecar.read_bytes()
    sidecar.unlink()
    os.mkfifo(sidecar)
    return sidecar, payload


class CaptureRead:
    """Makes reading the capture observable, over `fifo_sidecar`'s FIFO: a watcher sees a
    reader arrive (its non-blocking write-open stops failing `ENXIO`), records it, and hands the
    reader the payload, so a read completes as it would have. Used as a context manager, once
    per call under observation."""

    def __init__(self, sidecar: Path, payload: bytes) -> None:
        self.sidecar = sidecar
        self.payload = payload
        self.read = threading.Event()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._watch, daemon=True)

    def __enter__(self) -> CaptureRead:
        self._thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self._stop.set()
        self._thread.join(S.DEADLINE)

    def _watch(self) -> None:
        while not self._stop.is_set():
            try:
                fd = os.open(self.sidecar, os.O_WRONLY | os.O_NONBLOCK)
            except OSError as e:
                if e.errno != errno.ENXIO:
                    return
                time.sleep(0.002)
                continue
            self.read.set()
            try:
                os.write(fd, self.payload)
            finally:
                os.close(fd)
            return


BASE_KINDS = ("plain", "empty", "symlink", "dangling", "hardlink", "fifo", "directory")


def _plant_base(ep: Path, kind: str, host: Path) -> S.Planted:
    at = ep / LAYOUT.served_base
    at.parent.mkdir(parents=True, exist_ok=True)
    if kind in ("plain", "empty"):
        at.write_bytes(b'{"an": "earlier prime"}\n' if kind == "plain" else b"")
        return S.Planted("file", at)
    return S.plant_leaf(at, kind, host=host)


@pytest.mark.parametrize("kind", BASE_KINDS)
def test_r3_anything_at_the_base_is_already_primed_before_the_capture_is_read(tmp_path, host,
                                                                              kind):
    """`prime_base` lists `served/` through the view first: an entry named `base.jsonl` of any
    kind — a plain file, an empty one, a link (live or dangling), a hard link, a FIFO, a
    directory — is "already holds a primed base" `LedgerError` BEFORE the capture is read (a FIFO
    at the capture's payload sidecar sees no reader), without the base being opened (no open of
    `base.jsonl` reaches the `os_` seam) and with no write on the held root. The entry is left as
    it was.

    Control on the same address: the entry removed, the same capture IS read (the observation
    works) and primed by one `create`."""
    capture = mod("learning.branch.capture")
    ledger = mod("learning.branch.ledger")
    run_dir = _one_call_source(tmp_path)
    sidecar, payload = fifo_sidecar(run_dir)
    ep = bare_episode(tmp_path)
    planted = _plant_base(ep, kind, host)
    before = S.census(ep.parent)
    spy = S.OsSpy()
    io = S.RecordingIo(os_=spy)

    with CaptureRead(sidecar, payload) as watch, S.open_episode(ep, io=io) as episode:
        raised = S.raised_by(lambda: capture.prime_base(run_dir, episode), fifo=planted.fifo)
    assert isinstance(raised, ledger.LedgerError), f"a {kind} at the base: {raised!r}"
    assert "already holds a primed base" in str(raised), raised
    assert not watch.read.is_set(), "the capture was read before the already-primed check"
    opened = [o for o in spy.opens if PurePosixPath(o.path).name == LAYOUT.served_base.name]
    assert opened == [], f"the base was opened: {opened}"
    assert [c for c in io.calls if c.method == "write"] == [], "the held root was written"
    assert S.census(ep.parent) == before, f"priming over a {kind} changed the tree"

    planted.remove()
    io = S.RecordingIo()
    with CaptureRead(sidecar, payload) as watch, S.open_episode(ep, io=io) as episode:
        report = S.in_time(lambda: capture.prime_base(run_dir, episode), fifo=sidecar)
    assert watch.read.is_set(), "control: the capture read is not observable"
    assert report.primed == 1
    writes = [c for c in io.calls if c.method == "write"]
    assert [(c.name, c.kwargs.get("mode")) for c in writes] == [(LAYOUT.served_base, "create")]


def test_r3_zero_rows_are_refused_by_default_and_primed_empty_with_allow_empty(tmp_path):
    """`prime_base(source_run_dir, episode, *, allow_empty=False)`: a capture that yields no row
    is "primed no base rows" `LedgerError` by default (#947's pin), with no base made and no
    write; with `allow_empty=True` it is primed — `primed == 0`, the base a plain, empty,
    single-linked file — by ONE `create` of the (empty) joined lines."""
    capture = mod("learning.branch.capture")
    ledger = mod("learning.branch.ledger")
    run_dir = _empty_source(tmp_path)
    ep = bare_episode(tmp_path)
    base = ep / LAYOUT.served_base

    io = S.RecordingIo()
    with S.open_episode(ep, io=io) as episode, pytest.raises(
            ledger.LedgerError, match="primed no base rows"):
        capture.prime_base(run_dir, episode)
    assert not os.path.lexists(base)
    assert [c for c in io.calls if c.method == "write"] == []

    io = S.RecordingIo()
    with S.open_episode(ep, io=io) as episode:
        report = capture.prime_base(run_dir, episode, allow_empty=True)
    assert report.primed == 0
    assert base.read_bytes() == b""
    assert stat.S_ISREG(os.lstat(base).st_mode)
    assert os.lstat(base).st_nlink == 1
    writes = [c for c in io.calls if c.method == "write"]
    assert [(c.name, c.kwargs.get("mode"), c.text) for c in writes] == [
        (LAYOUT.served_base, "create", "")], writes


def _launcher(tmp_path: Path) -> tuple[Any, Path, Any, Path]:
    cli = mod("learning.branch.cli")
    _base, src = T.runs_base(tmp_path)
    tenant = T.current_tenant_paths()
    return cli, src, tenant, cli.episode_dir_for(T.EPISODE_ID, tenant=tenant)


@pytest.mark.parametrize("capture", ["no-rows", "one-call"])
@pytest.mark.parametrize("kind", ["plain", "empty", "symlink", "fifo", "directory"])
def test_r3_a_retry_through_prepare_episode_over_an_existing_base_is_already_primed(
        tmp_path, roots, host, kind, capture):
    """A retry through the launcher's door (`prepare_episode`, its default primer: `prime_base`
    with `allow_empty=True`) over an episode that already holds a base — any kind of entry — is
    the one "already holds a primed base" `LedgerError`: never a raw `FileExistsError` or core
    refusal from a second create (today's zero-row downgrade creates the base itself), and never
    after reading the capture. The base is left as it was, the claim released, the episode
    closed.

    Control on the same address: with no base, a zero-row source primes an empty base (with a
    warning) and a one-call source primes its row."""
    cli, src, tenant, ep = _launcher(tmp_path)
    ledger = mod("learning.branch.ledger")
    sidecar = None
    if capture == "no-rows":
        (src / "executed_queries.jsonl").write_text("", encoding="utf-8")
    else:
        sidecar, payload = fifo_sidecar(src)

    def watching() -> Any:
        return _Nothing() if sidecar is None else CaptureRead(sidecar, payload)

    ep.mkdir(parents=True)
    planted = _plant_base(ep, kind, host)
    before = S.census(ep)

    with watching() as watch:
        raised = S.raised_by(lambda: cli.prepare_episode(T.EPISODE_ID, src, tenant=tenant),
                             fifo=planted.fifo)
    assert isinstance(raised, ledger.LedgerError), (
        f"a retry over a {kind} base ({capture}): {raised!r}")
    assert "already holds a primed base" in str(raised), raised
    assert not watch.read.is_set(), "the capture was read before the already-primed check"
    assert S.census(ep) == before, f"the retry changed the episode over a {kind} base"
    assert S.open_fds_on(ep) == [], "prepare_episode left the episode open on its refusal"

    planted.remove()
    with watching() as watch:
        episode = S.in_time(lambda: cli.prepare_episode(T.EPISODE_ID, src, tenant=tenant),
                            fifo=sidecar)
    with episode:
        assert Path(episode.dir) == ep
    assert watch.read.is_set() is (sidecar is not None), "control: the capture read not observed"
    base = (ep / LAYOUT.served_base).read_bytes()
    assert (base == b"") is (capture == "no-rows"), base


class _Nothing:
    """A `CaptureRead` stand-in for a source with no sidecar: nothing is ever read."""

    read = threading.Event()

    def __enter__(self) -> _Nothing:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None


def test_r3_the_launchers_default_primer_primes_an_empty_capture_once_and_warns(
        tmp_path, roots, caplog):
    """The launcher's default primer is `prime_base(..., allow_empty=True)`: a source whose
    capture yields no row gets an EMPTY base (a plain file), with a warning that every key
    reaches the live estate; there is no message-matched downgrade left to create it a second
    time (`_is_empty_capture` is removed)."""
    cli, src, tenant, ep = _launcher(tmp_path)
    (src / "executed_queries.jsonl").write_text("", encoding="utf-8")
    caplog.set_level(logging.WARNING)
    with cli.prepare_episode(T.EPISODE_ID, src, tenant=tenant) as episode:
        assert Path(episode.dir) == ep
    base = ep / LAYOUT.served_base
    assert base.read_bytes() == b""
    assert stat.S_ISREG(os.lstat(base).st_mode)
    assert os.lstat(base).st_nlink == 1
    # The warning's wording is the implementer's: any WARNING that speaks of the base, the
    # prime, the capture or its emptiness counts.
    assert S.warned(caplog, "base", "primed", "prime", "capture", "empty", "EMPTY", "rows"), (
        "an empty prime was not warned about")
    assert not hasattr(cli, "_is_empty_capture"), (
        "the message-matched downgrade `_is_empty_capture` is still there (R3: one primer)")


# =======================================================================================
# R4 — one leaf writer; a durable write never makes a folder
# =======================================================================================

@pytest.mark.parametrize("lane", ["held", "rooted_write", "staged.append_durable"])
def test_r4_a_durable_append_that_cannot_encode_its_text_leaves_no_descriptor_open(
        tmp_path, lane):
    """One writer owns the leaf's descriptor: it is handed to `fdopen` before the text is
    encoded, so a `str` that cannot be encoded (a lone surrogate) fails the durable append with
    a `UnicodeError` and leaves NO descriptor of this process open on the leaf (today the
    encode runs before `fdopen` and the fd leaks), and the leaf keeps its bytes. Through the held
    root, `rooted_write` (the `Run` lane) and the staging record. Control on the same address: a
    plain append of the same text leaks nothing either, and an encodable durable append lands."""
    root = tmp_path / "episodes" / EPISODE_ID
    root.mkdir(parents=True)
    rel = str(LAYOUT.staged) if lane == "staged.append_durable" else "rec.jsonl"
    leaf = root / rel
    leaf.write_text("prior\n", encoding="utf-8")

    def append(text: str, *, durable: bool = True) -> None:
        if lane == "held":
            with S.hold(root) as held:
                held.write(rel, text, mode="append", durable=durable)
        elif lane == "rooted_write":
            _io.rooted_write(root, rel, text, mode="append", durable=durable)
        else:
            with S.open_episode(root) as episode:
                if durable:
                    episode.staged.append_durable(text)
                else:
                    raise AssertionError("the staging record has no plain append")

    try:
        raised = S.raised_by(lambda: append(UNENCODABLE))
        assert isinstance(raised, UnicodeError), f"an unencodable durable append: {raised!r}"
        assert S.open_fds_on(leaf) == [], "the durable append left the leaf's descriptor open"
        assert leaf.read_text(encoding="utf-8") == "prior\n"
        if lane != "staged.append_durable":
            assert isinstance(S.raised_by(lambda: append(UNENCODABLE, durable=False)),
                              UnicodeError)
            assert S.open_fds_on(leaf) == []
        append("landed\n")
        assert leaf.read_text(encoding="utf-8") == "prior\nlanded\n"
    finally:
        for fd in S.open_fds_on(leaf):
            os.close(fd)


def test_r4_a_durable_append_into_a_missing_holding_folder_makes_nothing(tmp_path):
    """`Held.write(..., durable=True)` walks WITHOUT creating: a missing holding folder is
    `FileNotFoundError`, no folder is made and nothing is synced (a folder a durable walk made
    would not be synced). Control on the same address: a plain append makes the folder and
    lands; then the durable append lands in it."""
    root = tmp_path / "root"
    root.mkdir()
    spy = S.OsSpy()
    with S.hold(root, os_=spy) as held:
        before = S.census(root)
        raised = S.raised_by(lambda: held.write("fa/rec.jsonl", "row\n", mode="append",
                                                durable=True))
        assert isinstance(raised, FileNotFoundError), f"a durable append into fa/: {raised!r}"
        assert S.census(root) == before, "a durable append made a folder"
        assert spy.mkdirs == [], f"a durable append made folders: {spy.mkdirs}"
        assert spy.fsyncs == [], f"a refused durable append synced: {spy.fsyncs}"

        held.write("fa/rec.jsonl", "plain\n", mode="append")
        held.write("fa/rec.jsonl", "durable\n", mode="append", durable=True)
    assert (root / "fa" / "rec.jsonl").read_text(encoding="utf-8") == "plain\ndurable\n"


# =======================================================================================
# Patches
# =======================================================================================

@pytest.mark.parametrize(("token", "minted"), [
    pytest.param("Control", False, id="dotless-not-case-stable"),
    pytest.param("E1133.b", False, id="head-not-case-stable"),
    pytest.param("e1133.B", False, id="label-not-case-stable"),
    pytest.param("control", True, id="dotless-case-stable"),
    pytest.param("e1133.b", True, id="a-world-token"),
])
def test_patch_the_minting_check_judges_the_whole_token(token, minted):
    """`check_minted_token` requires the WHOLE token to be case-stable, not only the text after
    its last dot: a dot-less `Control` is refused (today it skips the check) and so is an
    upper-case head. Every episode token is already casefolded, so a real token still mints."""
    from defender._episode_paths import check_minted_token

    if minted:
        assert check_minted_token(token) == token
    else:
        with pytest.raises(ValueError, match="not case-stable"):
            check_minted_token(token)


def test_patch_scratch_ledger_refuses_a_dotless_label_that_is_not_case_stable(tmp_path):
    """`scratch_ledger(scratch, world_label=)` builds its ledger through `for_world`, whose
    minting check now judges the whole token: `Control` is `LedgerError` and no world file is
    made. Control on the same scratch: `control` builds and records."""
    ledger = mod("learning.branch.ledger")
    review = mod("learning.branch.review")
    with S.create_episode(tmp_path / "review-scratch" / "scratch") as scratch:
        with pytest.raises(ledger.LedgerError):
            review.scratch_ledger(scratch, world_label="Control")
        served = scratch.dir / "served"
        assert sorted(p.name for p in served.iterdir()) == ["base.jsonl"], (
            sorted(p.name for p in served.iterdir()))
        book = review.scratch_ledger(scratch, world_label="control")
        book.declare()
    assert (served / "control.jsonl").read_bytes() == b""


def test_patch_resume_with_no_held_episode_is_refused_never_an_ordinary_run(tmp_path):
    """`--resume` with no held episode is refused (`SystemExit`), never an ordinary run: `main`
    always holds one for `--resume`, so this guard is driven on `run._resume_target` directly.
    Controls: with no `--resume` the answer is `None` (an ordinary run); with the episode held,
    it is the manifest's world."""
    run = mod("run")
    _base, src = T.runs_base(tmp_path)
    ep = T.episode(tmp_path, doc=T.family_doc(source_run_dir=str(src)))
    ns = run.parse_args(["--resume", str(ep / LAYOUT.family), "--world", "b",
                         "--tenant", T.SOURCE_TENANT])

    def settings() -> Path:
        raise AssertionError("the tenant's settings were read for a manifest that names them")

    with pytest.raises(SystemExit):
        run._resume_target(ns, episode=None, settings=settings)

    ordinary = run.parse_args([str(src / "alert.json"), "--tenant", T.SOURCE_TENANT])
    assert run._resume_target(ordinary, episode=None, settings=settings) is None
    with S.open_episode(ep) as episode:
        world = run._resume_target(ns, episode=episode, settings=settings)
    assert world is not None, "a held episode's --resume answered no world"
    assert world.label == "b", world

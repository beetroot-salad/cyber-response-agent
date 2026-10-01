"""#1133 O4 / O4.8 / S1 — behaviour is otherwise unchanged; each declared tightening, through
the real migrated entry point, with its rev-2 signature (D3').

One section per item, each driven through the smallest real entry point with its own injection
seams (`cli.main`'s `questioner=` / `door=` / `adapters=` / `spawn=`, `cli.prepare_episode`'s
`prime=`, `grade_episode`'s `judge=`, `run.main`'s `lifecycle=` / `materialize=`, the
`Episode`'s `io=`), never `monkeypatch.setattr`. Every plant is a real filesystem entry, and
every negative has a positive control on the same address.

- O4.1 `staged.yaml`'s header is an exclusive create, tolerating `FileExistsError` (through
  `cli.main`, whose signature is unchanged).
- O4.2 `staging.merge_review(episode, key, block)` reads the record through the view without
  following links, then replaces it. Rev 3 (R1): a REFUSED record (a link, a non-plain entry,
  undecodable bytes) is `StagingRefused` naming the reason, and nothing is written.
- O4.3 / O4.8.3 `capture.prime_base(source_run_dir, episode)` creates the base whole with one
  exclusive create. Rev 3 (R3): anything named `base.jsonl` in the `served/` listing (a plain
  file, a link, a hard link, a FIFO, a directory) is the one "already holds a primed base"
  `LedgerError`, before the capture is read; the create still refuses a rival that lands after
  the listing. A linked `served/` is the core's FOLDER refusal (R2), raised as is — not the
  "already primed" refusal.
- O4.4 `Ledger.for_world(episode, token)`: a plant at `served/<token>.jsonl` or at `served/`
  refuses `declare()` and `record()`.
- O4.8.1 `Ledger.for_world(episode, <bad or non-case-stable id>)` is `LedgerError` at
  construction, before anything is written — every id the owner's minting check refuses (a
  newline, a NUL, an over-long name among them), not only the ones a hand-rolled check sees;
  since rev 3 the WHOLE token must be case-stable (a dot-less `Control`, an upper-case head).
- D4' the scratch ledger: one scratch `Episode` serves two worlds; its base is created empty
  once; a base holding rows is still the review's refusal.
- O4.5 the priming claim, through `cli.prepare_episode`, which now returns the `Episode` (and
  closes it on its own exception); the `prime=` seam is handed `(source_run_dir, episode)`.
- O4.6 / S1 the judge's draw removal: a non-plain draw (the core's leaf refusal, rev 3's
  `NotPlainEntry`) is refused, logged and left, and the pass goes on; any OTHER `OSError` from
  the removal (EACCES, EPERM, EROFS, and equally EIO or ENOTDIR, injected through the
  `Episode`'s `io=` seam) stops the pass and the stale draw stays. (A linked `judge/` folder is
  not the leaf class: `test_1133_rev3.py`.)
- D3' `enqueue.draws_on_disk(view, label)` / `draws_on_disk_report(view, label)`: every `.yaml`
  entry of any kind is counted, and a link at `worlds/`, `worlds/<label>` or its `judge/` yields
  no draws (C13: `worlds/b -> worlds/c` never yields c's draws under b).
- O4.8.2 `grade_episode` / `render_episode` on a missing episode dir are `JudgeRefused`, and the
  dir is not recreated (C14).
- D3' "Changed": `learning/branch/episode.py`'s served-world read makes no minting check (a
  legacy, non-case-stable world label still reads).
- The sibling door: `run.py --resume <manifest>` refuses a manifest not named `family.yaml`
  before anything is spent; and it holds ONE descriptor on the episode dir for the run — the
  `Episode` it hands the lifecycle.

Red before rev 3 (on the rev-2 tree): the O4.2 refusal rows (today an `OSError` from the
replace), the linked-`served/` prime (today mapped to "already primed"), the dot-less and
upper-case-head O4.8.1 rows, and every leaf-plant row checked with `assert_refusal` (no
`_io.NotPlainEntry`). Everything else holds today and is pinned to keep holding.
"""
from __future__ import annotations

import contextlib
import errno
import json
import logging
import os
import stat
from pathlib import Path
from typing import Any

import pytest
import yaml

from defender import _io
from defender._episode_paths import LAYOUT
from defender._io import read_jsonl_rows
from defender.tests import _judge_921 as J
from defender.tests import _spec1133 as S
from defender.tests import _triplet_947 as T
from defender.tests.test_947_capture_prime import append_call, call_row, source_run

EPISODE_ID = "ep-1133"
TOKEN = "e1133.b"


@pytest.fixture
def roots(tmp_path, monkeypatch):
    """The configured roots inside `tmp_path` (environment steering, the resolvers' own seam):
    the runs base, the episodes root and the learning state root the judge's queue lands in."""
    monkeypatch.setenv(T.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    monkeypatch.setenv(J.STATE_DIR_ENV, str(tmp_path / "learning-state"))


@contextlib.contextmanager
def umask(mask: int):
    old = os.umask(mask)
    try:
        yield
    finally:
        os.umask(old)


def bare_episode(tmp_path: Path) -> tuple[Path, Path]:
    """(an episode dir under an episodes root, a host folder outside it)."""
    ep = tmp_path / "episodes" / EPISODE_ID
    ep.mkdir(parents=True)
    host = tmp_path / "host"
    host.mkdir()
    return ep, host


# =======================================================================================
# O4.1 — the staging record's header (through cli.main; unchanged signature)
# =======================================================================================

class PlantsOnFirstCall:
    """The questioner seam, answering as `inner` does, that plants `plant()` on its first call:
    after the launcher's sweep has read the staging record and before the staging step writes
    it."""

    def __init__(self, inner: Any, plant: Any) -> None:
        self.inner = inner
        self.plant = plant
        self.planted = False

    def __call__(self, prompt: str, **kw: Any) -> Any:
        if not self.planted:
            self.planted = True
            self.plant()
        return self.inner(prompt, **kw)


def launch(tmp_path: Path, *, questioner: Any, before: Any = None) -> tuple[Any, Path, Any, Any]:
    """One episode through the real launcher (`cli.main`), every model and cluster seam faked."""
    cli = T.mod("learning.branch.cli")
    _base, src = T.runs_base(tmp_path)
    ep = cli.episode_dir_for(T.EPISODE_ID, tenant=T.current_tenant())
    if before is not None:
        before(ep)
    door, adapters, spawn = T.FakeDoor(), T.FakeAdapters(), T.FakeSpawn()
    try:
        outcome: Any = cli.main(
            [str(src), str(T.BRANCH_MESSAGE_ID), "--continuation-prompt", "go"],
            spawn=spawn, door=door, questioner=questioner, adapters=adapters,
            invoke=T.FakeAgent(*["same"] * 24), preflight=T.no_preflight,
            live_tree=T.source_capture())
    except (SystemExit, Exception) as refused:  # noqa: BLE001 — the refusal is the observation
        outcome = refused
    return outcome, ep, door, adapters


def test_o4_1_a_link_at_staged_yaml_refuses_the_staging_step_even_when_no_world_stages_a_name(
        tmp_path, roots):
    """The header is `staged.create(header)`, which refuses a link at the name: a link planted
    there ends the episode at staging — the review never runs, no cluster name is created — and
    the link and its target are left as they were."""
    host = tmp_path / "host"
    host.mkdir()
    target = host / "staged-target.yaml"
    target.write_bytes(S.HOST_BYTES)
    family = T.family_doc(worlds=[
        T.base_world(),
        T.world_doc("b", ov=T.overlay(patches={"identity": {"web-2": {"owner": "platform"}}})),
        T.world_doc("c", ov=T.overlay(patches={"identity": {"web-1": {"owner": "platform"}}})),
    ])
    holder: dict[str, Path] = {}
    questioner = PlantsOnFirstCall(
        T.FakeAgent(family, T.world_doc("b"), T.world_doc("c")),
        lambda: (holder["ep"] / "staged.yaml").symlink_to(target))

    rc, ep, door, adapters = launch(tmp_path, questioner=questioner,
                                    before=lambda ep: holder.setdefault("ep", ep))

    staged = ep / "staged.yaml"
    assert questioner.planted, "the scenario never reached the questioner"
    assert staged.is_symlink(), "the link planted at staged.yaml was replaced or removed"
    assert os.readlink(staged) == str(target), "the link planted at staged.yaml was repointed"
    assert target.read_bytes() == S.HOST_BYTES, "the header was written through the link"
    assert adapters.calls == [], f"the review ran over a link at staged.yaml: {adapters.calls}"
    assert door.created() == [], f"a cluster name was created: {door.created()}"
    assert rc != 0, f"the episode reported success over a refused staging record: {rc!r}"


def test_o4_1_a_staging_record_already_there_is_kept_and_appended_to_not_rewritten(
        tmp_path, roots):
    """A re-entered episode finds its staging record already there: the exclusive create's
    `FileExistsError` is tolerated, the record is kept byte for byte and this attempt's rows are
    appended after it. (Positive control for the test above, on the same address.)"""
    earlier = "# an earlier attempt's staging record, rows appended below\n"

    def keep_a_record(ep: Path) -> None:
        ep.mkdir(parents=True, exist_ok=True)
        (ep / "staged.yaml").write_text(earlier, encoding="utf-8")

    rc, ep, door, _adapters = launch(
        tmp_path, questioner=T.FakeAgent(T.family_doc(), T.world_doc("b"), T.world_doc("c")),
        before=keep_a_record)

    text = (ep / "staged.yaml").read_text(encoding="utf-8")
    assert text.startswith(earlier), "the existing staging record was replaced"
    assert "staged names for episode" not in text, "a second header was written"
    rows = T.staged_rows(ep)
    assert rows, "this attempt's rows were not appended to the kept record"
    assert {r["name"] for r in rows} == set(door.created())
    assert os.lstat(ep / "staged.yaml").st_nlink == 1
    assert rc == 0


# =======================================================================================
# O4.2 — the review merge takes the Episode
# =======================================================================================

def test_o4_2_merge_review_keeps_every_other_key_and_replaces_the_record_whole(tmp_path):
    """Positive control: a plain record's other keys are kept, the block merges into an
    existing key, and the record is a plain single-linked file afterwards."""
    staging = T.mod("learning.branch.staging")
    ep, _host = bare_episode(tmp_path)
    review = ep / "review.yaml"
    review.write_text(yaml.safe_dump({
        "worlds": {"b": {"decision": "accepted"}},
        "episode": {"outcome": "accepted", "reason": "all worlds agreed"}}), encoding="utf-8")

    with S.open_episode(ep) as episode:
        staging.merge_review(episode, "episode", {"decision": "rejected"})

    doc = yaml.safe_load(review.read_text(encoding="utf-8"))
    assert doc == {"worlds": {"b": {"decision": "accepted"}},
                   "episode": {"outcome": "accepted", "reason": "all worlds agreed",
                               "decision": "rejected"}}
    assert stat.S_ISREG(os.lstat(review).st_mode)
    assert os.lstat(review).st_nlink == 1


def test_o4_2_merge_review_does_not_read_through_a_hard_link_at_the_record(tmp_path):
    """A hard link at `review.yaml` whose other name holds bytes that are not text is the
    view's refusal — the other name's bytes are never decoded — so the merge is
    `StagingRefused` naming the alias reason (R1), and nothing changes."""
    staging = T.mod("learning.branch.staging")
    ep, host = bare_episode(tmp_path)
    other = host / "other-name-of-review.yaml"
    other.write_bytes(b"\xff\xfe host bytes, not text\n")
    os.link(other, ep / "review.yaml")
    before = S.census(tmp_path)

    with S.open_episode(ep) as episode:
        raised = S.raised_by(lambda: staging.merge_review(episode, "teardown", {"ok": False}))

    assert isinstance(raised, staging.StagingRefused), f"merge over a hard link: {raised!r}"
    assert "aliased" in str(raised), raised
    assert "codec" not in str(raised), f"the other name's bytes were decoded: {raised}"
    assert S.census(tmp_path) == before, "a refused merge changed the tree"
    assert os.lstat(other).st_nlink == 2


def test_o4_2_merge_review_refuses_a_symlink_at_the_record_and_leaves_it(tmp_path):
    """A symlink at `review.yaml` is the view's refusal: `StagingRefused` naming the alias
    reason (R1), nothing written, the link and what it reaches left as they were."""
    staging = T.mod("learning.branch.staging")
    ep, host = bare_episode(tmp_path)
    target = host / "review-target.yaml"
    target.write_text(yaml.safe_dump({"worlds": {"x": 1}}), encoding="utf-8")
    (ep / "review.yaml").symlink_to(target)
    before = S.census(tmp_path)
    with S.open_episode(ep) as episode:
        raised = S.raised_by(lambda: staging.merge_review(episode, "episode", {"o": 1}))
    assert isinstance(raised, staging.StagingRefused), f"merge over a symlink: {raised!r}"
    assert "aliased" in str(raised), raised
    assert S.census(tmp_path) == before


# =======================================================================================
# O4.3 / O4.8.3 — the primed base takes the Episode; the create is the check
# =======================================================================================

def _source_with_one_call(tmp_path: Path) -> Path:
    run_dir = source_run(tmp_path)
    append_call(run_dir, call_row("l-001", 0, "cmdb", "get-host", {"host": "canary-1"}),
                json.dumps({"owner": "estate", "role": "canary"}))
    return run_dir


def test_o4_3_prime_base_refuses_a_linked_served_folder_and_writes_nothing_where_it_points(
        tmp_path):
    """`prime_base(source_run_dir, episode)` writes the base with `served_base.create(rows)`,
    whose walk never follows a link at `served/`. A direct caller (no `served.ensure()` first)
    reaches the core's FOLDER refusal there (R2): a plain `OSError(ELOOP)`, raised as is — not
    the leaf class `NotPlainEntry` and not the "already holds a primed base" `LedgerError` (the
    listing of a linked `served/` is refused, so the create judges it) — and the folder the link
    points at gains no `base.jsonl`.

    Control on the same address: a real `served/` takes the whole capture as one plain,
    single-linked file; a second prime is the "already primed" `LedgerError`, base untouched."""
    capture = T.mod("learning.branch.capture")
    ledger = T.mod("learning.branch.ledger")
    run_dir = _source_with_one_call(tmp_path)
    ep, host = bare_episode(tmp_path)
    elsewhere = host / "served-elsewhere"
    elsewhere.mkdir()
    (ep / "served").symlink_to(elsewhere, target_is_directory=True)
    base = ep / "served" / "base.jsonl"
    before = S.census(tmp_path)

    with S.open_episode(ep) as episode:
        raised = S.raised_by(lambda: capture.prime_base(run_dir, episode))
    assert not isinstance(raised, ledger.LedgerError), (
        f"a linked served/ was read as an existing base: {raised!r}")
    S.assert_refusal(raised, "folder_link_outside", where="prime_base through a linked served/")
    assert S.census(tmp_path) == before, "the primer wrote through the linked served/"
    assert list(elsewhere.iterdir()) == []

    (ep / "served").unlink()
    with S.open_episode(ep) as episode:
        report = capture.prime_base(run_dir, episode)
        assert report.primed == 1
        assert [r["source"] for r in read_jsonl_rows(base)] == [ledger.CAPTURED]
        assert stat.S_ISREG(os.lstat(base).st_mode)
        assert os.lstat(base).st_nlink == 1
        original = base.read_bytes()
        with pytest.raises(ledger.LedgerError, match="already holds a primed base"):
            capture.prime_base(run_dir, episode)
    assert base.read_bytes() == original


@pytest.mark.parametrize("kind", ["plain", "symlink", "dangling", "hardlink", "fifo",
                                  "directory"])
def test_o4_8_3_anything_at_the_base_is_the_one_already_primed_refusal(tmp_path, kind):
    """O4.8.3 / R3: anything named `base.jsonl` in `served/` — a plain file, a link (live or
    dangling) or any non-plain entry (a hard link, a FIFO, a directory) — is the same "already
    holds a primed base" `LedgerError`, and the entry is left exactly as it was — nothing
    written through it, no dangling target made, no blocking on the FIFO. (That the capture is
    not read first, and the base not read at all, is `test_1133_rev3.py`'s.)"""
    capture = T.mod("learning.branch.capture")
    ledger = T.mod("learning.branch.ledger")
    run_dir = _source_with_one_call(tmp_path)
    ep, host = bare_episode(tmp_path)
    base = ep / "served" / "base.jsonl"
    fifo = None
    if kind == "plain":
        base.parent.mkdir(parents=True)
        base.write_bytes(b'{"an": "earlier prime"}\n')
    else:
        fifo = S.plant_leaf(base, kind, host=host).fifo
    before = S.census(tmp_path)

    with S.open_episode(ep) as episode:
        raised = S.raised_by(lambda: capture.prime_base(run_dir, episode), fifo=fifo)

    assert isinstance(raised, ledger.LedgerError), f"a {kind} at the base: {raised!r}"
    assert "already holds a primed base" in str(raised), raised
    assert S.census(tmp_path) == before, f"priming over a {kind} changed the tree"


# =======================================================================================
# O4.4 / O4.8.1 — the replay ledger takes the Episode
# =======================================================================================

def _ledger_episode(tmp_path: Path) -> tuple[Path, Path]:
    ep, host = bare_episode(tmp_path)
    (ep / "served").mkdir()
    (ep / "served" / "base.jsonl").write_text("", encoding="utf-8")
    return ep, host


def _call(ledger: Any, world_id: str = TOKEN) -> Any:
    return ledger.ServedCall(system="cmdb", verb="get-host", params={"host": "canary-1"},
                             payload_text=json.dumps({"owner": "live"}),
                             source=ledger.PASSTHROUGH, world_id=world_id)


@pytest.mark.parametrize("kind", ["dangling", "symlink", "hardlink", "fifo"])
def test_o4_4_a_plant_at_the_world_ledger_refuses_declare_and_record(tmp_path, kind):
    """`Ledger.for_world(episode, token)`'s `declare()` and `record()` append through the
    episode's `served_world(token)` record: a plant at `served/<token>.jsonl` is refused in the
    core's row and left in place. Control on the same address: the plant removed, `declare()`
    creates the file empty and `record()` appends the row."""
    ledger = T.mod("learning.branch.ledger")
    ep, host = _ledger_episode(tmp_path)
    world_file = ep / "served" / f"{TOKEN}.jsonl"
    planted = S.plant_leaf(world_file, kind, host=host)
    with S.open_episode(ep) as episode:
        book = ledger.Ledger.for_world(episode, TOKEN)
        before = S.census(tmp_path)
        S.assert_refusal(S.raised_by(book.declare, fifo=planted.fifo), kind,
                         where="declare() into a plant")
        S.assert_refusal(S.raised_by(lambda: book.record(_call(ledger)), fifo=planted.fifo),
                         kind, where="record() into a plant")
        assert S.census(tmp_path) == before, "a refused ledger write changed the tree"

        planted.remove()
        book = ledger.Ledger.for_world(episode, TOKEN)
        assert book.declare() is book
        assert world_file.read_bytes() == b""
        book.record(_call(ledger))
    assert read_jsonl_rows(world_file) == [_call(ledger).row()]


def test_o4_4_a_linked_served_folder_refuses_the_world_ledgers_declare(tmp_path):
    """A symlinked `served/` (to a real folder holding a base, so the ledger still builds) is
    refused by `declare()`'s walk, and the linked folder gains no world file."""
    ledger = T.mod("learning.branch.ledger")
    ep, host = bare_episode(tmp_path)
    elsewhere = host / "served-elsewhere"
    elsewhere.mkdir()
    (elsewhere / "base.jsonl").write_text("", encoding="utf-8")
    (ep / "served").symlink_to(elsewhere, target_is_directory=True)
    with S.open_episode(ep) as episode:
        book = ledger.Ledger.for_world(episode, TOKEN)
        before = S.census(tmp_path)
        S.assert_refusal(S.raised_by(book.declare), "folder_link_outside",
                         where="declare() through a linked served/")
    assert S.census(tmp_path) == before
    assert sorted(p.name for p in elsewhere.iterdir()) == ["base.jsonl"]


@pytest.mark.parametrize("world_id", [
    pytest.param("e1133.B", id="label-not-case-stable"),
    pytest.param("e1133.b/x", id="two-components"),
    pytest.param("../escape", id="climbs"),
    pytest.param("..", id="dotdot"),
    pytest.param(".", id="dot"),
    pytest.param("", id="empty"),
    pytest.param(None, id="none"),
    pytest.param(7, id="int"),
    pytest.param("base", id="the-capture-itself"),
    pytest.param("e1133.Base", id="capture-case-folded"),
    pytest.param("e1133.b\n", id="newline"),
    pytest.param("e1133.b\x00", id="nul"),
    pytest.param("e1133." + "b" * 250, id="longer-than-a-file-name"),
    # Rev 3's patch: the WHOLE token must be case-stable, not only the text after its last dot.
    pytest.param("Control", id="dotless-not-case-stable"),
    pytest.param("E1133.b", id="head-not-case-stable"),
])
def test_o4_8_1_a_bad_world_id_is_a_ledger_error_at_construction(tmp_path, world_id):
    """O4.8.1: `Ledger.for_world(episode, world_id)` builds its `served_world` record at
    construction, so a bad id — not one component, not case-stable (the owner's minting
    check, mapped to `LedgerError`), or naming the family's own capture — is a `LedgerError`
    from `for_world` itself, before anything is written. The check is the OWNER's, whole: an id
    a hand-rolled "one component, case-stable label" test would pass but the owner's component
    grammar refuses (a newline, a NUL, a name longer than a file name may be) is refused at
    construction too, not left for the first write. Control on the same episode: a good token
    builds, its `.path` / `.base_path` derive from the episode, and it declares."""
    ledger = T.mod("learning.branch.ledger")
    ep, _host = _ledger_episode(tmp_path)
    with S.open_episode(ep) as episode:
        before = S.census(tmp_path)
        with pytest.raises(ledger.LedgerError):
            ledger.Ledger.for_world(episode, world_id)
        assert S.census(tmp_path) == before, "for_world wrote before refusing its id"

        book = ledger.Ledger.for_world(episode, TOKEN)
        assert Path(book.path) == ep / "served" / f"{TOKEN}.jsonl"
        assert Path(book.base_path) == ep / "served" / "base.jsonl"
        book.declare()
    assert (ep / "served" / f"{TOKEN}.jsonl").read_bytes() == b""


# =======================================================================================
# D4' — one scratch Episode serves every world of a review
# =======================================================================================

def _base_call(ledger: Any, host: str) -> Any:
    return ledger.ServedCall(system="cmdb", verb="get-host", params={"host": host},
                             payload_text=json.dumps({"owner": host}),
                             source=ledger.BASE, world_id=None)


def test_d4_the_scratch_ledger_serves_two_worlds_on_one_scratch_episode(tmp_path):
    """`review.scratch_ledger(scratch, world_label=...)` takes the review's one scratch
    `Episode`: two worlds' ledgers share its base (created empty once, the second call
    tolerating the existing file) and each writes only its own `served/<label>.jsonl`.
    A scratch whose base holds rows is still the review's refusal (a replay through a recording
    agrees with itself) — control for the two ledgers above, on the same address."""
    ledger = T.mod("learning.branch.ledger")
    review = T.mod("learning.branch.review")
    with S.create_episode(tmp_path / "review-scratch" / "scratch") as scratch:
        b = review.scratch_ledger(scratch, world_label="b")
        c = review.scratch_ledger(scratch, world_label="c")
        base = scratch.dir / "served" / "base.jsonl"
        assert Path(b.base_path) == Path(c.base_path) == base
        assert base.read_bytes() == b"", "the scratch base is not empty"
        assert Path(b.path) != Path(c.path)
        b.record(_base_call(ledger, "for-b"))
        c.record(_base_call(ledger, "for-c"))
        assert read_jsonl_rows(Path(b.path)) == [_base_call(ledger, "for-b").row()]
        assert read_jsonl_rows(Path(c.path)) == [_base_call(ledger, "for-c").row()]
        assert base.read_bytes() == b"", "a world's rows reached the scratch base"

        base.write_text(json.dumps(_base_call(ledger, "recorded").row()) + "\n",
                        encoding="utf-8")
        with pytest.raises(review.ReviewError, match="holds rows"):
            review.scratch_ledger(scratch, world_label="d")


# =======================================================================================
# O4.5 — the priming claim; prepare_episode returns the Episode
# =======================================================================================

class Primed:
    """`prepare_episode`'s `prime=` seam, `(source_run_dir, episode)`: records what it was
    handed and the claim as it stands while priming runs, then does `act(claim)` if given."""

    def __init__(self, act: Any = None) -> None:
        self.act = act
        self.seen: dict[str, Any] = {}

    def __call__(self, source_run_dir: Path, episode: Any) -> Any:
        claim = Path(episode.dir) / "served" / ".priming"
        st = os.lstat(claim)
        self.seen = {"source": Path(source_run_dir), "episode": episode,
                     "mode": stat.S_IMODE(st.st_mode), "regular": stat.S_ISREG(st.st_mode),
                     "nlink": st.st_nlink}
        if self.act is not None:
            self.act(claim)
        return T.mod("learning.branch.capture").PrimeReport(primed=1)


def _prime_setup(tmp_path: Path) -> tuple[Any, Path, Any, Path]:
    cli = T.mod("learning.branch.cli")
    _base, src = T.runs_base(tmp_path)
    tenant = T.current_tenant()
    return cli, src, tenant, cli.episode_dir_for(T.EPISODE_ID, tenant=tenant)


def test_o4_5_prepare_episode_returns_the_held_episode_and_the_claim_is_released(
        tmp_path, roots):
    """`prepare_episode` creates the episode (`Episode.create`), claims with
    `priming_lock.create("")` — a plain, single-linked regular file of mode 0644 while the
    primer runs — hands the primer the source run and THE SAME `Episode` it returns, releases
    the claim, and returns that `Episode` still open (it holds the episode dir until the
    caller's `with` ends)."""
    cli, src, tenant, ep = _prime_setup(tmp_path)
    prime = Primed()
    with umask(0o022):
        got = cli.prepare_episode(T.EPISODE_ID, src, tenant=tenant, prime=prime)
    with got as episode:
        assert isinstance(episode, S.Episode()), f"prepare_episode returned {got!r}"
        assert Path(episode.dir) == ep
        assert prime.seen["episode"] is episode, "the primer was handed another episode"
        assert prime.seen["source"] == src
        assert prime.seen["regular"]
        assert prime.seen["nlink"] == 1
        assert prime.seen["mode"] == 0o644, f"the claim's mode is {oct(prime.seen['mode'])}"
        assert not os.path.lexists(ep / "served" / ".priming"), "the claim was not released"
        assert S.open_fds_on(ep), "the returned episode does not hold the episode dir"
    assert S.open_fds_on(ep) == [], "leaving the caller's `with` did not release the episode"


@pytest.mark.parametrize("kind", ["plain", "symlink", "dangling", "hardlink"])
def test_o4_5_an_occupied_or_aliased_claim_is_the_same_ledger_error_and_primes_nothing(
        tmp_path, roots, kind):
    """An occupied claim (a plain file: another launcher) and an alias at the claim are the one
    `LedgerError` naming another launcher; the primer never runs, the claim is left exactly as
    it was, and `prepare_episode` closed the episode it created before raising (no descriptor
    is left open on the episode dir while the refusal is still alive)."""
    cli, src, tenant, ep = _prime_setup(tmp_path)
    host = tmp_path / "host"
    host.mkdir()
    claim = ep / "served" / ".priming"
    if kind == "plain":
        claim.parent.mkdir(parents=True)
        claim.write_text("", encoding="utf-8")
    else:
        S.plant_leaf(claim, kind, host=host)
    before = S.census(tmp_path)

    def never(*_a: Any, **_kw: Any) -> Any:
        pytest.fail("the primer ran past an occupied or aliased claim")

    with pytest.raises(T.mod("learning.branch.ledger").LedgerError,
                       match="another launcher is priming") as refused:
        cli.prepare_episode(T.EPISODE_ID, src, tenant=tenant, prime=never)
    assert S.census(tmp_path) == before
    assert refused.value is not None
    assert S.open_fds_on(ep) == [], "prepare_episode left its episode open on its own refusal"


class PrimerFailed(Exception):
    """The primer's own failure, which the claim's release must never mask."""


def _swap_claim(kind: str, claim: Path, host: Path) -> Any:
    """Replace the held claim with a `kind` plant, and answer a check that the plant is still
    there as planted."""
    served = claim.parent
    claim.unlink()
    if kind == "directory":
        claim.mkdir()
        (claim / "keep").write_text("kept\n", encoding="utf-8")
        return lambda: claim.is_dir() and (claim / "keep").read_text(encoding="utf-8") == "kept\n"
    if kind == "symlink":
        target = host / "claim-target"
        target.write_bytes(S.HOST_BYTES)
        claim.symlink_to(target)
        return lambda: (claim.is_symlink() and os.readlink(claim) == str(target)
                        and target.read_bytes() == S.HOST_BYTES)
    if kind == "hardlink":
        other = host / "other-name-of-the-claim"
        other.write_bytes(S.HOST_BYTES)
        os.link(other, claim)
        return lambda: os.lstat(claim).st_nlink == 2 and other.read_bytes() == S.HOST_BYTES
    if kind == "fifo":
        os.mkfifo(claim)
        return lambda: stat.S_ISFIFO(os.lstat(claim).st_mode)
    served.rmdir()
    if kind == "served-file":
        served.write_bytes(S.HOST_BYTES)
        return lambda: stat.S_ISREG(os.lstat(served).st_mode) and served.read_bytes() == (
            S.HOST_BYTES)
    if kind == "served-link":
        elsewhere = host / "served-elsewhere"
        elsewhere.mkdir()
        (elsewhere / claim.name).write_bytes(S.HOST_BYTES)
        served.symlink_to(elsewhere, target_is_directory=True)
        return lambda: (served.is_symlink() and os.readlink(served) == str(elsewhere)
                        and (elsewhere / claim.name).read_bytes() == S.HOST_BYTES)
    raise AssertionError(kind)


@pytest.mark.parametrize("kind", ["directory", "symlink", "hardlink", "fifo", "served-file",
                                  "served-link"])
def test_o4_5_a_claim_release_refused_in_finally_never_masks_the_primers_exception(
        tmp_path, roots, caplog, kind):
    """The claim's `delete()` in `prepare_episode`'s `finally` suppresses EVERY refusal it can
    raise: the primer swaps the claim for a plant and fails; the refusal is logged, the
    primer's own exception propagates, the plant is left as planted, and the episode is closed
    before the exception leaves `prepare_episode`."""
    cli, src, tenant, ep = _prime_setup(tmp_path)
    host = tmp_path / "host"
    host.mkdir()
    still_planted: dict[str, Any] = {}

    def swap_then_fail(claim: Path) -> None:
        still_planted["check"] = _swap_claim(kind, claim, host)
        raise PrimerFailed("the primer failed")

    caplog.set_level(logging.WARNING)
    with pytest.raises(PrimerFailed) as failed:
        cli.prepare_episode(T.EPISODE_ID, src, tenant=tenant, prime=Primed(swap_then_fail))
    assert still_planted["check"](), f"the {kind} plant was changed by the claim's release"
    assert S.warned(caplog, ".priming"), "the refused release was not logged"
    assert failed.value is not None
    assert S.open_fds_on(ep) == [], "prepare_episode left its episode open on the primer's error"


def test_o4_5_a_link_planted_at_the_claim_is_left_in_place_by_its_release(
        tmp_path, roots, caplog):
    """The primer swaps the claim for a symlink to a host file and succeeds: the release in
    `finally` refuses the link (marked) and leaves it for the reap scan; the refusal is logged
    and suppressed, so priming still returns the episode. The link's target is untouched."""
    cli, src, tenant, ep = _prime_setup(tmp_path)
    target = tmp_path / "host-claim-target"
    target.write_bytes(S.HOST_BYTES)

    def swap(claim: Path) -> None:
        claim.unlink()
        claim.symlink_to(target)

    caplog.set_level(logging.WARNING)
    with cli.prepare_episode(T.EPISODE_ID, src, tenant=tenant, prime=Primed(swap)) as got:
        assert Path(got.dir) == ep
    claim = ep / "served" / ".priming"
    assert claim.is_symlink(), "the link planted at the claim was removed"
    assert os.readlink(claim) == str(target), "the link planted at the claim was repointed"
    assert target.read_bytes() == S.HOST_BYTES
    assert S.warned(caplog, ".priming", "aliased"), "the refused release was not logged"


# =======================================================================================
# O4.6 / S1 — the judge's draw removal
# =======================================================================================

class ScriptedJudge:
    """The judge seam (`judge=`): `by_agent[agent_id]` or `default`, recording each call."""

    def __init__(self, by_agent: dict[str, str], default: str) -> None:
        self.by_agent = by_agent
        self.default = default
        self.agent_ids: list[str] = []

    def __call__(self, prompt: str, *, role: Any = None, agent_id: str = "judge",
                 **kw: Any) -> str:
        self.agent_ids.append(agent_id)
        return self.by_agent.get(agent_id, self.default)


def _malformed_first() -> ScriptedJudge:
    good = J.as_reply_text(J.reply_doc())
    bad = J.as_reply_text(J.reply_doc(), malformed="lookalike-bucket")
    return ScriptedJudge({"judge:b:0": bad}, default=good)


def _judged_episode(tmp_path: Path) -> Path:
    """An accepted, archived episode whose world `b` is graded (it carries a staged row)."""
    return J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []})


@pytest.mark.parametrize("target", ["inside", "outside"])
def test_o4_6_a_link_at_a_malformed_draws_name_is_refused_logged_and_left_and_the_loop_goes_on(
        tmp_path, roots, caplog, target):
    """A malformed reply removes this index's draw file (`world.draw(n).delete()`). A symlink
    planted at `worlds/b/judge/0.yaml` is refused and LEFT; the refusal is contained — logged,
    and the loop continues: draw 1 is written, the pass completes with the malformed draw
    counted, the link's target untouched. A later disk read (`draws_on_disk_report(view, "b")`)
    counts that name unreadable and reads only draw 1."""
    enqueue = J.mod("learning.judge.enqueue")
    ep = _judged_episode(tmp_path)
    draw_dir = ep / "worlds" / "b" / "judge"
    draw_dir.mkdir(parents=True, exist_ok=True)
    outside = (ep / "worlds" / "b" / "planted-draw.yaml" if target == "inside"
               else tmp_path / "outside-draw.yaml")
    outside.write_text("findings: [{bucket: planted}]\n", encoding="utf-8")
    (draw_dir / "0.yaml").symlink_to(outside)

    caplog.set_level(logging.WARNING)
    judge = _malformed_first()
    J.mod("learning.judge").grade_episode(ep, judge=judge, runs_base=tmp_path / "defender-runs",
                                          draws=2)

    assert "judge:b:1" in judge.agent_ids, "the draw loop stopped at the refused removal"
    link = draw_dir / "0.yaml"
    assert link.is_symlink(), "the link planted at the malformed draw's name was removed"
    assert os.readlink(link) == str(outside), "the planted link was repointed"
    assert outside.read_text(encoding="utf-8") == "findings: [{bucket: planted}]\n"
    assert (draw_dir / "1.yaml").is_file(), "the loop did not go on to write draw 1"
    row = J.world_rows(J.judge_record(ep))["b"]
    assert (row["malformed_replies"], row["completed_draws"]) == (1, 1), row
    assert S.warned(caplog, "0.yaml", "aliased"), "the refused draw removal was not logged"
    with _io.bind(ep) as view:
        draws, report = enqueue.draws_on_disk_report(view, "b")
    assert sorted(draws) == [1], f"the disk read picked up {sorted(draws)}"
    assert report.unreadable == 1, f"the linked draw was not counted unreadable: {report}"


def test_o4_6_a_plain_stale_draw_at_a_malformed_index_is_still_removed(tmp_path, roots):
    """Positive control on the same address: a plain file an earlier pass left at
    `worlds/b/judge/0.yaml` is removed when this pass's draw 0 is malformed."""
    ep = _judged_episode(tmp_path)
    draw_dir = ep / "worlds" / "b" / "judge"
    draw_dir.mkdir(parents=True, exist_ok=True)
    (draw_dir / "0.yaml").write_text("findings: [{bucket: stale}]\n", encoding="utf-8")

    J.mod("learning.judge").grade_episode(ep, judge=_malformed_first(),
                                          runs_base=tmp_path / "defender-runs", draws=2)

    assert not os.path.lexists(draw_dir / "0.yaml"), "the stale plain draw survived"
    assert (draw_dir / "1.yaml").is_file()


def _run_draws(episode: Any, judge: ScriptedJudge) -> Any:
    """`judge._run_world_draws(episode, "b", ...)`: the draw loop, handed the pass's Episode."""
    return J.mod("learning.judge")._run_world_draws(
        episode, "b", judge=judge, draws=2, model="judge-model", effort="low",
        prompt="the framed prompt")


def _stale_draw(ep: Path) -> Path:
    draw = ep / "worlds" / "b" / "judge" / "0.yaml"
    draw.parent.mkdir(parents=True, exist_ok=True)
    draw.write_text("findings: [{bucket: stale}]\n", encoding="utf-8")
    return draw


@pytest.mark.parametrize("code", [errno.EACCES, errno.EPERM, errno.EROFS, errno.EIO,
                                  errno.ENOTDIR],
                         ids=["EACCES", "EPERM", "EROFS", "EIO", "ENOTDIR"])
def test_s1_any_other_error_removing_a_stale_draw_stops_the_pass_and_keeps_nothing_silently(
        tmp_path, code):
    """S1: only the core's non-plain refusal at the draw's name (rev 3: the leaf class
    `NotPlainEntry`) is contained. Any other `OSError`
    from removing a stale plain draw — the design's EACCES, EPERM and EROFS, and equally an EIO
    or an ENOTDIR, which its parenthetical does not list — injected through the `Episode`'s
    `io=` seam (the held root's `unlink` of `worlds/b/judge/0.yaml` raises it) propagates out of
    the draw loop and stops it: draw 1 is never paid for, and the stale draw is still there for
    the operator to see (it was never silently kept as this pass's).

    Control on the same address, no fault: the stale draw is removed and the loop goes on."""
    ep = _judged_episode(tmp_path)
    draw = _stale_draw(ep)
    rel = LAYOUT.world("b").draw(0)

    def fault(method: str, args: tuple, kwargs: dict) -> None:
        name = args[0] if args else kwargs.get("name")
        if method == "unlink" and S.as_rel(name) == rel:
            raise OSError(code, os.strerror(code), str(draw))

    judge = _malformed_first()
    with S.open_episode(ep, io=S.RecordingIo(before=fault)) as episode:
        raised = S.raised_by(lambda: _run_draws(episode, judge))
    refused = S.refusal_in(raised)
    assert refused is not None, f"a {errno.errorcode[code]} removing a draw was contained: {raised!r}"
    assert refused.errno == code, raised
    assert judge.agent_ids == ["judge:b:0"], (
        f"the loop went on past a {errno.errorcode[code]}: {judge.agent_ids}")
    assert draw.read_text(encoding="utf-8") == "findings: [{bucket: stale}]\n"

    judge = _malformed_first()
    with S.open_episode(ep) as episode:
        completed, _spread, documents, malformed = _run_draws(episode, judge)
    assert judge.agent_ids == ["judge:b:0", "judge:b:1"]
    assert (completed, malformed) == (1, 1)
    assert sorted(documents) == [1]
    assert not os.path.lexists(draw), "control: the stale plain draw survived"


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo", "directory"])
def test_s1_a_non_plain_draw_is_contained_logged_and_left(tmp_path, caplog, kind):
    """The contained rows, through the same loop: a symlink or a FIFO or a directory at the
    malformed draw's name (the core's leaf refusal, ELOOP) or a hard link (EMLINK) is refused,
    logged, and left for the reap scan, and the loop goes on to draw 1."""
    ep = _judged_episode(tmp_path)
    draw = ep / "worlds" / "b" / "judge" / "0.yaml"
    host = tmp_path / "host"
    host.mkdir()
    planted = S.plant_leaf(draw, kind, host=host)
    caplog.set_level(logging.WARNING)

    judge = _malformed_first()
    with S.open_episode(ep) as episode:
        completed, _spread, _docs, malformed = S.in_time(lambda: _run_draws(episode, judge),
                                                         fifo=planted.fifo)
    assert judge.agent_ids == ["judge:b:0", "judge:b:1"], "the loop stopped at a contained row"
    assert (completed, malformed) == (1, 1)
    assert os.path.lexists(draw), f"the {kind} at the draw's name was removed"
    assert S.warned(caplog, "0.yaml"), "the refused removal was not logged"


# =======================================================================================
# D3' — the draw reader takes a view and a label
# =======================================================================================

def test_d3_draws_on_disk_report_counts_every_yaml_entry_of_any_kind(tmp_path):
    """`draws_on_disk_report(view, label)` reads `view.under(worlds/<label>/judge)`: every entry
    whose name ends in `.yaml`, of any kind, is considered. A non-file entry (a symlink, a
    directory, a FIFO) and a hard link count as `unreadable`, as does a non-digit stem; a
    non-canonical stem (`01.yaml`) is `skipped`; only the plain `0.yaml` is read.
    `draws_on_disk(view, label)` answers the same draws. The same through `episode.view()`."""
    enqueue = J.mod("learning.judge.enqueue")
    ep = tmp_path / "episodes" / EPISODE_ID
    draw_dir = ep / "worlds" / "b" / "judge"
    draw_dir.mkdir(parents=True)
    host = tmp_path / "host"
    host.mkdir()
    (draw_dir / "0.yaml").write_text("findings: []\n", encoding="utf-8")
    (draw_dir / "01.yaml").write_text("findings: []\n", encoding="utf-8")
    (draw_dir / "x.yaml").write_text("findings: []\n", encoding="utf-8")
    S.plant_leaf(draw_dir / "1.yaml", "symlink", host=host, body=b"findings: []\n")
    S.plant_leaf(draw_dir / "2.yaml", "directory", host=host)
    S.plant_leaf(draw_dir / "3.yaml", "fifo", host=host)
    S.plant_leaf(draw_dir / "4.yaml", "hardlink", host=host, body=b"findings: []\n")

    with _io.bind(ep) as view:
        draws, report = S.in_time(lambda: enqueue.draws_on_disk_report(view, "b"),
                                  fifo=draw_dir / "3.yaml")
        assert enqueue.draws_on_disk(view, "b") == draws
    assert draws == {0: {"findings": []}}
    assert (report.unreadable, report.skipped) == (5, 1), report
    with S.open_episode(ep) as episode:
        assert enqueue.draws_on_disk(episode.view(), "b") == {0: {"findings": []}}


@pytest.mark.parametrize("at", ["worlds", "worlds/b", "worlds/b/judge"])
def test_d3_a_link_at_worlds_or_the_world_or_its_draws_folder_yields_no_draws(tmp_path, at):
    """C13's exploit: the draw reader walks from the episode root without following, so a link
    at `worlds/`, `worlds/b` or `worlds/b/judge` — each pointing at a real folder holding a
    draw (for `worlds/b`, the sibling world `worlds/c`, so `b` would read `c`'s draws) — yields
    NO draws under `b`. Controls on the same episode: `c`'s own draws read as `c`'s, and with
    the link replaced by a real folder holding a draw, `b` reads it."""
    enqueue = J.mod("learning.judge.enqueue")
    ep = tmp_path / "episodes" / EPISODE_ID
    ep.mkdir(parents=True)
    c_draw = {"findings": [{"bucket": "c-only"}]}
    if at == "worlds":
        elsewhere = tmp_path / "elsewhere"
        (elsewhere / "b" / "judge").mkdir(parents=True)
        (elsewhere / "b" / "judge" / "0.yaml").write_text(yaml.safe_dump(c_draw),
                                                           encoding="utf-8")
        (ep / "worlds").symlink_to(elsewhere, target_is_directory=True)
    else:
        c_judge = ep / "worlds" / "c" / "judge"
        c_judge.mkdir(parents=True)
        (c_judge / "0.yaml").write_text(yaml.safe_dump(c_draw), encoding="utf-8")
        if at == "worlds/b":
            (ep / "worlds" / "b").symlink_to(ep / "worlds" / "c", target_is_directory=True)
        else:
            (ep / "worlds" / "b").mkdir()
            (ep / "worlds" / "b" / "judge").symlink_to(c_judge, target_is_directory=True)

    with _io.bind(ep) as view:
        assert enqueue.draws_on_disk(view, "b") == {}, f"a link at {at} yielded draws under b"
        draws, _report = enqueue.draws_on_disk_report(view, "b")
        assert draws == {}
        if at != "worlds":
            assert enqueue.draws_on_disk(view, "c") == {0: c_draw}, "control: c's own draws"

    (ep / at).unlink()
    real = ep / "worlds" / "b" / "judge"
    real.mkdir(parents=True, exist_ok=True)
    (real / "0.yaml").write_text("findings: [{bucket: b-own}]\n", encoding="utf-8")
    with _io.bind(ep) as view:
        assert enqueue.draws_on_disk(view, "b") == {0: {"findings": [{"bucket": "b-own"}]}}


# =======================================================================================
# O4.8.2 — the path doors refuse a missing episode dir and never recreate it
# =======================================================================================

@pytest.mark.parametrize("kind", ["missing", "missing-parent", "file"])
def test_o4_8_2_grade_episode_refuses_a_missing_episode_dir_and_does_not_recreate_it(
        tmp_path, roots, kind):
    """`grade_episode(episode_dir, ...)` opens the episode at its door: a missing dir (or a
    missing episodes root, or a file at the name) is `JudgeRefused`, and nothing is created —
    rev 1 wrote a not-graded stamp and so recreated the dir (C14). Control: an existing episode
    that is not `accepted` is graded not-graded, its stamp written inside it."""
    judge_mod = J.mod("learning.judge")
    ep = tmp_path / "episodes" / EPISODE_ID
    if kind != "missing-parent":
        ep.parent.mkdir()
    if kind == "file":
        ep.write_bytes(S.HOST_BYTES)
    before = S.census(tmp_path)

    with pytest.raises(judge_mod.JudgeRefused):
        judge_mod.grade_episode(ep, runs_base=tmp_path / "defender-runs",
                                judge=ScriptedJudge({}, default="never called"))
    assert S.census(tmp_path) == before, f"grading a {kind} episode dir created something"

    control = T.episode(tmp_path / "control")
    grade = judge_mod.grade_episode(control, runs_base=tmp_path / "defender-runs",
                                    judge=ScriptedJudge({}, default="never called"))
    assert grade.not_graded is not None
    assert (control / "judge.yaml").is_file()


@pytest.mark.parametrize("kind", ["missing", "missing-parent"])
def test_o4_8_2_render_episode_refuses_a_missing_episode_dir_and_does_not_recreate_it(
        tmp_path, kind):
    """`render_episode(episode_dir)` keeps raising `JudgeRefused` for a missing dir (its door
    converts the open's `FileNotFoundError`), and creates nothing. Control: an existing
    episode's page is written inside it."""
    page = T.mod("scripts.visualize.visualize_episode")
    ep = tmp_path / "episodes" / EPISODE_ID
    if kind == "missing":
        ep.parent.mkdir()
    before = S.census(tmp_path)
    with pytest.raises(page.JudgeRefused):
        page.render_episode(ep)
    assert S.census(tmp_path) == before

    control = T.episode(tmp_path / "control")
    written = page.render_episode(control)
    assert Path(written) == control / "learning.html"
    assert (control / "learning.html").is_file()


# =======================================================================================
# D3' "Changed" — episode.py's served-world read makes no minting check
# =======================================================================================

def test_d3_the_episode_reader_reads_a_legacy_non_case_stable_worlds_served_file(tmp_path):
    """`episode.delta_o` reads each world's served file by its layout name (an N-b read), not
    through `Ledger.for_world`, whose construction now applies the minting check: an episode
    written before labels had to be case-stable — a world `B` whose token's label is not
    case-stable — still reads, and its keys are classified. Holds today; pinned so the rev-2
    `for_world` refusal does not reach the reader."""
    episode_mod = T.mod("learning.branch.episode")
    doc = T.family_doc(worlds=[T.base_world(), T.world_doc("B")])
    ep = T.episode(tmp_path, doc=doc)
    for label in ("a", "B"):
        T.archived_world(ep, label)
    T.base_capture(ep, [T.captured_row(key="k1"), T.captured_row(key="k2")])
    (ep / "served" / f"{T.world_token('B')}.jsonl").write_text(
        json.dumps(T.captured_row(key="k1")) + "\n"
        + json.dumps(T.captured_row(key="k2", payload={"hits": [{"_id": "planted"}]})) + "\n",
        encoding="utf-8")

    out = episode_mod.delta_o(ep)

    assert out["B"]["k1"] == "same", out
    assert "k2" in out["B"], f"the legacy world's served file was not read: {out}"


# =======================================================================================
# The sibling door — run.py --resume refuses a manifest not named family.yaml
# =======================================================================================

class Recorder:
    """`run.main`'s lifecycle seam: records that it ran and leaves a report, as a sibling does."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def __call__(self, **kw: Any) -> dict[str, Any]:
        self.calls.append(kw)
        (kw["run_dir"] / "report.md").write_text("disposition: malicious\n", encoding="utf-8")
        return {"output": "done", "requests": 1, "truncated_by": None}


def _resume_argv(manifest: Path) -> list[str]:
    return ["--resume", str(manifest), "--world", "b", "--tenant", T.SOURCE_TENANT]


@pytest.mark.parametrize("name", ["not-the-manifest.yaml", "family.yml", "FAMILY.yaml"])
def test_the_sibling_door_refuses_a_resume_manifest_not_named_family_yaml(tmp_path, name):
    """`run.py --resume <manifest>` is the sibling's door: a `<manifest>` whose name is not
    `LAYOUT.family` is refused — a `SystemExit` that names `family.yaml` — before anything is
    spent: no run dir is materialized and the lifecycle never runs, even though the file holds
    a valid manifest's bytes (so the refusal is about the name, not the content).

    Control on the same episode: the same bytes at `family.yaml` run to completion."""
    run = T.mod("run")
    _base, src = T.runs_base(tmp_path)
    ep = T.episode(tmp_path, doc=T.family_doc(source_run_dir=str(src)))
    other = ep / name
    other.write_bytes((ep / "family.yaml").read_bytes())
    lifecycle = Recorder()
    materialized: list[Any] = []

    def materialize(*a: Any, **kw: Any) -> Any:
        materialized.append((a, kw))
        raise AssertionError("a run dir was materialized for a refused manifest")

    with pytest.raises(SystemExit) as refused:
        run.main(_resume_argv(other), lifecycle=lifecycle, visualize=lambda _run: None,
                 preflight=T.no_preflight, materialize=materialize)
    assert refused.value.code not in (0, None), refused.value.code
    assert str(LAYOUT.family) in str(refused.value.code), (
        f"the refusal does not name the manifest's own name: {refused.value.code!r}")
    assert materialized == [], "a run dir was materialized"
    assert lifecycle.calls == [], "the lifecycle ran over a refused manifest"

    lifecycle = Recorder()
    rc = run.main(_resume_argv(ep / "family.yaml"), lifecycle=lifecycle,
                  visualize=lambda _run: None, preflight=T.no_preflight)
    assert rc == 0
    assert len(lifecycle.calls) == 1


def test_the_sibling_door_holds_one_descriptor_on_the_episode_for_the_whole_run(tmp_path):
    """`run.py --resume`'s door opens the episode once, around materialize -> lifecycle, and
    that one handle serves the manifest read and the world ledger: while the lifecycle runs,
    exactly one descriptor is open on the episode dir, and it is the `Episode` handed to the
    lifecycle (its `.dir` the manifest's parent) — no second root held beside it by name."""
    run = T.mod("run")
    _base, src = T.runs_base(tmp_path)
    ep = T.episode(tmp_path, doc=T.family_doc(source_run_dir=str(src)))
    seen: dict[str, Any] = {}

    class Holding(Recorder):
        def __call__(self, **kw: Any) -> dict[str, Any]:
            seen["fds"] = S.open_fds_on(ep)
            seen["episode"] = kw.get("episode")
            return super().__call__(**kw)

    rc = run.main(_resume_argv(ep / "family.yaml"), lifecycle=Holding(),
                  visualize=lambda _run: None, preflight=T.no_preflight)
    assert rc == 0
    assert "fds" in seen, "the lifecycle never ran"
    assert len(seen["fds"]) == 1, (
        f"descriptors open on the episode dir while the sibling ran: {seen['fds']}")
    assert seen["episode"] is not None, "the lifecycle was handed no Episode"
    assert Path(seen["episode"].dir) == ep, seen["episode"].dir
    assert S.open_fds_on(ep) == [], "the sibling's door left the episode dir open"

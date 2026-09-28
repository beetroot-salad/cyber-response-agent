"""#1133 O4 — behaviour is otherwise unchanged; each declared tightening, through the real
migrated entry point.

One section per O4 item, each driven through the smallest real entry point with its own
injection seams (`cli.main`'s `questioner=` / `door=` / `adapters=` / `spawn=`,
`cli.prepare_episode`'s `prime=`, `grade_episode`'s `judge=`), never `monkeypatch.setattr`.
Every plant is a real filesystem entry.

- O4.1 `staged.yaml`'s header is an exclusive create, tolerating `FileExistsError`: a record
  already there is kept (a re-entered episode appends to it), and a link at the name refuses the
  staging step even when no world stages a name (today the link-following `exists()` sees the
  link's target and skips the header, so the step completes and the review runs).
- O4.2 `staging.merge_review` reads the record without following links, then replaces it. A hard
  link at `review.yaml` whose other name holds non-UTF-8 bytes is refused as an alias, not
  decoded (today `read_text` reads the other name's bytes and raises `UnicodeDecodeError`).
- O4.3 `capture.prime_base` creates the primed base whole and exclusively: a symlinked `served/`
  is refused and nothing lands where it points (today `append_jsonl` makes and writes through
  it). The "already primed" `LedgerError` pre-check is kept.
- O4.4 the replay ledger's world file is declared and appended through the handle: a link at
  `served/<token>.jsonl` or at `served/` refuses `declare()` and `record()` (today both follow
  it). D3: a directly constructed `Ledger` writes through the rooted core too, and
  `for_world(...).path` makes no minting check (a reader's use) while `declare()` does.
- O4.5 the priming claim is the core's exclusive create (mode 0644, was 0600); an alias at the
  claim is the same `LedgerError` an occupied claim raises; the claim's `delete()` in the
  launcher's `finally` logs and suppresses its own refusal, so a planted directory never masks
  the primer's exception (today `unlink` raises `IsADirectoryError` over it) and a planted link
  is left in place (today `unlink` removes it).
- O4.6 the judge's draw removal: a link at a malformed draw's name is refused and left in place
  (today `unlink` removes it); the refusal is logged and the loop continues; a later disk read
  counts that name unreadable. D3's `draws_on_disk_report` counts every `.yaml` entry of any kind.
- O4.7 the path-typed entry points keep their signatures and refuse a path that is not that
  record's own: `load_family` / `manifest_digest` / `check_manifest_digest` (`FamilyError`),
  `merge_review` and `prime_base` (`ValueError` or the module's own error).
- N-g: the three creation doors (`write_family`, `record_staged`, `merge_review`) refuse a
  symlinked episode dir, as `guarded_mkdir(episode_dir, base=parent)` does today.

Red before #1133: the O4.1 no-staged-name link, O4.2 hard link, O4.3 linked `served/`, O4.4 (all
three plants and the reader/minting split), O4.5 mode / directory-in-finally / link-in-finally,
O4.6 link removal and O4.7 wrong-name paths. The rest pins behaviour that must keep holding.
"""
from __future__ import annotations

import contextlib
import json
import logging
import os
import stat
from pathlib import Path
from typing import Any

import pytest
import yaml

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


def warned(caplog, *needles: str) -> list[str]:
    """Messages logged at WARNING or above that mention any of `needles`."""
    return [r.getMessage() for r in caplog.records
            if r.levelno >= logging.WARNING and any(n in r.getMessage() for n in needles)]


# =======================================================================================
# O4.1 — the staging record's header
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
    """One episode through the real launcher (`cli.main`), every model and cluster seam faked.
    `before(ep)` runs once the episode's path is known and before the launch. Answers the exit
    status, or the refusal `main` raised (an operator exit is a `SystemExit`)."""
    cli = T.mod("learning.branch.cli")
    _base, src = T.runs_base(tmp_path)
    ep = cli.episode_dir_for(T.EPISODE_ID, tenant=T.current_tenant_paths())
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
    """The header is `staged.create(header)`, which refuses a link at the name (only a
    `FileExistsError` is tolerated). A family whose worlds stage no corpus appends no row, so
    the header is the ONLY write the staging step makes: a link planted there (to an existing
    host file) now ends the episode at staging — the review never runs, no cluster name is
    created — and the link and its target are left as they were.

    Today `staged.exists()` follows the link, sees the target, skips the header, and the step
    completes: the review runs over the linked record."""
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
    assert adapters.calls == [], (
        "the review ran: the staging step completed over a link at staged.yaml — the header "
        f"write was skipped (a link-following exists()) instead of refused. calls={adapters.calls}")
    assert door.created() == [], f"a cluster name was created: {door.created()}"
    assert rc != 0, f"the episode reported success over a refused staging record: {rc!r}"


def test_o4_1_a_staging_record_already_there_is_kept_and_appended_to_not_rewritten(
        tmp_path, roots):
    """A re-entered episode finds its staging record already there: the exclusive create's
    `FileExistsError` is tolerated, the record is kept byte for byte (no second header, nothing
    replaced) and this attempt's rows are appended after it. (Positive control for the test
    above, on the same address; holds today and must keep holding.)"""
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
    assert {r["name"] for r in rows} == set(door.created()), (
        f"the kept record's rows are not this attempt's cluster names: {rows}")
    assert os.lstat(ep / "staged.yaml").st_nlink == 1
    assert rc == 0


# =======================================================================================
# O4.2 — the review merge
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

    staging.merge_review(review, "episode", {"decision": "rejected"})

    doc = yaml.safe_load(review.read_text(encoding="utf-8"))
    assert doc == {"worlds": {"b": {"decision": "accepted"}},
                   "episode": {"outcome": "accepted", "reason": "all worlds agreed",
                               "decision": "rejected"}}
    assert stat.S_ISREG(os.lstat(review).st_mode)
    assert os.lstat(review).st_nlink == 1


def test_o4_2_merge_review_does_not_read_through_a_hard_link_at_the_record(tmp_path):
    """The merge reads `review.yaml` with the handle's no-follow read, which refuses a hard
    link without reading it; the replace then refuses the alias. So a hard link whose other
    name (outside the episode) holds bytes that are not text is refused as an OSError — the
    other name's bytes are never decoded — and nothing changes: the link, the other name's
    bytes and its link count.

    Today `artifact_file` passes a hard link (a regular file) and `read_text` decodes the other
    name's bytes: `UnicodeDecodeError`."""
    staging = T.mod("learning.branch.staging")
    ep, host = bare_episode(tmp_path)
    other = host / "other-name-of-review.yaml"
    other.write_bytes(b"\xff\xfe host bytes, not text\n")
    os.link(other, ep / "review.yaml")
    before = S.census(tmp_path)

    with pytest.raises(OSError, match="aliased") as refused:
        staging.merge_review(ep / "review.yaml", "teardown", {"ok": False})

    assert not isinstance(refused.value, UnicodeError)
    assert S.census(tmp_path) == before, "a refused merge changed the tree"
    assert os.lstat(other).st_nlink == 2


def test_o4_2_merge_review_refuses_a_symlink_at_the_record_and_leaves_it(tmp_path):
    """Holds today and must keep holding: a symlink at `review.yaml` is never merged into or
    written through; it is refused (the alias mark) and left in place."""
    staging = T.mod("learning.branch.staging")
    ep, host = bare_episode(tmp_path)
    target = host / "review-target.yaml"
    target.write_text(yaml.safe_dump({"worlds": {"x": 1}}), encoding="utf-8")
    (ep / "review.yaml").symlink_to(target)
    before = S.census(tmp_path)
    raised = S.raised_by(lambda: staging.merge_review(ep / "review.yaml", "episode", {"o": 1}))
    S.assert_refusal(raised, "symlink", where="merge_review over a symlink")
    assert S.census(tmp_path) == before


# =======================================================================================
# O4.3 — the primed base
# =======================================================================================

def _source_with_one_call(tmp_path: Path) -> Path:
    run_dir = source_run(tmp_path)
    append_call(run_dir, call_row("l-001", 0, "cmdb", "get-host", {"host": "canary-1"}),
                json.dumps({"owner": "estate", "role": "canary"}))
    return run_dir


def test_o4_3_prime_base_refuses_a_linked_served_folder_and_writes_nothing_where_it_points(
        tmp_path):
    """`prime_base` writes the base with `served_base.create(rows)`, which makes `served/`
    with `rooted_mkdir` and never walks a link there: a symlinked `served/` (to a real folder
    outside the episode) is the core's unmarked ELOOP, and the folder it points at gains no
    `base.jsonl`.

    Today the pre-check's `exists()` follows the link and finds nothing, then `append_jsonl`
    makes and writes `base.jsonl` in the linked folder.

    Control on the same address: a real `served/` takes the whole capture as one plain,
    single-linked file; and the "already primed" pre-check is kept (a second prime is the same
    `LedgerError`, the base untouched)."""
    capture = T.mod("learning.branch.capture")
    ledger = T.mod("learning.branch.ledger")
    run_dir = _source_with_one_call(tmp_path)
    ep, host = bare_episode(tmp_path)
    elsewhere = host / "served-elsewhere"
    elsewhere.mkdir()
    (ep / "served").symlink_to(elsewhere, target_is_directory=True)
    base = ep / "served" / "base.jsonl"
    before = S.census(tmp_path)

    raised = S.raised_by(lambda: capture.prime_base(run_dir, base))

    S.assert_refusal(raised, "folder_link_outside", where="prime_base through a linked served/")
    assert S.census(tmp_path) == before, "the primer wrote through the linked served/"
    assert list(elsewhere.iterdir()) == []

    (ep / "served").unlink()
    report = capture.prime_base(run_dir, base)
    assert report.primed == 1
    assert [r["source"] for r in read_jsonl_rows(base)] == [ledger.CAPTURED]
    assert stat.S_ISREG(os.lstat(base).st_mode)
    assert os.lstat(base).st_nlink == 1
    original = base.read_bytes()
    with pytest.raises(ledger.LedgerError, match="already holds a primed base"):
        capture.prime_base(run_dir, base)
    assert base.read_bytes() == original


@pytest.mark.parametrize("kind", ["symlink", "dangling", "hardlink"])
def test_o4_3_an_alias_at_the_base_is_still_the_already_primed_refusal(tmp_path, kind):
    """The pre-check stays: an alias at `served/base.jsonl` is the "already primed"
    `LedgerError`, the alias left in place and nothing written through it."""
    capture = T.mod("learning.branch.capture")
    ledger = T.mod("learning.branch.ledger")
    run_dir = _source_with_one_call(tmp_path)
    ep, host = bare_episode(tmp_path)
    S.plant_leaf(ep / "served" / "base.jsonl", kind, host=host)
    before = S.census(tmp_path)
    with pytest.raises(ledger.LedgerError, match="already holds a primed base"):
        capture.prime_base(run_dir, ep / "served" / "base.jsonl")
    assert S.census(tmp_path) == before


# =======================================================================================
# O4.4 — the replay ledger's world file
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
    """`Ledger.for_world(...)`'s `declare()` and `record()` go through
    `episode.served_world(token)`'s append: a plant at `served/<token>.jsonl` is refused in the
    core's row (a dangling link's target is never created; a live link's target and a hard
    link's other name keep their bytes), and the plant is left in place.

    Today `declare()` opens the path in append mode and `record()` `append_jsonl`s it, both
    following a link.

    Control on the same address: the plant removed, `declare()` creates the file empty and
    `record()` appends the row."""
    ledger = T.mod("learning.branch.ledger")
    ep, host = _ledger_episode(tmp_path)
    world_file = ep / "served" / f"{TOKEN}.jsonl"
    planted = S.plant_leaf(world_file, kind, host=host)
    book = ledger.Ledger.for_world(ep, TOKEN)
    before = S.census(tmp_path)

    S.assert_refusal(S.raised_by(book.declare, fifo=planted.fifo), kind,
                     where="declare() into a plant")
    S.assert_refusal(S.raised_by(lambda: book.record(_call(ledger)), fifo=planted.fifo), kind,
                     where="record() into a plant")
    assert S.census(tmp_path) == before, "a refused ledger write changed the tree"

    planted.remove()
    book = ledger.Ledger.for_world(ep, TOKEN)
    assert book.declare() is book
    assert world_file.read_bytes() == b""
    book.record(_call(ledger))
    assert read_jsonl_rows(world_file) == [_call(ledger).row()]


def test_o4_4_a_linked_served_folder_refuses_the_world_ledgers_declare(tmp_path):
    """A symlinked `served/` (to a real folder holding a base, so the ledger still builds) is
    refused by `declare()`'s holding-folder walk, and the linked folder gains no world file.
    Today `mkdir(exist_ok=True)` accepts the link and the append opens the file through it."""
    ledger = T.mod("learning.branch.ledger")
    ep, host = bare_episode(tmp_path)
    elsewhere = host / "served-elsewhere"
    elsewhere.mkdir()
    (elsewhere / "base.jsonl").write_text("", encoding="utf-8")
    (ep / "served").symlink_to(elsewhere, target_is_directory=True)
    book = ledger.Ledger.for_world(ep, TOKEN)
    before = S.census(tmp_path)

    S.assert_refusal(S.raised_by(book.declare), "folder_link_outside",
                     where="declare() through a linked served/")
    assert S.census(tmp_path) == before
    assert sorted(p.name for p in elsewhere.iterdir()) == ["base.jsonl"]


def test_d3_a_directly_constructed_ledger_writes_through_the_rooted_core_too(tmp_path):
    """D3: a `Ledger` built directly (no episode behind it: tests) writes with
    `io.rooted_write(path.parent, path.name, mode="append")`, so a link at its own file is
    refused and its target is not created. Today `declare()` follows it. Control: a plain
    path lands."""
    ledger = T.mod("learning.branch.ledger")
    ep, host = _ledger_episode(tmp_path)
    path = ep / "served" / "direct.jsonl"
    path.symlink_to(host / "direct-target.jsonl")
    book = ledger.Ledger(path=path, base_path=ep / "served" / "base.jsonl")
    before = S.census(tmp_path)
    S.assert_refusal(S.raised_by(book.declare), "dangling", where="direct declare()")
    S.assert_refusal(S.raised_by(lambda: book.record(_call(ledger, "direct"))), "dangling",
                     where="direct record()")
    assert S.census(tmp_path) == before
    path.unlink()
    book.declare()
    book.record(_call(ledger, "direct"))
    assert read_jsonl_rows(path) == [_call(ledger, "direct").row()]


def test_d3_for_world_path_is_a_readers_use_and_mints_nothing_but_declare_does(tmp_path):
    """D3: the record is built at write time, so `for_world(...).path` (the episode page's
    reader use) makes no minting check — a token whose label is not case-stable still names its
    file — while `declare()` applies the owner's minting check (`EpisodePaths.served_world`'s
    case-stable label) and refuses it with a `ValueError` before anything is written.

    Today `declare()` creates the file."""
    ledger = T.mod("learning.branch.ledger")
    ep, _host = _ledger_episode(tmp_path)
    book = ledger.Ledger.for_world(ep, "e1133.B")
    assert book.path == ep / "served" / "e1133.B.jsonl"
    before = S.census(tmp_path)
    with pytest.raises(ValueError, match="is not case-stable"):
        book.declare()
    assert S.census(tmp_path) == before, "declare() wrote before its name check"


# =======================================================================================
# O4.5 — the priming claim
# =======================================================================================

class Primed:
    """`prepare_episode`'s `prime=` seam: records what it was handed and the claim as it
    stands while priming runs, then does `act(claim)` (a plant, a raise) if given."""

    def __init__(self, act: Any = None) -> None:
        self.act = act
        self.seen: dict[str, Any] = {}

    def __call__(self, source_run_dir: Path, base_path: Path) -> Any:
        claim = Path(base_path).parent / ".priming"
        st = os.lstat(claim)
        self.seen = {"source": Path(source_run_dir), "base": Path(base_path),
                     "mode": stat.S_IMODE(st.st_mode), "regular": stat.S_ISREG(st.st_mode),
                     "nlink": st.st_nlink}
        if self.act is not None:
            self.act(claim)
        return T.mod("learning.branch.capture").PrimeReport(primed=1)


def _prime_setup(tmp_path: Path) -> tuple[Any, Path, Any, Path]:
    cli = T.mod("learning.branch.cli")
    _base, src = T.runs_base(tmp_path)
    tenant = T.current_tenant_paths()
    return cli, src, tenant, cli.episode_dir_for(T.EPISODE_ID, tenant=tenant)


def test_o4_5_the_priming_claim_is_the_cores_exclusive_create_mode_0644_released_after(
        tmp_path, roots):
    """The claim is `priming_lock.create("")`: while the primer runs it is a plain,
    single-linked regular file of mode 0644 (under umask 022; today's raw `os.open` makes it
    0600). The primer is handed the source run and `served/base.jsonl`. The claim is gone once
    priming returns."""
    cli, src, tenant, ep = _prime_setup(tmp_path)
    prime = Primed()
    with umask(0o022):
        got = cli.prepare_episode(T.EPISODE_ID, src, tenant=tenant, prime=prime)
    assert got == ep
    assert prime.seen["source"] == src
    assert prime.seen["base"] == ep / "served" / "base.jsonl"
    assert prime.seen["regular"]
    assert prime.seen["nlink"] == 1
    assert prime.seen["mode"] == 0o644, f"the claim's mode is {oct(prime.seen['mode'])}"
    assert not os.path.lexists(ep / "served" / ".priming"), "the claim was not released"


@pytest.mark.parametrize("kind", ["plain", "symlink", "dangling", "hardlink"])
def test_o4_5_an_occupied_or_aliased_claim_is_the_same_ledger_error_and_primes_nothing(
        tmp_path, roots, kind):
    """An occupied claim (a plain file: another launcher) and an alias at the claim (a live or
    dangling symlink, a hard link: the marked alias refusal) are the one `LedgerError` naming
    another launcher; the primer never runs, and the claim is left exactly as it was (a
    dangling link's target is not created)."""
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
                       match="another launcher is priming"):
        cli.prepare_episode(T.EPISODE_ID, src, tenant=tenant, prime=never)
    assert S.census(tmp_path) == before


class PrimerFailed(Exception):
    """The primer's own failure, which the claim's release must never mask."""


def test_o4_5_a_claim_release_refused_in_finally_never_masks_the_primers_exception(
        tmp_path, roots, caplog):
    """The claim's `delete()` runs in `prepare_episode`'s `finally`. Here the primer swaps the
    claim for a DIRECTORY and then fails: the delete is refused (a non-plain entry), that
    refusal is logged and suppressed, and the primer's own exception is what propagates. The
    directory is left in place.

    Today `claim.unlink(missing_ok=True)` raises `IsADirectoryError` from the `finally`, which
    replaces the primer's exception."""
    cli, src, tenant, ep = _prime_setup(tmp_path)

    def swap_then_fail(claim: Path) -> None:
        claim.unlink()
        claim.mkdir()
        (claim / "keep").write_text("kept\n", encoding="utf-8")
        raise PrimerFailed("the primer failed")

    caplog.set_level(logging.WARNING)
    with pytest.raises(PrimerFailed):
        cli.prepare_episode(T.EPISODE_ID, src, tenant=tenant, prime=Primed(swap_then_fail))
    claim = ep / "served" / ".priming"
    assert claim.is_dir(), "the planted directory at the claim was removed"
    assert (claim / "keep").read_text(encoding="utf-8") == "kept\n", (
        "the planted directory at the claim was emptied")
    assert warned(caplog, ".priming", "aliased"), "the refused release was not logged"


def test_o4_5_a_link_planted_at_the_claim_is_left_in_place_by_its_release(
        tmp_path, roots, caplog):
    """The primer swaps the claim for a symlink to a host file and succeeds: the release in
    `finally` is `rooted_unlink`, which refuses the link (marked) and leaves it for the reap
    scan; the refusal is logged and suppressed, so priming still returns the episode. The link's
    target is untouched.

    Today `claim.unlink()` removes the planted link."""
    cli, src, tenant, ep = _prime_setup(tmp_path)
    target = tmp_path / "host-claim-target"
    target.write_bytes(S.HOST_BYTES)

    def swap(claim: Path) -> None:
        claim.unlink()
        claim.symlink_to(target)

    caplog.set_level(logging.WARNING)
    got = cli.prepare_episode(T.EPISODE_ID, src, tenant=tenant, prime=Primed(swap))
    claim = ep / "served" / ".priming"
    assert got == ep
    assert claim.is_symlink(), "the link planted at the claim was removed"
    assert os.readlink(claim) == str(target), "the link planted at the claim was repointed"
    assert target.read_bytes() == S.HOST_BYTES
    assert warned(caplog, ".priming", "aliased"), "the refused release was not logged"


# =======================================================================================
# O4.6 — the judge's draw removal
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


def _judged_episode(tmp_path: Path) -> Path:
    """An accepted, archived episode whose world `b` is graded (it carries a staged row)."""
    return J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []})


def _grade_with_a_malformed_first_draw(tmp_path: Path, ep: Path) -> ScriptedJudge:
    good = J.as_reply_text(J.reply_doc())
    bad = J.as_reply_text(J.reply_doc(), malformed="lookalike-bucket")
    judge = ScriptedJudge({"judge:b:0": bad}, default=good)
    J.mod("learning.judge").grade_episode(ep, judge=judge, runs_base=tmp_path / "defender-runs",
                                          draws=2)
    return judge


@pytest.mark.parametrize("target", ["inside", "outside"])
def test_o4_6_a_link_at_a_malformed_draws_name_is_refused_logged_and_left_and_the_loop_goes_on(
        tmp_path, roots, caplog, target):
    """A malformed reply removes this index's draw file (`world.draw(n).delete()`). A symlink
    planted at `worlds/b/judge/0.yaml` — to a file inside the world, or outside the episode —
    is refused and LEFT (the reap scan must still see it); the refusal is contained — logged,
    and the loop continues: draw 1 is written, the pass completes with the malformed draw
    counted, and the link's target is untouched. A later disk read counts that name unreadable
    and reads only draw 1.

    Today `unlink(missing_ok=True)` removes a link to a file inside the world, and a link
    outside the episode fails the whole pass at `WorldPaths.draw`'s containment resolve."""
    enqueue = J.mod("learning.judge.enqueue")
    ep = _judged_episode(tmp_path)
    draw_dir = ep / "worlds" / "b" / "judge"
    draw_dir.mkdir(parents=True, exist_ok=True)
    outside = (ep / "worlds" / "b" / "planted-draw.yaml" if target == "inside"
               else tmp_path / "outside-draw.yaml")
    outside.write_text("findings: [{bucket: planted}]\n", encoding="utf-8")
    (draw_dir / "0.yaml").symlink_to(outside)

    caplog.set_level(logging.WARNING)
    judge = _grade_with_a_malformed_first_draw(tmp_path, ep)

    assert "judge:b:1" in judge.agent_ids, "the draw loop stopped at the refused removal"
    link = draw_dir / "0.yaml"
    assert link.is_symlink(), "the link planted at the malformed draw's name was removed"
    assert os.readlink(link) == str(outside), "the planted link was repointed"
    assert outside.read_text(encoding="utf-8") == "findings: [{bucket: planted}]\n"
    assert (draw_dir / "1.yaml").is_file(), "the loop did not go on to write draw 1"
    assert not (draw_dir / "1.yaml").is_symlink()
    row = J.world_rows(J.judge_record(ep))["b"]
    assert (row["malformed_replies"], row["completed_draws"]) == (1, 1), row
    assert warned(caplog, "0.yaml", "aliased"), "the refused draw removal was not logged"
    draws, report = enqueue.draws_on_disk_report(draw_dir)
    assert sorted(draws) == [1], f"the disk read picked up {sorted(draws)}"
    assert report.unreadable == 1, f"the linked draw was not counted unreadable: {report}"


def test_o4_6_a_plain_stale_draw_at_a_malformed_index_is_still_removed(tmp_path, roots):
    """Positive control on the same address: a plain file an earlier pass left at
    `worlds/b/judge/0.yaml` is removed when this pass's draw 0 is malformed, so a disk re-read
    cannot queue its findings as this pass's."""
    ep = _judged_episode(tmp_path)
    draw_dir = ep / "worlds" / "b" / "judge"
    draw_dir.mkdir(parents=True, exist_ok=True)
    (draw_dir / "0.yaml").write_text("findings: [{bucket: stale}]\n", encoding="utf-8")

    _grade_with_a_malformed_first_draw(tmp_path, ep)

    assert not os.path.lexists(draw_dir / "0.yaml"), "the stale plain draw survived"
    assert (draw_dir / "1.yaml").is_file()


def test_d3_draws_on_disk_report_counts_every_yaml_entry_of_any_kind(tmp_path):
    """D3: the draw reader considers every entry whose name ends in `.yaml`, of any kind. A
    non-file entry (a symlink, a directory, a FIFO) and a hard link count as `unreadable`, as
    does a non-digit stem; a non-canonical stem (`01.yaml`) is `skipped`; only the plain `0.yaml`
    is read. And a linked draws folder yields no draws at all.

    (Holds today through the path glob; pinned so the move onto `bind(draw_dir)` does not keep
    only `entries().files()`, which drops a linked entry silently.)"""
    enqueue = J.mod("learning.judge.enqueue")
    draw_dir = tmp_path / "judge"
    draw_dir.mkdir()
    host = tmp_path / "host"
    host.mkdir()
    (draw_dir / "0.yaml").write_text("findings: []\n", encoding="utf-8")
    (draw_dir / "01.yaml").write_text("findings: []\n", encoding="utf-8")
    (draw_dir / "x.yaml").write_text("findings: []\n", encoding="utf-8")
    S.plant_leaf(draw_dir / "1.yaml", "symlink", host=host, body=b"findings: []\n")
    S.plant_leaf(draw_dir / "2.yaml", "directory", host=host)
    S.plant_leaf(draw_dir / "3.yaml", "fifo", host=host)
    S.plant_leaf(draw_dir / "4.yaml", "hardlink", host=host, body=b"findings: []\n")

    draws, report = S.in_time(lambda: enqueue.draws_on_disk_report(draw_dir),
                              fifo=draw_dir / "3.yaml")
    assert draws == {0: {"findings": []}}
    assert (report.unreadable, report.skipped) == (5, 1), report

    linked = tmp_path / "linked-judge"
    linked.symlink_to(draw_dir, target_is_directory=True)
    draws, report = enqueue.draws_on_disk_report(linked)
    assert draws == {}
    assert (report.unreadable, report.skipped) == (0, 0)


# =======================================================================================
# O4.7 — path-typed entry points refuse a path that is not the record's own
# =======================================================================================

@pytest.mark.parametrize("entry", ["load_family", "manifest_digest", "check_manifest_digest"])
def test_o4_7_the_manifest_readers_refuse_a_path_that_is_not_family_yaml(tmp_path, entry):
    """`load_family`, `manifest_digest` and `check_manifest_digest` keep their path signature
    and derive `Episode(path.parent).family`; a path whose name is not the manifest's is a
    `FamilyError`, even when it holds a valid manifest's bytes (so the refusal is about the
    name, not the content). Control: the same bytes at `family.yaml` are read."""
    fam = T.mod("runtime.branch._family")
    ep = T.episode(tmp_path)
    manifest = ep / "family.yaml"
    digest = fam.manifest_digest(manifest)
    elsewhere = ep / "not-the-manifest.yaml"
    elsewhere.write_bytes(manifest.read_bytes())
    call = {
        "load_family": fam.load_family,
        "manifest_digest": fam.manifest_digest,
        "check_manifest_digest": lambda p: fam.check_manifest_digest(p, digest),
    }[entry]

    call(manifest)
    with pytest.raises(fam.FamilyError):
        call(elsewhere)


def test_o4_7_merge_review_refuses_a_path_that_is_not_review_yaml_and_writes_nothing(
        tmp_path):
    """`merge_review(path, ...)` derives `Episode(path.parent).review`; any other name is
    refused (`ValueError` or `StagingRefused`) before anything is written. Control: the same
    call on `review.yaml` merges."""
    staging = T.mod("learning.branch.staging")
    ep, _host = bare_episode(tmp_path)
    before = S.census(tmp_path)
    with pytest.raises((ValueError, staging.StagingRefused)):
        staging.merge_review(ep / "not-review.yaml", "episode", {"outcome": "x"})
    assert S.census(tmp_path) == before
    staging.merge_review(ep / "review.yaml", "episode", {"outcome": "x"})
    assert yaml.safe_load((ep / "review.yaml").read_text(encoding="utf-8")) == {
        "episode": {"outcome": "x"}}


@pytest.mark.parametrize("wrong", ["served/not-base.jsonl", "elsewhere/base.jsonl"])
def test_o4_7_prime_base_refuses_a_path_that_is_not_the_served_base_and_writes_nothing(
        tmp_path, wrong):
    """`capture.prime_base(source_run_dir, base_path)` derives
    `Episode(base_path.parent.parent).served_base`; a path that is not that record's own is
    refused (`ValueError` or `LedgerError`) and nothing is created. Control: the served base
    itself primes."""
    capture = T.mod("learning.branch.capture")
    ledger = T.mod("learning.branch.ledger")
    run_dir = _source_with_one_call(tmp_path)
    ep, _host = bare_episode(tmp_path)
    before = S.census(tmp_path)
    with pytest.raises((ValueError, ledger.LedgerError)):
        capture.prime_base(run_dir, ep / wrong)
    assert S.census(tmp_path) == before
    assert capture.prime_base(run_dir, ep / "served" / "base.jsonl").primed == 1


# =======================================================================================
# N-g — the three creation doors judge the episode dir from its parent
# =======================================================================================

@pytest.mark.parametrize("door", ["write_family", "record_staged", "merge_review"])
def test_n_g_each_creation_door_refuses_a_symlinked_episode_dir(tmp_path, door):
    """`write_family`, `record_staged` and `merge_review` each call `Episode.create_dir()`
    first, which refuses a link at the episode dir's name (as `guarded_mkdir(episode_dir,
    base=parent)` does today): an OSError, and nothing lands in the folder the link points at.
    Control: the same door on a real episode dir writes its record."""
    host = tmp_path / "host"
    real = host / "real-episode"
    real.mkdir(parents=True)
    episodes = tmp_path / "episodes"
    episodes.mkdir()
    ep = episodes / EPISODE_ID
    ep.symlink_to(real, target_is_directory=True)
    fam = T.mod("runtime.branch._family")
    staging = T.mod("learning.branch.staging")
    call = {
        "write_family": lambda d: fam.write_family(d, T.family_doc()),
        "record_staged": lambda d: staging.record_staged(d, {"name": "wv-x", "kind": "index"}),
        "merge_review": lambda d: staging.merge_review(d / "review.yaml", "episode", {"o": 1}),
    }[door]
    before = S.census(tmp_path)
    with pytest.raises(OSError, match=S.CORE_REFUSAL):
        call(ep)
    assert S.census(tmp_path) == before, f"{door} wrote through the linked episode dir"
    assert list(real.iterdir()) == []

    ep.unlink()
    call(ep)
    assert ep.is_dir()
    assert not ep.is_symlink()
    assert any(ep.iterdir()), f"{door} wrote nothing into the real episode dir"

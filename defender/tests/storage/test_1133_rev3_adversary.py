"""#1133 rev 3 adversary regressions: wrong-but-plausible implementations the main rev-3 suite let through."""
from __future__ import annotations

import errno
import json
import os
import shutil
import types

import pytest

from defender.records._episode_paths import LAYOUT
from defender.tests.support.learning.judge import _judge_921 as J
from defender.tests.support.storage import _spec1133 as S
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.storage import test_1133_rev3 as R
from defender.tests.learning.branch.test_947_capture_prime import append_call, call_row, source_run


def test_a_linked_served_holding_a_base_elsewhere_is_the_folder_refusal_not_already_primed(tmp_path):
    capture = T.mod("learning.branch.capture")
    ledger = T.mod("learning.branch.ledger")
    run_dir = source_run(tmp_path)
    append_call(run_dir, call_row("l-001", 0, "cmdb", "get-host", {"host": "canary-1"}),
                json.dumps({"owner": "estate", "role": "canary"}))
    ep = tmp_path / "episodes" / "ep-1133"
    ep.mkdir(parents=True)
    elsewhere = tmp_path / "host" / "elsewhere-served"
    elsewhere.mkdir(parents=True)
    (elsewhere / "base.jsonl").write_bytes(b'{"an": "earlier prime elsewhere"}\n')
    (ep / "served").symlink_to(elsewhere, target_is_directory=True)
    with S.open_episode(ep) as episode:
        raised = S.raised_by(lambda: capture.prime_base(run_dir, episode))
    assert not isinstance(raised, ledger.LedgerError), (
        f"a linked served/ was followed to a base outside the episode: {raised!r}")
    S.assert_refusal(raised, "folder_link_outside", where="prime_base through a linked served/")


def test_the_already_primed_check_follows_the_held_root_not_the_path(tmp_path):
    capture = S.T.mod("learning.branch.capture") if hasattr(S, "T") else R.mod("learning.branch.capture")
    ledger = R.mod("learning.branch.ledger")
    run_dir = R._one_call_source(tmp_path)
    sidecar, payload = R.fifo_sidecar(run_dir)
    ep = R.bare_episode(tmp_path)
    (ep / "served").mkdir()
    (ep / LAYOUT.served_base).write_bytes(b'{"an": "earlier prime"}\n')
    moved = ep.parent / "moved-while-held"
    with R.CaptureRead(sidecar, payload) as watch, S.open_episode(ep) as episode:
        ep.rename(moved)
        raised = S.raised_by(lambda: capture.prime_base(run_dir, episode), fifo=sidecar)
    assert isinstance(raised, ledger.LedgerError), raised
    assert "already holds a primed base" in str(raised), raised
    assert not watch.read.is_set(), "the capture was read: the check looked at the old path"


@pytest.mark.parametrize("reader", ["verdicts", "delta_o"])
def test_a_linked_outcome_record_holding_accepted_is_refused_by_both_readers(tmp_path, reader):
    episode = T.mod("learning.branch.episode")
    doc = T.family_doc(worlds=[T.base_world(), T.world_doc("b")])
    ep = T.episode(tmp_path, doc=doc)
    for label in ("a", "b"):
        T.archived_world(ep, label)
    T.base_capture(ep, [T.captured_row(key="k1")])
    J.outcome_record(ep)
    host = tmp_path / "host"
    host.mkdir()
    record = ep / LAYOUT.outcome
    # Both halves read through the episode's WALKED view (review-3 F32 / review-4 F36: the
    # readers take the view and no `Path`), opened OUTSIDE `pytest.raises`, so a view that
    # cannot be opened fails as itself instead of satisfying the refusal below.
    read = getattr(episode, reader)
    # Control: the plain accepted record passes the gate.
    J.through_view(ep, read)
    record.rename(host / "outcome.yaml")
    record.symlink_to(host / "outcome.yaml")
    # A followed link would read `accepted` and pass; the gate refuses it instead.
    with J.walked_view(ep) as view, pytest.raises(episode.EpisodeError):
        read(view)


def test_a_linked_served_folder_is_no_primed_base_never_followed(tmp_path):
    episode = T.mod("learning.branch.episode")
    ledger = T.mod("learning.branch.ledger")
    doc = T.family_doc(worlds=[T.base_world(), T.world_doc("b")])
    ep = T.episode(tmp_path, doc=doc)
    for label in ("a", "b"):
        T.archived_world(ep, label)
    T.base_capture(ep, [T.captured_row(key="k1")])
    J.outcome_record(ep)
    (ep / LAYOUT.served_world(T.world_id(ep, "b"))).write_text(
        json.dumps(T.captured_row(key="k1")) + "\n", encoding="utf-8")
    outside = tmp_path / "host" / "served-elsewhere"
    shutil.copytree(ep / "served", outside)
    shutil.rmtree(ep / "served")
    (ep / "served").symlink_to(outside, target_is_directory=True)
    # A classification here means delta_o followed the linked served/ outside the episode.
    with pytest.raises(ledger.LedgerError, match="no primed base"):
        J.through_view(ep, episode.delta_o)  # review-3 F32: the walked view, never a path


def test_an_under_derivation_taken_before_close_is_refused_after_it(tmp_path):
    root = tmp_path / "root"
    (root / "fa").mkdir(parents=True)
    (root / "fa" / "rec.txt").write_text("ROOT\n", encoding="utf-8")
    held = S.hold(root)
    sub = held.view().under("fa")
    assert sub.read("rec.txt").text == "ROOT\n"
    held.close()
    assert S.open_fds_on(root) == [], f"a descriptor on the root outlived close: {S.open_fds_on(root)}"
    rec = sub.read("rec.txt")
    assert rec.text is None, rec
    assert rec.reason == os.strerror(errno.EBADF), rec
    assert sub.entries().entries is None


class FdopenFails(types.SimpleNamespace):
    def __getattr__(self, name):
        return getattr(os, name)

    def fdopen(self, *_a, **_k):
        raise MemoryError("fdopen could not allocate its buffer")


@pytest.mark.parametrize("durable", [False, True])
def test_a_failed_fdopen_leaves_no_descriptor_open_on_the_leaf(tmp_path, durable):
    root = tmp_path / "root"
    root.mkdir()
    leaf = root / "rec.jsonl"
    leaf.write_text("prior\n", encoding="utf-8")
    try:
        with S.hold(root, os_=FdopenFails()) as held:
            with pytest.raises(MemoryError):
                held.write("rec.jsonl", "row\n", mode="append", durable=durable)
            assert S.open_fds_on(leaf) == [], "the leaf's fd leaked when fdopen raised"
    finally:
        for fd in S.open_fds_on(leaf):
            os.close(fd)


@pytest.mark.parametrize("token", ["e1133.straße", "straße", "e1133ß.b"])
def test_a_token_lower_accepts_but_casefold_refuses_is_refused(tmp_path, token):
    from defender.records._episode_paths import EpisodePaths
    assert token == token.lower()
    with pytest.raises(ValueError, match="not a valid world id"):
        EpisodePaths(tmp_path).served_world(token)

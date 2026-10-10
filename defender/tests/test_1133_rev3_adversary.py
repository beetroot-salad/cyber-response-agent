"""#1133 rev 3: the adversary's third pass on the tests-only commit `3039adbb`.

Each test here greened a wrong-but-plausible rev-3 implementation that `test_1133_rev3.py` let
through; each is red on that implementation's exploit and green on an honest one.
"""
from __future__ import annotations

import errno
import json
import os
import shutil
import types

import pytest

from defender import _io
from defender._episode_paths import LAYOUT
from defender.tests import _judge_921 as J
from defender.tests import _spec1133 as S
from defender.tests import _triplet_947 as T
from defender.tests import test_1133_rev3 as R
from defender.tests.test_947_capture_prime import append_call, call_row, source_run


# ---------------------------------------------------------------------------------------
# E2 (R3): the already-primed check lists through the held view; a linked `served/` holding a base elsewhere is the folder refusal.
# ---------------------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------------------
# E10 (R3): the already-primed check follows the held root, not the path, and reads nothing from the base.
# ---------------------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------------------
# E3 (R1): the outcome gate refuses a refused outcome record for both readers that share it
# (#1224 moved the gate from `review.yaml` to pre-flight's `outcome.yaml`).
# ---------------------------------------------------------------------------------------


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
    # Control: the plain accepted record passes the gate.
    getattr(episode, reader)(ep)
    record.rename(host / "outcome.yaml")
    record.symlink_to(host / "outcome.yaml")
    # A followed link would read `accepted` and pass; the gate refuses it instead.
    with pytest.raises(episode.EpisodeError):
        getattr(episode, reader)(ep)


# ---------------------------------------------------------------------------------------
# E4 (R1): `delta_o` reads through its one bind; a linked `served/` is no primed base, never followed.
# ---------------------------------------------------------------------------------------


def test_a_linked_served_folder_is_no_primed_base_never_followed(tmp_path):
    episode = T.mod("learning.branch.episode")
    ledger = T.mod("learning.branch.ledger")
    doc = T.family_doc(worlds=[T.base_world(), T.world_doc("b")])
    ep = T.episode(tmp_path, doc=doc)
    for label in ("a", "b"):
        T.archived_world(ep, label)
    T.base_capture(ep, [T.captured_row(key="k1")])
    J.outcome_record(ep)
    (ep / LAYOUT.served_world(T.world_token("b"))).write_text(
        json.dumps(T.captured_row(key="k1")) + "\n", encoding="utf-8")
    outside = tmp_path / "host" / "served-elsewhere"
    shutil.copytree(ep / "served", outside)
    shutil.rmtree(ep / "served")
    (ep / "served").symlink_to(outside, target_is_directory=True)
    # A classification here means delta_o followed the linked served/ outside the episode.
    with pytest.raises(ledger.LedgerError, match="no primed base"):
        episode.delta_o(ep)


# ---------------------------------------------------------------------------------------
# E5 (R1): an `under` derivation owns nothing; taken before a close, it is refused after it.
# ---------------------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------------------
# E6 (R4): one leaf writer, which closes the descriptor when `fdopen` fails.
# ---------------------------------------------------------------------------------------


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


def test_there_is_one_leaf_writer():
    assert not hasattr(_io, "_write_synced"), "`_write_synced` is still there (R4: one writer)"


# ---------------------------------------------------------------------------------------
# E7 (patch): case-stable is casefold, not `.lower()`.
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("token", ["e1133.straße", "straße", "e1133ß.b"])
def test_a_token_lower_accepts_but_casefold_refuses_is_refused(token):
    from defender._episode_paths import check_minted_token
    assert token == token.lower()
    with pytest.raises(ValueError, match="not case-stable"):
        check_minted_token(token)

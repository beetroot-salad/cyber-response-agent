"""record_lead.claim_lead: atomic exclusive claim of a lead id and its failure modes."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import fixture_runs_base

from defender.tests.support.shared.contracts._spec1077 import fixture_run
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender import _io
from defender.run_repository import Run

import errno
import json
import os
from pathlib import Path

from defender.hooks.record_lead import (
    ALREADY_CLAIMED,
    CLAIMED,
    NOT_CLAIMED,
    claim_lead,
)


def _dispatch(run_dir: Path, lead_id, goal: str, dims: list[str]) -> dict:
    return {
        "run_dir": str(run_dir),
        "lead_id": lead_id,
        "goal": goal,
        "what_to_summarize": dims,
    }


def test_writes_lead_id_keyed_sidecar(tmp_path):
    run_dir = tmp_path / fixture_uuid("run-a")
    (run_dir / "gather_raw").mkdir(parents=True)
    dispatch = _dispatch(
        run_dir, "l-001", "Did the FIM fire trace to apt?", ["apt history", "checksum"]
    )
    assert claim_lead(dispatch, run=fixture_run(run_dir)) == CLAIMED

    sidecar = run_dir / "gather_raw" / "l-001.lead.json"
    assert sidecar.is_file()
    assert json.loads(sidecar.read_text()) == {
        "goal": "Did the FIM fire trace to apt?",
        "what_to_summarize": ["apt history", "checksum"],
    }


def test_creates_gather_raw_dir_if_missing(tmp_path):
    run_dir = tmp_path / fixture_uuid("run-c")
    assert claim_lead(_dispatch(run_dir, "l-002", "g", ["d"]), run=fixture_run(run_dir)) == CLAIMED
    assert (run_dir / "gather_raw" / "l-002.lead.json").is_file()


def test_distinct_ids_in_a_batch_both_claim(tmp_path):
    run_dir = tmp_path / fixture_uuid("run-batch")
    (run_dir / "gather_raw").mkdir(parents=True)
    assert claim_lead(_dispatch(run_dir, "l-001", "g1", ["d"]), run=fixture_run(run_dir)) == CLAIMED
    assert claim_lead(_dispatch(run_dir, "l-002", "g2", ["d"]), run=fixture_run(run_dir)) == CLAIMED
    assert (run_dir / "gather_raw" / "l-001.lead.json").is_file()
    assert (run_dir / "gather_raw" / "l-002.lead.json").is_file()


def test_reused_id_returns_already_claimed_with_remediation(tmp_path, capsys):
    run_dir = tmp_path / fixture_uuid("run-reuse")
    (run_dir / "gather_raw").mkdir(parents=True)
    assert claim_lead(_dispatch(run_dir, "l-001", "first", ["d"]), run=fixture_run(run_dir)) == CLAIMED
    assert claim_lead(_dispatch(run_dir, "l-001", "second", ["d"]), run=fixture_run(run_dir)) == ALREADY_CLAIMED
    err = capsys.readouterr().err
    assert "l-001" in err
    assert "append a new :L" in err
    assert json.loads((run_dir / "gather_raw" / "l-001.lead.json").read_text())["goal"] == "first"


def test_the_three_codes_are_distinct(tmp_path):
    """#855 F-12, at the seam that caused it: a caller must be able to write "the row is on
    disk" as a check, and it can only do that if SUCCESS has a code no skip shares. One run
    over the three domains — a good claim, a refused one, a reused one — and the three answers
    are three."""
    run_dir = tmp_path / fixture_uuid("run")
    good = claim_lead(_dispatch(run_dir, "l-001", "g", ["d"]), run=fixture_run(run_dir))
    refused = claim_lead(_dispatch(run_dir, "l-002", "", ["d"]), run=fixture_run(run_dir))
    reused = claim_lead(_dispatch(run_dir, "l-001", "again", ["d"]), run=fixture_run(run_dir))
    assert len({good, refused, reused}) == 3, \
        "two of the claim's outcomes share a code — a caller cannot tell them apart"
    assert (good, refused, reused) == (CLAIMED, NOT_CLAIMED, ALREADY_CLAIMED)


def test_an_empty_or_whitespace_goal_claims_nothing(tmp_path):
    """The leads row records the STRIPPED goal, so `"   "` used to claim the id and write a
    row whose goal is `""` — the same empty row the falsy arm refuses, reached by a string
    that merely is not falsy. Both spellings now leave the id unclaimed AND unburnt: the
    corrected re-dispatch of the same id must still be able to take it."""
    run_dir = tmp_path / fixture_uuid("run")
    (run_dir / "gather_raw").mkdir(parents=True)
    for empty in ("", "   ", "\n\t"):
        assert claim_lead(_dispatch(run_dir, "l-001", empty, ["d"]), run=fixture_run(run_dir)) == NOT_CLAIMED
    assert list((run_dir / "gather_raw").glob("*.lead.json")) == []
    assert claim_lead(_dispatch(run_dir, "l-001", "a real question", ["d"]), run=fixture_run(run_dir)) == CLAIMED


def test_an_overlong_lead_id_is_refused_before_os_open(tmp_path):
    """A well-shaped but unbounded id spent as a filename component fails the create with
    ENAMETOOLONG, and "the write failed" is the outcome a caller has the least to say about.
    `LEAD_ID_RE` bounds the body, so the refusal happens at the shape check — and the same
    bound is what `tools_gather`'s own seam check reads."""
    run_dir = tmp_path / fixture_uuid("run")
    (run_dir / "gather_raw").mkdir(parents=True)
    assert claim_lead(_dispatch(run_dir, "l-" + "a" * 300, "g", ["d"]), run=fixture_run(run_dir)) == NOT_CLAIMED
    assert list((run_dir / "gather_raw").glob("*.lead.json")) == []


def test_malformed_lead_id_silently_skips(tmp_path):
    run_dir = tmp_path / fixture_uuid("run-bad-id")
    (run_dir / "gather_raw").mkdir(parents=True)
    assert claim_lead(_dispatch(run_dir, "0", "g", ["d"]), run=fixture_run(run_dir)) == NOT_CLAIMED
    assert list((run_dir / "gather_raw").glob("*.lead.json")) == []


def test_missing_required_keys_silently_skips_write(tmp_path):
    run_dir = tmp_path / fixture_uuid("run-d")
    (run_dir / "gather_raw").mkdir(parents=True)
    assert claim_lead({"run_dir": str(run_dir), "lead_id": "l-001"}, run=fixture_run(run_dir)) == NOT_CLAIMED
    assert not (run_dir / "gather_raw" / "l-001.lead.json").exists()


def test_non_list_what_to_summarize_silently_skips(tmp_path):
    """The `isinstance(wtc, list)` guard the live caller relies on: `tools_gather`
    unfreezes the request's tuple back to a list at that boundary precisely
    because a non-list is skipped here rather than coerced."""
    run_dir = tmp_path / fixture_uuid("run-tuple")
    (run_dir / "gather_raw").mkdir(parents=True)
    assert claim_lead(_dispatch(run_dir, "l-001", "g", ("d",)), run=fixture_run(run_dir)) == NOT_CLAIMED
    assert not (run_dir / "gather_raw" / "l-001.lead.json").exists()


def _fd_is_closed(fd: int) -> bool:
    """Whether `fd` names no open descriptor — `EBADF` on the errno, never on `strerror`, which
    is libc's and locale-dependent."""
    try:
        os.fstat(fd)
    except OSError as e:
        return e.errno == errno.EBADF
    return False


def test_fdopen_failure_removes_empty_sidecar_and_allows_retry(tmp_path, monkeypatch):
    """A write failure after the O_EXCL create must not leave a 0-byte sidecar:
    it would degrade the lead to an orphan AND falsely reject a same-id retry."""
    run_dir = tmp_path / fixture_uuid("run")
    (run_dir / "gather_raw").mkdir(parents=True)
    dispatch = _dispatch(run_dir, "l-001", "g", ["d"])

    real_fdopen = os.fdopen
    handed_out: list[int] = []

    def boom(fd, *a, **k):
        handed_out.append(fd)
        raise OSError("fdopen refused the descriptor")

    monkeypatch.setattr(os, "fdopen", boom)
    try:
        assert claim_lead(dispatch, run=fixture_run(run_dir)) == NOT_CLAIMED
    finally:
        monkeypatch.setattr(os, "fdopen", real_fdopen)

    assert len(handed_out) == 1, "the claim never reached fdopen"
    assert _fd_is_closed(handed_out[0]), \
        "the never-took-ownership branch leaked the descriptor it still owned"

    sidecar = run_dir / "gather_raw" / "l-001.lead.json"
    assert not sidecar.exists()

    assert claim_lead(dispatch, run=fixture_run(run_dir)) == CLAIMED
    assert json.loads(sidecar.read_text())["goal"] == "g"


def test_failed_flush_does_not_close_a_descriptor_it_no_longer_owns(tmp_path, monkeypatch):
    """#878 F-36 — the rooted named-create backend must not double-close on failure."""
    run_dir = tmp_path / fixture_uuid("run")
    (run_dir / "gather_raw").mkdir(parents=True)
    dispatch = _dispatch(run_dir, "l-001", "g", ["d"])

    sentinel_path = tmp_path / "sentinel"
    sentinel_path.write_text("intact", encoding="utf-8")
    class NamedCreateIo:
        def __getattr__(self, name):
            return getattr(_io, name)

        def rooted_write(self, *args, **kwargs):
            def unavailable(_directory_fd):
                raise OSError(errno.EOPNOTSUPP, "test named-create fallback")
            return _io.rooted_write(*args, **kwargs, open_unnamed=unavailable)

    run = Run.under(fixture_runs_base(run_dir.parent), run_dir.name, io=NamedCreateIo())
    real_fdopen = os.fdopen
    handed_out: list[int] = []
    sentinel_fds: list[int] = []

    class _FlushFails:
        """A REAL owner of the fd whose write fails — `__exit__` closes the underlying file,
        which is what the production `with` does and what makes the fd free again."""

        def __init__(self, fh):
            self._fh = fh

        def __enter__(self):
            return self

        def write(self, _payload):
            raise OSError(errno.ENOSPC, "No space left on device")

        def __exit__(self, *_exc):
            self._fh.close()
            sentinel_fds.append(os.open(sentinel_path, os.O_RDONLY))
            return False

    def owning_but_failing(fd, *a, **k):
        handed_out.append(fd)
        return _FlushFails(real_fdopen(fd, *a, **k))

    monkeypatch.setattr(os, "fdopen", owning_but_failing)
    try:
        assert claim_lead(dispatch, run=run) == NOT_CLAIMED
    finally:
        monkeypatch.setattr(os, "fdopen", real_fdopen)

    assert len(sentinel_fds) == 1, "the write path never reached the failing flush"
    assert sentinel_fds[0] == handed_out[0], \
        "the sentinel did not land on the freed number — this run cannot observe the double close"
    assert os.read(sentinel_fds[0], 6) == b"intact", \
        "the rollback closed a descriptor the file object already owned and already closed"
    os.close(sentinel_fds[0])

    sidecar = run_dir / "gather_raw" / "l-001.lead.json"
    assert not sidecar.exists(), "a 0-byte sidecar survived the failed write"
    assert claim_lead(dispatch, run=run) == CLAIMED, "the id was not left takeable"
    assert json.loads(sidecar.read_text())["goal"] == "g"


def test_a_planted_alias_refuses_with_the_same_remedy_the_reuse_gate_gives(tmp_path, capsys):
    """#1077 D7 review: the owner's containment check moved the alias refusal ahead of the
    `O_EXCL` create, and the new arm answered `ALREADY_CLAIMED` in SILENCE. Both arms tell the
    model the same thing — the id is held — so both owe it the same correctable instruction.
    A refusal carrying only a code is one the model can do nothing with but repeat."""
    run_dir = tmp_path / fixture_uuid("run-alias")
    (run_dir / "gather_raw").mkdir(parents=True)
    outside = tmp_path / "elsewhere.json"
    outside.write_text("{}")
    (run_dir / "gather_raw" / "l-001.lead.json").symlink_to(outside)

    assert claim_lead(_dispatch(run_dir, "l-001", "g", ["d"]), run=fixture_run(run_dir)) == ALREADY_CLAIMED
    err = capsys.readouterr().err
    assert "l-001" in err, "the alias refusal named no id"
    assert "append a new :L" in err, \
        "the alias refusal handed the model a bare code with no way to correct it"
    assert outside.read_text() == "{}", "the claim wrote through the planted alias"


def test_a_lead_id_that_is_not_a_plain_string_claims_nothing_and_does_not_raise(tmp_path):
    """`claim_lead`'s contract is "never raises: the contract is a code". The shape half of
    the owner's check (`_check_component`) raises `ValueError` for a component that is not a
    plain string, and the id regex runs on `str(lead_id)` — so an object whose `str()` looks
    like an id reaches the owner as itself. The old hand-composed f-string accepted it.

    NOT_CLAIMED, not ALREADY_CLAIMED: nothing holds the name. This is the caller handing us an
    id we cannot compose, which is a refusal, not a taken id."""
    run_dir = tmp_path / fixture_uuid("run-shape")
    assert claim_lead(_dispatch(run_dir, Path("l-a1"), "g", ["d"]), run=fixture_run(run_dir)) == NOT_CLAIMED
    assert not list((run_dir / "gather_raw").glob("*.lead.json")), "a row was written anyway"


def test_parent_alias_is_not_a_taken_lead_and_claim_recovers_when_restored(tmp_path, capsys):
    """#1165: parent preparation failure retains NOT_CLAIMED, unlike a held leaf."""
    run_dir = tmp_path / fixture_uuid("run-parent-alias")
    run_dir.mkdir()
    outside = tmp_path / "outside-claims"
    outside.mkdir()
    parent = run_dir / "gather_raw"
    parent.symlink_to(outside, target_is_directory=True)
    run = fixture_run(run_dir)
    dispatch = _dispatch(run_dir, "l-001", "g", ["d"])
    assert claim_lead(dispatch, run=run) == NOT_CLAIMED
    assert not list(outside.iterdir())
    assert "append a new :L" not in capsys.readouterr().err
    parent.unlink()
    assert claim_lead(dispatch, run=run) == CLAIMED
    assert json.loads((parent / "l-001.lead.json").read_text())["goal"] == "g"

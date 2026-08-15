"""Tests for defender/hooks/record_lead.py.

`claim_lead` writes the leads-table row `gather_raw/{lead_id}.lead.json` and
claims the `lead_id` with an atomic exclusive create — a reused id fails the
create and returns `ALREADY_CLAIMED`, which `runtime/tools_gather._run_gather`
turns into a `ModelRetry` before gather is spawned.

THE CODES ARE THREE, and every assertion below names which one it means (#855
F-12). They used to be two: success and every silent skip both returned 0, so
the one live caller could not write the check it needed and read "not the reuse
code" as success — which ran a gather session under an id with no leads row,
past the reuse gate that IS that row's exclusive create. An assertion that
spells `== CLAIMED` is one that would have failed when the write did not happen.

Driven through `claim_lead(dispatch)` — the function that live caller reaches,
with the same dict shape it builds from the typed `gather` request. These used
to run through the module's `claude -p` PreToolUse `main()`, which recovered
that dict from a Task prompt's fenced YAML; nothing invokes it, and the lenient
parser it fed (`extract_dispatch`/`_parse_block`) was deleted with it.
"""
from __future__ import annotations

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
    run_dir = tmp_path / "run-A"
    (run_dir / "gather_raw").mkdir(parents=True)
    dispatch = _dispatch(
        run_dir, "l-001", "Did the FIM fire trace to apt?", ["apt history", "checksum"]
    )
    assert claim_lead(dispatch) == CLAIMED

    sidecar = run_dir / "gather_raw" / "l-001.lead.json"
    assert sidecar.is_file()
    assert json.loads(sidecar.read_text()) == {
        "goal": "Did the FIM fire trace to apt?",
        "what_to_summarize": ["apt history", "checksum"],
    }


def test_creates_gather_raw_dir_if_missing(tmp_path):
    run_dir = tmp_path / "run-C"
    assert claim_lead(_dispatch(run_dir, "l-002", "g", ["d"])) == CLAIMED
    assert (run_dir / "gather_raw" / "l-002.lead.json").is_file()


def test_distinct_ids_in_a_batch_both_claim(tmp_path):
    run_dir = tmp_path / "run-batch"
    (run_dir / "gather_raw").mkdir(parents=True)
    assert claim_lead(_dispatch(run_dir, "l-001", "g1", ["d"])) == CLAIMED
    assert claim_lead(_dispatch(run_dir, "l-002", "g2", ["d"])) == CLAIMED
    assert (run_dir / "gather_raw" / "l-001.lead.json").is_file()
    assert (run_dir / "gather_raw" / "l-002.lead.json").is_file()


def test_reused_id_returns_already_claimed_with_remediation(tmp_path, capsys):
    run_dir = tmp_path / "run-reuse"
    (run_dir / "gather_raw").mkdir(parents=True)
    assert claim_lead(_dispatch(run_dir, "l-001", "first", ["d"])) == CLAIMED
    assert claim_lead(_dispatch(run_dir, "l-001", "second", ["d"])) == ALREADY_CLAIMED
    err = capsys.readouterr().err
    assert "l-001" in err
    assert "append a new :L" in err
    assert json.loads((run_dir / "gather_raw" / "l-001.lead.json").read_text())["goal"] == "first"


def test_the_three_codes_are_distinct(tmp_path):
    """#855 F-12, at the seam that caused it: a caller must be able to write "the row is on
    disk" as a check, and it can only do that if SUCCESS has a code no skip shares. One run
    over the three domains — a good claim, a refused one, a reused one — and the three answers
    are three."""
    run_dir = tmp_path / "run"
    good = claim_lead(_dispatch(run_dir, "l-001", "g", ["d"]))
    refused = claim_lead(_dispatch(run_dir, "l-002", "", ["d"]))
    reused = claim_lead(_dispatch(run_dir, "l-001", "again", ["d"]))
    assert len({good, refused, reused}) == 3, \
        "two of the claim's outcomes share a code — a caller cannot tell them apart"
    assert (good, refused, reused) == (CLAIMED, NOT_CLAIMED, ALREADY_CLAIMED)


def test_an_empty_or_whitespace_goal_claims_nothing(tmp_path):
    """The leads row records the STRIPPED goal, so `"   "` used to claim the id and write a
    row whose goal is `""` — the same empty row the falsy arm refuses, reached by a string
    that merely is not falsy. Both spellings now leave the id unclaimed AND unburnt: the
    corrected re-dispatch of the same id must still be able to take it."""
    run_dir = tmp_path / "run"
    (run_dir / "gather_raw").mkdir(parents=True)
    for empty in ("", "   ", "\n\t"):
        assert claim_lead(_dispatch(run_dir, "l-001", empty, ["d"])) == NOT_CLAIMED
    assert list((run_dir / "gather_raw").glob("*.lead.json")) == []
    assert claim_lead(_dispatch(run_dir, "l-001", "a real question", ["d"])) == CLAIMED


def test_an_overlong_lead_id_is_refused_before_os_open(tmp_path):
    """A well-shaped but unbounded id spent as a filename component fails the create with
    ENAMETOOLONG, and "the write failed" is the outcome a caller has the least to say about.
    `LEAD_ID_RE` bounds the body, so the refusal happens at the shape check — and the same
    bound is what `tools_gather`'s own seam check reads."""
    run_dir = tmp_path / "run"
    (run_dir / "gather_raw").mkdir(parents=True)
    assert claim_lead(_dispatch(run_dir, "l-" + "a" * 300, "g", ["d"])) == NOT_CLAIMED
    assert list((run_dir / "gather_raw").glob("*.lead.json")) == []


def test_malformed_lead_id_silently_skips(tmp_path):
    run_dir = tmp_path / "run-bad-id"
    (run_dir / "gather_raw").mkdir(parents=True)
    assert claim_lead(_dispatch(run_dir, "0", "g", ["d"])) == NOT_CLAIMED
    assert list((run_dir / "gather_raw").glob("*.lead.json")) == []


def test_missing_lead_id_silently_skips(tmp_path):
    run_dir = tmp_path / "run-no-id"
    (run_dir / "gather_raw").mkdir(parents=True)
    dispatch = {"run_dir": str(run_dir), "goal": "g", "what_to_summarize": ["d"]}
    assert claim_lead(dispatch) == NOT_CLAIMED
    assert list((run_dir / "gather_raw").glob("*.lead.json")) == []


def test_missing_required_keys_silently_skips_write(tmp_path):
    run_dir = tmp_path / "run-D"
    (run_dir / "gather_raw").mkdir(parents=True)
    assert claim_lead({"run_dir": str(run_dir), "lead_id": "l-001"}) == NOT_CLAIMED
    assert not (run_dir / "gather_raw" / "l-001.lead.json").exists()


def test_non_list_what_to_summarize_silently_skips(tmp_path):
    """The `isinstance(wtc, list)` guard the live caller relies on: `tools_gather`
    unfreezes the request's tuple back to a list at that boundary precisely
    because a non-list is skipped here rather than coerced."""
    run_dir = tmp_path / "run-tuple"
    (run_dir / "gather_raw").mkdir(parents=True)
    assert claim_lead(_dispatch(run_dir, "l-001", "g", ("d",))) == NOT_CLAIMED
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
    it would degrade the lead to an orphan AND falsely reject a same-id retry.

    NAMED for the branch it actually drives (#878 F-36). The stub raises FROM `os.fdopen`, so
    this is the one case where ownership never transferred and the hook still owes the fd a
    close — not the flush failure its "disk full" message names.
    `failed_flush_does_not_close_a_descriptor_it_no_longer_owns` below drives that one.

    The stub LEAVES THE FD OPEN, which is what the real failure does: `io.open` over a passed-in
    descriptor sets `fd_is_own = 0`, so a `FileIO` init fault — the OSError arm this branch
    exists for — returns with the descriptor untouched. A stub that closed it first would make
    the hook's own `os.close(fd)` the second close F-36 is about, silently absorbed by
    `contextlib.suppress` and invisible to every assertion here. The fd is captured instead, and
    `os.fstat` on it afterwards is what proves the hook closed the one it still owned."""
    run_dir = tmp_path / "run"
    (run_dir / "gather_raw").mkdir(parents=True)
    dispatch = _dispatch(run_dir, "l-001", "g", ["d"])

    real_fdopen = os.fdopen
    handed_out: list[int] = []

    def boom(fd, *a, **k):
        handed_out.append(fd)
        raise OSError("fdopen refused the descriptor")

    monkeypatch.setattr(os, "fdopen", boom)
    try:
        assert claim_lead(dispatch) == NOT_CLAIMED
    finally:
        monkeypatch.setattr(os, "fdopen", real_fdopen)

    assert len(handed_out) == 1, "the claim never reached fdopen"
    assert _fd_is_closed(handed_out[0]), \
        "the never-took-ownership branch leaked the descriptor it still owned"

    sidecar = run_dir / "gather_raw" / "l-001.lead.json"
    assert not sidecar.exists()

    assert claim_lead(dispatch) == CLAIMED
    assert json.loads(sidecar.read_text())["goal"] == "g"


def test_failed_flush_does_not_close_a_descriptor_it_no_longer_owns(tmp_path, monkeypatch):
    """#878 F-36 — the flush-failure rollback must NOT call `os.close(fd)`.

    `os.fdopen` takes ownership, and the `with` block closes the fd on the way out INCLUDING
    when the failure is the implicit flush inside `close()` — the ENOSPC/EDQUOT/EIO case the
    arm exists for. The `os.close(fd)` that followed was therefore a SECOND close, silent under
    `contextlib.suppress(OSError)` whether it hit EBADF or an unrelated descriptor the OS had
    since handed the same number.

    That window is reproduced here rather than reasoned about: the stub is a real file object
    that really owns the fd, and on the way out of the `with` it closes that fd and then opens a
    SENTINEL, which Linux hands the same (now lowest-free) number — exactly what lead-0's
    fire-and-forget correlation task does when its `asyncio.to_thread` → `subprocess.run` opens
    pipes while `claim_lead` runs on the event-loop thread. The assertion is that the sentinel
    is still readable afterwards. Under the defect it is closed and `os.read` raises EBADF; the
    hook has corrupted an unrelated descriptor and reported nothing.

    The rest of `failed_payload_write_removes_empty_sidecar_and_allows_retry`'s contract is
    re-asserted on this branch too, because it was only ever driven on the other one: the
    0-byte sidecar is removed, the code is `NOT_CLAIMED`, and the id stays takeable."""
    run_dir = tmp_path / "run"
    (run_dir / "gather_raw").mkdir(parents=True)
    dispatch = _dispatch(run_dir, "l-001", "g", ["d"])

    sentinel_path = tmp_path / "sentinel"
    sentinel_path.write_text("intact", encoding="utf-8")
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
        assert claim_lead(dispatch) == NOT_CLAIMED
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
    assert claim_lead(dispatch) == CLAIMED, "the id was not left takeable"
    assert json.loads(sidecar.read_text())["goal"] == "g"

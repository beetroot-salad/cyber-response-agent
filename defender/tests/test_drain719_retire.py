"""Issue #719, part 1/5 — D9's retire seam and the accounting decisions 2 and 3 settled.

Executable spec, written before the implementation (`spec_graph_719.yaml`; the demand ids
are in each test's `discharged_by`). `defender.learning.author.drain` does not exist at the
base commit, so this module errors at collection — the expected red.

Every fault below is either a real input driven through the real primitive (a row with no
id, a `.tmp` path that is a directory, a pending file that cannot be replaced) or a fake
whose fault class cites the ledger claim that observed it. The fakes inject and record;
they never classify. Injection is `dataclasses.replace(cfg, invoke_agent=...)` — the
established seam — never `monkeypatch.setattr`.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

import _drain719 as h
from _drain719 import drain  # the not-yet-written target, via the suite's own shim
from defender.learning.author import shared as author_shared  # type: ignore[import-not-found]


# Demand #0 — the return-value contract, after decision 1 flipped its `2` branch




# O6 + O8 — one uniform, bounded retirement into one graveyard








def test_an_intervening_success_does_not_reset_the_attempt_count(tmp_path: Path):
    """Decision 2: the count is LIFETIME. A row that failed, rode through a tick that
    succeeded, and failed again carries its whole history — a clean tick confers no
    exemption, and nothing on the success path clears the field.

    RE-STAGED, because the staging this was first written with is unreachable against the
    real pre-author gate. It committed the row and requeued it with `hold_committed`, then
    expected the NEXT tick to author and fault it again — but a row whose id is now in the
    corpus is exactly what the idempotency gate exists to catch, so that tick consumed it
    without ever reaching the agent and returned 0. Making it fault again would mean
    re-authoring work already in the corpus, which is the behaviour decision 9's reconciling
    tick demands the opposite of.

    So the intervening success is a tick the agent HOLDS the row back from: it succeeds,
    rotates, writes the held report, and leaves the row queued and still authorable. That is
    the one shape in which a row can survive a clean tick and fail again — which is why this
    runs on the findings channel, the only one with a held bucket."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of(paths, "findings")
    h.write_source_refs(paths, "run-I")
    h.seed(ch, [h.row_for("findings", "run-I/0")])

    fault = h.cfg_for(
        paths,
        "findings",
        max_attempts=2,
        invoke_agent=h.raising(author_shared.AuthorError("first failure")),
    )
    assert drain.run_batch(cfg=fault) == 2
    assert h.attempts_of(ch, "run-I/0") == 1

    def hold_back(rows, batch_id, cfg):
        return {
            "committed": [],
            "consumed_skip": [],
            "held_forward_bad": [
                {"finding_id": r["finding_id"], "reason": "the forward check says no"}
                for r in rows
            ],
            "commit_message": "",
        }

    ok = h.recording(hold_back)
    assert drain.run_batch(cfg=h.cfg_for(paths, "findings", max_attempts=2, invoke_agent=ok)) == 0
    assert len(ok.calls) == 1, "the successful tick never reached the agent"
    assert h.attempts_of(ch, "run-I/0") == 1, "a clean tick reset the count"

    assert drain.run_batch(cfg=fault) == 2
    assert h.pending(ch) == []
    assert [r["attempts"] for r in h.graveyard(ch)] == [2], "2, not 1 — no reset happened"




# Decision 3 — terminality: consumed ledger, graveyard first








# The ceiling's own domain — 1, 0 and -1


#: ONE DEMAND LEFT THIS FILE WITH #922. `test_a_faulted_tick_defers_its_held_and_pre_consumed_
#: classifications` needed one batch whose rows land in THREE different gate buckets at once —
#: authored, held, pre-consumed — which the observation channels gave for free because their
#: rows carried no source bundle for the gate to judge. Every findings row in one batch with
#: one ground truth lands in the same bucket, so the batch shape the demand was about cannot be
#: built on the surviving channel. Restore it when a second channel returns.


def _retires_on_the_first_failure(tmp_path: Path, ceiling: int) -> None:
    """Shared body for the three ceiling members; each demand's own test drives it."""
    paths = h.make_paths(tmp_path)
    h.write_source_refs(paths, "b")
    ch = h.channel_of(paths, "findings")
    h.seed(ch, [h.row_for("findings", "b/0")])
    cfg = h.cfg_for(
        paths,
        "findings",
        max_attempts=ceiling,
        invoke_agent=h.raising(author_shared.AuthorError("one and done")),
    )
    assert drain.run_batch(cfg=cfg) == 2
    assert h.pending(ch) == []
    assert [r["attempts"] for r in h.graveyard(ch)] == [1]


def test_ceiling_of_one_retires_on_the_first_failure(tmp_path: Path):
    """Fail-fast is the ceiling at 1, not a second mechanism: one failure retires the row
    into the graveyard with `attempts` 1. Decision 4 rejected the clause's argument that
    this had no in-suite exercise because its only production caller is out of scope — the
    retire seam is driven here with no such caller, exactly as C33 drove it."""
    _retires_on_the_first_failure(tmp_path, 1)


def test_zero_ceiling_retires_on_first_failure(tmp_path: Path):
    """A ceiling of 0 is a reachable operator input — `env_int` applies no floor (G25) — and
    it is FALSY, the `x or DEFAULT` shape that would silently promote it to 3. It means
    retire on the first observed failure, not retire before any attempt: the row is authored
    once, fails once, and leaves."""
    _retires_on_the_first_failure(tmp_path, 0)


def test_negative_ceiling_retires_like_zero(tmp_path: Path):
    """A negative ceiling is accepted rather than rejected, and behaves as 0 — probed
    identical at 1/0/-1 by C33. Pinned rather than validated away, because the design never
    asked for a validation layer here."""
    _retires_on_the_first_failure(tmp_path, -1)


# The seam's edges — what it does not touch, and what stops it


def test_retire_leaves_every_row_outside_the_batch_byte_identical(tmp_path: Path):
    """Retirement is scoped to the ids it was handed. Rows outside the batch come through
    unchanged in EVERY field — no attempts key appears on them, no ordering rewrite, no
    re-serialisation drift — so an unrelated row cannot be quietly edited by a neighbour's
    failure."""
    paths = h.make_paths(tmp_path)
    h.write_source_refs(paths, "a")
    ch = h.channel_of(paths, "findings")
    outsiders = [
        h.row_for("findings", "a/1", note="keep me", nested={"x": [1, 2]}),
        h.row_for("findings", "a/2", attempts=7),
    ]
    h.seed(ch, [h.row_for("findings", "a/0"), *outsiders])

    drain.retire(channel=ch, batch_ids=["a/0"], reason="scoped", max_attempts=1)

    survivors = h.pending_by_id(ch)
    assert sorted(survivors) == ["a/1", "a/2"]
    assert survivors["a/1"] == outsiders[0]
    assert survivors["a/2"] == outsiders[1]


def test_a_failing_retirement_write_stops_the_drain_and_leaves_the_queue_intact(tmp_path: Path):
    """A11: the retire step's OWN write failing is systemic. It sits outside the widened
    guard by construction (decision 6), so the fault propagates out of the drain instead of
    being caught and counted as another attempt against the row it was trying to retire —
    and the active queue is left byte-identical for the next tick to re-read. Induced for
    real: the channel's graveyard path is a directory, so the append cannot land."""
    paths = h.make_paths(tmp_path)
    h.write_source_refs(paths, "a")
    ch = h.channel_of(paths, "findings")
    h.seed(ch, [h.row_for("findings", "a/0")])
    before = ch.file.read_bytes()
    drain.graveyard_file(ch).mkdir(parents=True)

    cfg = h.cfg_for(
        paths,
        "findings",
        max_attempts=1,
        invoke_agent=h.raising(author_shared.AuthorError("triggers a retirement")),
    )
    with pytest.raises(OSError):  # noqa: PT011 - the OS-level append failure's exact subclass is platform-dependent; the point is that it propagates uncaught
        drain.run_batch(cfg=cfg)
    assert ch.file.read_bytes() == before, "the queue survives a failed retirement write"






def test_an_all_empty_tick_writes_no_consumed_row_and_no_graveyard_row(tmp_path: Path):
    """C15: a tick that finds nothing on any channel is inert — it appends no consumed row
    and no graveyard row, so a steady state of empty ticks cannot grow either file. The
    positive control is the same drain on a non-empty channel, which does write both."""
    paths = h.make_paths(tmp_path)
    h.write_source_refs(paths, "a")
    for name in h.AUTHOR_CHANNELS:
        ch = h.channel_of(paths, name)
        cfg = h.cfg_for(paths, name, invoke_agent=h.raising(AssertionError("never called")))
        assert drain.run_batch(cfg=cfg) == 0
        assert h.consumed(ch) == []
        assert h.graveyard(ch) == []

    ch = h.channel_of(paths, "findings")
    h.seed(ch, [h.row_for("findings", "a/0")])
    live = h.cfg_for(
        paths,
        "findings",
        max_attempts=1,
        invoke_agent=h.raising(author_shared.AuthorError("so the sinks can be seen")),
    )
    assert drain.run_batch(cfg=live) == 2
    assert h.graveyard(ch)
    assert h.consumed(ch)




#: `(file, function)` pairs that reach `write_atomic` without writing a QUEUE — the census's
#: proxy for "rewrites a queue file wholesale" went wide the moment a second kind of writer
#: adopted the same seam. `synthesize_drafts` writes one `_draft/{digest}.md` catalog template
#: per identity, into the corpus, never into `state_dir`: no queue, nothing to merge, no
#: lost-append race for a rotation to close. Keyed on the FUNCTION and not on the file (the way
#: `markers.py` is skipped whole) so the rest of `draft_synthesis.py` stays inside the census —
#: an exclusion the width of a module is one that stops answering the moment that module grows
#: a second writer.
_NOT_A_QUEUE_WRITER = frozenset({("draft_synthesis.py", "synthesize_drafts")})


def test_exactly_one_function_rewrites_a_pending_file(tmp_path: Path):
    """D9 removes the second write path rather than adding a lock to it: after the fold
    exactly one function under `defender/learning` rewrites a queue file wholesale, and the
    retire seam reaches it through the same locked rotation that rotation uses. The census
    picks the subject; the drive is what discharges it — a row appended between the read and
    the rewrite survives, which only the merging rotation gives."""
    import defender.learning as learning_pkg  # type: ignore[import-not-found]

    root = Path(learning_pkg.__path__[0]).resolve()  # namespace pkg: __file__ is None
    writers: dict[str, set[str]] = {}
    for py in sorted(root.rglob("*.py")):
        if py.name == "markers.py":
            continue  # a marker-directory queue, explicitly out of scope (A5)
        tree = ast.parse(py.read_text(encoding="utf-8"), filename=str(py))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if (py.name, node.name) in _NOT_A_QUEUE_WRITER:
                continue
            for call in ast.walk(node):
                if isinstance(call, ast.Call):
                    fn = call.func
                    nm = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
                    if nm == "write_atomic":
                        writers.setdefault(node.name, set()).add(py.name)
    assert set(writers) == {"_rewrite_queue"}, f"more than one queue rewriter: {writers}"

    paths = h.make_paths(tmp_path)
    h.write_source_refs(paths, "a")
    ch = h.channel_of(paths, "findings")
    h.seed(ch, [h.row_for("findings", "a/0"), h.row_for("findings", "a/9")])
    drain.retire(channel=ch, batch_ids=["a/0"], reason="via the rotation", max_attempts=1)
    assert sorted(h.pending_by_id(ch)) == ["a/9"]


def test_attempt_count_survives_a_fresh_process(tmp_path: Path):
    """P38: `attempts` lives on the queue row, so a second, genuinely separate process picks
    the count up off disk rather than starting over. Driven as a real subprocess because
    `DEFAULT_PATHS` is frozen at import (F7) — an in-process environment change would not
    reach a second actor at all."""
    paths = h.make_paths(tmp_path)
    h.write_source_refs(paths, "a")
    ch = h.channel_of(paths, "findings")
    h.seed(ch, [h.row_for("findings", "a/0")])

    drain.retire(channel=ch, batch_ids=["a/0"], reason="first process", max_attempts=3)
    assert h.attempts_of(ch, "a/0") == 1

    script = (
        "import sys\n"
        "from pathlib import Path\n"
        "from defender.learning.author import drain\n"
        "from defender.learning.core.config import LoopPaths\n"
        "paths = LoopPaths(repo_root=Path(sys.argv[1]))\n"
        "out = drain.retire(channel=paths.findings, batch_ids=['a/0'],\n"
        "                   reason='second process', max_attempts=2)\n"
        "print(out.bumped['a/0'])\n"
    )
    proc = h.run_in_subprocess(script, repo=paths.repo_root)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "2", "the fresh process read 1 off the row and bumped to 2"
    assert h.pending(ch) == []
    assert [r["attempts"] for r in h.graveyard(ch)] == [2]

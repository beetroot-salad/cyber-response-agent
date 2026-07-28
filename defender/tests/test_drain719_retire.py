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
import json
import threading
from pathlib import Path

import pytest

import _drain719 as h
from _drain719 import drain  # the not-yet-written target, via the suite's own shim
from defender.learning.author import shared as author_shared  # type: ignore[import-not-found]
from defender.learning.core import persist  # type: ignore[import-not-found]
from defender.learning.leads import pitfalls_curator  # type: ignore[import-not-found]


# =======================================================================================
# Demand #0 — the return-value contract, after decision 1 flipped its `2` branch
# =======================================================================================


def test_folded_drain_rc_alphabet_after_the_pitfalls_fault_conversion(tmp_path: Path):
    """The folded drain keeps today's `0` branch on every leg — an empty queue, a drain
    lock another process holds, and an unavailable repo lock all return 0 with the queue
    untouched — and keeps `2` for a faulted author batch on the findings and observation
    channels. The pitfalls leg's `2` is REJECTED: `run_pitfalls` signals an authoring
    failure by raising a non-systemic `AuthorError` the retire seam observes, not by
    returning a value `_drain_pitfalls` never inspects (G18/C23).
    """
    paths = h.make_paths(tmp_path)
    obs = h.channel_of(paths, "actor_observations")
    fnd = h.channel_of(paths, "findings")

    empty_cfg = h.cfg_for(paths, "actor_observations", invoke_agent=h.raising(AssertionError()))
    assert drain.run_batch(cfg=empty_cfg) == 0, "an empty queue is the 0 branch"

    h.seed(obs, [h.row_for("actor_observations", "a/0")])
    with h.Holder(obs.drain_lock, blocking_discipline=False):
        held = h.recording(h.skipping())
        assert drain.run_batch(cfg=h.cfg_for(paths, "actor_observations", invoke_agent=held)) == 0
        assert held.calls == [], "a held drain lock skips the tick before any authoring"

    with h.Holder(paths.author_lock_file):
        starved = h.recording(h.skipping())
        cfg = h.cfg_for(
            paths, "actor_observations", invoke_agent=starved, repo_lock_wait_seconds=1
        )
        assert drain.run_batch(cfg=cfg) == 0, "an unavailable repo lock is the 0 branch"
        assert starved.calls == []

    faulting = h.cfg_for(
        paths, "actor_observations", invoke_agent=h.raising(author_shared.AuthorError("boom"))
    )
    assert drain.run_batch(cfg=faulting) == 2, "an author-channel fault keeps rc 2"

    h.write_source_refs(paths, "run-K")
    h.seed(fnd, [h.row_for("findings", "run-K/0")])
    findings_fault = h.cfg_for(
        paths, "findings", invoke_agent=h.raising(author_shared.AuthorError("boom"))
    )
    assert drain.run_batch(cfg=findings_fault) == 2

    h.seed(paths.pitfalls, [h.row_for("pitfalls", f"r:l-{i:03d}:0") for i in range(2)])
    with pytest.raises(author_shared.AuthorError):
        pitfalls_curator.run_pitfalls(paths=paths, invoke=lambda *a, **k: 7)


# =======================================================================================
# O6 + O8 — one uniform, bounded retirement into one graveyard
# =======================================================================================


def test_retirement_is_identical_for_observations_and_findings(tmp_path: Path):
    """One retire seam, so the same fault at the same ceiling produces the same observable
    on the findings channel and on an observation channel: the row leaves the pending file,
    lands in that channel's own graveyard carrying its reason and its attempt count, and the
    two graveyard rows differ only in the id field each channel keys on."""
    paths = h.make_paths(tmp_path)
    h.write_source_refs(paths, "run-A")
    outcomes = {}
    for name, rid in (("findings", "run-A/0"), ("actor_observations", "a/0")):
        ch = h.channel_of(paths, name)
        h.seed(ch, [h.row_for(name, rid)])
        cfg = h.cfg_for(
            paths,
            name,
            max_attempts=2,
            invoke_agent=h.raising(author_shared.AuthorError("uniform fault")),
        )
        for _ in range(2):
            assert drain.run_batch(cfg=cfg) == 2
        grave = h.graveyard(ch)
        assert h.pending(ch) == [], f"{name}: the retired row left the active queue"
        assert len(grave) == 1
        outcomes[name] = (
            grave[0]["attempts"],
            grave[0]["deadletter_reason"],
            sorted(set(grave[0]) - {"observation_id", "finding_id"}),
        )
    assert outcomes["findings"] == outcomes["actor_observations"]


def test_retirement_is_batch_granular(tmp_path: Path):
    """Re-scoped by decision 2: what is batch-granular is THE BUMP. Every row in a faulted
    batch bumps by one, so rows that entered together and failed together cross the ceiling
    together and leave as a unit — the uniform-entry case that keeps
    `test_dlq_quarantine_is_batch_granular`'s meaning intact."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of(paths, "actor_environment_observations")
    ids = ["e/0", "e/1", "e/2"]
    h.seed(ch, [h.row_for("actor_environment_observations", i) for i in ids])
    cfg = h.cfg_for(
        paths,
        "actor_environment_observations",
        max_attempts=2,
        invoke_agent=h.raising(author_shared.AuthorError("poison batch")),
    )

    assert drain.run_batch(cfg=cfg) == 2
    assert sorted(h.pending_by_id(ch)) == ids, "no row leaves before the ceiling"
    assert [r["attempts"] for r in h.pending(ch)] == [1, 1, 1]

    assert drain.run_batch(cfg=cfg) == 2
    assert h.pending(ch) == [], "the whole batch crosses together"
    assert sorted(r["observation_id"] for r in h.graveyard(ch)) == ids


def test_a_faulted_batch_bumps_every_row_and_retires_only_the_ceiling_crossers(tmp_path: Path):
    """Decision 2, the discriminating half: rows in one faulted batch with DIVERGENT prior
    counts all bump by one, and only the rows now at or over the ceiling retire. The
    first-attempt newcomer in the same batch is the positive control — it bumps to 1 and
    stays queued while its ceiling-crossing sibling leaves."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of(paths, "actor_observations")
    h.seed(
        ch,
        [
            h.row_for("actor_observations", "a/0", attempts=2),
            h.row_for("actor_observations", "a/1"),
        ],
    )
    cfg = h.cfg_for(
        paths,
        "actor_observations",
        max_attempts=3,
        invoke_agent=h.raising(author_shared.AuthorError("divergent-count batch")),
    )
    assert drain.run_batch(cfg=cfg) == 2

    survivors = h.pending_by_id(ch)
    assert sorted(survivors) == ["a/1"], "only the crosser retires"
    assert survivors["a/1"]["attempts"] == 1, "the newcomer bumped and stayed"
    grave = {r["observation_id"]: r for r in h.graveyard(ch)}
    assert sorted(grave) == ["a/0"]
    assert grave["a/0"]["attempts"] == 3


def test_an_intervening_success_does_not_reset_the_attempt_count(tmp_path: Path):
    """Decision 2: the count is LIFETIME. A row that failed, was authored successfully on a
    later tick, was requeued, and failed again carries its whole history — being authored
    once confers no exemption, and nothing on the success path clears the field."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of(paths, "actor_observations")
    h.seed(ch, [h.row_for("actor_observations", "a/0")])

    fault = h.cfg_for(
        paths,
        "actor_observations",
        max_attempts=2,
        invoke_agent=h.raising(author_shared.AuthorError("first failure")),
    )
    assert drain.run_batch(cfg=fault) == 2
    assert h.attempts_of(ch, "a/0") == 1

    ok = h.cfg_for(paths, "actor_observations", max_attempts=2, invoke_agent=h.committing())
    assert drain.run_batch(cfg=ok, hold_committed=True) == 0
    assert h.attempts_of(ch, "a/0") == 1, "an authored-then-requeued row keeps its count"

    assert drain.run_batch(cfg=fault) == 2
    assert h.pending(ch) == []
    assert [r["attempts"] for r in h.graveyard(ch)] == [2], "2, not 1 — no reset happened"


def test_a_row_at_or_over_the_ceiling_on_arrival_does_not_retire_until_it_fails(tmp_path: Path):
    """Decision 2: the ceiling is consulted only after an observed failure, never on entry.
    A row imported at 5 under a ceiling of 3, and a row at 2 under a ceiling lowered to 1,
    both survive a tick that authors them cleanly; only a tick that actually faults them
    retires them."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of(paths, "actor_observations")

    h.seed(ch, [h.row_for("actor_observations", "a/0", attempts=5)])
    ok = h.cfg_for(paths, "actor_observations", max_attempts=3, invoke_agent=h.committing("l1"))
    assert drain.run_batch(cfg=ok) == 0
    assert h.graveyard(ch) == [], "arriving over the ceiling is not itself a failure"
    assert [r["attempts"] for r in h.consumed(ch)] == [5], "the count rode through untouched"

    h.seed(ch, [h.row_for("actor_observations", "a/1", attempts=2)])
    lowered_ok = h.cfg_for(
        paths, "actor_observations", max_attempts=1, invoke_agent=h.committing("l2")
    )
    assert drain.run_batch(cfg=lowered_ok) == 0
    assert h.graveyard(ch) == [], "a lowered ceiling applies at the next failure, not on sight"

    h.seed(ch, [h.row_for("actor_observations", "a/2", attempts=2)])
    lowered_fault = h.cfg_for(
        paths,
        "actor_observations",
        max_attempts=1,
        invoke_agent=h.raising(author_shared.AuthorError("now it fails")),
    )
    assert drain.run_batch(cfg=lowered_fault) == 2
    assert [r["observation_id"] for r in h.graveyard(ch)] == ["a/2"]


# =======================================================================================
# Decision 3 — terminality: consumed ledger, graveyard first
# =======================================================================================


def test_a_retired_id_is_deduped_out_of_a_later_append_on_the_dedup_channels(tmp_path: Path):
    """Decision 3: retirement is terminal because the retired row is written to the CONSUMED
    ledger, which the observation append path already reads to dedup (G23) — not because a
    new graveyard read was added to the hot append path. A later append regenerating the same
    id is skipped; a fresh id in the same call still lands, which is the control proving the
    appender was working and the skip was the ledger's doing."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of(paths, "actor_observations")
    h.seed(ch, [h.row_for("actor_observations", "run-Z/0")])
    cfg = h.cfg_for(
        paths,
        "actor_observations",
        max_attempts=1,
        invoke_agent=h.raising(author_shared.AuthorError("terminal fault")),
    )
    assert drain.run_batch(cfg=cfg) == 2
    assert [r["observation_id"] for r in h.graveyard(ch)] == ["run-Z/0"]
    assert [(r["observation_id"], r["consumed_category"]) for r in h.consumed(ch)] == [
        ("run-Z/0", "consumed_retired")
    ]

    written = persist._append_observations(
        ch.file,
        ch.consumed,
        ch.append_lock,
        "run-Z",
        [{"o": 0}, {"o": 1}],
        lambda i, obs, oid: {"observation_id": oid, "judge_outcome": "caught"},
    )
    assert written == 1, "the retired id is deduped out; its fresh sibling still lands"
    assert sorted(h.pending_by_id(ch)) == ["run-Z/1"]


def test_the_graveyard_append_lands_before_the_pending_rewrite_and_is_advisory(tmp_path: Path):
    """Decision 3 pins the ORDER: the graveyard append happens first, and the pending file
    stays authoritative. Observed by making the rewrite fail for real — the tmp path
    `write_atomic` needs is occupied by a directory — and seeing the graveyard row already
    on disk while the queue is untouched. Recovering the tmp path and retiring again leaves
    the queue authoritative; the duplicate graveyard row a crash between the two writes
    leaves costs nothing, because the graveyard has no production reader (G16/C20)."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of(paths, "actor_observations")
    h.seed(ch, [h.row_for("actor_observations", "a/0"), h.row_for("actor_observations", "a/1")])
    before = ch.file.read_bytes()

    blocker = ch.file.with_name(ch.file.name + ".tmp")
    blocker.mkdir(parents=True)
    with pytest.raises(OSError):  # noqa: PT011 - the OS-level rename failure's exact subclass is platform-dependent; the point is that the write does not silently succeed
        drain.retire(channel=ch, batch_ids=["a/0"], reason="advisory probe", max_attempts=1)

    assert [r["observation_id"] for r in h.graveyard(ch)] == ["a/0"], "graveyard first"
    assert ch.file.read_bytes() == before, "the queue is authoritative and untouched"

    blocker.rmdir()
    outcome = drain.retire(
        channel=ch, batch_ids=["a/0"], reason="advisory probe", max_attempts=1
    )
    assert outcome.retired == ("a/0",)
    assert sorted(h.pending_by_id(ch)) == ["a/1"]
    assert [r["observation_id"] for r in h.graveyard(ch)] == ["a/0", "a/0"]


def test_consumed_ledger_append_survives_a_concurrent_interleaving(tmp_path: Path):
    """The consumed ledger is a genuine read/write shared path — three of five channels read
    it back to dedup (G23) — and decision 3 makes the retire seam a second writer into it.
    Two writers interleaving on one channel must leave every line parseable and every id
    present: a torn line here is a silent dedup bug, not merely a lost write."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of(paths, "actor_observations")
    left = [f"L/{i}" for i in range(40)]
    right = [f"R/{i}" for i in range(40)]
    h.seed(ch, [h.row_for("actor_observations", i) for i in left + right])

    def retire_all(ids):
        return lambda: drain.retire(
            channel=ch, batch_ids=ids, reason="interleaved", max_attempts=1
        )

    a, b = h.Background(retire_all(left)), h.Background(retire_all(right))
    with a, b:
        pass
    assert a.error is None
    assert b.error is None

    text = ch.consumed.read_text()
    rows = [json.loads(ln) for ln in text.splitlines() if ln.strip()]
    assert len(rows) == 80, "no lost update"
    assert {r["observation_id"] for r in rows} == set(left + right)


# =======================================================================================
# The ceiling's own domain — 1, 0 and -1
# =======================================================================================


def _retires_on_the_first_failure(tmp_path: Path, ceiling: int) -> None:
    """Shared body for the three ceiling members; each demand's own test drives it."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of(paths, "environment_observations")
    h.seed(ch, [h.row_for("environment_observations", "b/0")])
    cfg = h.cfg_for(
        paths,
        "environment_observations",
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


# =======================================================================================
# The seam's edges — what it does not touch, and what stops it
# =======================================================================================


def test_retire_leaves_every_row_outside_the_batch_byte_identical(tmp_path: Path):
    """Retirement is scoped to the ids it was handed. Rows outside the batch come through
    unchanged in EVERY field — no attempts key appears on them, no ordering rewrite, no
    re-serialisation drift — so an unrelated row cannot be quietly edited by a neighbour's
    failure."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of(paths, "actor_observations")
    outsiders = [
        h.row_for("actor_observations", "a/1", note="keep me", nested={"x": [1, 2]}),
        h.row_for("actor_observations", "a/2", attempts=7),
    ]
    h.seed(ch, [h.row_for("actor_observations", "a/0"), *outsiders])

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
    ch = h.channel_of(paths, "actor_observations")
    h.seed(ch, [h.row_for("actor_observations", "a/0")])
    before = ch.file.read_bytes()
    drain.graveyard_file(ch).mkdir(parents=True)

    cfg = h.cfg_for(
        paths,
        "actor_observations",
        max_attempts=1,
        invoke_agent=h.raising(author_shared.AuthorError("triggers a retirement")),
    )
    with pytest.raises(OSError):  # noqa: PT011 - the OS-level append failure's exact subclass is platform-dependent; the point is that it propagates uncaught
        drain.run_batch(cfg=cfg)
    assert ch.file.read_bytes() == before, "the queue survives a failed retirement write"


def test_a_faulted_tick_defers_its_held_and_pre_consumed_classifications(tmp_path: Path):
    """A8: a tick whose authoring faults commits only the retirement. The rows the gate held
    and the rows it pre-consumed are left exactly where they were, to be re-classified on the
    next tick — the failing tick does not get to half-rotate a queue whose authoring never
    landed."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of(paths, "actor_observations")
    rows = [
        h.row_for("actor_observations", "a/0"),
        h.row_for("actor_observations", "a/1", outcome="survived"),
        h.row_for("actor_observations", "a/2", outcome="unrecognised-outcome"),
    ]
    h.seed(ch, rows)
    cfg = h.cfg_for(
        paths,
        "actor_observations",
        max_attempts=1,
        invoke_agent=h.raising(author_shared.AuthorError("authoring failed")),
    )
    assert drain.run_batch(cfg=cfg) == 2

    survivors = h.pending_by_id(ch)
    assert sorted(survivors) == ["a/1", "a/2"], "only the authored row retired"
    assert survivors["a/1"] == rows[1], "the pre-consumed row was not rotated out"
    assert survivors["a/2"] == rows[2], "the held row carries no held_reason yet"
    assert [r.get("consumed_category") for r in h.consumed(ch)] == ["consumed_retired"]


def test_a_row_with_no_value_under_its_id_key_retires_instead_of_aborting(tmp_path: Path):
    """E1: a row carrying no value under its channel's id field — a fixture copy, an older
    schema, a truncation — is bad data, not a broken system. It retires as a per-item failure
    carrying a reason that names the missing field, and its well-formed batch-mates are
    authored on the same tick rather than being stranded behind it."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of(paths, "actor_observations")
    unkeyable = {"judge_outcome": "caught", "source_run_dir": "", "note": "no id at all"}
    h.seed(ch, [unkeyable, h.row_for("actor_observations", "a/1")])

    agent = h.recording(h.committing("keyed"))
    cfg = h.cfg_for(paths, "actor_observations", max_attempts=1, invoke_agent=agent)
    assert drain.run_batch(cfg=cfg) == 0

    assert [r["observation_id"] for r in agent.calls[0]["rows"]] == ["a/1"]
    grave = h.graveyard(ch)
    assert len(grave) == 1
    assert grave[0]["note"] == "no id at all"
    assert ch.id_key in grave[0]["deadletter_reason"]
    assert h.pending(ch) == []


def test_an_all_empty_tick_writes_no_consumed_row_and_no_graveyard_row(tmp_path: Path):
    """C15: a tick that finds nothing on any channel is inert — it appends no consumed row
    and no graveyard row, so a steady state of empty ticks cannot grow either file. The
    positive control is the same drain on a non-empty channel, which does write both."""
    paths = h.make_paths(tmp_path)
    for name in h.AUTHOR_CHANNELS:
        ch = h.channel_of(paths, name)
        cfg = h.cfg_for(paths, name, invoke_agent=h.raising(AssertionError("never called")))
        assert drain.run_batch(cfg=cfg) == 0
        assert h.consumed(ch) == []
        assert h.graveyard(ch) == []

    ch = h.channel_of(paths, "actor_observations")
    h.seed(ch, [h.row_for("actor_observations", "a/0")])
    live = h.cfg_for(
        paths,
        "actor_observations",
        max_attempts=1,
        invoke_agent=h.raising(author_shared.AuthorError("so the sinks can be seen")),
    )
    assert drain.run_batch(cfg=live) == 2
    assert h.graveyard(ch)
    assert h.consumed(ch)


def test_retirement_retains_row_appended_mid_window(tmp_path: Path):
    """O1 on the retire path: a row appended while the retire seam is between its read and
    its rewrite is still in pending afterward. The appender's own blocking acquisition of the
    append lock is what serialises it — so this is the property the unlocked
    read-modify-write lost today (G13/C16), driven through the real appender."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of(paths, "actor_observations")
    h.seed(ch, [h.row_for("actor_observations", "a/0")])

    started = threading.Event()

    def late_append():
        started.wait(timeout=10)
        persist._append_observations(
            ch.file,
            ch.consumed,
            ch.append_lock,
            "late",
            [{"o": 0}],
            lambda i, obs, oid: {"observation_id": oid, "judge_outcome": "caught"},
        )

    with h.Background(late_append):
        started.set()
        drain.retire(channel=ch, batch_ids=["a/0"], reason="mid-window", max_attempts=1)

    survivors = sorted(h.pending_by_id(ch))
    assert survivors == ["late/0"], "the concurrently appended row is not lost"
    assert [r["observation_id"] for r in h.graveyard(ch)] == ["a/0"]


def test_exactly_one_function_rewrites_a_pending_file(tmp_path: Path):
    """D9 removes the second write path rather than adding a lock to it: after the fold
    exactly one function under `defender/learning` rewrites a queue file wholesale, and the
    retire seam reaches it through the same locked rotation that rotation uses. The census
    picks the subject; the drive is what discharges it — a row appended between the read and
    the rewrite survives, which only the merging rotation gives."""
    import defender.learning as learning_pkg  # type: ignore[import-not-found]

    root = Path(learning_pkg.__file__).resolve().parent
    writers: dict[str, set[str]] = {}
    for py in sorted(root.rglob("*.py")):
        if py.name == "markers.py":
            continue  # a marker-directory queue, explicitly out of scope (A5)
        tree = ast.parse(py.read_text(encoding="utf-8"), filename=str(py))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for call in ast.walk(node):
                if isinstance(call, ast.Call):
                    fn = call.func
                    nm = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
                    if nm == "write_atomic":
                        writers.setdefault(node.name, set()).add(py.name)
    assert set(writers) == {"_rewrite_queue"}, f"more than one queue rewriter: {writers}"

    paths = h.make_paths(tmp_path)
    ch = h.channel_of(paths, "actor_observations")
    h.seed(ch, [h.row_for("actor_observations", "a/0"), h.row_for("actor_observations", "a/9")])
    drain.retire(channel=ch, batch_ids=["a/0"], reason="via the rotation", max_attempts=1)
    assert sorted(h.pending_by_id(ch)) == ["a/9"]


def test_attempt_count_survives_a_fresh_process(tmp_path: Path):
    """P38: `attempts` lives on the queue row, so a second, genuinely separate process picks
    the count up off disk rather than starting over. Driven as a real subprocess because
    `DEFAULT_PATHS` is frozen at import (F7) — an in-process environment change would not
    reach a second actor at all."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of(paths, "actor_observations")
    h.seed(ch, [h.row_for("actor_observations", "a/0")])

    drain.retire(channel=ch, batch_ids=["a/0"], reason="first process", max_attempts=3)
    assert h.attempts_of(ch, "a/0") == 1

    script = (
        "import sys\n"
        "from pathlib import Path\n"
        "from defender.learning.author import drain\n"
        "from defender.learning.core.config import LoopPaths\n"
        "paths = LoopPaths(repo_root=Path(sys.argv[1]))\n"
        "out = drain.retire(channel=paths.actor_observations, batch_ids=['a/0'],\n"
        "                   reason='second process', max_attempts=2)\n"
        "print(out.bumped['a/0'])\n"
    )
    proc = h.run_in_subprocess(script, repo=paths.repo_root)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "2", "the fresh process read 1 off the row and bumped to 2"
    assert h.pending(ch) == []
    assert [r["attempts"] for r in h.graveyard(ch)] == [2]

"""#996 — the document stamp, and branch/resume reading it instead of the transcript.

D6 records the document's state on every MAIN request row AT THE STORE and deletes the
transcript walk that used to reconstruct it. The smell that motivated it is worth restating,
because it is what the demands here are shaped around: `fence_count_at` replayed tool ARGUMENTS
in place of state nobody recorded, and three separate facts break the "count the append calls"
shortcut — one call may carry several fences, one turn may carry several calls, and not every
fence came from a call at all.

PROBED at this base and carried as fact rather than as a reading:
  * one MAIN turn carrying TWO `record` calls lands ONE `kind='request'` row, because the
    framework bundles both tool returns into one request — so the arithmetic is "one row per
    turn's tool-return message", never "one row per `record` call";
  * `scan_fences` never raises and answers zero for an empty or header-only document, so the
    missing-document case is `(0, 0)` with no special case;
  * the `message` table has NO id-keyed uniqueness constraint and `seq` is recomputed per
    insert, so a re-ingest DUPLICATES SILENTLY — the re-entrancy guard the stamp can inherit is
    the render-length slice, not a database rule that does not exist.

RED against `7fa49f04`: there is no `document_state` table, no `document_state_at`, and the
schema version is 2.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender._run_paths import RunPaths  # noqa: E402
from defender.tests import _clerk_996 as C  # noqa: E402
from defender.tests._session_store_705 import (  # noqa: E402
    complete_pair,
    make_store,
    nine_row_fixture,
    runs_base,
    selection_mod,
    sql,
    store_factory,
    store_mod,
    text_response,
    tool_call_response,
    tool_return_request,
    user_request,
)
from defender.tests.e2e._replay_harness import Turn  # noqa: E402


def _reader_for(text: str):
    """A `document_reader` over a fixed document — the callable shape the design names, taking
    nothing and answering `(byte_len, fence_count)`."""
    def read() -> tuple[int, int]:
        return len(text.encode("utf-8")), C.fences(text)

    return read


def _stamped_store(tmp_path: Path, text: str):
    """A real store whose handle carries a `document_reader`, plus one main session."""
    store = make_store(tmp_path)
    store.document_reader = _reader_for(text)
    return store, store.new_session(agent_id="main")


# ---------------------------------------------------------------------------------------
# the stamp itself (D6, S5)
# ---------------------------------------------------------------------------------------


def test_996_every_main_request_row_carries_a_document_stamp(tmp_path: Path) -> None:
    """Every `kind='request'` row of a driven run's main session carries a `document_state`
    stamp — and the reader is attached on the HANDLE the store factory returned, not inside the
    default factory.

    The distinction is the whole of fork F-STAMP and it is why this is driven through the
    INJECTED factory rather than the default one: a reader attached only on the default arm
    leaves exactly the resumed and replay-injected runs unstamped, which are the runs O9 exists
    for — and a stated positive control that drives the default path passes under either arm
    and discriminates nothing.

    The accepted cost is stated with the decision: the handle gains a post-construction mutable
    field, so a caller that forgets to attach one gets a silently unstamped store."""
    sink: list = []
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE)
    C.record_run(tmp_path, run_dir=run_dir,
                 clerk=C.ScriptedClerk(C.clerk_reply(C.CLEAN_ROWS)),
                 store_factory=store_factory(tmp_path, sink=sink),
                 prose=[C.PROSE, C.SECOND_PROSE])

    assert sink, "the injected store factory was never called"
    store = sink[0]
    requests = sql(store, "SELECT id FROM message WHERE kind = 'request' AND agent_id = 'main'")
    assert requests, "the run recorded no main request rows at all"
    stamped = {row[0] for row in sql(store, "SELECT message_id FROM document_state")}
    missing = [rid for (rid,) in requests if rid not in stamped]
    assert missing == [], (
        f"main request row(s) {missing} carry no document stamp — a branch at one of them has "
        f"nothing to read and O9's whole mechanism is unavailable there"
    )


def test_996_the_document_state_table_stores_two_integers(tmp_path: Path) -> None:
    """NEGATIVE (S5): the stamp table holds two integers and a message id, and no document
    CONTENT — the store sits beside the runs base and must gain no replay surface.

    The DDL is the control, and the assertion is over the columns the table actually has rather
    than over the values one row happens to hold: a TEXT column nobody fills today is a replay
    surface tomorrow.

    POSITIVE CONTROL on the same address under the complementary condition: the document's
    bytes DO reach disk through `investigation.md`, so "the content is not in the store" is a
    boundary rather than a run in which nothing was written."""
    text = C.PROLOGUE + "\nSECRET-DOCUMENT-MARKER-996\n"
    store, session = _stamped_store(tmp_path, text)
    store.append(session, [user_request("investigate")], agent_id="main")

    cols = sql(store, "PRAGMA table_info(document_state)")
    assert cols, "there is no `document_state` table"
    by_name = {row[1]: row[2].upper() for row in cols}
    assert set(by_name) == {"message_id", "byte_len", "fence_count"}, by_name
    assert all(t == "INTEGER" for t in by_name.values()), by_name

    blob = "\n".join(str(row) for row in sql(store, "SELECT * FROM document_state"))
    assert "SECRET-DOCUMENT-MARKER-996" not in blob, "the stamp table carries document content"
    assert "SECRET-DOCUMENT-MARKER-996" in text, "the control marker is not in the document"


def test_996_two_record_calls_in_one_turn_share_one_document_stamp(tmp_path: Path) -> None:
    """One MAIN turn carrying TWO `record` calls stamps ONE request row, once.

    PROBED against a real driven loop: the framework bundles every tool return answering one
    model response into a SINGLE request message, so two `record` calls in one turn land as one
    `kind='request'` row. That is what makes D6's arithmetic sound as written, and it is why
    every demand here is stated over "one row per turn's tool-return message" rather than over
    "one row per `record` call" — the second reading would have the stamp count calls and
    disagree with the row it is attached to."""
    sink: list = []
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE)
    both = Turn(tool_calls=[("record", {"text": C.PROSE}),
                            ("record", {"text": C.SECOND_PROSE})])
    main = C.MainWithReceipts([both, Turn(text="Holding here.")])
    C.record_run(tmp_path, run_dir=run_dir, main=main,
                 clerk=C.ScriptedClerk(C.clerk_reply("")),
                 store_factory=store_factory(tmp_path, sink=sink))

    store = sink[0]
    rows = sql(store, "SELECT message_id, COUNT(*) FROM document_state GROUP BY message_id")
    assert rows, "nothing was stamped at all"
    duplicated = [mid for mid, n in rows if n > 1]
    assert duplicated == [], f"message row(s) {duplicated} carry more than one stamp"


def test_996_the_document_reader_reads_zero_zero_for_a_missing_or_fenceless_document(
    tmp_path: Path,
) -> None:
    """The reader answers `(0, 0)` for a missing document and for a fence-less one — the value
    the seed already treats as legitimate, with NO special case.

    PROBED, and the probe refutes the fail-closed reading: `scan_fences` never raises, returning
    a normal scan with zero fences for the empty string and for header-only text, and the run
    path constructor touches no filesystem. The probe also carries the qualifier the reading did
    not have — the untouched-document case is reached on a resumed run or a run with no lead-0
    registry, not on every first MAIN request, so it is a real state rather than a theoretical
    one.

    A stamp read that genuinely RAISES is a different thing and is not squashed into `(0, 0)`:
    fail-open covers absence and emptiness only. Because the read precedes the transaction,
    nothing is half-written when it does, so the fault propagates as the append's own failure."""
    build = C.sym("runtime.session_store", "document_reader_for")
    run_dir = tmp_path / "empty-run"
    run_dir.mkdir()

    assert build(run_dir)() == (0, 0), "a missing document did not read as (0, 0)"
    RunPaths(run_dir).investigation.write_text("", encoding="utf-8")
    assert build(run_dir)() == (0, 0), "an empty document did not read as (0, 0)"
    RunPaths(run_dir).investigation.write_text("## ORIENT\n\nprose only\n", encoding="utf-8")
    assert build(run_dir)() == (len("## ORIENT\n\nprose only\n"), 0), (
        "a fence-less document did not read as zero fences"
    )


def test_996_a_reproduced_invlang_fence_in_main_prose_moves_the_stamped_count(
    tmp_path: Path,
) -> None:
    """Fence counting is AUTHOR-BLIND, and the consequence is material rather than theoretical:
    a COMPLETE, well-formed invlang fence MAIN reproduces verbatim inside its own prose moves
    the stamped count, and therefore can move a branch cut.

    PROBED: only well-formed spans count. A ```yaml block in MAIN's prose and an inline
    unterminated mention count ZERO — a distinct assertion from the quoted-invlang case, and
    the two must not be collapsed, because a rule that counted "fenced text" would move the cut
    on every quoted log excerpt.

    Author-blindness is the only rule that makes the stamp self-consistent: the stamp is read
    off the DOCUMENT, so a count that asked who wrote each fence would disagree with the
    document it is attached to."""
    quoted, _, _ = C.record_run(
        tmp_path, run_dir=C.new_run_dir(tmp_path, name="quoted"),
        prose=[C.QUOTED_FENCE_PROSE], clerk=C.ScriptedClerk(C.clerk_reply("")))
    yamlish, _, _ = C.record_run(
        tmp_path, run_dir=C.new_run_dir(tmp_path, name="yamlish"),
        prose=[C.YAML_FENCE_PROSE], clerk=C.ScriptedClerk(C.clerk_reply("")))

    assert C.fences(C.document(quoted)) == 1, (
        "a complete invlang fence MAIN reproduced in prose was not counted"
    )
    assert C.fences(C.document(yamlish)) == 0, (
        "a ```yaml block in MAIN's prose moved the fence count"
    )


def test_996_a_resumed_reingest_lands_no_second_stamp_for_one_message(
    tmp_path: Path,
) -> None:
    """A resumed process re-ingesting a history it already ingested lands NO second stamp for a
    message it already stamped.

    PROBED, AND THE PROBE GOES PAST THE PROVISIONAL READING: the `message` table has no
    `ON CONFLICT`, no id-keyed uniqueness constraint and recomputes `seq` per insert, so a
    re-ingest duplicates SILENTLY rather than raising. There is no idempotency rule for the
    stamp to inherit. TWO ARMS SATISFY THE RE-ENTRANCY AND THE RESOLUTION LEAVES BOTH OPEN:
    the render-length slice `ingest` already applies, driven by the `last_render_len` persisted
    on the session row, or an explicit new uniqueness constraint on the stamp table — never a
    database rule borrowed from a table that does not have one. An implementer who adds a
    message-id-keyed constraint to a stamp table is building a deliberate NEW guarantee, not
    parity, so the assertion is over the OBSERVABLE both arms produce and is driven through
    the real re-ingest path rather than over either arm's own mechanism. A test raising on the
    constraint would mandate the arm the resolution singled out as the risky one.

    The re-entry is the real one: a second handle opened on the same case store is the file a
    restarted process reopens, and the resumed ingest is handed the whole history the first
    pass already recorded. A stamp written outside the guard — per ingest call, per render, or
    against the session tip rather than a newly appended row — lands a second stamp for a
    message that already has one, and this is the only place that shows.

    The control keeps the refutation executable rather than remembered, and it is driven on its
    own session so it cannot perturb the path under test: the `message` table still takes the
    same row twice without complaint, so there is nothing to inherit.
    """
    sel = selection_mod()
    store, session = _stamped_store(tmp_path, C.PROLOGUE)

    control = store.new_session(agent_id="main")
    store.append(control, [user_request("investigate")], agent_id="main")
    seen = sql(store, "SELECT COUNT(*) FROM message WHERE session_id = ?", (control,))[0][0]
    store.append(control, [user_request("investigate")], agent_id="main")
    assert sql(store, "SELECT COUNT(*) FROM message WHERE session_id = ?",
               (control,))[0][0] == seen + 1, (
        "the message table now refuses a duplicate, so the stamp could inherit a rule after "
        "all — re-read this demand rather than assuming it"
    )

    live = [user_request("investigate"), *complete_pair()]
    assert sel.ingest(store, session, live, agent_id="main"), (
        "the first ingest landed no rows at all, so nothing below is a re-ingest"
    )
    stamped = dict(sql(
        store, "SELECT message_id, COUNT(*) FROM document_state GROUP BY message_id"))
    assert stamped, (
        "the first ingest stamped nothing, so a second stamp would be unobservable here"
    )

    resumed = make_store(tmp_path)
    resumed.document_reader = _reader_for(C.PROLOGUE)
    sel.ingest(resumed, session, live, agent_id="main")

    after = dict(sql(
        resumed, "SELECT message_id, COUNT(*) FROM document_state GROUP BY message_id"))
    doubled = [mid for mid in stamped if after.get(mid, 0) > 1]
    assert doubled == [], (
        f"message row(s) {doubled} carry a second stamp after the resumed re-ingest"
    )
    assert all(after.get(mid) == n for mid, n in stamped.items()), (
        f"the resumed re-ingest changed the stamps of rows it had already stamped: "
        f"{stamped} -> {after}"
    )


# ---------------------------------------------------------------------------------------
# the reader (D6, O9; cluster A's [47])
# ---------------------------------------------------------------------------------------


def test_996_document_state_at_reads_the_latest_stamped_request_on_the_path(
    tmp_path: Path,
) -> None:
    """`document_state_at` answers with the stamp on the LATEST stamped request row on the
    path at or before the branch point — and a RESPONSE row resolves to the request that
    precedes it, because that is the prefix the send-role hydration keeps.

    A reader that answered from the newest stamp in the store rather than from the newest on
    the PATH would hand a sibling the state of a run it never shared."""
    ss = store_mod()
    store = make_store(tmp_path)
    session = store.new_session(agent_id="main")
    first, second = "```invlang\n:V a [id]\nv-1\n```\n", C.PROLOGUE

    store.document_reader = _reader_for(first)
    r1 = store.append(session, [user_request("investigate")], agent_id="main")[0]
    a1 = store.append(session, [text_response("thinking")], agent_id="main", parent_id=r1)[0]
    store.document_reader = _reader_for(first + second)
    r2 = store.append(session, [user_request("again")], agent_id="main", parent_id=a1)[0]

    at_first = ss.document_state_at(store, session, r1)
    assert (at_first.byte_len, at_first.fence_count) == (
        len(first.encode("utf-8")), C.fences(first))
    at_response = ss.document_state_at(store, session, a1)
    assert (at_response.byte_len, at_response.fence_count) == (
        at_first.byte_len, at_first.fence_count), (
        "a response row did not resolve to the request that precedes it"
    )
    at_second = ss.document_state_at(store, session, r2)
    assert at_second.fence_count == C.fences(first + second)


def test_996_document_state_at_refuses_a_foreign_message_id(tmp_path: Path) -> None:
    """`document_state_at` REFUSES a message id that is not on this session's path — it does
    not resolve it to whatever stamp happens to precede it.

    The guard as designed is session id plus id-ordering with NO run identity, so a foreign id
    in a shared store resolves silently to another run's document. Silent is the whole problem:
    the caller gets a plausible state for the wrong run, seeds a sibling from it, and every
    downstream comparison is against a document that run never held. A path with no stamped
    request raises for the same reason.

    POSITIVE CONTROL on the same address under the complementary condition: the id from THIS
    session's own path resolves."""
    ss = store_mod()
    branch = C.mod("runtime.branch")
    store = make_store(tmp_path)
    store.document_reader = _reader_for(C.PROLOGUE)
    mine = store.new_session(agent_id="main")
    theirs = store.new_session(agent_id="main")
    my_row = store.append(mine, [user_request("investigate")], agent_id="main")[0]
    their_row = store.append(theirs, [user_request("investigate")], agent_id="main")[0]

    assert ss.document_state_at(store, mine, my_row).fence_count == C.fences(C.PROLOGUE)
    with pytest.raises(branch.BranchError):
        ss.document_state_at(store, mine, their_row)


def test_996_a_branch_at_or_after_the_fold_frontier_reads_a_stamp(tmp_path: Path) -> None:
    """A branch taken AT the synthesized fold frontier, and one taken after it, both read a
    stamp — the rows a fold and a correlation injection write are stamped like any other.

    The fold appends a synthesized frontier request parented to the ROOT and re-roots the
    session, so after it the path is `[root, frontier, …]` and every earlier request is off it.
    A stamp written only on the ingest path would leave the frontier row, the correlation row
    and the run-end flush's rows unstamped — and a branch at any of them then has nothing to
    read, on exactly the runs the mechanism exists for. Stamping at the store's single write
    primitive is what makes "every request row" true rather than "every request row some
    caller remembered"."""
    ss = store_mod()
    store = make_store(tmp_path)
    store.document_reader = _reader_for(C.PROLOGUE)
    fixture = nine_row_fixture(store)
    ids, session = fixture["row_ids"], fixture["main"]

    at_frontier = ss.document_state_at(store, session, ids[5])
    assert at_frontier.fence_count == C.fences(C.PROLOGUE), (
        "the synthesized fold frontier carries no stamp — a branch at the frontier row has "
        "nothing to read"
    )
    assert ss.document_state_at(store, session, ids[7]).fence_count == C.fences(C.PROLOGUE)


def test_996_fence_count_is_the_truncation_authority_and_byte_len_is_diagnostic(
    tmp_path: Path,
) -> None:
    """`fence_count` is the truncation AUTHORITY; `byte_len` is a recorded diagnostic that no
    gate reads.

    The two disagree deliberately in this fixture: the source document has been rewritten
    smaller in bytes while keeping every fence. The repair verb only ever replaces or drops
    ROWS, never delimiters, so a shrink that removes bytes without removing a fence is the
    ordinary consequence of an in-place repair — and keying the refusal on bytes would refuse
    every legitimately repaired source.

    The accepted cost is stated: a shrink that removes bytes without removing a fence is not
    detectable at all. The column stays in the table as a diagnostic, which is cheap to
    reverse; what must not happen is a second gate growing on it."""
    ss = store_mod()
    branch = C.mod("runtime.branch")
    store = make_store(tmp_path)
    fat = C.PROLOGUE + "\nprose that a later repair removes\n"
    store.document_reader = _reader_for(fat)
    session = store.new_session(agent_id="main")
    row = store.append(session, [user_request("investigate")], agent_id="main")[0]

    stamp = ss.document_state_at(store, session, row)
    assert stamp.byte_len == len(fat.encode("utf-8"))
    assert stamp.fence_count == C.fences(C.PROLOGUE)

    source = tmp_path / "source-run"
    source.mkdir()
    RunPaths(source).investigation.write_text(C.PROLOGUE, encoding="utf-8")
    spec = branch.BranchSpec(
        source_run_dir=source, branch_message_id=row,
        continuation_prompt="continue", as_of=branch.branch_point_time(store, source, row),
    )
    sibling = tmp_path / "sibling-run"
    sibling.mkdir()
    assert branch.seed_investigation(store, spec, sibling) == stamp.fence_count, (
        "a source that shrank in BYTES while keeping every fence was refused — the byte length "
        "is acting as the truncation authority"
    )


def test_996_a_source_document_below_the_stamped_count_raises_brancherror(
    tmp_path: Path,
) -> None:
    """A source document holding FEWER fences than its own stamp says were landed is REFUSED —
    the document and the session disagree about what had landed, and a seed cut from either is
    a guess.

    POSITIVE CONTROL on the same address under the complementary condition: the same branch
    against the untruncated source seeds successfully, so the refusal is the truncation and not
    a branch point the store cannot resolve."""
    ss = store_mod()
    branch = C.mod("runtime.branch")
    store = make_store(tmp_path)
    whole = C.PROLOGUE + C.CLEAN_ROWS
    store.document_reader = _reader_for(whole)
    session = store.new_session(agent_id="main")
    row = store.append(session, [user_request("investigate")], agent_id="main")[0]
    assert ss.document_state_at(store, session, row).fence_count == C.fences(whole) >= 2

    source = tmp_path / "source-run"
    source.mkdir()
    RunPaths(source).investigation.write_text(whole, encoding="utf-8")
    spec = branch.BranchSpec(
        source_run_dir=source, branch_message_id=row,
        continuation_prompt="continue", as_of=branch.branch_point_time(store, source, row),
    )
    ok = tmp_path / "ok-sibling"
    ok.mkdir()
    assert branch.seed_investigation(store, spec, ok) == C.fences(whole)

    RunPaths(source).investigation.write_text(C.PROLOGUE, encoding="utf-8")
    truncated = tmp_path / "truncated-sibling"
    truncated.mkdir()
    with pytest.raises(branch.BranchError):
        branch.seed_investigation(store, spec, truncated)


def test_996_seed_investigation_cuts_at_the_stamped_fence_bound(tmp_path: Path) -> None:
    """The sibling's seed is the source's own bytes cut at the STAMPED fence bound — sliced,
    not rebuilt, so the author's prose between blocks comes across.

    The cut being the stamped count is what makes the seeded document and the frontier the
    branch validated the same state by construction rather than by coincidence. Byte-identity
    with a prefix of the source is the property that makes the two documents comparable at
    all."""
    ss = store_mod()
    branch = C.mod("runtime.branch")
    store = make_store(tmp_path)
    early = C.PROLOGUE + "\nprose between the blocks\n"
    whole = early + C.CLEAN_ROWS
    store.document_reader = _reader_for(early)
    session = store.new_session(agent_id="main")
    row = store.append(session, [user_request("investigate")], agent_id="main")[0]

    source = tmp_path / "source-run"
    source.mkdir()
    RunPaths(source).investigation.write_text(whole, encoding="utf-8")
    spec = branch.BranchSpec(
        source_run_dir=source, branch_message_id=row,
        continuation_prompt="continue", as_of=branch.branch_point_time(store, source, row),
    )
    sibling = tmp_path / "sibling-run"
    sibling.mkdir()
    assert branch.seed_investigation(store, spec, sibling) == ss.document_state_at(
        store, session, row).fence_count

    seed = RunPaths(sibling).investigation.read_text(encoding="utf-8")
    assert whole.startswith(seed), "the seed is not a byte-prefix of the source"
    assert "attrs.owner" not in seed, "the seed carries a fence landed after the branch point"


# ---------------------------------------------------------------------------------------
# the version bump and what it orphans (D16)
# ---------------------------------------------------------------------------------------


def test_996_a_version_two_store_is_refused_by_both_openers(tmp_path: Path) -> None:
    """The schema version moves 2 → 3, and BOTH openers refuse a version-2 file with no
    migration and no fallback reader.

    That is the store's existing policy, not a new one, and D16 is the recorded acceptance of
    its consequence: runs recorded before the port are not branchable after it. Keeping a
    fallback reader would keep exactly the smell the stamp removes — two readers of the
    document's history, one of them replaying the transcript.

    Both openers, because the refusal has to hold on the READ path too: a reader that opened a
    stale file would answer branch questions from a store with no stamps at all."""
    ss = store_mod()
    assert ss.SCHEMA_VERSION == 3
    store = make_store(tmp_path)
    path = store.path
    store.close()

    conn = sqlite3.connect(path)
    conn.execute("PRAGMA user_version = 2")
    conn.commit()
    conn.close()

    with pytest.raises(ss.StoreError):
        ss.open_store(case_id="case-alpha", runs_base=runs_base(tmp_path))
    with pytest.raises(ss.StoreError):
        ss.open_store_for_read(path)


def test_996_branch_and_resume_no_longer_walk_the_transcript_for_fences(
    tmp_path: Path,
) -> None:
    """SURVIVAL: the transcript walk is DELETED, and the workflow it served still completes
    through the stamp.

    `fence_count_at` and `_appended_text` go — a PUBLIC surface, so the deletion is a demand and
    not a cleanup — and the three callers move onto the stamp. The deletion half alone would be
    satisfied by removing the function and breaking the branch; the survival half alone would
    be satisfied by leaving both mechanisms in place, which is the two-readers smell D6 exists
    to remove. Both are asserted here.

    Everything the walk could not answer stays answered the same way: the lead set and the
    branch time remain transcript-derived, a named follow-up rather than part of this change."""
    frontier = C.mod("runtime.branch._frontier")
    assert not hasattr(frontier, "fence_count_at"), (
        "`fence_count_at` still exists, so the document's history has two readers and they can "
        "disagree"
    )
    assert not hasattr(frontier, "_appended_text")

    ss = store_mod()
    branch = C.mod("runtime.branch")
    store = make_store(tmp_path)
    store.document_reader = _reader_for(C.PROLOGUE)
    session = store.new_session(agent_id="main")
    call = store.append(session, [user_request("investigate")], agent_id="main")[0]
    resp = store.append(session, [tool_call_response("record", {"text": C.PROSE},
                                                    tool_call_id="r1")],
                        agent_id="main", parent_id=call)[0]
    ret = store.append(session, [tool_return_request("record", "ok", tool_call_id="r1")],
                       agent_id="main", parent_id=resp)[0]

    source = tmp_path / "source-run"
    source.mkdir()
    RunPaths(source).investigation.write_text(C.PROLOGUE, encoding="utf-8")
    spec = branch.BranchSpec(
        source_run_dir=source, branch_message_id=ret,
        continuation_prompt="continue", as_of=branch.branch_point_time(store, source, ret),
    )
    sibling = tmp_path / "sibling-run"
    sibling.mkdir()
    assert branch.seed_investigation(store, spec, sibling) == ss.document_state_at(
        store, session, ret).fence_count, (
        "the seed no longer agrees with the stamp, so the workflow the deleted walk served "
        "does not survive its removal"
    )


def test_996_render_and_trace_readers_are_unaffected_by_the_stamp_table(
    tmp_path: Path,
) -> None:
    """COHERENCE: the two existing store readers whose answers must NOT move — the send-role
    render the model is handed each request, and the run's own trace — answer identically over
    a store that carries stamps and one that does not.

    A new table in a store both of them walk is exactly the shape that quietly changes an
    answer: the render rebuilds the model's whole message list from the store on every request,
    so a stamp that reached it would change what the model reads."""
    ss = store_mod()
    observe = C.mod("runtime.observe")

    plain = make_store(tmp_path / "plain")
    stamped = make_store(tmp_path / "stamped")
    stamped.document_reader = _reader_for(C.PROLOGUE)
    rendered = []
    for store in (plain, stamped):
        session = store.new_session(agent_id="main")
        row = store.append(session, [user_request("investigate")], agent_id="main")[0]
        store.append(session, [text_response("thinking")], agent_id="main", parent_id=row)
        rendered.append(
            [type(m).__name__ for m in ss.hydrate(store, session, role="send")])
        run_dir = tmp_path / f"trace-{store.case_id}-{len(rendered)}"
        run_dir.mkdir(parents=True)
        observe.write_trace(run_dir, store=store, session_id=session, wall_ms=1.0)

    assert rendered[0] == rendered[1], (
        f"the send-role render differs between a stamped and an unstamped store: {rendered}"
    )


def test_996_an_unreadable_document_leaves_the_row_unstamped(tmp_path: Path) -> None:
    """A document the stamp reader cannot READ neither raises nor stamps a zero: it answers
    NO STAMP, and the branch point falls through to the last row that had one.

    Two failures are in play and only one of them is obvious. It must not raise —
    `StoreHandle.append` calls this on every request row, outside its own transaction and with
    no guard, so an exception propagates out of `append`, out of the history processor, and
    takes the model round with it, over the same two faults `_tool_append_block` already
    catches on this file.

    And it must not answer `(0, 0)`, which is the half a fail-open gets wrong. `fence_count` is
    the branch/resume truncation authority and `document_state_at` STOPS at the first stamped
    row it meets walking back — so a zero written for a momentary read failure outranks the
    real count beside it, and a forty-fence document seeds a sibling with none. Driven on both:
    the reader's own answer, and the branch lookup falling through it to the earlier stamp."""
    ss = store_mod()
    run_dir = C.new_run_dir(tmp_path)
    RunPaths(run_dir).investigation.write_bytes(b"\xff\xfe not utf-8 \x00")

    read = C.sym("runtime.session_store", "document_reader_for")(run_dir)
    assert read() is None, (
        f"the unreadable document was stamped {read()!r} — `fence_count` is the truncation "
        "authority and this value outranks the real one on the row before it"
    )

    store = make_store(tmp_path)
    session = store.new_session(agent_id="main")
    store.document_reader = _reader_for(C.PROLOGUE)
    r1 = store.append(session, [user_request("investigate")], agent_id="main")[0]
    store.document_reader = read
    r2 = store.append(session, [user_request("again")], agent_id="main", parent_id=r1)[0]

    assert ss.document_state_at(store, session, r2).fence_count == C.fences(C.PROLOGUE), (
        "the branch point at the unreadable row answered its own zero instead of falling "
        "through to the last row that carried a real count"
    )

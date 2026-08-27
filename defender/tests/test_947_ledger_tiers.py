"""#947 Part B — the ledger's two family tiers, and the file each of them lives in.

#920 had one tier for "what the estate answered": `world_id=None`, written by whichever sibling
asked first, replayed by the rest. That is invariance between siblings and it is NOT the base
world the design asks for — the base world is what the real adapters returned during the REAL
run, and a row read live this afternoon is the estate NOW. The two coincide only on a quiet
estate, and a table that cannot tell them apart can never say which one it holds.

So the family tier splits in two. `captured` is the source run's own capture, primed into
`served/base.jsonl` before any sibling forks and read-only for the whole episode; `base` stays
the narrower thing it always honestly was — a live read of a key the capture never recorded,
which happens exactly when a sibling asks a question its source never did. Counting `base` rows
across a family measures that residual, which is the one part of the estate a primed capture
cannot make deterministic.

The FILES follow the tiers. Each world writes its own `served/<world_id>.jsonl` — one writer per
file, no interleaving — and reads the shared capture beside it. `Ledger.__post_init__` refuses a
`base_path` that is not a file, which is how "the episode was primed before any sibling opened a
ledger over it" becomes a checkable ordering rather than a convention.

WHAT THIS FILE DOES NOT OWN. The PRIMER — what it reads, what it skips and what it counts — is
`test_947_capture_prime.py`. Here the primed file is written by hand through the ledger's own
`ServedCall.row()`, so these arms fail on the ledger rather than on the primer.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from defender._io import append_jsonl, read_jsonl_rows
from defender.learning.branch.ledger import (
    APPLIER_DECISIONS,
    BASE,
    BASE_FILENAME,
    CAPTURED,
    FAMILY_SOURCES,
    FAULT,
    PASSTHROUGH,
    PATCHED,
    REFUSED,
    SERVED_DIRNAME,
    SOURCES,
    STAGED,
    Ledger,
    LedgerError,
    ServedCall,
    payload_text,
)


def captured(system: str, verb: str, params: dict, payload: dict) -> dict:
    """One primed row, built through the ledger's OWN row writer and canonicaliser.

    Not a hand-spelled dict and not a local `json.dumps`: the primer and the serving path have
    to agree byte for byte on how a payload is canonicalised — which is why `payload_text` is
    published here rather than kept private to the registry — and a fixture spelling its own
    copy of that would be asserting against itself rather than against the table.
    """
    return ServedCall(
        system=system, verb=verb, params=params, payload_text=payload_text(payload),
        source=CAPTURED, world_id=None,
    ).row()


def episode(tmp_path: Path, *, rows: list[dict] | None = None) -> Path:
    """An episode directory whose capture has been primed. Returns the episode root."""
    root = tmp_path / "episode"
    (root / SERVED_DIRNAME).mkdir(parents=True, exist_ok=True)
    base = base_file(root)
    base.touch()
    if rows:
        append_jsonl(base, rows)
    return root


def base_file(root: Path) -> Path:
    """The episode's primed capture, spelled through the ledger's own constants.

    Named there rather than restated here: the primer writes this path and every sibling reads
    it, and two spellings of one filename is how an episode primes into a file nothing opens.
    """
    return root / SERVED_DIRNAME / BASE_FILENAME


# ==========================================================================
# 1. the vocabulary
# ==========================================================================

def test_the_family_tier_is_two_labels_and_the_applier_owns_neither():
    """    `SOURCES` partitions into the FAMILY tier, the seam's own two, and the applier's three.

    `captured` joining `base` in the family tier is the whole of Part B at the vocabulary level:
    both are `world_id=None` rows every sibling replays, and neither is a decision an applier may
    name. Without the partition spelled out, "the vocabulary is closed" reads as "any applier may
    claim any member of it" — which now includes the label that means "this is what the estate
    said during the real run"."""
    assert CAPTURED in SOURCES
    assert {BASE, CAPTURED} == FAMILY_SOURCES
    assert APPLIER_DECISIONS | FAMILY_SOURCES | {REFUSED, FAULT} == SOURCES
    assert not (APPLIER_DECISIONS & FAMILY_SOURCES), (
        "an applier can name a family-tier label — one world's answer offered as the shared "
        "recording, with its own row still reading honestly")


@pytest.mark.parametrize("world_id", [None, "w1"])
def test_the_ledger_refuses_a_captured_row_at_its_own_door(tmp_path, world_id):
    """    `record` refuses `captured` outright, whichever tier the row claims.

    Only the primer may claim capture provenance, and the primer does not come through here.
    A row a SIBLING could stamp `captured` is a live read of a moving estate wearing the
    provenance of the source run's own capture — and every reader downstream believes it,
    because provenance is not something a payload can be re-checked against.

    The `world_id=None` arm is the one that matters: it satisfies the tier invariant, so a
    widened `(source in FAMILY_SOURCES) != (world_id is None)` admits it silently unless the
    refusal is its own rule."""
    root = episode(tmp_path)
    ledger = Ledger(root / SERVED_DIRNAME / "w1.jsonl", base_path=base_file(root))

    with pytest.raises(LedgerError, match=CAPTURED):
        ledger.record(ServedCall(
            system="cmdb", verb="get-host", params={"host": "canary-1"},
            payload_text='{"owner": "estate"}', source=CAPTURED, world_id=world_id))

    assert read_jsonl_rows(root / SERVED_DIRNAME / "w1.jsonl") == []


@pytest.mark.parametrize(("source", "world_id"), [
    (BASE, "w1"), (PASSTHROUGH, None), (STAGED, None), (PATCHED, None),
])
def test_the_two_tiers_still_have_to_agree_after_the_split(tmp_path, source, world_id):
    """    The widened invariant is still an invariant: a family label owned by a world, or a
    world-tier row with no owner, is refused.

    `(source == BASE) != (world_id is None)` became `(source in FAMILY_SOURCES) != ...`, and a
    widening is exactly where a check stops checking. A `base` row owned by a world puts that
    world's answer in the slot its siblings replay; an owner-less `passthrough` is a difference
    nobody can attribute, which a comparison then charges to whichever sibling it reads next."""
    root = episode(tmp_path)
    ledger = Ledger(root / SERVED_DIRNAME / "w1.jsonl", base_path=base_file(root))

    with pytest.raises(LedgerError):
        ledger.record(ServedCall(
            system="cmdb", verb="get-host", params={"host": "canary-1"},
            payload_text="{}", source=source, world_id=world_id))

    assert read_jsonl_rows(root / SERVED_DIRNAME / "w1.jsonl") == []


def test_a_live_base_read_is_still_recordable(tmp_path):
    """    The positive control: `base` with no owner is still exactly what a live family read is.

    Without it, the refusals above are satisfied by a `record` that refuses everything — and the
    residual the split exists to measure (a key the capture never held) would have nowhere to
    land."""
    root = episode(tmp_path)
    ledger = Ledger(root / SERVED_DIRNAME / "w1.jsonl", base_path=base_file(root))

    ledger.record(ServedCall(
        system="cmdb", verb="get-host", params={"host": "canary-1"},
        payload_text='{"owner": "estate"}', source=BASE, world_id=None))

    assert [r["source"] for r in read_jsonl_rows(ledger.path)] == [BASE]


# ==========================================================================
# 2. the primed base is a precondition, not a parameter
# ==========================================================================

def test_a_ledger_without_a_primed_base_does_not_construct(tmp_path):
    """    `base_path` is REQUIRED: a ledger cannot be opened without naming the capture it reads.

    Optional, it would default to "no capture" — and a sibling would then run its whole episode
    against a live estate while every row read exactly as it does in a primed one. The episode
    would look complete and measure the estate's drift."""
    root = episode(tmp_path)

    with pytest.raises(TypeError):
        Ledger(root / SERVED_DIRNAME / "w1.jsonl")


@pytest.mark.parametrize("shape", ["absent", "directory"])
def test_a_base_path_that_is_not_a_file_is_refused_at_construction(tmp_path, shape):
    """    A `base_path` that is not a file is a `LedgerError` at construction.

    THIS IS THE ORDERING GUARANTEE. Nothing else in the seam can tell whether priming happened
    before the siblings forked, and the consequence of it not having is silent: every key misses
    the capture, every world reads the live estate, and the pair's invariance is gone with every
    row still honest. Refused where the ledger is OPENED, because that is the last moment before
    a sibling can serve.

    `absent` is the un-primed episode; `directory` is the same fault arriving through a path
    that exists, which an `exists()` check would admit and then fail on much later, inside a
    served call, as an `IsADirectoryError` the query tool files as infra."""
    root = tmp_path / "episode"
    (root / SERVED_DIRNAME).mkdir(parents=True)
    base = base_file(root)
    if shape == "directory":
        base.mkdir()

    with pytest.raises(LedgerError):
        Ledger(root / SERVED_DIRNAME / "w1.jsonl", base_path=base)


def test_the_primed_capture_is_never_written_to(tmp_path):
    """    A world's rows go to the world's own file; the capture is read-only for the whole run.

    One writer per file is what makes a torn line impossible without a lock the seam does not
    have — sibling gather leads dispatch in parallel, and a multi-hundred-KB row is several
    `write()` calls. It is also what keeps the capture re-readable: an episode re-run next week
    primes from the same source run and must find the same base."""
    root = episode(tmp_path, rows=[captured("cmdb", "get-host", {"host": "canary-1"},
                                            {"owner": "estate"})])
    before = base_file(root).read_bytes()
    ledger = Ledger(root / SERVED_DIRNAME / "w1.jsonl", base_path=base_file(root))

    ledger.record(ServedCall(
        system="cmdb", verb="list-hosts", params={}, payload_text='{"hosts": []}',
        source=BASE, world_id=None))
    ledger.record(ServedCall(
        system="cmdb", verb="list-hosts", params={}, payload_text='{"hosts": []}',
        source=PASSTHROUGH, world_id="w1"))

    assert base_file(root).read_bytes() == before, "the run appended to the primed capture"
    assert len(read_jsonl_rows(ledger.path)) == 2


# ==========================================================================
# 3. what `base_payload` reads
# ==========================================================================

def test_a_primed_key_is_answered_without_the_world_ever_asking(tmp_path):
    """    A key the capture holds resolves out of `base.jsonl` — the world's own file is empty.

    This is what a primed base IS: the source run already asked this question of the real
    estate, and the sibling replays that answer instead of a fresh live read. Without it every
    sibling re-asks, and two siblings minutes apart measure the estate's drift as the world's
    difference."""
    root = episode(tmp_path, rows=[captured("cmdb", "get-host", {"host": "canary-1"},
                                            {"owner": "estate"})])
    ledger = Ledger(root / SERVED_DIRNAME / "w1.jsonl", base_path=base_file(root))

    hit = ledger.base_payload("cmdb", "get-host", {"host": "canary-1"})

    assert hit is not None, "the primed capture answered nothing for a key it holds"
    assert json.loads(hit) == {"owner": "estate"}
    assert read_jsonl_rows(ledger.path) == [], (
        "the world recorded a row for a key it never had to ask — a replay is not a serve")


def test_a_key_spelled_in_another_order_is_the_same_primed_key(tmp_path):
    """    The capture is keyed through `request_key`, so param order does not split one memo in two.

    The primer writes params in whatever order the source run's table recorded them, and the
    sibling asks in whatever order the model wrote them. Keyed on the spelling, half the capture
    would silently miss and those keys would go live."""
    root = episode(tmp_path, rows=[captured("elastic", "query",
                                            {"native_query": "x", "limit": 5}, {"hits": []})])
    ledger = Ledger(root / SERVED_DIRNAME / "w1.jsonl", base_path=base_file(root))

    assert ledger.base_payload("elastic", "query", {"limit": 5, "native_query": "x"}) is not None


def test_a_worlds_own_live_read_is_answered_from_its_own_file(tmp_path):
    """    A key the capture never held, read live and recorded as `base`, answers from the world's
    own rows on the next ask.

    The residual: a sibling genuinely asks questions its source never did, and those still cost
    exactly one adapter call apiece rather than one per ask. `base ∪ own` is what makes that
    true without letting one world's live read reach another's."""
    root = episode(tmp_path)
    ledger = Ledger(root / SERVED_DIRNAME / "w1.jsonl", base_path=base_file(root))

    ledger.record(ServedCall(
        system="cmdb", verb="get-host", params={"host": "new-9"},
        payload_text='{"owner": "live"}', source=BASE, world_id=None))

    assert ledger.base_payload("cmdb", "get-host", {"host": "new-9"}) == '{"owner": "live"}'


def test_one_siblings_live_read_is_not_served_to_another(tmp_path):
    """    World B does not read World A's own rows — only the shared capture crosses between them.

    The split is what makes this asked at all, and the answer has to be "no": A's live read
    happened at A's moment, through A's ctx, possibly against A's staged corpus. Serving it to B
    is contamination rather than a saved call, and it is invisible — B's row would report
    `passthrough` over bytes B never asked for. The capture is the ONE shared tier, because it
    is the only one that predates both."""
    root = episode(tmp_path)
    a = Ledger(root / SERVED_DIRNAME / "a.jsonl", base_path=base_file(root))
    b = Ledger(root / SERVED_DIRNAME / "b.jsonl", base_path=base_file(root))

    a.record(ServedCall(
        system="cmdb", verb="get-host", params={"host": "new-9"},
        payload_text='{"owner": "read-by-a"}', source=BASE, world_id=None))

    assert a.base_payload("cmdb", "get-host", {"host": "new-9"}) is not None
    assert b.base_payload("cmdb", "get-host", {"host": "new-9"}) is None, (
        "world b was served world a's own live read as though it were the family's capture")


def test_the_capture_outranks_a_live_row_for_the_same_key(tmp_path):
    """    A key held by BOTH the capture and the world's own file resolves to the CAPTURE.

    The capture predates the run, so a live row for a key it already holds can only come from
    the check-then-act window `base_payload` documents — two readers both missing and both
    recording. First-row-wins across the union resolves that to the row that was there first,
    which is the capture, and every process rebuilding the memo from the files agrees. Resolved
    the other way, this process serves its own live read while a sibling serves the capture: two
    answers to one question, both rows honest."""
    root = episode(tmp_path, rows=[captured("cmdb", "get-host", {"host": "canary-1"},
                                            {"owner": "captured"})])
    ledger = Ledger(root / SERVED_DIRNAME / "w1.jsonl", base_path=base_file(root))
    append_jsonl(ledger.path, [ServedCall(
        system="cmdb", verb="get-host", params={"host": "canary-1"},
        payload_text='{"owner": "live"}', source=BASE, world_id=None).row()])

    reopened = Ledger(ledger.path, base_path=base_file(root))

    assert json.loads(reopened.base_payload("cmdb", "get-host", {"host": "canary-1"})) == {
        "owner": "captured"}


def test_a_failed_write_leaves_no_memo_behind_it(tmp_path):
    """    A `record` whose append FAILS must not leave the payload live in memory.

    Memoized first, a failed write leaves the family's answer in the memo with NO ROW behind it:
    every later call for that key takes the hit, issues no adapter call, and serves a payload the
    table cannot account for — "a served response with no row", the one state this table exists
    to make visible. And it is silently divergent as well as unaccounted: a later sibling
    rebuilding the memo from the file finds nothing, re-asks the live estate and gets different
    bytes, so the pair's invariance is gone with nothing in the record to show it.

    REACHABLE, not theoretical: `_record_beside` deliberately swallows write failures so that
    recording why a call failed cannot displace the call's own exception — so the process runs on
    after exactly this.

    The fault is a real primitive rather than an authored exception: the ledger's own path is a
    DIRECTORY, so the real `append_jsonl` takes the real `IsADirectoryError` from the real
    open."""
    root = episode(tmp_path)
    ledger = Ledger(root / SERVED_DIRNAME / "w1.jsonl", base_path=base_file(root))
    ledger.path.mkdir(parents=True)

    with pytest.raises(IsADirectoryError):
        ledger.record(ServedCall(
            system="cmdb", verb="get-host", params={"host": "canary-1"},
            payload_text='{"owner": "never landed"}', source=BASE, world_id=None))

    assert ledger.base_payload("cmdb", "get-host", {"host": "canary-1"}) is None, (
        "the payload is memoized with no row behind it — every later call for this key serves "
        "bytes the table cannot account for, and any other process serves something else")


def test_two_staged_calls_for_one_question_pair_on_the_asked_form(tmp_path):
    """    `correlation_key` is computed from `asked_params`, so two worlds' staged rows PAIR.

    The column being written is not the same claim as the function reading it, and only the
    function is what a comparator calls. On a staged system the prepared forms differ BY
    CONSTRUCTION — that is what staging is — so `ΔO` over `keys(A) ∩ keys(B)` intersects to
    nothing: A recorded `FROM wv-a-…`, B recorded `FROM wv-b-…`, no row of A's ever meets a row
    of B's, and "the worlds differ" and "the worlds are identical" produce the same empty
    answer. Silent, and silent on the event stream, where most of a run's evidence lives.

    Both halves in one assertion pair: the correlation keys must MEET while the memo keys must
    NOT, because a `correlation_key` that quietly returned `key` would also make the two agree
    if the params happened to match."""
    asked = {"query": "FROM logs-system.auth-*"}
    rows = [
        ServedCall(system="elastic", verb="esql", params={"query": f"FROM wv-{w}-logs-system.auth-"},
                   payload_text="{}", source=STAGED, world_id=w, asked_params=asked)
        for w in ("a", "b")
    ]

    assert rows[0].correlation_key == rows[1].correlation_key, (
        "two worlds asked one question and their rows do not pair — ΔO over this system is "
        "empty rather than measured")
    assert rows[0].key != rows[1].key, (
        "the memo keys collapsed too, so each world would replay the other's staged corpus")


def test_a_torn_base_row_is_not_served_as_an_answer(tmp_path):
    """    A base row whose `payload_text` is present, non-empty and NOT JSON is skipped.

    A torn line is what a crash mid-append leaves, and it is the shape the two cheaper guards
    miss: it is a `str` and it is truthy. Served as a hit, it reaches `json.loads` INSIDE the
    verb body, where the resulting `JSONDecodeError` is not an `AdapterFault` — so the query
    tool's catch-all files it as exit 2, an INFRA code, and one torn row starts counting against
    the circuit breaker for a system that is perfectly healthy.

    Skipped, the key falls through to the live adapter, which is the honest reading of "nothing
    recorded"."""
    root = episode(tmp_path, rows=[{
        "system": "cmdb", "verb": "get-host", "params": {"host": "canary-1"},
        "payload_text": '{"owner": "est', "source": CAPTURED, "world_id": None,
    }])
    ledger = Ledger(root / SERVED_DIRNAME / "w1.jsonl", base_path=base_file(root))

    assert ledger.base_payload("cmdb", "get-host", {"host": "canary-1"}) is None


def test_a_world_owned_row_never_answers_for_the_family_even_when_it_is_first(tmp_path):
    """    A world's OWN row is not the family's answer, whatever order the file happens to hold.

    The two rules meet here and one has to win: `base_payload` reads the family tier ONLY, and a
    duplicate resolves to the FIRST row. A memo that absorbed world rows would take this file's
    opening row — a world's applied payload — and serve it to every sibling as the estate's own
    answer, while each sibling's row still honestly reported `passthrough`. That is silent
    scenario INJECTION, invisible in exactly the record meant to show it.

    The ordering is the whole fixture: a world row BEFORE the base row for one key is what a
    crashed earlier attempt leaves behind, and it is the only arrangement under which the tier
    filter and the tie-break disagree. With the base row first, an unfiltered absorb answers
    correctly by accident."""
    root = episode(tmp_path)
    path = root / SERVED_DIRNAME / "w1.jsonl"
    call = dict(system="cmdb", verb="get-host", params={"host": "canary-1"})
    append_jsonl(path, [
        ServedCall(payload_text='{"owner": "world a made this"}', source=PATCHED,
                   world_id="w1", **call).row(),
        ServedCall(payload_text='{"owner": "estate"}', source=BASE, world_id=None, **call).row(),
    ])

    ledger = Ledger(path, base_path=base_file(root))

    assert json.loads(ledger.base_payload("cmdb", "get-host", {"host": "canary-1"})) == {
        "owner": "estate"}


def test_a_duplicate_inside_one_file_resolves_to_the_first_row(tmp_path):
    """    Two rows for one key resolve to the FIRST, in memory and on a rebuild alike.

    The rule the append-only reading demands, and the one that has to hold in both loops: built
    twice with opposite tie-breaks, this process served the second payload while any process
    rebuilding from the file served the first."""
    root = episode(tmp_path)
    ledger = Ledger(root / SERVED_DIRNAME / "w1.jsonl", base_path=base_file(root))
    call = dict(system="cmdb", verb="get-host", params={"host": "canary-1"},
                source=BASE, world_id=None)

    ledger.record(ServedCall(payload_text='{"owner": "first"}', **call))
    ledger.record(ServedCall(payload_text='{"owner": "second"}', **call))

    assert ledger.base_payload("cmdb", "get-host", {"host": "canary-1"}) \
        == Ledger(ledger.path, base_path=base_file(root)).base_payload(
            "cmdb", "get-host", {"host": "canary-1"}) \
        == '{"owner": "first"}'


# ==========================================================================
# 4. `for_world`: one file per world, under the episode's own capture
# ==========================================================================

def test_for_world_opens_this_worlds_file_beside_the_shared_capture(tmp_path):
    """    `for_world` is the naming rule: `served/<world_id>.jsonl` over `served/base.jsonl`.

    Spelled once, because the two halves are not independent — a caller that derived its own
    path would have to derive the capture's too, and a sibling reading the right rows against
    the wrong base is exactly the un-primed episode that reads as primed."""
    root = episode(tmp_path, rows=[captured("cmdb", "get-host", {"host": "canary-1"},
                                            {"owner": "estate"})])

    ledger = Ledger.for_world(root, "w1")

    assert ledger.path == root / SERVED_DIRNAME / "w1.jsonl"
    assert ledger.base_payload("cmdb", "get-host", {"host": "canary-1"}) is not None
    ledger.record(ServedCall(
        system="cmdb", verb="get-host", params={"host": "canary-1"},
        payload_text='{"owner": "estate"}', source=PASSTHROUGH, world_id="w1"))
    assert [r["world_id"] for r in read_jsonl_rows(root / SERVED_DIRNAME / "w1.jsonl")] == ["w1"]


def test_for_world_refuses_an_episode_that_was_never_primed(tmp_path):
    """    `for_world` over an episode with no `served/base.jsonl` is refused.

    The same ordering guarantee reached through the constructor callers actually use. Answering
    with a ledger over an absent capture would let the whole episode run un-primed, and the only
    symptom is an adapter call count nobody is counting."""
    root = tmp_path / "episode"
    (root / SERVED_DIRNAME).mkdir(parents=True)

    with pytest.raises(LedgerError):
        Ledger.for_world(root, "w1")


@pytest.mark.parametrize("world_id", ["", ".", "..", "a/b", "../base", "sub/w1", "w1/"])
def test_for_world_refuses_a_world_id_that_is_not_a_filename(tmp_path, world_id):
    """    A world id that is not a single filename component is refused, not sanitized.

    The id reaches a PATH here, and it is not a value this seam mints — a world file names it,
    and #920's own arms show ids arriving from outside. `..` walks out of the episode; a
    separator writes a sibling's rows into a directory nobody reads; an empty id names the
    directory itself. Each of those is a run that records into the wrong place while every row
    it writes reads perfectly well.

    Refused rather than repaired, because a repaired id no longer matches the id the ledger's own
    rows carry — the file would be named for one world and its rows for another."""
    root = episode(tmp_path)

    with pytest.raises(LedgerError):
        Ledger.for_world(root, world_id)

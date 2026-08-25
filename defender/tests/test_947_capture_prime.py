"""#947 Part B — priming the captured base out of the source run's own evidence.

The base world of a turn-N episode is not "whatever the estate says when the first sibling
asks". It is what the real adapters returned during the REAL run, and that is already on disk:
`executed_queries.jsonl` names every call the defender made, and `gather_raw/{lead}/{seq}.json`
holds what came back. `prime_base` folds those into `served/base.jsonl` before any sibling
forks, so every question the source already asked is answered from the capture and costs no
live call at all — which is what makes two siblings' evidence identical wherever their worlds
did not differ.

WHAT IT MUST NOT TAKE. The table records more than captures. A `∅.`-prefixed `query_id` is a
writer-only sentinel for something that never reached a system (a refused repeat, a failed
reducer shim); a non-zero `exit_code` is a call the system refused or faulted on; and a sidecar
can be absent, empty or truncated. Each of those primed as a capture is a sibling served a
non-answer AS the estate's answer, with a `captured` row behind it that no reader can
second-guess. Each is counted separately, because they are different faults and an operator
reading `primed=8` needs to know whether the other four were sentinels or lost payloads.

THE ROUND TRIP IS THE SUBTLE ONE. The sidecar was written by `record_query` without
`sort_keys`; the ledger canonicalises through `payload_text`. A primer that copied sidecar
bytes into the row would produce a capture that is byte-different from what the serving path
produces for the identical payload — so ΔO would report a difference on every primed key, in a
field no world touched.

Hermetic: the source runs are built in `tmp_path` in the shape the real fixture at
`.defender-runs/turnN-A/` has (a mix of `exit_code: 0` captures and `exit_code: 1` failures,
sidecars whose keys are in the writer's insertion order), rather than read from it — that path
is gitignored, so a test bound to it would be a test CI cannot run.
"""
from __future__ import annotations

import datetime as dt
import importlib
import json
from pathlib import Path

import pytest

from defender._io import append_jsonl, read_jsonl_rows
from defender._run_paths import RunPaths
from defender.learning.branch.ledger import (
    BASE_FILENAME,
    CAPTURED,
    SERVED_DIRNAME,
    Ledger,
    LedgerError,
    payload_text,
)
from defender.runtime.verb_grant import VerbGrant
from defender.runtime.verbs import VerbContext
from defender.scripts.gather_tools.record_query import (
    ABOVE_GUARD_QUERY_ID,
    BASH_SHIM_QUERY_ID,
    REPEAT_TRIP_QUERY_ID,
)

#: The episode's clock. A primed capture is served under it like anything else, so the registry
#: this file drives needs one; nothing here is about its value.
T0 = dt.datetime(2026, 5, 25, 15, 30, 45, tzinfo=dt.UTC)

#: A payload whose keys are NOT in sorted order, and nested, so a re-dump has to reach the
#: subtree too. `json.dumps` without `sort_keys` preserves insertion order — which is exactly
#: what `record_query.persist_payload` writes and what the primer has to normalise away.
UNSORTED_PAYLOAD = {"zebra": 1, "alpha": {"n": 2, "m": 3}, "beta": [3, 1]}

#: A cmdb body answering differently from anything a source run captured, so "the capture was
#: replayed" and "the estate was asked" are distinguishable from the payload alone. Written to
#: disk rather than patched in: `ModuleVerbRegistry` cold-reads this `VERBS = {...}` literal
#: through the AST and checks the grant against it before importing anything.
_LIVE_ADAPTER = '''\
"""A verb body that answers `live-estate` and logs that it ran at all."""
from __future__ import annotations

import json
from pathlib import Path

from defender.runtime.verbs import VerbContext, verb

CALLS = "adapter-calls.jsonl"


@verb()
def get_host(ctx: VerbContext, *, host: str) -> dict:
    log = Path(ctx.run_dir) / CALLS
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({"host": host}) + "\\n")
    return {"owner": "live-estate", "host": host}


@verb()
def health_check(ctx: VerbContext) -> dict:
    return {"ok": True}


VERBS = {"get-host": get_host, "health-check": health_check}
'''

LIVE_GRANT = VerbGrant(role="gather", entries=(
    ("cmdb", "get-host", "r"), ("cmdb", "health-check", "r"),
))


def capture_mod():
    """`defender.learning.branch.capture` — #947's new module, imported per test so a missing
    target is one failure per test rather than one collection error for the file."""
    return importlib.import_module("defender.learning.branch.capture")


def call_row(lead: str, seq: int, system: str, verb: str, params: dict, **extra) -> dict:
    """One `executed_queries.jsonl` row, shaped as the query tool writes one.

    `**extra` overrides any field — `exit_code`, `query_id`, `payload_path` — so a test names
    only the thing it is varying and the rest stays a realistic row.
    """
    row = {
        "lead_id": lead, "seq": seq, "system": system, "verb": verb,
        "query_id": f"{system}.{verb}", "params": params,
        "payload_path": f"gather_raw/{lead}/{seq}.json",
        "exit_code": 0, "error_class": None, "payload_status": "ok",
    }
    row.update(extra)
    return row


def append_call(run_dir: Path, row: dict, sidecar: str | None) -> dict:
    """Land one captured call in a source run: the table row, and the sidecar it names.

    `sidecar=None` writes no file — the row still names one, which is what a payload lost to a
    failed `persist_payload` looks like on disk.
    """
    append_jsonl(RunPaths(run_dir).executed_queries, [row])
    if sidecar is not None:
        target = run_dir / str(row["payload_path"])
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(sidecar, encoding="utf-8")
    return row


def source_run(tmp_path: Path, name: str = "run-source") -> Path:
    run_dir = tmp_path / name
    RunPaths(run_dir).gather_raw.mkdir(parents=True, exist_ok=True)
    return run_dir


def episode(tmp_path: Path) -> tuple[Path, Path]:
    """An episode root and the base path a primer writes into. Returns `(root, base_path)`."""
    root = tmp_path / "episode"
    (root / SERVED_DIRNAME).mkdir(parents=True, exist_ok=True)
    return root, root / SERVED_DIRNAME / BASE_FILENAME


def counts(report) -> dict:
    """The whole tally, as one comparable object.

    Asserted whole rather than field by field: the five counters partition the table, so a row
    that moved from one bucket to another shows up as a diff naming both — where five separate
    asserts would report only the first.
    """
    return {name: getattr(report, name)
            for name in ("primed", "duplicates", "failed", "sentinels", "unreadable")}


def fake_estate(tmp_path: Path) -> Path:
    adapters = tmp_path / "adapters"
    adapters.mkdir(parents=True, exist_ok=True)
    (adapters / "cmdb_adapter.py").write_text(_LIVE_ADAPTER, encoding="utf-8")
    return adapters


def run_ctx(tmp_path: Path) -> VerbContext:
    """The context a served call arrives on — NAMING NO MOMENT, as `query_tool.py` builds one.

    Nothing here is about the clock, which is exactly why it must not be pre-seeded: a fixture
    that hands the seam the value the seam is supposed to supply makes the seam redundant, and
    an arm elsewhere that leans on this helper would pass with the injection deleted."""
    run_dir = tmp_path / "sibling-run"
    run_dir.mkdir(parents=True, exist_ok=True)
    return VerbContext(defender_dir=tmp_path, run_dir=run_dir, env={})


# ==========================================================================
# 1. what a primed row is
# ==========================================================================

def test_a_captured_call_becomes_a_family_row_the_ledger_can_read(tmp_path):
    """    One captured call in, one `captured` family row out — and the ledger reads it straight
    back through the key the sibling will ask with.

    Asserted at BOTH ends deliberately. The row's own fields say the primer wrote the right
    provenance (`captured`, and `world_id=None`, which is how the family tier is spelled); the
    read-back says it wrote it in the shape the reader actually keys on. A primer that got the
    fields right and the key wrong writes a file that is never once hit, and the only symptom is
    an episode that quietly asks the live estate for everything."""
    run_dir = source_run(tmp_path)
    append_call(run_dir, call_row("l-001", 0, "cmdb", "get-host", {"host": "canary-1"}),
                json.dumps({"owner": "estate", "role": "canary"}))
    root, base = episode(tmp_path)

    report = capture_mod().prime_base(run_dir, base)

    assert counts(report) == {"primed": 1, "duplicates": 0, "failed": 0,
                              "sentinels": 0, "unreadable": 0}
    rows = read_jsonl_rows(base)
    assert [(r["source"], r["world_id"]) for r in rows] == [(CAPTURED, None)]
    assert (rows[0]["system"], rows[0]["verb"], rows[0]["params"]) == (
        "cmdb", "get-host", {"host": "canary-1"})
    hit = Ledger.for_world(root, "w1").base_payload("cmdb", "get-host", {"host": "canary-1"})
    assert hit is not None, "the primed row is not reachable through the key a sibling asks with"
    assert json.loads(hit) == {"owner": "estate", "role": "canary"}


def test_a_primed_payload_is_canonical_rather_than_the_sidecars_own_bytes(tmp_path):
    """    A sidecar whose keys are in the writer's order is RE-DUMPED, so the primed row is byte
    identical to what the serving path produces for the same payload.

    THE arm that catches a primer that copies sidecar bytes. `record_query.persist_payload`
    writes without `sort_keys` and the ledger canonicalises with it, so a verbatim copy differs
    from a live serve of the same object in key ORDER alone — every primed key reporting a
    difference in a field no world touched, on the tier whose entire purpose is that siblings
    agree there.

    The fixture's own discriminating power is asserted first: if the sidecar bytes happened to
    already be canonical, this arm would pass against the copier it exists to catch."""
    run_dir = source_run(tmp_path)
    sidecar = json.dumps(UNSORTED_PAYLOAD)
    assert sidecar != payload_text(UNSORTED_PAYLOAD), (
        "the fixture's sidecar is already canonical, so a verbatim copy would pass this arm")
    append_call(run_dir, call_row("l-001", 0, "cmdb", "get-host", {"host": "canary-1"}), sidecar)
    _root, base = episode(tmp_path)

    capture_mod().prime_base(run_dir, base)

    assert read_jsonl_rows(base)[0]["payload_text"] == payload_text(UNSORTED_PAYLOAD)


def test_a_primed_key_is_served_without_the_estate_being_asked(tmp_path):
    """    A sibling asking a question the source already asked is answered from the capture, and
    the adapter body never runs.

    This is the property the whole part exists for, driven through the real seam rather than
    asserted at the ledger: the payload the caller gets back is the SOURCE RUN's, and the fake
    adapter — which would have answered `live-estate` — recorded no call at all. Without it,
    "the base file holds a row" is a claim about a file rather than about what a sibling reads.
    """
    from defender.learning.branch.estate.registry import WorldRegistry

    run_dir = source_run(tmp_path)
    append_call(run_dir, call_row("l-001", 0, "cmdb", "get-host", {"host": "canary-1"}),
                json.dumps({"owner": "estate", "host": "canary-1"}))
    root, base = episode(tmp_path)
    capture_mod().prime_base(run_dir, base)

    class World:
        world_id = "w1"
        touches = ()

    reg = WorldRegistry(fake_estate(tmp_path), LIVE_GRANT, world=World(),
                        ledger=Ledger.for_world(root, "w1"), as_of=T0)
    ctx = run_ctx(tmp_path)

    payload = reg.verbs("cmdb")["get-host"](ctx, host="canary-1")

    assert payload == {"owner": "estate", "host": "canary-1"}, (
        f"the sibling was served {payload} — the live estate, not the run's own capture")
    assert read_jsonl_rows(Path(ctx.run_dir) / "adapter-calls.jsonl") == [], (
        "the adapter ran for a key the capture already holds")


# ==========================================================================
# 2. what it refuses to take
# ==========================================================================

def test_the_five_counters_partition_a_realistic_table(tmp_path):
    """    One table carrying every shape at once: a capture, a sentinel, a failure, a lost payload
    and a repeat — five rows, one primed, and each skip counted under its own name.

    Together rather than one at a time because the counters are a PARTITION: a primer that
    filed failures as unreadable would pass five single-shape arms and still tell an operator
    the run lost four payloads when it lost none. The real fixture at `.defender-runs/turnN-A/`
    is this shape — twelve rows, two of them `exit_code` failures, one with a zero-byte
    sidecar."""
    run_dir = source_run(tmp_path)
    append_call(run_dir, call_row("l-001", 0, "cmdb", "get-host", {"host": "canary-1"}),
                json.dumps({"owner": "estate"}))
    append_call(run_dir, call_row("l-001", 1, "cmdb", "get-host", {"host": "canary-1"},
                                  query_id=ABOVE_GUARD_QUERY_ID), json.dumps({"note": "repeat"}))
    append_call(run_dir, call_row("l-002", 0, "cmdb", "get-host", {"host": "gone-9"},
                                  exit_code=1, payload_status="error"), "")
    append_call(run_dir, call_row("l-002", 1, "cmdb", "list-hosts", {}), None)
    append_call(run_dir, call_row("l-003", 0, "cmdb", "get-host", {"host": "canary-1"}),
                json.dumps({"owner": "asked-again"}))
    _root, base = episode(tmp_path)

    report = capture_mod().prime_base(run_dir, base)

    assert counts(report) == {"primed": 1, "duplicates": 1, "failed": 1,
                              "sentinels": 1, "unreadable": 1}
    assert len(read_jsonl_rows(base)) == 1


@pytest.mark.parametrize("query_id",
                         [ABOVE_GUARD_QUERY_ID, BASH_SHIM_QUERY_ID, REPEAT_TRIP_QUERY_ID])
def test_every_shipped_sentinel_is_skipped_by_the_shared_predicate(tmp_path, query_id):
    """    A `∅.`-prefixed row is never primed, whichever sentinel it is.

    Parametrized over the shipped constants rather than over a `"∅."` literal, because the
    predicate has to be `record_query.is_reserved_query_id` and not a second spelling of the
    prefix: a sentinel primed as a capture serves a record of something that NEVER REACHED A
    SYSTEM as though it were the estate's answer, and the row behind it says `captured`.

    `payload_status: ok` on purpose — a sentinel's row is well-formed in every other respect,
    so nothing but the id separates it from a capture."""
    run_dir = source_run(tmp_path)
    append_call(run_dir, call_row("l-001", 0, "cmdb", "get-host", {"host": "canary-1"}),
                json.dumps({"owner": "estate"}))
    append_call(run_dir, call_row("l-001", 1, "cmdb", "list-hosts", {}, query_id=query_id),
                json.dumps({"hosts": []}))
    _root, base = episode(tmp_path)

    report = capture_mod().prime_base(run_dir, base)

    assert (report.primed, report.sentinels) == (1, 1)
    assert [r["verb"] for r in read_jsonl_rows(base)] == ["get-host"]


def test_a_failed_call_is_skipped_even_when_its_payload_reads_perfectly(tmp_path):
    """    A non-zero `exit_code` is not a capture, however readable the sidecar beside it is.

    The discriminator against a primer that gates on the PAYLOAD instead of the row: a refused
    or faulted call still writes a sidecar (the query tool persists the error body), so
    "readable JSON" admits it. Primed, the sibling is served a refusal as the estate's answer
    for that key — and never asks the live system, because the capture reports a hit.

    Counted as `failed` rather than `unreadable`, because the two name different faults: one is
    the source run's own record of a system saying no, the other is evidence this episode has
    lost."""
    run_dir = source_run(tmp_path)
    append_call(run_dir, call_row("l-001", 0, "cmdb", "get-host", {"host": "canary-1"}),
                json.dumps({"owner": "estate"}))
    append_call(run_dir, call_row("l-002", 0, "cmdb", "get-host", {"host": "gone-9"},
                                  exit_code=64, payload_status="error"),
                json.dumps({"error": "HTTP 404 from http://cmdb:8080/hosts/gone-9"}))
    _root, base = episode(tmp_path)

    report = capture_mod().prime_base(run_dir, base)

    assert counts(report)["failed"] == 1
    assert counts(report)["unreadable"] == 0, "a system's refusal was filed as a lost payload"
    assert [r["params"] for r in read_jsonl_rows(base)] == [{"host": "canary-1"}]


@pytest.mark.parametrize(("label", "sidecar", "payload_path"), [
    ("absent", None, None),
    ("empty", "", None),
    ("truncated", '{"owner": "est', None),
    ("not-json", "OSError: no space left on device", None),
    ("escaping", '{"owner": "estate"}', "../../etc/passwd"),
    ("unshaped", '{"owner": "estate"}', "gather_raw/l-001/notes.txt"),
])
def test_a_payload_this_episode_cannot_read_is_counted_not_guessed(
        tmp_path, label, sidecar, payload_path):
    """    A sidecar that cannot be read back as JSON is skipped and COUNTED, never primed as
    something else.

    Four of these are the run's own accidents (a `persist_payload` that failed, a torn write, a
    disk that filled) and two are the run dir being the box's rw bind: `payload_path` is a
    recorded string, so a row naming `../../etc/passwd` or a path outside the payload families
    is a read this episode must not make. Resolved through the same containment rule the offline
    readers use rather than opened as given.

    Counted rather than silently dropped, because `primed` alone cannot distinguish "the source
    ran eight queries" from "the source ran twelve and this episode lost four" — and the second
    is an episode whose siblings will go live for a third of their evidence."""
    run_dir = source_run(tmp_path)
    append_call(run_dir, call_row("l-000", 0, "cmdb", "list-hosts", {}),
                json.dumps({"hosts": ["canary-1"]}))
    extra = {} if payload_path is None else {"payload_path": payload_path}
    append_call(run_dir, call_row("l-001", 0, "cmdb", "get-host", {"host": "canary-1"}, **extra),
                sidecar)
    _root, base = episode(tmp_path)

    report = capture_mod().prime_base(run_dir, base)

    assert counts(report) == {"primed": 1, "duplicates": 0, "failed": 0,
                              "sentinels": 0, "unreadable": 1}, label
    assert [r["verb"] for r in read_jsonl_rows(base)] == ["list-hosts"]


@pytest.mark.parametrize("physical_line", ['{"lead_id": "lost"', '["not", "a", "row"]'],
                         ids=["truncated-json", "non-dict-json"])
def test_a_malformed_capture_table_line_is_counted_before_the_tolerant_reader_drops_it(
        tmp_path, physical_line):
    """Every malformed non-blank physical line advances the primer's unreadable count.

    The ordinary JSONL reader intentionally drops truncated and non-dict lines. Priming cannot:
    each may be a lost question, and reporting a clean capture would let a sibling re-ask that
    key against the live estate without any skipped-row signal.
    """
    run_dir = source_run(tmp_path)
    append_call(run_dir, call_row("l-001", 0, "cmdb", "list-hosts", {}),
                json.dumps({"hosts": ["canary-1"]}))
    with RunPaths(run_dir).executed_queries.open("a", encoding="utf-8") as fh:
        fh.write(physical_line + "\n")
    _root, base = episode(tmp_path)

    report = capture_mod().prime_base(run_dir, base)

    assert counts(report) == {"primed": 1, "duplicates": 0, "failed": 0,
                              "sentinels": 0, "unreadable": 1}
    assert [row["verb"] for row in read_jsonl_rows(base)] == ["list-hosts"]


def test_a_repeated_question_keeps_the_answer_the_run_saw_first(tmp_path):
    """    Two captures of one key resolve to the FIRST, and the second is counted as a duplicate.

    One rule, in one direction, shared with the ledger's own memo: `base_payload` resolves a
    duplicate key to the first row it reads, so a primer that kept the LAST would write a file
    whose reader disagrees with its writer — and an episode re-primed from the same run would
    then serve a different answer from one primed earlier.

    The two payloads differ on purpose: a run genuinely does ask one question twice and get two
    answers, which is the estate moving under it. The capture takes the earlier one, which is
    the one nearer the branch point's own moment."""
    run_dir = source_run(tmp_path)
    append_call(run_dir, call_row("l-001", 0, "cmdb", "get-host", {"host": "canary-1"}),
                json.dumps({"owner": "first"}))
    append_call(run_dir, call_row("l-004", 0, "cmdb", "get-host", {"host": "canary-1"}),
                json.dumps({"owner": "second"}))
    _root, base = episode(tmp_path)

    report = capture_mod().prime_base(run_dir, base)

    assert (report.primed, report.duplicates) == (1, 1)
    assert json.loads(read_jsonl_rows(base)[0]["payload_text"]) == {"owner": "first"}


def test_a_key_spelled_in_another_order_is_the_same_captured_question(tmp_path):
    """    Two rows whose params differ only in ORDER are one key, so the second is a duplicate.

    The capture is keyed through `request_key`, the same function the seam serves through — so
    the question a model writes as `{limit, native_query}` finds the row the run recorded as
    `{native_query, limit}`. Keyed on the spelling, half a capture silently misses and those
    keys go live, which is the failure the family tier exists to prevent arriving through the
    one door nothing watches."""
    run_dir = source_run(tmp_path)
    append_call(run_dir, call_row("l-001", 0, "elastic", "query",
                                  {"native_query": "x", "limit": 5}),
                json.dumps({"hits": []}))
    append_call(run_dir, call_row("l-002", 0, "elastic", "query",
                                  {"limit": 5, "native_query": "x"}),
                json.dumps({"hits": ["later"]}))
    _root, base = episode(tmp_path)

    report = capture_mod().prime_base(run_dir, base)

    assert (report.primed, report.duplicates) == (1, 1)


def test_priming_an_existing_base_is_refused_without_changing_its_first_capture(tmp_path):
    """An episode's capture is immutable: a second source cannot append beneath the first.

    The ledger resolves duplicate keys first-row-wins, so appending a new prime would report the
    new source while every sibling continued receiving the old source's answer. The refusal is
    checked both by the exception and by the original bytes remaining untouched.
    """
    first = source_run(tmp_path, "run-first")
    second = source_run(tmp_path, "run-second")
    row = call_row("l-001", 0, "cmdb", "get-host", {"host": "canary-1"})
    append_call(first, row, json.dumps({"owner": "first"}))
    append_call(second, row, json.dumps({"owner": "second"}))
    root, base = episode(tmp_path)
    capture_mod().prime_base(first, base)
    original = base.read_bytes()

    with pytest.raises(LedgerError, match="already holds a primed base"):
        capture_mod().prime_base(second, base)

    assert base.read_bytes() == original
    payload = Ledger.for_world(root, "w1").base_payload(
        "cmdb", "get-host", {"host": "canary-1"})
    assert payload is not None
    assert json.loads(payload) == {"owner": "first"}


# ==========================================================================
# 3. an episode that primed nothing is not an episode
# ==========================================================================

@pytest.mark.parametrize("label", ["empty-table", "all-sentinels", "all-failed", "no-table"])
def test_priming_nothing_is_refused_rather_than_reported(tmp_path, label):
    """    A run that yields no capture at all raises `LedgerError` instead of returning `primed=0`.

    A zero primer is an episode whose every question goes live: both siblings read a moving
    estate, their difference is the estate's drift, and every row still reads honestly because
    `base` is a legitimate label for a live family read. There is no downstream reader that
    could notice, so the refusal has to be here.

    All four shapes, because they arrive from different directions — a source that never
    gathered, one whose whole table is writer-only sentinels, one whose every call was refused,
    and a run dir with no table at all (which `validate` also refuses, one layer up, and which
    must not reach this as a crash)."""
    run_dir = source_run(tmp_path)
    if label == "all-sentinels":
        append_call(run_dir, call_row("l-001", 0, "cmdb", "get-host", {"host": "canary-1"},
                                      query_id=ABOVE_GUARD_QUERY_ID), json.dumps({"n": 1}))
    elif label == "all-failed":
        append_call(run_dir, call_row("l-001", 0, "cmdb", "get-host", {"host": "canary-1"},
                                      exit_code=1, payload_status="error"), "")
    elif label == "empty-table":
        RunPaths(run_dir).executed_queries.write_text("", encoding="utf-8")
    _root, base = episode(tmp_path)

    with pytest.raises(LedgerError):
        capture_mod().prime_base(run_dir, base)


def test_a_refused_priming_leaves_no_base_a_sibling_could_open(tmp_path):
    """    After a refusal there is no `served/base.jsonl` — so `Ledger.for_world` still refuses too.

    The two halves of the ordering guarantee are one guarantee. `Ledger.__post_init__` refuses a
    base that is not a file, and that is the ONLY check that priming happened; a primer that
    created its output file before discovering it had nothing to write would convert that
    refusal into a silent pass, and the episode would run un-primed with a ledger that opened
    perfectly well."""
    run_dir = source_run(tmp_path)
    append_call(run_dir, call_row("l-001", 0, "cmdb", "get-host", {"host": "canary-1"},
                                  query_id=ABOVE_GUARD_QUERY_ID), json.dumps({"n": 1}))
    root, base = episode(tmp_path)

    with pytest.raises(LedgerError):
        capture_mod().prime_base(run_dir, base)

    assert not base.is_file(), (
        "a refused priming left a base file behind — every later sibling opens it, finds "
        "nothing, and goes live for the whole episode with nothing red anywhere")
    with pytest.raises(LedgerError):
        Ledger.for_world(root, "w1")

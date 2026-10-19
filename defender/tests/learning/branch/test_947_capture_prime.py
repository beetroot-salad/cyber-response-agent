"""#947 Part B — priming the captured base out of the source run's own evidence."""
from __future__ import annotations

import datetime as dt
import importlib
import json
from pathlib import Path

import pytest

from defender._io import append_jsonl, read_jsonl_rows
from defender.run_repository import RunPaths
from defender.runtime.verbs import read_roster
from defender._episode_handle import Episode
from defender._episode_paths import BASE_FILENAME, SERVED_DIRNAME
from defender.learning.branch.ledger import (
    CAPTURED,
    Ledger,
    LedgerError,
    payload_text,
)
from defender.runtime.verb_grant import VerbGrant
from defender.tests.support.tenancy import _tenants1106
from defender.runtime.verbs import VerbContext
from defender._query_rules import ABOVE_GUARD_QUERY_ID, BASH_SHIM_QUERY_ID, REPEAT_TRIP_QUERY_ID

#: The episode's clock. A primed capture is served under it like anything else, so the registry
#: this file drives needs one; nothing here is about its value.
T0 = dt.datetime(2026, 5, 25, 15, 30, 45, tzinfo=dt.UTC)

UNSORTED_PAYLOAD = {"zebra": 1, "alpha": {"n": 2, "m": 3}, "beta": [3, 1]}

#: A cmdb body answering differently from anything a source run captured, so "the capture was
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
    """One `executed_queries.jsonl` row, shaped as the query tool writes one."""
    row = {
        "lead_id": lead, "seq": seq, "system": system, "verb": verb,
        "query_id": f"{system}.{verb}", "params": params,
        "payload_path": f"gather_raw/{lead}/{seq}.json",
        "exit_code": 0, "error_class": None, "payload_status": "ok",
    }
    row.update(extra)
    return row


def append_call(run_dir: Path, row: dict, sidecar: str | None) -> dict:
    """Land one captured call in a source run"""
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


def _prime(run_dir: Path, root: Path):
    """`prime_base` over an `Episode` opened on the episode root: it takes the handle, not the
    base path (#1133 rev 2)."""
    with Episode.open(root) as ep:
        return capture_mod().prime_base(run_dir, ep)


def counts(report) -> dict:
    """The whole tally, as one comparable object."""
    return {name: getattr(report, name)
            for name in ("primed", "duplicates", "failed", "sentinels", "unreadable")}


def fake_estate(tmp_path: Path) -> Path:
    adapters = tmp_path / "adapters"
    adapters.mkdir(parents=True, exist_ok=True)
    (adapters / "cmdb_adapter.py").write_text(_LIVE_ADAPTER, encoding="utf-8")
    return adapters


def run_ctx(tmp_path: Path) -> VerbContext:
    """The context a served call arrives on — NAMING NO MOMENT, as `query_tool.py` builds one."""
    run_dir = tmp_path / "sibling-run"
    run_dir.mkdir(parents=True, exist_ok=True)
    return VerbContext(defender_dir=tmp_path, run_dir=run_dir, env={},
                       tenant=_tenants1106.fixture_run_tenant())


# 1. what a primed row is

def test_a_captured_call_becomes_a_family_row_the_ledger_can_read(tmp_path):
    """One captured call in, one `captured` family row out — and the ledger reads it straight back through the key the sibling will ask with."""
    run_dir = source_run(tmp_path)
    append_call(run_dir, call_row("l-001", 0, "cmdb", "get-host", {"host": "canary-1"}),
                json.dumps({"owner": "estate", "role": "canary"}))
    root, base = episode(tmp_path)

    report = _prime(run_dir, root)

    assert counts(report) == {"primed": 1, "duplicates": 0, "failed": 0,
                              "sentinels": 0, "unreadable": 0}
    rows = read_jsonl_rows(base)
    assert [(r["source"], r["world_id"]) for r in rows] == [(CAPTURED, None)]
    assert (rows[0]["system"], rows[0]["verb"], rows[0]["params"]) == (
        "cmdb", "get-host", {"host": "canary-1"})
    with Episode.open(root) as ep:
        hit = Ledger.for_world(ep, "w1").base_payload("cmdb", "get-host", {"host": "canary-1"})
    assert hit is not None, "the primed row is not reachable through the key a sibling asks with"
    assert json.loads(hit) == {"owner": "estate", "role": "canary"}


def test_a_primed_payload_is_the_sidecars_own_bytes(tmp_path):
    run_dir = source_run(tmp_path)
    sidecar = json.dumps(UNSORTED_PAYLOAD)
    assert sidecar != payload_text(UNSORTED_PAYLOAD), (
        "the fixture's sidecar is already canonical, so a re-dumping primer would pass this arm")
    append_call(run_dir, call_row("l-001", 0, "cmdb", "get-host", {"host": "canary-1"}), sidecar)
    root, base = episode(tmp_path)

    _prime(run_dir, root)

    assert read_jsonl_rows(base)[0]["payload_text"] == sidecar
    with Episode.open(root) as ep:
        hit = Ledger.for_world(ep, "w1").base_payload("cmdb", "get-host", {"host": "canary-1"})
    assert hit == sidecar, "the sibling's lookup is not handed the sidecar's own bytes"


def test_a_primed_key_is_served_without_the_estate_being_asked(tmp_path):
    """A sibling asking a question the source already asked is answered from the capture, and the adapter body never runs."""
    from defender.tests.learning.oracle.live_contracts._spec1224 import build_registry

    run_dir = source_run(tmp_path)
    append_call(run_dir, call_row("l-001", 0, "cmdb", "get-host", {"host": "canary-1"}),
                json.dumps({"owner": "estate", "host": "canary-1"}))
    root, base = episode(tmp_path)
    _prime(run_dir, root)

    class World:
        world_id = "w1"
        touches = ()

    with Episode.open(root) as ep:
        reg = build_registry(read_roster(fake_estate(tmp_path)), LIVE_GRANT, world=World(),
                            ledger=Ledger.for_world(ep, "w1"), as_of=T0)
        ctx = run_ctx(tmp_path)

        payload = reg.verbs("cmdb")["get-host"](ctx, host="canary-1")

        assert payload == {"owner": "estate", "host": "canary-1"}, (
            f"the sibling was served {payload} — the live estate, not the run's own capture")
        assert read_jsonl_rows(Path(ctx.run_dir) / "adapter-calls.jsonl") == [], (
            "the adapter ran for a key the capture already holds")


# 2. what it refuses to take


@pytest.mark.parametrize("query_id",
                         [ABOVE_GUARD_QUERY_ID, BASH_SHIM_QUERY_ID, REPEAT_TRIP_QUERY_ID])
def test_every_shipped_sentinel_is_skipped_by_the_shared_predicate(tmp_path, query_id):
    """A `∅.`-prefixed row is never primed, whichever sentinel it is."""
    run_dir = source_run(tmp_path)
    append_call(run_dir, call_row("l-001", 0, "cmdb", "get-host", {"host": "canary-1"}),
                json.dumps({"owner": "estate"}))
    append_call(run_dir, call_row("l-001", 1, "cmdb", "list-hosts", {}, query_id=query_id),
                json.dumps({"hosts": []}))
    root, base = episode(tmp_path)

    report = _prime(run_dir, root)

    assert (report.primed, report.sentinels) == (1, 1)
    assert [r["verb"] for r in read_jsonl_rows(base)] == ["get-host"]


def test_a_failed_call_is_skipped_even_when_its_payload_reads_perfectly(tmp_path):
    """A non-zero `exit_code` is not a capture, however readable the sidecar beside it is."""
    run_dir = source_run(tmp_path)
    append_call(run_dir, call_row("l-001", 0, "cmdb", "get-host", {"host": "canary-1"}),
                json.dumps({"owner": "estate"}))
    append_call(run_dir, call_row("l-002", 0, "cmdb", "get-host", {"host": "gone-9"},
                                  exit_code=64, payload_status="error"),
                json.dumps({"error": "HTTP 404 from http://cmdb:8080/hosts/gone-9"}))
    root, base = episode(tmp_path)

    report = _prime(run_dir, root)

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
    """A sidecar that cannot be read back as JSON is skipped and COUNTED, never primed as something else."""
    run_dir = source_run(tmp_path)
    append_call(run_dir, call_row("l-000", 0, "cmdb", "list-hosts", {}),
                json.dumps({"hosts": ["canary-1"]}))
    extra = {} if payload_path is None else {"payload_path": payload_path}
    append_call(run_dir, call_row("l-001", 0, "cmdb", "get-host", {"host": "canary-1"}, **extra),
                sidecar)
    root, base = episode(tmp_path)

    report = _prime(run_dir, root)

    assert counts(report) == {"primed": 1, "duplicates": 0, "failed": 0,
                              "sentinels": 0, "unreadable": 1}, label
    assert [r["verb"] for r in read_jsonl_rows(base)] == ["list-hosts"]


@pytest.mark.parametrize("physical_line", ['{"lead_id": "lost"', '["not", "a", "row"]'],
                         ids=["truncated-json", "non-dict-json"])
def test_a_malformed_capture_table_line_is_counted_before_the_tolerant_reader_drops_it(
        tmp_path, physical_line):
    """Every malformed non-blank physical line advances the primer's unreadable count."""
    run_dir = source_run(tmp_path)
    append_call(run_dir, call_row("l-001", 0, "cmdb", "list-hosts", {}),
                json.dumps({"hosts": ["canary-1"]}))
    with RunPaths(run_dir).executed_queries.open("a", encoding="utf-8") as fh:
        fh.write(physical_line + "\n")
    root, base = episode(tmp_path)

    report = _prime(run_dir, root)

    assert counts(report) == {"primed": 1, "duplicates": 0, "failed": 0,
                              "sentinels": 0, "unreadable": 1}
    assert [row["verb"] for row in read_jsonl_rows(base)] == ["list-hosts"]


def test_a_repeated_question_keeps_the_answer_the_run_saw_first(tmp_path):
    """Two captures of one key resolve to the FIRST, and the second is counted as a duplicate."""
    run_dir = source_run(tmp_path)
    append_call(run_dir, call_row("l-001", 0, "cmdb", "get-host", {"host": "canary-1"}),
                json.dumps({"owner": "first"}))
    append_call(run_dir, call_row("l-004", 0, "cmdb", "get-host", {"host": "canary-1"}),
                json.dumps({"owner": "second"}))
    root, base = episode(tmp_path)

    report = _prime(run_dir, root)

    assert (report.primed, report.duplicates) == (1, 1)
    assert json.loads(read_jsonl_rows(base)[0]["payload_text"]) == {"owner": "first"}


def test_a_key_spelled_in_another_order_is_the_same_captured_question(tmp_path):
    """Two rows whose params differ only in ORDER are one key, so the second is a duplicate."""
    run_dir = source_run(tmp_path)
    append_call(run_dir, call_row("l-001", 0, "elastic", "query",
                                  {"native_query": "x", "limit": 5}),
                json.dumps({"hits": []}))
    append_call(run_dir, call_row("l-002", 0, "elastic", "query",
                                  {"limit": 5, "native_query": "x"}),
                json.dumps({"hits": ["later"]}))
    root, base = episode(tmp_path)

    report = _prime(run_dir, root)

    assert (report.primed, report.duplicates) == (1, 1)


def test_priming_an_existing_base_is_refused_without_changing_its_first_capture(tmp_path):
    """An episode's capture is immutable"""
    first = source_run(tmp_path, "run-first")
    second = source_run(tmp_path, "run-second")
    row = call_row("l-001", 0, "cmdb", "get-host", {"host": "canary-1"})
    append_call(first, row, json.dumps({"owner": "first"}))
    append_call(second, row, json.dumps({"owner": "second"}))
    root, base = episode(tmp_path)
    _prime(first, root)
    original = base.read_bytes()

    with pytest.raises(LedgerError, match="already holds a primed base"):
        _prime(second, root)

    assert base.read_bytes() == original
    with Episode.open(root) as ep:
        payload = Ledger.for_world(ep, "w1").base_payload(
            "cmdb", "get-host", {"host": "canary-1"})
    assert payload is not None
    assert json.loads(payload) == {"owner": "first"}


# 3. an episode that primed nothing is not an episode

@pytest.mark.parametrize("label", ["empty-table", "all-sentinels", "all-failed", "no-table"])
def test_priming_nothing_is_refused_rather_than_reported(tmp_path, label):
    """A run that yields no capture at all raises `LedgerError` instead of returning `primed=0`."""
    run_dir = source_run(tmp_path)
    if label == "all-sentinels":
        append_call(run_dir, call_row("l-001", 0, "cmdb", "get-host", {"host": "canary-1"},
                                      query_id=ABOVE_GUARD_QUERY_ID), json.dumps({"n": 1}))
    elif label == "all-failed":
        append_call(run_dir, call_row("l-001", 0, "cmdb", "get-host", {"host": "canary-1"},
                                      exit_code=1, payload_status="error"), "")
    elif label == "empty-table":
        RunPaths(run_dir).executed_queries.write_text("", encoding="utf-8")
    root, base = episode(tmp_path)

    with pytest.raises(LedgerError):
        _prime(run_dir, root)


def test_a_refused_priming_leaves_no_base_a_sibling_could_open(tmp_path):
    """After a refusal there is no `served/base.jsonl` — so `Ledger.for_world` still refuses too."""
    run_dir = source_run(tmp_path)
    append_call(run_dir, call_row("l-001", 0, "cmdb", "get-host", {"host": "canary-1"},
                                  query_id=ABOVE_GUARD_QUERY_ID), json.dumps({"n": 1}))
    root, base = episode(tmp_path)

    with pytest.raises(LedgerError):
        _prime(run_dir, root)

    assert not base.is_file(), (
        "a refused priming left a base file behind — every later sibling opens it, finds "
        "nothing, and goes live for the whole episode with nothing red anywhere")
    with Episode.open(root) as ep, pytest.raises(LedgerError):
        Ledger.for_world(ep, "w1")

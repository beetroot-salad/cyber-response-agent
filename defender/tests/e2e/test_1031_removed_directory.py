"""#1031 end to end — what the query tool RECORDS once the adapters directory is gone from
under a live registry, and what its rows charge the breaker.

WHAT IS DRIVEN, and why a real registry rather than the harness's `FakeVerbs`: every claim here
is about the roster the REAL `ModuleVerbRegistry` hands the REAL `QueryCapture` after the real
fault — the directory it was built over is `rmtree`d between construction and the first call.
A fake registry's `systems()` cannot have that fault; the one it could have (a raise) is N1's
broken fake. The registry is injected through `run_investigation(verbs=…)`, the harness's own
seam (#611), and everything between the replay models and the row is production code. The
unit half — the roster itself, the construction-time fault, the resolver, the subclass — is
`tests/test_1031_roster_snapshot.py`.

THE ROW IN ONE PARAGRAPH. `_system_of_record` answers `system if declared else ""`, and the
above-guard pair is `(that, system_fingerprint(raw, that))` — a fingerprint minted only on the
`""` arm. With the roster re-read from disk per call, a removed directory made every name
undeclared, so a DECLARED system's rejection was recorded as `("", sha256("elastic"))`: a real
name's hash keyed like a ghost's, which `system_fingerprint`'s contract forbids and which the
pitfalls channel would then read as a ghost. With the roster fixed at construction the pair is
`("elastic", "")` whatever the disk says, the ghost's is `("", sha256(ghost))` as before, and
every above-guard row is one the rejection guards count (#871 repeat, #1015 budget), so a loop
of them against a declared system ends the lead as it did before #1030.
"""
from __future__ import annotations

import asyncio
import json
import shutil
from dataclasses import replace
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender._io import read_text_utf8  # noqa: E402
from defender.agents import GATHER_DEF  # noqa: E402
from defender.runtime import circuit_breaker  # noqa: E402
from defender.runtime.agent_definition import bind  # noqa: E402
from defender.runtime.circuit_breaker import (  # noqa: E402
    AGENT_FIXABLE_ERROR_CLASS,
    PER_SYSTEM_FAIL_LIMIT,
)
from defender.runtime.query_tool import DEFAULT_FAULT_EXIT, QueryCapture  # noqa: E402
from defender.runtime.verbs import ModuleVerbRegistry  # noqa: E402
from defender.scripts.gather_tools import record_query  # noqa: E402
from defender.scripts.gather_tools.record_query import REJECTION_BUDGET  # noqa: E402
from defender.tests._declared869 import write  # noqa: E402
from defender.tests._verb_authorization_632 import grant_of  # noqa: E402
from defender.tests.e2e._replay_harness import DEFENDER, GOLDEN_AB3, materialize  # noqa: E402
from defender.tests.e2e.test_1015_rejection_budget import _assert_budget_stop  # noqa: E402
from defender.tests.e2e.test_855_model_named_systems import (  # noqa: E402
    PARAMS,
    _above_guard,
    _bad_args,
    _detail,
)
from defender.tests.e2e.test_pitfalls_input_823 import LEAD, _Res, _run  # noqa: E402
from defender.tests.e2e.test_query_tool_611 import DONE, q  # noqa: E402

pytestmark = pytest.mark.e2e

#: A REAL adapter — read cold by the registry's load check at construction, imported by the
#: dispatch on the corrected call — declaring the one verb the harness's `q("elastic",
#: "query", PARAMS)` turn names, with the harness's param contract (`native_query` required).
#: It writes its payload to the run dir so a call that reached it is observable on disk.
ELASTIC_ADAPTER = '''\
from pathlib import Path

from defender.runtime.verbs import VerbContext, verb

REACHED = "adapter-reached.txt"


@verb()
def query(ctx: VerbContext, *, native_query: str, limit: int = 10) -> list[dict]:
    (Path(ctx.run_dir) / REACHED).write_text(native_query, encoding="utf-8")
    return [{"hit": native_query}]


VERBS = {"query": query}
'''

#: The grant the registry is built under: the one system, the one verb. Real, so `decide`
#: reaches `elastic` (an unknown verb on it is the GRANT placement's unresolvable branch, not
#: an ungranted-system refusal) and the corrected call is GRANTED.
GRANT = grant_of("gather", (("elastic", "query"),))

ELASTIC_KEY = record_query.system_fingerprint("elastic", "")


def _real_registry(tmp_path: Path) -> tuple[Path, ModuleVerbRegistry]:
    """A real `ModuleVerbRegistry` over a real adapters directory declaring `elastic`."""
    adapters = tmp_path / "adapters"
    write(adapters / "elastic_adapter.py", ELASTIC_ADAPTER)
    return adapters, ModuleVerbRegistry(adapters, GRANT)


def _reached(r: _Res) -> bool:
    return (r.run_dir / "adapter-reached.txt").is_file()


def _assert_no_forbidden_pair(r: _Res) -> None:
    """The universal, over the WHOLE table (lead-0's rows included): no row carries `system=""`
    beside the fingerprint of a name the registry declares."""
    for row in r.rows:
        assert not (row["system"] == "" and row["system_key"] == ELASTIC_KEY), \
            f"a declared name's fingerprint is on a coarsened row: {row!r}"


# ---------------------------------------------------------------------------------------
# O3 — a rejection against a declared system is recorded as its own after the directory is gone
# ---------------------------------------------------------------------------------------


def test_a_declared_systems_rejection_keeps_its_name_after_the_directory_is_removed(tmp_path):
    """O3/O1 — the registry is built over a real directory, the directory is REMOVED, and the
    lead sends four above-guard rejections through both placements: a schema-rejected call and
    an unresolvable-verb call naming `elastic` (declared), and the same two naming ghosts. The
    declared rows carry `system="elastic"` with `system_key=""`, exit 64, `agent-fixable`, the
    model's verb in the detail; the ghost rows are coarsened to `""` with the ghost's own
    fingerprint — the same four rows the healthy control below writes with the directory
    intact. No row anywhere on the table pairs `""` with `sha256("elastic")`.

    The control is a second run over an intact directory with a corrected call appended: the
    adapter is REACHED (its marker file exists), so the fixture is a registry whose verbs
    dispatch, not a stub the grant happens to accept.

    Observed failing by (today): the two declared rows recorded as `("", sha256("elastic"))`
    — the roster re-globbed over a directory that is not there answers `()`."""
    rejections = [
        _bad_args("elastic", verb="ghostverb"), q("elastic", "otherverb", PARAMS),
        _bad_args("ghostone", verb="ghostverb"), q("ghosttwo", "otherverb", PARAMS),
    ]
    adapters, registry = _real_registry(tmp_path / "removed")
    shutil.rmtree(adapters)
    assert not adapters.exists()
    r = _run(tmp_path / "removed", run_id="d1031-removed", verbs=registry,
             turns=[*rejections, DONE])

    rows = _above_guard(r)
    assert len(rows) == 4, f"the four rejections did not all leave counted rows: {r.own_rows!r}"
    schema_declared, grant_declared, schema_ghost, grant_ghost = rows
    for row in (schema_declared, grant_declared):
        assert row["system"] == "elastic", \
            f"a declared system's rejection was coarsened away: {row!r}"
        assert row["system_key"] == "", \
            f"a declared system's rejection was fingerprinted: {row['system_key']!r}"
        assert row["exit_code"] == 64
        assert row["error_class"] == AGENT_FIXABLE_ERROR_CLASS
    assert "Extra inputs are not permitted" in _detail(schema_declared), \
        f"the schema row's detail is not the model's own schema error: {_detail(schema_declared)!r}"
    assert "otherverb" in _detail(grant_declared), \
        f"the grant row's detail no longer names the verb: {_detail(grant_declared)!r}"
    assert (schema_ghost["system"], schema_ghost["system_key"]) \
        == ("", record_query.system_fingerprint("ghostone", ""))
    assert (grant_ghost["system"], grant_ghost["system_key"]) \
        == ("", record_query.system_fingerprint("ghosttwo", ""))
    _assert_no_forbidden_pair(r)

    _adapters, intact = _real_registry(tmp_path / "intact")
    healthy = _run(tmp_path / "intact", run_id="d1031-intact", verbs=intact,
                   turns=[*rejections, q("elastic", "query", PARAMS), DONE])
    assert _reached(healthy), "the corrected call never reached the adapter — the fixture is a stub"
    assert healthy.own_rows[-1]["exit_code"] == 0
    control = [(row["system"], row["system_key"], row["exit_code"]) for row in _above_guard(healthy)]
    assert control == [(row["system"], row["system_key"], row["exit_code"]) for row in rows], \
        "the removed-directory run and the intact one disagree on the above-guard rows"
    _assert_no_forbidden_pair(healthy)


# ---------------------------------------------------------------------------------------
# O4 — the rejection guards bound a loop against a declared system; the breaker is charged
#      to the row's own system
# ---------------------------------------------------------------------------------------


def test_a_loop_of_rejections_against_a_declared_system_is_ended_by_the_budget(tmp_path):
    """O4 — `REJECTION_BUDGET + 3` schema-rejected calls naming the DECLARED `elastic` under a
    registry whose directory has been removed, each with a different verb so the repeat guard
    is silent by construction: the budget ends the lead at its `REJECTION_BUDGET`th rejection
    (the three-part oracle #1015 pins: terminator, digest, main's summary) and the corrected
    call appended after them never runs. Every counted row carries `system="elastic"`, so the
    rows the guard counted are the declared system's own.

    `e2e/test_1015_rejection_budget.py` pins the same bound for ghosts; this is the declared
    arm, which #1017 D4's `infra` row took OUT of the guards' domain when the registry could
    not list (the issue's first finding). The BOUND holds on the pre-#1031 code too — a
    removed directory coarsened these rows rather than making them `infra`, so the budget
    counted them — and is kept as the positive control that the guards see the rows O3
    changes the shape of; what fails today is the name on the counted rows (`""` beside
    `sha256("elastic")`), O3's failure inside O4's population."""
    adapters, registry = _real_registry(tmp_path)
    shutil.rmtree(adapters)
    r = _run(tmp_path, run_id="d1031-budget", verbs=registry, turns=[
        *[_bad_args("elastic", verb=f"ghostverb{i}") for i in range(REJECTION_BUDGET + 3)],
        q("elastic", "query", PARAMS), DONE,
    ])
    rows = _above_guard(r)
    assert len(rows) == REJECTION_BUDGET, \
        f"the lead wrote {len(rows)} above-guard rejections against a budget of {REJECTION_BUDGET}"
    assert {row["system"] for row in rows} == {"elastic"}, \
        "the counted rows do not carry the declared system's name"
    assert {row["system_key"] for row in rows} == {""}
    _assert_budget_stop(r)
    assert len(r.own_rows) == REJECTION_BUDGET, \
        "the lead ran on past its dead end and left rows after the stop"
    _assert_no_forbidden_pair(r)


def _breaker_doc(run_dir: Path) -> dict:
    path = run_dir / "circuit_breaker.json"
    return json.loads(read_text_utf8(path)) if path.is_file() else {}


def _record(capture: QueryCapture, run_dir: Path, *, system: str, exit_code: int, **extra) -> dict:
    """One `_record` call the way `_spec771`'s writer probe makes it: real deps bound to the
    run dir, a dispatched lead id, every row column the caller decides spelled out."""
    deps = replace(bind(GATHER_DEF, run_dir, defender_dir=DEFENDER), lead_id=LEAD)
    row, _text = asyncio.run(capture._record(
        deps, system=system, verb="query", query_id="elastic.query", params={},
        payload=None, exit_code=exit_code, detail="down", system_key="", **extra,
    ))
    return row


def test_record_charges_the_breaker_to_the_rows_own_system(tmp_path):
    """O4/D4 — `_record` has no `breaker_key`: the outcome is charged to the row's `system`.
    Two `infra`-exit rows for `elastic` leave the breaker document keyed on `elastic` alone,
    with `PER_SYSTEM_FAIL_LIMIT` failures and a trip, and `is_tripped(run_dir, "elastic")` is
    True — while no `host:`-prefixed key (the #1017 D4 reserved counter) exists in it. The
    positive controls: before the second row the system is not tripped; an exit-64 row for
    `elastic` charges nothing (`record_outcome` counts infra exits only); and a coarsened
    `system=""` row charges nothing either, which is why the rejection GUARDS, not the
    breaker, bound a ghost loop (B5). Passing `breaker_key=` is a `TypeError`, as a second
    assertion behind the behavioural one.

    Observed failing by (today): `TypeError` on the first call — `breaker_key` is required."""
    run_dir = materialize(tmp_path, GOLDEN_AB3)
    capture = QueryCapture(ModuleVerbRegistry(_real_registry(tmp_path)[0], GRANT))

    row = _record(capture, run_dir, system="elastic", exit_code=DEFAULT_FAULT_EXIT)
    assert row["system"] == "elastic"
    assert _breaker_doc(run_dir)["systems"]["elastic"]["failures"] == 1
    assert not circuit_breaker.is_tripped(run_dir, "elastic"), "one infra row tripped the system"

    _record(capture, run_dir, system="elastic", exit_code=DEFAULT_FAULT_EXIT)
    doc = _breaker_doc(run_dir)
    assert set(doc["systems"]) == {"elastic"}, \
        f"the breaker is keyed on {sorted(doc['systems'])}, not on the row's own system alone"
    assert doc["systems"]["elastic"]["failures"] == PER_SYSTEM_FAIL_LIMIT
    assert "tripped_at" in doc["systems"]["elastic"]
    assert circuit_breaker.is_tripped(run_dir, "elastic")
    assert not any(key.startswith("host:") for key in doc["systems"]), \
        "a reserved host counter is still charged"

    _record(capture, run_dir, system="elastic", exit_code=64)
    _record(capture, run_dir, system="", exit_code=DEFAULT_FAULT_EXIT)
    after = _breaker_doc(run_dir)
    assert after["systems"] == doc["systems"], "a usage row or a systemless row charged the breaker"
    assert after["total_failures"] == PER_SYSTEM_FAIL_LIMIT

    with pytest.raises(TypeError):
        _record(capture, run_dir, system="elastic", exit_code=DEFAULT_FAULT_EXIT,
                breaker_key="elastic")

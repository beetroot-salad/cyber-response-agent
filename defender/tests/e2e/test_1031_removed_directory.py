"""#1031 e2e: with the adapters directory removed from under a live registry, a declared system's above-guard rejection is still recorded under its own name (not as a ghost's fingerprint)."""
from __future__ import annotations


import shutil
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender.runtime.circuit_breaker import (  # noqa: E402
    AGENT_FIXABLE_ERROR_CLASS,
)
from defender.runtime.verbs import ModuleVerbRegistry, read_roster  # noqa: E402
from defender.scripts.gather_tools import record_query  # noqa: E402
from defender.tests._declared869 import write  # noqa: E402
from defender.tests._after_start_1256 import AfterStart  # noqa: E402
from defender.tests._verb_authorization_632 import grant_of  # noqa: E402
from defender.tests.e2e.test_855_model_named_systems import (  # noqa: E402
    PARAMS,
    _above_guard,
    _bad_args,
    _detail,
)
from defender.tests.e2e.test_pitfalls_input_823 import _Res, _run  # noqa: E402
from defender.tests.e2e.test_query_tool_611 import DONE, q  # noqa: E402
from defender.tests.tenant_1107_settings import _spec1107 as S  # noqa: E402

pytestmark = pytest.mark.e2e

#: A REAL adapter — read cold by the registry's load check at construction, imported by the
#: dispatch on the corrected call — declaring the one verb the harness's `q("elastic",
#: "query", PARAMS)` turn names, with the harness's param contract (`native_query` required).
#: It writes its payload to the run dir so a call that reached it is observable on disk.
ELASTIC_ADAPTER = '''\
from pathlib import Path

from defender.runtime.verbs import VerbContext, verb

REACHED = "adapter-reached.txt"


def check_settings(*_a, **_k):
    """This system needs no settings (#1256 O-5: every adapter declares its check)."""
    return None


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
    return adapters, ModuleVerbRegistry(read_roster(adapters), GRANT)


def _reached(r: _Res) -> bool:
    return (r.run_dir / "adapter-reached.txt").is_file()


def _assert_no_forbidden_pair(r: _Res) -> None:
    """The universal, over the WHOLE table (lead-0's rows included):"""
    for row in r.rows:
        assert not (row["system"] == "" and row["system_key"] == ELASTIC_KEY), \
            f"a declared name's fingerprint is on a coarsened row: {row!r}"


# ---------------------------------------------------------------------------------------
# O3 — a rejection against a declared system is recorded as its own after the directory is gone
# ---------------------------------------------------------------------------------------


def test_a_declared_systems_rejection_keeps_its_name_after_the_directory_is_removed(tmp_path):
    """O3/O1 — the registry is built over a real directory, the directory is REMOVED, and the lead sends four..."""
    rejections = [
        _bad_args("elastic", verb="ghostverb"), q("elastic", "otherverb", PARAMS),
        _bad_args("ghostone", verb="ghostverb"), q("ghosttwo", "otherverb", PARAMS),
    ]
    root = tmp_path / "tenant-data"
    S.plant(root, table="dispositions:\n  elastic:\n    query: {roles: [gather]}\n")
    tenant = S.tenant_folder_of(root)
    adapters, registry = _real_registry(tmp_path / "removed")
    removal = AfterStart(rejections[0], lambda: shutil.rmtree(adapters))
    r = _run(tmp_path / "removed", run_id="d1031-removed", verbs=registry, tenant=tenant,
             turns=[removal, *rejections[1:], DONE])
    assert removal.fired, "premise: the adapters directory was not removed during the run"
    assert not adapters.exists(), "premise: the adapters directory is still there"

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
    healthy = _run(tmp_path / "intact", run_id="d1031-intact", verbs=intact, tenant=tenant,
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


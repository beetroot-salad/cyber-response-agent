"""A startup-down adapter stays unloaded through admitted and denied query calls."""
from pathlib import Path

import pytest

from defender._io import read_jsonl_rows
from defender.run_repository import RunPaths
from defender.runtime import circuit_breaker
from defender.runtime.verbs import ModuleVerbRegistry, read_roster
from defender.tests.e2e._replay_harness import GOLDEN_AB3, Turn, drive, materialize
from defender.tests.startup_usability_1256.test_1256_adapter_checks import (
    _planted_source,
    _replies,
    planted_tree,
)
from defender.tests.tenant_1107_settings import _spec1107 as S
from defender.tests.test_920_estate_seam import SERVED_FILE, control_oracle, served_rows, world_registry

_TABLE = """\
dispositions:
  cmdb:
    get-host: {roles: [gather]}
  identity:
    get-user: {roles: [gather]}
"""


@pytest.mark.parametrize("replay", [False, True])
def test_queries_to_a_startup_broken_adapter_never_import_it_again(tmp_path: Path, replay: bool):
    probe = tmp_path / "probe"
    probe.mkdir()
    imports = probe / "identity.imports"
    broken = _planted_source("identity", probe, at_import=[
        f"with open({str(imports)!r}, 'a', encoding='utf-8') as counter:",
        "    counter.write('import\\n')",
        "raise ImportError('identity startup failure')",
    ])
    broken += "\ndef withheld(ctx):\n    return {}\n"
    broken = broken.replace("VERBS = {'get-user': get_user}",
                            "VERBS = {'get-user': get_user, 'withheld': withheld}")
    tree = planted_tree(tmp_path / "tree", probe, sources={
        "cmdb": _planted_source("cmdb", probe), "identity": broken,
    })
    root = tmp_path / "data"
    S.plant(root, table=_TABLE)
    tenant = S.resolve(root)
    roster = read_roster(tree / "scripts" / "adapters")
    ledger = tmp_path / SERVED_FILE
    registry = (world_registry(roster.root, tenant.grants.gather, ledger,
                               **control_oracle({"system": "cmdb", "planted": True})) if replay else
                ModuleVerbRegistry(roster, tenant.grants.gather))
    main = _replies([
        Turn(tool_calls=[("gather", {"lead_id": "l-001", "system": "cmdb",
                                    "goal": "measure both systems",
                                    "what_to_summarize": ["what each system says"]})]),
        Turn(text="Investigation complete."),
    ])
    gather = _replies([
        Turn(tool_calls=[("query", {"system": "identity", "verb": "get-user",
                                     "params": {"user": "dana"}})]),
        Turn(tool_calls=[("query", {"system": "identity", "verb": "get-user",
                                     "params": {"user": "sam"}})]),
        Turn(tool_calls=[("query", {"system": "identity", "verb": "withheld", "params": {}})]),
        Turn(tool_calls=[("query", {"system": "cmdb", "verb": "get-host",
                                     "params": {"host": "web-1"}})]),
        Turn(text="Summary: identity unavailable; cmdb queried."),
    ])
    run_dir = materialize(tmp_path / "replay", GOLDEN_AB3, run_id="cold1256")
    drive(run_dir, run_id="cold1256", main=main, gather=gather, verbs=registry,
          roster=roster, defender_dir=tree, tenant=S.tenant_folder_of(root))

    assert imports.read_text(encoding="utf-8").splitlines() == ["import"]
    for reply in gather.replies[1:3]:
        assert "adapter broken" in reply.lower()
        assert "identity startup failure" in reply
    assert "not granted" in gather.replies[3]
    assert (probe / "cmdb.ran").is_file(), "the healthy admitted call did not resolve and run"
    denials = list(read_jsonl_rows(RunPaths(run_dir).policy_denials))
    assert [(row["system"], row["verb"]) for row in denials] == [("identity", "withheld")]
    rows = list(read_jsonl_rows(run_dir / "executed_queries.jsonl"))
    assert [(row["system"], row["exit_code"]) for row in rows] == [
        ("identity", circuit_breaker.DENIED_EXIT_CODE), ("cmdb", 0)]
    if replay:
        assert [row["source"] for row in served_rows(ledger)] == ["refused", "passthrough"]

"""#1359 one transport; the comment action is never a verb; the committed tenants carry no retired case folder."""
from __future__ import annotations

import ast
from pathlib import Path

from defender.tests.support.shared.contracts._data_root_1078 import current_data_root, ensure_d9_tenant
from defender.tests.tenancy.case_comment_1359 import _spec1359 as C
from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S

DEFENDER = S.DEFENDER
#: The shared transport's own route functions: only the transport and the proxy client call them.
ROUTE_NAMES = {"proxy_exchange", "proxy_call"}
#: Where they may be called: the two kit modules that are the transport.
TRANSPORT_HOMES = {"kit/transport.py", "kit/proxy_client.py"}


def _product_py() -> list[Path]:
    return [p for p in sorted(DEFENDER.rglob("*.py"))
            if "tests" not in p.relative_to(DEFENDER).parts]


def _is_adapter(path: Path) -> bool:
    return path.parent == DEFENDER / "integrations" and path.name.endswith("_adapter.py")


def test_o2_the_committed_tenants_carry_no_case_history_folder():
    """Neither the committed template nor the fixture tenant holds `systems/case-history/`. O2."""
    for half in ("tenant-template", "tenant-fixture"):
        folder = DEFENDER.parent / "knowledge" / half / "settings" / "systems" / C.RETIRED_SYSTEM
        # positive control (#1366 O9: neither half carries `settings/systems/` at all; the half is there)
        assert (folder.parent.parent / "verb-grants.yaml").is_file(), f"{half} has no settings"
        assert not folder.exists(), f"the committed {half} still carries {folder}"


def test_o2_a_tenant_with_no_case_system_is_accepted_and_runs(tmp_path, monkeypatch):
    """No case-record file and no case-history folder: accepted, and a run without --update-ticket completes. O2."""
    ensure_d9_tenant()
    root = current_data_root()
    C.plant_case_tenant(root, case_system=None)
    accepted = S.T1106.accept(root, S.PLAYGROUND_ID)
    assert accepted is not None
    rec = C.CaseRunRecorder(tmp_path / "runs" / "r-none")
    rc, refused = S.drive_run(S.run_argv(C.plant_alert(tmp_path / "in"), root), rec,
                              visualize=rec.visualize)
    assert refused is None, refused
    assert rc == 0, rc
    assert "lifecycle" in rec.order, rec.order


def test_o3_no_second_copy_of_a_transport_route():
    """Only the shared transport and the proxy client reference the route functions. O3."""
    seen: dict[str, set[str]] = {}
    for path in _product_py():
        rel = path.relative_to(DEFENDER)
        tree = ast.parse(path.read_bytes(), filename=str(path))
        names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
        names |= {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        names |= {a.name.rsplit(".", 1)[-1] for n in ast.walk(tree)
                  if isinstance(n, ast.ImportFrom) for a in n.names}
        if names & ROUTE_NAMES:
            seen[str(rel)] = names & ROUTE_NAMES
    assert "kit/transport.py" in seen, f"positive control: {seen}"
    outside = {k: v for k, v in seen.items() if k not in TRANSPORT_HOMES}
    assert outside == {}, outside

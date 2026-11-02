"""#1359 the product names no ticket system; one transport; the comment action is never a verb."""
from __future__ import annotations

import ast
import importlib.util
import re
import subprocess
import sys
from pathlib import Path

from defender.tests.support.shared.contracts._data_root_1078 import current_data_root, ensure_d9_tenant
from defender.tests.tenancy.case_comment_1359 import _spec1359 as C
from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S

DEFENDER = S.DEFENDER
#: The census's product text (PROVISIONAL scope): every `.py` under `defender/` but tests and
#: the per-system adapters, comments and docstrings included.
RETIRED_NAMES = {n: re.compile(re.escape(n)) for n in (C.RETIRED_SYSTEM, C.RETIRED_PREFIX)}
#: The store's path, not a host name (`https://tickets.<tenant>.example` in `api/demo.py`).
RETIRED_NAMES["/tickets"] = re.compile(r"(?<![/\w])/tickets(?![\w.-])")
#: The shared transport's own route functions: only the transport and the proxy client call them.
ROUTE_NAMES = {"docker_exec_curl", "split_status", "proxy_exchange", "proxy_call", "uses_proxy"}
TRANSPORT_HOMES = {"integrations", "_proxy_client.py"}


def _product_py() -> list[Path]:
    return [p for p in sorted(DEFENDER.rglob("*.py"))
            if "tests" not in p.relative_to(DEFENDER).parts]


def _is_adapter(path: Path) -> bool:
    return path.parent == DEFENDER / "integrations" and path.name.endswith("_adapter.py")


def _shippable_surface() -> list[Path]:
    """The lint-shippable surface (r4 Census scope): tracked text files under `defender/` minus the lint's own exclusions."""
    spec = importlib.util.spec_from_file_location(
        "_lint_shippable_surface_1359", DEFENDER.parent / "tooling" / "lint" / "lint_shippable_surface.py")
    assert spec is not None
    sys.path.insert(0, str(DEFENDER.parent / "tooling" / "lint"))
    try:
        lint = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(lint)  # type: ignore[union-attr]
    finally:
        sys.path.remove(str(DEFENDER.parent / "tooling" / "lint"))
    tracked = subprocess.run(["git", "ls-files", "defender"], cwd=DEFENDER.parent, check=True,
                             capture_output=True, text=True).stdout.splitlines()
    prefixes = lint.excluded_prefixes(DEFENDER.parent)
    committed = subprocess.run(
        ["git", "ls-files", "knowledge/tenant-fixture", "knowledge/tenant-template"],
        cwd=DEFENDER.parent, check=True, capture_output=True, text=True).stdout.splitlines()
    # r4 counts the committed tenants in the surface, though they sit beside `defender/`, outside the lint's walk.
    return [DEFENDER.parent / rel for rel in tracked
            if Path(rel).suffix in lint.TEXT_SUFFIXES and not lint._excluded(rel, prefixes)  # noqa: SLF001
            ] + [DEFENDER.parent / rel for rel in committed if Path(rel).suffix in lint.TEXT_SUFFIXES]


def test_o2_the_shippable_surface_names_no_ticket_system_but_one_marked_exemption():
    """No file of the lint-shippable surface names `case-history`, `CASE_HISTORY` or `/tickets`, except one inline-marked line. O2."""
    files = _shippable_surface()
    rels = {p.relative_to(DEFENDER.parent).as_posix() for p in files}
    assert len(files) > 100, f"positive control: the surface was read ({len(files)})"
    assert "defender/integrations/ticket_adapter.py" not in rels, "the adapters are outside the surface"
    assert any(r.startswith("knowledge/tenant-fixture/") for r in rels), "positive control: the fixture is read"
    assert any(r.startswith("knowledge/tenant-template/") for r in rels), "positive control: the template is read"
    assert RETIRED_NAMES["/tickets"].search(
        (DEFENDER / "integrations" / "ticket_adapter.py").read_text(encoding="utf-8")), (
        "positive control: the needle matches")
    unmarked: list[str] = []
    marked: list[str] = []
    for path in files:
        for number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            for name, rx in RETIRED_NAMES.items():
                if rx.search(line):
                    where = f"{path.relative_to(DEFENDER.parent)}:{number}: {name}"
                    (marked if "lint-shippable: ok" in line else unmarked).append(where)
    assert unmarked == [], "\n".join(unmarked)
    assert len(marked) <= 1, f"more than the one exemption (the legacy-folder constant): {marked}"


def test_o2_the_committed_tenants_carry_no_case_history_folder():
    """Neither the committed template nor the fixture tenant holds `systems/case-history/`. O2."""
    for half in ("tenant-template", "tenant-fixture"):
        folder = DEFENDER.parent / "knowledge" / half / "settings" / "systems" / C.RETIRED_SYSTEM
        assert (folder.parent / "ticket").is_dir() or half == "tenant-template", "positive control"
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
    assert any(k.startswith("integrations") for k in seen), f"positive control: {seen}"
    outside = {k: v for k, v in seen.items() if Path(k).parts[0] not in TRANSPORT_HOMES}
    assert outside == {}, outside

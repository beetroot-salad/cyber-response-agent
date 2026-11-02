"""#1359 the product names no ticket system; one transport; the comment action is never a verb."""
from __future__ import annotations

import ast
import re
import textwrap
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


def test_o2_no_product_module_names_a_ticket_system():
    """No product module outside the adapters names `case-history`, `CASE_HISTORY` or `/tickets`. O2."""
    files = [p for p in _product_py() if not _is_adapter(p)]
    assert len(files) > 100, f"positive control: the product tree was read ({len(files)})"
    adapter = DEFENDER / "integrations" / "ticket_adapter.py"
    assert RETIRED_NAMES["/tickets"].search(adapter.read_text(encoding="utf-8")), (
        "positive control: the needle matches")
    hits = sorted(f"{p.relative_to(DEFENDER)}: {n}" for p in files
                  for n, rx in RETIRED_NAMES.items() if rx.search(p.read_text(encoding="utf-8")))
    assert hits == [], "\n".join(hits)
    for half in ("tenant-template", "tenant-fixture"):
        folder = DEFENDER / "knowledge" / half / "settings" / "systems" / C.RETIRED_SYSTEM
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


def _adapter_source(verb_key: str | None) -> str:
    extra = f'    "{verb_key}": {C.PROVISIONAL_COMMENT_ACTION},\n' if verb_key else ""
    return textwrap.dedent(f"""\
        def check_settings(tenant):
            return None


        def health_check(ctx):
            return {{}}


        def {C.PROVISIONAL_COMMENT_ACTION}(ctx, *, key, body):
            return None


        VERBS = {{
            "health-check": health_check,
        """) + extra + "}\n"


def test_o4_the_roster_refuses_an_adapter_whose_verbs_hold_the_comment_action(tmp_path):
    """An adapter whose VERBS holds the comment action is not accepted; the same adapter without it is. O4."""
    read_roster = S.mod("systems.verbs").read_roster
    key = C.PROVISIONAL_COMMENT_ACTION.replace("_", "-")
    good, bad = tmp_path / "good", tmp_path / "bad"
    for where, verb_key in ((good, None), (bad, key)):
        where.mkdir()
        (where / "casesys_adapter.py").write_text(_adapter_source(verb_key), encoding="utf-8")
    assert "casesys" in read_roster(good).accepted, "positive control: the clean adapter is accepted"
    roster = read_roster(bad)
    assert "casesys" not in roster.accepted, (
        f"an adapter whose VERBS holds {key!r} was accepted: {dict(roster.verbs)}")


def test_o4_no_checkout_adapter_declares_the_comment_action(checkout_roster):
    """No adapter in the checkout lists the comment action among its verbs. O4."""
    assert checkout_roster.declared_verbs("ticket"), "positive control: verbs were read"
    key = C.PROVISIONAL_COMMENT_ACTION.replace("_", "-")
    holding = sorted(s for s in checkout_roster.accepted
                     if {key, C.PROVISIONAL_COMMENT_ACTION} & checkout_roster.declared_verbs(s))
    assert holding == [], holding
    module = S.mod("systems.verbs").fresh_adapter_module(checkout_roster, "ticket")
    assert callable(getattr(module, C.PROVISIONAL_COMMENT_ACTION, None)), (
        "the playground ticket adapter exports no comment action")

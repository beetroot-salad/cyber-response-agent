from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from defender.runtime.verbs import read_roster
from defender.tests.support.tenancy import _tenants1106 as T6
from defender.tests.tenancy.alert_front_door_1222._spec1222 import host_paths_in
from defender.tests.e2e import _lead_zero_808 as LZ
from defender.tests.e2e import _replay_harness as RH
from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S7

#: What the escaped call-time fault carries, so its reaching the model is observable.
CALL_MARK = "FD1256-ONE-MAKER-CALL"
#: What the broken adapter's start-time check carries.
START_MARK = "FD1256-ONE-MAKER-START"

_LEAD = ("gather", {"lead_id": "l-001", "system": "cmdb", "goal": "who is web-1",
                    "what_to_summarize": ["web-1's owner"]})


def _get_host(host: str) -> tuple[str, dict]:
    return ("query", {"system": "cmdb", "verb": "get-host", "params": {"host": host}})


def _doubles() -> tuple[RH.ReplayFn, RH.ReplayFn]:
    """MAIN dispatches one cmdb lead; the lead asks cmdb twice (the escape, then a call to a
    system down since), then summarises."""
    main = RH.ReplayFn([RH.Turn(tool_calls=[_LEAD]), RH.Turn(text="Investigation complete.")])
    gather = RH.ReplayFn([RH.Turn(tool_calls=[_get_host("web-1")]),
                          RH.Turn(tool_calls=[_get_host("web-2")]),
                          RH.Turn(text="Summary: asked cmdb who web-1 is.")])
    return main, gather


def _after_escape(main: RH.ReplayFn, gather: RH.ReplayFn) -> str:
    """Everything the models were handed after the escaping call: every later gather request,
    and every MAIN request after its dispatch."""
    return "\n".join([*gather.seen[1:], *main.seen[1:]])


def _roster_adapters(given: Path, resolved: Path) -> dict[str, str]:
    """cmdb, usable at start, whose `get-host` raises a ConfigFault naming its own file in the
    roster (both spellings); elastic, whose check raises a non-ConfigFault naming its own file
    (Down(AdapterBroken) at start, O-5a)."""
    spelled = f"{given}/{{name}} ({resolved}/{{name}})"
    cmdb = f'''\
"""#1256 planted: a cmdb adapter in a roster outside the defender tree."""
from defender.integrations.faults import ConfigFault


def check_settings(*_a, **_k):
    return None


def get_host(ctx, *, host: str) -> dict:
    raise ConfigFault("{CALL_MARK}: cannot read {spelled.format(name="cmdb_adapter.py")} - "
                      "this tenant's settings do not configure this system")


def list_hosts(ctx, *, role=None, criticality=None, owner=None) -> dict:
    return {{"hosts": [], "planted": True}}


def health_check(ctx) -> dict:
    return {{"ok": True, "planted": True}}


VERBS = {{"get-host": get_host, "list-hosts": list_hosts, "health-check": health_check}}
'''
    elastic = f'''\
"""#1256 planted: an elastic adapter in a roster outside the defender tree, broken at start."""


def check_settings(*_a, **_k):
    raise RuntimeError("{START_MARK}: cannot load {spelled.format(name="elastic_adapter.py")}")


def _search(ctx, *, native_query: str, start=None, end=None, limit: int = 20, index=None,
            sort: str = "desc") -> dict:
    return {{"hits": [], "planted": True}}


def esql(ctx, *, query: str) -> dict:
    return {{"values": [], "planted": True}}


def health_check(ctx) -> dict:
    return {{"ok": True, "planted": True}}


VERBS = {{"health-check": health_check, "query": _search, "alerts": _search, "esql": esql}}
'''
    return {"cmdb": cmdb, "elastic": elastic}


def test_an_escaped_fault_naming_an_out_of_tree_roster_reaches_the_model_with_that_path_hidden(
        tmp_path: Path) -> None:
    """r4 "one maker": the run reads its adapters from a roster outside the defender tree, reached through a link. cmdb passes its start check; its `get-host` then raises a ConfigFault whose text names its own file in that roster, as linked and as resolved (O-5b). That reason reaches the gather model (the refusal of a system down since carries it) with neither spelling of the roster — as the start-time reason of elastic, whose check crashes naming its own file in the same roster, reaches MAIN's opening message and gather's index beside elastic with neither. Red at base, which hides only the settings folder."""
    real = tmp_path / "lab-checkout" / "adapters"
    real.mkdir(parents=True)
    link = tmp_path / "lab-roster"
    link.symlink_to(real.parent, target_is_directory=True)
    given, resolved = link / "adapters", real.resolve()
    spellings = sorted({str(given), str(resolved)})
    assert len(spellings) == 2, f"premise: the roster's two spellings coincide: {spellings}"
    for system, source in _roster_adapters(given, resolved).items():
        (real / f"{system}_adapter.py").write_text(source, encoding="utf-8")
    root = tmp_path / "data"
    S7.plant(root, marker="om1256", table=T6.TABLE_A)
    run_dir = LZ.materialize_alert(tmp_path / "replay", LZ.alert_doc(ancestors=[]))
    main, gather = _doubles()

    RH.drive(run_dir, run_id="om1256", main=main, gather=gather, roster=read_roster(given),
             tenant=S7.tenant_folder_of(root))

    after = _after_escape(main, gather)
    assert CALL_MARK in after, (
        f"premise: the escaped fault's reason never reached the gather model (gather was asked "
        f"{len(gather.seen)} times):\n{after[-2000:]}")
    leaked = [s for s in spellings if s in after]
    assert not leaked, (
        f"an escaped call-time fault reached the model naming the adapters roster {leaked} — the "
        f"one maker hides it, as it does a start-time reason (r4, A6)")
    for where, text in (("MAIN's opening message", main.seen[0]),
                        ("gather's system index", gather.seen[0])):
        shown = [ln for ln in text.splitlines() if "elastic" in ln and START_MARK in ln]
        assert shown, (
            f"{where} does not show elastic down with its start-time reason ({START_MARK}) on "
            f"its line (O-5a, flow step 4)")
        leaked = [s for s in spellings if s in text]
        assert not leaked, f"{where} names the adapters roster {leaked} (A6)"


#: What a sibling's folder name adds to the name it shares a prefix with: a word character, a
#: digit, a whole word, and the separators a boundary that stops only at a word character misses.
SIBLING_SUFFIXES = ("-old", ".bak", "_x", "2", "base")


@pytest.mark.parametrize("suffix", SIBLING_SUFFIXES)
def test_hiding_a_path_never_rewrites_part_of_one_that_merely_shares_its_prefix(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, suffix: str) -> None:
    """r4 "one maker", the boundary half: an escaped call-time ConfigFault (O-5b) names three paths that SHARE A PREFIX with a path a reason hides — the data root's sibling `<root><suffix>/…`, the tenant folder's `<tenant><suffix>/…`, the settings folder's `<settings><suffix>/…`, for each suffix shape (`-old`, `.bak`, `_x`, `2`, `base`) — none of them inside the folder whose name it extends. Each reaches the model whole, or hidden whole (with its ancestors, up to a separator), never with the shared prefix rewritten and its rest left dangling (`<data root>base/…`, `the tenant's settings-old/…`). Red at base, whose settings redaction rewrites `<settings><suffix>/…` into `the tenant's settings<suffix>/…` (a #1107 CX5 replace that is not boundary-aware, reached by the escaped fault's reason)."""
    shim = S7.DockerShim(tmp_path / "docker")
    monkeypatch.setenv("PATH", shim.path_value())
    root = tmp_path / "tenants-bnd1256"
    S7.plant(root, marker="bnd1256")
    tenant = S7.tenant_folder_of(root)
    settings = Path(tenant.settings)
    siblings: dict[str, tuple[Path, str]] = {
        "the data root's": (root, f"{suffix}/fd1256-root.conf"),
        "the tenant folder's": (root / S7.PLAYGROUND_ID, f"{suffix}/fd1256-tenant.conf"),
        "the settings folder's": (settings, f"{suffix}/fd1256-settings.txt"),
    }
    paths = [f"{prefix}{tail}" for prefix, tail in siblings.values()]

    def get_host(ctx: Any, *, host: str = "web-1") -> dict:
        raise S7.config_fault()(
            f"{CALL_MARK}: cannot read {', '.join(paths)} - this tenant's settings do not "
            f"configure this system")

    run_dir = LZ.materialize_alert(tmp_path / "replay", LZ.alert_doc(ancestors=[]))
    main, gather = _doubles()
    RH.drive(run_dir, run_id="bnd1256", main=main, gather=gather, tenant=tenant,
             verbs=RH.FakeVerbs({"cmdb": {"get-host": get_host}}))

    after = _after_escape(main, gather)
    assert CALL_MARK in after, (
        f"premise: the escaped fault's reason never reached the gather model:\n{after[-2000:]}")
    for whose, (prefix, tail) in siblings.items():
        bounded = f"/{prefix.name}{tail}"
        assert after.count(tail) == after.count(bounded), (
            f"a path sharing {whose} prefix reached the model partly rewritten — its tail "
            f"{tail!r} no longer follows its own directory name {prefix.name!r} (r4: the one "
            f"maker hides whole paths): "
            f"{[ln for ln in after.splitlines() if tail in ln][:3]}")
    assert shim.calls() == [], shim.calls()


def test_an_escaped_fault_naming_a_data_root_path_reaches_the_model_with_no_host_path(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """r4 "one maker": the escaped call-time fault's reason (O-5b) is made by the function that makes a start-time reason, so it obeys the start-time rule that a reason the model sees carries no host path (#1106; O-5a: "including a path under the data root outside the tenant's own folder"). cmdb's `get-host` raises a ConfigFault naming a file under the data root, in the tenant's folder but neither its settings folder nor adapter code (`<root>/<tenant>/agent/…conf`). The reason reaches the model; neither that file's path nor any line carrying the reason names the data root, the tenant's folder, or their resolved spellings. A reason built by hiding only the settings folder and code paths leaves it whole: red. Red at base, whose escaped reason hides only the settings folder."""
    shim = S7.DockerShim(tmp_path / "docker")
    monkeypatch.setenv("PATH", shim.path_value())
    root = tmp_path / "tenants-host1256"
    S7.plant(root, marker="host1256")
    tenant = S7.tenant_folder_of(root)
    folder = root / S7.PLAYGROUND_ID
    host_only = folder / "agent" / "fd1256-host-only.conf"
    assert Path(tenant.settings) not in (host_only, *host_only.parents), (
        f"premise: {host_only} is under the tenant's settings folder {tenant.settings}")

    def get_host(ctx: Any, *, host: str = "web-1") -> dict:
        raise S7.config_fault()(
            f"{CALL_MARK}: cannot read {host_only} - this tenant's settings do not configure "
            f"this system")

    run_dir = LZ.materialize_alert(tmp_path / "replay", LZ.alert_doc(ancestors=[]))
    main, gather = _doubles()
    RH.drive(run_dir, run_id="host1256", main=main, gather=gather, tenant=tenant,
             verbs=RH.FakeVerbs({"cmdb": {"get-host": get_host}}))

    after = _after_escape(main, gather)
    carrying = [ln for ln in after.splitlines() if CALL_MARK in ln]
    assert carrying, (
        f"premise: the escaped fault's reason never reached the gather model:\n{after[-2000:]}")
    spelled = sorted({str(p) for p in (host_only, host_only.resolve())})
    assert not [s for s in spelled if s in after], (
        f"an escaped call-time fault reached the model naming the host file it read, under the "
        f"data root (r4: the one maker hides it, as at start; #1106): {carrying[:3]}")
    roots = sorted({p for base in (root, folder) for p in (base, base.resolve())}, key=str)
    leaked = sorted({hit for ln in carrying for hit in host_paths_in(ln, *roots)})
    assert not leaked, (
        f"the escaped fault's reason, as the model sees it, names host path(s) {leaked}: "
        f"{carrying[:3]}")
    assert shim.calls() == [], shim.calls()

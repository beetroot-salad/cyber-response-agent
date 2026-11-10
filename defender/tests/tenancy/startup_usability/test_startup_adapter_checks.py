"""Startup checks follow gather permissions and refuse missing adapter references.
"""
from __future__ import annotations

import importlib
import inspect
import logging
import shutil
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from defender._io import read_jsonl_rows
from defender.kit.settings import NOT_CONFIGURED, SystemConfig
from defender.kit.faults import ConfigFault
from defender.tests.support.tenancy import _tenants1106 as T6
from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S
from defender.systems import system_status
from defender.systems.verb_grant import GrantError
from defender.systems.verbs import read_roster


#: The settings check every adapter declares.
CHECK = "check_settings"


@dataclass(frozen=True)
class Family:
    """One way a system's settings can be unusable: what is done to its folder, and what the
    resulting fault must name (any one of `names`, case-sensitive; `{system}` is filled in). Under
    #1366 DC6 a record's fault is located "system <s> settings", never by the file."""

    label: str
    kind: str  # "no-folder" | "stored" | "drop" | "set"
    names: tuple[str, ...]
    mutate: Callable[[Path, str], Any]
    key: str = ""
    value: str = ""


def _remove_folder(folder: Path, system: str) -> None:
    shutil.rmtree(S.config_path(folder, system).parent)


def _remove_file(folder: Path, system: str) -> None:
    S.config_path(folder, system).unlink()


# Retired (#1366 P2/O9): the `config-env-not-utf8` and `config-env-unreadable` families. A settings FILE that is
# not text, or not a plain file, can no longer reach a run (the store refuses non-text settings at write, the files
# are retired); what is left of them is an unusable record: empty settings, the `config-env-absent` family here.
# The store's refusal of bad bytes: tenant_1108_p4/test_system_records_1366.py.
FILE_FAMILIES: tuple[Family, ...] = (
    Family("no-folder", "no-folder", (NOT_CONFIGURED, "system {system} settings"), _remove_folder),
    Family("config-env-absent", "stored", ("system {system} settings",), _remove_file),
)


FAULTS: dict[str, tuple[Family, ...]] = {
    **{system: FILE_FAMILIES for system in (
        "cmdb", "identity", "change-mgmt", "threat-intel", "ticket", "elastic")},
    # host-state reads no `config.env` key, so without the file it is usable (#1391 r5 O-S1).
    "host-state": tuple(f for f in FILE_FAMILIES if f.label != "config-env-absent"),
}


_PARAM_VALUES: dict[str, str] = {
    "host": "web-1", "at": "2026-05-25T15:00:00Z", "path": "/etc/passwd", "user": "root",
    "key": "T1256-1", "cr_id": "CR-1256", "value": "203.0.113.7", "native_query": "*",
    "query": "FROM logs-* | LIMIT 1", "container_id": "c0ffee1256", "actor": "svc-1256",
    "pattern": "nightly-backup",
}


def _cases() -> list[Any]:
    return [pytest.param(system, family, id=f"{system}-{family.label}")
            for system, families in FAULTS.items() for family in families]


def _adapter(roster: Any, system: str) -> Any:
    """`system`'s adapter module, found through the roster (the file it dispatches from) and
    imported as the package module of that file."""
    path = roster.adapter_files.get(system)
    assert path is not None, (
        f"the checkout's roster has no adapter for {system!r} (it has {sorted(roster.adapter_files)}) — "
        "this contract's fault table names a system the tree no longer ships")
    module = importlib.import_module(f"defender.integrations.{path.stem}")
    assert Path(module.__file__).resolve() == Path(path).resolve(), (
        f"precondition: the imported module is the roster's file: {module.__file__} != {path}")
    return module


def _declared_check(module: Any, system: str) -> Callable[..., Any]:
    check = getattr(module, CHECK, None)
    assert callable(check), (
        f"{system}'s adapter declares no `{CHECK}`: got {check!r}")
    return check


def _required_params(fn: Callable[..., Any]) -> dict[str, str]:
    return {p.name: _PARAM_VALUES.get(p.name, "x")
            for p in inspect.signature(fn).parameters.values()
            if p.kind is inspect.Parameter.KEYWORD_ONLY and p.default is inspect.Parameter.empty}


def _every_verb(module: Any, ctx: Any) -> dict[str, BaseException | None]:
    """Call every verb `module.VERBS` declares over `ctx`: verb -> what it raised, or None."""
    outcomes: dict[str, BaseException | None] = {}
    for name, fn in module.VERBS.items():
        try:
            fn(ctx, **_required_params(fn))
        except Exception as exc:  # noqa: BLE001 — the test reads whatever the verb raised
            outcomes[name] = exc
        else:
            outcomes[name] = None
    return outcomes


def _check_outcome(check: Callable[..., Any], record: Any) -> BaseException | None:
    try:
        check(record)
    except Exception as exc:  # noqa: BLE001 — the test reads whatever the check raised
        return exc
    return None


def _plant(tmp_path: Path, marker: str) -> tuple[Path, Path]:
    root = tmp_path / "tenants"
    return root, S.plant(root, marker=marker)


def _ctx(record: Any, tmp_path: Path) -> Any:
    """A context whose calls reach the credential proxy's stand-in (#1391 O1), which answers every
    request with a JSON object (host-state's health-check reads its `hosts`)."""
    run_dir = tmp_path / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    proxy = S.ProxyStandIn(tmp_path / "proxy", [S.answer('{"hosts": []}')])
    return S.verb_context(record, run_dir, {}, proxy_url=proxy.url, request_token="token-1256")


def _landed(record: Any, system: str, family: Family) -> bool:
    """Did `family`'s mutation reach the record the run would carry?"""
    entry = record.systems.get(system)
    if family.kind == "no-folder":
        return system not in record.systems
    if family.kind == "stored":
        return isinstance(entry, ConfigFault)
    if not isinstance(entry, SystemConfig):
        return False
    if family.kind == "drop":
        return family.key not in entry
    return entry.get(family.key) == family.value


#: The ready-made case-comment adapters (#1359 r4): in every checkout roster, with `VERBS = {}`.
NO_AGENT_ACTIONS = {"jira", "servicenow"}


def test_o5_every_roster_adapter_declares_a_settings_check(checkout_roster):
    systems = set(checkout_roster.adapter_files)
    assert len(systems) >= 8, f"precondition: the roster was read: {sorted(systems)}"
    # #1359 r4: the ready-made case adapters have no agent actions, so no verb can raise a ConfigFault
    # to hold their check to: they are judged by the check declaration alone (and by slice C's tests).
    assert checkout_roster.declared_verbs("jira") == frozenset(), "jira offers the agent nothing"
    assert checkout_roster.declared_verbs("servicenow") == frozenset(), "servicenow offers the agent nothing"
    assert systems - NO_AGENT_ACTIONS == set(FAULTS), (
        f"the roster and this contract's fault table disagree — roster only: "
        f"{sorted(systems - set(FAULTS))}, table only: {sorted(set(FAULTS) - systems)} (a new "
        "adapter needs its fault families listed here)")
    undeclared = [s for s in sorted(systems)
                  if not callable(getattr(_adapter(checkout_roster, s), CHECK, None))]
    assert (systems >= NO_AGENT_ACTIONS), f"the checkout roster lacks {sorted(NO_AGENT_ACTIONS - systems)}"
    assert undeclared == [], f"adapters that declare no `{CHECK}`: {undeclared}"


@pytest.mark.parametrize(("system", "family"), _cases())
def test_o5_settings_that_make_a_verb_raise_make_the_check_raise(
        tmp_path, checkout_roster, system, family):
    module = _adapter(checkout_roster, system)
    marker = "o5f"
    root, folder = _plant(tmp_path, marker)
    family.mutate(folder, system)
    record = S.resolve(root)
    assert _landed(record, system, family), (
        f"precondition: the {family.label} mutation reached the record: "
        f"{record.systems.get(system)!r}")

    complete = S.config_texts(marker)[system]
    S.write_config(folder, system, complete)  # the disk is complete again; the record is not

    outcomes = _every_verb(module, _ctx(record, tmp_path))
    raising = {v: str(e) for v, e in outcomes.items() if isinstance(e, ConfigFault)}
    assert raising, (
        f"premise: some {system} verb raises ConfigFault under {family.label}: {outcomes}")
    names = tuple(n.format(system=system) for n in family.names)
    assert any(n in text for text in raising.values() for n in names), (
        f"premise: the verbs' fault names one of {names}: {raising}")

    fault = _check_outcome(_declared_check(module, system), record)
    assert isinstance(fault, ConfigFault), (
        f"{system}'s verbs raise ConfigFault under {family.label} ({sorted(raising)}) but its "
        f"settings check does not: got {fault!r}")
    assert any(n in str(fault) for n in names), (
        f"{system}'s check does not name what is wrong (one of {names}): {fault}")


#: Elastic is complete only with an access declaration, which this config.env-only fixture does
#: not write; its complete-settings control is `credential_proxy_1163/test_query_flow.py` (#1391 O3, D12).
@pytest.mark.parametrize("system", sorted(set(FAULTS) - {"elastic"}))
def test_o5_complete_settings_pass_every_verb_and_the_check(tmp_path, checkout_roster, system):
    module = _adapter(checkout_roster, system)
    root, folder = _plant(tmp_path, "okc")
    record = S.resolve(root)
    shutil.rmtree(S.config_path(folder, system).parent, ignore_errors=True)
    outcomes = _every_verb(module, _ctx(record, tmp_path))
    config = {v: e for v, e in outcomes.items() if isinstance(e, ConfigFault)}
    assert config == {}, f"precondition: the complete fixture is complete for {system}: {config}"
    assert "health-check" in outcomes, f"precondition: {system} declares health-check: {sorted(outcomes)}"
    assert outcomes["health-check"] is None, (
        f"precondition: {system}'s health-check answers over the complete fixture: "
        f"{outcomes['health-check']!r}")

    fault = _check_outcome(_declared_check(module, system), record)
    assert fault is None, (
        f"{system} is usable (no verb raises ConfigFault) but its check raised {fault!r}")


def _no_systems(folder: Path, _system: str) -> None:
    """No system's settings at all: every `config.env` gone, and every system folder holding no
    file the resolver requires removed whole. What resolution requires stays
    (`_tenants1106.REQUIRED_FILES`, none of them under `systems/` since #1359): without them the tenant
    is refused before any check is asked, which is not this arm's subject."""
    settings = S.settings_of(folder)
    required = {settings / rel for rel in T6.REQUIRED_FILES}
    for system_dir in sorted((settings / "systems").iterdir()):
        kept = [p for p in system_dir.rglob("*") if p in required]
        if not kept:
            shutil.rmtree(system_dir)
            continue
        for path in sorted(system_dir.rglob("*"), reverse=True):
            if path not in required and path.is_file():
                path.unlink()


def _every_record_faulted(folder: Path, _system: str) -> None:
    """Every configured system's record unusable (empty settings: what an upgrade leaves, R12), each a stored fault in the
    run's tenant. (#1366 P2/O9 retired the arm that planted a `tacit-knowledge` `config.env` that was not UTF-8: no
    record can exist for a platform-served name, R3, and a bad file cannot reach a run.)"""
    for config in sorted((S.settings_of(folder) / "systems").glob("*/config.env")):
        config.unlink()


def _registry_malformed(folder: Path, _system: str) -> None:
    path = Path(folder) / "agent" / "skills" / "tacit-knowledge" / "registry.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("sanctions:\n  - id: tk-misfiled\n", encoding="utf-8")


@pytest.mark.parametrize(("label", "mutate"), [
    pytest.param("complete", None, id="complete"),
    pytest.param("no-system-configured", _no_systems, id="no-system-configured"),
    pytest.param("every-record-faulted", _every_record_faulted, id="every-record-faulted"),
    pytest.param("registry-malformed", _registry_malformed, id="registry-malformed"),
])
def test_1390_judge_run_never_marks_the_platform_served_registry_down(
        tmp_path, checkout_roster, label, mutate):
    """A run granting `tacit-knowledge` starts with it up whatever the tenant's settings or its registry file hold, with no adapter file to load. A4."""
    from defender.systems import system_status

    root = tmp_path / "tenants"
    folder = S.plant(root, marker="tkn", table=T6.TABLE_A + (
        "  tacit-knowledge:\n    health-check: {roles: [gather]}\n    lookup: {roles: [gather]}\n"))
    if mutate is not None:
        mutate(folder, "tacit-knowledge")
    record = S.resolve(root)
    assert "tacit-knowledge" in record.grants.gather.systems, "premise: the tenant grants the registry"
    assert "tacit-knowledge" not in checkout_roster.adapter_files, "premise: no file serves it"
    if label == "every-record-faulted":
        assert any(isinstance(v, ConfigFault) for v in record.systems.values()), (
            f"premise: the records hold stored faults: {record.systems!r}")

    judged = system_status.judge_run(checkout_roster, record, defender_dir=S.DEFENDER)

    assert "tacit-knowledge" not in judged.down, (
        f"the registry is down at the start ({label}): {judged.down.get('tacit-knowledge')!r}")
    if label in ("no-system-configured", "every-record-faulted"):
        assert judged.down, "positive control: settings that break adapters take them down"


def test_1390_the_platform_verbs_answer_over_records_holding_stored_config_faults(tmp_path, checkout_roster):
    """With the tenant's system records all unusable (stored ConfigFaults), neither `lookup` nor `health-check` of `tacit-knowledge` raises one, and `health-check` answers. A4. (Was: a stored fault for tacit-knowledge itself; no record can exist for a platform-served name, R3, so the premise is retired, #1366 P2/O9.)"""
    from defender.systems.verbs import ModuleVerbRegistry

    root = tmp_path / "tenants"
    folder = S.plant(root, marker="tkn", table=T6.TABLE_A + (
        "  tacit-knowledge:\n    health-check: {roles: [gather]}\n    lookup: {roles: [gather]}\n"))
    _every_record_faulted(folder, "tacit-knowledge")
    record = S.resolve(root)
    assert any(isinstance(v, ConfigFault) for v in record.systems.values()), (
        f"premise: the records hold stored faults: {record.systems!r}")
    verbs = ModuleVerbRegistry(checkout_roster, record.grants.gather).verbs("tacit-knowledge")
    ctx = _ctx(record, tmp_path)

    outcomes: dict[str, Any] = {}
    for name, params in (("lookup", {"actor": "a", "host": "h", "pattern": "p"}), ("health-check", {})):
        try:
            outcomes[name] = verbs[name](ctx, **params)
        except Exception as exc:  # noqa: BLE001 — the test reads whatever the verb raised
            outcomes[name] = exc

    assert not [e for e in outcomes.values() if isinstance(e, ConfigFault)], (
        f"a platform verb raised the stored ConfigFault: {outcomes}")
    assert isinstance(outcomes["health-check"], dict), (
        f"health-check did not answer over the faulted record: {outcomes['health-check']!r}")


#: Not mirrored into the planted tree: nothing a run reads (and the first two are large).
_NOT_MIRRORED = frozenset({".venv", "__pycache__", "tests", "fixtures-e2e"})


_PLANTED: dict[str, dict[str, str]] = {
    "cmdb": {"verb": "get-host", "fn": "get_host", "param": "host", "arg": "web-1",
             "token": ""},
    "identity": {"verb": "get-user", "fn": "get_user", "param": "user", "arg": "dev.dana",
                 "token": "defender_planted_absent_module_1256"},
    # Declares no check: the reason names the missing `check_settings` declaration.
    "threat-intel": {"verb": "lookup", "fn": "lookup", "param": "value", "arg": "203.0.113.7",
                     "token": CHECK},
    # Its check raises something that is not a ConfigFault (a crash).
    "change-mgmt": {"verb": "get-change", "fn": "get_change", "param": "cr_id", "arg": "CR-1256",
                    "token": "planted-check-crash-1256"},
    # Its check raises another adapter fault (not a ConfigFault): still AdapterBroken.
    "host-state": {"verb": "proc-tree", "fn": "proc_tree", "param": "host", "arg": "web-1",
                   "token": "planted-check-transport-1256"},
}


_BROKEN = ("identity", "threat-intel", "change-mgmt", "host-state")


_LOG_CONTROL = "log-channel control for #1256 O-5a (names no system)"


#: What the well-formed planted verb logs at ERROR when it runs: proves a record emitted INSIDE
#: the run reaches the same capture the ERROR-record assertions read. Names no system.
_IN_RUN_LOG_CONTROL = "in-run log-channel control for #1256 O-5a"


_OUTSIDE_TENANT = Path("shared-1256", "credentials")


def _planted_source(system: str, probe: Path, *, outside: Path | None = None,
                    at_import: list[str] | None = None, check: list[str] | None = None) -> str:
    """`system`'s planted adapter (`_PLANTED[system]`'s verb, recording to `probe`), broken the
    way `_PLANTED` says — or, given `at_import` / `check`, with those module lines instead (what
    runs at import, and the declared check)."""
    spec = _PLANTED[system]
    head = [f'"""Planted by #1256\'s contract (O-5a) as the {system} adapter."""',
            "import json", "import logging", "from pathlib import Path"]
    declared = ["def check_settings(*_a, **_k):", "    return None"]
    if at_import is not None or check is not None:
        head += at_import or []
        declared = check if check is not None else declared
    elif system == "identity":
        head.append("import defender_planted_absent_module_1256  # noqa: F401 — the planted fault")
    elif system == "threat-intel":
        declared = []
    elif system == "change-mgmt":
        declared = ["def check_settings(*_a, **_k):",
                    f"    raise RuntimeError({spec['token']!r} + ': cannot read ' + __file__)"]
    elif system == "host-state":
        # Another adapter fault, its text pointing under the data root outside the tenant's own
        # folder (`outside`): a host path no settings-path redaction rewrites.
        head.append("from defender.kit.faults import TransportFault")
        declared = ["def check_settings(*_a, **_k):",
                    f"    raise TransportFault({spec['token']!r} + ': see ' + {str(outside)!r})"]
    body = [
        f"SYSTEM = {system!r}",
        f"_PROBE = Path({str(probe)!r})",
        "",
        *declared,
        "",
        f"def {spec['fn']}(ctx, *, {spec['param']}: str) -> dict:",
        "    with open(_PROBE / (SYSTEM + '.ran'), 'a', encoding='utf-8') as fh:",
        f"        fh.write(json.dumps({{{spec['param']!r}: {spec['param']}}}) + '\\n')",
        f"    logging.getLogger('defender.planted_adapter').error({_IN_RUN_LOG_CONTROL!r})",
        "    return {'system': SYSTEM, 'planted': True}",
        "",
        f"VERBS = {{{spec['verb']!r}: {spec['fn']}}}",
    ]
    return "\n".join([*head, "", *body]) + "\n"


def planted_tree(root: Path, probe: Path, sources: dict[str, str] | None = None, *,
                 outside: Path | None = None) -> Path:
    """A defender tree whose adapters are the planted ones: every top-level entry of this
    checkout symlinked except `integrations/`,
    a real folder holding only the planted files — `sources` (system -> source), else every
    `_PLANTED` system's. `<root>/repo/defender`, as the catalog's repo-relative locators expect.
    (Adapter files must be real: the roster refuses a file that resolves outside the adapters
    directory.)"""
    tree = root / "repo" / "defender"
    tree.mkdir(parents=True)
    for entry in S.DEFENDER.iterdir():
        if entry.name not in _NOT_MIRRORED and entry.name != "integrations":
            (tree / entry.name).symlink_to(entry)
    adapters = tree / "integrations"
    adapters.mkdir()
    if sources is None:
        sources = {system: _planted_source(system, probe, outside=outside) for system in _PLANTED}
    for system, source in sources.items():
        (adapters / f"{system.replace('-', '_')}_adapter.py").write_text(source, encoding="utf-8")
    return tree


def _table(systems: tuple[str, ...]) -> str:
    """A verb-disposition table granting gather each planted system's one verb."""
    return "dispositions:\n" + "".join(
        f"  {system}:\n    {_PLANTED[system]['verb']}: {{roles: [gather]}}\n" for system in systems)


_O5A_TABLE = _table(tuple(_PLANTED))


def _replies(turns: list[Any], on_first: Callable[[], None] | None = None) -> Any:
    """A `ReplayFn` that also keeps, per model request, the text of the request's LAST message —
    the tool results (or retry prompts) answering the previous turn's calls."""
    from defender.tests.e2e._replay_harness import ReplayFn, messages_text

    class _Replies(ReplayFn):
        def __init__(self) -> None:
            super().__init__(turns)
            self.replies: list[str] = []

        def __call__(self, messages, info):
            if on_first is not None and not self.replies:
                on_first()
            self.replies.append(messages_text(list(messages)[-1:]))
            return super().__call__(messages, info)

    return _Replies()


def _token_lines(text: str, token: str) -> list[str]:
    """The lines of `text` that carry `token` (case-insensitive)."""
    return [ln for ln in text.splitlines() if token.lower() in ln.lower()]


#: The broken systems whose reason carries a host path as raised: change-mgmt's crash names the
#: planted adapter's own file, host-state's fault a path under the data root outside the tenant.
_PATH_BEARING = ("change-mgmt", "host-state")


def test_o5a_a_broken_granted_adapter_is_down_from_the_start(tmp_path, checkout_roster, caplog):  # noqa: C901, PLR0912, PLR0915 — one scene, every broken-adapter kind judged on the same channels
    pytest.importorskip("pydantic_ai")
    from defender.tests.e2e._replay_harness import GOLDEN_AB3, Turn, drive, materialize

    assert set(_PLANTED) <= set(checkout_roster.adapter_files), (
        f"precondition: each planted system is a real one (its skill and catalog exist): {sorted(_PLANTED)}")
    probe = tmp_path / "probe"
    probe.mkdir()
    root = tmp_path / "tenants"
    tree = planted_tree(tmp_path / "tree", probe, outside=root / _OUTSIDE_TENANT)
    S.plant(root, marker="o5a", table=_O5A_TABLE)
    run_dir = materialize(tmp_path / "replay", GOLDEN_AB3, run_id="t1256a")

    order = ["cmdb", *_BROKEN]
    at_start: list[logging.LogRecord] = []
    main = _replies([
        *[Turn(tool_calls=[("gather", {
            "lead_id": f"l-00{i + 1}", "system": system, "goal": f"measure {system} for #1256",
            "what_to_summarize": ["what the system says"]})]) for i, system in enumerate(order)],
        Turn(text="Investigation complete."),
    ], on_first=lambda: at_start.extend(caplog.records))
    gather = _replies([
        *[Turn(tool_calls=[("query", {
            "system": system, "verb": _PLANTED[system]["verb"],
            "params": {_PLANTED[system]["param"]: _PLANTED[system]["arg"]}})]) for system in order],
        *[Turn(tool_calls=[("list_verbs", {"system": system})]) for system in _BROKEN],
        Turn(text="Summary: measured the lead."),
    ])
    with caplog.at_level(logging.WARNING):
        # The log channel's own control: a defender logger's ERROR before the run reaches the
        # records MAIN's first turn snapshots. It names no system.
        logging.getLogger("defender.tests.tenancy.startup_usability").error(_LOG_CONTROL)
        summary = drive(run_dir, run_id="t1256a", main=main, gather=gather, defender_dir=tree,
                        tenant=S.tenant_folder_of(root))
    run_state = summary["run_state"]
    rows = list(read_jsonl_rows(run_dir / "executed_queries.jsonl"))

    # Positive control: the well-formed adapter in the same machinery is called and recorded.
    assert (probe / "cmdb.ran").is_file(), (
        f"control: the planted cmdb verb ran (gather replies: {gather.replies[:2]})")
    cmdb_rows = [r for r in rows if r.get("system") == "cmdb"]
    assert [r.get("exit_code") for r in cmdb_rows] == [0], f"control: cmdb's one row: {cmdb_rows}"
    assert main.calls == len(order) + 1, (
        f"control: MAIN played its whole script ({main.calls} turns of {len(order) + 1})")
    assert gather.calls == len(order) + len(_BROKEN) + 1, (
        f"control: the gather lead played its whole script ({gather.calls} turns)")

    assert [r for r in at_start if r.getMessage() == _LOG_CONTROL], (
        "control: an ERROR logged before the run is among the records snapshotted at MAIN's "
        "first turn")
    assert [r for r in caplog.records if r.getMessage() == _IN_RUN_LOG_CONTROL], (
        "control: an ERROR logged inside the run (by the planted cmdb verb) reaches the capture")
    breaker = run_state.breaker_snapshot()
    host_paths = sorted({str(p) for base in (tmp_path / "tree", tree, root)
                         for p in (base, base.resolve())})
    opening, index = main.seen[0], gather.seen[0]
    violations: list[str] = []
    for i, system in enumerate(_BROKEN, start=1):
        token = _PLANTED[system]["token"]
        if (probe / f"{system}.ran").exists():
            violations.append(f"{system}: its broken adapter's verb ran")
        if refused := [r for r in rows if r.get("system") == system]:
            violations.append(f"{system}: a refused call wrote query row(s) {refused}")
        if system in breaker.get("systems", {}):
            violations.append(f"{system}: charged to the breaker {breaker}")
        replies = (("query", gather.replies[i + 1]), ("dispatch", main.replies[i + 1]),
                   ("list_verbs", gather.replies[len(order) + i]))
        for where, text in replies:
            low = text.lower()
            if system not in low or token.lower() not in low:
                violations.append(
                    f"{system}: its {where} reply must name it down and the reason "
                    f"({token!r}): {text[-300:]!r}")
            # One notion of down, the message naming the ACTUAL cause — a broken adapter is
            # neither a breaker trip nor a system whose settings do not configure it.
            for wrong_cause in ("tripped", "not configured"):
                if wrong_cause in low:
                    violations.append(
                        f"{system}: its {where} reply says {wrong_cause!r}, not the adapter "
                        f"fault: {text[-300:]!r}")
            # The reason shown to the agent carries no host path: not the planted tree's, not the
            # data root's (as written or resolved).
            if leaked := [p for p in host_paths if p in text]:
                violations.append(
                    f"{system}: its {where} reply shows host path(s) {leaked}: {text[-300:]!r}")
        if not [r for r in at_start if r.levelno >= logging.ERROR and system in r.getMessage()]:
            violations.append(
                f"{system}: no ERROR-or-above record naming it before the agent's first turn")
        if system not in _PATH_BEARING:
            continue
        # The start surfaces: each shows the reason beside the system (non-vacuity of the sweep
        # below), and no line carrying the reason carries a host path.
        for where, text in (("MAIN's opening message", opening), ("gather's system index", index)):
            carrying = _token_lines(text, token)
            if not [ln for ln in carrying if system in ln]:
                violations.append(
                    f"{system}: {where} has no line naming it with its reason ({token!r})")
            for ln in carrying:
                if leaked := [p for p in host_paths if p in ln]:
                    violations.append(f"{system}: {where} shows host path(s) {leaked}: {ln!r}")
    if breaker.get("total_failures", 0) != 0:
        violations.append(f"failures were charged to the run-wide breaker: {breaker}")
    assert violations == [], "a broken granted adapter is not down from the start:\n  " + (
        "\n  ".join(violations) + "\n  records at the first turn: "
        + repr([(r.levelname, r.getMessage()[:160]) for r in at_start]))


# --- O-5a at both seams (import, check), whatever the adapter raises (#678) ---------------------

_ANY_BREAK: tuple[tuple[str, str, list[str], list[str] | None, str], ...] = (
    ("import", "NameError", ["planted_undefined_name_1256  # noqa: F821"], None,
     "planted_undefined_name_1256"),
    ("import", "ValueError", ["raise ValueError('planted-import-value-1256')"], None,
     "planted-import-value-1256"),
    ("import", "AttributeError", ["json.planted_missing_attribute_1256"], None,
     "planted_missing_attribute_1256"),
    ("import", "own-Exception-subclass",
     ["class PlantedFault1256(Exception):", "    pass",
      "raise PlantedFault1256('planted-import-own-1256')"], None, "planted-import-own-1256"),
    ("check", "ValueError", [],
     ["def check_settings(*_a, **_k):", "    raise ValueError('planted-check-value-1256')"],
     "planted-check-value-1256"),
    ("check", "KeyError", [],
     ["def check_settings(*_a, **_k):", "    raise KeyError('planted-check-key-1256')"],
     "planted-check-key-1256"),
    ("check", "TypeError-wrong-signature", [],
     ["def check_settings():", "    return None"], CHECK),
    ("check", "own-Exception-subclass",
     ["class PlantedFault1256(Exception):", "    pass"],
     ["def check_settings(*_a, **_k):", "    raise PlantedFault1256('planted-check-own-1256')"],
     "planted-check-own-1256"),
    ("check", "not-callable", [], ["check_settings = 'planted-not-callable-1256'"], CHECK),
)


@pytest.mark.parametrize(("seam", "label", "at_import", "check", "token"),
                         [pytest.param(*case, id=f"{case[0]}-{case[1]}") for case in _ANY_BREAK])
def test_o5a_any_exception_at_import_or_from_the_check_is_adapter_broken(
        tmp_path, checkout_roster, caplog, seam, label, at_import, check, token):
    pytest.importorskip("pydantic_ai")
    from defender.tests.e2e._replay_harness import GOLDEN_AB3, Turn, drive, materialize

    probe = tmp_path / "probe"
    probe.mkdir()
    tree = planted_tree(tmp_path / "tree", probe, {
        "cmdb": _planted_source("cmdb", probe),
        "identity": _planted_source("identity", probe, at_import=at_import, check=check)})
    root = tmp_path / "tenants"
    S.plant(root, marker="o5x", table=_table(("cmdb", "identity")))
    run_dir = materialize(tmp_path / "replay", GOLDEN_AB3, run_id="t1256x")
    at_start: list[logging.LogRecord] = []
    main = _replies([
        *[Turn(tool_calls=[("gather", {
            "lead_id": f"l-00{i + 1}", "system": system, "goal": f"measure {system} for #1256",
            "what_to_summarize": ["what the system says"]})])
          for i, system in enumerate(("cmdb", "identity"))],
        Turn(text="Investigation complete."),
    ], on_first=lambda: at_start.extend(caplog.records))
    gather = _replies([
        *[Turn(tool_calls=[("query", {
            "system": system, "verb": _PLANTED[system]["verb"],
            "params": {_PLANTED[system]["param"]: _PLANTED[system]["arg"]}})])
          for system in ("cmdb", "identity")],
        Turn(text="Summary: measured the lead."),
    ])
    with caplog.at_level(logging.WARNING):
        try:
            summary = drive(run_dir, run_id="t1256x", main=main, gather=gather,
                            defender_dir=tree, tenant=S.tenant_folder_of(root))
        except Exception as raised:  # noqa: BLE001 — the run must not raise; shown whole
            pytest.fail(f"{seam} {label}: the run raised instead of taking identity down: "
                        f"{type(raised).__name__}: {raised}")
    rows = list(read_jsonl_rows(run_dir / "executed_queries.jsonl"))
    breaker = summary["run_state"].breaker_snapshot()

    assert (probe / "cmdb.ran").is_file(), "control: the well-formed cmdb verb ran"
    assert main.calls == 3, f"control: MAIN played its whole script ({main.calls} of 3)"
    assert not (probe / "identity.ran").exists(), (
        f"{seam} {label}: the broken identity adapter's verb ran")
    identity_rows = [r for r in rows if r.get("system") == "identity"]
    assert identity_rows == [], (
        f"{seam} {label}: a refused identity call wrote a row: {identity_rows}")
    assert breaker.get("total_failures", 0) == 0, (
        f"{seam} {label}: the broken adapter was charged to the run: {breaker}")
    assert "identity" not in breaker.get("systems", {}), (
        f"{seam} {label}: the broken adapter was charged: {breaker}")
    for where, text in (("query", gather.replies[2]), ("dispatch", main.replies[2])):
        low = text.lower()
        assert "identity" in low, (
            f"{seam} {label}: identity's {where} reply must refuse naming it: {text[-300:]!r}")
        assert token.lower() in low, (
            f"{seam} {label}: identity's {where} reply must name the reason ({token!r}): "
            f"{text[-300:]!r}")
        for wrong_cause in ("tripped", "not configured"):
            assert wrong_cause not in low, (
                f"{seam} {label}: identity's {where} refusal says {wrong_cause!r}: "
                f"{text[-300:]!r}")
    assert [r for r in at_start if r.levelno >= logging.ERROR and "identity" in r.getMessage()], (
        f"{seam} {label}: no ERROR-or-above record naming identity before the agent's first "
        f"turn: {[(r.levelname, r.getMessage()[:160]) for r in at_start]}")


MARKER = "o5k"


#: Values every key is tried with: blank and whitespace-only (`kit.settings.is_blank`).
_EVERY_KEY: tuple[tuple[str, str], ...] = (("blank", ""), ("whitespace", "   "))


_GRAMMAR: dict[str, tuple[tuple[str, str], ...]] = {
    "_TIMEOUT_SEC": (("non-numeric", "abc"), ("negative", "-5"), ("fractional", "1.5"),
                     ("zero", "0"), ("ten-digits", "1234567890"), ("padded", " 10"),
                     ("non-ascii-digits", "١٠")),
}


#: Adapters with settings faults but no config.env key: host-state's settings are its access
#: declaration alone (#1391 O5), whose faults `test_1256_adapter_checks` covers.
READS_NO_KEY = frozenset({"host-state"})


def _keys(text: str) -> list[str]:
    """The keys a planted `config.env` text sets, in file order."""
    return [line.split("=", 1)[0].strip() for line in text.splitlines()
            if "=" in line and not line.lstrip().startswith("#")]


def _dropping(key: str) -> Callable[[Path, str], Any]:
    return lambda folder, system: S.drop_key(folder, system, key)


def _setting(key: str, value: str) -> Callable[[Path, str], Any]:
    return lambda folder, system: S.set_key(folder, system, key, value)


def _mutations(key: str) -> list[Family]:
    families = [Family(f"{key}-absent", "drop", (key,), _dropping(key), key=key)]
    grammar = [g for suffix, values in _GRAMMAR.items() if key.endswith(suffix) for g in values]
    for label, value in (*_EVERY_KEY, *grammar):
        families.append(Family(f"{key}-{label}", "set", (key,), _setting(key, value),
                               key=key, value=value))
    return families


def _key_cases() -> list[Any]:
    texts = S.config_texts(MARKER)
    return [pytest.param(system, family, id=f"{system}-{family.label}")
            for system in sorted(FAULTS) if FAULTS[system]
            for key in _keys(texts.get(system, ""))
            for family in _mutations(key)]


def test_o5_the_key_census_covers_every_settings_reading_adapter() -> None:
    texts = S.config_texts(MARKER)
    readers = sorted(s for s, families in FAULTS.items() if families and s not in READS_NO_KEY)
    assert readers, "precondition: FAULTS names settings-reading adapters"
    empty = [s for s in readers if not _keys(texts.get(s, ""))]
    assert empty == [], f"settings-reading adapters with no planted key to mutate: {empty}"
    every_key = [k for s in readers for k in _keys(texts[s])]
    unused = [suffix for suffix in _GRAMMAR if not any(k.endswith(suffix) for k in every_key)]
    assert unused == [], f"grammars no planted key carries (the census skips them): {unused}"


@pytest.mark.parametrize(("system", "family"), _key_cases())
def test_o5_the_check_raises_exactly_where_a_verb_raises(
        tmp_path, checkout_roster, system, family):
    module = _adapter(checkout_roster, system)
    root, folder = _plant(tmp_path, MARKER)
    family.mutate(folder, system)
    record = S.resolve(root)
    assert _landed(record, system, family), (
        f"precondition: the {family.label} mutation reached the record: "
        f"{record.systems.get(system)!r}")
    # The disk is complete again; the record is not (the check reads the record).
    S.write_config(folder, system, S.config_texts(MARKER)[system])

    outcomes = _every_verb(module, _ctx(record, tmp_path))
    raising = {v: str(e) for v, e in outcomes.items() if isinstance(e, ConfigFault)}
    if raising:
        assert any(family.key in text for text in raising.values()), (
            f"premise: the verbs' fault names {family.key}: {raising}")
        fault = _check_outcome(_declared_check(module, system), record)
        assert isinstance(fault, ConfigFault), (
            f"{system}'s verbs {sorted(raising)} raise ConfigFault under {family.label} but its "
            f"settings check does not: got {fault!r}")
        assert family.key in str(fault), (
            f"{system}'s check does not name what is wrong ({family.key}): {fault}")
        return

    assert "health-check" in outcomes, f"premise: {system} declares health-check: {sorted(outcomes)}"
    assert outcomes["health-check"] is None, (
        f"premise: under {family.label} no {system} verb raises ConfigFault and its health-check "
        f"answers — got {outcomes['health-check']!r}")
    fault = _check_outcome(_declared_check(module, system), record)
    assert fault is None, (
        f"under {family.label} every {system} verb answers without a ConfigFault, but its "
        f"check raised {fault!r}")


_TABLE = """\
dispositions:
  cmdb:
    get-host: {roles: [gather]}
    health-check: {roles: [gather]}
"""


def _roster(tmp_path: Path):
    adapters = tmp_path / "adapters"
    adapters.mkdir()
    probe = tmp_path / "checks"
    for system in ("cmdb", "identity"):
        (adapters / f"{system}_adapter.py").write_text(
            f"def check_settings(tenant):\n"
            f"    with open({str(probe)!r}, 'a') as out:\n"
            f"        out.write({system!r} + '\\n')\n"
            "def get_host(ctx, *, host: str):\n    return {}\n"
            "VERBS = {'get-host': get_host}\n", encoding="utf-8")
    return read_roster(adapters), probe


def test_a_missing_granted_system_refuses_before_checks_or_run_creation(tmp_path, data_root):
    table = _TABLE + "  absent-system:\n    lookup: {roles: [gather]}\n    health-check: {roles: [gather]}\n"
    S.plant(data_root, table=table)
    tenant = S.resolve(data_root)
    roster, probe = _roster(tmp_path)
    with pytest.raises(GrantError) as invalid:
        system_status.judge_run(roster, tenant, defender_dir=S.DEFENDER)
    assert "absent-system" in str(invalid.value)
    assert tenant.table_pointer in str(invalid.value)
    assert not probe.exists(), "an adapter check ran before the invalid grant was refused"

    rec = S.RunRecorder(tmp_path / "run")
    alert = S.plant_alert(tmp_path / "alert.json")
    rc, refused = S.drive_run(S.run_argv(alert, data_root), rec, roster=roster)
    assert rc is None
    assert isinstance(refused, SystemExit)
    assert refused.code != 0
    assert "absent-system" in str(refused)
    assert tenant.table_pointer in str(refused)
    assert rec.order == [], "startup reached preflight, run creation or lifecycle"
    assert not rec.run_dir_at.exists()
    assert not probe.exists()


def test_an_ungranted_adapter_is_not_checked(tmp_path, data_root):
    S.plant(data_root, table=_TABLE)
    roster, probe = _roster(tmp_path)
    systems = system_status.judge_run(roster, S.resolve(data_root), defender_dir=S.DEFENDER)
    assert probe.read_text(encoding="utf-8").splitlines() == ["cmdb"]
    assert not systems.down

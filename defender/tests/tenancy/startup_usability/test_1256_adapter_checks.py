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

#: The declaration K1 names.
CHECK = "check_settings"


@dataclass(frozen=True)
class Family:
    """One way a system's settings can be unusable: what is done to its folder, and what the
    resulting fault must name (any one of `names`, case-sensitive — they are key names or the
    file's own name)."""

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


def _not_utf8(folder: Path, system: str) -> None:
    S.write_config(folder, system, b"\xff\xfe not text \x80\n")


def _directory_at_file(folder: Path, system: str) -> None:
    # "Unreadable" through a real primitive that holds as root (a mode bit would not): a
    # directory where the file is (`read_regular_bytes` refuses anything not a plain file).
    path = S.config_path(folder, system)
    path.unlink()
    path.mkdir()


FILE_FAMILIES: tuple[Family, ...] = (
    Family("no-folder", "no-folder", ("config.env", NOT_CONFIGURED), _remove_folder),
    Family("config-env-absent", "stored", ("config.env",), _remove_file),
    Family("config-env-not-utf8", "stored", ("UTF-8",), _not_utf8),
    Family("config-env-unreadable", "stored", ("config.env",), _directory_at_file),
)


FAULTS: dict[str, tuple[Family, ...]] = {
    **{system: FILE_FAMILIES for system in (
        "cmdb", "identity", "change-mgmt", "threat-intel", "ticket", "elastic", "host-state")},
    "tacit-knowledge": (),
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
    path = roster.accepted.get(system)
    assert path is not None, (
        f"the checkout's roster has no adapter for {system!r} (it has {sorted(roster.accepted)}) — "
        "this contract's fault table names a system the tree no longer ships")
    module = importlib.import_module(f"defender.integrations.{path.stem}")
    assert Path(module.__file__).resolve() == Path(path).resolve(), (
        f"precondition: the imported module is the roster's file: {module.__file__} != {path}")
    return module


def _declared_check(module: Any, system: str) -> Callable[..., Any]:
    check = getattr(module, CHECK, None)
    assert callable(check), (
        f"{system}'s adapter declares no `{CHECK}` (K1, O-5: every adapter declares its settings "
        f"check, a system needing none declares one that never raises) — got {check!r}")
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


def _ctx(record: Any, tmp_path: Path, shim: S.DockerShim) -> Any:
    run_dir = tmp_path / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    return S.verb_context(record, run_dir, shim.env())


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


def test_o5_every_roster_adapter_declares_a_settings_check(checkout_roster):
    systems = set(checkout_roster.accepted)
    assert len(systems) >= 8, f"precondition: the roster was read: {sorted(systems)}"
    assert systems == set(FAULTS), (
        f"the roster and this contract's fault table disagree — roster only: "
        f"{sorted(systems - set(FAULTS))}, table only: {sorted(set(FAULTS) - systems)}. A new "
        "adapter needs its fault families listed here (O-5: its check must raise each).")
    undeclared = [s for s in sorted(systems)
                  if not callable(getattr(_adapter(checkout_roster, s), CHECK, None))]
    assert undeclared == [], f"adapters that declare no `{CHECK}` (K1, O-5): {undeclared}"


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
    path = S.config_path(folder, system)
    if path.is_dir():
        path.rmdir()
    S.write_config(folder, system, complete)  # the disk is complete again; the record is not

    shim = S.DockerShim(tmp_path / "shim")
    outcomes = _every_verb(module, _ctx(record, tmp_path, shim))
    raising = {v: str(e) for v, e in outcomes.items() if isinstance(e, ConfigFault)}
    assert raising, (
        f"premise: some {system} verb raises ConfigFault under {family.label}: {outcomes}")
    assert any(n in text for text in raising.values() for n in family.names), (
        f"premise: the verbs' fault names one of {family.names}: {raising}")

    fault = _check_outcome(_declared_check(module, system), record)
    assert isinstance(fault, ConfigFault), (
        f"O-5: {system}'s verbs raise ConfigFault under {family.label} ({sorted(raising)}), so its "
        f"settings check must raise ConfigFault over the same record — got {fault!r}")
    assert any(n in str(fault) for n in family.names), (
        f"K1: {system}'s check must name what is wrong (one of {family.names}): {fault}")


@pytest.mark.parametrize("system", sorted(FAULTS))
def test_o5_complete_settings_pass_every_verb_and_the_check(tmp_path, checkout_roster, system):
    module = _adapter(checkout_roster, system)
    root, folder = _plant(tmp_path, "okc")
    record = S.resolve(root)
    shutil.rmtree(S.config_path(folder, system).parent, ignore_errors=True)
    shim = S.DockerShim(tmp_path / "shim")
    outcomes = _every_verb(module, _ctx(record, tmp_path, shim))
    config = {v: e for v, e in outcomes.items() if isinstance(e, ConfigFault)}
    assert config == {}, f"precondition: the complete fixture is complete for {system}: {config}"
    assert "health-check" in outcomes, f"precondition: {system} declares health-check: {sorted(outcomes)}"
    assert outcomes["health-check"] is None, (
        f"precondition: {system}'s health-check answers over the complete fixture: "
        f"{outcomes['health-check']!r}")

    fault = _check_outcome(_declared_check(module, system), record)
    assert fault is None, (
        f"K1/O-1: {system} is usable (no verb raises ConfigFault), so its check must return "
        f"without raising — got {fault!r}")


def test_o5_elastic_without_a_kibana_container_stays_usable(tmp_path, checkout_roster):
    module = _adapter(checkout_roster, "elastic")
    root, folder = _plant(tmp_path, "kbn")
    S.drop_key(folder, "elastic", "ELASTIC_KIBANA_CONTAINER")
    record = S.resolve(root)
    entry = record.systems.get("elastic")
    assert isinstance(entry, SystemConfig), f"precondition: elastic is configured: {entry!r}"
    assert "ELASTIC_KIBANA_CONTAINER" not in entry, f"precondition: elastic is configured: {entry!r}"
    shim = S.DockerShim(tmp_path / "shim")
    ctx = _ctx(record, tmp_path, shim)
    outcomes = _every_verb(module, ctx)
    assert outcomes == dict.fromkeys(outcomes), (
        f"precondition: every elastic verb answers with no Kibana container: {outcomes}")
    health = module.VERBS["health-check"](ctx)
    assert "not configured" in str(health.get("kibana", "")), (
        f"precondition: health-check reports Kibana as a result: {health}")

    fault = _check_outcome(_declared_check(module, "elastic"), record)
    assert fault is None, (
        f"elastic answers every verb without a Kibana container, so its check must not raise: "
        f"{fault!r}")


def _no_systems(folder: Path, _system: str) -> None:
    """No system's settings at all: every `config.env` gone, and every system folder holding no
    file the resolver requires removed whole. What resolution requires stays
    (`_tenants1106.REQUIRED_FILES`, `systems/case-history/mapping.yaml`): without it the tenant
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


def _own_folder_broken(folder: Path, system: str) -> None:
    S.write_config(folder, system, b"\xff\xfe not text \x80\n")


def test_o5_tacit_knowledge_needs_no_settings_and_its_check_never_raises(tmp_path, checkout_roster):
    module = _adapter(checkout_roster, "tacit-knowledge")
    check = _declared_check(module, "tacit-knowledge")
    for label, mutate in (("complete", None), ("no-system-configured", _no_systems),
                          ("own-folder-not-utf8", _own_folder_broken)):
        where = tmp_path / label
        root, folder = _plant(where, "tkn")
        if mutate is not None:
            mutate(folder, "tacit-knowledge")
        record = S.resolve(root)
        if label == "no-system-configured":
            configured = sorted(s for s, e in record.systems.items() if isinstance(e, SystemConfig))
            assert configured == [], (
                f"precondition: the record configures no system at all: {configured}")
        if label == "own-folder-not-utf8":
            assert isinstance(record.systems.get("tacit-knowledge"), ConfigFault), (
                f"precondition: the record holds tacit-knowledge's stored fault: "
                f"{record.systems.get('tacit-knowledge')!r}")
        shim = S.DockerShim(where / "shim")
        outcomes = _every_verb(module, _ctx(record, where, shim))
        assert not [e for e in outcomes.values() if isinstance(e, ConfigFault)], (
            f"premise ({label}): no tacit-knowledge verb raises ConfigFault: {outcomes}")
        assert outcomes.get("health-check") is None, (
            f"premise ({label}): tacit-knowledge's health-check answers: {outcomes}")
        fault = _check_outcome(check, record)
        assert fault is None, f"tacit-knowledge's check must never raise ({label}): {fault!r}"


#: Not mirrored into the planted tree: nothing a run reads (and the first two are large).
_NOT_MIRRORED = frozenset({".venv", "__pycache__", "tests", "fixtures-e2e"})

_PLANTED: dict[str, dict[str, str]] = {
    "cmdb": {"verb": "get-host", "fn": "get_host", "param": "host", "arg": "web-1",
             "token": ""},
    "identity": {"verb": "get-user", "fn": "get_user", "param": "user", "arg": "dev.dana",
                 "token": "defender_planted_absent_module_1256"},
    # Declares no check: the reason names the missing declaration, K1's `check_settings`.
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
#: the run reaches the same capture the K3 assertion reads. Names no system.
_IN_RUN_LOG_CONTROL = "in-run log-channel control for #1256 O-5a"


_OUTSIDE_TENANT = Path("shared-1256", "credentials")


def _planted_source(system: str, probe: Path, *, outside: Path | None = None,
                    at_import: list[str] | None = None, check: list[str] | None = None) -> str:
    """`system`'s planted adapter (`_PLANTED[system]`'s verb, recording to `probe`), broken the
    way `_PLANTED` says — or, given `at_import` / `check`, with those module lines instead (the
    seams O-5a names: what runs at import, and the declared check)."""
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
    """A defender tree whose adapters are the planted ones (K2): every top-level entry of this
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

    assert set(_PLANTED) <= set(checkout_roster.accepted), (
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
            violations.append(f"{system}: its broken adapter's verb ran (O-5a: no call to it runs)")
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
                    f"({token!r}) (O-5a, DP4): {text[-300:]!r}")
            # DP4: one notion of down, the message naming the ACTUAL cause — a broken adapter is
            # neither a breaker trip nor a system whose settings do not configure it.
            for wrong_cause in ("tripped", "not configured"):
                if wrong_cause in low:
                    violations.append(
                        f"{system}: its {where} reply says {wrong_cause!r}, not the adapter "
                        f"fault (DP4): {text[-300:]!r}")
            # The reason shown to the agent carries no host path: not the planted tree's, not the
            # data root's (as written or resolved).
            if leaked := [p for p in host_paths if p in text]:
                violations.append(
                    f"{system}: its {where} reply shows host path(s) {leaked}: {text[-300:]!r}")
        if not [r for r in at_start if r.levelno >= logging.ERROR and system in r.getMessage()]:
            violations.append(
                f"{system}: no ERROR-or-above record naming it before the agent's first turn "
                f"(O-5a, K3)")
        if system not in _PATH_BEARING:
            continue
        # The start surfaces: each shows the reason beside the system (non-vacuity of the sweep
        # below), and no line carrying the reason carries a host path.
        for where, text in (("MAIN's opening message", opening), ("gather's system index", index)):
            carrying = _token_lines(text, token)
            if not [ln for ln in carrying if system in ln]:
                violations.append(
                    f"{system}: {where} has no line naming it with its reason ({token!r}) "
                    f"(flow step 4: the statuses feed it)")
            for ln in carrying:
                if leaked := [p for p in host_paths if p in ln]:
                    violations.append(f"{system}: {where} shows host path(s) {leaked}: {ln!r}")
    if breaker.get("total_failures", 0) != 0:
        violations.append(f"failures were charged to the run-wide breaker: {breaker}")
    assert violations == [], "O-5a — a broken granted adapter is down from the start:\n  " + (
        "\n  ".join(violations) + "\n  records at the first turn: "
        + repr([(r.levelname, r.getMessage()[:160]) for r in at_start]))


# --- O-5a at both seams, whatever the adapter raises (#678: a catch-all discharged at one seam) --

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
            pytest.fail(f"{seam} {label}: the run raised instead of taking identity down "
                        f"(O-5a): {type(raised).__name__}: {raised}")
    rows = list(read_jsonl_rows(run_dir / "executed_queries.jsonl"))
    breaker = summary["run_state"].breaker_snapshot()

    assert (probe / "cmdb.ran").is_file(), "control: the well-formed cmdb verb ran"
    assert main.calls == 3, f"control: MAIN played its whole script ({main.calls} of 3)"
    assert not (probe / "identity.ran").exists(), (
        f"{seam} {label}: the broken identity adapter's verb ran (O-5a)")
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
                f"{seam} {label}: identity's {where} refusal says {wrong_cause!r} (DP4): "
                f"{text[-300:]!r}")
    assert [r for r in at_start if r.levelno >= logging.ERROR and "identity" in r.getMessage()], (
        f"{seam} {label}: no ERROR-or-above record naming identity before the agent's first "
        f"turn (O-5a, K3): {[(r.levelname, r.getMessage()[:160]) for r in at_start]}")

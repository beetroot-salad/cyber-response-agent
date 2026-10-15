"""#1256 slice A — every adapter declares its settings check (O-5), and a granted adapter that is
broken is down from the start (O-5a).

Design: issue #1256, revision r2. The binding contract choices are the orchestrator's K1-K4:

  * K1 — each adapter module declares `check_settings(tenant)`, a pure function of the run's
    tenant record (`RunTenant`) that returns None when the system is usable and raises
    `ConfigFault` naming what is wrong otherwise; tacit-knowledge declares one that never raises.
  * K2 — the run takes the check from the adapter modules of the roster it reads (the files under
    `<defender_dir>/scripts/adapters`), for the systems its grants name.
  * K3 — an adapter that is broken (O-5a) is logged at ERROR or above, naming its system.
  * K4 — observe what the agent is shown, whether a verb ran, the breaker, the query rows and the
    logs; pin no status type, state field or module.

O-5 is driven per adapter over the CHECKOUT'S roster (`read_roster`, the `checkout_roster`
fixture), so a new adapter without a check, or one this contract's fault table has no row for,
fails the census rather than going unexamined. Each fault family is a real planted tenant folder
(`_spec1107.plant`) resolved by the real resolver; the premise — a REAL verb of that adapter
raises `ConfigFault` over that record — is proven in the same test before the check is asked, so
the table can never claim a fault the adapter does not raise. The only fake is the docker CLI
(`_spec1107.DockerShim`, first on the PATH of the env a transport forks with).

O-5a is driven through the replay harness (`drive`) over a planted defender tree whose
`scripts/adapters` holds planted adapter files (K2), granted by the planted tenant's table. No
verb registry is injected, so the run builds the production `ModuleVerbRegistry` over the planted
roster and the planted module's own verb is what would run: each planted verb appends to a probe
file, which is the "never called" observation. A well-formed planted adapter in the same run is
the positive control (it IS called, writes its row, is the usable system that keeps the run from
O-8's refusal).

Red before #1256 is implemented, by construction: no adapter declares `check_settings`, and no
startup check exists — a broken adapter's call runs (or fails to import) at call time, writes an
exit-2 row and is charged to the breaker.
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
from defender.runtime.tenant_settings import NOT_CONFIGURED, SystemConfig
from defender.scripts.adapters.faults import ConfigFault
from defender.tests import _tenants1106 as T6
from defender.tests.tenant_1107_settings import _spec1107 as S

#: The declaration K1 names.
CHECK = "check_settings"


# =============================================================================================
# O-5 — the fault table: one row per adapter, one entry per distinct ConfigFault family any of
# its verbs can raise (code map item 2, grounded at d7b1886d). A family is (a mutation of a
# COMPLETE planted tenant folder, the token(s) the fault must name). The premise half of every
# case proves the family is real for that adapter: no entry here is taken on trust.
# =============================================================================================

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


def _drop(key: str) -> Family:
    return Family(f"{key}-missing", "drop", (key,),
                  lambda folder, system: S.drop_key(folder, system, key), key=key)


def _set(key: str, value: str, label: str) -> Family:
    return Family(f"{key}-{label}", "set", (key,),
                  lambda folder, system: S.set_key(folder, system, key, value), key=key, value=value)


#: The file families every settings-reading adapter shares: no folder (the system is not
#: configured at all — `system_entry`), and a folder whose `config.env` is a stored fault the
#: record keeps (`tenant_settings.read_systems`): absent, not UTF-8, unreadable.
FILE_FAMILIES: tuple[Family, ...] = (
    Family("no-folder", "no-folder", ("config.env", NOT_CONFIGURED), _remove_folder),
    Family("config-env-absent", "stored", ("config.env",), _remove_file),
    Family("config-env-not-utf8", "stored", ("UTF-8",), _not_utf8),
    Family("config-env-unreadable", "stored", ("config.env",), _directory_at_file),
)


def access_families(prefix: str) -> tuple[Family, ...]:
    """`_stub_transport.access_context`'s faults: the access method missing or not `docker-exec`,
    the docker context missing or blank. Reached through the docker transport, never through
    `load_config`."""
    return (
        _drop(f"{prefix}_TRANSPORT"),
        _set(f"{prefix}_TRANSPORT", "http", "not-docker-exec"),
        _drop(f"{prefix}_DOCKER_CONTEXT"),
        _set(f"{prefix}_DOCKER_CONTEXT", "", "blank"),
    )


def template_families(prefix: str) -> tuple[Family, ...]:
    """`_stub_transport.load_config`'s faults over the three-key template: each key missing, one
    blank, and a TIMEOUT that is not a whole number of seconds above zero."""
    return (
        _drop(f"{prefix}_URL_BASE"),
        _drop(f"{prefix}_BASTION_HOST"),
        _drop(f"{prefix}_TIMEOUT_SEC"),
        _set(f"{prefix}_URL_BASE", "", "blank"),
        _set(f"{prefix}_TIMEOUT_SEC", "0", "not-above-zero"),
    )


def _stub(prefix: str, *extra: Family) -> tuple[Family, ...]:
    return (*FILE_FAMILIES, *template_families(prefix), *extra, *access_families(prefix))


#: Every adapter of the checkout's roster -> its fault families. tacit-knowledge reads no
#: settings, so it has none (its check is driven by its own test below). A roster adapter with no
#: row here fails `test_o5_every_roster_adapter_declares_a_settings_check`.
FAULTS: dict[str, tuple[Family, ...]] = {
    "cmdb": _stub("CMDB"),
    "identity": _stub("IDENTITY"),
    "change-mgmt": _stub("CHANGE_MGMT"),
    "threat-intel": _stub("THREAT_INTEL"),
    # ticket: the template plus its key grammar (`ticket_adapter.REQUIRED_CONFIG_KEYS`).
    "ticket": _stub("TICKET", _drop("TICKET_KEY_PATTERN")),
    # elastic: `elastic_adapter.load_config` (system_entry + access_context + its four keys), then
    # the ES container read on EVERY request (`_es_container`) — the key `load_config` never
    # checks, r1's demonstrated defect (C4).
    "elastic": (
        *FILE_FAMILIES,
        _drop("ELASTICSEARCH_URL"), _drop("KIBANA_URL"),
        _drop("ELASTIC_EVENTS_INDEX"), _drop("ELASTIC_ALERTS_INDEX"),
        *access_families("ELASTIC"),
        _drop("ELASTIC_ES_CONTAINER"),
        _set("ELASTIC_ES_CONTAINER", "", "blank"),
    ),
    # host-state: `access_context` only (no keys of its own).
    "host-state": (*FILE_FAMILIES, *access_families("HOST_STATE")),
    "tacit-knowledge": (),
}

#: A value per verb parameter NAME, so every verb of every adapter can be called with its
#: required keyword parameters (none of these is a fault the verb would raise before reaching its
#: settings: hosts are in host-state's inventory, `at` is UTC ISO 8601, the path is absolute).
#: An unknown name gets "x".
_PARAM_VALUES: dict[str, str] = {
    "host": "web-1", "at": "2026-05-25T15:00:00Z", "path": "/etc/passwd", "user": "root",
    "key": "T1256-1", "cr_id": "CR-1256", "value": "203.0.113.7", "native_query": "*",
    "query": "FROM logs-* | LIMIT 1", "container_id": "c0ffee1256", "actor": "svc-1256",
    "pattern": "nightly-backup",
}


def _cases() -> list[Any]:
    return [pytest.param(system, family, id=f"{system}-{family.label}")
            for system, families in FAULTS.items() for family in families]


# =============================================================================================
# O-5 helpers
# =============================================================================================

def _adapter(roster: Any, system: str) -> Any:
    """`system`'s adapter module, found through the roster (the file it dispatches from) and
    imported as the package module of that file."""
    path = roster.accepted.get(system)
    assert path is not None, (
        f"the checkout's roster has no adapter for {system!r} (it has {sorted(roster.accepted)}) — "
        "this contract's fault table names a system the tree no longer ships")
    module = importlib.import_module(f"defender.scripts.adapters.{path.stem}")
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


# =============================================================================================
# O-5 — the census
# =============================================================================================

def test_o5_every_roster_adapter_declares_a_settings_check(checkout_roster):
    """O-5 / K1: every adapter of the checkout's roster declares `check_settings`, and every one
    has a row in this contract's fault table — a ninth adapter, or one renamed, fails here rather
    than being skipped by the per-family cases below."""
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
    """O-5: for each adapter and each distinct ConfigFault family its verbs can raise, the
    settings that make a verb raise make `check_settings(record)` raise `ConfigFault`, naming
    what is wrong.

    Premise first, in the same test: the family's mutation landed on the record, and a REAL verb
    of this adapter (every verb is called; at least one must raise) raises `ConfigFault` over it.

    The check is a function of the RECORD (K1, DP1: the frozen settings, never re-read): before
    it is asked, the file on disk is put back complete. The verbs still fault (they read the
    record), so a check that re-reads `config.env` — and so finds it complete — is caught."""
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


# =============================================================================================
# O-5 — positive controls: the check is not one that always raises
# =============================================================================================

@pytest.mark.parametrize("system", sorted(FAULTS))
def test_o5_complete_settings_pass_every_verb_and_the_check(tmp_path, checkout_roster, system):
    """The positive control for every case above: over a COMPLETE planted tenant, no verb of the
    adapter raises ConfigFault and its health-check answers through the (shimmed) transport —
    the settings are usable — and `check_settings(record)` returns without raising. A check that
    always raises, or that judges a key no verb needs, fails here.

    The system's folder is removed from disk after resolve: the record still holds it, so a
    check that re-reads the disk (and finds nothing) is caught here too."""
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
    """The Kibana container is optional to elastic (#1107 MF-7c, standing): only health-check reads
    it, and it asks first and answers with a result, never a ConfigFault (#1256 non-obligation
    "no verb-level granularity"). So no verb raises with it unset, and the system is usable:
    `check_settings` returns without raising (K1: None when usable). A check that demanded the
    Kibana container would take an Elasticsearch-only tenant's elastic down at start."""
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
    """O-5: "a system needing none declares that". tacit-knowledge reads no settings (its
    registry is the defender tree's file), so no settings make its verbs raise ConfigFault — and
    its check never raises: not over a complete tenant, not over a tenant that configures no
    system at all, and not over one whose `systems/tacit-knowledge/config.env` is itself a stored
    fault (a generic per-folder check would raise there)."""
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


# =============================================================================================
# O-5a — a broken granted adapter is down from the start
# =============================================================================================

#: Not mirrored into the planted tree: nothing a run reads (and the first two are large).
_NOT_MIRRORED = frozenset({".venv", "__pycache__", "tests", "fixtures-e2e"})

#: Each planted adapter: system -> (what is wrong with it, its verb, the verb's one parameter,
#: the value gather binds, the token the agent's refusal and the reason must carry). Real system
#: names, so each has its shipped skill and catalog; the files are NOT the shipped adapters.
#: `cmdb` is the well-formed control.
_PLANTED: dict[str, dict[str, str]] = {
    "cmdb": {"verb": "get-host", "fn": "get_host", "param": "host", "arg": "web-1",
             "token": ""},
    # Fails to import — at RUN time (a missing module), with a source the roster's cold read
    # still parses: a file whose `VERBS` literal cannot be read would be refused at run start as
    # a grant naming an undeclared verb (C11), which is not this obligation.
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


def _planted_source(system: str, probe: Path) -> str:
    spec = _PLANTED[system]
    head = [f'"""Planted by #1256\'s contract (O-5a) as the {system} adapter."""',
            "import json", "import logging", "from pathlib import Path"]
    check = ["def check_settings(*_a, **_k):", "    return None"]
    if system == "identity":
        head.append("import defender_planted_absent_module_1256  # noqa: F401 — the planted fault")
    elif system == "threat-intel":
        check = []
    elif system == "change-mgmt":
        # The crash's own text carries the adapter's absolute host path (as an exception's often
        # does), so the "no host path in what the agent is shown" negative can fail on a reason
        # passed through verbatim.
        check = ["def check_settings(*_a, **_k):",
                 f"    raise RuntimeError({spec['token']!r} + ': cannot read ' + __file__)"]
    elif system == "host-state":
        head.append("from defender.scripts.adapters.faults import TransportFault")
        check = ["def check_settings(*_a, **_k):",
                 f"    raise TransportFault({spec['token']!r})"]
    body = [
        f"SYSTEM = {system!r}",
        f"_PROBE = Path({str(probe)!r})",
        "",
        *check,
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


def planted_tree(root: Path, probe: Path) -> Path:
    """A defender tree whose adapters are the planted ones (K2): every top-level entry of this
    checkout symlinked except `scripts/`, which is a real folder of symlinks except `adapters/`,
    a real folder holding only `_PLANTED`'s files. `<root>/repo/defender`, as the catalog's
    repo-relative locators expect. (Adapter files must be real: the roster refuses a file that
    resolves outside the adapters directory.)"""
    tree = root / "repo" / "defender"
    tree.mkdir(parents=True)
    for entry in S.DEFENDER.iterdir():
        if entry.name not in _NOT_MIRRORED and entry.name != "scripts":
            (tree / entry.name).symlink_to(entry)
    scripts = tree / "scripts"
    scripts.mkdir()
    for entry in (S.DEFENDER / "scripts").iterdir():
        if entry.name not in _NOT_MIRRORED and entry.name != "adapters":
            (scripts / entry.name).symlink_to(entry)
    adapters = scripts / "adapters"
    adapters.mkdir()
    for system in _PLANTED:
        (adapters / f"{system.replace('-', '_')}_adapter.py").write_text(
            _planted_source(system, probe), encoding="utf-8")
    return tree


_O5A_TABLE = "dispositions:\n" + "".join(
    f"  {system}:\n    {spec['verb']}: {{roles: [gather]}}\n" for system, spec in _PLANTED.items())


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


def test_o5a_a_broken_granted_adapter_is_down_from_the_start(tmp_path, checkout_roster, caplog):  # noqa: C901 — one scene, every broken-adapter kind judged on the same channels
    """O-5a: a granted adapter that fails to import, declares no check, or whose check raises
    anything but ConfigFault (a crash, or another adapter fault) is Down(AdapterBroken(reason))
    from the start: logged at ERROR or above naming its system before the agent's first turn
    (K3), every dispatch and every call to it refused with a message that names it and the reason
    — not a breaker trip and not "not configured" (DP4), and no host path of the planted tree or
    the data root — its verb never run, no query row written, nothing charged to the breaker.

    Positive control in the same run: the well-formed planted `cmdb` adapter IS called — its verb
    writes the probe file and its row — so the "never called" and "no row" observations can fail;
    it is also the usable system that keeps the run from being refused (O-8)."""
    pytest.importorskip("pydantic_ai")
    from defender.tests.e2e._replay_harness import GOLDEN_AB3, Turn, drive, materialize

    assert set(_PLANTED) <= set(checkout_roster.accepted), (
        f"precondition: each planted system is a real one (its skill and catalog exist): {sorted(_PLANTED)}")
    probe = tmp_path / "probe"
    probe.mkdir()
    tree = planted_tree(tmp_path / "tree", probe)
    root = tmp_path / "tenants"
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
        Turn(text="Summary: measured the lead."),
    ])
    with caplog.at_level(logging.WARNING):
        # The log channel's own control: a defender logger's ERROR before the run reaches the
        # records MAIN's first turn snapshots. It names no system.
        logging.getLogger("defender.tests.startup_usability_1256").error(_LOG_CONTROL)
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

    assert [r for r in at_start if r.getMessage() == _LOG_CONTROL], (
        "control: an ERROR logged before the run is among the records snapshotted at MAIN's "
        "first turn")
    assert [r for r in caplog.records if r.getMessage() == _IN_RUN_LOG_CONTROL], (
        "control: an ERROR logged inside the run (by the planted cmdb verb) reaches the capture")
    # Every broken system's observations are collected, then judged together, so one run reports
    # each one that does not hold. The replies are indexed by the script: MAIN's request i+1
    # answers its dispatch of `_BROKEN[i-1]`; gather's request i+1 (lead l-001) answers its query.
    breaker = run_state.breaker_snapshot()
    host_paths = sorted({str(p) for base in (tmp_path / "tree", tree, root)
                         for p in (base, base.resolve())})
    violations: list[str] = []
    for i, system in enumerate(_BROKEN, start=1):
        token = _PLANTED[system]["token"]
        if (probe / f"{system}.ran").exists():
            violations.append(f"{system}: its broken adapter's verb ran (O-5a: no call to it runs)")
        if refused := [r for r in rows if r.get("system") == system]:
            violations.append(f"{system}: a refused call wrote query row(s) {refused}")
        if system in breaker.get("systems", {}):
            violations.append(f"{system}: charged to the breaker {breaker}")
        for where, text in (("query", gather.replies[i + 1]), ("dispatch", main.replies[i + 1])):
            low = text.lower()
            if system not in low or token.lower() not in low:
                violations.append(
                    f"{system}: its {where} reply must refuse naming it and the reason "
                    f"({token!r}) (O-5a, DP4): {text[-300:]!r}")
            # DP4: one notion of down, the message naming the ACTUAL cause — a broken adapter is
            # neither a breaker trip nor a system whose settings do not configure it.
            for wrong_cause in ("tripped", "not configured"):
                if wrong_cause in low:
                    violations.append(
                        f"{system}: its {where} refusal says {wrong_cause!r}, not the adapter "
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
    if breaker.get("total_failures", 0) != 0:
        violations.append(f"failures were charged to the run-wide breaker: {breaker}")
    assert violations == [], "O-5a — a broken granted adapter is down from the start:\n  " + (
        "\n  ".join(violations) + "\n  records at the first turn: "
        + repr([(r.levelname, r.getMessage()[:160]) for r in at_start]))

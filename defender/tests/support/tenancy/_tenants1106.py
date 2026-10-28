"""#1106 — the per-tenant knowledge folder: shared fixtures for the spec and the migrated suites."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import fixture_data_root

from defender.tests.support.shared._fixture_uuid import fixture_uuid

import dataclasses
import importlib
import json
from pathlib import Path
from typing import Any

#: The repo root and the checkout's defender tree, spelled from this file's own location.
REPO_ROOT = Path(__file__).resolve().parents[4]
DEFENDER = REPO_ROOT / "defender"

#: The committed template, spelled as a literal.
TEMPLATE_DIR = REPO_ROOT / "knowledge" / "tenant-template"
#: The retired lab's id: tests still name a tenant `playground` under their own data root.
PLAYGROUND_ID = fixture_uuid("tenant:playground")
TEMPLATE_SETTINGS = TEMPLATE_DIR / "settings"
#: The frozen test fixture tenant (#1120 H2): what a test runs as when it names no tenant.
FIXTURE = REPO_ROOT / "knowledge" / "tenant-fixture"
FIXTURE_SETTINGS = FIXTURE / "settings"
FIXTURE_AGENT = FIXTURE / "agent"
TEMPLATE_AGENT = TEMPLATE_DIR / "agent"

#: The three files run start requires, relative to a tenant's `settings/`. A system's
#: `config.env` is deliberately not here: some adapters need none, and a missing one fails only
#: that system's settings check, so the system is down, not the run (#1256).
REQUIRED_FILES: tuple[str, ...] = (
    "verb-grants.yaml",
    "lead-zero.yaml",
    "systems/case-history/mapping.yaml",
)

#: The lead-zero template the fixture tenant names (it binds `elastic.alerts`). The catalog is
#: the tenant's own (`agent/skills/gather/queries/`), never the checkout's, so the run-start
#: agreement check (#1003) passes only when the fixture's `agent/` carries this template.
SHIPPED_CORRELATION_TEMPLATE = "elastic.correlate-alerts-by-entity"


def mod(dotted: str) -> Any:
    """Import `defender.<dotted>` at CALL time, never at collection time."""
    return importlib.import_module(f"defender.{dotted}")


def run_grants(settings_dir: Path) -> Any:
    """The per-run grants projected from `settings_dir`'s table (M4)."""
    return mod("systems.verb_dispositions").run_grants(Path(settings_dir))


def fixture_tenant(tenant_id: str | None = None) -> Any:
    """The committed fixture tenant set up under the current test's data root and accepted
    through the real `accept_tenant`: what every replay that names no tenant runs as.
    Idempotent within one test."""
    from defender.tests.support.shared.contracts import _data_root_1078

    return _data_root_1078.set_up_tenant(
        _data_root_1078.current_data_root(),
        tenant_id if tenant_id is not None else _data_root_1078.D9_TENANT_ID)


def fixture_grants() -> Any:
    """The committed fixture tenant's grants (what older suites call "the shipped grant")."""
    return run_grants(FIXTURE_SETTINGS)


def fixture_gather_def() -> Any:
    """`GATHER_DEF` carrying the fixture tenant's gather grant. The definition itself carries
    none and `compile_policy` refuses a verb-bearing tool bit over an empty grant, so a suite
    binds gather with a run's grant, as the driver does."""
    gather_def = mod("investigation.driver").GATHER_DEF
    return dataclasses.replace(gather_def, verb_grant=fixture_grants().gather)


def accept(root: Path, tenant_id: str, **kw: Any) -> Any:
    """`tenant_id` under `root`, through the real `accept_tenant` against this checkout's
    `defender/`."""
    return mod("tenancy._tenant").accept_tenant(fixture_data_root(root), tenant_id, defender_dir=DEFENDER, **kw)


def run_tenant(tenant: Any, *, defender_dir: Path | None = None,
               dispatches_lead_zero: bool = False, agent_root: Path | None = None,
               settings_root: Path | None = None) -> Any:
    """The driver's `RunTenant` for an accepted `tenant`, built from the real pieces only: run
    start's `resolve_run_tenant` (same grants and refusals; the lead-zero template is checked
    against the agent root's catalog only when `dispatches_lead_zero`), then `resolved_settings`.
    A scenario that wants other grants plants a tenant whose `verb-grants.yaml` says so.

    `agent_root`/`settings_root` default to the tenant's own `agent/`/`settings/`; the replay
    harness hands one export's halves. `defender_dir` is ignored (kept for callers' call shape):
    the catalog never comes from the checkout."""
    del defender_dir
    rt = mod("systems.run_tenant")
    root = Path(agent_root) if agent_root is not None else Path(tenant.agent)
    settings = Path(settings_root) if settings_root is not None else Path(tenant.settings)
    ready = rt.resolve_run_tenant(
        settings, agent_root=root, dispatches_lead_zero=dispatches_lead_zero)
    return rt.RunTenant(tenant=tenant, grants=ready.grants, correlation=ready.correlation,
                        agent_root=root, settings_root=settings,
                        **rt.resolved_settings(tenant, settings_root=settings))


def fixture_run_tenant(**kw: Any) -> Any:
    """The fixture tenant, set up under this test's data root, as the driver takes it."""
    return run_tenant(fixture_tenant(), **kw)


def verb_context(defender_dir: Path, run_dir: Path, env: Any, *,
                 tenant: Any = None, settings_dir: Path | None = None, **kw: Any) -> Any:
    """A `VerbContext` carrying the run's tenant record. `tenant` is a `RunTenant`; omitted, it
    is the fixture tenant's record, or that of the accepted tenant whose `settings/` is
    `settings_dir` (`<root>/<id>/knowledge/settings`)."""
    if tenant is None:
        if settings_dir is None or Path(settings_dir) == FIXTURE_SETTINGS:
            tenant = fixture_run_tenant()
        else:
            knowledge = Path(settings_dir).parent
            tenant = run_tenant(accept(knowledge.parent.parent, knowledge.parent.name))
    return mod("systems.verbs").VerbContext(
        defender_dir=Path(defender_dir), run_dir=Path(run_dir), env=env, tenant=tenant, **kw)


# ---------------------------------------------------------------------------------------------
# Fixture tenants — written from the data below, never copied from a committed tenant.
# ---------------------------------------------------------------------------------------------

#: Tenant A's table: gather reaches cmdb and elastic; the correlation lead holds elastic.alerts
#: (so the lead-zero agreement check has a pair to agree on); identity is withheld.
TABLE_A = """\
dispositions:
  cmdb:
    get-host: {roles: [gather]}
    health-check: {roles: [gather]}
    list-hosts: {roles: [gather]}
  elastic:
    alerts: {roles: [gather, lead-zero-correlation]}
    health-check: {roles: [gather, lead-zero-correlation]}
    query: {roles: [gather]}
  identity:
    get-user: {roles: [], reason: "tenant A withholds identity in this fixture on purpose"}
    health-check: {roles: [], reason: "tenant A withholds identity in this fixture on purpose"}
"""

#: The pairs TABLE_A grants gather / the correlation lead — the independent oracle.
GATHER_PAIRS_A: frozenset[tuple[str, str]] = frozenset({
    ("cmdb", "get-host"), ("cmdb", "health-check"), ("cmdb", "list-hosts"),
    ("elastic", "alerts"), ("elastic", "health-check"), ("elastic", "query"),
})
CORRELATION_PAIRS_A: frozenset[tuple[str, str]] = frozenset({
    ("elastic", "alerts"), ("elastic", "health-check"),
})

#: Tenant B's table: gather reaches identity and threat-intel; cmdb is withheld; the
#: correlation lead is withheld (no row names it), which is legal and skips the lead.
TABLE_B = """\
dispositions:
  cmdb:
    get-host: {roles: [], reason: "tenant B withholds cmdb in this fixture on purpose"}
    health-check: {roles: [], reason: "tenant B withholds cmdb in this fixture on purpose"}
  identity:
    get-user: {roles: [gather]}
    health-check: {roles: [gather]}
    list-users: {roles: [gather]}
  threat-intel:
    health-check: {roles: [gather]}
    lookup: {roles: [gather]}
"""

GATHER_PAIRS_B: frozenset[tuple[str, str]] = frozenset({
    ("identity", "get-user"), ("identity", "health-check"), ("identity", "list-users"),
    ("threat-intel", "health-check"), ("threat-intel", "lookup"),
})

#: A grant-nothing table in the template's shape: every row `roles: []` with a reason. It
#: loads clean; it is gather's empty grant that must refuse the run at start.
TABLE_BLANK = """\
dispositions:
  cmdb:
    get-host: {roles: [], reason: "copied from the template; no operator has granted it yet"}
    health-check: {roles: [], reason: "copied from the template; no operator has granted it yet"}
  elastic:
    alerts: {roles: [], reason: "copied from the template; no operator has granted it yet"}
    health-check: {roles: [], reason: "copied from the template; no operator has granted it yet"}
"""


def lead_zero_text(template_id: str = SHIPPED_CORRELATION_TEMPLATE) -> str:
    return f"correlation_template: {template_id}\n"


#: The tenant's alert mapping (#1222): the file every planted tenant carries beside its case-history mapping.
ALERT_MAPPING_TEXT = "signature: rule.id\nevent_time: timestamp\nsummary: rule.description\n"


def mapping_text(reporter: str = "defender", open_status: str = "open") -> str:
    """A complete case-history mapping whose `open.reporter` is the one value a reader test
    watches flow out. `open_status` is written quoted as given, so a template (`"{summary}"`)
    makes the one mapping the loader refuses (#1221). It keeps the legacy `released:` section an
    un-migrated tenant repo carries, so every planted tenant exercises the loader's tolerance."""
    return f"""\
open:
  key: "{{case_id}}"
  summary: "{{summary}}"
  description: "Auto-created from alert {{case_id}} (rule {{signature}})."
  status: "{open_status}"
  reporter: {reporter}
  labels:
    - "sig:{{signature}}"
    - "evt:{{event_time}}"
comment:
  author: defender
  body: "{{disposition}} — {{cause}}\\n\\n{{narrative}}"
released:
  status: closed
"""


#: The one implemented access method (#1107 D2).
DOCKER_EXEC = "docker-exec"

#: Each system folder's key prefix, as the adapters spell it.
PREFIX: dict[str, str] = {
    "cmdb": "CMDB",
    "identity": "IDENTITY",
    "ticket": "TICKET",
    "case-history": "CASE_HISTORY",
    "change-mgmt": "CHANGE_MGMT",
    "threat-intel": "THREAT_INTEL",
    "elastic": "ELASTIC",
    "host-state": "HOST_STATE",
}


def context_name(marker: str, system: str) -> str:
    """The docker context a fixture tenant names for `system`: distinct per system and per
    tenant, and never `soc-playground` (the base's built-in default)."""
    return f"ctx-{marker}-{system}"


def es_container(marker: str) -> str:
    return f"es-{marker}"


def kibana_container(marker: str) -> str:
    return f"kibana-{marker}"


def access_lines(marker: str, system: str) -> str:
    """`system`'s access method and docker context lines (and elastic's two containers):
    without them its settings check fails and the system starts down (#1256)."""
    prefix = PREFIX[system]
    text = (f'{prefix}_TRANSPORT="{DOCKER_EXEC}"\n'
            f'{prefix}_DOCKER_CONTEXT="{context_name(marker, system)}"\n')
    if system == "elastic":
        text += (f'ELASTIC_ES_CONTAINER="{es_container(marker)}"\n'
                 f'ELASTIC_KIBANA_CONTAINER="{kibana_container(marker)}"\n')
    return text


def config_texts(marker: str, *, events_index: str | None = None,
                 alerts_index: str | None = None) -> dict[str, str]:
    """One complete `config.env` per system, every value carrying `marker` so a reader that
    returns another tenant's (or the checkout's) value is caught by the value alone. Complete
    means every key the adapter's settings check reads: a system failing it is down from run
    start, and a run whose every granted system is down is refused (#1256)."""
    events = events_index if events_index is not None else f"{marker}-events-*"
    alerts = alerts_index if alerts_index is not None else f"{marker}-alerts-*"
    base = {
        "cmdb": (
            f'CMDB_URL_BASE="http://cmdb-{marker}:8080"\n'
            f'CMDB_BASTION_HOST="bastion-{marker}"\n'
            'CMDB_TIMEOUT_SEC="10"\n'
        ),
        "identity": (
            f'IDENTITY_URL_BASE="http://identity-{marker}:8080"\n'
            f'IDENTITY_BASTION_HOST="bastion-{marker}"\n'
            'IDENTITY_TIMEOUT_SEC="10"\n'
        ),
        "ticket": (
            f'TICKET_URL_BASE="http://ticket-{marker}:8080"\n'
            f'TICKET_BASTION_HOST="bastion-{marker}"\n'
            'TICKET_TIMEOUT_SEC="10"\n'
            f'TICKET_KEY_PATTERN="{marker.upper()}-[0-9]+"\n'
        ),
        "case-history": (
            f'CASE_HISTORY_URL_BASE="http://case-history-{marker}:8080"\n'
            f'CASE_HISTORY_BASTION_HOST="bastion-{marker}"\n'
            'CASE_HISTORY_TIMEOUT_SEC="10"\n'
        ),
        "elastic": (
            f'ELASTICSEARCH_URL="https://es-{marker}:9200"\n'
            f'KIBANA_URL="http://kibana-{marker}:5601"\n'
            f'ELASTIC_EVENTS_INDEX="{events}"\n'
            f'ELASTIC_ALERTS_INDEX="{alerts}"\n'
            'ELASTIC_SSL_VERIFY="true"\n'
        ),
        "change-mgmt": (
            f'CHANGE_MGMT_URL_BASE="http://change-mgmt-{marker}:8080"\n'
            f'CHANGE_MGMT_BASTION_HOST="bastion-{marker}"\n'
            'CHANGE_MGMT_TIMEOUT_SEC="10"\n'
        ),
        "threat-intel": (
            f'THREAT_INTEL_URL_BASE="http://threat-intel-{marker}:8080"\n'
            f'THREAT_INTEL_BASTION_HOST="bastion-{marker}"\n'
            'THREAT_INTEL_TIMEOUT_SEC="10"\n'
        ),
        "host-state": "",
    }
    return {system: text + access_lines(marker, system) for system, text in base.items()}


#: Made-up templates a planted tenant's lead-zero config names, written into the tenant's own
#: catalog (`agent/skills/gather/queries/<system>/<name>.md`): run start resolves
#: `lead-zero.yaml` against the run copy's catalog, never the checkout's. Front matter follows
#: the template schema; bodies are made up (no copy of lab content).
TENANT_CATALOG: dict[str, str] = {
    "elastic/correlate-alerts-by-entity.md": """\
---
id: elastic.correlate-alerts-by-entity
status: established
verb: alerts
params: [end, start]
body_substitutions: [entity_filter]
---

## Goal

Fixture template (#1222 suite, #1108 P4): alerts naming one entity over a window, counted
across every rule (correlate alerts, same host, prior alert).

## Query

```
${entity_filter}
```
""",
    "cmdb/list-all-hosts.md": """\
---
id: cmdb.list-all-hosts
status: established
verb: list-hosts
params: []
---

## Goal

Fixture template (#1222 suite, #1108 P4): the whole host inventory, to find the registered
name of a host a lookup did not recognise.

## Query

```query
verb: list-hosts
```
""",
}


def plant_tenant(  # noqa: PLR0913 — one tenant folder's whole content, each part overridable
    root: Path, tenant_id: str, *,
    table: str = TABLE_A,
    lead_zero: str | None = None,
    reporter: str = "defender",
    open_status: str = "open",
    marker: str | None = None,
    configs: dict[str, str] | None = None,
    omit: tuple[str, ...] = (),
    agent_files: dict[str, str] | None = None,
    catalog: bool = True,
) -> Path:
    """Write a plain knowledge folder `root/<tenant_id>/{settings,agent}/` and return it: the
    committed template's shape (no `.tenant-id`, no row). `omit` names settings-relative files
    not to write (e.g. one of `REQUIRED_FILES`), for refusal tests. `agent/` always holds one
    marker file, so a mount of it is observably this tenant's."""
    tenant = Path(root) / tenant_id
    settings = tenant / "settings"
    agent = tenant / "agent"
    files: dict[str, str] = {
        "verb-grants.yaml": table,
        "lead-zero.yaml": lead_zero if lead_zero is not None else lead_zero_text(),
        "systems/case-history/mapping.yaml": mapping_text(reporter, open_status),
        "alert-mapping.yaml": ALERT_MAPPING_TEXT,
    }
    system_configs = configs if configs is not None else config_texts(marker or tenant_id)
    for system, text in system_configs.items():
        files[f"systems/{system}/config.env"] = text
    for rel, text in files.items():
        if rel in omit:
            continue
        path = settings / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    settings.mkdir(parents=True, exist_ok=True)
    agent.mkdir(parents=True, exist_ok=True)
    for name, text in (agent_files if agent_files is not None
                       else {"AGENT.md": f"agent half of {tenant_id}\n"}).items():
        (agent / name).write_text(text, encoding="utf-8")
    # Run start resolves `lead-zero.yaml` against the tenant's own catalog, and system skills
    # are tenant knowledge, so a planted tenant carries the templates its tables name and a
    # made-up `SKILL.md` per configured system. `catalog=False` plants neither (the "names a
    # template its catalog lacks" shape).
    if catalog:
        for rel, text in TENANT_CATALOG.items():
            template = agent / "skills" / "gather" / "queries" / rel
            template.parent.mkdir(parents=True, exist_ok=True)
            template.write_text(text, encoding="utf-8")
        for system in system_configs:
            skill = agent / "skills" / system / "SKILL.md"
            skill.parent.mkdir(parents=True, exist_ok=True)
            skill.write_text(system_skill_text(system), encoding="utf-8")
    return tenant


def system_skill_text(system: str) -> str:
    """A made-up system skill descriptor for `system` (front matter `name` + `description`)."""
    return (f"---\nname: defender-{system}\ndescription: Fixture {system} system of record for "
            f"a planted test tenant (#1108 P4).\n---\n\nFixture content; no real "
            f"environment.\n")


def place_tenant(root: Path, tenant_id: str, **kw: Any) -> Path:
    """A set-up tenant under `root`: `plant_tenant`'s folder as `root/<tenant_id>/knowledge/`,
    `agent/.tenant-id` naming it, and its row written by hand (so one root can hold several
    tenants: `create_tenant`'s one-tenant guard is setup's, not acceptance's). Returns the
    knowledge folder; `accept(root, tenant_id)` accepts it."""
    folder = Path(root) / tenant_id
    defaults = {"marker": tenant_id, "agent_files": {"AGENT.md": f"agent half of {tenant_id}\n"}}
    knowledge = plant_tenant(folder, "knowledge", **{**defaults, **kw})
    (knowledge / "agent" / ".tenant-id").write_text(f"{tenant_id}\n", encoding="utf-8")
    (folder / "tenant.json").write_text(json.dumps(
        {"tenant_id": tenant_id, "created_at": "2026-09-28T00:00:00+00:00"},
        indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return knowledge


#: The lead-zero id a planted census repo's folders name, and the template carrying it: the CI
#: census checks that each folder's `lead-zero.yaml` names a template its own catalog holds.
CENSUS_LEAD_ZERO_ID = "alpha.by-entity"
CENSUS_QUERY_TEMPLATE = """\
---
id: alpha.by-entity
status: established
verb: lookup
---

## Goal

Everything alpha knows about one entity.

## Query

```
entity
```
"""


def plant_census_catalog(folder: Path) -> Path:
    """Write the query template a planted census folder's lead-zero names into that folder's
    own catalog (`<folder>/agent/skills/gather/queries/`)."""
    q = Path(folder) / "agent" / "skills" / "gather" / "queries" / "alpha" / "by-entity.md"
    q.parent.mkdir(parents=True, exist_ok=True)
    q.write_text(CENSUS_QUERY_TEMPLATE, encoding="utf-8")
    return q


def plant_census_settings(repo: Path, rows: dict, *, template_rows: dict | None = None,
                          ) -> list[Path]:
    """Give a planted repo (`_dispositions995.planted_tree`) the two knowledge folders the
    census gate walks, `knowledge/tenant-fixture/` and `knowledge/tenant-template/`: each holds
    the table `rows` (the template `template_rows` when given), a `lead-zero.yaml` naming
    `CENSUS_LEAD_ZERO_ID`, the mappings, and that template in its own catalog. Plain folders as
    committed (no `.tenant-id`, no row). Returns the table paths, fixture first."""
    from defender.tests.support.invlang.validation._dispositions995 import write_table

    repo = Path(repo)
    written: list[Path] = []
    for name, table_rows in (("tenant-fixture", rows),
                             ("tenant-template", template_rows if template_rows is not None
                              else rows)):
        folder = repo / "knowledge" / name
        files = {"lead-zero.yaml": lead_zero_text(CENSUS_LEAD_ZERO_ID),
                 "systems/case-history/mapping.yaml": mapping_text(),
                 "alert-mapping.yaml": ALERT_MAPPING_TEXT}
        for rel, text in files.items():
            (folder / "settings" / rel).parent.mkdir(parents=True, exist_ok=True)
            (folder / "settings" / rel).write_text(text, encoding="utf-8")
        (folder / "agent").mkdir(parents=True, exist_ok=True)
        (folder / "agent" / ".gitkeep").write_text("", encoding="utf-8")
        plant_census_catalog(folder)
        written.append(write_table(folder / "settings" / "verb-grants.yaml", table_rows))
    return written


def paths_in(value: Any, *, _depth: int = 0, _seen: set[int] | None = None) -> set[Path]:  # noqa: C901 — one walk over every container shape a fake may be handed
    """Every `Path` (and absolute path string) reachable from `value` through mappings,
    sequences, dataclass fields and object attributes, a few levels deep: for asserting what a
    fake was handed without pinning the keyword it arrived under."""
    seen = _seen if _seen is not None else set()
    out: set[Path] = set()
    if _depth > 5 or id(value) in seen:
        return out
    seen.add(id(value))
    if isinstance(value, Path):
        out.add(value)
        return out
    if isinstance(value, str):
        if value.startswith("/") and "\n" not in value and len(value) < 4096:
            out.add(Path(value))
        return out
    if isinstance(value, (bytes, int, float, bool)) or value is None:
        return out
    if isinstance(value, dict):
        for k, v in value.items():
            out |= paths_in(k, _depth=_depth + 1, _seen=seen)
            out |= paths_in(v, _depth=_depth + 1, _seen=seen)
        return out
    if isinstance(value, (list, tuple, set, frozenset)):
        for v in value:
            out |= paths_in(v, _depth=_depth + 1, _seen=seen)
        return out
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        for f in dataclasses.fields(value):
            out |= paths_in(getattr(value, f.name, None), _depth=_depth + 1, _seen=seen)
        return out
    attrs = getattr(value, "__dict__", None)
    if isinstance(attrs, dict) and not isinstance(value, type):
        for v in attrs.values():
            out |= paths_in(v, _depth=_depth + 1, _seen=seen)
    return out


def reaches(value: Any, target: Path) -> bool:
    """Does `value` carry `target`, or a path at or below it (both compared resolved)?"""
    target = Path(target).resolve()
    for p in paths_in(value):
        try:
            rp = p.resolve()
        except (OSError, RuntimeError, ValueError):
            continue
        if rp == target or rp.is_relative_to(target):
            return True
    return False


def exposes(value: Any, target: Path) -> bool:
    """Does `value` carry a path that would expose `target` if mounted as a tree: the target,
    a path below it, or an ancestor? (A bind of `<root>/<tenant>` carries
    `<root>/<tenant>/settings` without ever spelling it.)"""
    target = Path(target).resolve()
    for p in paths_in(value):
        try:
            rp = p.resolve()
        except (OSError, RuntimeError, ValueError):
            continue
        if rp == target or rp.is_relative_to(target) or target.is_relative_to(rp):
            return True
    return False


__all__ = [
    "CENSUS_LEAD_ZERO_ID",
    "CENSUS_QUERY_TEMPLATE",
    "CORRELATION_PAIRS_A",
    "DEFENDER",
    "FIXTURE",
    "FIXTURE_AGENT",
    "FIXTURE_SETTINGS",
    "GATHER_PAIRS_A",
    "GATHER_PAIRS_B",
    "PLAYGROUND_ID",
    "REPO_ROOT",
    "REQUIRED_FILES",
    "SHIPPED_CORRELATION_TEMPLATE",
    "TABLE_A",
    "TABLE_B",
    "TABLE_BLANK",
    "TEMPLATE_AGENT",
    "TEMPLATE_DIR",
    "TEMPLATE_SETTINGS",
    "config_texts",
    "lead_zero_text",
    "mapping_text",
    "mod",
    "paths_in",
    "place_tenant",
    "plant_tenant",
    "accept",
    "fixture_gather_def",
    "fixture_grants",
    "fixture_run_tenant",
    "fixture_tenant",
    "plant_census_catalog",
    "plant_census_settings",
    "exposes",
    "reaches",
    "run_grants",
    "verb_context",
]

"""#1106 — the per-tenant knowledge folder: shared fixtures for the spec and the migrated suites.

The four settings kinds (each system's `config.env`, `verb-grants.yaml`, `lead-zero.yaml`,
`systems/case-history/mapping.yaml`) live in a tenant's knowledge folder under the DATA ROOT,
`<root>/<tenant>/knowledge/settings/`, beside an `agent/` half the box mounts read-only (#1120
D1/D2). A tenant is reached only through `_tenant.accept_tenant`; `accept` below calls it.

THE SEAMS THIS MODULE REACHES — each imported at CALL time, never at collection:

  * `defender._tenant.accept_tenant(root, id, *, defender_dir)` -> `Tenant`.
  * `defender.runtime.verb_dispositions.run_grants(settings_dir) -> RunGrants` — the per-run
    grants (`path`, `gather`, `correlation`, `correlation_system`); and
    `dispositions_path(settings_dir)`.
  * `defender.runtime.lead_zero_config.lead_zero_config_path(settings_dir)`.
  * `VerbContext(..., settings_dir=...)` — a REQUIRED field with no default.

A test that names no tenant runs as the committed fixture (`knowledge/tenant-fixture/`), set up
under its own tmp data root (`fixture_tenant`, #1120 H2). The lab is retired (#1120, PR #1157):
a test that wants a complete committed settings folder reads `FIXTURE_SETTINGS`, its copy.

THE ORACLES ARE LITERALS. Every PLANTED tenant is written from data spelled here — never copied
from a committed tenant, never from the retired
`defender/knowledge/environment/` — so an expected value can disagree with the file under test,
and the fixtures do not depend on where the committed copy lives.

Underscore-prefixed so pytest does not collect it; it defines no tests.
"""
from __future__ import annotations

import dataclasses
import importlib
import json
from pathlib import Path
from typing import Any

#: The repo root and the checkout's defender tree, spelled from this file's own location.
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFENDER = REPO_ROOT / "defender"

#: The committed template, as the design lays it out (M1), spelled as a literal.
TEMPLATE_DIR = REPO_ROOT / "knowledge" / "tenant-template"
#: The retired lab's id: tests still name a tenant `playground` under their own data root.
PLAYGROUND_ID = "playground"
TEMPLATE_SETTINGS = TEMPLATE_DIR / "settings"
#: The frozen test fixture tenant (#1120 H2): what a test runs as when it names no tenant.
FIXTURE = REPO_ROOT / "knowledge" / "tenant-fixture"
FIXTURE_SETTINGS = FIXTURE / "settings"
FIXTURE_AGENT = FIXTURE / "agent"
TEMPLATE_AGENT = TEMPLATE_DIR / "agent"

#: The retired home. #1106 deletes `defender/knowledge/` whole (O9).
RETIRED_KNOWLEDGE = DEFENDER / "knowledge"

#: D3's three files required at run start, relative to a tenant's `settings/`. A system's
#: `config.env` is deliberately NOT here: some adapters need none, and its absence stays the
#: per-call `ConfigFault`.
REQUIRED_FILES: tuple[str, ...] = (
    "verb-grants.yaml",
    "lead-zero.yaml",
    "systems/case-history/mapping.yaml",
)

#: The shipped lead-zero template (it exists in the real catalog, and its front matter binds
#: `elastic.alerts`). A fixture tenant that grants the correlation lead names it, so the
#: run-start agreement check (#1003) passes against the checkout's own catalog.
SHIPPED_CORRELATION_TEMPLATE = "elastic.correlate-alerts-by-entity"


def mod(dotted: str) -> Any:
    """Import `defender.<dotted>` at CALL time, never at collection time."""
    return importlib.import_module(f"defender.{dotted}")


def tenants() -> Any:
    """`defender._tenants` — the resolver module #1106 adds."""
    return mod("_tenants")


def run_grants(settings_dir: Path) -> Any:
    """The per-run grants projected from `settings_dir`'s table (M4)."""
    return mod("runtime.verb_dispositions").run_grants(Path(settings_dir))


def fixture_tenant(tenant_id: str | None = None) -> Any:
    """The committed fixture tenant (`knowledge/tenant-fixture/`) set up under the CURRENT
    test's data root and accepted through the real `accept_tenant` (#1120 H2) — what every
    replay that names no tenant runs as. The operator's steps, done by hand: the fixture
    copied to `<root>/<id>/knowledge`, its `agent/.tenant-id` written, the row minted by the
    real `create_tenant` (`_data_root_1078.ensure_d9_tenant`). Idempotent within one test."""
    from defender.tests import _data_root_1078

    return _data_root_1078.set_up_tenant(
        _data_root_1078.current_data_root(),
        tenant_id if tenant_id is not None else _data_root_1078.D9_TENANT_ID)


def fixture_grants() -> Any:
    """The committed fixture tenant's grants — what every pre-#1106 suite meant by "the
    shipped grant" (`GATHER_DEF.verb_grant`, `CORRELATION_GRANT`, `shipped_dispositions()`)."""
    return run_grants(FIXTURE_SETTINGS)


def fixture_gather_def() -> Any:
    """`GATHER_DEF` carrying the fixture tenant's gather grant.

    After M4 the definition carries NO table-projected grant (it would be one fixed per
    process), and `compile_policy` refuses a verb-bearing tool bit over an empty grant (K4). A
    suite that binds gather therefore binds it with a RUN's grant, exactly as the driver does."""
    gather_def = mod("runtime.driver").GATHER_DEF
    return dataclasses.replace(gather_def, verb_grant=fixture_grants().gather)


def accept(root: Path, tenant_id: str, **kw: Any) -> Any:
    """`tenant_id` under `root`, through the real `accept_tenant` (#1120 D1) against this
    checkout's `defender/`."""
    return mod("_tenant").accept_tenant(Path(root), tenant_id, defender_dir=DEFENDER, **kw)


def run_tenant(tenant: Any, *, defender_dir: Path | None = None,
               dispatches_lead_zero: bool = False) -> Any:
    """The driver's `RunTenant` for `tenant` (an accepted `Tenant`), built from the real
    pieces and nothing else (#1107): run start's readiness function (`resolve_run_tenant`: the
    same grants, the lead-zero dispatch identity checked over `defender_dir`'s catalog, default
    this checkout, only when `dispatches_lead_zero` — the harness says so for exactly the runs
    the driver dispatches the lead on — and the same refusals, raised as run start raises them),
    then `resolved_settings` (systems, Elastic view, ticket mapping). A scenario that wants
    other grants plants a tenant whose `verb-grants.yaml` says so."""
    rt = mod("runtime.run_tenant")
    ready = rt.resolve_run_tenant(
        tenant.settings, defender_dir=defender_dir if defender_dir is not None else DEFENDER,
        dispatches_lead_zero=dispatches_lead_zero)
    return rt.RunTenant(tenant=tenant, grants=ready.grants, correlation=ready.correlation,
                        **rt.resolved_settings(tenant))


def fixture_run_tenant(**kw: Any) -> Any:
    """The fixture tenant, set up under this test's data root, as the driver takes it."""
    return run_tenant(fixture_tenant(), **kw)


def verb_context(defender_dir: Path, run_dir: Path, env: Any, *,
                 tenant: Any = None, settings_dir: Path | None = None, **kw: Any) -> Any:
    """A `VerbContext` carrying the run's tenant record (the required field #1107 adds).

    `tenant` is a `RunTenant`; omitted, it is the fixture tenant's record, or the record of the
    accepted tenant whose `settings/` is `settings_dir` (`<root>/<id>/knowledge/settings`, kept
    as the spelling the pre-#1107 callers used, so a caller names WHICH folder and gets the
    real record for it)."""
    if tenant is None:
        if settings_dir is None or Path(settings_dir) == FIXTURE_SETTINGS:
            tenant = fixture_run_tenant()
        else:
            knowledge = Path(settings_dir).parent
            tenant = run_tenant(accept(knowledge.parent.parent, knowledge.parent.name))
    return mod("runtime.verbs").VerbContext(
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

#: A grant-nothing table, the template's shape (D1): every row `roles: []` with a reason. It
#: LOADS clean (K3) — it is gather's empty grant that must refuse the run at start (C9).
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


def mapping_text(reporter: str = "defender", open_status: str = "open") -> str:
    """A complete case-history mapping whose `open.reporter` is the one value a reader test
    watches flow out. `open_status` is written quoted and as given, so a template
    (`"{summary}"`) makes the one mapping the loader still refuses (#1221's amendment kept only
    the literal-`open.status` rule).

    It still carries #767's `released:` section, as an un-migrated tenant repo does: the loader
    accepts it and nothing reads it (#1221, amended), so every tenant planted from this text
    exercises that tolerance."""
    return f"""\
source:
  signature: rule.id
  summary: rule.description
  event_time: timestamp
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


def config_texts(marker: str, *, events_index: str | None = None,
                 alerts_index: str | None = None) -> dict[str, str]:
    """One `config.env` per system, every value carrying `marker` so a reader that returns
    another tenant's (or the checkout's) value is caught by the value alone."""
    events = events_index if events_index is not None else f"{marker}-events-*"
    alerts = alerts_index if alerts_index is not None else f"{marker}-alerts-*"
    return {
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
) -> Path:
    """Write a plain knowledge folder `root/<tenant_id>/{settings,agent}/` and return it — the
    shape of the committed template and fixture (no `.tenant-id`, no row). `place_tenant` puts
    one under a data root as a set-up tenant.

    `omit` names settings-relative files NOT to write (e.g. one of `REQUIRED_FILES`), for the
    refusal tests; the folder is otherwise complete. `agent/` always exists and holds one
    marker file, so a mount of it is observably THIS tenant's."""
    tenant = Path(root) / tenant_id
    settings = tenant / "settings"
    agent = tenant / "agent"
    files: dict[str, str] = {
        "verb-grants.yaml": table,
        "lead-zero.yaml": lead_zero if lead_zero is not None else lead_zero_text(),
        "systems/case-history/mapping.yaml": mapping_text(reporter, open_status),
    }
    for system, text in (configs if configs is not None
                         else config_texts(marker or tenant_id)).items():
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
    return tenant


def place_tenant(root: Path, tenant_id: str, **kw: Any) -> Path:
    """A set-up tenant under the data root `root` (#1120 D1): `plant_tenant`'s folder as its
    knowledge folder `root/<tenant_id>/knowledge/`, the `agent/.tenant-id` naming it, and its
    row written by hand (so one root can hold several fixture tenants — `create_tenant`'s
    one-tenant guard is setup's, not acceptance's). Returns the KNOWLEDGE folder, so
    `/ "settings"` and `/ "agent"` name the two halves; `accept(root, tenant_id)` accepts it."""
    folder = Path(root) / tenant_id
    defaults = {"marker": tenant_id, "agent_files": {"AGENT.md": f"agent half of {tenant_id}\n"}}
    knowledge = plant_tenant(folder, "knowledge", **{**defaults, **kw})
    (knowledge / "agent" / ".tenant-id").write_text(f"{tenant_id}\n", encoding="utf-8")
    (folder / "tenant.json").write_text(json.dumps(
        {"tenant_id": tenant_id, "created_at": "2026-09-28T00:00:00+00:00"},
        indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return knowledge


#: The lead-zero id a planted census repo's folders name, and the established catalog template
#: that carries it (`defender/skills/gather/queries/alpha/by-entity.md`). M7's CI pass checks
#: that each folder's `lead-zero.yaml` names a template the catalog holds, so a planted repo
#: whose folders name one must also hold it.
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


def plant_census_catalog(repo: Path) -> Path:
    """Write the one established query template a planted census repo's lead-zero names."""
    q = Path(repo) / "defender" / "skills" / "gather" / "queries" / "alpha" / "by-entity.md"
    q.parent.mkdir(parents=True, exist_ok=True)
    q.write_text(CENSUS_QUERY_TEMPLATE, encoding="utf-8")
    return q


def plant_census_settings(repo: Path, rows: dict, *, template_rows: dict | None = None,
                          ) -> list[Path]:
    """Give a planted repo (`_dispositions995.planted_tree`) the two knowledge folders the
    census gate walks (#1120 C26): `knowledge/tenant-fixture/` and
    `knowledge/tenant-template/`, each holding the table `rows` (as
    `_dispositions995.write_table` renders them — the template `template_rows` when given),
    a `lead-zero.yaml` naming `CENSUS_LEAD_ZERO_ID`, and the mapping; plus the catalog template
    that id resolves to. Plain folders, as committed: no `.tenant-id`, no row. Returns the
    table paths written, fixture first, template last."""
    from defender.tests._dispositions995 import write_table

    repo = Path(repo)
    plant_census_catalog(repo)
    written: list[Path] = []
    for name, table_rows in (("tenant-fixture", rows),
                             ("tenant-template", template_rows if template_rows is not None
                              else rows)):
        folder = repo / "knowledge" / name
        files = {"lead-zero.yaml": lead_zero_text(CENSUS_LEAD_ZERO_ID),
                 "systems/case-history/mapping.yaml": mapping_text()}
        for rel, text in files.items():
            (folder / "settings" / rel).parent.mkdir(parents=True, exist_ok=True)
            (folder / "settings" / rel).write_text(text, encoding="utf-8")
        (folder / "agent").mkdir(parents=True, exist_ok=True)
        (folder / "agent" / ".gitkeep").write_text("", encoding="utf-8")
        written.append(write_table(folder / "settings" / "verb-grants.yaml", table_rows))
    return written


def plant_tenant_record(runs_base: Path, tenant_id: str) -> Path:
    """`<runs_base>/_tenant.json` naming `tenant_id` — the record a run reads its tenant from
    (D4). Written in the record's own three-field shape."""
    runs_base = Path(runs_base)
    runs_base.mkdir(parents=True, exist_ok=True)
    path = runs_base / "_tenant.json"
    path.write_text(json.dumps({
        "tenant_id": tenant_id, "base_world_id": "0" * 32,
        "created_at": "2026-09-26T00:00:00+00:00",
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def paths_in(value: Any, *, _depth: int = 0, _seen: set[int] | None = None) -> set[Path]:  # noqa: C901 — one walk over every container shape a fake may be handed
    """Every `Path` (and absolute path string) reachable from `value` — through mappings,
    sequences, dataclass / pydantic fields and plain object attributes, a few levels deep.

    For asserting on what a FAKE was handed without pinning the keyword it arrived under: the
    question is "did the run's tenant settings folder reach this seam, and did any other
    tenant's", and the answer should not depend on whether the implementer called the
    argument `tenant`, `settings_dir` or `grants`."""
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
    """Does `value` carry a path that would EXPOSE `target` if mounted or read as a tree — the
    target itself, a path below it, or a path ABOVE it (an ancestor directory holds the target)?

    `reaches` answers "was this path handed over"; a mount source is a TREE, so for it the
    question is also "is the forbidden path inside what was handed over". A bind of
    `<root>/<tenant>` carries `<root>/<tenant>/settings` without ever spelling it."""
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
    "RETIRED_KNOWLEDGE",
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
    "plant_tenant_record",
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
    "tenants",
    "verb_context",
]

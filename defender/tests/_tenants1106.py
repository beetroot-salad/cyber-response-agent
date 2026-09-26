"""#1106 — the per-tenant knowledge folder: shared fixtures for the spec and the migrated suites.

The four settings kinds (each system's `config.env`, `verb-grants.yaml`, `lead-zero.yaml`,
`systems/case-history/mapping.yaml`) leave `defender/knowledge/environment/` for
`<tenants root>/<tenant>/settings/` at the REPO ROOT, beside an `agent/` half the box mounts
read-only. Nothing below `defender/` holds them any more, and no reader finds the tenants root
itself: a process entry point is handed it and passes it down (D2).

THE SEAMS THIS MODULE REACHES — each imported at CALL time, never at collection, so a suite that
imports this helper collects cleanly before #1106 lands and each test fails at the seam it needs
(an `ImportError`/`AttributeError` there is a real red, not a fixture bug):

  * `defender._tenants` — `TenantDir` (frozen: `tenant_id`, `settings`, `agent`), `tenant_dir(
    tenants_root, tenant_id)`, `TenantDirError(ValueError)`, `REQUIRED_SETTINGS`,
    `default_tenants_root(repo_root)`.
  * `defender.runtime.verb_dispositions.run_grants(settings_dir) -> RunGrants` — the per-run
    grants (`path`, `gather`, `correlation`, `correlation_system`); and
    `dispositions_path(settings_dir)`.
  * `defender.runtime.lead_zero_config.lead_zero_config_path(settings_dir)`.
  * `VerbContext(..., settings_dir=...)` — a REQUIRED field with no default.

THE ORACLES ARE LITERALS. Every fixture tenant is written from data spelled here — never copied
from the checkout's `knowledge/tenants/playground/`, never from the retired
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

#: The committed tenants root and template, as the design lays them out (M1). Spelled as
#: literals rather than through `default_tenants_root`, so the layout test can compare the
#: helper's answer against an independent statement of where the folder is.
TENANTS_ROOT = REPO_ROOT / "knowledge" / "tenants"
TEMPLATE_DIR = REPO_ROOT / "knowledge" / "tenant-template"
PLAYGROUND_ID = "playground"
PLAYGROUND = TENANTS_ROOT / PLAYGROUND_ID
PLAYGROUND_SETTINGS = PLAYGROUND / "settings"
PLAYGROUND_AGENT = PLAYGROUND / "agent"
TEMPLATE_SETTINGS = TEMPLATE_DIR / "settings"
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


def playground_grants() -> Any:
    """The committed playground tenant's grants — what every pre-#1106 suite meant by "the
    shipped grant" (`GATHER_DEF.verb_grant`, `CORRELATION_GRANT`, `shipped_dispositions()`)."""
    return run_grants(PLAYGROUND_SETTINGS)


def playground_gather_def() -> Any:
    """`GATHER_DEF` carrying the playground tenant's gather grant.

    After M4 the definition carries NO table-projected grant (it would be one fixed per
    process), and `compile_policy` refuses a verb-bearing tool bit over an empty grant (K4). A
    suite that binds gather therefore binds it with a RUN's grant, exactly as the driver does."""
    gather_def = mod("runtime.driver").GATHER_DEF
    return dataclasses.replace(gather_def, verb_grant=playground_grants().gather)


def playground_tenant() -> Any:
    """The committed playground tenant, through the real resolver."""
    return tenants().tenant_dir(TENANTS_ROOT, PLAYGROUND_ID)


def verb_context(defender_dir: Path, run_dir: Path, env: Any, *,
                 settings_dir: Path = PLAYGROUND_SETTINGS, **kw: Any) -> Any:
    """A `VerbContext` carrying `settings_dir` (the required field #1106 adds)."""
    return mod("runtime.verbs").VerbContext(
        defender_dir=Path(defender_dir), run_dir=Path(run_dir), env=env,
        settings_dir=Path(settings_dir), **kw)


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


def mapping_text(released_status: str = "closed", reporter: str = "defender") -> str:
    """A complete, valid case-history mapping whose `released.status` is the one value a
    reader test watches flow out."""
    return f"""\
source:
  signature: rule.id
  summary: rule.description
  event_time: timestamp
open:
  key: "{{case_id}}"
  summary: "{{summary}}"
  description: "Auto-created from alert {{case_id}} (rule {{signature}})."
  status: open
  reporter: {reporter}
  labels:
    - "sig:{{signature}}"
    - "evt:{{event_time}}"
comment:
  author: defender
  body: "{{disposition}} — {{cause}}\\n\\n{{narrative}}"
released:
  status: {released_status}
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
    released_status: str = "closed",
    reporter: str = "defender",
    marker: str | None = None,
    configs: dict[str, str] | None = None,
    omit: tuple[str, ...] = (),
    agent_files: dict[str, str] | None = None,
) -> Path:
    """Write `root/<tenant_id>/{settings,agent}/` and return the tenant folder.

    `omit` names settings-relative files NOT to write (e.g. one of `REQUIRED_FILES`), for the
    refusal tests; the folder is otherwise complete. `agent/` always exists and holds one
    marker file, so a mount of it is observably THIS tenant's."""
    tenant = Path(root) / tenant_id
    settings = tenant / "settings"
    agent = tenant / "agent"
    files: dict[str, str] = {
        "verb-grants.yaml": table,
        "lead-zero.yaml": lead_zero if lead_zero is not None else lead_zero_text(),
        "systems/case-history/mapping.yaml": mapping_text(released_status, reporter),
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


def plant_census_settings(repo: Path, rows: dict, *, tenant_ids: tuple[str, ...] = (PLAYGROUND_ID,),
                          template_rows: dict | None = None) -> list[Path]:
    """Give a planted repo (`_dispositions995.planted_tree`) the settings folders #1106's census
    gate walks: `knowledge/tenants/<id>/settings/` for each id plus
    `knowledge/tenant-template/settings/`, every one holding the table `rows` (as
    `_dispositions995.write_table` renders them — the template `template_rows` when given),
    a `lead-zero.yaml` naming `CENSUS_LEAD_ZERO_ID`, and the mapping; plus the catalog template
    that id resolves to. Returns the table paths written, tenants first, template last.

    This replaces planting ONE table at `defender/knowledge/environment/verb-grants.yaml`: the
    gate no longer reads that path, and a repo with no tenant folder has no table to check."""
    from defender.tests._dispositions995 import write_table

    repo = Path(repo)
    plant_census_catalog(repo)
    folders = [(repo / "knowledge" / "tenants", t, rows) for t in tenant_ids]
    folders.append((repo / "knowledge", "tenant-template",
                    template_rows if template_rows is not None else rows))
    written: list[Path] = []
    for parent, tenant_id, table_rows in folders:
        tenant = plant_tenant(parent, tenant_id, table="dispositions: {}\n", configs={},
                              lead_zero=lead_zero_text(CENSUS_LEAD_ZERO_ID))
        written.append(write_table(tenant / "settings" / "verb-grants.yaml", table_rows))
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


def paths_in(value: Any, *, _depth: int = 0, _seen: set[int] | None = None) -> set[Path]:
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


__all__ = [
    "CENSUS_LEAD_ZERO_ID",
    "CENSUS_QUERY_TEMPLATE",
    "CORRELATION_PAIRS_A",
    "DEFENDER",
    "GATHER_PAIRS_A",
    "GATHER_PAIRS_B",
    "PLAYGROUND",
    "PLAYGROUND_AGENT",
    "PLAYGROUND_ID",
    "PLAYGROUND_SETTINGS",
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
    "TENANTS_ROOT",
    "config_texts",
    "lead_zero_text",
    "mapping_text",
    "mod",
    "paths_in",
    "plant_tenant",
    "plant_tenant_record",
    "playground_gather_def",
    "playground_grants",
    "playground_tenant",
    "plant_census_catalog",
    "plant_census_settings",
    "reaches",
    "run_grants",
    "tenants",
    "verb_context",
]

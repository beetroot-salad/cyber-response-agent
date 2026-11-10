"""#1366 test machinery (r7): the one place that spells every name the contract invents. NO test functions.
The names, their meaning and the seeding rules are in `.contract-first/shared-interface.md`; read that first.

Nothing here judges a record. Seeders put records into the read side (the memory twin, or Postgres through the store's
own import door with an accept-all judge); the operator command is `cli.tenant.main`; credentials sit in a KV stand-in
that only stores what it is sent. The production modules named here do not exist at the base: every import is lazy, so
a missing one is a red at the first call, never a collection error.
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import re
import uuid
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, NamedTuple

import httpx
import yaml

# --- operator command surface (DC8) ---------------------------------------------------------------------------------
CATALOG, IMPORT, SYSTEMS = "catalog", "import", "systems"
SET_SYSTEM, DELETE_SYSTEM, SET_CASE, DELETE_CASE, SET_CREDENTIALS = (
    "set-system", "delete-system", "set-case", "delete-case", "set-credentials")
DRY_RUN, REPLACES, FOR_VERSION, DISABLED, EXPORT = "--dry-run", "--replaces", "--for-version", "--disabled", "--export"
#: A version's author is the writing command's name (R9).
AUTHOR = {cmd: f"tenant.py {cmd}" for cmd in (IMPORT, SET_SYSTEM, DELETE_SYSTEM, SET_CASE, DELETE_CASE)}
#: Rows the seeders write (not an operator command).
SEED_AUTHOR = "test seed"
#: The adapters the product carries today (O2): real, then lab examples.
REAL = ("elastic", "jira", "servicenow")
EXAMPLES = ("change-mgmt", "cmdb", "host-state", "identity", "threat-intel", "ticket")
KV_MOUNT = "kv"
PROXY_ROLE = "defender_proxy_reader"  # R14: NOLOGIN, SELECT on tenancy.system_versions only (migration 0011_system_records)
#: The records tables (schema `tenancy`); columns in shared-interface.md.
SYSTEM_VERSIONS, CASE_VERSIONS, RECORDS_MARK = "system_versions", "case_versions", "records_mark"


# --- declarations and folders ---------------------------------------------------------------------------------------

OAUTH = "oauth-client-credentials"


def declaration(base: str, *, scheme: str = "bearer", reads: tuple[tuple[str, str], ...] = (),
                writes: tuple[tuple[str, str], ...] = (), token_url: str | None = None,
                scopes: tuple[str, ...] = ("read",), auth: Mapping[str, Any] | None = None,
                ca: str | bytes | None = None) -> str:
    """An http-proxy access declaration at `base` (YAML text; JSON is YAML). Data only.
    `scheme` "bearer" (default) / "basic" / "header" / `OAUTH` (needs `token_url`; `scopes`); `auth=` is the whole auth
    block verbatim (wins over `scheme`); `ca` is a PEM written inline."""
    if auth is None:
        auth = {"scheme": scheme}
        if scheme == OAUTH:
            auth.update(token_url=token_url, scopes=list(scopes))
        elif scheme != "basic":
            auth["field"] = "api_key"
        if scheme == "header":
            auth["header"] = "X-Api-Key"
    doc: dict[str, Any] = {"access": "http-proxy", "base": base, "auth": dict(auth),
                           "reads": [{"method": m, "path": p} for m, p in reads],
                           "writes": [{"method": m, "path": p} for m, p in writes]}
    if ca is not None:
        doc["ca"] = ca.decode() if isinstance(ca, bytes) else ca
    return json.dumps(doc, indent=2) + "\n"


def bearer_access(base: str, *, writes: tuple[tuple[str, str], ...] = (), scheme: str = "bearer") -> str:
    return declaration(base, scheme=scheme, writes=writes)


def system_folder(where: Path, system: str, *, config: Mapping[str, str] | None, access: str | None) -> Path:
    """`<where>/<system>/` holding `config.env` (KEY="value" lines) and `access.yaml`; None leaves the file out.
    The operator command's `set-system` input and connect's handoff shape."""
    folder = where / system
    folder.mkdir(parents=True, exist_ok=True)
    if config is not None:
        (folder / "config.env").write_text("".join(f'{k}="{v}"\n' for k, v in config.items()), encoding="utf-8")
    if access is not None:
        (folder / "access.yaml").write_text(access, encoding="utf-8")
    return folder


def parse_config_env(text: str) -> dict[str, str]:
    """`KEY="value"` / `KEY=value` lines of a planted config.env (comments and blanks skipped). A planter's data, read
    back to seed a record; not a judgement."""
    found: dict[str, str] = {}
    for line in text.splitlines():
        match = re.fullmatch(r'\s*([A-Z][A-Z0-9_]*)\s*=\s*(.*?)\s*', line)
        if match and not line.lstrip().startswith("#"):
            found[match.group(1)] = match.group(2).strip('"')
    return found


#: The retired fixture tenant's `settings/` (slice A deleted it from `knowledge/tenant-fixture/`; the files moved here
#: byte for byte, so the diff is a rename and the import tests read real files).
FIXTURE_DATA = Path(__file__).resolve().parents[2] / "fixtures" / "retired-tenant-fixture" / "settings"


def _read_fixture_folders() -> Mapping[str, tuple[Mapping[str, str], str]]:
    found: dict[str, tuple[Mapping[str, str], str]] = {}
    for folder in sorted(p for p in (FIXTURE_DATA / "systems").iterdir() if p.is_dir()):
        config = folder / "config.env"
        found[folder.name] = (parse_config_env(config.read_text("utf-8")) if config.is_file() else {},
                              (folder / "access.yaml").read_text("utf-8"))
    return found


#: system -> (settings keys as stored, access text as committed, comments included). host-state has no config.env.
FIXTURE_FOLDERS: Mapping[str, tuple[Mapping[str, str], str]] = _read_fixture_folders()
FIXTURE_SYSTEMS = frozenset(FIXTURE_FOLDERS)
_FIXTURE_CASE = yaml.safe_load((FIXTURE_DATA / "case-record.yaml").read_text("utf-8"))
FIXTURE_CASE_SYSTEM = _FIXTURE_CASE["system"]
FIXTURE_CASE_BODY = _FIXTURE_CASE["comment"]["body"]


def case_record_text(system: str = FIXTURE_CASE_SYSTEM, body: str = FIXTURE_CASE_BODY) -> str:
    """`case-record.yaml` text (what `set-case` and `import` read; #1359's format)."""
    return f"system: {system}\ncomment:\n  body: {json.dumps(body)}\n"


def import_files(**overrides: str | None) -> dict[str, str | None]:
    """`published_tenant(files=...)` content that plants the fixture's systems and case record as the retired
    `settings/` folders the import reads; `overrides` (path -> text) replace entries, a path mapped to None is left out.
    Use it in every test that imports, so none depends on a placed fixture carrying those folders (slice A dropped them)."""
    files: dict[str, str | None] = {
        str(p.relative_to(FIXTURE_DATA.parent)): p.read_text("utf-8") for p in sorted(FIXTURE_DATA.rglob("*")) if p.is_file()}
    files.update(overrides)
    return {k: v for k, v in files.items() if v is not None}


# --- the records value, computed (pure) -----------------------------------------------------------------------------

@dataclass(frozen=True)
class SysSpec:
    """One system's current record as a seeder holds it (production's `SystemRecord` is built from it by `to_value`)."""

    settings: Mapping[str, str]
    access: str
    version: int = 1
    generation: int = 1
    enabled: bool = True
    #: The catalog adapter id the record names; None = the system id. A seeder's data (accept-all judge), so a test can
    #: store a record whose adapter an upgrade has since removed from the catalog.
    adapter: str | None = None


@dataclass(frozen=True)
class CaseSpec:
    system_id: str = FIXTURE_CASE_SYSTEM
    comment_body: str = FIXTURE_CASE_BODY
    version: int = 1


@dataclass(frozen=True)
class RecordsSpec:
    systems: Mapping[str, SysSpec] = field(default_factory=dict)
    case: CaseSpec | None = None


def edited(spec: RecordsSpec, system: str, **changes: Any) -> RecordsSpec:
    """`spec` with `system` changed (`version=`, `generation=`, `settings=`, `access=`, `enabled=`)."""
    return replace(spec, systems={**spec.systems, system: replace(spec.systems[system], **changes)})


def without(spec: RecordsSpec, *systems: str) -> RecordsSpec:
    return replace(spec, systems={s: v for s, v in spec.systems.items() if s not in systems})


def fixture_records() -> RecordsSpec:
    """The committed fixture tenant's records (every `FIXTURE_FOLDERS` system at version 1, generation 1; case v1)."""
    return RecordsSpec({s: SysSpec(dict(c), a) for s, (c, a) in FIXTURE_FOLDERS.items()}, CaseSpec())


def records_from_settings(settings: Path) -> RecordsSpec:
    """The records a planter's `settings/` folder stands for: a system per `systems/<s>/` folder holding either file
    (a missing config.env is empty settings, a missing access.yaml is empty text: the system is then down at start, as
    the folder world had it), the case from `case-record.yaml` (none when absent). PURE: reads files, calls nothing
    of production."""
    systems: dict[str, SysSpec] = {}
    root = Path(settings) / "systems"
    for folder in sorted(p for p in root.iterdir() if p.is_dir()) if root.is_dir() else ():
        config, access = folder / "config.env", folder / "access.yaml"
        if not (config.is_file() or access.is_file()):
            continue
        systems[folder.name] = SysSpec(parse_config_env(config.read_text("utf-8")) if config.is_file() else {},
                                       access.read_text("utf-8") if access.is_file() else "")
    case = None
    case_file = Path(settings) / "case-record.yaml"
    if case_file.is_file():
        data = yaml.safe_load(case_file.read_text("utf-8")) or {}
        case = CaseSpec(str(data.get("system", "")), str((data.get("comment") or {}).get("body", "")))
    return RecordsSpec(systems, case)


def settings_of(data_root: Path | str | None, tenant: str) -> Path | None:
    """The `settings/` a run of `tenant` would read: the published run copy (`exports/current`) else the placed folder."""
    if data_root is None:
        return None
    base = Path(str(data_root)) / str(tenant)
    pointer = base / "exports" / "current"
    if pointer.is_file():
        published = base / "exports" / pointer.read_text("utf-8").strip() / "settings"
        if published.is_dir():
            return published
    placed = base / "knowledge" / "settings"
    return placed if placed.is_dir() else None


class _Derived:
    def __repr__(self) -> str:
        return "DERIVED"


#: `records=` default of every planting helper: seed what the tenant's own planted/published `settings/` stands for,
#: else the fixture's. `records=None`: NOT imported (nothing seeded). A `RecordsSpec`: exactly that.
DERIVED: Any = _Derived()


def resolve(records: Any, data_root: Path | str | None, tenant: str) -> RecordsSpec | None:
    """DERIVED = the systems the test itself planted under the tenant's `settings/systems` (published run copy, else
    placed folder), else the retired fixture's records. The case record: the planted `case-record.yaml`, else the
    fixture's when its system is among the planted ones (slice A deleted the fixture's own `settings/`, so a placed copy
    carries neither systems nor a case record unless the test plants them)."""
    if records is not DERIVED:
        return records
    folder = settings_of(data_root, tenant)
    planted = records_from_settings(folder) if folder is not None else RecordsSpec()
    if not planted.systems:
        return fixture_records()
    case = planted.case or (fixture_records().case if fixture_records().case.system_id in planted.systems else None)
    return replace(planted, case=case)


def to_value(spec: RecordsSpec) -> Any:
    """Production's `TenantRecords(imported=True, ...)` for `spec` (fields in shared-interface.md)."""
    from defender.tenancy.models import CaseRecord, SystemRecord, TenantRecords

    systems = {s: SystemRecord(system_id=s, version=v.version, adapter_id=v.adapter or s, enabled=v.enabled,
                               settings=dict(v.settings), access=v.access, credential_generation=v.generation)
               for s, v in spec.systems.items()}
    case = None if spec.case is None else CaseRecord(version=spec.case.version, system_id=spec.case.system_id,
                                                     comment_body=spec.case.comment_body)
    return TenantRecords(imported=True, systems=systems, case=case)


# --- seeders: the planting helpers call these (R8: the memory twin defaults to NOT imported) -------------------------

def seed_twin_records(twin: Any, data_root: Path | str | None, tenant: str, records: Any = DERIVED) -> None:
    """Make `tenant` imported in the memory twin with `records` (`twin.add_records`, a public seeder beside
    `add_generation`; the tenant must exist). `records=None` seeds nothing: the tenant stays not imported."""
    spec = resolve(records, data_root, str(tenant))
    if spec is None:
        return
    from defender.tests.support.tenancy._active1214 import _await, run_sync

    run_sync(_await(twin.add_records(str(tenant), to_value(spec))))


def seed_postgres_records(dsn: str, tenant: str, records: Any = DERIVED, data_root: Path | str | None = None) -> None:
    """Make `tenant` (a registered row) imported in Postgres with `records`, through the store's own import door
    (`RecordStore.import_tenant`) under an accept-all judge: first versions only (version and generation 1)."""
    spec = resolve(records, data_root, str(tenant))
    if spec is None:
        return
    if any(v.version != 1 or v.generation != 1 for v in spec.systems.values()) or (spec.case and spec.case.version != 1):
        raise ValueError("the Postgres seeder writes first versions; edit through the operator command")
    from defender.tests.support.tenancy._active1214 import run_sync

    async def put() -> None:
        from defender.system_records import RecordStore
        from defender.tests.support.jobs._jobs1342 import fixed_clock

        store = RecordStore(dsn, clock=fixed_clock, judge=lambda after: [])
        try:
            await store.import_tenant(str(tenant), to_value(spec), author=SEED_AUTHOR)
        finally:
            await store.close()

    run_sync(put())


def drop_records(dsn: str, tenant: str) -> None:
    """Delete `tenant`'s rows in the records tables (they reference `tenancy.tenants`); a no-op before the migration."""
    from defender.tests.support.shared._postgres1339 import execute

    for table in (SYSTEM_VERSIONS, CASE_VERSIONS, RECORDS_MARK):
        found = execute(dsn, "SELECT to_regclass(%s)", (f"tenancy.{table}",))
        if found and found[0][0] is not None:
            execute(dsn, f'DELETE FROM tenancy."{table}" WHERE tenant_id = %s', (str(tenant),))  # noqa: S608


# --- reads (tests observe state; they do not use the writer for it) -------------------------------------------------

class Version(NamedTuple):
    """One stored system version (columns of tenancy.system_versions)."""

    version: int
    adapter_id: str
    enabled: bool
    settings: dict[str, str]
    access: str
    credential_generation: int
    deleted: bool
    author: str
    written_at: Any


class CaseVersion(NamedTuple):
    version: int
    system_id: str
    comment_body: str
    deleted: bool
    author: str
    written_at: Any


def current_records(dsn: str, tenant_id: str) -> Any:
    """`PostgresTenantRepository(dsn).current_records(tenant_id)`: the R10 read, as production's read side gives it."""
    async def go() -> Any:
        from defender.tenancy.postgres import PostgresTenantRepository

        repository = PostgresTenantRepository(dsn)
        try:
            return await repository.current_records(tenant_id)
        finally:
            await repository.close()

    return asyncio.run(go())


def imported(dsn: str, tenant_id: str) -> bool:
    return bool(current_records(dsn, tenant_id).imported)


def system_versions(dsn: str, tenant_id: str, system: str) -> list[Version]:
    from defender.tests.support.shared._postgres1339 import execute

    rows = execute(dsn, f"""SELECT version, adapter_id, enabled, settings, access, credential_generation, deleted, author,
                            written_at FROM tenancy.{SYSTEM_VERSIONS} WHERE tenant_id = %s AND system_id = %s
                            ORDER BY version""", (tenant_id, system))  # noqa: S608
    return [Version(*row) for row in rows]


def case_versions(dsn: str, tenant_id: str) -> list[CaseVersion]:
    from defender.tests.support.shared._postgres1339 import execute

    rows = execute(dsn, f"""SELECT version, system_id, comment_body, deleted, author, written_at
                            FROM tenancy.{CASE_VERSIONS} WHERE tenant_id = %s ORDER BY version""", (tenant_id,))  # noqa: S608
    return [CaseVersion(*row) for row in rows]


# --- OpenBao stand-in -----------------------------------------------------------------------------------------------

class KvStandIn(httpx.MockTransport):
    """OpenBao's KV v2 by transport, at mount `kv`: stores each POSTed `data` under its path (versions counted), answers
    GET data / metadata from what it holds (404 otherwise), records every (method, path). Decides nothing."""

    def __init__(self, held: Mapping[str, Mapping[str, Any]] | None = None) -> None:
        super().__init__(self._handle)
        self.held: dict[str, list[dict[str, Any]]] = {p: [dict(v)] for p, v in (held or {}).items()}
        self.requests: list[tuple[str, str]] = []

    def _handle(self, request: httpx.Request) -> httpx.Response:
        prefix = f"/v1/{KV_MOUNT}/"
        path = request.url.path
        self.requests.append((request.method, path))
        if not path.startswith(prefix):
            return httpx.Response(404, json={"errors": []})
        kind, _, key = path[len(prefix):].partition("/")
        versions = self.held.get(key)
        if kind == "data" and request.method in ("POST", "PUT"):
            self.held.setdefault(key, []).append(dict(json.loads(request.content)["data"]))
            return httpx.Response(200, json={"data": {"version": len(self.held[key])}})
        if not versions:
            return httpx.Response(404, json={"errors": []})
        if kind == "data":
            return httpx.Response(200, json={"data": {"data": versions[-1], "metadata": {"version": len(versions)}}})
        if kind == "metadata":
            return httpx.Response(200, json={"data": {"current_version": len(versions), "versions": {
                str(n): {"deletion_time": "", "destroyed": False} for n in range(1, len(versions) + 1)}}})
        return httpx.Response(404, json={"errors": []})

    def written(self) -> list[str]:
        """Paths under the mount that were written, in order."""
        return [p.removeprefix(f"/v1/{KV_MOUNT}/data/") for m, p in self.requests
                if m in ("POST", "PUT") and p.startswith(f"/v1/{KV_MOUNT}/data/")]

    def read_paths(self) -> list[str]:
        return [p.removeprefix(f"/v1/{KV_MOUNT}/data/") for m, p in self.requests
                if m == "GET" and p.startswith(f"/v1/{KV_MOUNT}/data/")]


def operator_secrets(kv: KvStandIn) -> Any:
    """The operator's OpenBao login over `kv` (`main(..., secrets=)`; the class is production's)."""
    from defender.credential_proxy._openbao import OpenBaoSecrets

    return OpenBaoSecrets(addr="http://openbao.test:8200", token="operator-token", mount=KV_MOUNT, transport=kv)


def proxy_credentials(kv: KvStandIn) -> Any:
    """The proxy's OpenBao read over `kv`."""
    from defender.credential_proxy._openbao import OpenBaoStore

    return OpenBaoStore(addr="http://openbao.test:8200", token="proxy-token", mount=KV_MOUNT, transport=kv)


def credential_set(fields: Mapping[str, str], kind: str = "static") -> dict[str, Any]:
    """A stored set as the KV holds it (`{kind, fields}`, `OpenBaoStore.read`'s shape)."""
    return {"kind": kind, "fields": dict(fields)}


# --- the proxy's side -----------------------------------------------------------------------------------------------

class ExportRecords:
    """A hermetic `SystemRecordsPort` for the EXISTING proxy tests (`credential_proxy_1163/_tenant.deps` uses it): the
    current version of a system is what the tenant's published export's `settings/systems/<s>/` holds (version 1,
    generation 1) -- the legacy data the old proxy read, now handed through the new port. Read on each call (tests
    republish). Decides nothing; new tests seed Postgres and use `PostgresSystemRecords` instead."""

    def __init__(self, data_root: Path | str) -> None:
        self.data_root = Path(data_root)

    def current_system(self, tenant_id: str, system_id: str) -> Any:
        folder = settings_of(self.data_root, tenant_id)
        spec = None if folder is None else records_from_settings(folder).systems.get(system_id)
        return None if spec is None else to_value(RecordsSpec({system_id: spec})).systems[system_id]


class GenerationBlind:
    """The EXISTING proxy tests' credential fakes take `read(tenant, system)`; the port now passes the generation too.
    This wrapper drops it (those tests all sit at generation 1). New tests use `OpenBaoStore` over `KvStandIn`."""

    def __init__(self, store: Any) -> None:
        self._store = store

    def read(self, tenant_id: str, system: str, generation: int) -> Any:
        return self._store.read(tenant_id, system)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._store, name)


@contextlib.contextmanager
def proxy_login(dsn: str, *, granted: bool = True) -> Iterator[str]:
    """A DSN logging in as a fresh LOGIN role (unique name: roles are cluster-wide and tests share a server) that is a
    member of `PROXY_ROLE` (`granted`) or has no grant at all. Dropped after. `dsn` must be the superuser's."""
    from sqlalchemy.engine import make_url

    from defender.tests.support.shared._postgres1339 import execute

    name, password = f"proxy_login_{uuid.uuid4().hex[:12]}", uuid.uuid4().hex
    execute(dsn, f'CREATE ROLE "{name}" LOGIN PASSWORD \'{password}\'')
    try:
        if granted:
            execute(dsn, f'GRANT "{PROXY_ROLE}" TO "{name}"')
        yield make_url(dsn).set(username=name, password=password).render_as_string(hide_password=False)
    finally:
        with contextlib.suppress(Exception):
            execute(dsn, f'DROP OWNED BY "{name}"')
            execute(dsn, f'DROP ROLE IF EXISTS "{name}"')


# --- the operator -----------------------------------------------------------------------------------------------------

class Operator:
    """The operator command for one tenant registered on a migrated database (`DEFENDER_DATABASE_DSN` set by the caller's
    fixture): `.run(*argv)` is `cli.tenant.main` with the KV stand-in as the operator's OpenBao (`secrets=`). It is also
    handed to `import` so that a copy (R13 says there is none) would show in `kv.requests`."""

    def __init__(self, tenant_id: str, dsn: str, tmp: Path, capsys: Any, kv: KvStandIn | None = None) -> None:
        self.tid, self.dsn, self.tmp, self.capsys = tenant_id, dsn, tmp, capsys
        self.kv = kv if kv is not None else KvStandIn()

    def run(self, *argv: str) -> tuple[int, str]:
        from defender.cli import tenant

        self.capsys.readouterr()
        seams = {"secrets": operator_secrets(self.kv)} if argv[0] in (IMPORT, SET_CREDENTIALS, "check", SYSTEMS) else {}
        rc = tenant.main(list(argv), **seams)
        said = self.capsys.readouterr()
        return rc, said.out + said.err

    def import_(self, *, dry_run: bool = False) -> tuple[int, str]:
        return self.run(IMPORT, self.tid, *((DRY_RUN,) if dry_run else ()))

    def _folder(self, system: str, config: Mapping[str, str] | None, access: str | None) -> Path:
        n = len(list(self.tmp.glob("folder-*")))
        return system_folder(self.tmp / f"folder-{n}", system, config=config, access=access)

    def set_system(self, system: str, *, replaces: int, config: Mapping[str, str] | None,
                   access: str | None, disabled: bool = False) -> tuple[int, str]:
        folder = self._folder(system, config, access)
        return self.run(SET_SYSTEM, self.tid, system, str(folder), REPLACES, str(replaces),
                        *((DISABLED,) if disabled else ()))

    def delete_system(self, system: str, *, replaces: int) -> tuple[int, str]:
        return self.run(DELETE_SYSTEM, self.tid, system, REPLACES, str(replaces))

    def set_case(self, *, replaces: int, system: str = FIXTURE_CASE_SYSTEM, body: str = FIXTURE_CASE_BODY) -> tuple[int, str]:
        self.tmp.mkdir(parents=True, exist_ok=True)
        file = self.tmp / f"case-{len(list(self.tmp.glob('case-*')))}.yaml"
        file.write_text(case_record_text(system, body), encoding="utf-8")
        return self.run(SET_CASE, self.tid, str(file), REPLACES, str(replaces))

    def delete_case(self, *, replaces: int) -> tuple[int, str]:
        return self.run(DELETE_CASE, self.tid, REPLACES, str(replaces))

    def set_credentials(self, system: str, fields: Mapping[str, str], *, for_version: int,
                        kind: str = "static") -> tuple[int, str]:
        self.tmp.mkdir(parents=True, exist_ok=True)
        file = self.tmp / f"creds-{system}-{for_version}.json"
        file.write_text(json.dumps(credential_set(fields, kind)), encoding="utf-8")
        return self.run(SET_CREDENTIALS, self.tid, system, str(file), FOR_VERSION, str(for_version))

    def systems(self, *export: str) -> tuple[int, str]:
        return self.run(SYSTEMS, self.tid, *export)

    def check(self) -> tuple[int, str]:
        return self.run("check", self.tid)

    def current(self) -> dict[str, Any]:
        return dict(current_records(self.dsn, self.tid).systems)

    def versions(self, system: str) -> list[Version]:
        return system_versions(self.dsn, self.tid, system)

    def numbers(self, system: str) -> list[tuple[int, int, bool]]:
        """(version, credential_generation, deleted) per stored version of `system`."""
        return [(v.version, v.credential_generation, v.deleted) for v in self.versions(system)]


def lines_naming(text: str, *words: str) -> list[str]:
    """Lines of `text` that contain every one of `words`."""
    return [line for line in text.splitlines() if all(w in line for w in words)]

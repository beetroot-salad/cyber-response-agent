"""`tenant.py`'s record commands (#1366 DC8): the operator writes a tenant's system and case records and its credentials.

    catalog                                         the adapters the product carries
    import <id> [--dry-run]                         the tenant's retired settings folders, once, as first versions
    set-system <id> <system> <folder> --replaces N [--disabled]
    delete-system <id> <system> --replaces N
    set-case <id> <case-record file> --replaces N
    delete-case <id> --replaces N
    systems <id> [--export <dir>]                   the current systems, or each written out as a folder
    set-credentials <id> <system> <file> --for-version N [--token-file <path>]

Every write goes through the record store (`system_records.open_store`, the real judgement injected) over
`DEFENDER_DATABASE_DSN`, as one new version naming the version it replaces (`--replaces`; 0 = none ever); a version's
author is the command's name. Refusals print `[tenant.py] <sentence>` and exit 1; a sentence names the system and the
key or part, never a file, except where a file is what the operator fixes (the import's folders, a case-record file).
"""
from __future__ import annotations

import asyncio
import datetime as _dt
import json
import os
import sys
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from defender import tenancy
from defender.kit.settings import RECORDS, FolderLocator
from defender.tenancy.models import CaseRecord, SystemRecord, TenantRecords

#: The command that imports a tenant (R8: what every refusal of a tenant not imported names).
IMPORT_COMMAND = "tenant.py import"
#: The words a refusal names the import with.
NOT_IMPORTED = "its system records are not imported: run `tenant.py import {tenant}` first"


def author(command: str) -> str:
    """A version's author: the writing command's name (R9)."""
    return f"tenant.py {command}"


def _say(message: object) -> None:
    print(f"[tenant.py] {message}", file=sys.stderr)


def _now() -> _dt.datetime:
    return _dt.datetime.now(_dt.UTC)


def _dsn() -> str | None:
    """The records' database (`DEFENDER_DATABASE_DSN`), or a printed refusal and None."""
    variable = tenancy.database_address_variable()
    dsn = os.environ.get(variable, "")
    if not dsn:
        _say(f"{variable} is not set: system and case records are stored in the database")
    return dsn or None


def _store_call(dsn: str, call: Callable[[Any], Any]) -> Any:
    """`call(store)` on a fresh record store with the real judgement, closed after."""
    from defender.system_records import open_store

    async def go() -> Any:
        store = open_store(dsn, clock=_now)
        try:
            return await call(store)
        finally:
            await store.close()

    return asyncio.run(go())


def _written(dsn: str, call: Callable[[Any], Any]) -> tuple[bool, Any]:
    """`_store_call`, with a refusal or a database fault printed: `(True, result)` or `(False, None)`."""
    from sqlalchemy.exc import SQLAlchemyError

    from defender.system_records import RecordRefused

    try:
        return True, _store_call(dsn, call)
    except RecordRefused as refused:
        for fault in refused.faults:
            _say(fault)
        return False, None
    except (OSError, SQLAlchemyError) as fault:
        _say(f"the records could not be written: {type(fault).__name__}")
        return False, None


# ==========================================================================================
# catalog
# ==========================================================================================

def catalog(defender_dir: Path) -> int:
    """`catalog`: one block per adapter the checkout carries: its id and display name (and "example" for a lab
    example), each settings key as a record stores it, marked required, and its tools. tacit-knowledge is served by
    the platform and is no entry."""
    from defender.systems.catalog import Catalog
    from defender.systems.verbs import RegistryError

    try:
        entries = Catalog.of_checkout(defender_dir).entries()
    except RegistryError as unreadable:
        _say(f"the catalog could not be read: {unreadable}")
        return 1
    blocks = []
    for entry in entries:
        head = f"{entry.adapter_id}: {entry.display_name or '(no display name declared)'}"
        lines = [head + (" (example)" if entry.example else "")]
        if entry.unparsed is not None:
            lines.append(f"  not loadable: {entry.unparsed}")
        if entry.required_keys is None or entry.prefix is None:
            lines.append("  settings: not declared")
        elif not entry.stored_keys:
            lines.append("  settings: none")
        else:
            lines.append("  settings:")
            lines += [f"    {key} (required)" for key in entry.stored_keys]
        lines.append(f"  tools: {', '.join(sorted(entry.tools)) or 'none'}")
        blocks.append("\n".join(lines))
    print("\n\n".join(blocks))
    return 0


# ==========================================================================================
# import
# ==========================================================================================

def _export_settings(tenant: tenancy.Tenant) -> dict[str, bytes] | str:
    """Every file of the tenant's PUBLISHED current export's `settings/` (what runs read today), by path below it, or
    why it cannot be read."""
    try:
        export = tenancy.current_export(tenant)
        return tenancy.regular_files(export.path / tenancy.SETTINGS_HALF)
    except tenancy.DeliveryRefused as refused:
        return str(refused)


def import_candidate(files: Mapping[str, bytes]) -> tuple[TenantRecords, list[str]]:
    """The records a retired `settings/` folder (its files by relative path) stands for, and the faults of reading it
    (each naming the file): a system per `systems/<s>/` folder holding a `config.env` or an `access.yaml`, and the case
    record from `case-record.yaml` (#1359's rules)."""
    from defender.systems.system_folder import folder_of_bytes
    from defender.tenancy.case_ticket import CASE_RECORD_REL, CaseTicketError, parse_case_record

    locator = FolderLocator()
    names = sorted({rel.split("/")[1] for rel in files
                    if rel.startswith("systems/") and rel.count("/") == 2 and not rel.split("/")[1].startswith(".")
                    and rel.rsplit("/", 1)[1] in ("config.env", "access.yaml")})
    systems: dict[str, SystemRecord] = {}
    faults: list[str] = []
    for name in names:
        read = folder_of_bytes(name, config=files.get(f"systems/{name}/config.env"),
                               access=files.get(f"systems/{name}/access.yaml"), locator=locator)
        faults += read.faults
        systems[name] = SystemRecord(system_id=name, version=1, adapter_id=name, enabled=True,
                                     settings=dict(read.settings), access=read.access, credential_generation=1)
    case = None
    raw = files.get(CASE_RECORD_REL)
    if raw is not None:
        try:
            parsed = parse_case_record(raw.decode("utf-8"))
        except UnicodeDecodeError:
            faults.append(f"{locator.case()} is not UTF-8 text")
        except CaseTicketError as bad:
            faults.append(str(bad).replace(f"settings/{CASE_RECORD_REL}", locator.case(), 1))
        else:
            case = CaseRecord(version=1, system_id=parsed.system, comment_body=parsed.body)
    return TenantRecords(imported=True, systems=systems, case=case), faults


def run_import(admitted: Any, *, dry_run: bool) -> int:
    """`import <id> [--dry-run]` (O9, R13): the published export's `settings/systems/<s>/` folders and
    `settings/case-record.yaml` become first versions at generation 1, and the tenant is marked imported, in one
    transaction; any fault refuses the whole import, each fault naming the file to fix. The dry run lists every fault
    and writes nothing. No secret is read, copied or written: each system has no credentials until `set-credentials`."""
    from defender.systems.record_judgement import judge_records

    tenant = admitted.tenant
    if admitted.directory.current_records(tenant.id).imported:
        _say(f"tenant {tenant.id} is already imported: `{IMPORT_COMMAND}` runs once per tenant, and nothing was "
             "written; change its records with set-system, delete-system, set-case and delete-case")
        return 1
    files = _export_settings(tenant)
    if isinstance(files, str):
        _say(f"the import reads the tenant's published export, which could not be read: {files}")
        return 1
    records, faults = import_candidate(files)
    # The folder locator first, so each fault names the file the operator fixes in the tenant's repo.
    faults += judge_records(records, locator=FolderLocator())
    for fault in faults:
        _say(fault)
    what = (f"{len(records.systems)} system record(s)"
            + (f" and the case record (case system {records.case.system_id})" if records.case else ", no case record"))
    if faults:
        _say(f"the import of tenant {tenant.id} is refused ({len(faults)} fault(s)): nothing was written")
        return 1
    if dry_run:
        print(f"the import of tenant {tenant.id} would write {what}; nothing was written (dry run)")
        return 0
    dsn = _dsn()
    if dsn is None:
        return 1
    done, _ = _written(dsn, lambda store: store.import_tenant(tenant.id, records, author=author("import")))
    if not done:
        return 1
    print(f"imported tenant {tenant.id}: {what}, each at version 1, credential generation 1. No credentials were "
          "copied: set each system's with `tenant.py set-credentials`")
    return 0


# ==========================================================================================
# set-system / delete-system / set-case / delete-case
# ==========================================================================================

def run_set_system(admitted: Any, system: str, folder: Path, *, replaces: int, disabled: bool) -> int:
    """`set-system`: the folder's `config.env` and `access.yaml` as `system`'s next version (its adapter is the catalog
    adapter of that id), enabled unless `--disabled`."""
    from defender.systems.system_folder import read_folder

    dsn = _dsn()
    if dsn is None:
        return 1
    read = read_folder(folder, system, locator=RECORDS)
    if read.faults:
        for fault in read.faults:
            _say(fault)
        return 1
    done, record = _written(dsn, lambda store: store.put_system(
        admitted.tenant.id, system, replaces=replaces, adapter=system, enabled=not disabled,
        settings=dict(read.settings), access=read.access, author=author("set-system")))
    if not done:
        return 1
    print(f"system {system}: version {record.version} stored ({'disabled' if disabled else 'enabled'}), credential "
          f"generation {record.credential_generation}")
    return 0


def run_delete_system(admitted: Any, system: str, *, replaces: int) -> int:
    dsn = _dsn()
    if dsn is None:
        return 1
    done, _ = _written(dsn, lambda store: store.delete_system(admitted.tenant.id, system, replaces=replaces,
                                                              author=author("delete-system")))
    if not done:
        return 1
    print(f"system {system}: deleted as version {replaces + 1}")
    return 0


def _case_of_file(file: Path) -> Any:
    """The case record `file` holds (#1359's format and rules), or a printed refusal and None."""
    from defender.tenancy.case_ticket import CASE_RECORD_REL, CaseTicketError, parse_case_record
    from defender.tenancy.tenant_settings import read_regular_bytes

    try:
        text = read_regular_bytes(Path(file)).decode("utf-8")
    except (OSError, UnicodeDecodeError) as unreadable:
        _say(f"{file} cannot be read as UTF-8 text: {type(unreadable).__name__}")
        return None
    try:
        return parse_case_record(text)
    except CaseTicketError as bad:
        _say(str(bad).replace(f"settings/{CASE_RECORD_REL}", str(file), 1))
        return None


def run_set_case(admitted: Any, file: Path, *, replaces: int) -> int:
    dsn = _dsn()
    if dsn is None:
        return 1
    parsed = _case_of_file(file)
    if parsed is None:
        return 1
    done, case = _written(dsn, lambda store: store.put_case(admitted.tenant.id, replaces=replaces,
                                                            system_id=parsed.system, comment_body=parsed.body,
                                                            author=author("set-case")))
    if not done:
        return 1
    print(f"the case record: version {case.version} stored (case system {case.system_id})")
    return 0


def run_delete_case(admitted: Any, *, replaces: int) -> int:
    dsn = _dsn()
    if dsn is None:
        return 1
    done, _ = _written(dsn, lambda store: store.delete_case(admitted.tenant.id, replaces=replaces,
                                                            author=author("delete-case")))
    if not done:
        return 1
    print(f"the case record: deleted as version {replaces + 1}")
    return 0


# ==========================================================================================
# systems
# ==========================================================================================

def _has_credentials(secrets: Any, tenant_id: object, record: SystemRecord) -> bool:
    return bool(asyncio.run(secrets.has_credentials(str(tenant_id), record.system_id,
                                                    generation=record.credential_generation)))


def run_systems(admitted: Any, *, export: Path | None, secrets: Any) -> int:
    """`systems <id>`: one line per current system (deleted ones are gone): its version, credential generation,
    enabled or disabled, and whether credentials are stored at that generation (asked of the secret store's
    metadata). `--export <dir>` writes each as `<dir>/<system>/{config.env,access.yaml}`, the folder `set-system`
    takes."""
    from defender.systems.system_folder import config_text

    tenant = admitted.tenant
    records = admitted.directory.current_records(tenant.id)
    if not records.imported:
        _say(f"tenant {tenant.id}: " + NOT_IMPORTED.format(tenant=tenant.id))
        return 1
    if export is not None:
        for system, record in sorted(records.systems.items()):
            folder = Path(export) / system
            folder.mkdir(parents=True, exist_ok=True)
            if record.settings:
                (folder / "config.env").write_text(config_text(record.settings), encoding="utf-8")
            (folder / "access.yaml").write_text(record.access, encoding="utf-8")
        print(f"wrote {len(records.systems)} system folder(s) under {export}")
        return 0
    for system, record in sorted(records.systems.items()):
        if secrets is None:
            held = "credentials not checked (give --token-file)"
        else:
            try:
                held = ("credentials stored" if _has_credentials(secrets, tenant.id, record)
                        else "no credentials at the current generation")
            except Exception as e:  # noqa: BLE001 — one unanswered question is that line's, not the listing's
                held = f"credentials unknown ({type(e).__name__})"
        print(f"{system}: version {record.version}, generation {record.credential_generation}, "
              f"{'enabled' if record.enabled else 'disabled'}, {held}")
    if records.case is not None:
        print(f"the case record: version {records.case.version}")
    return 0


# ==========================================================================================
# set-credentials
# ==========================================================================================

def _credential_file(file: Path) -> tuple[str, dict[str, str]] | None:
    """The `{kind, fields}` set `file` holds, or a printed refusal and None. Never prints a value."""
    from defender.tenancy.tenant_settings import read_regular_bytes

    try:
        data = json.loads(read_regular_bytes(Path(file)).decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as unreadable:
        _say(f"{file} cannot be read as a JSON credential set: {type(unreadable).__name__}")
        return None
    if not (isinstance(data, dict) and set(data) == {"kind", "fields"} and isinstance(data["kind"], str)
            and isinstance(data["fields"], dict)
            and all(isinstance(k, str) and isinstance(v, str) for k, v in data["fields"].items())):
        _say(f"{file} must hold one JSON object {{\"kind\": ..., \"fields\": {{name: text}}}}")
        return None
    return data["kind"], dict(data["fields"])


def run_set_credentials(admitted: Any, system: str, file: Path, *, for_version: int, secrets: Any) -> int:
    """`set-credentials` (O8): the set is written at the generation path of the system version it was prepared for,
    which must be the current one (disabled included). The version is read again after the write: if another
    operator wrote the system meanwhile, the command reports the refusal (the set left at the old version's path is
    never read for the new one)."""
    from defender.kit.faults import ConfigFault

    tenant = admitted.tenant
    loaded = _credential_file(file)
    if loaded is None:
        return 1
    kind, fields = loaded
    current = _current_system(admitted, system, for_version)
    if current is None:
        return 1
    try:
        asyncio.run(secrets.put_credentials(str(tenant.id), system, kind, fields,
                                            generation=current.credential_generation))
    except ConfigFault as refused:
        _say(f"system {system}: the credentials were not written: {refused}")
        return 1
    after = admitted.directory.current_records(tenant.id).systems.get(system)
    if after is None or after.version != current.version:
        now = "it has no current record" if after is None else f"version {after.version} is now current"
        _say(f"system {system}: it was written while its credentials were stored for version {for_version}, and {now}: "
             f"the set stored at generation {current.credential_generation} serves only that version; prepare the "
             "credentials for the current version and set them again")
        return 1
    print(f"system {system}: credentials stored for version {for_version} at credential generation "
          f"{current.credential_generation}")
    return 0


def _current_system(admitted: Any, system: str, for_version: int) -> SystemRecord | None:
    tenant = admitted.tenant
    records = admitted.directory.current_records(tenant.id)
    if not records.imported:
        _say(f"tenant {tenant.id}: " + NOT_IMPORTED.format(tenant=tenant.id))
        return None
    current = records.systems.get(system)
    if current is None:
        _say(f"system {system} has no current record (never written, or deleted): credentials are set only for a "
             "current system")
        return None
    if current.version != for_version:
        _say(f"system {system}: the credentials were prepared for version {for_version}, but version {current.version} "
             "is current: check its record (`tenant.py systems`) and prepare them for that version")
        return None
    return current


def operator_secrets(token_file: Path | None, *, mount: str) -> Any:
    """The operator's OpenBao login: the deployment's address, the token read from `token_file`; or a printed
    refusal and None."""
    from defender.credential_proxy import OpenBaoSecrets
    from defender.configuration.issuer import DEPLOYMENT_ISSUER
    from defender.tenancy.tenant_settings import read_regular_bytes

    if token_file is None:
        _say("this command needs the operator's OpenBao token: give --token-file <path>")
        return None
    try:
        token = read_regular_bytes(Path(token_file)).decode("utf-8").strip()
    except (OSError, UnicodeDecodeError) as unreadable:
        _say(f"{token_file} cannot be read as a token: {type(unreadable).__name__}")
        return None
    if not token:
        _say(f"{token_file} holds no token")
        return None
    return OpenBaoSecrets(addr=DEPLOYMENT_ISSUER.openbao_url, token=token, mount=mount)


__all__ = ["IMPORT_COMMAND", "NOT_IMPORTED", "author", "catalog", "import_candidate", "operator_secrets",
           "run_delete_case", "run_delete_system", "run_import", "run_set_case", "run_set_credentials",
           "run_set_system", "run_systems"]

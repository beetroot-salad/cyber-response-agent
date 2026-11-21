"""The adoption kind (#1471 A1-A3, R13-1): `--kind adoption --job <id> --tenant T --system S`, the helper half of one adoption.

Its host half, before the container: the tenant's lock and admission (`host_tenant`), the system's record re-read (the record
may be gone since the request was made), the worker's own catalog's base files for that system's adapter rendered (the release
ships them, or none: P-8), and the tenant's forge credential made (the container asks for tokens, G-A5). The container is then
handed the tenant, the system, the rendering and its digest, and the tenant's recorded forge wiring in the launch facts: it is
answered `launch` and `forge.token` and nothing else (N-A1: no pass, no box, no signing), and its entry is
`python3 -m defender.adoption --job <id> --tenant <T>`, which fetches, decides and delivers (`adoption/__main__.py`).

An ending the helper decides before the container is written here as the one create-only `{failed, reason}` record, in the
kind's own vocabulary (`job_lane.ADOPTION_HELPER_REASONS`): the record gone (`system_gone`), the release shipping none
(`no_base_files`), a tenant that is not active at claim (`tenant_not_active`), any other refusal of a setup step, the lock, the
credential or a tenant with no forge wiring (`setup_refused`), a container that cannot be started (`start_failed`), a crash
(`worker_error`). A stop before the container writes none: the stopping worker ends the row (R13-5)."""
from __future__ import annotations

import base64
import contextlib
from dataclasses import dataclass
from typing import Any, NoReturn

from . import _host_request
from ._learning import _TenantCredential, forge_token_answer
from ._session import KindSpec, Prepared, Registry, Session, SetupRefused

KIND = "adoption"


def _adoption_lane() -> _host_request.ResultLane:
    from defender.records import job_lane

    return _host_request.ResultLane(
        kind=KIND, read=lambda lane, rid: lane.read_adoption(rid), write=lambda lane, rid, rec: lane.write_adoption(rid, rec),
        failed=job_lane.AdoptionRecord.failed, refused_reason="setup_refused")


_LANE = _adoption_lane()


@dataclass
class _Adoption:
    """What an adoption's host half settled: the forge credential the container's `forge.token` asks are answered from."""

    credential: Any


def _refuse_adoption(session: Session, reason: str, why: str) -> NoReturn:
    """The helper's ending for a refusal it can name: the record, then `SetupRefused` (which ends the helper before any
    container starts, with the record kept: the shared ending writes `setup_refused` only when none is there)."""
    from defender.records import job_lane

    _host_request.write_once(session, _LANE, job_lane.AdoptionRecord.failed(reason))
    raise SetupRefused(why)


def _admit_adoption_tenant(session: Session, hold: contextlib.ExitStack) -> Any:
    from defender.records.formats import TenantRefused

    try:
        return _host_request.admit_host_tenant(session, hold)
    except TenantRefused as refused:
        state = _host_request.tenant_state(session)
        if state is not None and state != "active":
            _refuse_adoption(session, "tenant_not_active", f"this job's tenant is {state}, not active")
        _refuse_adoption(session, "setup_refused", f"this job's tenant cannot be used: {refused}")


def _render_for_system(session: Session, admitted: Any) -> tuple[dict[str, bytes], str]:
    """The release's rendering of the base files for the tenant's record of `session.system`, with its digest. The
    rendering is the release's alone: nothing of the tenant's own files is read."""
    from defender.records.formats import TenantRefused
    from defender.system_rules import Catalog, RegistryError, base_files

    system = str(session.system)
    try:
        record = admitted.directory.current_records(admitted.tenant.id).systems.get(system)
    except TenantRefused as refused:
        _refuse_adoption(session, "setup_refused", f"this job's tenant records cannot be read: {refused}")
    if record is None:
        _refuse_adoption(session, "system_gone", f"the tenant has no record of system {system!r} now")
    try:
        catalog = Catalog.of_checkout(session.defender_dir)
        entry = catalog.entry(record.adapter_id) if record.adapter_id in catalog else None
    except RegistryError as unreadable:
        _refuse_adoption(session, "setup_refused", f"the adapters cannot be read: {unreadable}")
    if entry is None or entry.base_files is None:
        _refuse_adoption(session, "no_base_files", f"this release ships no base files for adapter {record.adapter_id!r}")
    try:
        rendering = base_files.render(entry, system)
    except ValueError as unrenderable:
        _refuse_adoption(session, "setup_refused", f"the base files cannot be rendered: {unrenderable}")
    return rendering, base_files.digest(rendering)


def _adoption_credential(session: Session, admitted: Any, cleanup: contextlib.ExitStack) -> Any:
    """The tenant's forge credential (the helper's seam, else the live generation's), made now so a credential that cannot be
    made is a setup refusal; nothing is minted until the container asks."""
    try:
        if session.forge is not None:
            return _TenantCredential(session.forge(session.tenant_id, KIND), session.tenant_id)
        from defender.learning.author.version_control import forge_credential

        built = forge_credential(admitted.tenant.id, KIND, directory=admitted.directory, config=None)
        cleanup.callback(built.close)
        return built
    except Exception as failed:  # noqa: BLE001 — any fault making the credential is a refused setup
        _refuse_adoption(session, "setup_refused", f"the tenant's forge credential cannot be made: {type(failed).__name__}: {failed}")


def prepare_adoption(session: Session, hold: contextlib.ExitStack) -> Prepared:
    admitted = _admit_adoption_tenant(session, hold)
    rendering, digest = _render_for_system(session, admitted)
    wiring = admitted.wiring
    if wiring is None or not wiring.origin:
        _refuse_adoption(session, "setup_refused", "the tenant has no forge wiring recorded")
    cleanup = contextlib.ExitStack()
    try:
        credential = _adoption_credential(session, admitted, cleanup)
    except BaseException:
        cleanup.close()
        raise
    job = _host_request.request_id(session)
    command = session.command or ["python3", "-m", "defender.adoption", "--job", job, "--tenant", session.tenant_id]
    facts = {"kind": KIND, "tenant": session.tenant_id, "job": job, "tenant_state": "active", "system": session.system,
             "digest": digest, "rendering": {path: base64.b64encode(data).decode("ascii") for path, data in rendering.items()},
             "forge_origin": wiring.origin, "forge_repo": wiring.repo}
    return Prepared(launch=facts, command=list(command), state=_Adoption(credential), cleanup=cleanup, exited=_host_request.after_container(_LANE))


def _adoption_forge_token(session: Session, fields: dict[str, Any]) -> dict[str, Any]:
    state = session.prepared.state if session.prepared is not None else None
    from defender.job_socket import Refused

    if not isinstance(state, _Adoption):
        raise Refused("the job is not set up", "internal")
    return forge_token_answer(fields, lambda: state.credential)


def register_adoption(registry: Registry) -> None:
    """The adoption kind's hooks and its own request, `forge.token` (`after_signal`: the container unwinds); `launch` is
    every kind's (`register_common`)."""
    registry.kind(KIND, KindSpec(prepare=prepare_adoption, end=_host_request.end_before_container(_LANE)))
    registry.add("forge.token", kinds=(KIND,), handler=_adoption_forge_token, required=("min_validity",), after_signal=True)

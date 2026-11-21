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
import logging
import sys
from dataclasses import dataclass
from typing import Any, NoReturn

from ._learning import _TenantCredential, forge_token_answer
from ._session import DOCKER_DID_NOT_RUN, KindSpec, Prepared, Registry, Session, SetupRefused

_logger = logging.getLogger(__name__)

KIND = "adoption"


@dataclass
class _Adoption:
    """What an adoption's host half settled: the forge credential the container's `forge.token` asks are answered from."""

    credential: Any


def _write_failed(session: Session, reason: str) -> None:
    """The helper's own `{failed, reason}` record, create-only: one already there is kept. One that cannot be written
    raises, so the helper exits non-zero, which the worker reads as the helper's own failure."""
    from defender.records import job_lane

    with job_lane.JobLane.open(session.root, session.tenant_id) as lane:
        if lane.read_adoption(str(session.job_id)) is not None:
            return
        lane.write_adoption(str(session.job_id), job_lane.AdoptionRecord.failed(reason))


def _refuse_adoption(session: Session, reason: str, why: str) -> NoReturn:
    """The helper's ending for a refusal it can name: the record, then `SetupRefused` (which ends the helper before any
    container starts, with the record kept: `adoption_end` writes `setup_refused` only when none is there)."""
    _write_failed(session, reason)
    raise SetupRefused(why)


def _state_now(session: Session) -> str | None:
    """The tenant's state as the records say it now, or None when it cannot be read or the tenant is unknown."""
    from defender.records.formats import TenantId
    from defender.systems.run_tenant import entry_directory

    try:
        return entry_directory(None).state(TenantId(session.tenant_id))
    except Exception:  # noqa: BLE001 — a state that cannot be read is no reason to call the refusal anything finer
        return None


def _admit_adoption_tenant(session: Session, hold: contextlib.ExitStack) -> Any:
    from defender.records.formats import TenantRefused
    from defender.systems.run_tenant import host_tenant

    try:
        admitted = host_tenant(session.root, session.tenant_id, defender_dir=session.defender_dir)
    except TenantRefused as refused:
        state = _state_now(session)
        if state is not None and state != "active":
            _refuse_adoption(session, "tenant_not_active", f"this job's tenant is {state}, not active")
        _refuse_adoption(session, "setup_refused", f"this job's tenant cannot be used: {refused}")
    hold.enter_context(admitted)
    session.tenant_accepted(admitted.tenant)
    return admitted


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
    job = str(session.job_id)
    command = session.command or ["python3", "-m", "defender.adoption", "--job", job, "--tenant", session.tenant_id]
    facts = {"kind": KIND, "tenant": session.tenant_id, "job": job, "tenant_state": "active", "system": session.system,
             "digest": digest, "rendering": {path: base64.b64encode(data).decode("ascii") for path, data in rendering.items()},
             "forge_origin": wiring.origin, "forge_repo": wiring.repo}
    return Prepared(launch=facts, command=list(command), state=_Adoption(credential), cleanup=cleanup, exited=_adoption_exited)


def adoption_end(session: Session, cause: str) -> None:
    """The adoption's `{failed, reason}` record for an ending decided before the container (module doc). A stop writes
    none; a refusal keeps the record its step wrote."""
    if cause == "start-failed" and session.signalled.is_set():
        return
    _write_failed(session, {"refused": "setup_refused", "start-failed": "start_failed"}.get(cause, "worker_error"))


def _adoption_exited(session: Session, rc: int) -> None:
    """After the container: a `docker run` that never ran the job (and so wrote no record) is a start failure."""
    from defender.records import job_lane

    if rc not in DOCKER_DID_NOT_RUN:
        return
    try:
        with job_lane.JobLane.open(session.root, session.tenant_id) as lane:
            written = lane.read_adoption(str(session.job_id)) is not None
    except (OSError, job_lane.JobLaneRefused):
        written = False
    if not written:
        sys.stderr.write(f"[job_host] adoption {session.job_id}: the job container did not start (docker exit {rc}); "
                         "the job ran nowhere\n")
        adoption_end(session, "start-failed")


def _adoption_forge_token(session: Session, fields: dict[str, Any]) -> dict[str, Any]:
    state = session.prepared.state if session.prepared is not None else None
    from defender.job_socket import Refused

    if not isinstance(state, _Adoption):
        raise Refused("the job is not set up", "internal")
    return forge_token_answer(fields, lambda: state.credential)


def register_adoption(registry: Registry) -> None:
    """The adoption kind's hooks and its two requests: `launch` and `forge.token` (`after_signal`: the container unwinds)."""
    registry.kind(KIND, KindSpec(prepare=prepare_adoption, end=adoption_end))
    registry.add("launch", kinds=(KIND,), handler=lambda session, _fields: session.launch(), after_signal=True)
    registry.add("forge.token", kinds=(KIND,), handler=_adoption_forge_token, required=("min_validity",), after_signal=True)

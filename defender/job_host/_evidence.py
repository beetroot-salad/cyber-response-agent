"""The helper's evidence half (#1546 PR2, PR7, PR8, A-O3, A-O6; flow steps 2-3): what a job stages and pushes, and what it
pulls.

**Facts.** Every record verb (`outcome`, `page`, `arms`, `arm`, `progress`, `result`) is parsed on receipt
(`_records`) and staged as one closed fact under the job's claim through the job store (`_rows.Rows.stage`), which
checks the claim is live in the same transaction (PR7). A malformed record is staged `refused/<name>{reason}` instead
(a `progress` is dropped and logged: it is replaced, never decided on). `arm/<run id>` is staged only for a run the
staged roster names. Facts are create-once; `progress` is replaced.

**Pushes.** `evidence.put(object=, part=, last=, data=[, sha256=])` streams one object in order into the claim's private
spool (`<root>/.job-spool/<claim>/`, bound into nothing); a gap, a repeat, a part out of order or a last part whose digest
is not the bytes' refuses the object and removes its bytes. The object must be one the job's kind pushes, and owed by a
staged fact (PR8: the bundle and the episode page by an outcome or a refused one, the run page by `page = rendered`, an
arm's page by its `arm/<id>` fact `page = rendered`), at its first part, or the put is refused at once. Nothing is stored
while the job runs: once its container has exited, each whole object is uploaded (`upload_all`): its row `pending`
first (a fresh data key per object, wrapped by the tenant's key), one PUT of the spooled file, then `uploaded`, or
`refused` once its budget (`upload_budget`, 120 s; after a stop, never past 30 s from it) is spent. A row the store
refuses to begin (the claim ended) is no upload at all.

**Pulls.** `evidence.pull(owner=, object=, part=)` answers an object of the claim's fixed input set, whole and checked
against its recorded digest, in parts: `out_of_claim` for anything outside the set, `unavailable` for a member that is not
usable now, `store_fault` when the store does not give the accepted bytes (retried by asking again)."""
from __future__ import annotations

import contextlib
import hashlib
import logging
import os
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from defender._io import read_text_utf8
from defender.evidence import object_key
from defender.job_socket import Refused
from defender.jobs.models import ClaimView
from defender.records.job_facts import BUNDLE, EPISODE_PAGE, RUN_PAGE

from . import _records
from ._rows import STORE_FAULT, Rows
from ._session import Registry, Session

_logger = logging.getLogger(__name__)

INVESTIGATION, LEARNING, DRAIN = "investigation", "learning", "drain"
#: The job kinds that push and pull evidence (and need the store and the key login at setup).
EVIDENCE_KINDS = (INVESTIGATION, LEARNING)
HOST_REQUEST_KINDS = ("readiness", "adoption", DRAIN)

_ARM_PAGE = re.compile(r"page/runs/([0-9a-f-]{36})/runtime\.html")
#: The largest part a put carries, and the largest object of each class.
PART_CAP = 8 * 1024 * 1024
_PAGE_CAP = 64 * 1024 * 1024
_BUNDLE_CAP = 8 * 1024 * 1024 * 1024
#: A pull's part size.
PULL_PART = 4 * 1024 * 1024
#: The design's per-object upload budget, and how long uploads go on after the helper is told to stop.
UPLOAD_BUDGET = 120.0
STOP_GRACE = 30.0
_BACKOFF = (0.5, 1.0, 2.0, 4.0)
_SHA = re.compile(r"[0-9a-f]{64}")


@dataclass
class _Spooled:
    """One object being pushed: its spool file, the next part it takes, the running digest and size."""

    path: Path
    scrub: str | None
    next_part: int = 0
    size: int = 0
    digest: Any = field(default_factory=hashlib.sha256)
    done: bool = False
    refused: bool = False


@dataclass
class _Pulled:
    path: Path
    size: int


@dataclass
class Evidence:
    """One claim's evidence state for the helper's life (module doc)."""

    rows: Rows
    claim: ClaimView
    kind: str
    job_id: str | None
    spool: Path | None
    store: Any = None
    keys: Any = None
    budget: float = UPLOAD_BUDGET
    #: What this helper staged under the claim (it is the claim's one stager), by name.
    staged: dict[str, Any] = field(default_factory=dict)
    roster: frozenset[str] | None = None
    objects: dict[str, _Spooled] = field(default_factory=dict)
    pulled: dict[tuple[str, str], _Pulled] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _counter: int = 0

    # --- facts ---------------------------------------------------------------------------------------------------

    def stage(self, name: str, body: Any) -> bool:
        """`name` staged (False when the store refused it: the claim ended, or it is staged already)."""
        if not self.rows.stage(self.claim.token, name, body):
            return False
        with self.lock:
            if name == "progress" or name not in self.staged:
                self.staged[name] = body
        return True

    def stage_refused(self, name: str, reason: str) -> None:
        self.stage(f"refused/{name}", {"reason": reason[:2000]})

    def has(self, name: str) -> bool:
        with self.lock:
            return name in self.staged

    def fact(self, name: str) -> Any:
        with self.lock:
            return self.staged.get(name)

    # --- pushes --------------------------------------------------------------------------------------------------

    def owed(self, obj: str) -> str | None:
        """`obj`'s upload-row scrub when the staged facts owe it (PR8), else a `Refused`."""
        owed_by_outcome = self.has("outcome") or self.has("refused/outcome")
        if self.kind == INVESTIGATION and obj == BUNDLE or self.kind == LEARNING and obj in (BUNDLE, EPISODE_PAGE):
            if not owed_by_outcome:
                raise Refused(f"{obj!r} is owed by the job's outcome, which is not staged", "not-owed")
            return None
        if self.kind == INVESTIGATION and obj == RUN_PAGE:
            page = self.fact("page")
            if not (isinstance(page, dict) and page.get("page") == "rendered"):
                raise Refused("the run page is owed only by a staged page fact that says rendered", "not-owed")
            return None
        found = _ARM_PAGE.fullmatch(obj) if self.kind == LEARNING else None
        if found is not None:
            fact = self.fact(f"arm/{found.group(1)}")
            if not (isinstance(fact, dict) and fact.get("page") == "rendered"):
                raise Refused("an arm's page is owed only by its arm fact that says rendered", "not-owed")
            return str(fact.get("scrub"))
        raise Refused(f"{obj!r} is no object a {self.kind} job pushes", "bad-object")

    def put(self, fields: dict[str, Any]) -> dict[str, Any]:
        obj, part, last, data = fields["object"], fields["part"], fields["last"], fields["data"]
        sha = fields.get("sha256")
        if not isinstance(obj, str) or isinstance(part, bool) or not isinstance(part, int) or part < 0 \
                or not isinstance(last, bool) or not isinstance(data, bytes) or len(data) > PART_CAP \
                or (sha is not None and not (isinstance(sha, str) and _SHA.fullmatch(sha))):
            raise Refused("evidence.put takes an object name, a part number, last, the part's bytes (at most "
                          f"{PART_CAP}) and optionally the object's sha256", "bad-fields")
        if self.spool is None:
            raise Refused("this job has no spool", "internal")
        with self.lock:
            spooled = self.objects.get(obj)
        if spooled is None:
            scrub = self.owed(obj)
            with self.lock:
                spooled = self.objects.get(obj)
                if spooled is None:
                    self._counter += 1
                    spooled = _Spooled(self.spool / f"object-{self._counter}", scrub)
                    self.objects[obj] = spooled
        with self.lock:
            return self._take(obj, spooled, part, last, data, sha)

    def _take(self, obj: str, s: _Spooled, part: int, last: bool, data: bytes, sha: str | None) -> dict[str, Any]:
        if s.refused:
            raise Refused(f"{obj!r} was refused earlier in its stream", "bad-part")
        if s.done or part != s.next_part:
            self._drop(s)
            raise Refused(f"{obj!r} part {part} is out of its stream (next is {s.next_part})", "bad-part")
        cap = _BUNDLE_CAP if obj == BUNDLE else _PAGE_CAP
        if s.size + len(data) > cap:
            self._drop(s)
            raise Refused(f"{obj!r} is over its {cap}-byte cap", "too-large")
        with s.path.open("ab" if part else "xb") as out:
            out.write(data)
        s.size += len(data)
        s.digest.update(data)
        s.next_part += 1
        if not last:
            return {"part": part}
        digest = s.digest.hexdigest()
        if sha is not None and sha != digest:
            self._drop(s)
            raise Refused(f"{obj!r} does not match the digest its last part named", "digest-mismatch")
        s.done = True
        return {"size": s.size, "sha256": digest}

    @staticmethod
    def _drop(s: _Spooled) -> None:
        s.refused = True
        with contextlib.suppress(OSError):
            s.path.unlink()

    def upload_all(self, *, signalled_at: float | None) -> None:
        """Each whole spooled object stored (module doc), after the container exited; the spool is the caller's to
        remove."""
        with self.lock:
            ready = [(obj, s) for obj, s in self.objects.items() if s.done and not s.refused]
        for obj, s in ready:
            self._upload(obj, s, signalled_at)

    def _upload(self, obj: str, s: _Spooled, signalled_at: float | None) -> None:
        from defender.evidence import BlobStoreError, EvidenceKeyError

        start = time.monotonic()
        deadline = start + self.budget
        if signalled_at is not None:
            deadline = min(deadline, signalled_at + STOP_GRACE)
        token, tenant = self.claim.token, self.claim.tenant_id
        digest = s.digest.hexdigest()
        try:
            made = self.keys.datakey(tenant)
        except EvidenceKeyError as fault:
            _logger.error("%s was not stored: no data key could be made: %s", obj, fault)
            self.rows.refuse_upload(token, obj, scrub=s.scrub)
            return
        if not self.rows.begin_upload(token, obj, size=s.size, sha256=digest, wrapped_key=made.wrapped, scrub=s.scrub):
            return
        key = object_key(tenant, self._owner_kind(), str(self.claim.reference), token, obj)
        status = "refused"
        attempt = 0
        while True:
            try:
                self.store.put(key, s.path, data_key=made.plaintext, sha256=digest)
                status = "uploaded"
                break
            except BlobStoreError as fault:
                wait = _BACKOFF[min(attempt, len(_BACKOFF) - 1)]
                attempt += 1
                if not fault.retryable or time.monotonic() + wait >= deadline:
                    _logger.error("%s was not stored (attempt %d): %s", obj, attempt, fault)
                    break
                _logger.warning("%s: the store did not take it (attempt %d), retrying: %s", obj, attempt, fault)
                time.sleep(wait)
        self.rows.finish_upload(token, obj, status=status)

    def _owner_kind(self) -> str:
        return LEARNING if self.kind == LEARNING else INVESTIGATION

    # --- pulls ---------------------------------------------------------------------------------------------------

    def pull(self, fields: dict[str, Any]) -> dict[str, Any]:
        owner, obj, part = fields["owner"], fields["object"], fields["part"]
        if isinstance(part, bool) or not isinstance(part, int) or part < 0:
            raise Refused("evidence.pull takes an owner, an object and a part number", "bad-fields")
        found = self.rows.input_object(self.claim, owner, obj)
        if isinstance(found, str):
            raise Refused(f"the pull of {obj!r} of {owner!r} is refused", found)
        at = (str(owner), str(obj))
        with self.lock:
            pulled = self.pulled.get(at)
        if pulled is None:
            pulled = self._fetch(at, found)
        with pulled.path.open("rb") as source:
            source.seek(part * PULL_PART)
            data = source.read(PULL_PART)
        return {"data": data, "last": (part + 1) * PULL_PART >= pulled.size}

    def _fetch(self, at: tuple[str, str], found: Any) -> _Pulled:
        from defender.evidence import BlobStoreError, EvidenceKeyError

        if self.spool is None or self.store is None or self.keys is None:
            raise Refused("this job reads no evidence store", STORE_FAULT)
        with self.lock:
            self._counter += 1
            dest = self.spool / f"pull-{self._counter}"
        try:
            key = self.keys.unwrap(self.claim.tenant_id, found.wrapped_key)
            size = self.store.download(found.key, dest, data_key=key)
        except (BlobStoreError, EvidenceKeyError, OSError) as fault:
            with contextlib.suppress(OSError):
                dest.unlink()
            _logger.warning("the pull of %s of %s found no accepted bytes: %s", at[1], at[0], fault)
            raise Refused("the store did not give the accepted object", STORE_FAULT) from None
        if size != found.size or _file_digest(dest) != found.sha256:
            with contextlib.suppress(OSError):
                dest.unlink()
            raise Refused("the stored object does not match its recorded digest", STORE_FAULT)
        pulled = _Pulled(dest, size)
        with self.lock:
            self.pulled.setdefault(at, pulled)
        return pulled


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


# --- the store and the key login, at setup ------------------------------------------------------------------------------

_ENV = "DEFENDER_EVIDENCE_"
_REQUIRED = ("ENDPOINT", "BUCKET", "ACCESS_KEY", "SECRET_KEY")


def store_from_env(environ: Any = os.environ) -> Any:
    """The blob store `DEFENDER_EVIDENCE_*` names, or None when any of the four required settings is unset."""
    from defender.evidence import BlobStore

    values = {name: (environ.get(f"{_ENV}{name}") or "").strip() for name in _REQUIRED}
    if not all(values.values()):
        return None
    return BlobStore(endpoint=values["ENDPOINT"], bucket=values["BUCKET"], access_key=values["ACCESS_KEY"],
                     secret_key=values["SECRET_KEY"], region=(environ.get(f"{_ENV}REGION") or "garage").strip())


def keys_from_generation(session: Session) -> Any:
    """The evidence-key login the tenant's live generation records (its evidence AppRole and secret file), or None when
    it records none or the secret cannot be read."""
    from defender import tenancy
    from defender.configuration.issuer import DEPLOYMENT_ISSUER
    from defender.evidence import EvidenceKeys
    from defender.records.formats import TenantId
    from defender.systems.run_tenant import entry_directory

    try:
        generation = tenancy.live_generation(entry_directory(session.directory), TenantId(session.tenant_id))
    except Exception as unknown:  # noqa: BLE001 — a generation that cannot be read records no login
        _logger.warning("the tenant's live generation cannot be read for its evidence login: %s", unknown)
        return None
    role, secret_file = getattr(generation, "evidence_role_id", None), getattr(generation, "evidence_secret_file", None)
    if not role or not secret_file or not Path(secret_file).is_absolute():
        return None
    try:
        secret = read_text_utf8(Path(secret_file)).strip()
    except OSError as unreadable:
        _logger.warning("the evidence login's secret file cannot be read: %s", unreadable)
        return None
    if not secret or not DEPLOYMENT_ISSUER.openbao_url:
        return None
    return EvidenceKeys(addr=DEPLOYMENT_ISSUER.openbao_url, role_id=str(role), secret_id=secret, mount="approle")


# --- the requests ---------------------------------------------------------------------------------------------------------

def state(session: Session) -> Evidence:
    found = session.evidence_state
    if not isinstance(found, Evidence):
        raise Refused("this job stages nothing: it has no claim", "internal")
    return found


def _record_verb(name: str, parse: Any) -> Any:
    """A verb staging `name` from its record: the body `parse` answers, else `refused/<name>`."""
    def handler(session: Session, fields: dict[str, Any]) -> dict[str, Any]:
        ev = state(session)
        try:
            body = parse(ev, fields.get("record"))
        except _records.Malformed as bad:
            ev.stage_refused(name, str(bad))
            raise Refused(f"the {name} record is refused: {bad}", "bad-record") from None
        if not ev.stage(name, body):
            raise Refused(f"{name} was not staged: the claim is not live, or it is staged already", "not-staged")
        return {"staged": name}

    return handler


def _outcome_record(ev: Evidence, record: Any) -> Any:
    if ev.kind == LEARNING:
        return _records.learning_outcome(record, str(ev.job_id))
    return _records.investigation_outcome(record)


def _answer_arms(session: Session, fields: dict[str, Any]) -> dict[str, Any]:
    ev = state(session)
    answer = _record_verb("arms", lambda _ev, r: _records.arms(r))(session, fields)
    roster = ev.fact("arms")
    with ev.lock:
        ev.roster = frozenset(e["run_id"] for e in roster["roster"])
    return answer


def _arm(session: Session, fields: dict[str, Any]) -> dict[str, Any]:
    ev = state(session)
    run = _records.canonical_run_id(fields["run_id"])
    with ev.lock:
        roster = ev.roster
    if run is None or roster is None or run not in roster:
        raise Refused("an arm fact is staged only for a run the staged roster names", "not-on-roster")
    return _record_verb(f"arm/{run}", lambda _ev, r: _records.arm(r))(session, fields)


def _progress(session: Session, fields: dict[str, Any]) -> dict[str, Any]:
    ev = state(session)
    parse = _records.learning_progress_record if ev.kind == LEARNING else _records.investigation_progress_record
    try:
        body = parse(fields.get("record"))
    except _records.Malformed as bad:
        _logger.info("a progress record was dropped: %s", bad)
        raise Refused(f"the progress record is dropped: {bad}", "bad-record") from None
    if not ev.stage("progress", body):
        raise Refused("progress was not staged: the claim is not live", "not-staged")
    return {"staged": "progress"}


def _result(session: Session, fields: dict[str, Any]) -> dict[str, Any]:
    parse = _records.RESULTS[session.kind]
    if session.kind == "readiness":
        from ._readiness import with_host_warnings  # here: the readiness kind imports this module

        return _record_verb("result", lambda _ev, r: with_host_warnings(session, parse(r)))(session, fields)
    return _record_verb("result", lambda _ev, r: parse(r))(session, fields)


def register_evidence(registry: Registry) -> None:
    """The record verbs and the object requests, each for the kinds that send it; all still answered once the helper is
    told to stop, so a job that unwinds can record its end and push what it owes."""
    registry.add("outcome", kinds=EVIDENCE_KINDS, handler=_record_verb("outcome", _outcome_record), optional=("record",),
                 after_signal=True)
    registry.add("page", kinds=(INVESTIGATION,), handler=_record_verb("page", lambda _ev, r: _records.page(r)),
                 optional=("record",), after_signal=True)
    registry.add("arms", kinds=(LEARNING,), handler=_answer_arms, optional=("record",), after_signal=True)
    registry.add("arm", kinds=(LEARNING,), handler=_arm, required=("run_id",), optional=("record",), after_signal=True)
    registry.add("progress", kinds=EVIDENCE_KINDS, handler=_progress, optional=("record",), after_signal=True)
    registry.add("result", kinds=HOST_REQUEST_KINDS, handler=_result, optional=("record",), after_signal=True)
    registry.add("evidence.put", kinds=EVIDENCE_KINDS, handler=lambda s, f: state(s).put(f),
                 required=("object", "part", "last", "data"), optional=("sha256",), after_signal=True)
    # A drain pulls its input set and unpacks it in its own container (#1546 r10, H3); it pushes nothing.
    registry.add("evidence.pull", kinds=(*EVIDENCE_KINDS, DRAIN), handler=lambda s, f: state(s).pull(f),
                 required=("owner", "object", "part"))



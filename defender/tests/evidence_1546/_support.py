"""#1546 (piece A of #1082) sketch against draft design r6: the new rows read and (as the helper would stage them)
written by SQL, the test blob store and its raw S3 oracle, and the bundle oracle.

SKETCH (contract-first, draft r6, unreviewed). Every name below that r6 implies but `main` lacks is a SEAM PICK,
listed once here so write-tests can rename it in one place. "FORCED CHOICE" marks a pick r6 does not make; the
report (`.contract-first/1546/sketch-r6-report.md`) lists each with the case that exposed it.

Seam picks (names only; r6 fixes the content, not the spelling):
- `jobs.claims` (token PK, tenant_id, kind, investigation_id | learning_job_id | host_request_id | hold_tenant_id,
  launch jsonb, inputs jsonb). Kinds `investigation | learning | post-step | drain | readiness | adoption`.
- `jobs.staged_facts` (token, name, body jsonb, staged_at): PK `(token, name)`, FK to the claim.
- `jobs.uploads` (token, object, size, sha256, wrapped_key, status, scrub, accepted_at, created_at): PK
  `(token, object)`, FK to the claim.
- Owner columns `claim_token`, `evidence_state` on `jobs.investigations` and `jobs.learning_jobs`; `scrub` on
  `jobs.investigations`.
- `tenancy.evidence_retention` (tenant_id, investigation_days, learning_days).
- The end function: `defender.jobs.ending.decide(...)` (r6: "one, in `jobs`").
- The evidence package: `defender.evidence` (blob store, data keys, pack/unpack). Its place in
  `tooling/lint/lint_import_order.py` is undecided (jobs, job_host, the learning entry and lifecycle all use it).
- Socket requests: `outcome(record=)`, `arms(roster=)`, `evidence.put(object=, part=, last=, data=[, scrub=])`
  answered `{size, sha256}` on the last part, `evidence.pull(owner=, object=, part=)` answered `{data, last}`.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import tarfile
from pathlib import Path
from typing import Any

import pytest

from defender.tests.support.shared._postgres1339 import execute

ENDPOINT_ENV = "DEFENDER_TEST_S3_ENDPOINT"
ACCESS_ENV = "DEFENDER_TEST_S3_ACCESS_KEY"
SECRET_ENV = "DEFENDER_TEST_S3_SECRET_KEY"
BUCKET_ENV = "DEFENDER_TEST_S3_BUCKET"

ROOTS, INPUTS, SPOOL = ".job-roots", ".job-inputs", ".job-spool"
SCRATCH, SOCKETS, OWNERS = ".job-scratch", ".job-sockets", ".job-owners"

EVIDENCE_STATES = ("complete", "partial", "none", "lost", "expired")
SCRUB_STATES = ("clean", "tainted", "not_run")

#: The run page's kind-table entry for an investigation's page and a learning arm's (#1161's kind table).
#: FORCED CHOICE (minor): r6 names `page/<kind-table entry>` and, for arms, `page/runs/<run id>/runtime.html`;
#: the investigation's own entry is not spelled. Picked `page/runtime.html`.
RUN_PAGE = "page/runtime.html"
EPISODE_PAGE = "page/learning.html"


def arm_page(run_id: str) -> str:
    return f"page/runs/{run_id}/runtime.html"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def object_key(tenant: str, kind: str, owner: str, claim: str, obj: str) -> str:
    """r6's layout spelled out (the oracle's own, not production's): `t/<tenant>/<owner kind>/<owner id>/<claim>/<obj>`.
    Owner kinds: `investigation`, `learning` (r6 says "investigation row or learning-job row", not the words)."""
    return f"t/{tenant}/{kind}/{owner}/{claim}/{obj}"


def job_root(data_root: Path, claim: str) -> Path:
    return Path(data_root) / ROOTS / claim


def job_inputs(data_root: Path, claim: str) -> Path:
    return Path(data_root) / INPUTS / claim


def job_spool(data_root: Path, claim: str) -> Path:
    return Path(data_root) / SPOOL / claim


# --- missing seams, touched before any service skip --------------------------------------------------------------

def evidence_module() -> Any:
    from defender import evidence  # SEAM (missing): the evidence package

    return evidence


def ending_module() -> Any:
    from defender.jobs import ending  # SEAM (missing): r6's one end function

    return ending


# --- the test blob store ----------------------------------------------------------------------------------------------

def s3_server() -> dict[str, str]:
    """The test S3 server (Garage): skipped where unset, failed in CI (r6 "Done when": Garage in CI; open probe)."""
    names = (ENDPOINT_ENV, ACCESS_ENV, SECRET_ENV, BUCKET_ENV)
    found = {name: os.environ.get(name) for name in names}
    if not all(found.values()):
        if os.environ.get("CI"):
            pytest.fail(f"{'/'.join(names)} are not set in CI; the test job's Garage service provides them")
        pytest.skip(f"{'/'.join(names)} are not set (no Garage here)")
    return {"endpoint": found[ENDPOINT_ENV], "access_key": found[ACCESS_ENV], "secret_key": found[SECRET_ENV],
            "bucket": found[BUCKET_ENV]}


class RawS3:
    """The bucket read and written with plain S3 calls (SSE-C when a key is given). No layout, no policy."""

    def __init__(self) -> None:
        server = s3_server()
        boto3 = pytest.importorskip("boto3")
        from botocore.config import Config

        self.bucket = server["bucket"]
        self.client = boto3.client(
            "s3", endpoint_url=server["endpoint"], region_name="garage", aws_access_key_id=server["access_key"],
            aws_secret_access_key=server["secret_key"],
            config=Config(s3={"addressing_style": "path"}, signature_version="s3v4"))

    @staticmethod
    def _ssec(key: bytes | None) -> dict[str, Any]:
        return {} if key is None else {"SSECustomerAlgorithm": "AES256", "SSECustomerKey": key}

    def put(self, name: str, data: bytes, key: bytes | None = None) -> None:
        self.client.put_object(Bucket=self.bucket, Key=name, Body=data, **self._ssec(key))

    def get(self, name: str, key: bytes | None = None) -> bytes | int:
        """The object's bytes, or the HTTP status S3 refused the read with."""
        from botocore.exceptions import ClientError

        try:
            return self.client.get_object(Bucket=self.bucket, Key=name, **self._ssec(key))["Body"].read()
        except ClientError as refused:
            return int(refused.response["ResponseMetadata"]["HTTPStatusCode"])

    def keys(self, prefix: str) -> list[str]:
        listed = self.client.list_objects_v2(Bucket=self.bucket, Prefix=prefix)
        return sorted(o["Key"] for o in listed.get("Contents", []))


def blob_store() -> Any:
    """The production blob store over the test server (seam: `evidence.BlobStore`)."""
    evidence = evidence_module()
    server = s3_server()
    return evidence.BlobStore(endpoint=server["endpoint"], bucket=server["bucket"], access_key=server["access_key"],
                              secret_key=server["secret_key"])


# --- the bundle oracle: tar+gzip, regular files and directories only (r6 "Objects per owner") ------------------------

def pack(files: dict[str, bytes]) -> bytes:
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz") as tar:
        for name, data in sorted(files.items()):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return out.getvalue()


def members(bundle: bytes) -> dict[str, bytes]:
    with tarfile.open(fileobj=io.BytesIO(bundle), mode="r:gz") as tar:
        return {m.name.removeprefix("./"): tar.extractfile(m).read() for m in tar.getmembers() if m.isfile()}  # type: ignore[union-attr]


# --- the new rows, by SQL ---------------------------------------------------------------------------------------------

UPLOAD = ("token", "object", "size", "sha256", "wrapped_key", "status", "scrub", "accepted_at")


def insert_claim(dsn: str, *, token: str, tenant: str, kind: str, ref: str, inputs: list | None = None) -> None:
    """A claim row as the claim's own transaction writes it (for setups that skip the claim)."""
    column = {"investigation": "investigation_id", "learning": "learning_job_id", "readiness": "host_request_id",
              "adoption": "host_request_id", "post-step": "hold_tenant_id", "drain": "hold_tenant_id"}[kind]
    execute(dsn, f"INSERT INTO jobs.claims (token, tenant_id, kind, {column}, inputs) "  # noqa: S608
                 "VALUES (%s, %s, %s, %s, %s::jsonb)", (token, tenant, kind, ref, json.dumps(inputs or [])))


def claim_row(dsn: str, token: str) -> dict[str, Any] | None:
    cols = ("token", "tenant_id", "kind", "investigation_id", "learning_job_id", "host_request_id", "hold_tenant_id",
            "launch", "inputs")
    found = execute(dsn, f"SELECT {', '.join(cols)} FROM jobs.claims WHERE token = %s", (token,))  # noqa: S608
    return dict(zip(cols, found[0], strict=True)) if found else None


def stage_fact(dsn: str, token: str, name: str, body: Any) -> None:
    """A staged fact as the helper writes it: create-once by `(token, name)` (`progress` is the one replaced)."""
    execute(dsn, "INSERT INTO jobs.staged_facts (token, name, body, staged_at) VALUES (%s, %s, %s::jsonb, now())",
            (token, name, json.dumps(body)))


def facts(dsn: str, token: str) -> dict[str, Any]:
    return dict(execute(dsn, "SELECT name, body FROM jobs.staged_facts WHERE token = %s", (token,)))


def stage_upload(dsn: str, token: str, obj: str, data: bytes | None, *, status: str = "uploaded",
                 wrapped_key: str = "wrapped-for-test", scrub: str | None = None) -> None:
    """An upload row as the helper leaves it after its PUT (`refused`/`pending`: `data` may be None)."""
    execute(dsn, "INSERT INTO jobs.uploads (token, object, size, sha256, wrapped_key, status, scrub, created_at) "
                 "VALUES (%s, %s, %s, %s, %s, %s, %s, now())",
            (token, obj, None if data is None else len(data), None if data is None else sha(data),
             None if data is None else wrapped_key, status, scrub))


def uploads(dsn: str, token: str) -> dict[str, dict[str, Any]]:
    rows = execute(dsn, f"SELECT {', '.join(UPLOAD)} FROM jobs.uploads WHERE token = %s", (token,))  # noqa: S608
    return {r[1]: dict(zip(UPLOAD, r, strict=True)) for r in rows}


def accepted(dsn: str, token: str) -> list[str]:
    """The claim's promoted objects, sorted."""
    return sorted(o for o, r in uploads(dsn, token).items() if r["accepted_at"] is not None)


def owner(dsn: str, table: str, owner_id: str, *cols: str) -> tuple[Any, ...]:
    [found] = execute(dsn, f"SELECT {', '.join(cols)} FROM jobs.{table} WHERE id = %s", (owner_id,))  # noqa: S608
    return tuple(found)


def claim_token(dsn: str, table: str, owner_id: str) -> str | None:
    return owner(dsn, table, owner_id, "claim_token")[0]


def evidence_state(dsn: str, table: str, owner_id: str) -> str | None:
    return owner(dsn, table, owner_id, "evidence_state")[0]


# --- records ---------------------------------------------------------------------------------------------------------

def closing(disposition: str = "benign") -> dict[str, Any]:
    """The closing-record fields the outcome carries (r6: "disposition, review outcome, #1534's summary").
    FORCED CHOICE: how an outcome says the close committed with no record, or the record could not be read
    (today's `closing.NeverClosed` / `CouldNotLook`, which make the row `unparseable`): r6 lists only the fields
    of a found record. Picked: `{"found": "record" | "never_closed" | "could_not_look", ...}`."""
    return {"found": "record", "disposition": disposition, "review": None, "summary": "the summary"}


def inv_outcome(**over: Any) -> dict[str, Any]:
    """An investigation's staged outcome: today's job-end facts with `scrub` for `scrub_verified`, the closing-record
    fields, cost and the lower-limit mark: a completed benign run costing 0.42 unless `over`.
    FORCED CHOICE (spelling): flat vs nested, the field names."""
    return {"setup": "done", "box": "started", "report_committed": True, "scrub": "clean", "cut_short": None,
            "closing": closing(), "cost_usd": 0.42, "cost_is_lower_limit": False, **over}


def learning_outcome(status: str = "completed", *, findings: Any = None, cost: float = 0.0) -> dict[str, Any]:
    """A learning job's staged outcome: today's learning-end fields, cost, and #1487's findings field."""
    return {"status": status, "reason": None, "message": None, "fork_message_id": "m-1", "stage": "judge",
            "sibling_cost_usd": cost, "findings": findings if findings is not None else {"state": "ok", "text":
                                                                                         '{"finding": [], "questioner_finding": []}'}}


STARTED = {"container": "started"}
#: The `knowledge` fact as staged: today's helper record (`KnowledgeSource.host_record()`), which the worker maps to the
#: row's served shape `KNOWLEDGE_SERVED` as it does today from `<run>.knowledge-source.json`.
KNOWLEDGE = {"kind": "fresh", "commit": "c" * 40, "stale_kind": None, "reason": None}
KNOWLEDGE_SERVED = {"status": "current", "commit": "c" * 40, "stale_kind": None}

# ruff: noqa: PLR0913
"""#1546 slice SE test machinery (retention, offboarding) — NO test functions.

The store-side rows (`jobs.claims`, `jobs.staged_facts`, `jobs.uploads`, owner columns `evidence_state`, `claim_token`) are
planted by SQL as the end transaction leaves them, and the evidence store is the real Garage (`_evidence1546.garage`).
Pinned names (design r8 leaves them open; the sketch's picks): those tables and columns, `tenancy.evidence_retention
(tenant_id, investigation_days, learning_days)`, `defender.evidence.BlobStore(endpoint=, bucket=, access_key=, secret_key=,
region=)`, the object key `t/<tenant>/<owner kind>/<owner id>/<claim token>/<object>` (owner kinds `investigation`, `learning`).
"""
from __future__ import annotations

import json
import uuid
from typing import Any

from defender.tests.support.evidence._evidence1546 import Garage
from defender.tests.support.shared._postgres1339 import execute

OWNER_TABLE = {"investigation": "investigations", "learning": "learning_jobs"}
UPLOAD = ("token", "object", "size", "sha256", "wrapped_key", "status", "scrub", "accepted_at")


def blob_store(garage: Garage) -> Any:
    """The production blob store over the test Garage (missing until the evidence package exists)."""
    from defender import evidence

    return evidence.BlobStore(endpoint=garage.endpoint, bucket=garage.bucket, access_key=garage.access_key,
                              secret_key=garage.secret_key, region=garage.region)


def object_key(tenant: str, kind: str, owner: str, claim: str, obj: str = "bundle") -> str:
    return f"t/{tenant}/{kind}/{owner}/{claim}/{obj}"


def set_retention(dsn: str, tenant: str, investigation_days: int, learning_days: int | None = None) -> None:
    execute(dsn, "INSERT INTO tenancy.evidence_retention (tenant_id, investigation_days, learning_days) VALUES (%s, %s, %s)",
            (tenant, investigation_days, investigation_days if learning_days is None else learning_days))


def insert_claim(dsn: str, *, token: str, tenant: str, kind: str, ref: str) -> None:
    column = {"investigation": "investigation_id", "learning": "learning_job_id"}[kind]
    execute(dsn, f"INSERT INTO jobs.claims (token, tenant_id, kind, {column}, inputs) VALUES (%s, %s, %s, %s, '[]'::jsonb)",  # noqa: S608
            (token, tenant, kind, ref))


def stage_fact(dsn: str, token: str, name: str, body: Any) -> None:
    execute(dsn, "INSERT INTO jobs.staged_facts (token, name, body, staged_at) VALUES (%s, %s, %s::jsonb, now())",
            (token, name, json.dumps(body)))


def stage_upload(dsn: str, token: str, obj: str, *, status: str = "uploaded", age_hours: float = 0.0,
                 accepted_days_ago: float | None = None) -> None:
    """An upload row as the helper leaves it after its PUT, `age_hours` old by the database clock; `accepted_days_ago`
    sets the applier's `accepted_at` that many days back (None: never promoted)."""
    execute(dsn, "INSERT INTO jobs.uploads (token, object, size, sha256, wrapped_key, status, scrub, created_at, accepted_at) "
                 "VALUES (%s, %s, 6, %s, 'wrapped-for-test', %s, NULL, now() - %s * interval '1 hour', "
                 "CASE WHEN %s::float8 IS NULL THEN NULL ELSE now() - %s::float8 * interval '1 day' END)",
            (token, obj, "0" * 64, status, age_hours, accepted_days_ago, accepted_days_ago))


def uploads(dsn: str, token: str) -> dict[str, dict[str, Any]]:
    rows = execute(dsn, f"SELECT {', '.join(UPLOAD)} FROM jobs.uploads WHERE token = %s", (token,))  # noqa: S608
    return {r[1]: dict(zip(UPLOAD, r, strict=True)) for r in rows}


def facts(dsn: str, token: str) -> dict[str, Any]:
    return dict(execute(dsn, "SELECT name, body FROM jobs.staged_facts WHERE token = %s", (token,)))


def claim_launch(dsn: str, token: str) -> tuple[bool, Any]:
    """(the claim row exists, its launch facts)."""
    found = execute(dsn, "SELECT launch FROM jobs.claims WHERE token = %s", (token,))
    return (bool(found), found[0][0] if found else None)


def evidence_state(dsn: str, kind: str, owner_id: str) -> str | None:
    [(state,)] = execute(dsn, f"SELECT evidence_state FROM jobs.{OWNER_TABLE[kind]} WHERE id = %s", (owner_id,))  # noqa: S608
    return state


def make_owner(dsn: str, garage: Garage, tenant: str, ticket: str, *, kind: str = "investigation",
               state: str = "complete", accepted_days_ago: float | None = 1.0, live: bool = False,
               put_object: bool = True, hours_old: float | None = None, ended_days_ago: float = 0.0) -> dict[str, Any]:
    """An owner of `tenant` under a claim of its own with one `bundle` upload, its object put in Garage; every row by SQL.

    `state`: the ended owner's `evidence_state`; `accepted_days_ago`: the bundle's acceptance age by the database clock
    (None: unpromoted); `live`: an investigation still running under an unexpired lease; `hours_old`: the upload's creation
    age; `ended_days_ago`: how long ago the owner ended (`finished_at`). A learning owner rides on a `none` investigation
    of its own. Returns owner id, claim token, the object's key and the investigation's id."""
    alert, inv_id, claim = str(uuid.uuid4()), str(uuid.uuid4()), uuid.uuid4().hex
    execute(dsn, "INSERT INTO jobs.alerts (id, tenant_id, vendor, vendor_ticket_id, fired_at, changed_at, received_at, raw) "
                 "VALUES (%s, %s, 'tickets', %s, now(), now(), now(), '{}')", (alert, tenant, f"T-{ticket}-{alert}"))
    execute(dsn, "INSERT INTO jobs.investigations (id, tenant_id, alert_id, request_key, attempt, stage, created_at, "
                 "cost_usd, cost_is_lower_limit, update_ticket) VALUES (%s, %s, %s, %s, 1, 'queued', now(), 0, false, false)",
            (inv_id, tenant, alert, f"k-{ticket}"))
    owner_id = inv_id
    ended = "finished_at = now() - %s * interval '1 day'"
    if kind == "learning":
        owner_id = str(uuid.uuid4())
        execute(dsn, "UPDATE jobs.investigations SET stage = 'completed', disposition = 'benign', finished_at = now(), "
                     "evidence_state = 'none', scrub = 'clean' WHERE id = %s", (inv_id,))
        execute(dsn, "INSERT INTO jobs.learning_jobs (id, tenant_id, alert_id, investigation_id, request_key, attempt, "
                     "trigger, status, created_at, sibling_cost_usd, publish_state, evidence_state, finished_at) "
                     "VALUES (%s, %s, %s, %s, %s, 1, 'explicit', 'completed', now(), 0, 'none', %s, "
                     "now() - %s * interval '1 day')", (owner_id, tenant, alert, inv_id, f"k-{ticket}-l", state, ended_days_ago))
        insert_claim(dsn, token=claim, tenant=tenant, kind="learning", ref=owner_id)
        execute(dsn, "UPDATE jobs.learning_jobs SET claim_token = %s WHERE id = %s", (claim, owner_id))
    else:
        insert_claim(dsn, token=claim, tenant=tenant, kind="investigation", ref=inv_id)
        if live:
            execute(dsn, "UPDATE jobs.investigations SET stage = 'running', started_at = now(), claim_token = %s, "
                         "lease_expires_at = now() + interval '1 hour' WHERE id = %s", (claim, inv_id))
        else:
            execute(dsn, f"UPDATE jobs.investigations SET stage = 'completed', disposition = 'benign', {ended}, "  # noqa: S608
                         "evidence_state = %s, scrub = 'clean', claim_token = %s WHERE id = %s",
                    (ended_days_ago, state, claim, inv_id))
    key = object_key(tenant, kind, owner_id, claim)
    garage.tenant_prefix(tenant)  # tracked: emptied at teardown
    if put_object:
        garage.put(key, b"bundle")
    stage_upload(dsn, claim, "bundle", status="uploaded", accepted_days_ago=accepted_days_ago,
                 age_hours=(24 * (accepted_days_ago or 0) if hours_old is None else hours_old))
    return {"owner": owner_id, "claim": claim, "key": key, "investigation": inv_id}


def gone(garage: Garage, key: str) -> bool:
    return garage.head(key).status_code == 404


def present(garage: Garage, key: str) -> bool:
    return garage.head(key).status_code == 200

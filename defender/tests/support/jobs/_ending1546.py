"""#1546 test support for the ending (PR9), the claims (PR7) and the evidence rows: builders for the staged facts and
uploads a helper leaves, SQL readers and planters that never go through the code under test, and the adapters that wrap
every interface choice r8 leaves open (the `decide` signature, the `ended_by` members, the exited path's reading of facts).

Nothing here decides an ending: the rule tables live in the tests that assert them. Pinned names are listed once, in
each adapter's docstring (see the slice return). S0 may dedupe the row builders with `tests/support/evidence`.
"""
from __future__ import annotations

import json
import uuid
from typing import Any

from defender.tests.support.shared._postgres1339 import execute

# --- the closed `ended_by` members, one adapter (r8 names them; their spelling is open) -----------------------------------

#: The members as the tests name them; the generated tests walk this list.
ENDED_BY = ("exited", "exited_failed", "stopped", "lapsed", "cancelled", "offboarded", "expired_in_queue", "not_launched")


def ended_by(name: str) -> Any:
    """PINNED: `defender.jobs.ending.Exited(status)`, `Stopped()`, `Lapsed()`, `Cancelled()`, `Offboarded()`,
    `ExpiredInQueue()`, `NotLaunched()`; `exited` is a helper that served the job to its end (status 0), `exited_failed`
    one that failed on its own."""
    from defender.jobs import ending

    return {"exited": lambda: ending.Exited(0), "exited_failed": lambda: ending.Exited(70),
            "stopped": ending.Stopped, "lapsed": ending.Lapsed, "cancelled": ending.Cancelled,
            "offboarded": ending.Offboarded, "expired_in_queue": ending.ExpiredInQueue,
            "not_launched": ending.NotLaunched}[name]()


def decide(kind: str, facts: dict[str, Any], uploads: dict[str, dict[str, Any]], by: str) -> Any:
    """PINNED: `defender.jobs.ending.decide(facts, uploads, ended_by, *, kind)` with `kind` one of `investigation`,
    `learning`, `host_request` (r8's signature has no kind, yet "Decided" is per kind); `facts` is `{name: body}`,
    `uploads` is `{object: {"status", "scrub"}}`. Returns `End` or `HandBack`."""
    from defender.jobs import ending

    return ending.decide(facts, uploads, ended_by(by), kind=kind)


# --- staged-fact bodies (the helper's closed shapes, r8 "Staged facts"; the spelling is pinned here) ------------------------

from defender.tests.support.evidence._facts1546 import (  # noqa: E402, F401 — re-exported: one owner of the fact bodies
    BUNDLE,
    EPISODE_PAGE,
    KNOWLEDGE,
    PENDING,
    REFUSED,
    RUN_PAGE,
    STARTED,
    UP,
    arm_page,
    closing_found,
    findings_refused,
    refused,
    screened,
    staged_inv_outcome,
    staged_learning_outcome,
    up,
)

#: The staged forms: what the worker reads (the decide and apply tests build their facts with these).
inv_outcome = staged_inv_outcome
learning_outcome = staged_learning_outcome
findings_screened = screened
FINDINGS_REFUSED = findings_refused()


# --- SQL planters and readers: the rows by SQL, never through the code under test -----------------------------------------

_REF = {"investigation": "investigation_id", "learning": "learning_job_id", "readiness": "host_request_id",
        "adoption": "host_request_id", "drain": "host_request_id", "post-step": "hold_tenant_id"}


def token_of(dsn: str, kind: str, ref: str) -> str:
    """The token of the one claim naming `ref` (a post-step hold may have several: the newest by `created_at` is not
    assumed, so this refuses to guess)."""
    found = execute(dsn, f"SELECT token FROM jobs.claims WHERE kind = %s AND {_REF[kind]} = %s", (kind, ref))  # noqa: S608
    assert len(found) == 1, f"expected one {kind} claim for {ref}, found {len(found)}"
    return str(found[0][0])


def plant_claim(dsn: str, *, tenant: str, kind: str, ref: str, token: str | None = None,
                inputs: list | None = None) -> str:
    token = token or uuid.uuid4().hex
    execute(dsn, f"INSERT INTO jobs.claims (token, tenant_id, kind, {_REF[kind]}, inputs) "  # noqa: S608
                 "VALUES (%s, %s, %s, %s, %s::jsonb)", (token, tenant, kind, ref, json.dumps(inputs or [])))
    return token


def plant_facts(dsn: str, token: str, facts: dict[str, Any]) -> None:
    for name, body in facts.items():
        execute(dsn, "INSERT INTO jobs.staged_facts (token, name, body, staged_at) VALUES (%s, %s, %s::jsonb, now())",
                (token, name, json.dumps(body)))


def plant_uploads(dsn: str, token: str, uploads: dict[str, dict[str, Any]]) -> None:
    """Upload rows as the helper leaves them, whatever their status (a real size and digest each)."""
    import hashlib

    for obj, spec in uploads.items():
        data = f"{token}/{obj}".encode()
        execute(dsn, "INSERT INTO jobs.uploads (token, object, size, sha256, wrapped_key, status, scrub, created_at) "
                     "VALUES (%s, %s, %s, %s, 'wrapped-for-test', %s, %s, now())",
                (token, obj, len(data), hashlib.sha256(data).hexdigest(), spec["status"], spec.get("scrub")))


def facts_of(dsn: str, token: str) -> dict[str, Any]:
    return dict(execute(dsn, "SELECT name, body FROM jobs.staged_facts WHERE token = %s", (token,)))


def uploads_of(dsn: str, token: str) -> dict[str, dict[str, Any]]:
    rows = execute(dsn, "SELECT object, status, scrub, accepted_at FROM jobs.uploads WHERE token = %s", (token,))
    return {o: {"status": s, "scrub": sc, "accepted_at": a} for o, s, sc, a in rows}


def accepted(dsn: str, token: str) -> list[str]:
    return sorted(o for o, r in uploads_of(dsn, token).items() if r["accepted_at"] is not None)


INV_COLUMNS = ("stage", "failure_reason", "disposition", "cost_usd", "cost_is_lower_limit", "knowledge", "scrub",
               "evidence_state")
LEARN_COLUMNS = ("status", "reason", "publish_state", "sibling_cost_usd", "evidence_state")


def inv_row(dsn: str, inv: str, *cols: str) -> dict[str, Any]:
    cols = cols or INV_COLUMNS
    [found] = execute(dsn, f"SELECT {', '.join(cols)} FROM jobs.investigations WHERE id = %s", (inv,))  # noqa: S608
    return dict(zip(cols, found, strict=True))


def learn_row(dsn: str, job: str, *cols: str) -> dict[str, Any]:
    cols = cols or LEARN_COLUMNS
    [found] = execute(dsn, f"SELECT {', '.join(cols)} FROM jobs.learning_jobs WHERE id = %s", (job,))  # noqa: S608
    return dict(zip(cols, found, strict=True))


def host_row(dsn: str, request: str) -> dict[str, Any]:
    cols = ("stage", "failure_reason", "result")
    [found] = execute(dsn, f"SELECT {', '.join(cols)} FROM jobs.host_requests WHERE id = %s", (request,))  # noqa: S608
    return dict(zip(cols, found, strict=True))


def alerts_rows(dsn: str, inv: str) -> list[tuple[str, str]]:
    """The attempts of the investigation's request, `(id, stage)` by attempt."""
    return [(str(i), s) for i, s in execute(
        dsn, "SELECT id, stage FROM jobs.investigations WHERE alert_id = (SELECT alert_id FROM jobs.investigations "
             "WHERE id = %s) ORDER BY attempt", (inv,))]


def learning_jobs_of(dsn: str, inv: str) -> int:
    [(n,)] = execute(dsn, "SELECT count(*) FROM jobs.learning_jobs WHERE investigation_id = %s", (inv,))
    return int(n)


async def plant_complete_source(dsn: str, store: Any, tenant: str, *, ticket: str | None = None) -> tuple[Any, str]:
    from defender.tests.support.jobs._jobs1342 import an_alert

    alert = await an_alert(store, tenant, ticket=ticket or f"T-{uuid.uuid4().hex[:6]}")
    inv, _ = await store.create_investigation(tenant, alert.alert_id, f"k-{uuid.uuid4().hex[:4]}", actor="u-1")
    execute(dsn, "UPDATE jobs.investigations SET stage = 'completed', disposition = 'benign', finished_at = now(), "
                 "evidence_state = 'complete', scrub = 'clean', knowledge = %s::jsonb WHERE id = %s",
            (json.dumps(KNOWLEDGE), inv.investigation_id))
    return alert, str(inv.investigation_id)


async def queue_learning_job(dsn: str, tenant: str, alert_id: str, source: str, *, key: str = "k-learn") -> str:
    job = str(uuid.uuid4())
    execute(dsn, "INSERT INTO jobs.learning_jobs (id, tenant_id, alert_id, investigation_id, request_key, attempt, "
                 "trigger, status, created_at, sibling_cost_usd, sibling_cost_is_lower_limit, publish_state) VALUES (%s, %s, %s, %s, %s, 1, "
                 "'auto', 'queued', now(), 0, false, 'none')", (job, tenant, alert_id, source, key))
    return job


# --- the exited path's one adapter ------------------------------------------------------------------------------------------


DECIDE_KIND = {"readiness": "host_request", "adoption": "host_request", "drain": "host_request"}  # claim kind -> decide's pinned kind


async def end_row(store: Any, dsn: str, *, kind: str, tenant: str, owner: str, token: str, by: str) -> Any:
    """The worker's end of a claimed row: read its claim's staged facts and uploads (here by SQL), `decide`, then
    `apply`. PINNED: `JobStore.apply(tenant_id, owner_id, decision)` (r8's `apply(row, Decision)`), answering the row's
    record, or `None` when the row is no longer live (the fence); who reads facts in the end transaction is open (a gap)."""
    decision = decide(DECIDE_KIND.get(kind, kind), facts_of(dsn, token), uploads_of(dsn, token), by)
    return decision, await store.apply(tenant, owner, decision)


async def end_through_the_store(store: Any, tenant: str, investigation_id: str, *, stage: str = "completed",
                                disposition: str | None = "malicious", cost_usd: float = 0.0) -> Any:
    """A running investigation ended as a #1546 normal end leaves it, through the store's own session (no DSN needed): its
    claim, the helper's facts (`started`, `knowledge`, an `outcome` with a clean scrub whose close found `disposition`, no
    page) and an uploaded bundle, then `decide` and `apply`. A `completed` stage reads `complete`, so its follow-ons run as
    today's finish did (the auto learning job, the alert outcome, the check clock). Returns `apply`'s record."""
    from sqlalchemy import text

    token = uuid.uuid4().hex
    closing = closing_found(disposition) if disposition is not None else {"found": "never_closed"}
    facts = {"started": STARTED, "knowledge": KNOWLEDGE, "page": {"page": "none"},
             "outcome": staged_inv_outcome(closing=closing, cost_usd=cost_usd,
                                           report_committed=stage == "completed", scrub="clean")}
    async with store._tx() as s:
        await s.execute(text("INSERT INTO jobs.claims (token, tenant_id, kind, investigation_id, inputs) "
                             "VALUES (:t, :tenant, 'investigation', :inv, '[]'::jsonb)"),
                        {"t": token, "tenant": tenant, "inv": str(investigation_id)})
        for name, body in facts.items():
            await s.execute(text("INSERT INTO jobs.staged_facts (token, name, body, staged_at) "
                                 "VALUES (:t, :n, CAST(:b AS jsonb), now())"), {"t": token, "n": name, "b": json.dumps(body)})
        await s.execute(text("INSERT INTO jobs.uploads (token, object, size, sha256, wrapped_key, status, created_at) "
                             "VALUES (:t, 'bundle', 6, :sha, 'wrapped-for-test', 'uploaded', now())"),
                        {"t": token, "sha": "0" * 64})
    decision = decide("investigation", facts, {"bundle": up()}, "exited")
    return await store.apply(tenant, str(investigation_id), decision)

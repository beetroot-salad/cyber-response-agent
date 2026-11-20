"""#1471 slice A: shared setup of the host-request tests (`jobs.host_requests`: readiness and adoption) - NO test functions.

The vocabulary is spelled here from the design's closed sets (`test-surface.md` §5, §6), never imported from the code under
test, so a code-side set that drifts is a red test. A `HostChild` stands in for the helper's launch (slice B owns the real
one): it leaves the records a helper or container would write, create-only, in the tenant's runs container, and exits.
Table columns are the surface's choice (§4)."""
from __future__ import annotations

import datetime as dt
import json
import shutil
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from defender.tests.support.jobs._jobs1342 import NOW, ScriptedChild, knowledge_record_of, make_worker
from defender.tests.support.shared._postgres1339 import execute
from defender.tests.support.shared.filesystem._handoff import write_whole

DEFENDER = Path(__file__).resolve().parents[3]
#: The adapter whose planted checkout declares `BASE_FILES`, and one that declares none there (§7: base files are the adapter's).
SHIPS_BASE_FILES = "identity"
NO_BASE_FILES = "ticket"
_PLANTED = {
    "skills/{system}/SKILL.md": b"---\nname: defender-{system}\ndescription: planted\n---\nbody\n",
    "skills/gather/queries/{system}/by-user.md": b"---\nid: {system}.by-user\nverb: x\n---\n",
}


def plant_checkout(root: Path) -> Path:
    """A code tree (a copy of `integrations/`) whose `SHIPS_BASE_FILES` adapter declares `BASE_FILES` and whose others declare none.
    The server's catalog reads `$DEFENDER_DIR`, so a test points it here before the server starts (sort-3 1a)."""
    shutil.copytree(DEFENDER / "integrations", root / "integrations", ignore=shutil.ignore_patterns("__pycache__"))
    adapter = root / "integrations" / f"{SHIPS_BASE_FILES}_adapter.py"
    adapter.write_text(adapter.read_text(encoding="utf-8") + f'\nBASE_FILES = "base-files/{SHIPS_BASE_FILES}"\n', encoding="utf-8")
    for rel, data in _PLANTED.items():
        target = root / "integrations" / "base-files" / SHIPS_BASE_FILES / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    return root


@pytest.fixture
def planted_checkout(tmp_path, monkeypatch) -> Path:
    """`plant_checkout` under `tmp_path`, set as `$DEFENDER_DIR` (`setenv`, not `setattr`)."""
    root = plant_checkout(tmp_path / "checkout")
    monkeypatch.setenv("DEFENDER_DIR", str(root))
    return root


COMMIT = "c" * 40
MARK = "CONTAINER-TEXT-1471"

READINESS = "{id}.readiness.json"
ADOPTION = "{id}.adoption.json"
KNOWLEDGE = "{id}.knowledge-source.json"

# --- the closed sets (surface §5), by the step's place in P-1 -----------------------------------------------------------

#: Helper steps whose refusal carries no knowledge: they come at or before `publish` (R3, R13-1.5).
STEPS_WITHOUT_KNOWLEDGE = ("tenant", "records", "alert_mapping", "publish")
#: Steps after `publish`, the container's included: the knowledge record is read there.
STEPS_WITH_KNOWLEDGE = ("knowledge_copy", "run_tenant", "roster", "tenant_verdict", "signing", "first_pass",
                        "container_tenant", "systems")
READINESS_STEPS = (*STEPS_WITHOUT_KNOWLEDGE, *STEPS_WITH_KNOWLEDGE)
READINESS_HELPER_REASONS = ("start_failed", "worker_error")
READINESS_CONTAINER_REASONS = ("census_unavailable", "handover")
WARNING_KINDS = ("case_system", "system_down", "grant_ignored", "verb_undecided", "verb_undeclared",
                 "tacit_registry", "tacit_grant", "feedback_setting", "retired_file")
ADOPTION_OUTCOMES = ("opened", "already_open", "rejected", "nothing_to_adopt")
WITH_NUMBER = ("opened", "already_open", "rejected")
#: §6 with the §9 addendum's `tenant_not_active` in both writers' sets.
ADOPTION_REASONS = ("system_gone", "no_base_files", "setup_refused", "start_failed", "worker_error", "repository_busy",
                    "delivery_failed", "handover", "tenant_not_active")
#: Every failure reason the worker's own words can give a row, either kind (surface §6).
WORKER_REASONS = ("bad_record", "tenant_offboarded", "worker_error", "no_record", "worker_stopped", "worker_lost")

FRESH = knowledge_record_of("fresh", COMMIT)
FRESH_SERVED = {"status": "current", "commit": COMMIT, "stale_kind": None}
STALE_OPERATOR = knowledge_record_of("stale", COMMIT, stale_kind="operator", reason="the forge said no")
STALE_OPERATOR_SERVED = {"status": "stale", "commit": COMMIT, "stale_kind": "operator"}
#: Text at the knowledge record's path that is not a status.
MALFORMED_KNOWLEDGE = ("", "{not json", "[]", '{"kind": "bogus", "commit": null, "stale_kind": null, "reason": null}',
                       '{"kind": "fresh"}')


# --- the records a helper or container writes ---------------------------------------------------------------------------

def refused(step: str, sentence: str = "no usable system", **extra: Any) -> str:
    return json.dumps({"outcome": "refused", "step": step, "sentence": sentence, **extra})


def ready(warnings: list[Mapping[str, Any]] | None = None, **extra: Any) -> str:
    return json.dumps({"outcome": "ready", "warnings": [] if warnings is None else list(warnings), **extra})


def failed(reason: str, **extra: Any) -> str:
    return json.dumps({"outcome": "failed", "reason": reason, **extra})


def warning(kind: str = "system_down", sentence: str = "elastic did not answer") -> dict[str, str]:
    return {"kind": kind, "sentence": sentence}


def adopted(outcome: str, pr_number: Any = None, **extra: Any) -> str:
    return json.dumps({"outcome": outcome, "pr_number": pr_number, **extra})


# --- a child that stands in for a launched helper ------------------------------------------------------------------------

class HostChild(ScriptedChild):
    """`readiness_argv`/`adoption_argv` for a worker: `ScriptedChild` keyed by the request id. `launches` notes each launch
    the worker built it for, in order."""

    def __post_init__(self) -> None:
        super().__post_init__()
        self.launches: list[Any] = []

    def __call__(self, launch: Any) -> list[str]:
        self.launches.append(launch)
        write_whole(self.spec, json.dumps(self.spec_dict()))
        return [sys.executable, str(self.script), str(self.spec), "--job", launch.request_id,
                "--tenant", launch.tenant_id, "--parent-pid", str(launch.parent_pid)]

    def started(self) -> list[str]:
        """The request ids whose child started, in the order its events say."""
        return [rid for kind, rid in self.events() if kind == "start"]


def host_child(world: dict, name: str = "host", **kw: Any) -> HostChild:
    return HostChild(world["tmp"] / name, world["runs"], **kw)


def host_worker(world: dict, store: Any, child: HostChild | None = None, *, readiness: Any = None, adoption: Any = None,
                investigation: Any = None, **kw: Any) -> Any:
    """A worker whose two host-request commands are `child` (or `readiness` and `adoption`), over the world's data root.
    The investigation command is a scripted child of its own."""
    from defender.tests.support.jobs._worker1342 import _child

    child = child if child is not None else host_child(world)
    return make_worker(store, world["root"], investigation if investigation is not None else _child(world, exit=0),
                       readiness_argv=readiness if readiness is not None else child,
                       adoption_argv=adoption if adoption is not None else child, **kw)


# --- the table, read and planted as SQL ----------------------------------------------------------------------------------

COLUMNS = ("id", "tenant_id", "kind", "dedupe_key", "system_id", "requester", "created_at", "started_at", "finished_at",
           "stage", "lease_expires_at", "result", "failure_reason", "failure_message")


def host_row(dsn: str, request_id: str) -> dict[str, Any] | None:
    found = execute(dsn, f"SELECT {', '.join(COLUMNS)} FROM jobs.host_requests WHERE id = %s", (request_id,))  # noqa: S608
    return dict(zip(COLUMNS, found[0], strict=True)) if found else None


def host_rows(dsn: str, tenant: str | None = None) -> list[dict[str, Any]]:
    """Every row (a tenant's), oldest first."""
    where, params = ("WHERE tenant_id = %s", (tenant,)) if tenant else ("", ())
    found = execute(dsn, f"SELECT {', '.join(COLUMNS)} FROM jobs.host_requests {where} ORDER BY created_at, id", params)  # noqa: S608
    return [dict(zip(COLUMNS, r, strict=True)) for r in found]


def ids_of(dsn: str, tenant: str | None = None) -> list[str]:
    return [r["id"] for r in host_rows(dsn, tenant)]


def set_created(dsn: str, request_id: str, when: dt.datetime) -> None:
    """Age one row: `fixed_clock` gives every row the same `created_at`."""
    execute(dsn, "UPDATE jobs.host_requests SET created_at = %s WHERE id = %s", (when, request_id))


def lapse(dsn: str, request_id: str) -> None:
    execute(dsn, "UPDATE jobs.host_requests SET lease_expires_at = now() - interval '1 second' WHERE id = %s",
            (request_id,))


def lease_left(dsn: str, request_id: str) -> float | None:
    found = execute(dsn, "SELECT EXTRACT(EPOCH FROM lease_expires_at - now()) FROM jobs.host_requests WHERE id = %s",
                    (request_id,))
    return None if not found or found[0][0] is None else float(found[0][0])


def plant(dsn: str,  # noqa: PLR0913 — a row's columns
           tenant: str, kind: str, *, system: str | None = None, stage: str = "queued", result: Any = None,
          reason: str | None = None, message: str | None = None, requester: str = "u-planted",
          created: dt.datetime = NOW, request_id: str | None = None) -> str:
    """A row as SQL (a state no request can reach quickly: running with a lease, a finished row with a result). Its
    dedupe key is the surface's spelling: the tenant, or `<tenant>/<system>`."""
    import uuid

    request_id = request_id or str(uuid.uuid4())
    key = tenant if kind == "readiness" else f"{tenant}/{system}"
    live = stage == "running"
    done = stage in ("completed", "failed")
    execute(dsn, "INSERT INTO jobs.host_requests (id, tenant_id, kind, dedupe_key, system_id, requester, created_at, "
                 "started_at, finished_at, stage, lease_expires_at, result, failure_reason, failure_message) "
                 "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s)",
            (request_id, tenant, kind, key, system, requester, created, NOW if live or done else None,
             NOW if done else None, stage, NOW + dt.timedelta(minutes=5) if live else None,
             None if result is None else json.dumps(result), reason, message))
    return request_id


def failure_of(row: Mapping[str, Any]) -> tuple[str, str | None]:
    return row["stage"], row["failure_reason"]


def runs_of(world: dict) -> Path:
    return world["runs"]

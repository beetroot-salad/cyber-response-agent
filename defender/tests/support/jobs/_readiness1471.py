"""#1471 slice B machinery: the readiness helper (`job_host`, kind `readiness`) and the readiness container entry
(`run.readiness_main`) driven over the helper scene, and the premise runs that show what a real investigation of the
same tenant does. NO test functions; every unbuilt name is imported lazily, so a missing one is a red at its call.

Names (test-surface.md §4, §5): the helper's `--kind readiness --job <id> --tenant <T>`, the container's
`run.readiness_main(["--readiness", id, "--tenant", T], *, environ, roster)`, and the records `<runs>/<id>.readiness.json`
and `<runs>/<id>.knowledge-source.json`, read here as raw JSON so the record shapes are the contract's, not a class's."""
from __future__ import annotations

import contextlib
import io
import json
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from defender.tests.support.jobs import _job_helper as J
from defender.tests.support.jobs._job_helper import (
    ContainerStandIn,
    HelperRan,
    HelperScene,
    drive_helper,
    helper_scene,
    make_signer,
)

#: A text the publish child's reply might carry (a forge reply, a host path): P-2 says it never reaches the admin.
PUBLISH_CANARY = "FORGE-REPLY-CANARY-1471 /srv/forge/secret-path"

#: `READINESS_STEPS` (surface §5) and the warning kinds (§5), spelled once as literals.
HELPER_STEPS = ("tenant", "records", "alert_mapping", "publish", "knowledge_copy", "run_tenant", "roster",
                "tenant_verdict", "signing", "first_pass")
CONTAINER_STEPS = ("container_tenant", "systems")
AFTER_PUBLISH = ("knowledge_copy", "run_tenant", "roster", "tenant_verdict", "signing", "first_pass", *CONTAINER_STEPS)
WARNING_KINDS = frozenset({"case_system", "system_down", "grant_ignored", "verb_undecided", "verb_undeclared",
                           "tacit_registry", "tacit_grant", "feedback_setting", "retired_file",
                           "evidence_key_missing"})  # #1546 A-O7 (r9): the evidence key, produced host-side
#: The tenant of a test's second scene (the first is the fixture's, registered in the same database).
SECOND_TENANT = "7a1c5e93-4b2d-4f86-9e07-3c8d1b6a2f54"
#: Words that name an operator command: an admin reads our sentences too (#1470 O11, C9).
OPERATOR_WORDS = ("tenant.py", "tenant check", "tenant update", "tenant propose")


@contextlib.contextmanager
def readiness_scene(tmp_path: Path, monkeypatch: Any, dsn: str, *, proxied: tuple[str, ...] = ("identity", "ticket"),
                    files: dict[str, Any] | None = None, records: Callable[[Any], Any] | None = None,
                    tenant_id: str | None = None) -> Iterator[HelperScene]:
    """`helper_scene` whose tenant's records are `records(default_spec)` when given: the tenant's records dropped and
    seeded again through the store (first versions), so a case can disable a system, break a case record or leave the
    tenant with none. `files` are written over the published fixture as `helper_scene` does. A second scene in one test
    passes `tenant_id=SECOND_TENANT`: the database already holds the fixture's id."""
    from defender.tests.support.tenancy import _systems1366 as R

    with helper_scene(tmp_path, monkeypatch, dsn, proxied=proxied, files=files, tenant_id=tenant_id) as scene:
        if records is not None:
            R.drop_records(dsn, scene.tenant)
            R.seed_postgres_records(dsn, scene.tenant, records(J.proxied_records(proxied)))
        yield scene


def grants_text(edit: Callable[[dict[str, Any]], None]) -> str:
    """The fixture's verb-grants table with `edit(dispositions)` applied, as the text to publish."""
    from defender.tests.tenancy.tenant_1120_piece1 import _spec1120 as H

    doc = yaml.safe_load((H.FIXTURE / "settings" / "verb-grants.yaml").read_text(encoding="utf-8"))
    edit(doc["dispositions"])
    return yaml.safe_dump(doc, sort_keys=False)


def read_json(path: Path) -> Any:
    """`path`'s JSON, or None when there is no such file."""
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


# --- the premise run: a real investigation over the same scene ------------------------------------------------------

@dataclass
class Investigated:
    """One helper run of an investigation (a stand-in container that does nothing): what setup decided, and why."""

    inv: str
    ran: HelperRan
    docker: ContainerStandIn
    err: str
    end: Any

    @property
    def refused(self) -> bool:
        return getattr(self.end, "setup", None) == "refused"

    @property
    def started(self) -> bool:
        """Setup went through: the helper started its container, and the container (which does nothing) wrote no end."""
        return self.docker.job_ran and self.end is None


def plant_premise(scene: HelperScene) -> str:
    """A premise investigation's row and its claim under `scene.claim`, as the worker's claim transaction leaves them; its id.
    #1546 (design: Claim, "inserted in the claim's own transaction for every launched child"): a worker claims a job of an
    active tenant before anything refuses it, so a case whose fault makes the tenant unclaimable (offboarding, creating)
    plants this BEFORE the fault. Asserted present: a premise never runs unclaimed (`claim_for` plants nothing for a tenant the
    store takes no job for, and the helper then fails for the missing claim, not for the fault)."""
    from defender.tests.support.shared._postgres1339 import execute

    inv = str(uuid.uuid4())
    # The scene has one claim token; a premise investigation run before the readiness starts from the claim's clean rows.
    for table in ("uploads", "staged_facts", "claims"):
        execute(scene.dsn, f"DELETE FROM jobs.{table} WHERE token = %s", (scene.claim,))  # noqa: S608
    scene.plant(inv)
    J.claim_for(scene, scene.argv("investigation", inv))
    assert execute(scene.dsn, "SELECT 1 FROM jobs.claims WHERE token = %s AND investigation_id = %s", (scene.claim, inv)), (
        "premise: the investigation's claim was not planted (plant it while the tenant is still claimable)")
    return inv


def investigate(scene: HelperScene, *, signer: Any = None, docker: ContainerStandIn | None = None, inv: str | None = None,
                **seams: Any) -> Investigated:
    """The helper for a planted investigation of the scene's tenant (`inv`: one `plant_premise` planted already, else
    planted now). Green at the base: a premise, never the subject."""
    job = inv if inv is not None else plant_premise(scene)
    docker = docker if docker is not None else ContainerStandIn(lambda c: 0)  # lint-default: ok — a test seam resolving its own default
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        ran = drive_helper(scene, scene.argv("investigation", job), docker=docker,
                           signer=signer if signer is not None else make_signer(), **seams)
    assert ran.raised is None, ran.raised
    return Investigated(job, ran, docker, err.getvalue(), scene.end(job))


# --- the subject: readiness ---------------------------------------------------------------------------------------

@dataclass
class Readied:
    """One helper-and-container run of a readiness check."""

    scene: HelperScene
    rid: str
    ran: HelperRan
    docker: ContainerStandIn
    err: str
    container_exit: BaseException | None = None
    container_raised: BaseException | None = None
    container_rc: int | None = None
    facts: dict[str, Any] | None = None
    extra: dict[str, Any] = field(default_factory=dict)
    #: The claim the check ran under (#1546: its typed records are staged facts of this token).
    token: str = ""

    @property
    def record_path(self) -> Path:
        """Where the record was a file before #1546 (A-O2: nothing is written there now)."""
        return self.scene.runs / f"{self.rid}.readiness.json"

    @property
    def knowledge_path(self) -> Path:
        return self.scene.runs / f"{self.rid}.knowledge-source.json"

    def staged(self) -> dict[str, Any]:
        """The claim's staged facts (#1546 PR2: the helper's typed records), name -> body."""
        from defender.tests.support.shared._postgres1339 import execute

        return dict(execute(self.scene.dsn, "SELECT name, body FROM jobs.staged_facts WHERE token = %s", (self.token,)))

    @property
    def record(self) -> Any:
        """The readiness record as the helper staged it (`result`), or None (#1546 D5: no record file)."""
        return self.staged().get("result")

    @property
    def knowledge(self) -> Any:
        """The check's knowledge record as the helper staged it (`knowledge`), or None."""
        return self.staged().get("knowledge")

    def said(self) -> str:
        """Everything a failing case should show: the record, the helper's stderr, a container fault."""
        return (f"record={self.record!r}; helper rc={self.ran.rc!r} raised={self.ran.raised!r}; "
                f"container exit={self.container_exit!r} raised={self.container_raised!r}; "
                f"docker.job_error={self.docker.job_error!r}; stderr tail={self.err[-1500:]!r}")

    def result(self) -> dict[str, Any]:
        """The one readiness record, asserted present first: the point where a missing helper or container is red."""
        record = self.record
        assert isinstance(record, dict), f"no readiness record was written: {self.said()}"
        return record


def entry_of(scene: HelperScene, rid: str, done: Readied, *, roster: Any = None,
             defender_dir: Path | None = None) -> Callable[[Any], int]:
    """The container's process: `run.readiness_main` over the container's own environment, reading `defender_dir` (the
    one code tree its census and roster read, surface §4) when given."""
    tree = {} if defender_dir is None else {"defender_dir": defender_dir}

    def run(container: Any) -> int:
        from defender import run as run_py

        try:
            done.container_rc = int(run_py.readiness_main(["--readiness", rid, "--tenant", scene.tenant],
                                                          environ=container.env, roster=roster, **tree))
            return done.container_rc
        except SystemExit as exited:
            done.container_exit = exited
            return exited.code if isinstance(exited.code, int) else 1
        except BaseException as crashed:  # noqa: BLE001 — kept for the case to name
            done.container_raised = crashed
            return 99

    return run


def readiness(  # noqa: PLR0913 — one keyword per seam the helper takes
              scene: HelperScene, *, signer: Any = None, docker: ContainerStandIn | None = None, rid: str | None = None,
              container: Callable[[Any], int] | None = None, roster: Any = None, fetch: Callable[..., str] | None = None,
              defender_dir: Path | None = None, directory: Any = None, staged: dict[str, Any] | None = None,
              client: Any = None) -> Readied:
    """The helper for a readiness check of the scene's tenant (kind `readiness`, job id `rid`), its container the real
    `readiness_main` unless `container(Container) -> rc` says otherwise. `fetch` is the one knowledge fetch seam (#1618:
    default the real fetch child over the scene's remote, `drive_helper`'s). `defender_dir`: the code tree the container entry reads. `directory`: the tenant records the helper is handed (`job_host.main(directory=)`),
    passed only when given. `staged`: facts (name -> body) already staged under the claim when the helper starts, as a crash
    or a second run would leave them. #1546: the request row (running) and its claim under the scene's claim token are planted
    first, as the worker's claim leaves them (`claim_check`); the helper is configured with the real store and the tenant's
    evidence key by `drive_helper` (an unconfigured store is refused at setup). Never raises for the subject's absence: the
    caller reads `.result()`."""
    rid = rid or str(uuid.uuid4())
    claim_check(scene, rid)
    for name, body in (staged or {}).items():
        stage_fact(scene, name, body)
    done = Readied(scene, rid, HelperRan(), ContainerStandIn(), "", token=scene.claim)
    stand_in = docker if docker is not None else ContainerStandIn()

    def captured(c: Any) -> int:
        with contextlib.suppress(Exception):
            done.facts = c.request("launch")
        return (container or entry_of(scene, rid, done, roster=roster, defender_dir=defender_dir))(c)

    stand_in.job = captured
    done.docker = stand_in
    seams: dict[str, Any] = {} if fetch is None else {"fetch": fetch}
    if directory is not None:
        seams["directory"] = directory
    if client is not None:  # #1618 D9: the forge client the branch-protection read uses (`job_host.main(client=)`)
        seams["client"] = client
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        done.ran = drive_helper(scene, scene.argv("readiness", rid), docker=stand_in,
                                signer=signer if signer is not None else make_signer(), **seams)
    done.err = err.getvalue()
    return done


def stage_fact(scene: HelperScene, name: str, body: Any) -> None:
    """One fact under the scene's claim as an earlier helper (or a fault) left it."""
    from defender.tests.support.shared._postgres1339 import execute

    execute(scene.dsn, "INSERT INTO jobs.staged_facts (token, name, body, staged_at) VALUES (%s, %s, %s::jsonb, now())",
            (scene.claim, name, json.dumps(body)))


def claim_check(scene: HelperScene, rid: str) -> None:
    """The running readiness row `rid` and its claim under `scene.claim`, as the worker's claim transaction leaves them
    (#1546 PR7). A second check in one scene first ends the previous live row (`failed/worker_error`, as a lapse would) and
    drops the previous claim's rows, so the scene's one claim token names this check."""
    host_claim(scene, "readiness", rid)


def host_claim(scene: HelperScene, kind: str, rid: str, *, system: str | None = None) -> None:
    """`claim_check` for a host request of `kind` (readiness or adoption; an adoption row names its `system`)."""
    from defender.tests.support.jobs._host_requests1471 import plant
    from defender.tests.support.shared._postgres1339 import execute

    if execute(scene.dsn, "SELECT 1 FROM jobs.claims WHERE token = %s AND kind = %s AND host_request_id = %s",
               (scene.claim, kind, rid)):
        return  # the case planted this request's own row and claim: kept as it wrote them
    execute(scene.dsn, "UPDATE jobs.host_requests SET stage = 'failed', failure_reason = 'worker_error', finished_at = now(), "
                       "lease_expires_at = NULL WHERE tenant_id = %s AND kind = %s AND stage IN ('queued', 'running') "
                       "AND id <> %s", (scene.tenant, kind, rid))
    for table in ("staged_facts", "uploads", "claims"):
        execute(scene.dsn, f"DELETE FROM jobs.{table} WHERE token = %s", (scene.claim,))  # noqa: S608 — fixed names
    if not execute(scene.dsn, "SELECT 1 FROM jobs.host_requests WHERE id = %s", (rid,)):
        plant(scene.dsn, scene.tenant, kind, system=system, stage="running", request_id=rid)
    execute(scene.dsn, "INSERT INTO jobs.claims (token, tenant_id, kind, host_request_id, launch, inputs) "
                       "VALUES (%s, %s, %s, %s, '{}'::jsonb, '[]'::jsonb)", (scene.claim, scene.tenant, kind, rid))


# --- test-only doubles and planted trees ----------------------------------------------------------------------------

class RestatingDirectory:
    """The real Postgres `TenantDirectory` (as a production host process builds it from `DEFENDER_DATABASE_DSN`), delegating
    everything; once `admission()` has answered `active` for the scene's tenant it moves the tenant to `state`, so the
    next real read of the tenant's records refuses (an offboarding racing the check). Records what it was asked."""

    def __init__(self, scene: HelperScene, *, state: str = "offboarding") -> None:
        from defender import tenancy

        self._real = tenancy.host_directory(None, check_version=lambda _dsn: None)
        self._scene, self._state = scene, state
        self.admitted_active = False
        self.restated = False
        self.records_asked: list[str] = []

    def admission(self, tenant_id: Any) -> Any:
        from defender.tests.support.jobs._jobs1342 import move_tenant

        answer = self._real.admission(tenant_id)
        if answer[0] == "active" and not self.restated:
            self.admitted_active = True
            self.restated = True
            # In place, as the lifecycle moves it (#1546: the claimed job's row and claim name the tenant, so it is not replaced).
            move_tenant(self._scene.dsn, self._scene.tenant, state=self._state)
        return answer

    def current_records(self, tenant_id: Any) -> Any:
        self.records_asked.append(str(tenant_id))
        return self._real.current_records(tenant_id)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)


class ExplodingDocker(ContainerStandIn):
    """A docker seam whose attached `docker run` raises a plain exception (not `OSError`, which the helper reads as a start
    failure): an unexpected crash in the helper's setup, after its host half. Nothing is started."""

    def _run(self, argv: list[str], cli_env: dict[str, str] | None = None) -> Any:
        raise RuntimeError("docker exploded (1471 test double)")


def planted_code_tree(root: Path, *, blind: bool = False) -> Path:
    """A copy of the checkout's `integrations/` as a code tree at `root`; with `blind`, one more adapter, recorded by no
    system of any tenant, whose `VERBS` is built rather than a literal, so the cold verb reader sees no verb in it and
    no census can be taken over the tree (as `case_comment_1359/test_adapter_roster.py` builds one)."""
    import shutil

    from defender._paths import process_defender_dir

    shutil.copytree(process_defender_dir() / "integrations", root / "integrations",
                    ignore=shutil.ignore_patterns("__pycache__"))
    if blind:
        (root / "integrations" / "blindsys_adapter.py").write_text(
            "def health_check(ctx):\n    return {}\n\n\nVERBS = dict(a=health_check)\n", encoding="utf-8")
    return root


# --- shared assertions and scene pieces -----------------------------------------------------------------------------

def norm(text: str) -> str:
    return " ".join(text.lower().split())


def assert_refused_shape(record: Any, step: str) -> str:
    """`record` is exactly `{outcome: refused, step, sentence}` (R13-1.2/.3: no `knowledge`, no `commit`) at `step`, its
    sentence non-empty text naming no operator command (P-2, C9); the sentence."""
    assert isinstance(record, dict), f"no readiness record: {record!r}"
    assert set(record) == {"outcome", "step", "sentence"}, f"not the refused shape: {record!r}"
    assert record["outcome"] == "refused", record
    assert record["step"] == step, f"refused at {record['step']!r}, not {step!r}: {record!r}"
    sentence = record["sentence"]
    assert isinstance(sentence, str)
    assert sentence.strip(), f"an empty sentence: {record!r}"
    named = [w for w in OPERATOR_WORDS if w in sentence]
    assert not named, f"an admin is told to run an operator command {named}: {sentence!r}"
    return sentence


def listed_runs(scene: HelperScene) -> list[str]:
    """The tenant's runs as its runs repository lists them (a folder holding an entry it does not serve refuses)."""
    from defender import tenancy
    from defender._paths import process_defender_dir

    accepted = tenancy.accept_tenant(tenancy.resolve_data_root(), scene.tenant, defender_dir=process_defender_dir())
    return [str(r) for r in accepted.runs_repository().list()]


def judged_by_an_investigation(scene: HelperScene, monkeypatch: Any) -> dict[str, Any]:
    """What a real investigation's container judges of the scene's tenant at its start (the premise for the systems check
    and the case verdict): `{"started": bool, "down": {system: reason}, "exit": text|None, "case": verdict}`. Green at the base."""
    from defender import run as run_py
    from defender.investigation.challenge_gate import ReviewState
    from defender.kit.access import PROXY_URL_ENV
    from defender.systems import case_system
    from defender.tests.support.jobs._container_entry1170 import enter

    monkeypatch.setenv(PROXY_URL_ENV, "http://proxy.invalid")
    inv, seen = str(uuid.uuid4()), {"down": {}, "case": None, "ran": False}
    scene.plant(inv)

    def lifecycle(**kw: Any) -> dict[str, Any]:
        seen["ran"] = True
        seen["down"] = {n: c.reason for n, c in kw["systems"].down.items()}
        seen["case"] = case_system.case_verdict(kw["tenant"], defender_dir=run_py.DEFENDER_DIR, roster=kw["systems"].roster)
        facts = kw["job_facts"]
        facts.box, facts.scrub_verified = "started", True
        facts.review_state["state"] = ReviewState(closed=True)
        return {"output": "x", "requests": 0, "truncated_by": None, "closed_before_cut": False, "exit_reason": None}

    got = enter(scene, inv, lifecycle=lifecycle, preflight=lambda *a, **k: 0, visualize=lambda *a, **k: None)
    return {"started": seen["ran"], "down": seen["down"], "case": seen["case"],
            "exit": None if got.exit is None else str(got.exit.code)}


def requests_other_than(answered: tuple[str, ...]) -> list[str]:
    """Every request name the job helper registers for any kind, less `answered`: what a kind answering only those must
    refuse (`not-for-kind`), read from the helper's own registry so a request added later is in the class."""
    from defender.job_host import _main

    return sorted({name for name, _kind in _main.registry().handlers} - set(answered))

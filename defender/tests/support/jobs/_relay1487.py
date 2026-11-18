"""#1487 (design r5): machinery for the tick-store port's contract. The port is `JobContainer.tick_store()` over the job
socket, the adapter `StoreAdapter` over the in-process store; the helper is the real one (`job_host.main`), as a process
(`PostStepHelper`: the tick may run on the test's main thread and take SIGTERM there) or in process over a container
stand-in (`run_kind`, for a stop the test delivers itself).

Nothing here implements the port's policy: the wire request names are the implementer's, so a test learns them by
recording what the port sends (`Recorder`), never by naming them. `Canon` and `Runner` run one call sequence over a
`TickStore` and record each call's result or exception in a form that compares across implementations; the oracle for
"what the port answers" is the adapter's answer (P2), and the sequences' races are made on the database directly.

Also the learning job's hand-in rows (`defender_row`, `world_finding_row`, `admitted`), used by the findings suites."""
from __future__ import annotations

import contextlib
import dataclasses
import datetime as _dt
import os
import random
import re
import signal
import uuid
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path
from typing import Any

from defender.tests.support.learning.curation._drain719 import finding_row
from defender.tests.support.learning.curation._spec773 import world_row

#: The episode sink's channel names (`learning.core.state.FINDINGS`, `QUESTIONER_FINDINGS`) and each one's store kind.
FINDINGS, QUESTIONER = "findings", "questioner_findings"
KIND = {FINDINGS: "finding", QUESTIONER: "questioner_finding"}
_ANCHORED = {"subject_anchor": "the lead", "subject_topic": "the lead was never revisited"}


def defender_row(job_id: str, n: int = 0, **extra: Any) -> dict[str, Any]:
    """A held defender finding of the job's episode, as the judge leaves it: its id `<episode>/<world>/<draw>/<index>`."""
    return finding_row(f"{job_id}/w-b/0/{n}", run_id=job_id, subject="defender", **{**_ANCHORED, **extra})


def world_finding_row(job_id: str, n: int = 0, **extra: Any) -> dict[str, Any]:
    """A held questioner (world) finding of the job's episode."""
    return world_row(f"{job_id}/w-c/0/{n}", run_id=job_id, direction="world", type="mislabelled",
                     citations=["family.yaml#worlds"], **{**_ANCHORED, **extra})


def admitted(rows: dict[str, list[dict[str, Any]]]) -> None:
    """Premise: every row passes its channel's rule today (`judge.enqueue`), so a refusal is the helper's own."""
    from defender.learning.judge.enqueue import _validate_row, _validate_world_row

    for row in rows.get(FINDINGS, ()):
        _validate_row(row)
    for row in rows.get(QUESTIONER, ()):
        _validate_world_row(row)


# --- the two implementations of the tick's store, over one database ---------------------------------------------------

#: The tick's store implementations the conformance suites run over (P2): `adapter` is `StoreAdapter` over the in-process
#: store; `port` is `JobContainer.tick_store()` over the real helper's job socket.
IMPLS = ("adapter", "port")
#: What the adapter is bound to; the port's owner is the helper's own, so a result's `owner` is not compared (`Canon`).
TICK_OWNER = "bound-owner"
#: The settings both sides hold: a lease and grace no test outlives, a renewer that never fires.
LEASE, GRACE, RENEW = 600.0, 300.0, 600.0
_AUTHOR = "author"


def due_thresholds() -> dict[str, int]:
    """One item of any kind is due: the thresholds `settings_env` gives the helper, spelled for the adapter."""
    return {"finding": 1, "questioner_finding": 1, "pitfall": 1, "curation_request": 1, "feedback_instruction": 1}


def settings_env(monkeypatch: Any, *, lease: float = LEASE, grace: float = GRACE, renew: float = RENEW,
                 threshold: int = 1) -> None:
    """The settings the helper reads from the worker's environment (set before the helper starts), the same numbers
    `adapter_store` is built with by default."""
    from defender.tests.support.learning.core._store1278 import GRACE_ENV, LEASE_ENV, RENEW_ENV

    monkeypatch.setenv(LEASE_ENV, str(lease))
    monkeypatch.setenv(GRACE_ENV, str(grace))
    monkeypatch.setenv(RENEW_ENV, str(renew))
    for name in ("LEARNING_AUTHOR_THRESHOLD", "LEARNING_QUESTIONER_THRESHOLD", "LEARNING_PITFALLS_THRESHOLD"):
        monkeypatch.setenv(name, str(threshold))


@contextlib.contextmanager
def adapter_store(dsn: str, tenant: str, *, lane: str = _AUTHOR, owner: str = TICK_OWNER,
                  thresholds: Mapping[str, int] | None = None, lease: float = LEASE, grace: float = GRACE,
                  renew: float = RENEW, **knobs: Any) -> Iterator[Any]:
    """The adapter over a blocking store on `dsn`, bound to `tenant`, `lane`, `owner` and `thresholds`."""
    from defender.learning_store import blocking
    from defender.learning_store.tick import StoreAdapter

    with blocking(dsn, lease=lease, grace=grace, renew_every=renew, **knobs) as raw:
        yield StoreAdapter(raw, tenant=tenant, lane=lane, owner=owner,
                           thresholds=dict(due_thresholds() if thresholds is None else thresholds))


class Recorder:
    """A job-socket client (`ask(name, **fields)`) that records each request it sends, and can fail the next one as the
    transport would (an exception raised instead of the call): what a request that never got an answer looks like."""

    def __init__(self, ask: Callable[..., dict[str, Any]]) -> None:
        self._ask = ask
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self._fail: BaseException | None = None
        self._answer: Any = None
        self._answers = False

    def answer_next(self, answer: Any) -> None:
        """The next request is answered `answer`, not sent: an answer that is not what the port asked for."""
        self._answer, self._answers = answer, True

    def fail_next(self, error: BaseException) -> None:
        self._fail = error

    def __call__(self, name: str, **fields: Any) -> dict[str, Any]:
        self.calls.append((name, dict(fields)))
        if self._fail is not None:
            error, self._fail = self._fail, None
            raise error
        if self._answers:
            self._answers = False
            return self._answer
        return self._ask(name, **fields)


def adopt_scene(t: Any, dsn: str, monkeypatch: Any) -> Any:
    """A helper scene over a tenant a case already published and registered active in `dsn` (the tick tests' `world`),
    for a `PostStepHelper`: the worker's claim in the environment, the tenant's runs folder. What `helper_scene` builds
    around a tenant of its own, without making another."""
    from defender.box import CLAIM_ENV
    from defender.tests.support.jobs._job_helper import HelperScene

    claim = uuid.uuid4().hex
    monkeypatch.setenv(CLAIM_ENV, claim)  # the worker hands each child its claim (`_worker._spawn`)
    monkeypatch.setenv("DEFENDER_DATA_ROOT", str(t.data_root))
    monkeypatch.setenv("DEFENDER_DATABASE_DSN", dsn)  # the helper holds the database login (N7)
    runs = Path(t.data_root) / t.tenant_id / "runs"
    runs.mkdir(parents=True, exist_ok=True)
    return HelperScene(Path(t.data_root), t, runs, dsn, claim)


class PostStepHelper:
    """The real post-step helper as a process of its own over the scene's tenant (`ProcessHelper`: its container a stand-in
    that reads its stdin), with the job socket's host path. The helper reads its settings from the environment at start:
    set `settings_env` (and any database address) first. `port()` is the tick's store over that socket; the tick may run on
    the test's main thread, taking its SIGTERM there. One helper at a time per scene (it holds the tenant's lock); `close()`
    before the next."""

    _count = 0

    def __init__(self, scene: Any, root: Path) -> None:
        from defender import job_host
        from defender.tests.support.jobs import _job_helper as J

        PostStepHelper._count += 1
        self.scene = scene
        argv = scene.argv("post-step", None)
        argv[-1] = "@worker"
        self._process = J.ProcessHelper(scene, root / f"helper-{PostStepHelper._count}", argv, worker=True)
        try:
            self._process.container_pid(timeout=60)
            (record,) = self._process.records().values()
            inside = J.parse_env(record["argv"])[job_host.SOCKET_ENV]
            self.socket = J.host_path(J.parse_mounts(record["argv"]), str(inside))
        except BaseException:
            self._process.close()
            raise

    def ask(self, name: str, **fields: Any) -> dict[str, Any]:
        from defender import job_host

        return job_host.ask(self.socket, name, **fields)

    def container(self, ask: Callable[..., dict[str, Any]] | None = None) -> Any:
        from defender.learning.branch.container import JobContainer

        return JobContainer.connect(ask or self.ask, tenant=self.scene.tenant)

    def port(self, ask: Callable[..., dict[str, Any]] | None = None) -> Any:
        return self.container(ask).tick_store()

    def signal(self) -> None:
        """Tell the helper to stop, as the worker does."""
        os.kill(self._process.helper_pid, signal.SIGTERM)

    def close(self) -> None:
        self._process.close()


def in_post_step(scene: Any, body: Callable[[Any], Any], *, rc: int = 0) -> Any:
    """`body(container)` run as the post-step container's one process, over the real helper in this process
    (`run_kind`); its value, or the exception it raised, comes back here. For a stop the test delivers itself
    (`os.kill(os.getpid(), SIGTERM)` from `body`, then `container.stopping.wait`): the tick's own stop path, which
    needs the main thread, is for `PostStepHelper`."""
    from defender.tests.support.jobs._job_helper_learning import run_kind

    got: dict[str, Any] = {}

    def job(container: Any) -> int:
        try:
            got["value"] = body(container)
        except BaseException as raised:  # noqa: BLE001 — handed back to the test thread
            got["raised"] = raised
        return rc

    run_kind(scene, "post-step", job, family_less=True)
    if "raised" in got:
        raise got["raised"]
    return got.get("value")


def container_port(container: Any, tenant: str) -> Any:
    """The tick's store over a container stand-in's own socket."""
    from defender.learning.branch.container import JobContainer

    return JobContainer.connect(container.request, tenant=tenant).tick_store()


# --- comparing the two implementations' answers ------------------------------------------------------------------------

#: A record id, or the 12 hex digits a batch's branch ends in (`lessons/<12 hex>`): minted anew by each run.
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|(?<=/)[0-9a-f]{12}\b")


class Canon:
    """A result or exception in a form two runs compare: record ids by order of first appearance, a datetime as its
    awareness and offset, a bound owner as `<bound>`, dataclasses by type name and fields, a list apart from a tuple.
    One `Canon` per run (its labels are that run's)."""

    def __init__(self) -> None:
        self._ids: dict[str, str] = {}

    def text(self, value: str) -> str:
        return _UUID.sub(lambda m: self._ids.setdefault(m.group(0), f"#{len(self._ids)}"), value)

    def __call__(self, value: Any) -> Any:  # noqa: PLR0911 — one arm per shape
        if value is None or isinstance(value, (bool, int, float)):
            return value
        if isinstance(value, str):
            kind = type(value).__name__
            return self.text(value) if kind == "str" else (kind, self.text(value))
        if isinstance(value, (bytes, bytearray)):
            return ("bytes", bytes(value))
        if isinstance(value, _dt.datetime):
            return ("datetime", value.tzinfo is None, value.utcoffset())
        if dataclasses.is_dataclass(value) and not isinstance(value, type):
            return (type(value).__name__, {f.name: "<bound>" if f.name == "owner" else self(getattr(value, f.name))
                                           for f in dataclasses.fields(value)})
        if isinstance(value, Mapping):
            return ("map", sorted(((self(k), self(v)) for k, v in value.items()), key=repr))
        if isinstance(value, (list, tuple)):
            return (type(value).__name__, [self(v) for v in value])
        if isinstance(value, (set, frozenset)):
            return ("set", sorted((self(v) for v in value), key=repr))
        return ("object", type(value).__name__, self.text(repr(value)))

    def outcome(self, call: Callable[[], Any]) -> tuple:
        """`("ok", result)` or `("raised", exception class, its arguments)`; the one outage exception is compared by
        class alone (its words are each side's own)."""
        try:
            result = call()
        except Exception as raised:  # noqa: BLE001 — the exception is the observation
            name = f"{type(raised).__module__}.{type(raised).__qualname__}"
            return ("raised", name, None if type(raised).__name__ == "StoreUnavailable" else self(raised.args))
        return ("ok", self(result))


def issued_by_listing(view: Any) -> bool:
    """Whether the helper issues this listed batch's id (design Flow 2): an own-lane batch in review, closing or lapsed;
    another reconcile lane's in review or closing. The sequences act only on ids a tick could hold."""
    closing = (view.kind != "registry" and view.phase == "ended" and view.outcome == "abandoned"
               and view.pr_number is not None
               and (view.last_checked is None or (view.ended_at is not None and view.last_checked < view.ended_at)))
    if view.lane == _AUTHOR:
        return view.phase == "in_review" or closing or bool(view.lapsed)
    return view.phase == "in_review" or closing


def reset_learning(dsn: str) -> None:
    """Every learning row gone, so the same seed can be laid down again for the next implementation's run."""
    from defender.tests.support.shared._postgres1339 import execute

    execute(dsn, "TRUNCATE learning.commit_changes, learning.commits, learning.work_items, learning.batches CASCADE")


def seed_work(dsn: str, tenant: str, *, findings: int = 3, lead_review: bool = True) -> None:
    """The state a sequence starts from, laid down on the database directly: `findings` waiting defender findings and a
    questioner finding, and (`lead_review`) a lead-lane batch in review for the other lane's reconcile."""
    from defender.tests.support.learning.core._store1278 import FINDING, QUESTIONER, call, finding, world_finding

    call(dsn, "publish_findings", tenant, "run-seed", [finding(f"seed/w/0/{i}") for i in range(findings)], kind=FINDING)
    call(dsn, "publish_findings", tenant, "run-seed", [world_finding("seed/q/0/0")], kind=QUESTIONER)
    if lead_review:
        lead_batch_in_review(dsn, tenant)


def lead_batch_in_review(dsn: str, tenant: str, *, pr: int = 41) -> str:
    """A lead-lane batch in review (a pitfall claimed and its PR recorded), made on the database directly: another
    reconcile lane's batch for the tick to see. Its id."""
    from defender.tests.support.learning.core._store1278 import LEAD_LANE, ONE, call

    for n in range(2):
        call(dsn, "add_pitfall", tenant, {"schema_version": 1, "source_run": f"r{n}", "system": "elastic",
                                          "query_id": "elastic.esql", "goal": f"goal {n}", "executed_query": f"q {n}",
                                          "stderr_digest": "", "error_class": "agent-fixable"})
    held = call(dsn, "claim", tenant, LEAD_LANE, owner="lead-operator", thresholds=ONE)
    assert held is not None, "premise: the lead lane claimed its pitfalls"
    call(dsn, "in_review", held, pr, {})
    return str(held.batch_id)


def _delete_batch(dsn: str, batch_id: str) -> None:
    """A batch an offboarding purge deleted, as the tick's listing may still name it: its rows removed directly."""
    from defender.tests.support.shared._postgres1339 import execute

    execute(dsn, "DELETE FROM learning.commit_changes WHERE commit_row IN "
                 "(SELECT id FROM learning.commits WHERE batch_id = %s)", (batch_id,))
    execute(dsn, "DELETE FROM learning.commits WHERE batch_id = %s", (batch_id,))
    execute(dsn, "DELETE FROM learning.work_items WHERE batch_id = %s", (batch_id,))
    execute(dsn, "DELETE FROM learning.batches WHERE id = %s", (batch_id,))


class Runner:
    """One call sequence over a `TickStore`, each step's result or exception canonical (`Canon`). A step names a verb and
    which of the batches it holds (`helds`, in the order claimed) or the ids a listing issued (`listed`, from the last
    `batches()`) it acts on, by index; a step whose target is not there is `("skipped",)` in every run alike. A `race`
    step acts on the database directly, as a second reconciler, a lapse, a cancel or new work would."""

    def __init__(self, store: Any, dsn: str, tenant: str) -> None:
        self.store, self.dsn, self.tenant = store, dsn, tenant
        self.canon = Canon()
        self.helds: list[Any] = []
        self.listed: list[Any] = []
        self.commits = 0

    def run(self, ops: list[tuple]) -> list[tuple]:
        return [self.step(op) for op in ops]

    def step(self, op: tuple) -> tuple:
        name, *args = op
        method = getattr(self, f"_{name}")
        target = method(*args)
        if target is None:
            return ("skipped",)
        return self.canon.outcome(target)

    # -- targets: a thunk to call and canonicalise, or None -------------------------------------------------------

    def _held(self, i: int) -> Any | None:
        return self.helds[i % len(self.helds)] if self.helds else None

    def _listed(self, i: int, *, own_lapsed: bool = False, own: bool = False, review: bool = False) -> Any | None:
        pool = [b for b in self.listed
                if (not own_lapsed or (b.lane == _AUTHOR and b.lapsed)) and (not own or b.lane == _AUTHOR)
                and (not review or b.phase == "in_review")]
        return pool[i % len(pool)] if pool else None

    def _batches(self) -> Callable[[], Any]:
        def go() -> Any:
            views = self.store.batches()
            self.listed = [b for b in views if issued_by_listing(b)]
            return views
        return go

    def _lane_work(self) -> Callable[[], Any]:
        return lambda: self.store.lane_work()

    def _work(self) -> Callable[[], Any]:
        return lambda: self.store.work(statuses=("waiting", "in_batch"))

    def _commit_record(self) -> Callable[[], Any]:
        return lambda: self.store.commit_record()

    def _claim(self) -> Callable[[], Any]:
        def go() -> Any:
            held = self.store.claim()
            if held is not None:
                self.helds.append(held)
            return held
        return go

    def _take_over(self, i: int) -> Callable[[], Any] | None:
        view = self._listed(i, own_lapsed=True)
        if view is None:
            return None

        def go() -> Any:
            held = self.store.take_over(str(view.id))
            self.helds.append(held)
            return held
        return go

    def _holder_verb(self, verb: str, i: int, *args: Any) -> Callable[[], Any] | None:
        held = self._held(i)
        return None if held is None else (lambda: getattr(self.store, verb)(held, *args))

    def _renew(self, i: int) -> Callable[[], Any] | None:
        return self._holder_verb("renew", i)

    def _record_commit(self, i: int) -> Callable[[], Any] | None:
        from defender.tests.support.learning.core._store1278 import changes_of, oid

        self.commits += 1
        n = self.commits
        return self._holder_verb("record_commit", i, oid(n), oid(1000), oid(1001), changes_of(f"agent/lessons/{n}.md"))

    def _in_review(self, i: int, pr: int) -> Callable[[], Any] | None:
        return self._holder_verb("in_review", i, pr, {})

    def _expire_own(self, i: int) -> Callable[[], Any] | None:
        return self._holder_verb("expire_own", i)

    def _abandon_clean(self, i: int) -> Callable[[], Any] | None:
        return self._holder_verb("abandon_clean", i)

    def _abandon_crashed(self, i: int) -> Callable[[], Any] | None:
        return self._holder_verb("abandon_crashed", i)

    def _end_no_commits(self, i: int) -> Callable[[], Any] | None:
        return self._holder_verb("end_no_commits", i, {})

    def _abandon(self, i: int) -> Callable[[], Any] | None:
        view = self._listed(i, own_lapsed=True)
        return None if view is None else (lambda: self.store.abandon(str(view.id)))

    def _note_check(self, i: int, reset: bool) -> Callable[[], Any] | None:
        view = self._listed(i)
        return None if view is None else (lambda: self.store.note_check(str(view.id), reset_refusals=reset))

    def _note_refusal(self, i: int) -> Callable[[], Any] | None:
        view = self._listed(i)
        return None if view is None else (lambda: self.store.note_refusal(str(view.id), "the forge said no"))

    def _needs_person(self, i: int) -> Callable[[], Any] | None:
        view = self._listed(i, own=True)
        return None if view is None else (lambda: self.store.needs_person(str(view.id), "a foreign tip"))

    def _end_review(self, i: int, outcome: str) -> Callable[[], Any] | None:
        view = self._listed(i, review=True)
        return None if view is None else (lambda: self.store.end_review(
            str(view.id), expect_phase="in_review", outcome=outcome, published=[], held=[]))

    # -- races: acts on the database, answered ("race", what it raised or None) -----------------------------------

    def _race(self, what: str, i: int = 0) -> Callable[[], Any] | None:
        from defender.tests.support.learning.core._store1278 import FINDING, call, finding, lapse_lease

        held = self._held(i)
        view = self._listed(i, review=True)
        if what in ("lapse", "rival_takeover") and held is not None:
            def lapse() -> Any:
                lapse_lease(self.dsn, str(held.batch_id))
                if what == "rival_takeover":
                    call(self.dsn, "take_over", self.tenant, str(held.batch_id), owner="rival-reconciler")
                return "raced"
            return lapse
        if what == "rival_ends" and view is not None:
            return lambda: call(self.dsn, "end_review", self.tenant, str(view.id), expect_phase="in_review",
                                outcome="merged", published=[], held=[]) and "raced"
        if what == "cancel":
            return lambda: call(self.dsn, "request_cancel", self.tenant) or "raced"
        if what == "rival_claim":
            return lambda: (call(self.dsn, "claim", self.tenant, _AUTHOR, owner="rival-claimer",
                                 thresholds=due_thresholds()), "raced")[1]
        if what == "delete_batch" and view is not None:
            return lambda: _delete_batch(self.dsn, str(view.id)) or "raced"
        if what == "more_work":
            return lambda: call(self.dsn, "publish_findings", self.tenant, "run-more",
                                [finding(f"more/w/0/{i}-{len(self.helds)}")], kind=FINDING) or "raced"
        return None


def generate(seed: int, length: int = 18) -> list[tuple]:
    """A call sequence of the census's verbs and races, from `seed`: a tick's own order is not assumed, so a verb is as
    likely to meet a lost lease, a rival's takeover or an ended batch as a live one."""
    rnd = random.Random(seed)
    menu: list[Callable[[], tuple]] = [
        lambda: ("batches",), lambda: ("batches",), lambda: ("lane_work",), lambda: ("work",),
        lambda: ("commit_record",), lambda: ("claim",), lambda: ("claim",),
        lambda: ("take_over", rnd.randrange(3)), lambda: ("renew", rnd.randrange(3)),
        lambda: ("record_commit", rnd.randrange(3)), lambda: ("in_review", rnd.randrange(3), rnd.randrange(1, 90)),
        lambda: ("expire_own", rnd.randrange(3)), lambda: ("abandon_clean", rnd.randrange(3)),
        lambda: ("abandon_crashed", rnd.randrange(3)), lambda: ("end_no_commits", rnd.randrange(3)),
        lambda: ("abandon", rnd.randrange(3)), lambda: ("note_check", rnd.randrange(3), rnd.random() < 0.5),
        lambda: ("note_refusal", rnd.randrange(3)), lambda: ("needs_person", rnd.randrange(3)),
        lambda: ("end_review", rnd.randrange(3), rnd.choice(["merged", "closed"])),
        lambda: ("race", "lapse", rnd.randrange(3)), lambda: ("race", "rival_takeover", rnd.randrange(3)),
        lambda: ("race", "rival_ends", rnd.randrange(3)), lambda: ("race", "cancel"),
        lambda: ("race", "more_work", rnd.randrange(3)),
    ]
    ops: list[tuple] = [("claim",)]
    for _ in range(length):
        ops.append(rnd.choice(menu)())
        if rnd.random() < 0.3:
            ops.append(("batches",))
    return ops


#: A tick's own order, written out: the scripts the generated sequences are checked against (each ends in what the
#: adapter does; see `test_1487_tick_store_conformance`).
LIFE = [("claim",), ("record_commit", 0), ("renew", 0), ("in_review", 0, 7), ("batches",), ("end_review", 0, "merged"),
        ("work",), ("commit_record",)]


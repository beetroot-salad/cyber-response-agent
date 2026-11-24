"""#1342 O16: one hermetic replay through the real worker lane, child process included.

The real `Worker` (in-process) over a per-test database claims a queued investigation, stages its claim and
spawns `_helper_child1546_replay.py` (`_helper_child1170.py` over a real evidence store, #1546): the real per-job host helper
(#1170 r4: admission, launch check, publish and the run's folders are its) whose job container is `_job_entry1342.py`, which
runs the real in-container job entry with the replay harness's seams (an unboxed executor handed through the lifecycle's
`start_box` seam, never the environment; a replay model closing with the golden's disposition). The row is read back from the
database, the run from the bundle the job stored."""
from __future__ import annotations

import dataclasses
import hashlib
import io
import json
import shutil
import sys
import tarfile
import tempfile
import uuid
from pathlib import Path

import pytest

from defender.tests.e2e._replay_harness import committed_record, golden_disposition, priced_billed, priced_cost
from defender.tests.support.evidence._evidence1546 import evidence_keys, garage  # noqa: F401 — fixtures
from defender.tests.support.evidence._facts1546 import evidence_env
from defender.tests.support.jobs._evidence_flows1546 import claim_of, facts, sha
from defender.tests.support.jobs._helper_evidence1546 import evidence_login
from defender.tests.support.jobs._jobs1342 import (
    DEFENDER,
    StandInContainers,
    an_alert,
    is_box_token,
    job_store,
    lower_limit,
    make_worker,
    register_tenant,
    row,
)
from defender.tests.support.jobs._job_helper import no_proxy_records
from defender.tests.support.presentation import _cost_page_1377 as C
from defender.tests.support.shared._openbao1163 import openbao  # noqa: F401 — fixture
from defender.tests.support.shared._postgres1339 import execute, migrated_database  # noqa: F401 — fixture
from defender.tests.support.tenancy._mapping1345 import FIXTURE_ALERT_MAPPING, remove_postgres_mapping, seed_postgres

pytestmark = [pytest.mark.anyio, pytest.mark.postgres, pytest.mark.e2e, pytest.mark.openbao, pytest.mark.garage]

# #1546 (A-O1, A-O2, r8 "An unconfigured store or evidence-key login is refused at helper setup, terminally"): the lane has the
# store a job needs. Garage and OpenBao stand behind the helper as in `e2e/test_1546_evidence_replay.py` (the store from
# `DEFENDER_EVIDENCE_*`, the tenant's key `evidence-<T>` and its AppRole login, handed through `_helper_child1546_replay.py`).
# A job's run, session store and ledger no longer live in the host's tenant folder (they are in the claim's root, gone after the
# job), so what these cases read of the run is the run held in the job's own stored bundle (`Lane.run`: fetched with the
# data key the upload row's wrapped key unwraps to, extracted here), and the alert and launch facts are read from the claim
# row. Kept as before: the ledger cost exact (and its lower-limit mark), the box token handed to `start`, the served knowledge.

CHILD = Path(__file__).resolve().parents[1] / "support" / "jobs" / "_helper_child1546_replay.py"
LOGIN_ENV = "DEFENDER_TEST_EVIDENCE_LOGIN"  # `_helper_child1546_replay.py` reads the tenant's key login from it


@dataclasses.dataclass
class Lane:
    """The evidence store behind one tenant's replay: the helper's child is built over it, the stored run read back from it."""

    garage: object
    keys: object
    dsn: str
    tenant: str

    def child(self, launch, mode: str, commit: str, marks: Path, *, remote: Path,
              stderr_to: Path | None = None) -> list[str]:
        """A worker's `child_argv` answer: the real helper over the store, in front of the replay job entry (`helper_child`'s
        shape; `remote` is the tenant's bare repository the helper's knowledge fetch reads, #1618)."""
        ticket = [*(["--alert-digest", launch.alert_digest] if launch.alert_digest is not None else []),
                  *(["--post-ticket", "--ticket-link", launch.ticket_link] if launch.update_ticket else [])]
        child = [sys.executable, str(CHILD), mode, commit, str(marks), str(remote), "--job", launch.investigation_id,
                 "--tenant", launch.tenant_id, "--parent-pid", str(launch.parent_pid), *ticket]
        return ["/bin/sh", "-c", 'exec "$@" 2>>"$0"', str(stderr_to), *child] if stderr_to is not None else child

    def bundle(self, investigation: str) -> bytes | None:
        """The investigation's stored bundle (read with the data key its upload row's wrapped key unwraps to), or None."""
        token = claim_of(self.dsn, "investigation", investigation)
        found = execute(self.dsn, "SELECT wrapped_key, sha256 FROM jobs.uploads WHERE token = %s AND object = 'bundle' "
                                  "AND status = 'uploaded'", (token,)) if token else []
        if not found:
            return None
        [(wrapped, digest)] = found
        got = self.garage.get(f"t/{self.tenant}/investigation/{investigation}/{token}/bundle",
                              sse_key=self.keys.unwrap(self.tenant, wrapped))
        assert got.status_code == 200, f"the stored bundle could not be read back: {got.status_code} {got.text[:300]!r}"
        body = got.content
        assert sha(body) == digest, "the stored bundle is not the bytes its row recorded"
        return body

    def run(self, investigation: str, dest: Path) -> Path:
        """The run folder held in the investigation's stored bundle, extracted under `dest` (a copy a case may read or change)."""
        investigation = str(investigation)  # an `InvestigationId` (a str subclass) cannot be a glob pattern
        body = self.bundle(investigation)
        assert body is not None, f"premise: the job stored a bundle ({self.uploads(investigation)})"
        with tarfile.open(fileobj=io.BytesIO(body), mode="r:gz") as packed:
            packed.extractall(dest, filter="data")
        found = [p for p in dest.rglob(investigation) if p.is_dir() and p.parent.name == "runs"]
        assert len(found) == 1, f"the bundle holds {len(found)} runs named {investigation}: {sorted(str(p) for p in dest.rglob('*'))[:40]}"
        _relocate_pointers(found[0].parent, found[0].parent.parent)
        return found[0]

    def uploads(self, investigation: str) -> list[tuple]:
        token = claim_of(self.dsn, "investigation", investigation)
        return execute(self.dsn, "SELECT object, status FROM jobs.uploads WHERE token = %s", (token,))


def _relocate_pointers(runs: Path, tenant_root: Path) -> None:
    """The bundle is the job's tenant folder from its root (design: Uploads, `bundle`), and a run's session pointer names its
    session database by the path it had there, under `.job-roots/<claim>/<tenant>/` (gone with the job). In the extracted
    copy each pointer is made to name the same database under the copy's tenant folder."""
    import re

    pattern = re.compile(r"[^\"]*/\.job-roots/[0-9a-f]+/[^/\"]+(?=/)")
    for pointer in runs.glob("*.session-pointer.json"):
        pointer.write_text(pattern.sub(lambda _m: str(tenant_root), pointer.read_text(encoding="utf-8")), encoding="utf-8")


def fresh_tenant() -> str:
    """A tenant id of this test alone. The store's objects live under `t/<tenant>/`, which the `garage` fixture empties at
    every test's end (`Garage.tenant_prefix`); the published fixture's id is shared by every helper suite running beside this
    one, whose teardown would empty this lane's prefix under it, so a lane publishes its tenant under its own id."""
    return str(uuid.uuid4())


def _lane(monkeypatch, dsn: str, tenant: str, openbao, garage, evidence_keys) -> Lane:  # noqa: F811 — the fixtures
    """The store the helper's setup needs for `tenant` (r8): Garage by the helper's own environment names, the tenant's
    `evidence-<T>` key in OpenBao and the AppRole login that holds the lifecycle's policy for it."""
    for name, value in evidence_env(garage).items():
        monkeypatch.setenv(name, value)
    evidence_keys.make(tenant)
    garage.tenant_prefix(tenant)
    monkeypatch.setenv(LOGIN_ENV, json.dumps({"addr": openbao.addr, **evidence_login(openbao, tenant)}))
    return Lane(garage, evidence_keys, dsn, tenant)


def _staged(dsn: str, investigation: str) -> dict:
    """The facts the helper staged under the investigation's claim (#1546: the end is read from rows, never job-end or launch
    files)."""
    token = claim_of(dsn, "investigation", investigation)
    assert token, "premise: the worker's claim wrote a claim row"
    return facts(dsn, token)


def _launch(dsn: str, investigation: str) -> dict:
    """The launch record as the claim holds it (`jobs.claims.launch`): alert digest, box token, label."""
    [(found,)] = execute(dsn, "SELECT launch FROM jobs.claims WHERE kind = 'investigation' AND investigation_id = %s",
                         (investigation,))
    return found



@pytest.fixture
def short_root():
    """The data root, short: the helper's job socket lives under it and a unix socket's path holds about 100 bytes, which
    pytest's nested temporary folders overrun."""
    root = Path(tempfile.mkdtemp(prefix="j", dir="/tmp"))
    yield root
    shutil.rmtree(root, ignore_errors=True)


@pytest.mark.parametrize("line_ends", ["as stored", "CRLF", "padded", "decomposed", "zwnbsp", "feff_rich"])
async def test_o16_a_replay_through_the_worker_lane_completes_with_its_disposition(
        migrated_database, tmp_path, monkeypatch, short_root, openbao, garage, evidence_keys, line_ends):  # noqa: F811
    """queued → completed with the golden's disposition, cost read from its sessions, knowledge current at the published commit; the run holds the alert's exact bytes, CRLF, padding whitespace, decomposed text and a U+FEFF inside a value included. (O16, r5 C1/C2: the real driver's review state is what the record's `report_committed` reads)"""
    from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B

    root = short_root
    monkeypatch.setenv("DEFENDER_DATA_ROOT", str(root))
    monkeypatch.setenv("DEFENDER_DATABASE_DSN", migrated_database)  # the child reads tenant records here (r6 R6-2)
    monkeypatch.delenv("DEFENDER_ALLOW_UNSANDBOXED", raising=False)
    golden = DEFENDER / "tests" / "fixtures" / "e2e" / "golden-v2sshd"
    disposition = golden_disposition(golden)
    golden_bytes = (golden / "alert.json").read_bytes()
    if line_ends == "CRLF":
        golden_bytes = golden_bytes.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
        assert b"\r\n" in golden_bytes, "premise: the alert has line ends to turn into CRLF"
    elif line_ends == "padded":
        golden_bytes = b"\n\t " + golden_bytes.rstrip(b"\n") + b"   \n"
    elif line_ends == "decomposed":
        document = json.loads(golden_bytes)
        document["analyst_note"] = "cafe\u0301"
        golden_bytes = (json.dumps(document, indent=2, ensure_ascii=False) + "\n").encode()
        assert "e\u0301".encode() in golden_bytes, "premise: a decomposed sequence in the stored bytes"
    elif line_ends == "zwnbsp":
        document = json.loads(golden_bytes)
        document["analyst_note"] = "a\ufeffb"
        golden_bytes = (json.dumps(document, indent=2, ensure_ascii=False) + "\n").encode()
        assert b"\xef\xbb\xbf" in golden_bytes, "premise: a U+FEFF in the stored bytes"
        assert not golden_bytes.startswith(b"\xef\xbb\xbf"), "premise: not a leading byte-order mark"
    elif line_ends == "feff_rich":
        document = json.loads(golden_bytes)
        document.update({"lead": "\ufeffx", "tail": "y\ufeff", "pair": "p\ufeff\ufeffq", "apart": "\ufeffm\ufeffn",
                         "k\ufeffey": 1})
        golden_bytes = (json.dumps(document, indent=2, ensure_ascii=False) + "\n").encode()
        bom = b"\xef\xbb\xbf"
        for shape in (b'"' + bom, bom + b'"', bom + bom, b"m" + bom + b"n", b'"k' + bom + b'ey":'):
            assert shape in golden_bytes, ("premise", shape)
    with B.run_tenant(tmp_path, root, tenant_id=fresh_tenant()) as t:
        register_tenant(migrated_database, t.tenant_id, data_root=root, records=no_proxy_records())
        (root / t.tenant_id / "runs").mkdir(exist_ok=True)  # R1: a set-up tenant has runs/
        lane = _lane(monkeypatch, migrated_database, t.tenant_id, openbao, garage, evidence_keys)

        def child(launch) -> list[str]:
            return lane.child(launch, "replay", t.commit, tmp_path / "marks", remote=t.remote)

        async with job_store(migrated_database) as store:
            alert = await an_alert(store, t.tenant_id, raw=golden_bytes)
            inv, _ = await store.create_investigation(t.tenant_id, alert.alert_id, "k1", actor="u-1")
            worker = make_worker(store, root, child, containers=StandInContainers(tmp_path / "containers"))
            await worker.drain()

        stored = row(migrated_database, inv.investigation_id)
        assert (stored["stage"], stored["disposition"], stored["failure_reason"]) == (
            "completed", disposition, None), stored
        # The run as the job's own stored bundle holds it (nothing of it stays on the host, A-O1).
        run = lane.run(inv.investigation_id, tmp_path / "stored")
        assert (run.parent / f"{inv.investigation_id}.session-pointer.json").is_file(), "premise: the run opened its session store"
        # CONFLICT-UPDATED (r7.1; was: pinned to $0.0 as an unpriced stand-in): the ledger's figure, a number and exact, not unknown.
        assert (type(stored["cost_usd"]), lower_limit(migrated_database, inv.investigation_id)) == (float, False), (
            "a clean replay's cost is a number read from the ledger, exact")
        assert stored["cost_usd"] > 0, "r7.1: a number, not $0: the stand-in is built under priced names"
        assert stored["knowledge"] == {"status": "current", "commit": t.commit, "stale_kind": None}
        closed = committed_record(run)
        assert closed is not None, "the replay's close left no closing record in the run's session database"
        assert closed.disposition == disposition, closed
        outcome = _staged(migrated_database, inv.investigation_id)["outcome"]
        assert {k: outcome[k] for k in ("setup", "box", "report_committed", "scrub", "cut_short")} == {
            "setup": "done", "box": "started", "report_committed": True, "scrub": "clean", "cut_short": None}
        launch = _launch(migrated_database, inv.investigation_id)
        # The alert the run held is the exact bytes queued: the launch record's digest is of them (the helper's copy of the
        # alert is not in the bundle, and trusted code reads no copy back, PR4).
        assert hashlib.sha256(golden_bytes).hexdigest() == launch["digest"]
        assert not (root / t.tenant_id / "runs" / inv.investigation_id).exists(), "A-O1: the run was left in the host's tenant folder"
        assert is_box_token(launch["box_token"]), launch
        assert (tmp_path / "marks" / "start-token").read_text(encoding="utf-8") == launch["box_token"], \
            "the child's box start was not handed the launch record's token (r5 C1)"


async def test_o8_a_raise_after_the_real_drivers_close_still_records_the_report_committed(
        migrated_database, tmp_path, monkeypatch, short_root, openbao, garage, evidence_keys):  # noqa: F811
    """The replay model commits the golden's report and the next model request raises (`KeyboardInterrupt`) inside the real driver: the staged outcome still says `report_committed: true`, because the driver's own review state (the holder's dict) closed. (O8, M2, r5 C2)"""
    from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B

    root = short_root
    monkeypatch.setenv("DEFENDER_DATA_ROOT", str(root))
    monkeypatch.setenv("DEFENDER_DATABASE_DSN", migrated_database)  # the child reads tenant records here (r6 R6-2)
    monkeypatch.delenv("DEFENDER_ALLOW_UNSANDBOXED", raising=False)
    golden = DEFENDER / "tests" / "fixtures" / "e2e" / "golden-v2sshd"
    with B.run_tenant(tmp_path, root, tenant_id=fresh_tenant()) as t:
        register_tenant(migrated_database, t.tenant_id, data_root=root, records=no_proxy_records())
        (root / t.tenant_id / "runs").mkdir(exist_ok=True)
        lane = _lane(monkeypatch, migrated_database, t.tenant_id, openbao, garage, evidence_keys)

        def child(launch) -> list[str]:
            return lane.child(launch, "replay-fault-after-close", t.commit, tmp_path / "marks", remote=t.remote)

        async with job_store(migrated_database) as store:
            alert = await an_alert(store, t.tenant_id, raw=(golden / "alert.json").read_bytes())
            inv, _ = await store.create_investigation(t.tenant_id, alert.alert_id, "k1", actor="u-1")
            await make_worker(store, root, child, containers=StandInContainers(tmp_path / "containers")).drain()
            row = await store.get_investigation(t.tenant_id, inv.investigation_id)

        end = _staged(migrated_database, inv.investigation_id)["outcome"]
        assert (tmp_path / "marks" / "fault-raised").is_file(), "premise: the driver made a request after the close and it raised"
        run = lane.run(inv.investigation_id, tmp_path / "stored")
        assert committed_record(run) is not None, "premise: the closing record was committed before the fault"
        assert (end["setup"], end["box"]) == ("done", "started"), end
        assert end["report_committed"] is True, end
        assert row.stage == "completed", "both facts held, so rule 4 reads the committed report (r5 C2, D-h superseded)"


async def test_1345_o4_a_queued_job_whose_tenant_has_no_mapping_ends_failed_setup_refused_with_the_reason_on_stderr(
        migrated_database, tmp_path, monkeypatch, short_root, openbao, garage, evidence_keys):  # noqa: F811
    """The real worker and child over a tenant whose mapping row is gone (a job queued before the upgrade): the row ends
    `failed`/`setup_refused`/"run setup refused the job", no run folder, and the child's stderr carries
    `ALERT_MAPPING_MISSING`. The mapped replay above is the control. (#1345 O4, M2)"""
    from defender.records.formats import ALERT_MAPPING_MISSING
    from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B

    root = short_root
    monkeypatch.setenv("DEFENDER_DATA_ROOT", str(root))
    monkeypatch.setenv("DEFENDER_DATABASE_DSN", migrated_database)
    monkeypatch.delenv("DEFENDER_ALLOW_UNSANDBOXED", raising=False)
    err_file = tmp_path / "child.stderr"
    golden = DEFENDER / "tests" / "fixtures" / "e2e" / "golden-v2sshd"
    with B.run_tenant(tmp_path, root, tenant_id=fresh_tenant()) as t:
        register_tenant(migrated_database, t.tenant_id, data_root=root, records=no_proxy_records())
        (root / t.tenant_id / "runs").mkdir(exist_ok=True)
        lane = _lane(monkeypatch, migrated_database, t.tenant_id, openbao, garage, evidence_keys)

        def child(launch) -> list[str]:
            return lane.child(launch, "replay", t.commit, tmp_path / "marks", remote=t.remote, stderr_to=err_file)

        async with job_store(migrated_database) as store:
            alert = await an_alert(store, t.tenant_id, raw=(golden / "alert.json").read_bytes())
            inv, _ = await store.create_investigation(t.tenant_id, alert.alert_id, "k1", actor="u-1")
            remove_postgres_mapping(migrated_database, t.tenant_id)
            worker = make_worker(store, root, child, containers=StandInContainers(tmp_path / "containers"))
            await worker.drain()

        stored = row(migrated_database, inv.investigation_id)
        assert (stored["stage"], stored["failure_reason"], stored["failure_message"]) == (
            "failed", "setup_refused", "run setup refused the job"), stored
        assert not (root / t.tenant_id / "runs" / inv.investigation_id).exists(), "a run folder was made"
        refused_bundle = lane.bundle(inv.investigation_id)  # a refused setup may keep a bundle (D2); it holds no run
        if refused_bundle is not None:
            with tarfile.open(fileobj=io.BytesIO(refused_bundle), mode="r:gz") as packed:
                assert not [n for n in packed.getnames() if inv.investigation_id in n.split("/")], "the refused job made a run"
        assert " ".join(ALERT_MAPPING_MISSING.split()) in " ".join(err_file.read_text(encoding="utf-8").split())


async def test_1345_o2_a_mapping_replaced_after_launch_leaves_the_alert_and_the_runs_stamped_label_as_launched(
        migrated_database, tmp_path, monkeypatch, short_root, openbao, garage, evidence_keys):  # noqa: F811
    """The real worker and child complete a run labelled with the alert's title at launch (the golden's `rule.description`
    under the default mapping); the tenant then replaces its mapping with one that would title it otherwise, and the
    alert, the run's provenance stamp and its launch record all keep the title it launched with. (#1345 Design "Alerts":
    the label is fixed at launch in the run's stamp; round 1 repair 11; #1420: a save leaves stored alerts as they were)"""
    from defender.records.formats import DISPLAY_CAPS
    from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B

    root = short_root
    monkeypatch.setenv("DEFENDER_DATA_ROOT", str(root))
    monkeypatch.setenv("DEFENDER_DATABASE_DSN", migrated_database)
    monkeypatch.delenv("DEFENDER_ALLOW_UNSANDBOXED", raising=False)
    golden = DEFENDER / "tests" / "fixtures" / "e2e" / "golden-v2sshd"
    document = json.loads((golden / "alert.json").read_bytes())
    # The title as launched: the mapped text, cut (#1345 O2).
    launched_with, later = document["rule"]["description"][:DISPLAY_CAPS["title"]], document["rule"]["id"]
    assert launched_with != later, "premise: the two titles differ"
    with B.run_tenant(tmp_path, root, tenant_id=fresh_tenant()) as t:
        register_tenant(migrated_database, t.tenant_id, data_root=root, records=no_proxy_records())
        (root / t.tenant_id / "runs").mkdir(exist_ok=True)
        lane = _lane(monkeypatch, migrated_database, t.tenant_id, openbao, garage, evidence_keys)

        def child(launch) -> list[str]:
            return lane.child(launch, "replay", t.commit, tmp_path / "marks", remote=t.remote)

        async with job_store(migrated_database) as store:
            alert = await an_alert(store, t.tenant_id, raw=(golden / "alert.json").read_bytes())
            inv, _ = await store.create_investigation(t.tenant_id, alert.alert_id, "k1", actor="u-1")
            await make_worker(store, root, child, containers=StandInContainers(tmp_path / "containers")).drain()
            assert row(migrated_database, inv.investigation_id)["stage"] == "completed", "premise: the run completed"
            seed_postgres(migrated_database, t.tenant_id, {**FIXTURE_ALERT_MAPPING, "title": "rule.id"})
            assert (await store.get_alert(t.tenant_id, alert.alert_id)).title == launched_with, "a save never retitles a stored alert"

        run = lane.run(inv.investigation_id, tmp_path / "stored")
        launch = _launch(migrated_database, inv.investigation_id)
        stamp = json.loads((run / "provenance.json").read_text(encoding="utf-8"))
        assert (launch["label"], stamp["alert_label"]) == (launched_with, launched_with)


# --- #1377: the spend ledger -------------------------------------------------------------------------

#: `replay-priced`'s calls: MAIN dispatch, append, close, text; l-001's query and final summary, and the correlation
#: lead's summary; the review's support, ablation, composer. Each reports the harness's `PRICED_USAGE` under its model.
PRICED_CALLS = {"main": 4, "gather": 3, "review": 3}
PRICED_MODELS = {"main": "claude-sonnet-4-6", "gather": "claude-haiku-4-5", "review": "kimi-k2.6"}


def _priced_spend(**calls: int) -> float:
    """What `calls` (by role) cost when each reports `PRICED_USAGE`: the pricing table over the billed counts."""
    return sum(priced_cost(PRICED_MODELS[role], n) for role, n in calls.items())


def _priced_env(monkeypatch, root: Path, dsn: str) -> None:
    monkeypatch.setenv("DEFENDER_DATA_ROOT", str(root))
    monkeypatch.setenv("DEFENDER_DATABASE_DSN", dsn)
    monkeypatch.delenv("DEFENDER_ALLOW_UNSANDBOXED", raising=False)
    monkeypatch.setenv("DEFENDER_MODEL", "claude-sonnet-4-6")
    monkeypatch.setenv("DEFENDER_GATHER_MODEL", "claude-haiku-4-5")
    monkeypatch.setenv("DEFENDER_REVIEW_MODEL", "kimi-k2.6")


def _calls(marks: Path) -> dict[str, int]:
    return {name: len((marks / f"calls-{name}").read_text(encoding="utf-8").splitlines())
            if (marks / f"calls-{name}").is_file() else 0 for name in PRICED_CALLS}


def _spend_errors(stderr: Path) -> list[str]:
    """The child's log lines at ERROR that name spend (the job entry configures logging as run.py's `__main__` does: JSON lines)."""
    lines = stderr.read_text(encoding="utf-8").splitlines() if stderr.is_file() else []
    return [line for line in lines if '"ERROR"' in line and "spend" in line.lower()]


def _page(run: Path) -> str:
    """The run page through the post-run step's own renderer (the job lane's child stubs the step), handed the run and nothing
    else: the page reads the ledger, as the command-line re-render does (r7.3 T1)."""
    from defender.presentation.visualize_run import render_page
    from defender.tests.support.shared.contracts._spec1077 import fixture_run

    return render_page(fixture_run(run))


def _run_result(run: Path) -> dict:
    lines = (run / "tool_trace.jsonl").read_text(encoding="utf-8").splitlines()
    return [e for e in map(json.loads, lines) if e.get("type") == "result"][-1]


async def test_s1_s5_a_priced_job_costs_every_response_the_run_received(  # noqa: PLR0915 — one flow
        migrated_database, tmp_path, monkeypatch, short_root, openbao, garage, evidence_keys):  # noqa: F811
    """`cost_usd` is every priced response, all four billed counts priced: MAIN, the lead's final one included, and the
    review's; exact, and the run file agrees on the total at full precision and on every usage count. EXTENDED (r7 S5, S6): the
    run page's headline is that cost, and its bar is one segment per agent kind from the ledger. (S1, S2, S5)"""
    from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B

    root = short_root
    _priced_env(monkeypatch, root, migrated_database)
    golden = DEFENDER / "tests" / "fixtures" / "e2e" / "golden-v2sshd"
    # Every system declared, as published: the priced run gathers from elastic, and a system with no access
    # declaration is down by design (`no_proxy_records()` would leave nothing to gather). The helper signs with its seam.
    with B.run_tenant(tmp_path, root, tenant_id=fresh_tenant()) as t:
        register_tenant(migrated_database, t.tenant_id, data_root=root)
        (root / t.tenant_id / "runs").mkdir(exist_ok=True)
        lane = _lane(monkeypatch, migrated_database, t.tenant_id, openbao, garage, evidence_keys)

        def child(launch) -> list[str]:
            return lane.child(launch, "replay-priced", t.commit, tmp_path / "marks", remote=t.remote)

        async with job_store(migrated_database) as store:
            alert = await an_alert(store, t.tenant_id, raw=(golden / "alert.json").read_bytes())
            inv, _ = await store.create_investigation(t.tenant_id, alert.alert_id, "k1", actor="u-1")
            await make_worker(store, root, child, containers=StandInContainers(tmp_path / "containers")).drain()
            served = await store.get_investigation(t.tenant_id, inv.investigation_id)

        run = lane.run(inv.investigation_id, tmp_path / "stored")  # the job's own stored bundle: nothing of the run stays on the host
        stored = row(migrated_database, inv.investigation_id)
        assert _calls(tmp_path / "marks") == PRICED_CALLS, ("premise: the run made exactly the scripted calls", stored)
        assert (served.cost_usd, served.cost_is_lower_limit) == (stored["cost_usd"], False), "the API read of the finished job"
        assert (stored["stage"], stored["disposition"]) == ("completed", "inconclusive"), stored
        spent = _priced_spend(**PRICED_CALLS)
        assert stored["cost_usd"] == pytest.approx(spent, rel=1e-9)
        assert lower_limit(migrated_database, inv.investigation_id) is False
        outcome = _staged(migrated_database, inv.investigation_id)["outcome"]
        assert outcome["cost_usd"] == pytest.approx(spent, rel=1e-9), "the staged outcome's cost is not the row's"
        assert (outcome["report_committed"], outcome["scrub"]) == (True, "clean"), outcome
        result = _run_result(run)
        assert result["total_cost_usd"] == pytest.approx(spent, abs=1e-6), "the run file's total is not the job's cost"
        assert result["total_cost_is_lower_limit"] is False
        assert result["usage"] == priced_billed(10), "usage counts every response's four billed counts, as the total does"
        assert result["num_turns"] == 4, "num_turns stays MAIN's turns (run health reads it)"
        # r7 S5/S6: the run page, rendered through its real entry on this job's run, agrees with the worker and the run file.
        monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path / "state"))  # lint-stale-ref: ok — the retired variable is set on purpose to prove the learning store ignores it
        html = _page(run)
        assert C.headline(html) == f"${stored['cost_usd']:.4f}", "the page's headline is not the worker's final cost, exact"
        segments = C.segments(html)
        by_kind = {"main": priced_cost(PRICED_MODELS["main"], 4), "gather": priced_cost(PRICED_MODELS["gather"], 2),
                   "correlation": priced_cost(PRICED_MODELS["gather"], 1), "review": priced_cost(PRICED_MODELS["review"], 3)}
        assert segments == pytest.approx(by_kind, abs=1e-4), f"the cost bar is not the kinds that spent, each its agents' ledger sum: {segments}"
        assert sum(segments.values()) == pytest.approx(stored["cost_usd"], abs=5e-4), "the bar does not add up to the headline"
        # r7.1 G: the stored figure is as of the run's end; a row written after it moves a re-rendered page, not the stored figure.
        from defender.records import session_store as ss
        from defender.tests.support.jobs._jobs1342 import UNSEEN, insert_spend
        from defender.tests.support.shared.contracts._spec1077 import fixture_run

        insert_spend(ss.resolve_store_path(fixture_run(run)), inv.investigation_id,
                     [(PRICED_MODELS["gather"], {})], agent_id="gather:l-00c", outcome=UNSEEN)
        assert C.at_least(C.headline(_page(run))), "a re-rendered page reads the ledger again"
        async with job_store(migrated_database) as reread_store:
            later = await reread_store.get_investigation(t.tenant_id, inv.investigation_id)
        assert (later.cost_usd, later.cost_is_lower_limit) == (served.cost_usd, False), "a stored figure moved after the run's end"


async def test_s2a_s5_r7_a_request_the_run_never_saw_the_end_of_marks_the_job_the_run_file_and_the_page_alike(
        migrated_database, tmp_path, monkeypatch, short_root, openbao, garage, evidence_keys):  # noqa: F811
    """The correlation lead's request raises an error that is no response: every other response is priced, and the job's cost,
    the run file's total and the page's headline are that sum, each "at least", with no correlation segment. (r7 S2a, S5, S6)"""
    from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B

    root = short_root
    _priced_env(monkeypatch, root, migrated_database)
    golden = DEFENDER / "tests" / "fixtures" / "e2e" / "golden-v2sshd"
    # Every system declared, as published: the priced run gathers from elastic, and a system with no access
    # declaration is down by design (`no_proxy_records()` would leave nothing to gather). The helper signs with its seam.
    with B.run_tenant(tmp_path, root, tenant_id=fresh_tenant()) as t:
        register_tenant(migrated_database, t.tenant_id, data_root=root)
        (root / t.tenant_id / "runs").mkdir(exist_ok=True)
        lane = _lane(monkeypatch, migrated_database, t.tenant_id, openbao, garage, evidence_keys)

        def child(launch) -> list[str]:
            return lane.child(launch, "replay-priced-unseen", t.commit, tmp_path / "marks", remote=t.remote)

        async with job_store(migrated_database) as store:
            alert = await an_alert(store, t.tenant_id, raw=(golden / "alert.json").read_bytes())
            inv, _ = await store.create_investigation(t.tenant_id, alert.alert_id, "k1", actor="u-1")
            await make_worker(store, root, child, containers=StandInContainers(tmp_path / "containers")).drain()

        run = lane.run(inv.investigation_id, tmp_path / "stored")  # the job's own stored bundle: nothing of the run stays on the host
        stored = row(migrated_database, inv.investigation_id)
        assert stored["stage"] == "completed", stored
        want = {"main": priced_cost(PRICED_MODELS["main"], 4), "gather": priced_cost(PRICED_MODELS["gather"], 2),
                "review": priced_cost(PRICED_MODELS["review"], 3)}
        assert stored["cost_usd"] == pytest.approx(sum(want.values()), rel=1e-9)
        assert lower_limit(migrated_database, inv.investigation_id) is True
        result = _run_result(run)
        assert (result["total_cost_usd"], result["total_cost_is_lower_limit"]) == (pytest.approx(stored["cost_usd"], abs=1e-6), True)
        monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path / "state"))  # lint-stale-ref: ok — the retired variable is set on purpose to prove the learning store ignores it
        html = _page(run)
        headline = C.headline(html)
        assert (C.at_least(headline), C.dollars(headline)) == (True, pytest.approx(stored["cost_usd"], abs=1e-4))
        assert C.segments(html) == pytest.approx(want, abs=1e-4), "a kind that did not spend has a segment, or one is missing"


async def test_s3_a_ledger_write_that_fails_in_review_leaves_the_verdict_and_report_and_marks_the_sum(
        migrated_database, tmp_path, monkeypatch, short_root, openbao, garage, evidence_keys):  # noqa: F811
    """Ledger inserts refused during the review (a real SQLite fault): same ending and closing record as the control; the sum lacks the review, is marked, and the child logs ERROR. (S3, S2, S5)"""
    from defender.records import closing
    from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B

    root = short_root
    _priced_env(monkeypatch, root, migrated_database)
    err_file = tmp_path / "child.stderr"
    golden = DEFENDER / "tests" / "fixtures" / "e2e" / "golden-v2sshd"
    modes: dict[str, str] = {}
    # Every system declared, as published: the priced run gathers from elastic, and a system with no access
    # declaration is down by design (`no_proxy_records()` would leave nothing to gather). The helper signs with its seam.
    with B.run_tenant(tmp_path, root, tenant_id=fresh_tenant()) as t:
        register_tenant(migrated_database, t.tenant_id, data_root=root)
        (root / t.tenant_id / "runs").mkdir(exist_ok=True)
        lane = _lane(monkeypatch, migrated_database, t.tenant_id, openbao, garage, evidence_keys)

        def child(launch) -> list[str]:
            mode = modes[launch.investigation_id]
            return lane.child(launch, mode, t.commit, tmp_path / mode, remote=t.remote,
                                stderr_to=err_file if mode.endswith("fault") else tmp_path / "control.stderr")

        async with job_store(migrated_database) as store:
            ids = []
            for ticket, mode in (("T-control", "replay-priced"), ("T-fault", "replay-priced-ledger-fault")):
                alert = await an_alert(store, t.tenant_id, raw=(golden / "alert.json").read_bytes(), ticket=ticket)
                inv, _ = await store.create_investigation(t.tenant_id, alert.alert_id, "k1", actor="u-1")
                modes[inv.investigation_id] = mode
                ids.append(inv.investigation_id)
            await make_worker(store, root, child, containers=StandInContainers(tmp_path / "containers")).drain()

        control, faulted = ids
        runs = {i: lane.run(i, tmp_path / f"stored-{n}") for n, i in enumerate(ids)}  # the jobs' own stored bundles
        assert _calls(tmp_path / "replay-priced-ledger-fault") == PRICED_CALLS, "premise: the faulted run made every call"
        got = {i: row(migrated_database, i) for i in ids}
        assert (got[control]["stage"], got[control]["disposition"]) == ("completed", "inconclusive"), "premise: the control"
        assert (got[faulted]["stage"], got[faulted]["disposition"], got[faulted]["failure_reason"]) == (
            "completed", "inconclusive", None), "a forced verdict reads `unresolved`"
        records = {i: committed_record(runs[i]) for i in ids}
        assert all(r is not None for r in records.values()), "premise: both runs left a closing record"
        by_run = {i: {k: v for k, v in dataclasses.asdict(r).items() if k != "run_id"} for i, r in records.items()}
        assert by_run[faulted] == by_run[control]
        assert records[faulted].outcome == closing.STANDS, "premise: the review's own outcome reached the record (a forced verdict reads `unresolved`)"
        lacking_review = _priced_spend(main=4, gather=3)  # the review's three responses are lost
        assert got[faulted]["cost_usd"] == pytest.approx(lacking_review, rel=1e-9)
        assert lower_limit(migrated_database, faulted) is True
        assert lower_limit(migrated_database, control) is False
        end = _staged(migrated_database, faulted)["outcome"]
        assert end["report_committed"] is True, end
        result = _run_result(runs[faulted])
        assert (result["total_cost_usd"], result["total_cost_is_lower_limit"]) == (pytest.approx(lacking_review, abs=1e-6), True)
        assert (result["usage"], result["num_turns"]) == (priced_billed(7), 4)
        assert _spend_errors(err_file), "the failed write was not logged at ERROR"
        monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path / "state"))  # lint-stale-ref: ok — the retired variable is set on purpose to prove the learning store ignores it
        page = C.headline(_page(runs[faulted]))
        assert (C.at_least(page), C.dollars(page)) == (True, pytest.approx(lacking_review, abs=1e-4)), (
            "the job reads at least, so the page, rendered from the run alone, must too (r7.3 T1; review finding 1)")
        assert _spend_errors(tmp_path / "control.stderr") == [], "the unfaulted control logged a failed spend write"

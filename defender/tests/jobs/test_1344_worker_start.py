"""#1344 O15 worker start, the image entry and the image's static facts, over real processes.

`python -m defender.worker` runs as a subprocess from a scratch code tree (the checkout's `defender/` without
its tests, a `.venv` planted), with no PYTHONPATH and no monkeypatching. Refusals need no database; serving does.
Not provable here, owed to a real container run: that the image builds, that git and the docker CLI work in it,
that a box mounts the copy through a Docker daemon, and that `-m defender.worker` is the image's command."""
from __future__ import annotations

import asyncio
import datetime as dt
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

from defender.tests.support.jobs import _worker_start1344 as W
from defender.tests.support.jobs._jobs1342 import T1, an_alert, register_tenant, row
from defender.tests.support.shared._postgres1339 import execute, migrated_database  # noqa: F401 — fixture

REPO = W.DEFENDER.parent
RUNTIME_DOCKERFILE = REPO / ".devcontainer" / "Dockerfile.runtime"
SECOND = "1344" + "b" * 36


@pytest.fixture(scope="module")
def source(tmp_path_factory) -> Path:
    """The code tree a worker is started from, made once."""
    return W.build_source(tmp_path_factory.mktemp("src1344"))


@pytest.fixture
def data_root(tmp_path) -> Path:
    root = tmp_path / "data"
    root.mkdir()
    return root


def _under(path: str, tree: Path) -> bool:
    return os.path.realpath(path).startswith(os.path.realpath(tree) + os.sep)


# --- refusals: no database, nothing touched ---------------------------------------------------------------------


def _not_commits() -> list[str]:
    """Build stamps that are not a commit (a commit is 7 to 64 lowercase hex characters, the marker reader's grammar):
    tags, branch names, uppercase or mixed-case hex, hex one short of 7 or one past 64, a `-dirty` suffix, a `0x`
    prefix, a non-hex letter, and a commit with whitespace around or inside it."""
    good = W.STAMP
    return ["v1.2.3", "release-2026.11", "main", "feature/1344-stamp", "HEAD",
            good.upper(), "A" + good[1:], good[:6], good + "a" * (65 - len(good)),
            good + "-dirty", good[:7] + "-dirty", "0x" + good[:38], "g" * 40,
            " " + good, good + "\n", "\t" + good + " ", good[:20] + " " + good[20:]]


@pytest.mark.parametrize("stamp", [None, "", " ", "\t\n  ", *_not_commits()])
def test_o15_an_empty_or_unset_build_stamp_refuses_before_serving_and_before_the_copy(source, data_root, stamp):
    """Unset, empty, or anything that is not a commit: nonzero exit naming the stamp's variable; no database reached,
    no lock taken and nothing made on the data mount. (O15, Code boxes, #1344 attack round F4)"""
    from defender.records._provenance import BUILD_COMMIT_ENV

    ran = W.run_to_exit(source, W.worker_env(data_root, stamp=stamp))

    assert "No module named" not in ran.stderr, f"the worker cannot be started: {ran.stderr[-300:]}"
    assert ran.returncode != 0
    assert BUILD_COMMIT_ENV in ran.stderr, ran.stderr[-800:]
    assert not re.search(r"(?i)connect|OperationalError|refused by the database", ran.stderr), ran.stderr[-800:]
    assert list(data_root.iterdir()) == [], "the refusal touched the data root"


@pytest.mark.postgres
@pytest.mark.parametrize("stamp", [W.STAMP[:7], (W.STAMP * 2)[:64]], ids=["7", "64"])
def test_o15_a_build_stamp_of_7_or_64_lowercase_hex_characters_starts(source, data_root, db, stamp):
    """The bounds of a commit start: the worker serves, its copy's marker holds the stamp as given. (O15, F4)"""
    serve, _probe = _serve(source, data_root, db, stamp=stamp)
    with serve as proc:
        (copy,) = W.code_copies(data_root)
        assert json.loads((copy / W.MARKER).read_text(encoding="utf-8")) == {"commit": stamp}
        assert W.stop(proc) == 0, W.stderr_of(proc)


@pytest.mark.parametrize(("slots", "learning", "named"), [
    ("0", None, "SLOTS"), ("-1", None, "SLOTS"), ("abc", None, "SLOTS"), ("2.5", None, "SLOTS"), (" ", None, "SLOTS"),
    ("3", "3", "LEARNING"), ("3", "4", "LEARNING"), ("3", "-1", "LEARNING"), ("3", "x", "LEARNING"),
    ("3", "1.5", "LEARNING"), ("1", "1", "LEARNING"), ("2", "2", "LEARNING"),
])
def test_o15_invalid_slot_settings_refuse_before_serving_and_before_the_copy(source, data_root, slots, learning, named):
    """Slots below 1, or learning slots outside 0..slots-1 (a learning slot per slot included), non-integers too: nonzero exit naming the setting. (O15, D3)"""
    ran = W.run_to_exit(source, W.worker_env(data_root, slots=slots, learning=learning))

    assert "No module named" not in ran.stderr, f"the worker cannot be started: {ran.stderr[-300:]}"
    assert ran.returncode != 0
    assert f"DEFENDER_WORKER_{'LEARNING_SLOTS' if named == 'LEARNING' else 'SLOTS'}" in ran.stderr, ran.stderr[-800:]
    assert not re.search(r"(?i)connect|OperationalError", ran.stderr), ran.stderr[-800:]
    assert list(data_root.iterdir()) == [], "the refusal touched the data root"


# --- serving: a database ----------------------------------------------------------------------------------------


def _live_store(dsn: str):
    from defender.jobs import JobStore

    return JobStore(dsn, clock=lambda: dt.datetime.now(dt.UTC))


def _queue_investigation(dsn: str, ticket: str, *, complete: bool = False, tenant: str = T1) -> str:
    """One investigation through the store; `complete`: claimed and finished `completed` by the store, its auto job queued."""
    async def go() -> str:
        store = _live_store(dsn)
        try:
            alert = await an_alert(store, tenant, ticket=ticket)
            inv, _ = await store.create_investigation(tenant, alert.alert_id, f"k-{ticket}", actor="u-1")
            if complete:
                claim = await store.claim()
                assert claim.record.investigation_id == inv.investigation_id, "premise: nothing else was queued"
                await store.finish(tenant, inv.investigation_id, stage="completed", disposition="malicious", cost_usd=0.0)
            return inv.investigation_id
        finally:
            await store.close()

    return asyncio.run(go())


def _job_status(dsn: str, investigation: str) -> str:
    found = execute(dsn, "SELECT status FROM jobs.learning_jobs WHERE investigation_id = %s", (investigation,))
    return found[0][0]


def _probe_ended(dsn: str, investigation: str) -> bool:
    """A tenant with no folder on this host: a serving worker claims the row and ends it `failed`, touching nothing else."""
    return (row(dsn, investigation) or {}).get("stage") == "failed"


@pytest.fixture
def db(migrated_database):  # noqa: F811
    register_tenant(migrated_database, T1)
    return migrated_database


def _serve(source, data_root, dsn, *, ticket="P-1", **settings):
    """A worker over `dsn`, ready once it has claimed a probe row (so it is serving, not starting)."""
    probe = _queue_investigation(dsn, ticket)
    return W.serving(source, W.worker_env(data_root, dsn=dsn, **settings),
                     ready=lambda: _probe_ended(dsn, probe)), probe


@pytest.mark.postgres
def test_o15_a_worker_with_default_settings_serves_from_a_fresh_read_only_copy_and_stops_on_sigterm(source, data_root, db):
    """The copy (the repository root's shape) holds the build commit in its marker, no `.venv`, no write bits; SIGTERM ends the worker with exit 0. (O15, Code boxes)"""
    serve, _probe = _serve(source, data_root, db)
    with serve as proc:
        (copy,) = W.code_copies(data_root)
        assert json.loads((copy / W.MARKER).read_text(encoding="utf-8")) == {"commit": W.STAMP}
        assert (copy / "defender" / "run.py").read_bytes() == (source / "defender" / "run.py").read_bytes(), \
            "`defender/run.py` is not beside the marker: the copy is not the repository root's shape"
        assert not list(copy.rglob(".venv"))
        assert (source / "defender" / W.VENV_SENTINEL).exists(), "premise: the source tree held a .venv"
        # Mode bits, not a write attempt: this machine runs as root.
        assert all(not p.lstat().st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)
                   for p in copy.rglob("*") if not p.is_symlink())
        assert W.stop(proc) == 0, W.stderr_of(proc)


@pytest.mark.postgres
def test_o15_each_start_replaces_the_copy_and_removes_the_files_of_the_previous_one(source, data_root, db):
    """Two starts, one folder: a stale file, a stale folder and an edited `run.py` of the first copy are gone or restored, the marker is the second stamp. (O15)"""
    first, _ = _serve(source, data_root, db, ticket="P-1")
    with first as proc:
        (copy,) = W.code_copies(data_root)
        assert W.stop(proc) == 0
    before = W.files_under(copy)
    for path in (copy, *copy.rglob("*")):
        path.chmod(0o755 if path.is_dir() else 0o644)
    (copy / "STALE.txt").write_text("left by the first start\n", encoding="utf-8")
    (copy / "stale_dir").mkdir()
    (copy / "stale_dir" / "old.py").write_text("OLD = 1\n", encoding="utf-8")
    entry = copy / "defender" / "run.py"
    entry.write_text("TAMPERED = 1\n", encoding="utf-8")

    second, _ = _serve(source, data_root, db, ticket="P-2", stamp=SECOND)
    with second as proc:
        assert W.code_copies(data_root) == [copy], "one folder, replaced: not one per start"
        assert not (copy / "STALE.txt").exists()
        assert not (copy / "stale_dir").exists()
        assert json.loads((copy / W.MARKER).read_text(encoding="utf-8")) == {"commit": SECOND}
        assert entry.read_bytes() == (source / "defender" / "run.py").read_bytes(), "an edited file of the first copy was kept"
        after = W.files_under(copy)
        assert set(after) == set(before), "the file set drifted between two starts of one build"
        assert {k for k in after if after[k][0] != before[k][0]} == {W.MARKER}, "only the marker differs between two starts"
        W.stop(proc)


@pytest.mark.postgres
def test_o15_a_second_worker_on_the_same_data_root_refuses_while_the_first_runs_and_a_third_starts_after_a_kill(
        source, data_root, db):
    """Real second process: nonzero exit, the first still serving and its copy untouched; after SIGKILL of the first (no stop path runs) a third serves. (O15, kernel lock)"""
    first, _ = _serve(source, data_root, db, ticket="P-1")
    with first as proc:
        (copy,) = W.code_copies(data_root)
        held = W.files_under(copy)
        assert json.loads((copy / W.MARKER).read_text(encoding="utf-8")) == {"commit": W.STAMP}

        second = W.run_to_exit(source, W.worker_env(data_root, dsn=db, stamp=SECOND))

        assert second.returncode != 0
        assert re.search(r"(?i)lock|already|another|running|held", second.stderr), second.stderr[-800:]
        assert proc.poll() is None, "the second start ended the first worker"
        assert W.files_under(copy) == held, "the refused second worker replaced the first one's live copy"
        assert json.loads((copy / W.MARKER).read_text(encoding="utf-8")) == {"commit": W.STAMP}, "the second stamp reached the first's copy"
        proc.kill()
        proc.wait(timeout=30)

    third, probe = _serve(source, data_root, db, ticket="P-3", stamp=SECOND)
    with third as proc:
        assert _probe_ended(db, probe)
        assert W.stop(proc) == 0, W.stderr_of(proc)


@pytest.mark.postgres
@pytest.mark.parametrize(("slots", "learning", "learns"), [
    ("1", None, False), ("3", "0", False), ("2", None, True), (None, None, True), ("3", "1", True)])
def test_o15_learning_slots_default_to_one_below_the_slots_and_zero_for_one_slot(source, data_root, db, slots, learning, learns):
    """A queued job is claimed when a learning slot exists: S=1 gives none (and starts), S>=2 gives one, `0` switches it off. (O15, O5)"""
    queued = _queue_investigation(db, "J-1", complete=True)
    assert _job_status(db, queued) == "queued", "premise: completing the investigation queued its job"
    serve, probe = _serve(source, data_root, db, ticket="P-1", slots=slots, learning=learning)
    with serve as proc:
        assert _probe_ended(db, probe), "control: the worker serves and claims investigations"
        if learns:
            W.wait_until(lambda: _job_status(db, queued) != "queued", timeout=90, what="the job to be claimed", proc=proc)
        else:
            time.sleep(8)  # several poll intervals
            assert _job_status(db, queued) == "queued", "a job was claimed with no learning slot"
        assert proc.poll() is None


#: What a child stamps for its own tree: `run_common.REPO_ROOT` is the parent of `defender`, read in the child's environment.
STAMP_PROBE = """
import json
from defender import run_common
from defender.records._provenance import capture_tree
stamp = capture_tree(run_common.REPO_ROOT)
print(json.dumps({"root": str(run_common.REPO_ROOT), "origin": stamp.origin, "commit": stamp.commit, "dirty": stamp.dirty}))
"""


def _start_form(child: dict) -> tuple[str, list[str]] | None:
    """How a Python entry child was started: (`-m:<module>` or the script's path, its arguments). None for any
    other child (git, docker, a shell, `python -c`): the worker may run those, and they are not entries."""
    argv = child["argv"]
    if not argv or not os.path.basename(argv[0]).startswith("python"):
        return None
    if "-m" in argv[1:3]:
        at = argv.index("-m")
        return f"-m:{argv[at + 1]}", argv[at + 2:]
    script = next((a for a in argv[1:] if a.endswith(".py")), None)
    return None if script is None else (script, argv[argv.index(script) + 1:])


def _runs_from(child: dict, copy: Path, source: Path) -> bool:
    """Judged by what the process is: a `-m` start by its working directory (modules are found from it), a script start by the script's path; never by a working directory the worker did not set."""
    argv = child["argv"]
    if "-m" in argv[1:3]:
        here = [child["cwd"]]
    else:
        form = _start_form(child)
        assert form is not None, child["argv"]
        script, _ = form
        here = [script if os.path.isabs(script) else os.path.join(child["cwd"], script)]
    return (all(_under(p, copy) or os.path.realpath(p) == os.path.realpath(copy) for p in here)
            and not any(_under(p, source) or os.path.realpath(p) == os.path.realpath(source) for p in here)
            and str(source) not in child["env"].get("PYTHONPATH", ""))


def _values_of(argv: list[str], flag: str) -> list[str]:
    """What follows `flag` up to the next flag."""
    if flag not in argv:
        return []
    rest = argv[argv.index(flag) + 1:]
    return rest[:next((i for i, a in enumerate(rest) if a.startswith("--")), len(rest))]


def _child_of(children: list[dict], kind: str, job: str) -> dict | None:
    """The child that runs the job entry (`cli.learning.job`) or the post-step (`post_step`) for `job`."""
    return next((c for c in children if job in _values_of(c["argv"], "--job")
                 and (form := _start_form(c)) is not None and kind in form[0]), None)


@pytest.mark.postgres
def test_o15_children_run_from_the_copy_and_load_modules_from_nowhere_else(source, data_root, db, tmp_path):
    """The worker's investigation child and learning child (found by their job ids) start from the copy, and re-running each entry in the child's environment loads only copy modules. (O15, Code boxes)"""
    from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B

    with B.run_tenant(tmp_path, data_root) as t:
        register_tenant(db, t.tenant_id, data_root=data_root)
        (data_root / t.tenant_id / "runs").mkdir(exist_ok=True)
        job = _job_of(db, _queue_investigation(db, "J-1", complete=True, tenant=t.tenant_id))
        investigation = _queue_investigation(db, "P-1", tenant=t.tenant_id)
        watch = W.ChildWatch()
        with W.serving(source, W.worker_env(data_root, dsn=db, slots="2"), ready=lambda: bool(W.code_copies(data_root)),
                       watch=watch) as proc:
            (copy,) = W.code_copies(data_root)
            children = watch.wait_for(
                lambda seen: all(any(wanted in " ".join(c["argv"]) for c in seen) for wanted in (investigation, job)),
                timeout=120, what="an investigation child and a learning child")
            W.wait_until(lambda: _job_status_by_id(db, job) not in ("queued", "running")
                         and (row(db, investigation) or {}).get("stage") not in ("queued", "running"),
                         timeout=120, what="both kinds of work to end", proc=proc)
        ours = {name: [c for c in children if wanted in " ".join(c["argv"]) and _start_form(c) is not None] for name, wanted in
                (("investigation", investigation), ("learning", job))}

        assert ours["investigation"], f"no investigation child was observed; saw {[c['argv'] for c in children]}"
        assert ours["learning"], f"no learning child was observed; saw {[c['argv'] for c in children]}"
        for kind, found in ours.items():
            for child in found:
                assert _runs_from(child, copy, source), f"a {kind} child did not run from the copy: {child['argv']}, cwd {child['cwd']}"
        for kind, found in ours.items():
            for child in found:
                assert child["env"].get("PYTHONDONTWRITEBYTECODE"), \
                    f"a {kind} child runs with bytecode writes on (O15: the worker sets it for its children): {child['argv']}"

        entries = {form[0]: c for found in ours.values() for c in found if (form := _start_form(c)) is not None}
        assert len(entries) >= 2, f"one entry for the investigation and one for the learning job: {sorted(entries)}"
        for number, (target, entry) in enumerate(entries.items()):
            ran, modules = W.modules_of(target, ["--help"], env=entry["env"], cwd=Path(entry["cwd"]), out=tmp_path / f"mods{number}.json")
            assert sum(1 for n in modules if n.startswith("defender.")) > 20, f"control: {target} loaded the package: {ran.stderr[-500:]}"
            assert W.module_files_outside(modules, copy / "defender") == {}, target
            assert [f for f in modules.values() if _under(f, source)] == [], target

        env = ours["investigation"][0]["env"]
        stamped = subprocess.run([sys.executable, "-c", STAMP_PROBE], cwd=copy, env=env, capture_output=True, text=True,  # noqa: S603
                                 timeout=120, check=False)
        assert stamped.returncode == 0, stamped.stderr[-800:]
        stamp = json.loads(stamped.stdout)
        assert os.path.realpath(stamp["root"]) == os.path.realpath(copy), "the stamped root is not the copy: the marker and `defender/` are not one level apart"
        assert (stamp["origin"], stamp["commit"], stamp["dirty"]) == ("code_copy", W.STAMP, False), stamp


def _job_of(dsn: str, investigation: str) -> str:
    return execute(dsn, "SELECT id FROM jobs.learning_jobs WHERE investigation_id = %s", (investigation,))[0][0]


def _job_status_by_id(dsn: str, job: str) -> str:
    return execute(dsn, "SELECT status FROM jobs.learning_jobs WHERE id = %s", (job,))[0][0]


@pytest.mark.postgres
def test_o15_the_default_child_commands_run_a_job_whose_source_is_missing_to_source_unavailable_with_a_post_step(
        source, data_root, db, tmp_path):
    """Default settings, no seams: a real `python -m defender.worker` runs the job's real entry (end record `source_unavailable`, not a crash) and then the real post-step (its record). (O15, O8, Worker start)"""
    from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B

    with B.run_tenant(tmp_path, data_root) as t:
        register_tenant(db, t.tenant_id, data_root=data_root)
        runs = data_root / t.tenant_id / "runs"
        runs.mkdir(exist_ok=True)
        investigation = _queue_investigation(db, "J-1", complete=True, tenant=t.tenant_id)
        job = _job_of(db, investigation)
        assert not list(runs.glob("*.session-pointer.json")), "premise: the source investigation has no run folder or session store"
        watch = W.ChildWatch()
        with W.serving(source, W.worker_env(data_root, dsn=db), ready=lambda: bool(W.code_copies(data_root)), watch=watch) as proc:
            children = watch.wait_for(lambda seen: _child_of(seen, "cli.learning.job", job) and _child_of(seen, "post_step", job),
                                      timeout=120, what="the job entry and the post-step children")
            W.wait_until(lambda: (runs / f"{job}.post-step.json").is_file(), timeout=120, what="the post-step's record", proc=proc)

        entry = _child_of(children, "cli.learning.job", job)
        assert entry is not None, f"no job-entry child was observed; saw {[c['argv'] for c in children]}"
        assert _values_of(entry["argv"], "--source") == [investigation], entry["argv"]
        assert _values_of(entry["argv"], "--job") == [job]
        post = _child_of(children, "post_step", job)
        assert post is not None, "no post-step child was observed"
        assert "--pending" not in post["argv"], "the pending jobs are handed in a record, never on the command line"
        handed = json.loads((runs / f"{job}.post-step-pending.json").read_text(encoding="utf-8"))
        assert handed == {"pending": []}, "control: nothing was pending before this job"

        end = json.loads((runs / f"{job}.learning-end.json").read_text(encoding="utf-8"))
        assert (end["status"], end["reason"]) == ("failed", "source_unavailable"), end
        (status, reason, message) = execute(db, "SELECT status, reason, message FROM jobs.learning_jobs WHERE id = %s", (job,))[0]
        assert (status, reason) == ("failed", "source_unavailable"), "the child command crashed or was never wired"
        assert message
        assert json.loads((runs / f"{job}.post-step.json").read_text(encoding="utf-8")) == {"published": [], "refused": []}


@pytest.mark.postgres
def test_o15_the_default_post_step_command_lists_the_tenants_earlier_pending_job(source, data_root, db, tmp_path):
    """An earlier job `completed`/`pending` and a new one: the real post-step child is handed the earlier job's id in its pending record. (O15, O14, Worker start)"""
    from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B

    with B.run_tenant(tmp_path, data_root) as t:
        register_tenant(db, t.tenant_id, data_root=data_root)
        runs = data_root / t.tenant_id / "runs"
        runs.mkdir(exist_ok=True)
        earlier = _job_of(db, _queue_investigation(db, "J-1", complete=True, tenant=t.tenant_id))
        execute(db, "UPDATE jobs.learning_jobs SET status = 'completed', publish_state = 'pending', "
                    "started_at = now(), finished_at = now(), lease_expires_at = NULL WHERE id = %s", (earlier,))
        assert execute(db, "SELECT status, publish_state FROM jobs.learning_jobs WHERE id = %s", (earlier,)) == [("completed", "pending")]
        new = _job_of(db, _queue_investigation(db, "J-2", complete=True, tenant=t.tenant_id))
        watch = W.ChildWatch()
        with W.serving(source, W.worker_env(data_root, dsn=db), ready=lambda: bool(W.code_copies(data_root)), watch=watch) as proc:
            children = watch.wait_for(lambda seen: _child_of(seen, "post_step", new), timeout=120, what="the post-step child")
            W.wait_until(lambda: (runs / f"{new}.post-step.json").is_file(), timeout=120, what="the post-step's record", proc=proc)
        post = _child_of(children, "post_step", new)
        assert post is not None, f"no post-step child was observed; saw {[c['argv'] for c in children]}"
        handed = json.loads((runs / f"{new}.post-step-pending.json").read_text(encoding="utf-8"))
        assert earlier in handed["pending"], handed


# --- image entry: the real entries from a copy, no PYTHONPATH --------------------------------------------------------


@pytest.fixture(scope="module")
def image(tmp_path_factory) -> Path:
    """`<root>/code/defender`: a copy of the code, nothing else on the machine named `defender` is importable from it."""
    root = tmp_path_factory.mktemp("image1344")
    shutil.copytree(W.DEFENDER, root / "code" / "defender",
                    ignore=shutil.ignore_patterns("tests", ".venv", "__pycache__", "*.db", ".git"))
    return root / "code"


def _bare_env() -> dict[str, str]:
    return {k: v for k, v in os.environ.items() if k != "PYTHONPATH" and not k.startswith("DEFENDER_")} | {
        "PYTHONDONTWRITEBYTECODE": "1"}


def _usage_from(target: str | Path, image: Path, tmp_path: Path, *, cwd: Path):
    ran, modules = W.modules_of(target, [], env=_bare_env(), cwd=cwd, out=tmp_path / "mods.json")
    return ran, modules


def _assert_usage_from_the_copy(ran: subprocess.CompletedProcess, modules: dict[str, str], copy: Path) -> None:
    assert "ModuleNotFoundError" not in ran.stderr, ran.stderr[-800:]
    assert "usage" in (ran.stdout + ran.stderr).lower(), (ran.stdout + ran.stderr)[-800:]
    assert sum(1 for n in modules if n.startswith("defender.")) > 20, "control: the entry loaded the package"
    assert W.module_files_outside(modules, copy) == {}
    assert [f for f in modules.values() if _under(f, W.DEFENDER)] == [], "a module came from the checkout"


def test_image_entry_run_py_from_a_copy_with_no_pythonpath_prints_usage_and_loads_only_the_copy(image, tmp_path):
    """`run.py` has no `defender` import above its own path setup. (Image entry, L-C22)"""
    cwd = tmp_path / "elsewhere"
    cwd.mkdir()
    ran, modules = _usage_from(image / "defender" / "run.py", image, tmp_path, cwd=cwd)
    _assert_usage_from_the_copy(ran, modules, image / "defender")


@pytest.mark.parametrize("module", ["defender.cli.learning.job", "defender.learning.branch.post_step"])
def test_image_entry_the_job_entry_and_post_step_from_a_copy_load_only_the_copy(image, tmp_path, module):
    """Started as modules from the copy's parent, nothing on PYTHONPATH. (Image entry, O8)"""
    ran, modules = _usage_from(f"-m:{module}", image, tmp_path, cwd=image)
    _assert_usage_from_the_copy(ran, modules, image / "defender")


# --- the image's static facts ------------------------------------------------------------------------------------------


def _instructions(text: str) -> list[str]:
    """Dockerfile instructions: continuations joined, comment and blank lines dropped."""
    joined = re.sub(r"\\[ \t]*\n", " ", text)
    return [line.strip() for line in joined.splitlines() if line.strip() and not line.strip().startswith("#")]


def _apt_packages(instructions: list[str]) -> set[str]:
    found: set[str] = set()
    for ins in instructions:
        if not ins.upper().startswith("RUN "):
            continue
        for part in re.split(r"&&|;", ins[4:]):
            words = part.split()
            if words[:2] in (["apt-get", "install"], ["apt", "install"]) or words[:2] == ["apk", "add"]:
                found |= {w for w in words[2:] if not w.startswith("-")}
    return found


DOCKER_CLI_PACKAGES = {"docker-ce-cli", "docker.io", "docker-cli", "docker"}


def test_the_parser_reads_instructions_not_comments():
    """Control for the two checks below on a literal sample: a package named only in a comment is not installed."""
    sample = "# git is not here\nRUN apt-get update && apt-get install -y --no-install-recommends \\\n   curl git \\\n && rm -rf /x\n"
    assert _apt_packages(_instructions(sample)) == {"curl", "git"}
    assert _apt_packages(_instructions("# RUN apt-get install -y git\nFROM x\n")) == set()


def test_the_runtime_image_reads_as_the_real_file_does():
    """Control: the parse finds what the file really installs, so a miss below is not an empty parse. (One image)"""
    instructions = _instructions(RUNTIME_DOCKERFILE.read_text(encoding="utf-8"))
    assert instructions[0] == "FROM python:3.11-slim"
    assert {"curl", "ca-certificates"} <= _apt_packages(instructions)
    assert any("uv sync --frozen" in i for i in instructions)


def test_the_runtime_image_installs_git():
    """The worker image carries git (tenant clones); installed, not merely mentioned in a comment. (One image, L-C2)"""
    packages = _apt_packages(_instructions(RUNTIME_DOCKERFILE.read_text(encoding="utf-8")))
    assert "git" in packages, sorted(packages)


def test_the_runtime_image_carries_the_docker_cli():
    """Investigations start boxes through the CLI: a package, or a copy of the binary from another stage. (One image, L-C2)"""
    instructions = _instructions(RUNTIME_DOCKERFILE.read_text(encoding="utf-8"))
    copied = [i for i in instructions if i.upper().startswith("COPY ") and "--from=" in i and re.search(r"docker\S*\s*$", i)]
    assert _apt_packages(instructions) & DOCKER_CLI_PACKAGES or copied, "no docker CLI in the image"


def test_the_runtime_image_still_bakes_the_build_stamp():
    """The stamp the worker refuses to start without stays an image build argument. (One image, Code boxes)"""
    instructions = _instructions(RUNTIME_DOCKERFILE.read_text(encoding="utf-8"))
    assert "ARG DEFENDER_BUILD_COMMIT=\"\"" in instructions
    assert any(i.startswith("ENV DEFENDER_BUILD_COMMIT=") for i in instructions)

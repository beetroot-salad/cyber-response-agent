"""#1344 O15 worker start, the image entry and the image's static facts, over real processes.

`python -m defender.worker` runs as a subprocess from a scratch code tree (the checkout's `defender/` without
its tests, a `.venv` planted), with no PYTHONPATH and no monkeypatching. Refusals need no database; serving does.
Not provable here, owed to a real container run: that the image builds, that git and the docker CLI work in it,
that a box mounts the copy through a Docker daemon, and that `-m defender.worker` is the image's command."""
from __future__ import annotations

import asyncio
import datetime as dt
import os
import re
import shutil
import stat
import subprocess
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


@pytest.mark.parametrize("stamp", [None, "", " ", "\t\n  "])
def test_o15_an_empty_or_unset_build_stamp_refuses_before_serving_and_before_the_copy(source, data_root, stamp):
    """Nonzero exit naming the stamp's variable; no database reached, nothing made on the data mount. (O15, Code boxes)"""
    from defender.records._provenance import BUILD_COMMIT_ENV

    ran = W.run_to_exit(source, W.worker_env(data_root, stamp=stamp))

    assert "No module named" not in ran.stderr, f"the worker cannot be started: {ran.stderr[-300:]}"
    assert ran.returncode != 0
    assert BUILD_COMMIT_ENV in ran.stderr, ran.stderr[-800:]
    assert not re.search(r"(?i)connect|OperationalError|refused by the database", ran.stderr), ran.stderr[-800:]
    assert list(data_root.iterdir()) == [], "the refusal touched the data root"


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


def _queue_investigation(dsn: str, ticket: str, *, complete: bool = False) -> str:
    """One investigation through the store; `complete`: claimed and finished `completed` by the store, its auto job queued."""
    async def go() -> str:
        store = _live_store(dsn)
        try:
            alert = await an_alert(store, T1, ticket=ticket)
            inv, _ = await store.create_investigation(T1, alert.alert_id, f"k-{ticket}", actor="u-1")
            if complete:
                claim = await store.claim()
                assert claim.record.investigation_id == inv.investigation_id, "premise: nothing else was queued"
                await store.finish(T1, inv.investigation_id, stage="completed", disposition="malicious", cost_usd=0.0)
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
    """The copy holds the build commit in its marker, no `.venv`, no write bits; SIGTERM ends the worker with exit 0. (O15, Code boxes)"""
    import json

    serve, _probe = _serve(source, data_root, db)
    with serve as proc:
        (copy,) = W.code_copies(data_root)
        assert json.loads((copy / W.MARKER).read_text(encoding="utf-8")) == {"commit": W.STAMP}
        assert (copy / "run.py").read_bytes() == (source / "defender" / "run.py").read_bytes()
        assert not (copy / ".venv").exists()
        assert (source / "defender" / W.VENV_SENTINEL).exists(), "premise: the source tree held a .venv"
        # Mode bits, not a write attempt: this machine runs as root.
        assert all(not p.lstat().st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)
                   for p in copy.rglob("*") if not p.is_symlink())
        assert W.stop(proc) == 0, W.stderr_of(proc)


@pytest.mark.postgres
def test_o15_each_start_replaces_the_copy_and_removes_the_files_of_the_previous_one(source, data_root, db):
    """Two starts, one folder: a file left in the first copy is gone, `run.py` is a new file, the marker is the second stamp. (O15)"""
    import json

    first, _ = _serve(source, data_root, db, ticket="P-1")
    with first as proc:
        (copy,) = W.code_copies(data_root)
        assert W.stop(proc) == 0
    before = W.files_under(copy)
    for path in (copy, *copy.rglob("*")):
        if path.is_dir():
            path.chmod(0o755)
    (copy / "STALE.txt").write_text("left by the first start\n", encoding="utf-8")
    (copy / "stale_dir").mkdir()
    (copy / "stale_dir" / "old.py").write_text("OLD = 1\n", encoding="utf-8")

    second, _ = _serve(source, data_root, db, ticket="P-2", stamp=SECOND)
    with second as proc:
        assert W.code_copies(data_root) == [copy], "one folder, replaced: not one per start"
        assert not (copy / "STALE.txt").exists()
        assert not (copy / "stale_dir").exists()
        assert json.loads((copy / W.MARKER).read_text(encoding="utf-8")) == {"commit": SECOND}
        after = W.files_under(copy)
        assert set(after) == set(before), "the file set drifted between two starts of one build"
        assert after["run.py"][0] != before["run.py"][0], "the first start's files were reused, not replaced"
        W.stop(proc)


@pytest.mark.postgres
def test_o15_a_second_worker_on_the_same_data_root_refuses_while_the_first_runs_and_a_third_starts_after_a_kill(
        source, data_root, db):
    """Real second process: nonzero exit, the first still serving and its copy untouched; after SIGKILL of the first (no stop path runs) a third serves. (O15, kernel lock)"""
    first, _ = _serve(source, data_root, db, ticket="P-1")
    with first as proc:
        (copy,) = W.code_copies(data_root)
        held = W.files_under(copy)

        second = W.run_to_exit(source, W.worker_env(data_root, dsn=db, stamp=SECOND))

        assert second.returncode != 0
        assert re.search(r"(?i)lock|already|another|running|held", second.stderr), second.stderr[-800:]
        assert proc.poll() is None, "the second start ended the first worker"
        assert W.files_under(copy) == held, "the refused second worker replaced the first one's live copy"
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


@pytest.mark.postgres
def test_o15_children_run_from_the_copy_and_load_modules_from_nowhere_else(source, data_root, db, tmp_path):
    """A real investigation child and a real learning child: argv and environment name the copy, not the source; re-running the child's entry in its environment loads only the copy. (O15)"""
    (data_root / T1 / "runs").mkdir(parents=True)
    (data_root / T1 / "sessions").mkdir()
    queued = _queue_investigation(db, "J-1", complete=True)
    probe = _queue_investigation(db, "P-1")
    with W.serving(source, W.worker_env(data_root, dsn=db, slots="2"),
                   ready=lambda: bool(W.code_copies(data_root))) as proc:
        (copy,) = W.code_copies(data_root)
        children = W.watch_children(proc, lambda c: len([a for a in c["argv"] if "run.py" in a]) >= 1, timeout=90)
        W.wait_until(lambda: _job_status(db, queued) != "queued" and (row(db, probe) or {}).get("stage") != "queued",
                     timeout=90, what="both kinds of work to be claimed", proc=proc)
        children += W.watch_children(proc, lambda c: False, timeout=1)

    assert children, "no child of the worker was ever observed"
    src_text = str(source)
    for child in children:
        text = " ".join(child["argv"])
        assert src_text not in text, f"a child ran from the source tree: {child['argv']}"
        assert str(copy) in text, f"a child ran from neither: {child['argv']}"
        assert src_text not in child["env"].get("PYTHONPATH", ""), child["env"]
    entry = next(c for c in children if any(a.endswith("run.py") for a in c["argv"]))
    script = Path(next(a for a in entry["argv"] if a.endswith("run.py")))
    assert script == copy / "run.py"

    empty = tmp_path / "empty"
    empty.mkdir()
    ran, modules = W.modules_of(script, ["--help"], env=entry["env"], cwd=empty, out=tmp_path / "mods.json")
    assert sum(1 for n in modules if n.startswith("defender.")) > 20, f"control: first-party modules were loaded: {ran.stderr[-500:]}"
    assert W.module_files_outside(modules, copy) == {}
    assert [f for f in modules.values() if _under(f, source)] == []


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


@pytest.mark.parametrize("module", ["defender.learning.branch.job_entry", "defender.learning.branch.post_step"])
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

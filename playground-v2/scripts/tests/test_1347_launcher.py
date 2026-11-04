"""#1347 D10/O6/O9/O10: the held-out launcher serves a frozen run and writes its index row.

Entry point bound by this contract: `playground-v2/scripts/launch_frozen.py::launch(case_dir,
*, index, parts_dir, lock_store, ops, run_fn, clock, work_dir, operator_docker_config, tenant,
reference=False) -> run_id`. `case_dir` holds alert.json and freeze.yaml (slug = its name);
parts are `parts_dir/<slug>/<name>`. `run_fn(argv, env) -> (rc, stdout, stderr)` starts the
agent (stdout line 1 is `run_id=<uuid>`). `ops` offers load_frozen(parts_dir, as_of) ->
{"docker_host": ...}, teardown(), fingerprint(window, as_of, arrived_by). The Docker config copy
is made under `work_dir`. A refusal (part missing or altered, lock held) raises an exception
naming the offending part or lock. Row digest: bare hex sha256 of sorted-key compact JSON of the
parsed freeze.yaml.

Production ops (FR1): `playground-v2/scripts/lab_ops.py::LabOps` implements `fingerprint(window,
as_of, arrived_by)` (tested in test_1347_lab_ops.py); `launch_frozen.py` binds it as `launch_frozen.LabOps`.
Nothing is injected for it: when the passed `ops` lacks `fingerprint` (or `es_now`), the script
builds its module-level `LabOps(...)` and uses that for the method.
A run that crashes before printing `run_id=` gets no row (r6.1); reference mode works on a freeze
whose `confirmed` is still empty. The launcher never sets or changes DOCKER_HOST / DOCKER_CONTEXT in
the agent's environment (`run_fn`'s `env`; an inherited operator value is left alone) and adds
nothing naming a freeze, slug or as_of.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path

import pytest
import yaml
from _lab_fakes import FINGERPRINT, FakeClock, FakeLockStore, Journal, instant, sha

LAUNCH = Path(__file__).resolve().parents[1] / "launch_frozen.py"
SLUG = "m05-lsass-access"
RUN_ID = "5b0d1f2e-3c4d-4e5f-8a6b-7c8d9e0f1a2b"
PARTS = {"proc-tree.txt": b"tree", "stubs.tar": b"stubs"}
FROZEN_HOST = "tcp://10.9.8.7:2375"
ALERT = b"{}"
FREEZE = {
    "alert_at": "2026-10-20T08:00:00Z", "alert": "sha256:" + sha(ALERT), "as_of": "2026-10-20T09:00:00Z",
    "window": ["2026-09-19T08:00:00Z", "2026-10-20T09:00:00Z"],
    "captured_at": "2026-10-20T09:03:17Z", "fingerprint": FINGERPRINT,
    "parts": {n: "sha256:" + sha(b) for n, b in PARTS.items()}, "chaos": None,
    "confirmed": {"by": "op", "at": "2026-10-20T10:00:00Z", "reference_run": RUN_ID},
}
DIGEST = hashlib.sha256(json.dumps(FREEZE, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
ROW_KEYS = {"slug", "run_id", "freeze", "verdict", "reason", "verified_at"}


def _module():
    spec = importlib.util.spec_from_file_location("launch_1347", LAUNCH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _tree(root: Path) -> dict[str, bytes]:
    return {str(p.relative_to(root)): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}


class Ops:
    def __init__(self, journal, fingerprint=FINGERPRINT, fail_at=None, index=None):
        self.journal, self.result, self.fail_at, self.index = journal, fingerprint, fail_at, index
        self.index_at_teardown = None
        self.load_args = None
        self.fp_kwargs = None

    def load_frozen(self, parts_dir, as_of):
        self.journal.append(("load_frozen", None))
        self.load_args = (parts_dir, as_of)
        if self.fail_at == "load":
            raise RuntimeError("load failed")
        return {"docker_host": FROZEN_HOST}

    def teardown(self):
        self.journal.append(("teardown", None))
        self.index_at_teardown = self.index.read_bytes() if self.index.exists() else b""
        if self.fail_at == "teardown":
            raise RuntimeError("teardown failed")

    def fingerprint(self, window, as_of, arrived_by):
        self.journal.append(("fingerprint", None))
        self.fp_kwargs = {"window": window, "as_of": as_of, "arrived_by": arrived_by}
        if self.fail_at == "fingerprint":
            raise RuntimeError("fingerprint failed")
        return self.result


class Rig:
    def __init__(self, tmp_path, fingerprint=FINGERPRINT, fail_at=None, rc=0, freeze=FREEZE):
        self.tmp = tmp_path
        self.journal = Journal()
        self.store = FakeLockStore(self.journal)
        self.clock = FakeClock(self.journal)
        self.case_dir = tmp_path / "held-out" / SLUG
        self.case_dir.mkdir(parents=True)
        (self.case_dir / "alert.json").write_bytes(ALERT)
        (self.case_dir / "freeze.yaml").write_text(yaml.safe_dump(freeze, sort_keys=False))
        self.parts_dir = tmp_path / "parts"
        (self.parts_dir / SLUG).mkdir(parents=True)
        for n, b in PARTS.items():
            (self.parts_dir / SLUG / n).write_bytes(b)
        self.index = tmp_path / "idx" / "index.jsonl"
        self.index.parent.mkdir()
        self.work = tmp_path / "work"
        self.work.mkdir()
        self.operator_cfg = tmp_path / "dot-docker"
        meta = self.operator_cfg / "contexts" / "meta"
        for key, name, host in (("a1", "soc-playground", "ssh://vps"), ("b2", "other", "tcp://x:1")):
            (meta / key).mkdir(parents=True)
            (meta / key / "meta.json").write_text(json.dumps(
                {"Name": name, "Endpoints": {"docker": {"Host": host}}}))
        (self.operator_cfg / "config.json").write_text('{"currentContext": "soc-playground"}')
        self.ops = Ops(self.journal, fingerprint, fail_at, self.index)
        self.rc, self.fail_at = rc, fail_at
        self.module = None
        self.argv = self.env = self.config_seen = None
        self.run_ended = self.lock_held_in_run = self.index_in_run = None
        self.store.on_delete = lambda name: setattr(
            self, "index_at_release", self.index.read_bytes() if self.index.exists() else b"")

    def run_fn(self, argv, env):
        self.journal.append(("run", None))
        self.argv, self.env = list(argv), dict(env)
        self.config_seen = _tree(Path(env["DOCKER_CONFIG"]))
        self.lock_held_in_run = "frozen-engine" in self.store.records
        if self.fail_at == "run":
            raise RuntimeError("run died")
        if self.fail_at == "interrupt":
            raise KeyboardInterrupt()
        self.run_ended = self.clock.now()
        return self.rc, f"run_id={RUN_ID}\nwork...\n", ""

    def launch(self, **kw):
        before = _tree(self.operator_cfg)
        out = (self.module or _module()).launch(
            self.case_dir, index=self.index, parts_dir=self.parts_dir, lock_store=self.store,
            ops=self.ops, run_fn=self.run_fn, clock=self.clock, work_dir=self.work,
            operator_docker_config=self.operator_cfg, tenant="tenant-1", **kw)
        assert _tree(self.operator_cfg) == before, "the operator's own Docker config changed"
        return out

    def rows(self):
        return [json.loads(x) for x in self.index.read_text().splitlines()] if self.index.exists() else []


def _opt(argv, flag):
    assert flag in argv, f"{flag} missing from {argv}"
    return argv[argv.index(flag) + 1]


def test_a_launch_runs_the_agent_with_the_freeze_times_and_no_learn(tmp_path):
    """D10: argv carries --as-of, --arrived-by (captured_at), --no-learn, the alert and tenant;
    no ticket write and no branching flag."""
    rig = Rig(tmp_path)
    rig.launch()
    a = rig.argv
    assert instant(_opt(a, "--as-of")) == instant(FREEZE["as_of"])
    assert instant(_opt(a, "--arrived-by")) == instant(FREEZE["captured_at"])
    assert "--no-learn" in a and _opt(a, "--tenant") == "tenant-1"
    assert str(rig.case_dir / "alert.json") in a
    assert not {"--update-ticket", "--episode", "--world"} & set(a)
    assert instant(rig.ops.load_args[1]) == instant(FREEZE["as_of"])


def test_the_run_sees_a_docker_config_with_only_the_playground_context_repointed(tmp_path):
    """D2: DOCKER_CONFIG is a copy whose soc-playground context points at the frozen engine,
    every other context is byte-identical, and the path names no freeze."""
    rig = Rig(tmp_path)
    rig.launch()
    cfg = Path(rig.env["DOCKER_CONFIG"])
    assert cfg != rig.operator_cfg
    rel = str(cfg.relative_to(rig.work)).lower()
    assert not any(w in rel for w in ("freeze", "frozen", SLUG.lower(), "as_of"))
    seen = rig.config_seen
    metas = {k: json.loads(v) for k, v in seen.items() if k.endswith("meta.json")}
    pg = [m for m in metas.values() if m["Name"] == "soc-playground"]
    assert len(pg) == 1 and pg[0]["Endpoints"]["docker"]["Host"] == FROZEN_HOST
    assert seen["contexts/meta/b2/meta.json"] == (rig.operator_cfg / "contexts/meta/b2/meta.json").read_bytes()
    assert seen["config.json"] == (rig.operator_cfg / "config.json").read_bytes()


def test_the_row_binds_the_run_to_the_freeze_and_is_appended_after_the_fingerprint(tmp_path):
    """O9/O6: one row with exactly the six keys, run id from the agent's first stdout line,
    freeze digest of the parsed freeze.yaml, verdict valid; appended after the fingerprint and
    before teardown (r6.2: a cleanup failure never costs a finished run its row), before the
    lock is released."""
    rig = Rig(tmp_path)
    older = {"slug": SLUG, "run_id": "older-run", "freeze": DIGEST, "verdict": "valid",
             "reason": "", "verified_at": "2026-10-20T11:00:00Z"}
    older_bytes = (json.dumps(older, sort_keys=True) + "\n").encode()
    rig.index.write_bytes(older_bytes)
    assert rig.launch() == RUN_ID
    first, row = rig.rows()
    assert rig.index.read_bytes().startswith(older_bytes), "an existing row was rewritten"
    assert first == older
    assert set(row) == ROW_KEYS
    assert (row["slug"], row["run_id"], row["freeze"], row["verdict"]) == (SLUG, RUN_ID, DIGEST, "valid")
    assert isinstance(row["reason"], str)
    ops = rig.journal.ops()
    assert ops.index("run") < ops.index("fingerprint") < ops.index("teardown") < ops.index("lock.delete")
    assert json.loads(rig.ops.index_at_teardown.splitlines()[-1]) == row
    assert len(rig.index_at_release.splitlines()) == 2
    kw = rig.ops.fp_kwargs
    assert [instant(x) for x in kw["window"]] == [instant(x) for x in FREEZE["window"]]
    assert instant(kw["as_of"]) == instant(FREEZE["as_of"])
    assert instant(kw["arrived_by"]) == instant(FREEZE["captured_at"])


def test_verified_at_is_after_the_run_ended(tmp_path):
    """O6: the verification timestamp comes after the agent run finished."""
    rig = Rig(tmp_path)
    rig.launch()
    assert instant(rig.rows()[0]["verified_at"]) > rig.run_ended


_BUCKET = "logs-system.auth-2026.10.20|2026-10-20T08"


@pytest.mark.parametrize("fingerprint", [
    {_BUCKET: [1200, 1199]},
    {_BUCKET: [1199, 1200]},
    {**FINGERPRINT, "logs-system.auth-2026.10.20|2026-10-20T09": [5, 5]},
    {},
], ids=["changed-value", "changed-count", "added-bucket", "removed-bucket"])
def test_a_differing_fingerprint_records_a_stale_verdict_with_a_reason(tmp_path, fingerprint):
    """O6: a post-run fingerprint with a changed value or count, an added or a removed bucket is stale."""
    rig = Rig(tmp_path, fingerprint=fingerprint)
    rig.launch()
    (row,) = rig.rows()
    assert row["verdict"] == "stale" and row["reason"].strip()
    assert row["freeze"] == DIGEST


def test_the_row_digest_ignores_comments_key_order_and_line_endings(tmp_path):
    """Freeze digest: a rewritten freeze.yaml with the same content yields the same row digest."""
    rig = Rig(tmp_path)
    text = "# edited\n" + yaml.safe_dump(FREEZE, sort_keys=True)
    (rig.case_dir / "freeze.yaml").write_bytes(text.replace("\n", "\r\n").encode())
    rig.launch()
    assert rig.rows()[0]["freeze"] == DIGEST


def test_a_run_that_crashed_after_announcing_its_id_still_gets_a_row(tmp_path):
    """O9: a nonzero agent exit with an announced run id is a run; the scorer counts it wrong."""
    rig = Rig(tmp_path, rc=1)
    rig.launch()
    assert [r["run_id"] for r in rig.rows()] == [RUN_ID]


def test_the_frozen_engine_lock_is_held_during_the_run_and_released_after(tmp_path):
    """O10: the frozen-engine lock is taken before load, held while the agent runs, then freed."""
    rig = Rig(tmp_path)
    rig.launch()
    assert rig.lock_held_in_run and "frozen-engine" not in rig.store.records
    ops = rig.journal.ops()
    assert ops.index("lock.create") < ops.index("load_frozen")


def test_a_second_launch_is_refused_while_the_frozen_engine_lock_is_held(tmp_path):
    """O10: a held frozen-engine lock stops the launch before any load or run; no row."""
    from chaos import lock
    rig = Rig(tmp_path)
    lock.take(rig.store, lock.FROZEN_ENGINE)
    with pytest.raises(lock.Held):
        rig.launch()
    assert {"load_frozen", "run"}.isdisjoint(rig.journal.ops()) and rig.rows() == []


@pytest.mark.parametrize("damage", ["missing", "altered"])
@pytest.mark.parametrize("name", sorted(PARTS))
def test_a_missing_or_altered_part_refuses_the_run_and_names_it(tmp_path, damage, name):
    """O6: whichever part is damaged: no run, no row, no load; the lock is released and the part is named."""
    rig = Rig(tmp_path)
    part = rig.parts_dir / SLUG / name
    part.unlink() if damage == "missing" else part.write_bytes(b"tampered")
    _module()  # a missing launch_frozen.py fails here, outside the refusal being tested
    with pytest.raises(Exception, match=name) as caught:
        rig.launch()
    assert not isinstance(caught.value, (AttributeError, TypeError, NameError))
    assert {"run", "load_frozen"}.isdisjoint(rig.journal.ops())
    assert rig.rows() == [] and "frozen-engine" not in rig.store.records


@pytest.mark.parametrize("stage", ["load", "run", "fingerprint"])
def test_a_launch_that_dies_leaves_no_row_and_frees_the_engine(tmp_path, stage):
    """O9: failing at load, run or fingerprint appends nothing, tears down any loaded
    or half-loaded copy, removes the config copy and releases the lock; an older row for the same freeze is untouched."""
    rig = Rig(tmp_path, fail_at=stage)
    older = json.dumps({"slug": SLUG, "run_id": "x", "freeze": DIGEST, "verdict": "valid",
                        "reason": "", "verified_at": "2026-10-20T11:00:00Z"}) + "\n"
    rig.index.write_text(older)
    with pytest.raises(RuntimeError, match=stage):
        rig.launch()
    assert rig.index.read_text() == older
    assert "frozen-engine" not in rig.store.records
    assert "teardown" in rig.journal.ops(), "a half-loaded copy was left running"
    assert list(rig.work.iterdir()) == [], "the Docker config copy was left behind"


def test_reference_mode_writes_no_row_prints_the_run_id_and_cleans_up(tmp_path, capsys):
    """O8/O9: a labelling run serves the freeze like any run but appends no row."""
    rig = Rig(tmp_path)
    run_id = rig.launch(reference=True)
    assert run_id == RUN_ID and RUN_ID in capsys.readouterr().out
    assert not rig.index.exists()
    assert "--as-of" in rig.argv and "--no-learn" in rig.argv
    ops = rig.journal.ops()
    assert "teardown" in ops and "frozen-engine" not in rig.store.records


def test_a_run_that_crashes_before_announcing_its_id_gets_no_row_and_cleans_up(tmp_path):
    """O9/r6.1: no `run_id=` line means no row; teardown still ran and the lock is free."""
    rig = Rig(tmp_path)
    rig.run_fn = lambda argv, env: (rig.journal.append(("run", None)) or
                                    (1, "Traceback (most recent call last):\n", "boom"))
    _module()  # a missing launch_frozen.py fails here, not inside the tolerated refusal
    try:
        rig.launch()
    except (AttributeError, TypeError, NameError, ImportError):
        raise  # a launcher bug is not a refusal of the crashed run
    except Exception:  # noqa: BLE001 - raising or returning are both acceptable for a dead run
        pass
    assert rig.rows() == []
    assert "teardown" in rig.journal.ops() and "frozen-engine" not in rig.store.records


def test_the_agents_environment_adds_nothing_naming_a_freeze_and_leaves_docker_vars_alone(
        tmp_path, monkeypatch):
    """P4/D2: variables the launcher adds or changes name no freeze, slug or as_of (paths read
    relative to work_dir), and DOCKER_HOST / DOCKER_CONTEXT are never set or changed by it."""
    monkeypatch.setenv("DOCKER_HOST", "tcp://elsewhere:1")
    monkeypatch.setenv("DOCKER_CONTEXT", "elsewhere")
    monkeypatch.setenv("GITHUB_HEAD_REF", "contract/1347-frozen-cases")
    rig = Rig(tmp_path)
    rig.launch()
    assert "DOCKER_CONFIG" in rig.env
    for name in ("DOCKER_HOST", "DOCKER_CONTEXT"):
        assert rig.env.get(name) in (None, os.environ[name]), f"launcher changed {name}"
    touched = {k: v for k, v in rig.env.items() if os.environ.get(k) != v}
    assert "DOCKER_CONFIG" in touched
    for name, value in touched.items():
        blob = f"{name}={str(value).replace(str(rig.work), '')}".lower()
        for word in ("freeze", "frozen", SLUG, "as_of", "as-of", "2026-10-20t09:00"):
            assert word not in blob, f"{name} names {word}"


def test_reference_mode_works_on_a_freeze_whose_confirmation_is_still_empty(tmp_path):
    """O8: the labelling run is launched before `confirmed` is filled; it serves the freeze and
    writes no row."""
    rig = Rig(tmp_path, freeze={**FREEZE, "confirmed": {}})
    assert rig.launch(reference=True) == RUN_ID
    assert "--as-of" in rig.argv and not rig.index.exists()
    assert "frozen-engine" not in rig.store.records


def test_without_an_injected_fingerprint_the_launcher_builds_the_production_lab_ops(
        tmp_path, monkeypatch):
    """FR1/O6: an ops object with no `fingerprint` leaves the launcher to build `LabOps` itself."""
    built = []

    class SpyLabOps:
        def __init__(self, *args, **kwargs):
            built.append((args, kwargs))

        def fingerprint(self, window, as_of, arrived_by):
            return {"spy|2026-10-20T08": [3, 3]}

    class WithoutFingerprint:
        def __init__(self, inner):
            self._inner = inner

        def __getattr__(self, name):
            if name == "fingerprint":
                raise AttributeError(name)
            return getattr(self._inner, name)

    rig = Rig(tmp_path)
    rig.module = _module()
    monkeypatch.setattr(rig.module, "LabOps", SpyLabOps)
    rig.ops = WithoutFingerprint(rig.ops)
    rig.launch()
    assert built
    assert [r["verdict"] for r in rig.rows()] == ["stale"]  # the spy's fingerprint was compared


def test_a_successful_launch_leaves_no_docker_config_copy_behind(tmp_path):
    """D2: the private Docker config copy is removed once the run is over."""
    rig = Rig(tmp_path)
    rig.launch()
    assert rig.config_seen and list(rig.work.iterdir()) == []


def test_an_interrupt_during_the_run_still_tears_down_and_frees_the_engine(tmp_path):
    """O9: Ctrl-C while the agent runs tears the copy down, removes the config copy, releases
    the lock and writes no row."""
    rig = Rig(tmp_path, fail_at="interrupt")
    with pytest.raises(KeyboardInterrupt):
        rig.launch()
    assert "teardown" in rig.journal.ops() and "frozen-engine" not in rig.store.records
    assert rig.rows() == [] and list(rig.work.iterdir()) == []


def test_a_docker_config_without_the_playground_context_refuses_and_still_tears_down(tmp_path):
    """D2/O9: the copy cannot be repointed, so nothing runs, no row, the loaded copy is torn
    down, no config copy is left and the lock is released."""
    rig = Rig(tmp_path)
    meta = rig.operator_cfg / "contexts/meta/a1/meta.json"
    meta.write_text(json.dumps({"Name": "renamed", "Endpoints": {"docker": {"Host": "ssh://vps"}}}))
    _module()
    with pytest.raises(Exception) as caught:
        rig.launch()
    assert not isinstance(caught.value, (AttributeError, TypeError, NameError))
    assert "run" not in rig.journal.ops() and rig.rows() == []
    ops = rig.journal.ops()
    assert "load_frozen" not in ops or "teardown" in ops
    assert "frozen-engine" not in rig.store.records
    assert list(rig.work.iterdir()) == []


def test_a_non_reference_launch_of_an_unconfirmed_freeze_is_refused(tmp_path):
    """O8/O9: a scored launch needs `confirmed`; nothing loads or runs, no row, lock released."""
    rig = Rig(tmp_path, freeze={**FREEZE, "confirmed": {}})
    _module()
    with pytest.raises(Exception) as caught:
        rig.launch()
    assert not isinstance(caught.value, (AttributeError, TypeError, NameError))
    assert {"load_frozen", "run"}.isdisjoint(rig.journal.ops()) and rig.rows() == []
    assert "frozen-engine" not in rig.store.records


def test_the_launcher_releases_only_with_its_own_token(tmp_path):
    """D14: if the lock was cleared and re-taken meanwhile, the launcher's release is refused
    with WrongToken and the other holder's lock survives."""
    from chaos import lock
    rig = Rig(tmp_path)
    taken: list[str] = []
    base = rig.run_fn

    def run_fn(argv, env):
        lock.clear(rig.store, lock.FROZEN_ENGINE)
        taken.append(lock.take(rig.store, lock.FROZEN_ENGINE))
        return base(argv, env)

    rig.run_fn = run_fn
    with pytest.raises(lock.WrongToken):
        rig.launch()
    assert taken and taken[0] in rig.store.records["frozen-engine"]


def test_the_row_digest_of_a_freeze_with_non_ascii_values_is_the_ascii_escaped_one(tmp_path):
    """Freeze digest: values like `café ☃` hash in json.dumps' default (ASCII-escaped) form,
    the same hex the scorer computes, however the YAML spells them."""
    freeze = {**FREEZE, "chaos": {"profile": "café ☃", "seed": 42, "ledger_ref": "chaos-é"}}
    expected = hashlib.sha256(json.dumps(freeze, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    rig = Rig(tmp_path, freeze=freeze)
    (rig.case_dir / "freeze.yaml").write_text(
        yaml.safe_dump(freeze, sort_keys=False, allow_unicode=True), encoding="utf-8")
    rig.launch()
    assert rig.rows()[0]["freeze"] == expected



def test_the_row_digest_is_the_scorers_own_function(monkeypatch):
    """O9: the launcher's row digest is computed by the scorer's `freeze_digest`, so the two can
    never drift apart; a value it cannot carry (TypeError or ValueError) refuses the launch."""
    module = _module()
    monkeypatch.setattr(module.held_out, "freeze_digest", lambda doc: "from-the-scorer")
    assert module.freeze_digest(FREEZE) == "from-the-scorer"

    def cannot(doc):
        raise ValueError("circular reference")
    monkeypatch.setattr(module.held_out, "freeze_digest", cannot)
    with pytest.raises(module.LaunchRefused, match="canonical JSON"):
        module.freeze_digest(FREEZE)

# -- the command line -------------------------------------------------------------------------


class _Proc:
    returncode, stderr = 0, ""
    stdout = f"run_id={RUN_ID}\n"


def _main(tmp_path, monkeypatch, *flags, prep=None):
    """Drive `launch_frozen.main` with the lab seams (docker lock store, LabOps, the agent
    subprocess) replaced; returns (rig, rc, agent argv list)."""
    rig = Rig(tmp_path)
    if prep is not None:
        prep(rig)
    module = _module()
    agent: list[list[str]] = []
    monkeypatch.setattr(module, "LabOps", lambda: rig.ops)
    monkeypatch.setattr(module.lock, "DockerLockStore", lambda: rig.store)
    monkeypatch.setattr(module.subprocess, "run", lambda argv, **kw: agent.append(list(argv)) or _Proc())
    monkeypatch.setenv("DOCKER_CONFIG", str(rig.operator_cfg))
    rc = module.main([str(rig.case_dir), "--tenant", "tenant-1", "--parts-dir", str(rig.parts_dir),
                      "--work-dir", str(rig.work), *flags])
    return rig, rc, agent


def test_the_command_line_appends_the_row_to_the_given_index_and_forwards_the_knowledge_commit(
        tmp_path, monkeypatch):
    """D10/O9: `--index F --knowledge-commit K` writes the row to F and starts the agent with K."""
    rig, rc, agent = _main(tmp_path, monkeypatch, "--index", str(tmp_path / "idx" / "index.jsonl"),
                           "--knowledge-commit", "abc1234")
    assert rc == 0 and [r["run_id"] for r in rig.rows()] == [RUN_ID]
    (argv,) = agent
    assert _opt(argv, "--knowledge-commit") == "abc1234" and "--no-learn" in argv


def test_the_command_line_reference_flag_writes_no_row(tmp_path, monkeypatch):
    """O8/O9: `--reference` serves the freeze and appends nothing to the index."""
    rig, rc, agent = _main(tmp_path, monkeypatch, "--reference",
                           "--index", str(tmp_path / "idx" / "index.jsonl"))
    assert rc == 0 and len(agent) == 1 and not rig.index.exists()


def test_the_command_line_passes_its_tenant_to_the_agent(tmp_path, monkeypatch):
    """D10: `--tenant T` is the tenant the agent is started with."""
    rig, rc, agent = _main(tmp_path, monkeypatch, "--index", str(tmp_path / "idx" / "index.jsonl"))
    assert rc == 0 and _opt(agent[0], "--tenant") == "tenant-1"


def test_a_launch_without_a_knowledge_pin_adds_no_knowledge_flag_and_only_string_arguments(tmp_path):
    """D10: with no pin the agent argv has no --knowledge-commit and every item is a string."""
    rig = Rig(tmp_path)
    rig.launch()
    assert "--knowledge-commit" not in rig.argv and all(isinstance(a, str) for a in rig.argv)


def test_the_docker_config_directory_name_shares_nothing_with_the_freeze(tmp_path):
    """P4: the config dir name the run can see shares no 6-character run with digest, slug or dates."""
    rig = Rig(tmp_path)
    rig.launch()
    name = Path(rig.env["DOCKER_CONFIG"]).name.lower()
    known = " ".join([DIGEST, SLUG, *map(str, (FREEZE["as_of"], FREEZE["alert_at"], FREEZE["captured_at"]))]).lower()
    shared = [name[i:i + 6] for i in range(len(name) - 5) if name[i:i + 6] in known]
    assert name and not shared, f"{name} repeats {shared}"


def test_a_reference_launch_is_refused_while_the_frozen_engine_lock_is_held(tmp_path):
    """O10: --reference serves the same frozen engine, so a held lock refuses it before any load."""
    from chaos import lock
    rig = Rig(tmp_path)
    lock.take(rig.store, lock.FROZEN_ENGINE)
    with pytest.raises(lock.Held):
        rig.launch(reference=True)
    assert {"load_frozen", "run"}.isdisjoint(rig.journal.ops())


def test_a_reference_launch_holds_the_frozen_engine_lock_during_the_run(tmp_path):
    """O10: the lock is held while the reference run executes and free after it."""
    rig = Rig(tmp_path)
    rig.launch(reference=True)
    assert rig.lock_held_in_run and "frozen-engine" not in rig.store.records


def test_a_last_index_row_without_a_newline_does_not_swallow_the_new_row(tmp_path):
    """O9: appending after an unterminated last row leaves two parseable rows, the first untouched."""
    rig = Rig(tmp_path)
    first = json.dumps({"slug": "earlier", "run_id": "r-0"}, sort_keys=True)
    rig.index.write_bytes(first.encode())
    rig.launch()
    assert rig.index.read_bytes().startswith(first.encode())
    rows = rig.rows()
    assert len(rows) == 2 and rows[0]["slug"] == "earlier" and rows[1]["run_id"] == RUN_ID


def test_parts_listed_by_bare_digest_are_accepted_like_prefixed_ones(tmp_path):
    """O6: a part digest written without the `sha256:` prefix verifies the same way."""
    bare = {**FREEZE, "parts": {n: sha(b) for n, b in PARTS.items()}}
    rig = Rig(tmp_path, freeze=bare)
    rig.launch()
    assert [r["verdict"] for r in rig.rows()] == ["valid"]


def test_the_default_agent_runner_hands_the_agent_the_repointed_docker_config(tmp_path, monkeypatch):
    """P4/D2: the default run function passes DOCKER_CONFIG, repointed at the frozen engine, to the subprocess."""
    rig = Rig(tmp_path)
    module = rig.module = _module()
    seen: dict = {}

    def run(argv, **kw):
        seen["env"] = kw.get("env")
        seen["config"] = _tree(Path(kw["env"]["DOCKER_CONFIG"])) if kw.get("env") else None
        return _Proc()

    monkeypatch.setattr(module.subprocess, "run", run)
    out = module.launch(rig.case_dir, index=rig.index, parts_dir=rig.parts_dir, lock_store=rig.store,
                        ops=rig.ops, clock=rig.clock, work_dir=rig.work,
                        operator_docker_config=rig.operator_cfg, tenant="tenant-1")
    assert out == RUN_ID and seen["env"] is not None
    assert Path(seen["env"]["DOCKER_CONFIG"]).parent == rig.work
    metas = [json.loads(v) for k, v in seen["config"].items() if k.endswith("meta.json")]
    assert FROZEN_HOST in [m["Endpoints"]["docker"]["Host"] for m in metas if m["Name"] == "soc-playground"]


def test_the_default_agent_runner_starts_a_real_process_that_sees_the_repointed_config(
        tmp_path, monkeypatch):
    """P4/D2: a real subprocess started by the default run function reads the frozen DOCKER_CONFIG."""
    rig = Rig(tmp_path)
    module = rig.module = _module()
    out_file = tmp_path / "agent-saw.txt"
    agent = tmp_path / "fake-agent.sh"
    agent.write_text(f'#!/bin/sh\necho "run_id={RUN_ID}"\nprintf %s "$DOCKER_CONFIG" > "{out_file}"\n')
    agent.chmod(0o755)
    monkeypatch.setattr(module, "_agent_python", lambda: str(agent))
    module.launch(rig.case_dir, index=rig.index, parts_dir=rig.parts_dir, lock_store=rig.store,
                  ops=rig.ops, clock=rig.clock, work_dir=rig.work,
                  operator_docker_config=rig.operator_cfg, tenant="tenant-1")
    seen = Path(out_file.read_text())
    assert seen.parent == rig.work and seen != rig.operator_cfg


def test_the_command_line_exits_4_and_names_a_damaged_part(tmp_path, monkeypatch, capsys):
    """O6: a refused launch exits 4 and prints the refusal naming the part; no agent, no row."""
    damage = lambda rig: (rig.parts_dir / SLUG / "stubs.tar").write_bytes(b"tampered")  # noqa: E731
    rig, rc, agent = _main(tmp_path, monkeypatch, "--index", str(tmp_path / "idx" / "index.jsonl"),
                           prep=damage)
    assert rc == 4 and "stubs.tar" in capsys.readouterr().err
    assert agent == [] and rig.rows() == []


def test_the_command_line_exits_4_and_names_the_held_lock(tmp_path, monkeypatch, capsys):
    """O10: a held frozen-engine lock exits 4 and the printed refusal names that lock."""
    from chaos import lock
    hold = lambda rig: lock.take(rig.store, lock.FROZEN_ENGINE)  # noqa: E731
    rig, rc, agent = _main(tmp_path, monkeypatch, "--index", str(tmp_path / "idx" / "index.jsonl"),
                           prep=hold)
    assert rc == 4 and "frozen-engine" in capsys.readouterr().err and agent == []


def test_a_run_id_line_that_is_not_the_first_output_line_binds_no_row(tmp_path):
    """O9/r6.1: only stdout line 1 announces the run id; a later `run_id=` line gets no row."""
    rig = Rig(tmp_path)
    rig.run_fn = lambda argv, env: (0, f"warming up\nrun_id={RUN_ID}\n", "")
    with pytest.raises(Exception):  # noqa: B017 - the refusal's type is the implementation's choice
        rig.launch()
    assert rig.rows() == [] and "teardown" in rig.journal.ops()


@pytest.mark.parametrize("reference", [False, True], ids=["scored", "reference"])
@pytest.mark.parametrize("alert", [b'{"_id": "another-alert"}', None], ids=["other-bytes", "absent"])
def test_a_case_whose_alert_is_not_the_one_its_freeze_names_is_refused(tmp_path, alert, reference):
    """r6.2 (review #1353): the freeze names its alert by sha256; a case whose alert.json is
    another alert (or none) is refused before anything loads or runs: no row, lock released."""
    rig = Rig(tmp_path)
    if alert is None:
        (rig.case_dir / "alert.json").unlink()
    else:
        (rig.case_dir / "alert.json").write_bytes(alert)
    module = _module()
    rig.module = module
    with pytest.raises(module.LaunchRefused, match="alert"):
        rig.launch(reference=reference)
    assert {"load_frozen", "run"}.isdisjoint(rig.journal.ops()) and rig.rows() == []
    assert "frozen-engine" not in rig.store.records


def test_a_freeze_that_names_no_alert_is_refused(tmp_path):
    """r6.2: a freeze captured before the alert was bound names none; it is captured again."""
    rig = Rig(tmp_path, freeze={k: v for k, v in FREEZE.items() if k != "alert"})
    module = _module()
    rig.module = module
    with pytest.raises(module.LaunchRefused, match="alert"):
        rig.launch()
    assert {"load_frozen", "run"}.isdisjoint(rig.journal.ops()) and rig.rows() == []


def test_a_teardown_that_fails_after_a_finished_run_keeps_its_row_and_says_so(tmp_path):
    """r6.2 (review #1353): the run finished and was fingerprinted, so its row is written; the
    teardown failure after it surfaces as its own error naming the run, and the config copy is
    removed and the lock released as on any other end."""
    rig = Rig(tmp_path, fail_at="teardown")
    module = _module()
    rig.module = module
    with pytest.raises(module.TeardownFailed, match=RUN_ID):
        rig.launch()
    (row,) = rig.rows()
    assert (row["run_id"], row["verdict"]) == (RUN_ID, "valid")
    assert "frozen-engine" not in rig.store.records
    assert list(rig.work.iterdir()) == []


def test_the_command_line_exits_non_zero_naming_a_failed_teardown_after_the_row(tmp_path, capsys):
    """r6.2: `main` reports a teardown failure after a written row (no traceback) and exits 5."""
    rig = Rig(tmp_path, fail_at="teardown")
    module = _module()

    def failing(*_a, **_k):
        raise module.TeardownFailed(f"{SLUG}: run {RUN_ID} recorded; teardown failed")

    module.launch = failing
    rc = module.main([str(rig.case_dir), "--tenant", "t", "--index", str(rig.index),
                      "--parts-dir", str(rig.parts_dir)])
    assert rc == 5
    assert "teardown" in capsys.readouterr().err


@pytest.mark.parametrize("exc", [OSError, KeyboardInterrupt])
def test_a_row_that_cannot_be_written_still_tears_the_frozen_copy_down(tmp_path, exc):
    """r6.2 (review): the row is written before teardown, so a failure writing it must still
    tear the loaded copy down and release the lock, with the write's error surfacing."""
    rig = Rig(tmp_path)
    module = _module()
    rig.module = module

    def unwritable(*_a, **_k):
        raise exc("index not writable")

    module._append_row = unwritable
    with pytest.raises(exc):
        rig.launch()
    assert "teardown" in rig.journal.ops(), "the frozen copy was left loaded"
    assert "frozen-engine" not in rig.store.records
    assert list(rig.work.iterdir()) == []

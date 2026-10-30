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
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest
import yaml
from _lab_fakes import FINGERPRINT, FakeClock, FakeLockStore, Journal, instant, sha

LAUNCH = Path(__file__).resolve().parents[1] / "launch_frozen.py"
SLUG = "m05-lsass-access"
RUN_ID = "5b0d1f2e-3c4d-4e5f-8a6b-7c8d9e0f1a2b"
PARTS = {"proc-tree.txt": b"tree", "stubs.tar": b"stubs"}
FROZEN_HOST = "tcp://10.9.8.7:2375"
FREEZE = {
    "alert_at": "2026-10-20T08:00:00Z", "as_of": "2026-10-20T09:00:00Z",
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
        (self.case_dir / "alert.json").write_text("{}")
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
        self.run_ended = self.clock.now()
        return self.rc, f"run_id={RUN_ID}\nwork...\n", ""

    def launch(self, **kw):
        before = _tree(self.operator_cfg)
        out = _module().launch(
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
    freeze digest of the parsed freeze.yaml, verdict valid; appended after fingerprint and
    teardown, before the lock is released."""
    rig = Rig(tmp_path)
    assert rig.launch() == RUN_ID
    (row,) = rig.rows()
    assert set(row) == ROW_KEYS
    assert (row["slug"], row["run_id"], row["freeze"], row["verdict"]) == (SLUG, RUN_ID, DIGEST, "valid")
    assert isinstance(row["reason"], str)
    ops = rig.journal.ops()
    assert ops.index("run") < ops.index("fingerprint") < ops.index("teardown") < ops.index("lock.delete")
    assert rig.ops.index_at_teardown == b"" and rig.index_at_release.strip() != b""
    kw = rig.ops.fp_kwargs
    assert [instant(x) for x in kw["window"]] == [instant(x) for x in FREEZE["window"]]
    assert instant(kw["as_of"]) == instant(FREEZE["as_of"])
    assert instant(kw["arrived_by"]) == instant(FREEZE["captured_at"])


def test_verified_at_is_after_the_run_ended(tmp_path):
    """O6: the verification timestamp comes after the agent run finished."""
    rig = Rig(tmp_path)
    rig.launch()
    assert instant(rig.rows()[0]["verified_at"]) > rig.run_ended


def test_a_differing_fingerprint_records_a_stale_verdict_with_a_reason(tmp_path):
    """O6: the post-run fingerprint differing from the freeze's marks the row stale."""
    rig = Rig(tmp_path, fingerprint={"logs-system.auth-2026.10.20|2026-10-20T08": [1200, 1199]})
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
def test_a_missing_or_altered_part_refuses_the_run_and_names_it(tmp_path, damage):
    """O6: no run, no row, no load; the lock is released and the part is named."""
    rig = Rig(tmp_path)
    part = rig.parts_dir / SLUG / "stubs.tar"
    part.unlink() if damage == "missing" else part.write_bytes(b"tampered")
    with pytest.raises(Exception, match="stubs.tar"):
        rig.launch()
    assert {"run", "load_frozen"}.isdisjoint(rig.journal.ops())
    assert rig.rows() == [] and "frozen-engine" not in rig.store.records


@pytest.mark.parametrize("stage", ["load", "run", "fingerprint", "teardown"])
def test_a_launch_that_dies_leaves_no_row_and_frees_the_engine(tmp_path, stage):
    """O9: failing at load, run, fingerprint or teardown appends nothing, tears down any loaded
    copy and releases the lock; an older row for the same freeze is untouched."""
    rig = Rig(tmp_path, fail_at=stage)
    older = json.dumps({"slug": SLUG, "run_id": "x", "freeze": DIGEST, "verdict": "valid",
                        "reason": "", "verified_at": "2026-10-20T11:00:00Z"}) + "\n"
    rig.index.write_text(older)
    with pytest.raises(RuntimeError, match=stage):
        rig.launch()
    assert rig.index.read_text() == older
    assert "frozen-engine" not in rig.store.records
    if stage != "load":
        assert "teardown" in rig.journal.ops()


def test_reference_mode_writes_no_row_prints_the_run_id_and_cleans_up(tmp_path, capsys):
    """O8/O9: a labelling run serves the freeze like any run but appends no row."""
    rig = Rig(tmp_path)
    run_id = rig.launch(reference=True)
    assert run_id == RUN_ID and RUN_ID in capsys.readouterr().out
    assert not rig.index.exists()
    assert "--as-of" in rig.argv and "--no-learn" in rig.argv
    ops = rig.journal.ops()
    assert "teardown" in ops and "frozen-engine" not in rig.store.records

"""Several cases of one variant are launched as one batch: one lock, one copy, one teardown, agents in waves.

Each launch served the copy for one case (about half an hour before the first agent ran, live); a freeze
yields many cases of the same variant, and the agent only reads the copy. A batch serves it once and runs
the cases' agents in waves of `parallel`: the node's clock is rewritten before each wave, so every agent of a
wave starts from one rewrite and no rewrite happens while an agent runs. A case whose agent dies loses only
its own row.
"""
from __future__ import annotations

import shutil
import threading
from pathlib import Path

import pytest
from _lab_fakes import LIVE_PROXY_URL, LabRig, canonical_digest


def _cases(rig, kind: str, uuids: list[str]) -> list[Path]:
    """One case dir per alert, all of variant `kind`, beside the rig's own case dir."""
    dirs = []
    for u in uuids:
        rig.write_expected_case(kind, alert_uuid=u)
        d = rig.case_dir.parent / f"case-{u}"
        d.mkdir()
        for name in ("alert.json", "case.yaml"):
            shutil.copy(rig.case_dir / name, d / name)
        dirs.append(d)
    return dirs


class Agents:
    """The agent seam for a batch: each run announces a run id of its own (`run-<case dir>`), and every
    clock rewrite and run start/end is recorded in one ordered log."""

    def __init__(self, rig, hook=None, dies: set[str] = frozenset()):
        self.rig, self.hook, self.dies = rig, hook, set(dies)
        self.log: list[tuple[str, str]] = []
        self.argv: dict[str, list[str]] = {}
        self._mu = threading.Lock()
        real = rig.ops.set_clock

        def set_clock(as_of):
            with self._mu:
                self.log.append(("clock", ""))
            return real(as_of)
        rig.ops.set_clock = set_clock

    def __call__(self, argv, env):
        case = Path(argv[2]).parent.name
        with self._mu:
            self.log.append(("start", case))
            self.argv[case] = list(argv)
        if self.hook is not None:
            self.hook(case)
        with self._mu:
            self.log.append(("end", case))
        return (1, "boom\n", "") if case in self.dies else (0, f"run_id=run-{case}\n", "")


def _module(rig):
    """The launcher module, loaded once per rig (each `rig.launch_module` is a fresh load)."""
    if not hasattr(rig, "_batch_module"):
        rig._batch_module = rig.launch_module
    return rig._batch_module


def _wave_starts_follow_a_rewrite(log, waves):
    """The entry before each wave's first start is a clock rewrite, and no agent was running then."""
    starts = [i for i, (k, _c) in enumerate(log) if k == "start"]
    firsts = [starts[sum(len(w) for w in waves[:n])] for n in range(len(waves))]
    return all(log[i - 1][0] == "clock" for i in firsts)


def _launch(rig, dirs, agents, **kw):
    kw = {"knowledge": "abc1234", **kw}
    rig._sync_env()
    try:
        return _module(rig).launch_batch(
            dirs, freezes_dir=rig.freezes, tenant_settings=rig.tenant_settings, index=rig.index,
            parts_dir=rig.parts, lock_store=rig.store, es=rig.ops.frozen_es(), ops=rig.ops, run_fn=agents,
            clock=rig.clock, env={"PATH": "/usr/bin", "DEFENDER_CREDENTIAL_PROXY_URL": LIVE_PROXY_URL},
            tenant="tenant-1", **kw)
    finally:
        rig._edges_modelled()


def _binding(rig, d: Path) -> str:
    import yaml
    return canonical_digest([canonical_digest(rig.freeze), canonical_digest(yaml.safe_load((d / "case.yaml").read_text()))])


UUIDS = ["young", "derived-in", "syslog-alert"]


def test_a_batch_serves_one_copy_once_and_writes_each_cases_bound_row_in_order(tmp_path):
    rig = LabRig(tmp_path)
    dirs = _cases(rig, "drop", UUIDS)
    agents = Agents(rig)
    ids = _launch(rig, dirs, agents, parallel=2)

    assert ids == [f"run-{d.name}" for d in dirs]
    assert [(r["slug"], r["run_id"], r["verdict"]) for r in rig.rows()] == \
        [(d.name, f"run-{d.name}", "valid") for d in dirs]
    assert [r["binding"] for r in rig.rows()] == [_binding(rig, d) for d in dirs]
    assert rig.cluster.restores == 1
    ops = rig.journal.ops()
    assert ops.count("lock.create") == 1 and ops.count("lock.delete") == 1
    assert rig.journal.last("lock.delete") > max(rig.docker_at())
    assert rig.nothing_serving() == []


def test_the_clock_is_rewritten_before_each_wave_and_never_while_an_agent_runs(tmp_path):
    rig = LabRig(tmp_path)
    dirs = _cases(rig, "none", UUIDS)
    agents = Agents(rig)
    _launch(rig, dirs, agents, parallel=2)

    assert _wave_starts_follow_a_rewrite(agents.log, [dirs[:2], dirs[2:]]), agents.log
    running = 0
    for kind, _case in agents.log:
        running += {"start": 1, "end": -1}.get(kind, 0)
        assert not (kind == "clock" and running), agents.log
    first, second = dirs[0].name, dirs[1].name
    anchor = lambda c: agents.argv[c][agents.argv[c].index("--as-of-anchor") + 1]  # noqa: E731
    assert anchor(first) == anchor(second)


def test_the_agents_of_a_wave_run_at_the_same_time(tmp_path):
    rig = LabRig(tmp_path)
    dirs = _cases(rig, "none", UUIDS[:2])
    together = threading.Barrier(2, timeout=10)
    _launch(rig, dirs, Agents(rig, hook=lambda _c: together.wait()), parallel=2)
    assert len(rig.rows()) == 2


def test_one_at_a_time_runs_each_agent_alone(tmp_path):
    rig = LabRig(tmp_path)
    dirs = _cases(rig, "none", UUIDS)
    agents = Agents(rig)
    _launch(rig, dirs, agents)

    seq = [(k, c) for k, c in agents.log if k != "clock"]
    assert seq == [x for d in dirs for x in (("start", d.name), ("end", d.name))]
    assert _wave_starts_follow_a_rewrite(agents.log, [[d] for d in dirs]), agents.log


def test_a_batch_of_two_variants_is_refused_before_the_lock_or_the_cluster(tmp_path):
    rig = LabRig(tmp_path)
    dirs = _cases(rig, "none", UUIDS[:1]) + _cases(rig, "drop", UUIDS[1:2])
    with pytest.raises(_module(rig).LaunchRefused, match="one variant"):
        _launch(rig, dirs, Agents(rig))
    assert rig.cluster.requests == [] and "lock.create" not in rig.journal.ops()
    assert rig.rows() == []


def test_a_batch_naming_one_case_twice_is_refused(tmp_path):
    rig = LabRig(tmp_path)
    dirs = _cases(rig, "none", UUIDS[:1])
    with pytest.raises(_module(rig).LaunchRefused, match="twice"):
        _launch(rig, dirs * 2, Agents(rig))
    assert "lock.create" not in rig.journal.ops()


def test_an_agent_that_dies_costs_only_its_own_row(tmp_path):
    rig = LabRig(tmp_path)
    dirs = _cases(rig, "drop", UUIDS)
    dead = dirs[1].name
    with pytest.raises(_module(rig).RunDied, match=dead):
        _launch(rig, dirs, Agents(rig, dies={dead}), parallel=2)
    assert [r["slug"] for r in rig.rows()] == [dirs[0].name, dirs[2].name]
    assert rig.nothing_serving() == []
    assert "frozen-engine" not in rig.store.records
    assert rig.journal.ops().count("lock.delete") == 1


def test_a_case_whose_alert_differs_is_stale_alone_and_the_copy_is_marked_dirty(tmp_path):
    import yaml
    rig = LabRig(tmp_path)
    dirs = _cases(rig, "drop", UUIDS)
    case = yaml.safe_load((dirs[2] / "case.yaml").read_text())
    case["alert"] = "0" * 64
    (dirs[2] / "case.yaml").write_text(yaml.safe_dump(case))
    _launch(rig, dirs, Agents(rig), parallel=2)

    assert [r["verdict"] for r in rig.rows()] == ["valid", "valid", "stale"]
    assert "alert" in rig.rows()[2]["reason"]
    assert rig.marker()["dirty"] is True


def test_a_reference_batch_joins_the_held_lock_and_leaves_it_held(tmp_path):
    from chaos import lock
    rig = LabRig(tmp_path)
    dirs = _cases(rig, "none", UUIDS)
    for d in dirs:      # a reference run works before `confirmed` is filled
        import yaml
        case = yaml.safe_load((d / "case.yaml").read_text())
        case["confirmed"] = None
        (d / "case.yaml").write_text(yaml.safe_dump(case))
    token = lock.take(rig.store, lock.FROZEN_ENGINE)
    held = dict(rig.store.records)
    ids = _launch(rig, dirs, Agents(rig), parallel=3, reference=True, lock_token=token)

    assert len(ids) == 3 and rig.rows() == []
    assert rig.store.records == held


def test_a_copy_its_agents_cannot_reach_starts_no_agent(tmp_path):
    from _lab_fakes import FROZEN_ENDPOINT
    rig = LabRig(tmp_path)
    dirs = _cases(rig, "none", UUIDS)
    rig.closed_ports.add((FROZEN_ENDPOINT.rsplit(":", 1)[0], 8007))
    agents = Agents(rig)
    with pytest.raises(Exception, match="8007"):
        _launch(rig, dirs, agents)
    assert not any(k == "start" for k, _c in agents.log)
    assert rig.rows() == [] and rig.nothing_serving() == []
    assert "frozen-engine" not in rig.store.records


def test_a_forward_that_drops_between_waves_keeps_the_rows_written_and_starts_no_more(tmp_path):
    from _lab_fakes import FROZEN_ENDPOINT
    rig = LabRig(tmp_path)
    dirs = _cases(rig, "none", UUIDS)
    address = FROZEN_ENDPOINT.rsplit(":", 1)[0]
    agents = Agents(rig, hook=lambda _c: rig.closed_ports.add((address, 9200)))
    with pytest.raises(Exception, match="9200"):
        _launch(rig, dirs, agents)
    assert [r["slug"] for r in rig.rows()] == [dirs[0].name]
    assert [c for k, c in agents.log if k == "start"] == [dirs[0].name]
    assert rig.nothing_serving() == []


def test_a_batch_hashes_each_freeze_part_once_however_many_cases_it_holds(tmp_path):
    """A batch is one freeze, so its parts are checked against freeze.yaml once per launch: a 42-case
    batch on a 17 GB freeze re-read 743 GB when every case re-hashed them."""
    rig = LabRig(tmp_path)
    dirs = _cases(rig, "drop", UUIDS)
    module = _module(rig)
    copy = module.frozen_copy
    real, hashed = copy.sha256_file, []

    def counting(path):
        hashed.append(Path(path).name)
        return real(path)
    copy.sha256_file = counting
    try:
        _launch(rig, dirs, Agents(rig), parallel=2)
    finally:
        copy.sha256_file = real

    parts = sorted(rig.freeze["parts"])
    assert sorted(n for n in hashed if n in parts) == parts

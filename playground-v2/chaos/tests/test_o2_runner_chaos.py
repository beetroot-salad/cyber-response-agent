"""O2 — an attack run under a fault is one invocation, and the fault never
outlives the run.

Driven through the real `attacks/runner.py::run_scenario`, with its two outbound
effects injected as parameter seams (this repo's convention — fakes enter through
the entry point, never `monkeypatch.setattr`):

    run_scenario(scenario, seed, overrides, dry_run, cr_mode=..., runs_dir=...,
                 chaos="none", keep_chaos=False, chaos_ctl=None,
                 post_cr=_post_cr, exec_fn=docker_exec)

`post_cr(body) -> (rc, payload)` and `exec_fn(host, command, user, dry_run) ->
(rc, stdout, stderr)` keep today's shapes and today's defaults, so the CLI is
unchanged. The two failure shapes the design calls out by line number:

  * runner.py:238 raises SystemExit when the cr_mode POST fails — activation must
    not have happened yet, or a CR failure leaks a live fault with no revert;
  * a step failure (or any exception) after activation must still revert, which
    today's `run_scenario` cannot do: it has no `finally`, only two explicit
    meta-writing branches.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
from _fakes import FakeChaosCtl

RUNNER_PATH = Path(__file__).resolve().parents[2] / "attacks" / "runner.py"
PROFILE = "cmdb-stale-owner"


@pytest.fixture(scope="module")
def runner():
    spec = importlib.util.spec_from_file_location("attacks_runner", RUNNER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def scenario() -> dict:
    """Shaped like a real catalog.yaml entry, trimmed to one instant step."""
    return {
        "id": "ssh-brute-force-canary",
        "category": "auth-metadata",
        "description": "spec fixture — one step, no sleeping\n",
        "source_host": "office-ws-1",
        "source_user": "dev.dana",
        "target_host": "canary-1",
        "default_intensity": 1,
        "steps": [{"cmd": "true ${target}", "repeat": 1, "delay_s_between": 0, "allow_fail": False}],
    }


def _ok_exec(host, command, user, dry_run):
    return 0, "", ""


def _meta(runs_dir: Path) -> dict:
    metas = sorted(runs_dir.glob("*/meta.json"))
    assert len(metas) == 1, f"expected one meta.json, found {metas}"
    return json.loads(metas[0].read_text())


def test_cr_failure_happens_before_chaos_is_ever_activated(runner, scenario, tmp_path):
    order: list[str] = []
    chaos_ctl = FakeChaosCtl(order=order)

    def failing_post_cr(body):
        order.append("post_cr")
        return 1, {"error": "change-mgmt refused"}

    with pytest.raises(SystemExit):
        runner.run_scenario(
            scenario,
            seed=42,
            overrides={},
            dry_run=False,
            cr_mode="valid",
            runs_dir=tmp_path,
            chaos=PROFILE,
            chaos_ctl=chaos_ctl,
            post_cr=failing_post_cr,
            exec_fn=_ok_exec,
        )

    assert order == ["post_cr"], "activation must come after a successful CR post"
    assert chaos_ctl.activate_calls == []
    assert chaos_ctl.revert_calls == []


def test_step_failure_after_activation_still_reverts(runner, scenario, tmp_path):
    chaos_ctl = FakeChaosCtl(ledger_ref="ledger-ref-step-fail")

    def failing_exec(host, command, user, dry_run):
        return 1, "", "boom"

    with pytest.raises(SystemExit):
        runner.run_scenario(
            scenario,
            seed=42,
            overrides={},
            dry_run=False,
            cr_mode="none",
            runs_dir=tmp_path,
            chaos=PROFILE,
            chaos_ctl=chaos_ctl,
            post_cr=lambda body: (0, {}),
            exec_fn=failing_exec,
        )

    assert len(chaos_ctl.activate_calls) == 1
    assert len(chaos_ctl.revert_calls) == 1
    # The revert must undo *that* activation, not some other bookkeeping.
    assert chaos_ctl.revert_calls[0]["ledger_ref"] == "ledger-ref-step-fail"


def test_an_exception_mid_run_still_reverts(runner, scenario, tmp_path):
    chaos_ctl = FakeChaosCtl(ledger_ref="ledger-ref-explode")

    def exploding_exec(host, command, user, dry_run):
        raise RuntimeError("docker exec died mid-run")

    with pytest.raises(RuntimeError):
        runner.run_scenario(
            scenario,
            seed=42,
            overrides={},
            dry_run=False,
            cr_mode="none",
            runs_dir=tmp_path,
            chaos=PROFILE,
            chaos_ctl=chaos_ctl,
            post_cr=lambda body: (0, {}),
            exec_fn=exploding_exec,
        )

    assert [c["ledger_ref"] for c in chaos_ctl.revert_calls] == ["ledger-ref-explode"]


def test_normal_exit_reverts_and_records_the_join_key(runner, scenario, tmp_path):
    chaos_ctl = FakeChaosCtl(ledger_ref="ledger-ref-clean")

    runner.run_scenario(
        scenario,
        seed=42,
        overrides={},
        dry_run=False,
        cr_mode="none",
        runs_dir=tmp_path,
        chaos=PROFILE,
        chaos_ctl=chaos_ctl,
        post_cr=lambda body: (0, {}),
        exec_fn=_ok_exec,
    )

    assert [c["profile_id"] for c in chaos_ctl.activate_calls] == [PROFILE]
    assert [c["seed"] for c in chaos_ctl.activate_calls] == [42]
    assert [c["ledger_ref"] for c in chaos_ctl.revert_calls] == ["ledger-ref-clean"]

    chaos_block = _meta(tmp_path)["pre_run"]["chaos"]
    assert chaos_block["profile"] == PROFILE
    assert chaos_block["seed"] == 42
    assert chaos_block["ledger_ref"] == "ledger-ref-clean"


def test_aborted_run_still_records_the_join_key(runner, scenario, tmp_path):
    chaos_ctl = FakeChaosCtl(ledger_ref="ledger-ref-aborted")
    with pytest.raises(SystemExit):
        runner.run_scenario(
            scenario,
            seed=7,
            overrides={},
            dry_run=False,
            cr_mode="none",
            runs_dir=tmp_path,
            chaos=PROFILE,
            chaos_ctl=chaos_ctl,
            post_cr=lambda body: (0, {}),
            exec_fn=lambda host, command, user, dry_run: (1, "", "boom"),
        )

    meta = _meta(tmp_path)
    assert meta["aborted"] is True
    assert meta["pre_run"]["chaos"]["ledger_ref"] == "ledger-ref-aborted"


def test_keep_chaos_holds_the_fault_open(runner, scenario, tmp_path):
    """--keep-chaos is the one exit that does not revert; without it the `finally`
    claim is unfalsifiable."""
    chaos_ctl = FakeChaosCtl()

    runner.run_scenario(
        scenario,
        seed=42,
        overrides={},
        dry_run=False,
        cr_mode="none",
        runs_dir=tmp_path,
        chaos=PROFILE,
        keep_chaos=True,
        chaos_ctl=chaos_ctl,
        post_cr=lambda body: (0, {}),
        exec_fn=_ok_exec,
    )

    assert len(chaos_ctl.activate_calls) == 1
    assert chaos_ctl.revert_calls == []


def test_no_chaos_flag_means_no_chaos_calls_at_all(runner, scenario, tmp_path):
    """Default behaviour is unchanged: a plain run touches the controller never."""
    chaos_ctl = FakeChaosCtl()

    runner.run_scenario(
        scenario,
        seed=42,
        overrides={},
        dry_run=False,
        cr_mode="none",
        runs_dir=tmp_path,
        chaos_ctl=chaos_ctl,
        post_cr=lambda body: (0, {}),
        exec_fn=_ok_exec,
    )

    assert chaos_ctl.activate_calls == []
    assert chaos_ctl.revert_calls == []
    assert not _meta(tmp_path)["pre_run"].get("chaos")

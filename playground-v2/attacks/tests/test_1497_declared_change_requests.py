"""A scenario can carry its own change request, and every dispatch runs as an account that exists.

The capture fires scenarios without a `--cr-mode` (#1347), so a scenario that needs a change
record to mean what it means (an approved window, one still awaiting approval) declares it in
the catalog (#1497). The runner posts it before the steps; an explicit mode still wins.
"""
from __future__ import annotations

import importlib.util
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

PLAYGROUND = Path(__file__).resolve().parents[2]
CATALOG = PLAYGROUND / "attacks" / "catalog.yaml"
RUNNER = PLAYGROUND / "attacks" / "runner.py"
INVENTORY = yaml.safe_load((PLAYGROUND / "hosts" / "inventory.yaml").read_text())
REALM = yaml.safe_load((PLAYGROUND / "keycloak" / "realm.yaml").read_text())


@pytest.fixture(scope="module")
def runner():
    spec = importlib.util.spec_from_file_location("attacks_runner_1497", RUNNER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _scenario(**extra):
    return {
        "id": "change-backed-web-maintenance", "category": "execution", "description": "x\n",
        "source_host": "jump-box-1", "source_user": "sre.alice", "target_host": "web-1",
        "default_intensity": 1,
        "steps": [{"cmd": "true", "repeat": 1, "delay_s_between": 0, "allow_fail": False}],
        **extra,
    }


def _fire(runner, scenario, tmp_path, **kwargs):
    posted = []

    def post_cr(body):
        posted.append(body)
        return 0, body

    # The capture's call: no cr_mode at all (scripts/lab_ops.py `fire`).
    _, run_dir, _ = runner.run_scenario(
        scenario, 42, {}, False, runs_dir=tmp_path, post_cr=post_cr,
        exec_fn=lambda host, command, user, dry_run: (0, "", ""), **kwargs,
    )
    return posted, run_dir


def test_a_capture_fires_a_scenario_with_the_change_request_it_declares(runner, tmp_path):
    posted, run_dir = _fire(runner, _scenario(cr_mode="valid"), tmp_path)
    assert [b["hosts"] for b in posted] == [["web-1"]]
    assert posted[0]["requester"] == "sre.alice"
    assert '"cr_mode": "valid"' in (run_dir / "meta.json").read_text()


def test_an_explicit_mode_wins_over_the_declared_one(runner, tmp_path):
    posted, _ = _fire(runner, _scenario(cr_mode="valid"), tmp_path, cr_mode="none")
    assert posted == []


def test_a_scenario_without_a_declared_mode_posts_nothing(runner, tmp_path):
    posted, _ = _fire(runner, _scenario(), tmp_path)
    assert posted == []


def test_an_unknown_declared_mode_is_refused_before_anything_fires(runner, tmp_path):
    fired = []
    with pytest.raises(SystemExit, match="unsupported cr_mode"):
        runner.run_scenario(
            _scenario(cr_mode="approved"), 42, {}, False, runs_dir=tmp_path,
            post_cr=lambda body: (0, body),
            exec_fn=lambda host, command, user, dry_run: fired.append(command) or (0, "", ""),
        )
    assert fired == []


def test_a_change_awaiting_approval_covers_the_work_but_shows_no_approval(runner):
    now = datetime(2026, 11, 14, 12, 0, tzinfo=timezone.utc)
    body = runner._build_cr_body("awaiting-approval", "db-maintenance-pending-approval-42-0000abcd",
                                 "db-1", "sre.alice", INVENTORY, now=now)
    assert body["hosts"] == ["db-1"] and body["requester"] == "sre.alice"
    assert body["status"] == "planned" and body["approver"] is None
    assert datetime.fromisoformat(body["window_start"]) <= now <= datetime.fromisoformat(body["window_end"])


def test_every_declared_mode_is_one_the_runner_knows(runner):
    declared = {s["id"]: s["cr_mode"] for s in yaml.safe_load(CATALOG.read_text())["scenarios"]
                if "cr_mode" in s}
    assert declared, "no scenario declares a change request"
    assert {i: m for i, m in declared.items() if m not in runner.CR_MODES} == {}


def _accounts(host: str) -> set[str]:
    """The accounts seed-users.py creates on `host`: role-wide, then the host's own."""
    role_of = {u["username"]: (u.get("realmRoles") or [None])[0] for u in REALM["users"]}
    names = {u for role, cfg in INVENTORY["roles"].items() if host in cfg.get("hosts", [])
             for u, r in role_of.items() if r == role}
    entry = next(h for h in INVENTORY["hosts"] if h["name"] == host)
    return names | {u["username"] for u in entry.get("users") or []} | {"root"}


def _dispatches():
    for scenario in yaml.safe_load(CATALOG.read_text())["scenarios"]:
        for index, step in enumerate(scenario["steps"]):
            host = step.get("source_host", scenario["source_host"])
            user = step.get("source_user", scenario.get("source_user", "root"))
            yield pytest.param(host, user, id=f"{scenario['id']}[{index}]")


@pytest.mark.parametrize("host,user", _dispatches())
def test_every_step_runs_as_an_account_its_host_has(host, user):
    # A missing account fails `docker exec -u` and the step never happens; allow_fail hides it.
    assert user in _accounts(host), f"{user} has no account on {host}"


BASELINE = yaml.safe_load((PLAYGROUND / "hosts" / "base" / "baseline" / "catalog.yaml").read_text())


@pytest.mark.parametrize("action", BASELINE["actions"], ids=lambda a: a["id"])
def test_every_background_action_binds_to_some_account(action):
    # The scheduler binds an action only to identities with an account on the host, and skips
    # the rest without a word: dba-tunnel sat on dev-ws, where dba.ivy has none, and never ran.
    from fnmatch import fnmatch
    hosts = [h["name"] for h in INVENTORY["hosts"] if h["role"] in action["host_roles"]]
    bound = {(h, u) for h in hosts for u in _accounts(h) - {"root"}
             if any(fnmatch(u, pattern) for pattern in action["identities"])}
    assert bound, f"{action['id']} binds to no account on {hosts}"

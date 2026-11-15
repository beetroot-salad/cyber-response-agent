"""A scenario can carry its own change request, and every account a step uses exists.

The capture fires scenarios without a `--cr-mode` (#1347), so a scenario that needs a change
record to mean what it means (an approved window) declares it in the catalog (#1497). The
runner posts it before the steps; an explicit mode still wins.

Accounts come from the baseline scheduler's own `users_on_host`, the copy of seed-users.py's
rule the lab already runs, rather than a third copy here.
"""
from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest
import yaml

PLAYGROUND = Path(__file__).resolve().parents[2]
CATALOG = PLAYGROUND / "attacks" / "catalog.yaml"
RUNNER = PLAYGROUND / "attacks" / "runner.py"
SCHEDULER = PLAYGROUND / "hosts" / "base" / "baseline" / "scheduler.py"
INVENTORY = yaml.safe_load((PLAYGROUND / "hosts" / "inventory.yaml").read_text())
SCENARIOS = yaml.safe_load(CATALOG.read_text())["scenarios"]
BASELINE = yaml.safe_load((PLAYGROUND / "hosts" / "base" / "baseline" / "catalog.yaml").read_text())
HOSTS = {h["name"] for h in INVENTORY["hosts"]}

# Logins meant to fail as an account the target does not have.
UNKNOWN_ON_PURPOSE = {("cross-tier-ssh-probe", "dev.dana", "db-1")}


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_scheduler = _load("baseline_scheduler_1497", SCHEDULER)
_scheduler.INVENTORY = PLAYGROUND / "hosts" / "inventory.yaml"
_scheduler.REALM = PLAYGROUND / "keycloak" / "realm.yaml"


def _accounts(host: str) -> set[str]:
    return set(_scheduler.users_on_host(host)) | {"root"}


@pytest.fixture(scope="module")
def runner():
    return _load("attacks_runner_1497", RUNNER)


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


def test_every_declared_mode_is_one_the_runner_knows(runner):
    declared = {s["id"]: s["cr_mode"] for s in SCENARIOS if "cr_mode" in s}
    assert declared, "no scenario declares a change request"
    assert {i: m for i, m in declared.items() if m not in runner.CR_MODES} == {}


def _steps():
    for scenario in SCENARIOS:
        for index, step in enumerate(scenario["steps"]):
            host = step.get("source_host", scenario["source_host"])
            user = step.get("source_user", scenario.get("source_user", "root"))
            yield pytest.param(scenario, step, host, user, id=f"{scenario['id']}[{index}]")


@pytest.mark.parametrize("scenario,step,host,user", _steps())
def test_every_step_runs_as_an_account_its_host_has(scenario, step, host, user):
    # A missing account fails `docker exec -u` and the step never happens; allow_fail hides it.
    assert user in _accounts(host), f"{user} has no account on {host}"


def _missing_logins(cmd: str) -> set[tuple[str, str]]:
    """Each literal `user@host` login in a rendered command whose host lacks that account.

    A login through a shell variable (`$u@host`, a loop over mistyped names) is not read: it is
    meant to try names that may not exist."""
    logins = {(u, h) for u, h in re.findall(r"(?<![\w$.-])([A-Za-z][\w.-]*)@([\w-]+)", cmd) if h in HOSTS}
    return {(u, h) for u, h in logins if u not in _accounts(h)}


@pytest.mark.parametrize("scenario,step,host,user", _steps())
def test_every_login_a_step_makes_is_as_an_account_its_target_has(scenario, step, host, user):
    # An unknown user's sshd attempt is also ingested as a success (#1497), so a login meant to
    # fail as a real account but made as a missing one fires success-after-failures on bad data.
    target = scenario["target_host"]
    cmd = step["cmd"].replace("${user}", user).replace("${target}", target).replace("${host}", target)
    missing = _missing_logins(cmd)
    assert missing <= {(u, h) for s, u, h in UNKNOWN_ON_PURPOSE if s == scenario["id"]}, missing


def _bindings(action):
    """(host, user) pairs the scheduler binds `action` to, by its own rule."""
    for host in INVENTORY["hosts"]:
        if host["role"] not in action.get("host_roles", []):
            continue
        for user in _scheduler.match_identities(action["identities"], _scheduler.users_on_host(host["name"])):
            yield host, user


@pytest.mark.parametrize("action", BASELINE["actions"], ids=lambda a: a["id"])
def test_every_background_action_binds_to_some_account(action):
    # The scheduler binds an action only to identities with an account on the host, and skips
    # the rest without a word: dba-tunnel sat on dev-ws, where dba.ivy has none, and never ran.
    assert list(_bindings(action)), f"{action['id']} binds to no account"


@pytest.mark.parametrize("action", BASELINE["actions"], ids=lambda a: a["id"])
def test_every_login_a_background_action_makes_is_as_an_account_its_target_has(action):
    # `${wrong}` is the typo action's deliberately missing host, so it is not a login to check.
    missing = set()
    for host, user in _bindings(action):
        targets = _scheduler._resolve_targets(action, host) or [None]
        for target in targets:
            cmd = _scheduler.substitute(action["cmd"], host=host["name"], user=user,
                                        target=target or "")
            missing |= _missing_logins(cmd)
    assert not missing, f"{action['id']} logs in as accounts its targets lack: {sorted(missing)}"

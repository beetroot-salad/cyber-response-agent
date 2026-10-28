"""#1108 P4: the drain logs in to OpenBao itself with AppRole (A-ID); issuer login material stays
in host-side delivery processes, never in a box or an environment variable, and the client config
lies under no box mount source (O8); a tenant P3's `open` refuses is the stage's refusal (O9).

`version_control.issuer_login(tenant, *, issuer_config, transport=)` reads the issuer client config
file and the tenant row's `forge` binding, then logs in; `transport` (the drain's
`issuer_transport=`) is the httpx transport its OpenBao client sends through. `AppRoleVault` adds
OpenBao's AppRole login to P3's issuer fake: `POST /v1/auth/approle/login` returns a client token
(`400` on a bad pair) that the identity-token request must carry (else `403`).
"""
from __future__ import annotations

import dataclasses
import logging
import os
import re
import shutil
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from defender.tests.support.learning.curation import _spec773 as S
from defender.tests.tenancy.tenant_1108_delivery._identity import ISSUER
from defender.learning.core.state import FINDINGS
from defender.tests.tenancy.tenant_1108_p4._support import DEFENDER, bind_forge, git, unbind_forge
from defender.tests.tenancy.tenant_1108_p4._drain_support import (
    CLIENT_TOKEN,
    DEV_CLIENT_DIR,
    ROLE_ID,
    SECRET_ID,
    AppRoleVault,
    vc,
    write_issuer_config,
    LESSON_NAME,
    BoxSpy,
    CuratorTrigger,
    LeadStep,
    author_drain,
    critical_text,
    drain_paths,
    draft_entries,
    executed_lead,
    lead_author_drain,
    product_repo,
    queue,
    queued_run,
    remote_branches,
    under,
)
from defender.tests.support.shared._locations_1210 import location_path

def _login(t: Any, config: Path, vault: AppRoleVault) -> Any:
    return vc().issuer_login(t.tenant, issuer_config=config, transport=vault.transport)


# ---------------------------------------------------------------------------------------------
# A-ID: issuer_login
# ---------------------------------------------------------------------------------------------


def test_a_id_issuer_login_logs_in_with_approle_and_mints_the_bound_tenant_token(p4_tenant, tmp_path):
    """The login sends the config's `role_id`/`secret_id` to OpenBao, then asks for the binding's
    role with the client token it got; the identity is bound to this tenant and the binding's
    audience and role, and yields the minted token."""
    t = p4_tenant
    binding = bind_forge(t)
    vault = AppRoleVault(t.tenant_id)
    config = write_issuer_config(tmp_path / "client")

    identity = _login(t, config, vault)
    token = identity.token()

    assert vault.logins() == [{"role_id": ROLE_ID, "secret_id": SECRET_ID}]
    assert [str(r.url) for r in vault.token_requests()] == [
        f"{ISSUER}/token/{binding['issuer_role']}"]
    assert vault.token_requests()[0].headers["X-Vault-Token"] == CLIENT_TOKEN
    assert token == vault.minted()
    assert (identity.tenant_id, identity.role, identity.audience, identity.issuer) == (
        t.tenant_id, binding["issuer_role"], binding["audience"], ISSUER)


def test_a_id_a_refused_approle_login_is_a_refusal_that_never_echoes_the_secret(p4_tenant, tmp_path):
    """A refused `secret_id` is an auth refusal, never a token, and its text carries neither id.
    Control: the right pair logs in (previous case)."""
    t = p4_tenant
    bind_forge(t)
    vault = AppRoleVault(t.tenant_id)
    config = write_issuer_config(tmp_path / "client", secret_id="p4-wrong-secret-7c41")

    with pytest.raises((vc().ForgejoAuthError, vc().DeliveryRefused)) as refused:
        _login(t, config, vault).token()

    assert vault.logins() == [{"role_id": ROLE_ID, "secret_id": "p4-wrong-secret-7c41"}]
    assert vault.token_requests() == []
    assert "p4-wrong-secret-7c41" not in str(refused.value)
    assert ROLE_ID not in str(refused.value)


@pytest.mark.parametrize("missing", ["config", "binding"])
def test_o9_a_missing_issuer_config_or_forge_binding_refuses_the_login_before_any_request(
        p4_tenant, tmp_path, missing):
    """A missing config file or forge binding is decidable locally: the login refuses before any
    request reaches the issuer, naming what is missing."""
    t = p4_tenant
    vault = AppRoleVault(t.tenant_id)
    config = write_issuer_config(tmp_path / "client")
    if missing == "config":
        bind_forge(t)
        config.unlink()
    else:
        unbind_forge(t)

    with pytest.raises((vc().ForgejoAuthError, vc().DeliveryRefused)) as refused:
        _login(t, config, vault)

    assert vault.calls == []
    said = str(refused.value).lower()
    assert ("issuer" in said and "config" in said) if missing == "config" else "forge" in said, said


# ---------------------------------------------------------------------------------------------
# The drain logs in itself; O8 drain half
# ---------------------------------------------------------------------------------------------


def test_a_id_o8_the_drain_logs_in_from_the_config_path_and_hands_no_login_material_to_the_box(
        p4_tenant, tmp_path, monkeypatch, caplog):
    """Given only the config's path, the drain logs in with AppRole itself and pushes and opens
    its PR with the minted token. No login material leaves the host process: none is in the box
    request's environment or under its mounts, or in the drain's environment while the model
    step runs. Each check has a positive control on the same channel."""
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
    t = p4_tenant
    bind_forge(t)
    vault = AppRoleVault(t.tenant_id)
    t.server.token = vault.minted()  # the origin accepts what this issuer mints
    config = write_issuer_config(tmp_path / "playground-issuer" / "client")
    paths = drain_paths(t, product_repo(tmp_path))
    queue(paths, [S.finding_row("f1", run_id="f1")])
    secrets = (ROLE_ID, SECRET_ID, CLIENT_TOKEN, vault.minted())
    env_seen: list[dict] = []
    curator = S.FakeCurator(writes={LESSON_NAME: S.lesson("f1")},
                            also=lambda *_a: env_seen.append(dict(os.environ)))
    trigger, box = CuratorTrigger(author=curator), BoxSpy()
    # The fixture's own publish authenticated with ITS identity's token; only the drain counts.
    t.server.authorizations.clear()

    with caplog.at_level(logging.INFO):
        rc = author_drain(t, paths, trigger=trigger, box=box, issuer_config=config,
                          issuer_transport=vault.transport)

    assert rc == 0, critical_text(caplog)
    assert vault.logins() == [{"role_id": ROLE_ID, "secret_id": SECRET_ID}]
    (branch, _tip), = remote_branches(t.remote).items()
    assert [c["head"] for c in t.forge.creates] == [branch]
    assert t.server.authorizations
    assert all(a is None or vault.minted() in a for a in t.server.authorizations)
    # The box: no login material in its environment, no mount over the config.
    (request,) = box.requests
    assert "DEFENDER_AGENT_DIR" in request.env, "control: the box environment is read"
    leaked = [(k, s) for k, v in request.env.items() for s in secrets if s in str(v)]
    assert leaked == [], leaked
    sources = [Path(m.source) for m in request.mounts]
    assert not [s for s in sources if under(config, s)], sources
    assert under(DEFENDER / "x" / "issuer.json", DEFENDER), "control: containment is detected"
    # The drain process's environment while the model step ran.
    assert env_seen, "the model step never ran"
    leaked_env = [k for env in env_seen for k, v in env.items() for s in secrets if s in v]
    assert leaked_env == [], leaked_env
    monkeypatch.setenv("P4_CONTROL_PROBE", SECRET_ID)
    assert [k for k, v in os.environ.items() if SECRET_ID in v] == ["P4_CONTROL_PROBE"]


# ---------------------------------------------------------------------------------------------
# O9: P3 `open()` refusals x both drains
# ---------------------------------------------------------------------------------------------

#: Each refusal P3's `TenantDelivery.open` (or the login before it) makes on a tenant that cannot
#: be delivered to, and what its one critical line must name (regex, lower-cased).
O9_REFUSALS = {
    "issuer-config": r"issuer.*config|config.*issuer",
    "forge-binding": r"forge",
    "unversioned": r"version|git",
    "local-origin": r"network|origin",
    "unprotected-main": r"protect",
}
#: The refusals decided locally, before any request to the issuer or the forge.
_LOCAL = ("issuer-config", "forge-binding")


def _break_tenant(t: Any, config: Path, fault: str) -> None:
    """Make `t` refuse delivery as `fault` names, the way P3's own open-refusal cases do
    (`tenant_1108_delivery/test_open.py`); `"none"` leaves it deliverable (the control)."""
    if fault == "forge-binding":
        unbind_forge(t)
        return
    if fault == "local-origin":
        # Whichever of the binding and the clone's configured origin the drain reads, it is a
        # filesystem path, not a network origin.
        bind_forge(t, origin="/tmp/p4-local-origin.git")
        git(t.clone, "remote", "set-url", "origin", "/tmp/p4-local-origin.git")
        return
    bind_forge(t)
    if fault == "issuer-config":
        config.unlink()
    elif fault == "unversioned":
        shutil.rmtree(t.clone / ".git")
    elif fault == "unprotected-main":
        t.forge.protection = {"name": "main", "protected": False, "user_can_push": True}


@dataclasses.dataclass
class _Tick:
    """One drain's tick over `t`: `run()` drives it through the stage runner with the issuer
    config path (the drain logs in itself); `handed()` is everything its work steps were handed;
    `queued_untouched()` is its row still waiting where it was queued, not in flight."""

    run: Callable[[], int]
    handed: Callable[[], list]
    queued_untouched: Callable[[], bool]
    delivered: Callable[[], bool]
    box: BoxSpy


def _tick(drain: str, t: Any, tmp_path: Path, config: Path, vault: AppRoleVault) -> _Tick:
    box = BoxSpy()
    seams = {"issuer_config": config, "issuer_transport": vault.transport}
    if drain == "author":
        paths = drain_paths(t, product_repo(tmp_path))
        queue(paths, [S.finding_row("f1", run_id="f1")])
        trigger = CuratorTrigger(author=S.FakeCurator(writes={LESSON_NAME: S.lesson("f1")}))
        return _Tick(
            run=lambda: author_drain(t, paths, trigger=trigger, box=box, **seams),
            handed=lambda: list(trigger.calls),
            queued_untouched=lambda: "f1" in S.pending_by_id(paths, FINDINGS),
            delivered=lambda: bool(remote_branches(t.remote)) and bool(t.forge.creates),
            box=box)
    paths = drain_paths(t, product_repo(tmp_path, adapters=("cmdb",)))
    run = queued_run(t, paths, "p4-lead-refused").name
    case = "case-p4-lead-refused"
    queue_dir = Path(location_path(paths.state_root)) / "author-queue"
    assert (queue_dir / f"{case}.json").is_file(), "control: the row is read where it was queued"
    step = LeadStep(executed={run: [executed_lead("cmdb.owner-by-tag")]}, edits={})
    pitfalls_calls: list[Any] = []

    def pitfalls(*a: Any, **k: Any) -> int:
        pitfalls_calls.append((a, k))
        return 0

    return _Tick(
        run=lambda: lead_author_drain(t, paths, box=box, run_lead_author=step,
                                      run_pitfalls=pitfalls, **seams),
        handed=lambda: [*step.served, *pitfalls_calls],
        queued_untouched=lambda: ((queue_dir / f"{case}.json").is_file()
                                  and not (queue_dir / "inflight" / f"{case}.json").is_file()),
        delivered=lambda: step.served == [run],
        box=box)


@pytest.mark.parametrize("drain", ["author", "lead"])
@pytest.mark.parametrize("fault", list(O9_REFUSALS))
def test_o9_a_tenant_open_refuses_is_the_stages_one_line_refusal_and_runs_nothing(
        p4_tenant, tmp_path, monkeypatch, caplog, drain, fault):
    """Each refusal P3's open makes is the stage runner's refusal on both drains: exit 2 with one
    critical line naming the cause and no traceback, no box, nothing handed to the lane's steps,
    no draft, no branch, and the queued row left in place. A locally decidable refusal (config,
    binding) reaches neither the issuer nor the forge. Control: the next case."""
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "1000")
    monkeypatch.setenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", "1000")
    t = p4_tenant
    vault = AppRoleVault(t.tenant_id)
    t.server.token = vault.minted()
    config = write_issuer_config(tmp_path / "playground-issuer" / "client")
    tick = _tick(drain, t, tmp_path, config, vault)
    _break_tenant(t, config, fault)
    t.forge.requests.clear()  # the fixture's own publish asked the forge; only the tick counts

    caplog.clear()
    with caplog.at_level(logging.DEBUG):
        rc = tick.run()

    assert rc == 2, critical_text(caplog)
    critical = [r.getMessage() for r in caplog.records if r.levelno >= logging.CRITICAL]
    assert len(critical) == 1, critical
    assert re.search(O9_REFUSALS[fault], critical[0].lower()), critical[0]
    assert "\n" not in critical[0], critical[0]
    assert [r.getMessage() for r in caplog.records if r.exc_info] == [], "a traceback was logged"
    if fault in _LOCAL:
        assert vault.calls == []
        assert t.forge.requests == []
    assert tick.box.requests == [], "a box was started for a tick that could not deliver"
    assert tick.handed() == []
    assert draft_entries(t) == []
    assert remote_branches(t.remote, "") == {"main": t.origin_main()}
    assert tick.queued_untouched(), "the row left its place in the queue"


@pytest.mark.parametrize("drain", ["author", "lead"])
def test_control_o9_a_deliverable_tenant_logs_in_and_serves_the_row(
        p4_tenant, tmp_path, monkeypatch, caplog, drain):
    """Positive control for the O9 matrix, same scene and seams with nothing broken: the drain
    logs in, its work step is handed the row, and the tick delivers."""
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "1000")
    monkeypatch.setenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", "1000")
    t = p4_tenant
    vault = AppRoleVault(t.tenant_id)
    t.server.token = vault.minted()
    config = write_issuer_config(tmp_path / "playground-issuer" / "client")
    tick = _tick(drain, t, tmp_path, config, vault)
    _break_tenant(t, config, "none")
    assert tick.queued_untouched(), "control: the observer sees the queued row"

    caplog.clear()
    with caplog.at_level(logging.INFO):
        rc = tick.run()

    assert rc == 0, critical_text(caplog)
    assert vault.logins() == [{"role_id": ROLE_ID, "secret_id": SECRET_ID}]
    assert tick.handed() != []
    assert tick.delivered()


def test_o8_the_dev_issuer_client_config_lies_under_no_drain_box_mount_source(p4_tenant):
    """The dev issuer client config folder lies under no mount source of a drain box (P3's real
    `Batch.box_request()`), neither the code mount nor the draft. Control: the check flags a
    path under the code mount."""
    t = p4_tenant
    batch = t.open_delivery().start_batch("o8-mounts", lanes=("lessons",))
    try:
        sources = [Path(m.source) for m in batch.box_request().mounts]
        assert any(under(DEFENDER, s) for s in sources), "control: the code mount is listed"
        assert [s for s in sources if under(DEV_CLIENT_DIR, s)] == [], sources
        assert under(DEFENDER / "playground-issuer" / "client", DEFENDER), "control"
    finally:
        batch.discard()

"""#1108 P4 slice S-D — A-ID (the drain logs in to OpenBao itself, AppRole), O8's drain half (issuer
login material only in host-side delivery processes: never in a box, a run's environment or any
env var; the client config passed by path and lying under no box mount source), and O9's
"missing issuer config refuses before any model call".

The login is one symbol (orchestrator decision OD4):
    defender.learning.author.version_control.issuer_login(tenant, *, issuer_config: Path)
        -> ForgejoIdentity
It reads the issuer client config FILE and the tenant row's `forge` binding (`{origin, audience,
issuer_role}`, written here with S0's `bind_forge`) and logs in.

ASSUMED SEAM (an extension of OD4, reported): `issuer_login(..., transport=None)` — the
`httpx` transport its OpenBao client sends through (production: none, a real TLS connection
trusting the config's CA). The drain forwards it as `author_drain(..., issuer_transport=)`.

ASSUMED SHAPE (the design fixes only the folder `<repo>/playground-issuer/client/` and the
contents "issuer URL, CA cert, AppRole role_id/secret_id"): a JSON file
    {"issuer": "https://<host>[:port]", "ca_cert": "<path to a PEM>",
     "role_id": "...", "secret_id": "..."}
named `issuer.json` here (S-F's gitignore probe spells the same name). `issuer` is OpenBao's
address; the identity endpoint is `<issuer>/v1/identity/oidc` (OpenBao's own path).

The issuer fake: P3's `VaultHTTP` answers only the identity-token GET and accepts any caller.
`AppRoleVault` below adds OpenBao's AppRole login as the API documents it (`POST
/v1/auth/approle/login` with `{role_id, secret_id}` -> `{auth: {client_token}}`; a bad pair is
`400`) and requires that client token (`X-Vault-Token`) on the identity-token request (else
`403`). It records every request; it decides nothing about the drain. S0/P3 are asked to adopt
it next to `VaultHTTP`.
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
    """A-ID: the login sends the config file's AppRole `role_id`/`secret_id` to OpenBao's login
    endpoint, then asks the identity endpoint for the binding's role with the client token it got;
    the identity it returns is bound to this tenant, the binding's audience and role, and hands
    back the token the issuer minted."""
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
    """A-ID: a `secret_id` OpenBao refuses is a refusal (an auth error), never a token, and its
    text carries neither the `secret_id` nor the `role_id`. Positive control: the same login
    with the right pair succeeds (previous case)."""
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
    """O9/O-STALE misconfiguration: no issuer client config file, or no forge binding in the
    tenant row, is decidable locally: the login refuses before any request reaches the issuer,
    naming what is missing. (Control: the first case logs in over the same fake.)"""
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
    """A-ID + O8 (drain half): given only the issuer client config's PATH (no identity), the
    drain logs in with AppRole itself, and its push and PR reach the tenant origin with the
    minted token. The login material never leaves the host process: the batch box's request
    carries no `role_id`, `secret_id`, client token or forge token in its environment, mounts
    no folder holding the config file, and no environment variable of the drain process holds
    any of them while the model step runs. Positive controls on the same channels: the box's
    environment does carry `DEFENDER_AGENT_DIR`; the containment check flags a config under the
    code mount; the env scan sees a variable set the same way."""
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
# O9: P3 `open()` refusals x both drains (R-L7)
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
    """O9 (R-L7), both drains: each refusal P3's open makes — no issuer client config file, no
    forge binding in the tenant row, an unversioned tenant clone, a non-network origin, an
    unprotected `main` — is the stage runner's refusal: exit 2 with ONE critical line naming the
    cause and no traceback; no box starts, the lane's work steps (curator; lead author and
    pitfalls) are handed nothing, no draft is left under `<T>/drafts/`, no branch reaches the
    origin, and the queued row stays where it was (the lead lane's at the top of the queue, not
    in flight). A refusal decidable locally (config, binding) reaches neither the issuer nor the
    forge. Restores the stage-refusal shape `test_1105_pr2_review_fixes_2`'s deleted no-data-root
    case pinned. Positive control: the next case, same seams, nothing broken."""
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
    """Positive control for the O9 matrix: the same scene and seams with nothing broken — the
    drain logs in with AppRole, the work step is handed the row, and (author lane) a `lessons/`
    branch and its PR reach the tenant forge. The matrix's observers see each channel here."""
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
    """O8: the dev issuer client config folder (`<repo>/playground-issuer/client/`) lies under no
    mount source of a drain box (P3's real `Batch.box_request()` over this checkout's
    `defender/`): neither the code mount nor the draft. Positive control: the same check flags a
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

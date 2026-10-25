"""#1108 P4 S-F — the dev issuer and Forgejo, against the running dev stack (`live`).

O12 (U1): after `docker compose up` (and any restart) OpenBao is unsealed without a human and a
delivery process logs in; one lesson PR is delivered end to end; the bot cannot push protected
`main`. O13 (U2): Forgejo's data is the `<repo>/playground-knowledge/` bind mount, and the lab
repo, its bot and its history carried over from the named volume. P-4/U4: deployment facts are
file-only and never in the tenant repo.

These are where the unprobed claims get verified: P4-C13 (lab `main` protected against the bot),
P4-C14 (OpenBao >= 2.4 static seal auto-unseals; identity tokens and AppRole behave as in Vault),
P4-C15 (Forgejo accepts an issuer on a non-443 port with a private CA). Nothing here presumes
their outcome beyond the design: a failure here is the probe answering.

Skips are for absent infrastructure only. A Forgejo older than 17 or a sealed issuer FAILS.

Inputs (test-only environment; P-4 forbids environment for the product, not for a test):

    DEFENDER_LIVE_DATA_ROOT        the host's real data root holding the lab tenant (the suite's
                                   conftest replaces DEFENDER_DATA_ROOT with a tmp root per test)
    DEFENDER_LIVE_TENANT           the lab tenant id (its row's forge binding names its issuer
                                   client config, <repo>/playground-issuer/client/<id>/issuer.json)
    DEFENDER_LIVE_ALLOW_RESTART=1  allow `docker restart` of the openbao container
    DEFENDER_LIVE_ALLOW_LAB_PR=1   allow opening (then closing) one PR on the lab repo and an
                                   attempted push to its `main`
    DEFENDER_LIVE_O13_OLD_VOLUME   the pre-migration named volume (just after migrating)
    DEFENDER_LIVE_O13_COMMIT       a lab commit made before the migration
    DEFENDER_LIVE_O13_BOT          the lab bot's Forgejo login before the migration

    PYTHONPATH="$PWD" flock /tmp/defender-pytest.lock defender/.venv/bin/python -m pytest \\
        -m live defender/tests/tenancy/tenant_1108_p4/test_live_dev_issuer.py

Assumed seam (A-ID, shared with S-D): `defender.learning.author.version_control.issuer_login(
tenant) -> ForgejoIdentity` — reads the tenant row's forge binding and the issuer client config
file it names (issuer URL, CA, AppRole role_id/secret_id), logs in to
OpenBao with AppRole, and returns the identity whose `client` is the authenticated, CA-trusting
OpenBao client. Every live delivery process (drains, `tenant.py`, the publish child) goes through
it, so this file logs in exactly as a drain does.

`survives docker compose down -v` (O13) cannot run from inside the dev container that `down`
stops. It is a manual step: `docker compose down -v && docker compose up -d`, then run this file;
`test_forgejo_data_is_the_playground_knowledge_bind_mount_O13` and the O13 history test are the
post-conditions.
"""
from __future__ import annotations

import base64
import dataclasses
import importlib
import json
import os
import re
import subprocess
import time
import uuid
from pathlib import Path

import pytest

from defender import _git
from defender._git import REPO_ROOT
from defender.tests.tenancy.tenant_1108_p4._support import committed_blobs
from defender.tests.support.sandbox._docker import daemon_reachable

pytestmark = pytest.mark.live

DEFENDER = REPO_ROOT / "defender"
COMPOSE_PROJECT = "cyber-response-agent_devcontainer"
RESTART_BUDGET_SECONDS = 120
_TEST_ONLY_ENV = ("DEFENDER_LIVE_", "DEFENDER_O14_")
_DEPLOYMENT_FACT = re.compile(
    r"BAO|VAULT|OPENBAO|ISSUER|APPROLE|ROLE_ID|SECRET_ID|FORGE_|FORGEJO_TOKEN|AUDIENCE")


# ---------------------------------------------------------------------------------------------
# Live inputs
# ---------------------------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class Lab:
    tenant: object
    tenant_id: str
    issuer_config: Path
    forge: dict


def _main_checkout() -> Path:
    """The checkout `docker compose up` ran from (`..` of `.devcontainer/`): the main checkout,
    also from a worktree."""
    common = _git.git(["rev-parse", "--path-format=absolute", "--git-common-dir"], cwd=REPO_ROOT)
    return Path(common).parent


def _lab() -> Lab:
    data_root = os.environ.get("DEFENDER_LIVE_DATA_ROOT")
    tenant_id = os.environ.get("DEFENDER_LIVE_TENANT")
    if not (data_root and tenant_id):
        pytest.skip("set DEFENDER_LIVE_DATA_ROOT and DEFENDER_LIVE_TENANT")
    from defender.tenancy._tenant import data_root_from_path, requested_tenant

    row = json.loads((Path(data_root) / tenant_id / "tenant.json").read_text(encoding="utf-8"))
    assert "forge" in row, f"the lab tenant row has no forge binding: {sorted(row)}"
    config = row["forge"].get("issuer_config")
    if not (isinstance(config, str) and Path(config).is_file()):
        pytest.skip(f"no issuer client config at {config!r}: the dev issuer is not provisioned")
    tenant = requested_tenant(data_root_from_path(Path(data_root)), tenant_id)
    return Lab(tenant=tenant, tenant_id=tenant_id, issuer_config=Path(config), forge=row["forge"])


def _login(lab: Lab):
    """AppRole login exactly as a delivery process does it (assumed seam, see module doc)."""
    vc = importlib.import_module("defender.learning.author.version_control")
    return vc.issuer_login(lab.tenant)


def _issuer_base(identity) -> str:
    """`https://host:port` of the issuer whose identity endpoint is `identity.issuer`."""
    return identity.issuer.split("/v1/", 1)[0]


def _seal_status(identity) -> dict:
    response = identity.client.get(_issuer_base(identity) + "/v1/sys/seal-status", timeout=10)
    response.raise_for_status()
    return response.json()


def _claims(token: str) -> dict:
    payload = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


def _forge(lab: Lab, identity):
    import httpx

    from defender.learning.author.version_control.forgejo import ForgejoForge

    return ForgejoForge(origin=lab.forge["origin"], identity=identity,
                        client=httpx.Client(timeout=30))


def _bearer(identity) -> dict[str, str]:
    return {"Authorization": "Bearer " + identity.token(min_validity=60)}


def _container(service: str) -> dict:
    if not daemon_reachable():
        pytest.skip("needs a reachable docker daemon")
    ids = subprocess.run(
        ["docker", "ps", "-q", "--filter", f"label=com.docker.compose.project={COMPOSE_PROJECT}",
         "--filter", f"label=com.docker.compose.service={service}"],
        capture_output=True, text=True, timeout=30, check=True).stdout.split()
    if not ids:
        pytest.skip(f"no running `{service}` container in compose project {COMPOSE_PROJECT}")
    assert len(ids) == 1, f"{len(ids)} `{service}` containers running"
    out = subprocess.run(["docker", "inspect", ids[0]], capture_output=True, text=True,
                         timeout=30, check=True).stdout
    return json.loads(out)[0]


def _host_repo() -> Path:
    """The host path the dev container's `/workspace` is (DooD: bind sources are host paths)."""
    mounts = _container("devcontainer")["Mounts"]
    found = [m["Source"] for m in mounts if m.get("Destination") == "/workspace"]
    assert len(found) == 1, f"devcontainer /workspace mounts: {found}"
    return Path(found[0])


def _forgejo_version(lab: Lab, identity) -> tuple[int, ...]:
    import httpx

    from defender.learning.author.version_control.forgejo import ForgeAddress

    origin = ForgeAddress.parse(lab.forge["origin"]).origin
    response = httpx.get(origin + "/api/v1/version", headers=_bearer(identity), timeout=30)
    response.raise_for_status()
    match = re.match(r"(\d+)\.(\d+)\.(\d+)", response.json()["version"])
    assert match, f"Forgejo version {response.text!r}"
    return tuple(int(g) for g in match.groups())


# ---------------------------------------------------------------------------------------------
# O13: Forgejo's data is the bind mount (configuration observed on the RUNNING stack)
# ---------------------------------------------------------------------------------------------

def test_forgejo_data_is_the_playground_knowledge_bind_mount_O13():
    """O13/U2: the running Forgejo's `/data` is a bind of `<host repo>/playground-knowledge`,
    not a docker volume — what makes `down -v` and rebuilds survivable. (Observed 2026-10-22:
    `response-forgejo` runs 15.0.9 with `/data` on volume
    `cyber-response-agent_devcontainer_forgejo-data`: red until the stack is re-created.)"""
    mounts = _container("forgejo")["Mounts"]
    data = [m for m in mounts if m.get("Destination") == "/data"]
    assert len(data) == 1, f"forgejo /data mounts: {data}"
    assert data[0]["Type"] == "bind", f"forgejo /data is a {data[0]['Type']} ({data[0].get('Name')})"
    assert Path(data[0]["Source"]) == _host_repo() / "playground-knowledge"


def test_running_forgejo_is_17_or_later_O12():
    """O12: the running Forgejo supports Authorized Integrations (17+). Fails, not skips, on an
    older one. (Observed 2026-10-22: `response-forgejo` runs `codeberg.org/forgejo/forgejo:15.0.9`
    while the compose default is 17.0.0 — red until the stack is re-created and upgraded.)"""
    image = _container("forgejo")["Config"]["Image"]
    match = re.search(r":v?(\d+)\.(\d+)\.(\d+)$", image)
    assert match, f"the running Forgejo image {image!r} names no version"
    assert int(match.group(1)) >= 17, f"the running Forgejo is {image!r}: no Authorized Integrations"


def test_issuer_state_is_on_disk_under_playground_issuer_and_no_host_port_U4():
    """U4/design: the running openbao keeps its state in binds under
    `<host repo>/playground-issuer/`, uses no docker volume, and publishes no host port."""
    bao = _container("openbao")
    host_issuer = _host_repo() / "playground-issuer"
    mounts = bao["Mounts"]
    assert not [m for m in mounts if m["Type"] == "volume"], f"openbao volumes: {mounts}"
    assert any(Path(m["Source"]) == host_issuer or host_issuer in Path(m["Source"]).parents
               for m in mounts if m["Type"] == "bind"), f"openbao binds: {mounts}"
    published = {port: b for port, b in (bao["NetworkSettings"].get("Ports") or {}).items() if b}
    assert not published, f"openbao publishes {published} to the host"


# ---------------------------------------------------------------------------------------------
# O12: unsealed without a human; a delivery process logs in; Forgejo accepts the issuer
# ---------------------------------------------------------------------------------------------

def test_issuer_is_unsealed_and_a_delivery_process_logs_in_O12_C14_C15():
    """O12: with the stack up, OpenBao is initialised and unsealed (no human ran `unseal`), an
    AppRole login yields a short-lived identity token bound to the lab tenant over the dev CA's
    TLS, and Forgejo (17+) accepts that token for the lab repository (P4-C14, P4-C15)."""
    lab = _lab()
    identity = _login(lab)
    assert identity.issuer.startswith("https://"), identity.issuer
    status = _seal_status(identity)
    assert status["initialized"] is True, status
    assert status["sealed"] is False, status
    claims = _claims(identity.token())
    assert claims["tenant_id"] == lab.tenant_id
    assert claims["exp"] - claims["iat"] <= 600, "the lab role's TTL exceeds 600 s"
    assert claims["aud"] in (lab.forge["audience"], [lab.forge["audience"]])
    assert _forgejo_version(lab, identity)[0] >= 17, "Forgejo older than 17: no Authorized Integrations"
    assert isinstance(_forge(lab, identity).repository_id(), int)


def test_after_an_issuer_restart_it_unseals_itself_and_publish_works_O12_C14():
    """O12 ('and any restart'): `docker restart` the openbao container; within the budget the
    issuer reports unsealed with nobody calling `sys/unseal`, a fresh AppRole login succeeds
    (identity state persisted in file storage), and a publish of the lab tenant — fetch through
    the issuer's token — succeeds. Mutates the dev stack: opt-in via
    DEFENDER_LIVE_ALLOW_RESTART=1. Publishing touches local derived state only (exports,
    `current`), never the lab repo."""
    lab = _lab()
    if os.environ.get("DEFENDER_LIVE_ALLOW_RESTART") != "1":
        pytest.skip("restarts the dev issuer: set DEFENDER_LIVE_ALLOW_RESTART=1")
    before = _seal_status(_login(lab))
    assert before["sealed"] is False, "precondition: the issuer is unsealed before the restart"
    container = _container("openbao")
    subprocess.run(["docker", "restart", container["Id"]], capture_output=True, timeout=120,
                   check=True)
    deadline = time.monotonic() + RESTART_BUDGET_SECONDS
    last: object = None
    while True:
        try:
            identity = _login(lab)
            status = _seal_status(identity)
            if status["sealed"] is False:
                break
            last = status
        except Exception as e:  # noqa: BLE001 — the issuer is still starting; keep the last fault
            last = e
        assert time.monotonic() < deadline, f"issuer not usable {RESTART_BUDGET_SECONDS}s after restart: {last!r}"
        time.sleep(2)
    import httpx

    from defender.learning.author.version_control import TenantDelivery

    delivery = TenantDelivery.open(lab.tenant, defender_dir=DEFENDER, client=httpx.Client(timeout=30),
                                   identity=identity, origin=lab.forge["origin"])
    export = delivery.publish()
    assert re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", export.commit)


# ---------------------------------------------------------------------------------------------
# O12 / P4-C13: protected main
# ---------------------------------------------------------------------------------------------

def test_lab_main_is_protected_against_the_bot_O12_C13():
    """O12/P4-C13: Forgejo reports lab `main` protected and not pushable by the bot (read-only;
    the same check `TenantDelivery.open` makes). Then, opted in, a real push of a commit to
    `main` with the bot's token is refused by Forgejo — attempted only after protection is
    reported, so an unprotected `main` fails here without being written. (Observed 2026-10-22:
    unprotected per the 2026-10-16 comment — red until the operator protects it.)"""
    lab = _lab()
    identity = _login(lab)
    _forge(lab, identity).verify_main_protection()
    if os.environ.get("DEFENDER_LIVE_ALLOW_LAB_PR") != "1":
        pytest.skip("the push half writes to the lab forge: set DEFENDER_LIVE_ALLOW_LAB_PR=1")
    import tempfile

    from defender.learning.author.version_control.transport import GitTransport

    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        _git.git(["init", "-b", "main"], cwd=repo)
        _git.git(["remote", "add", "origin", lab.forge["origin"]], cwd=repo)
        transport = GitTransport(repo, lab.forge["origin"], identity, 30)
        transport.fetch()
        _git.git(["reset", "--hard", "origin/main"], cwd=repo)
        _git.git(["-c", "user.name=Probe", "-c", "user.email=probe@invalid", "commit",
                  "--allow-empty", "-m", "O12 protected-main probe (must be refused)"], cwd=repo)
        commit = _git.git(["rev-parse", "HEAD"], cwd=repo)  # lint-oracle: ok — names the probe commit just made; not an expected value
        branch = "o12-probe/" + uuid.uuid4().hex
        # control: the same transport and token CAN push a branch. `GitTransport.push` has no
        # local destination guard, so the refusal below is Forgejo's branch protection.
        transport.push(commit, branch)
        try:
            with pytest.raises(_git.GitError):
                transport.push(commit, "main")
        finally:
            _delete_branch(lab, identity, branch)


def _delete_branch(lab: Lab, identity, branch: str) -> None:
    import httpx

    from defender.learning.author.version_control.forgejo import ForgeAddress

    api = ForgeAddress.parse(lab.forge["origin"]).api
    response = httpx.delete(f"{api}/branches/{branch}", headers=_bearer(identity), timeout=30)
    assert response.status_code in (204, 404), f"cleanup of {branch}: {response.status_code}"


# ---------------------------------------------------------------------------------------------
# O12: one lesson PR end to end
# ---------------------------------------------------------------------------------------------

def test_one_lesson_pr_is_delivered_end_to_end_through_the_dev_issuer_O12():
    """O12: through AppRole login -> `TenantDelivery.open` -> publish -> batch draft -> one
    lesson written in the `lessons` lane -> ChangeSet -> commit-maker -> push -> PR, the lab
    Forgejo shows an open PR against `main` whose only file is that lesson. The batch uses its
    own branch prefix so no drain's writer lease sees it, and the PR is closed and its branch
    deleted afterwards. Opt-in: DEFENDER_LIVE_ALLOW_LAB_PR=1 (it opens a PR on the lab repo and
    leaves a commit-maker record entry for the batch)."""
    lab = _lab()
    if os.environ.get("DEFENDER_LIVE_ALLOW_LAB_PR") != "1":
        pytest.skip("opens a PR on the lab repo: set DEFENDER_LIVE_ALLOW_LAB_PR=1")
    import httpx

    from defender.learning.author.version_control import DeliveryStatus, TenantDelivery
    from defender.learning.author.version_control.forgejo import ForgeAddress

    identity = _login(lab)
    delivery = TenantDelivery.open(lab.tenant, defender_dir=DEFENDER, client=httpx.Client(timeout=30),
                                   identity=identity, origin=lab.forge["origin"])
    delivery = dataclasses.replace(delivery, branch_prefix="live-o12/")
    batch_id = "o12-" + uuid.uuid4().hex[:12]
    name = f"live-o12-probe-{batch_id}"
    batch = delivery.start_batch(batch_id, lanes=("lessons",))
    api = ForgeAddress.parse(lab.forge["origin"]).api
    number = None
    try:
        lesson = batch.draft_root / "agent" / "lessons" / f"{name}.md"
        lesson.write_text(
            f"---\nname: {name}\ndescription: O12 live delivery probe; close without merging.\n"
            "created_at: 2026-10-22T00:00:00Z\n---\n\nProbe.\n", encoding="utf-8")
        change_set = batch.change_set()
        assert [c.path for c in change_set] == [f"agent/lessons/{name}.md"]
        batch.commit(change_set, f"O12 live probe {batch_id}")
        delivered = delivery.finish(batch)
        assert delivered.status == DeliveryStatus.OPENED, delivered
        number = int(str(delivered.url).rstrip("/").rsplit("/", 1)[1])
        pr = httpx.get(f"{api}/pulls/{number}", headers=_bearer(identity), timeout=30).json()
        assert pr["state"] == "open", pr
        assert pr["base"]["ref"] == "main", pr
        assert pr["head"]["ref"] == f"live-o12/{batch_id}"
        files = httpx.get(f"{api}/pulls/{number}/files", headers=_bearer(identity), timeout=30).json()
        assert [f["filename"] for f in files] == [f"agent/lessons/{name}.md"], files
    finally:
        batch.discard()
        if number is not None:
            closed = httpx.patch(f"{api}/pulls/{number}", json={"state": "closed"},
                                 headers=_bearer(identity), timeout=30)
            assert closed.is_success, closed.text
        _delete_branch(lab, identity, f"live-o12/{batch_id}")


# ---------------------------------------------------------------------------------------------
# P-4 / U4 / O8: deployment facts are file-only, never environment, never in the tenant repo
# ---------------------------------------------------------------------------------------------

def test_deployment_facts_are_file_only_and_never_in_the_tenant_repo_P4_U4():
    """P-4: the issuer client config lies under `<repo>/playground-issuer/client/` (dev, U4);
    the tenant row's forge binding is exactly `{origin, audience, issuer_role, issuer_config}`
    (no secret: the config's path, never its content); no
    issuer/forge fact is in this process's environment (the dev container's); and no blob of the
    lab repo's `main` carries the issuer URL, the audience, a certificate or a private key.
    Positive control for the blob scan: it finds the tenant id in `agent/.tenant-id`."""
    lab = _lab()
    client_dir = _main_checkout() / "playground-issuer" / "client"
    assert client_dir in lab.issuer_config.resolve().parents, (
        f"the issuer client config {lab.issuer_config} is not under {client_dir}")
    assert set(lab.forge) == {"origin", "audience", "issuer_role", "issuer_config"}, sorted(lab.forge)
    leaked = sorted(k for k in os.environ
                    if _DEPLOYMENT_FACT.search(k) and not k.startswith(_TEST_ONLY_ENV))
    assert not leaked, f"deployment facts in the environment: {leaked}"
    identity = _login(lab)
    clone = lab.tenant.knowledge
    blobs = committed_blobs(clone, "refs/remotes/origin/main", ".")
    assert lab.tenant_id.encode() in blobs.get("agent/.tenant-id", b""), "control: blobs are read"
    needles = [identity.issuer.encode(), _issuer_base(identity).encode(),
               lab.forge["audience"].encode(), b"BEGIN CERTIFICATE", b"PRIVATE KEY"]
    hits = sorted({(path, n.decode()) for path, data in blobs.items() for n in needles if n in data})
    assert not hits, f"deployment facts in the tenant repo: {hits}"


# ---------------------------------------------------------------------------------------------
# O13: the migration carried the lab repo, its bot and its history (run right after migrating)
# ---------------------------------------------------------------------------------------------

def test_migration_kept_the_lab_repo_bot_history_and_the_old_volume_O13():
    """O13: after the one-time migration from the named volume, the old volume still exists
    (kept until the operator deletes it), the bot authenticates as the same Forgejo user it was,
    and a lab commit made before the migration is an ancestor of the lab's `main`. Run right
    after migrating (the old volume is the operator's to delete later)."""
    lab = _lab()
    old = os.environ.get("DEFENDER_LIVE_O13_OLD_VOLUME")
    commit = os.environ.get("DEFENDER_LIVE_O13_COMMIT")
    bot = os.environ.get("DEFENDER_LIVE_O13_BOT")
    if not (old and commit and bot):
        pytest.skip("set DEFENDER_LIVE_O13_OLD_VOLUME, DEFENDER_LIVE_O13_COMMIT, DEFENDER_LIVE_O13_BOT")
    if not daemon_reachable():
        pytest.skip("needs a reachable docker daemon")
    kept = subprocess.run(["docker", "volume", "inspect", old], capture_output=True, timeout=30,
                          check=False)
    assert kept.returncode == 0, f"the old volume {old} is gone: {kept.stderr!r}"
    import httpx

    from defender.learning.author.version_control.forgejo import ForgeAddress
    from defender.learning.author.version_control.transport import GitTransport

    identity = _login(lab)
    origin = ForgeAddress.parse(lab.forge["origin"]).origin
    me = httpx.get(origin + "/api/v1/user", headers=_bearer(identity), timeout=30)
    me.raise_for_status()
    assert me.json()["login"] == bot
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        _git.git(["init", "-b", "main"], cwd=repo)
        _git.git(["remote", "add", "origin", lab.forge["origin"]], cwd=repo)
        GitTransport(repo, lab.forge["origin"], identity, 30).fetch()
        _git.git(["merge-base", "--is-ancestor", commit, "refs/remotes/origin/main"], cwd=repo)

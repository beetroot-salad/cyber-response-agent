"""#1170 (r4): the per-job host helper (H7), investigation kind. It holds the tenant's lock, admits, publishes, signs,
starts the job's one container and answers the job socket by job kind. Driven in-process through `job_host.main` over a
published, registered tenant (`ProcessHelper`: as a real process, for the case that kills it). The job container is
`ContainerStandIn`: the attached `docker run` runs a test function that sees the container's environment and mounts and
talks to the job socket. What a container can reach from inside is `e2e/test_job_box_boundary_e2e.py`. Every wait is bounded.
Names of the target (`job_host.main`, `ask`, `Refused`, `SOCKET_ENV`, `JOB_LABEL`, `IMAGE_ENV`) are picks, see the support
module's docstring."""
from __future__ import annotations

import inspect
import json
import os
import signal
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

import pytest
from defender.tests.support.jobs._job_helper import (
    ASK_LAUNCH,
    CANARY,
    OTHER_TENANT,
    ContainerStandIn,
    ProcessHelper,
    SignalingSigner,
    after_the_signal,
    claims_of,
    drive_helper,
    flag_values,
    helper_scene,
    listing,
    make_signer,
    parse_labels,
    parse_mounts,
    pid_alive,
    until,
)
from defender.tests.support.jobs import _job_helper as J

# The shared fixtures (`_job_helper`'s docs): `process_state` is autouse, `scene` the default helper scene.
process_state = J.process_state
scene = J.scene

pytestmark = [pytest.mark.postgres, pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="reads /proc and uses prctl(PR_SET_PDEATHSIG), Linux only")]

#: The dev run page's publish folder: one host folder shared by every tenant (A10), so not for the job container.
PUBLISH_ENV = "DEFENDER_RUN_VISUALIZATIONS_DIR"

#: Secrets and cross-tenant addresses a host process may hold, each with a value that must not reach the container.
_SECRETS = {"DEFENDER_DATABASE_DSN": None, "PGPASSWORD": "pg-secret-1170", "VAULT_ADDR": "https://vault.invalid:8200",
            "VAULT_TOKEN": "vault-token-1170", "BAO_ADDR": "https://bao.invalid:8200", "BAO_TOKEN": "bao-token-1170",
            "DEFENDER_LIFECYCLE_OPENBAO_LOGIN_FILE": "/run/secrets/openbao-login-1170",
            "DEFENDER_LIFECYCLE_FORGE_ADMIN_TOKEN_FILE": "/run/secrets/forge-admin-1170"}


def _investigation(scene) -> tuple[str, list[str]]:
    inv = str(uuid.uuid4())
    scene.plant(inv)
    return inv, scene.argv("investigation", inv)


def _go(scene, job=None, *, docker=None, signer=None, **seams):
    """One investigation helper run: `(inv, docker, ran, signer)`; the helper raised nothing and the job (if any) no error."""
    inv, argv = _investigation(scene)
    signer = signer or make_signer()
    docker = docker or ContainerStandIn(job)
    ran = drive_helper(scene, argv, docker=docker, signer=signer, **seams)
    assert ran.raised is None, ran.raised
    assert docker.job_error is None, docker.job_error
    return inv, docker, ran, signer


# --- the main flow ------------------------------------------------------------------------------------------------

def test_claim_flow_the_helper_starts_one_labelled_container_serves_it_and_cleans_up_once_it_exits(scene):
    """Lock, publish, one container labelled with tenant, claim and job, served until it exits; then removed by label,
    the lock free, and the job's own end record left as the job wrote it. (Flow: claim, H3, A3, A5, Design 1-8)"""
    from defender import job_host
    from defender.box import CLAIM_LABEL, TENANT_LABEL
    from defender.tenancy import host_lock

    seen: dict = {}
    inv, argv = _investigation(scene)

    def job(c) -> int:
        seen["holders"] = [h.pid for h in host_lock.holders(scene.root, scene.tenant)]
        seen["launch"] = c.request("launch")
        (scene.runs / f"{inv}.job-end.json").write_text('{"written": "by the job"}', encoding="utf-8")
        return 0

    docker = ContainerStandIn(job)
    ran = drive_helper(scene, argv, docker=docker, signer=make_signer())

    assert ran.raised is None, ran.raised
    assert docker.job_error is None, docker.job_error
    assert ran.rc == 0
    assert ran.publishes == 1, "the helper ran no launch-time publish"
    assert docker.box.labels[TENANT_LABEL] == scene.tenant
    assert docker.box.labels[CLAIM_LABEL] == scene.claim
    assert job_host.JOB_LABEL in docker.box.labels, "the container carries no job-container label (A5)"
    assert seen["holders"] == [os.getpid()], "the helper did not hold the tenant's lock as a recorded holder"
    assert seen["launch"]["export_commit"] == scene.t.commit
    assert docker.left(CLAIM_LABEL, scene.claim) == [], "the job's containers outlived the helper"
    assert (scene.runs / f"{inv}.job-end.json").read_text(encoding="utf-8") == '{"written": "by the job"}'
    assert [h.pid for h in host_lock.holders(scene.root, scene.tenant)] == []
    fd = host_lock.acquire(scene.root, scene.tenant, exclusive=True, timeout=0)
    assert fd is not None, "the helper kept the tenant's lock after it exited"
    host_lock.release_lock(fd)


# --- O1-O4, A7-A8, H9: what the container is given ------------------------------------------------------------------

def test_o1_the_job_container_mounts_its_tenants_folder_the_code_read_only_and_its_socket_and_nothing_else(
        scene, monkeypatch):
    """Exactly three binds: `<root>/<T>` read-write at the same path, one read-only code tree, the job socket; none of
    another tenant, `.host-locks`, host /tmp, the docker socket or a secret file; the image is the one the setting names.
    (O1, O2, A7)"""
    from defender import job_host

    monkeypatch.setenv(job_host.IMAGE_ENV, "registry.invalid/defender-job:1170")
    _inv, docker, ran, _s = _go(scene, lambda c: 0)

    assert ran.rc == 0
    box = docker.box
    own = str(scene.root / scene.tenant)
    assert {"source": own, "target": own, "readonly": False} in box.mounts, box.mounts
    binds = [m for m in box.mounts if m["source"]]  # a tmpfs names no source
    rest = [m for m in binds if m["source"] != own]
    assert len(rest) == 2, box.mounts
    sockets = [m for m in rest if Path(box.env[job_host.SOCKET_ENV]).is_relative_to(m["target"])]
    assert len(sockets) == 1, (rest, box.env)
    (code,) = [m for m in rest if m is not sockets[0]]
    assert code["readonly"], f"the code tree is mounted writable: {code}"
    for m in binds:
        source = Path(m["source"])
        assert not source.is_relative_to(scene.root / OTHER_TENANT), m
        assert ".host-locks" not in source.parts, m
        assert str(source) != "/tmp", m
        assert not str(source).startswith("/tmp/defender-oracle"), m
        assert not str(source).endswith("docker.sock"), m
        assert not any(s.is_relative_to(source) for s in scene.secrets), f"{m} exposes a secret file"
        assert not (scene.root / OTHER_TENANT).is_relative_to(source), f"{m} covers another tenant's folder"
    for flag in ("-v", "--volume", "--volumes-from", "--privileged", "--env-file"):
        assert flag not in box.argv, f"the job container's start carries {flag}"
    assert "registry.invalid/defender-job:1170" in box.argv, "the image is not the one the setting names"


#: The job container's `docker run` flags that take a value (every other flag before the image is bare).
_VALUED = frozenset({"--name", "--user", "--label", "--runtime", "--tmpfs", "--security-opt", "--cap-drop", "--network",
                     "--mount", "--workdir", "--env"})
#: Each flag the job container may carry before its image, with how many times: exactly these and no other (O1, A7, H9;
#: `--network` only when the deployment names one, `--env` once per setting).
_FLAG_COUNTS = {"-i": 1, "--rm": 1, "--init": 1, "--name": 1, "--user": 1, "--label": 3, "--pull=never": 1,
                "--runtime": 1, "--read-only": 1, "--tmpfs": 1, "--security-opt": 1, "--cap-drop": 1, "--mount": 3,
                "--workdir": 1}


def _run_flags(argv: list[str], image: str) -> list[tuple[str, str | None]]:
    """`docker run`'s `(flag, value)` pairs up to `image`, which must be the first word that is neither a flag nor a
    flag's value."""
    assert argv[:2] == ["docker", "run"], argv[:2]
    pairs, i = [], 2
    while i < len(argv) and argv[i].startswith("-"):
        if argv[i] in _VALUED:
            pairs.append((argv[i], argv[i + 1]))
            i += 2
        else:
            pairs.append((argv[i], None))
            i += 1
    assert i < len(argv), f"no image after the flags: {argv}"
    assert argv[i] == image, f"the first word past the flags is {argv[i]}, not the image {image}"
    return pairs


def test_o1_the_job_containers_start_carries_exactly_the_allowed_flags_with_the_box_runtime_and_its_hardening(
        scene, monkeypatch):
    """Before the image, the job container's `docker run` carries exactly `-i --rm --init --name --user`, three
    `--label`s, `--pull=never`, `--runtime` the box runtime the deployment sets, `--read-only`, one `--tmpfs`,
    `--security-opt no-new-privileges`, `--cap-drop ALL`, at most one `--network` (the job network, N5), three
    `--mount`s, `--workdir` and `--env`s: nothing else (`--pid host`, `--privileged`, `--cap-add`, `-v`, a second
    runtime). (O1, A7, H9, N5)"""
    from defender import job_host
    from defender.box import BoxSpec

    monkeypatch.setenv(job_host.IMAGE_ENV, "registry.invalid/defender-job:1170")
    runtime = BoxSpec.from_env(os.environ).runtime
    _inv, docker, _ran, _s = _go(scene, lambda c: 0)

    pairs = _run_flags(docker.box.argv, "registry.invalid/defender-job:1170")
    counts: dict[str, int] = {}
    for flag, _value in pairs:
        counts[flag] = counts.get(flag, 0) + 1
    envs, networks = counts.pop("--env", 0), counts.pop("--network", 0)
    assert counts == _FLAG_COUNTS, {k: (counts.get(k), _FLAG_COUNTS.get(k)) for k in set(counts) | set(_FLAG_COUNTS)
                                    if counts.get(k) != _FLAG_COUNTS.get(k)}
    assert envs >= 1, "the job container carries no setting"
    assert networks <= 1, "the job container joins more than one network"
    values = dict(p for p in pairs if p[0] not in ("--label", "--mount", "--env"))
    assert values["--runtime"] == runtime, (values["--runtime"], runtime)
    assert values["--security-opt"] == "no-new-privileges"
    assert values["--cap-drop"] == "ALL"
    assert values["--name"] == docker.box.name


def test_a7_the_code_mounted_is_read_only_at_the_same_path_and_holds_no_env_file(scene):
    """The one code bind is read-only, its source and target the same path, and the tree holds no `.env`. (A7; that it is
    the worker's code copy is the worker-lane composition's, `e2e/test_job_box_boundary_e2e.py`)"""
    own = str(scene.root / scene.tenant)
    _inv, docker, _ran, _s = _go(scene, lambda c: 0)

    (code,) = [m for m in docker.box.mounts if m["source"] and m["source"] != own and m["readonly"]]
    assert code["source"] == code["target"], code
    assert not list(Path(code["source"]).glob(".env")), "the mounted code tree holds an env file"


def test_h9_the_job_container_runs_as_the_uid_that_owns_the_data_root(scene):
    """`docker run --user` names the data root owner's uid (made a uid the test process lacks, when it may chown).
    (H9, O1)"""
    if os.geteuid() == 0:
        os.chown(scene.root, 4242, 4242)
    owner = os.stat(scene.root).st_uid
    _inv, docker, _ran, _s = _go(scene, lambda c: 0)

    (user,) = flag_values(docker.box.argv, "--user", "-u")
    assert user.partition(":")[0] == str(owner), (user, owner)


def test_h9_the_job_socket_lives_in_a_0700_folder_under_the_data_root_outside_every_tenant_folder_and_tmp(scene):
    """The folder holding the socket is under `<root>/` (so not the shared /tmp) and in no tenant's folder, mode 0700; the socket is
    0600; and it answers (control). (H9)"""
    got: dict = {}

    def job(c) -> int:
        sock = c.socket()
        got["launch"] = c.request("launch")
        got["folder"], got["folder_mode"] = sock.parent, sock.parent.stat().st_mode & 0o777
        got["mode"] = sock.stat().st_mode & 0o777
        return 0

    _go(scene, job)

    assert got["launch"]["export_commit"] == scene.t.commit
    folder = got["folder"].resolve()
    assert folder.is_relative_to(scene.root.resolve()), folder
    assert folder != scene.root.resolve(), folder
    for tenant in (scene.tenant, OTHER_TENANT):
        assert not folder.is_relative_to((scene.root / tenant).resolve()), f"the socket folder is inside {tenant}'s folder"
    assert folder.parent != Path("/tmp"), folder  # (the scene's data root is itself a short folder under /tmp)
    assert (got["folder_mode"], got["mode"]) == (0o700, 0o600)


def test_h9_a_peer_that_is_not_one_of_the_containers_processes_is_refused(scene, tmp_path):
    """A process the container's init started gets `launch` answered; a process of the same uid started outside the
    container gets nothing. (H9; peer check against the container's processes)"""
    got: dict = {}

    def job(c) -> int:
        sock = str(c.socket())
        got["inside"] = json.loads(c.client(ASK_LAUNCH, sock))
        got["outside"] = json.loads(c.foreign(ASK_LAUNCH, sock))
        return 0

    _go(scene, docker=ContainerStandIn(job, init=True, queue=tmp_path / "init"))

    assert got["inside"]["ok"]["export_commit"] == scene.t.commit, got["inside"]
    assert "ok" not in got["outside"], f"a process outside the container was answered: {got['outside']}"


class _NoProcessList(ContainerStandIn):
    """A daemon that cannot list the job container's processes (its init's pid and `top` both fail)."""

    def _process_question(self, argv, sub):  # noqa: ANN001
        if any(b.name in argv for b in self.boxes) and (sub == "top" or (
                sub == "inspect" and any("State.Pid" in a for a in argv))):
            self.calls.append(argv)
            return subprocess.CompletedProcess(argv, 1, "", "Error response from daemon: cannot list processes\n")
        return super()._process_question(argv, sub)


def test_h9_with_no_process_list_from_the_daemon_a_foreign_peer_is_still_refused(scene):
    """The peer check fails closed: when the daemon answers no list of the container's processes, a process of the same
    uid outside the container gets no answer. (H9; the answered case is `test_h9_a_peer_that_is_not_one_of...`)"""
    got: dict = {}

    def job(c) -> int:
        got["outside"] = json.loads(c.foreign(ASK_LAUNCH, str(c.socket())))
        return 0

    docker = _NoProcessList(job)
    _go(scene, docker=docker)

    assert any(c[1:2] in (["top"], ["inspect"]) and docker.box.name in c for c in docker.calls), \
        "control: the helper asked the daemon for the container's processes"
    assert "ok" not in got["outside"], f"a process outside the container was answered: {got['outside']}"


def test_h9_a_message_announcing_a_body_past_any_limit_is_refused_without_waiting_for_the_body(scene):
    """A peer sends only a length header announcing a 4 GiB body: the helper answers or closes at once, never waiting
    to read (or buffer) the body; the socket goes on answering a well-formed `launch` (control). (H9, O10: the job
    cannot make its helper hold unbounded input)"""
    import socket as socket_mod
    import struct

    got: dict = {}

    def job(c) -> int:
        conn = socket_mod.socket(socket_mod.AF_UNIX, socket_mod.SOCK_STREAM)
        conn.settimeout(10)
        try:
            conn.connect(str(c.socket()))
            started = time.monotonic()
            conn.sendall(struct.pack(">I", 0xFFFFFFFF))
            try:
                conn.recv(65536)  # a refusal frame, or b"" once the helper closes
                got["took"] = time.monotonic() - started
            except TimeoutError:
                got["took"] = None
        finally:
            conn.close()
        got["launch"] = c.request("launch")
        return 0

    _go(scene, job)

    assert got["launch"]["export_commit"] == scene.t.commit, "control: the socket answers a well-formed request"
    assert got["took"] is not None, "the helper never answered: it waited on the announced body"
    assert got["took"] < 5, f"the helper waited on the announced body: {got['took']}"


def test_a8_the_environment_is_every_setting_the_job_reads_minus_secrets_and_cross_tenant_addresses(scene, monkeypatch):
    """Deployment and model settings arrive with their values; the publish folder's setting (one host folder shared by
    every tenant, a cross-tenant address) does not, though the helper's environment holds it; no database address, OpenBao
    or vault address or token, secret-file path or login; no value carries one; every variable has a value; proxy, claim
    and socket are there. (A8 as corrected by A10, O3, O4)"""
    from defender import job_host
    from defender.box import CLAIM_ENV
    from defender.configuration.issuer import DEPLOYMENT_ISSUER
    from defender.kit.access import PROXY_URL_ENV

    settings = {"DEFENDER_DEPLOYMENT": "dev", "DEFENDER_MODEL": "model-1170"}
    for k, v in settings.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setenv(PUBLISH_ENV, str(scene.root / "published"))
    assert os.environ[PUBLISH_ENV], "premise: the helper's own environment holds the publish folder setting"
    secrets = {k: v for k, v in _SECRETS.items() if v is not None}
    for k, v in secrets.items():
        monkeypatch.setenv(k, v)
    assert os.environ["DEFENDER_DATABASE_DSN"] == scene.dsn, "premise: the helper holds the database address"
    _inv, docker, _ran, _s = _go(scene, lambda c: 0)

    env = docker.box.env
    assert all(v is not None for v in env.values()), f"inherited variables: {[k for k, v in env.items() if v is None]}"
    for k, v in settings.items():
        assert env.get(k) == v, f"{k} did not reach the job"
    assert PUBLISH_ENV not in env, "the cross-tenant publish folder's setting reached the job container (A10)"
    assert not (set(_SECRETS) & set(env)), set(_SECRETS) & set(env)
    for k, v in env.items():
        assert scene.dsn not in v, k
        assert "postgresql://" not in v, k
        assert DEPLOYMENT_ISSUER.openbao_url not in v, k
        assert not any(str(s) in v for s in scene.secrets), k
        assert not any(sv in v for sv in secrets.values()), k
        assert str(scene.root / "published") not in v, k
    assert env[PROXY_URL_ENV] == "http://proxy.invalid"
    assert env[CLAIM_ENV] == scene.claim
    assert job_host.SOCKET_ENV in env


#: A `DEFENDER_` setting per secret class a name marks (A8): each must stay out of the job container.
_SECRET_NAMED = {f"DEFENDER_X1170_{word}": f"value-of-{word.lower()}-1170" for word in (
    "SECRET", "PASSWORD", "PRIVATE", "VAULT", "TOKEN", "LOGIN", "OPENBAO", "DSN")} | {
    "DEFENDER_X1170_CERT_FILE": "/run/secrets/x1170", "DEFENDER_X1170_SIGNING_KEY": "key-material-1170"}


def test_a8_a_defender_setting_named_as_a_secret_or_carrying_an_address_never_reaches_the_container(scene, monkeypatch):
    """`DEFENDER_` settings whose name marks a secret, a vault, OpenBao, a login or a database address, or ends `_FILE` or
    `_KEY`, are kept out; so is a setting with an innocent name whose value embeds the helper's database address,
    OpenBao's address or the shared publish folder. Control: an innocent setting with an innocent value arrives. (A8, A10,
    O3, O4)"""
    from defender.configuration.issuer import DEPLOYMENT_ISSUER

    published = scene.root / "published"
    monkeypatch.setenv(PUBLISH_ENV, str(published))
    for k, v in _SECRET_NAMED.items():
        monkeypatch.setenv(k, v)
    carriers = {"DEFENDER_X1170_DATABASE": f"see {scene.dsn} for rows",
                "DEFENDER_X1170_ISSUER": f"via {DEPLOYMENT_ISSUER.openbao_url}/v1",
                "DEFENDER_X1170_PAGES": f"{published}/pages"}
    for k, v in carriers.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setenv("DEFENDER_X1170_PLAIN", "plain-1170")
    _inv, docker, _ran, _s = _go(scene, lambda c: 0)

    env = docker.box.env
    assert env.get("DEFENDER_X1170_PLAIN") == "plain-1170", "control: an innocent setting did not reach the job"
    assert sorted(set(_SECRET_NAMED) & set(env)) == [], "a setting named as a secret reached the job container"
    assert sorted(set(carriers) & set(env)) == [], "a setting whose value carries an address reached the job container"
    for k, v in env.items():
        assert not any(secret in (v or "") for secret in _SECRET_NAMED.values()), k


def test_n2_the_provider_key_the_helper_resolved_reaches_the_container_environment_and_no_env_file_is_mounted(
        scene, monkeypatch, tmp_path):
    """The key `resolve_first_party_key` reads from `DEFENDER_ENV_FILE` (the helper's environment holds none) is the
    container's `ANTHROPIC_API_KEY`, and the file it came from is under no mount. (N2, A8, A7)"""
    keys = tmp_path / "keys"
    keys.mkdir()
    env_file = keys / ".env"
    env_file.write_text("ANTHROPIC_API_KEY=sk-ant-test-1170\n", encoding="utf-8")
    monkeypatch.setenv("DEFENDER_ENV_FILE", str(env_file))
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    _inv, docker, _ran, _s = _go(scene, lambda c: 0)

    assert docker.box.env.get("ANTHROPIC_API_KEY") == "sk-ant-test-1170", "the resolved provider key did not reach the job"
    sources = [Path(m["source"]) for m in docker.box.mounts if m["source"]]
    assert sources, "premise: the container has mounts"
    assert not any(env_file.is_relative_to(src) for src in sources), "the env file's folder is mounted"
    assert not any((src / ".env").exists() for src in sources), "a mounted folder holds a .env"


# --- O5, O6, A1, A6: passes and ids ---------------------------------------------------------------------------------

def test_o5_a_pass_names_the_tenant_the_investigation_the_proxied_grant_and_a_600_second_expiry(scene):
    """The first pass is signed before the container starts; the one the job asks for decodes to exactly the tenant, the
    investigation, `identity` read and an expiry of one pass lifetime; no `rw` entry. (O5, H2)"""
    from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A

    inv, argv = _investigation(scene)
    signer = make_signer()
    got: dict = {}

    def job(c) -> int:
        got["signed_before_start"] = len(signer.payloads)
        got["asked_at"] = time.time()
        got["token"] = c.request("pass", id=inv)["token"]
        return 0

    docker = ContainerStandIn(job)
    ran = drive_helper(scene, argv, docker=docker, signer=signer)

    assert ran.raised is None, ran.raised
    assert docker.job_error is None, docker.job_error
    assert got["signed_before_start"] >= 1, "no pass was signed at claim"
    claims = claims_of(signer, got["token"])
    assert claims["tenant"] == scene.tenant
    assert claims["investigation"] == inv
    assert A.grant_of(claims) == [("identity", "r")]
    assert 590 <= claims["exp"] - got["asked_at"] <= 601, claims["exp"] - got["asked_at"]
    assert all(m != "rw" for p in signer.payloads for _s, m in A.claims_of_payload(p)["grant"])


def _ticket_ungranted() -> str:
    """The fixture's verb table with every `ticket` row granted to gather withheld (so `ticket` is granted to nobody)."""
    return _ungranted("ticket")


def _ungranted(system: str) -> str:
    """The fixture's verb table with every `system` row granted to gather withheld (so `system` is granted to nobody)."""
    import re

    from defender.tests.support.tenancy._tenants1106 import FIXTURE

    table = (FIXTURE / "settings" / "verb-grants.yaml").read_text(encoding="utf-8")
    head, found, rest = table.partition(f"\n  {system}:\n")
    assert found, f"premise: the fixture's verb table has a {system} section"
    following = re.search(r"\n  [a-z][a-z-]*:\n", rest)
    block, tail = (rest[:following.start()], rest[following.start():]) if following else (rest, "")
    withheld = block.replace("{roles: [gather]}", "{roles: [], reason: \"withheld for #1170's grant case\"}")
    assert withheld != block, f"premise: the fixture grants some {system} verb to gather"
    return head + found + withheld + tail


def test_o5_a_pass_is_the_helpers_alone_granted_and_proxied_systems_only_its_expiry_and_proxy_as_answered(
        tmp_path, monkeypatch, migrated_database):
    """Three systems: `identity` granted and proxied, `cmdb` granted and not proxied, `ticket` proxied and granted to
    nobody. A `pass` carrying anything beyond its id (a grant, a lifetime, any other field) is refused `bad-fields` and
    signs nothing; the plain `pass` decodes to the tenant, the job's id, exactly `identity` read and an expiry one pass
    lifetime from now; the answer's `expires_at` is the token's expiry and its `proxy_url` the configured proxy, which
    `launch` names too, with the same grant. (O5, H2, A6)"""
    from defender.kit.access import PROXY_URL_ENV
    from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A

    with helper_scene(tmp_path, monkeypatch, migrated_database, proxied=("identity", "ticket"),
                      files={"settings/verb-grants.yaml": _ticket_ungranted()}) as three:
        inv, argv = _investigation(three)
        signer = make_signer()
        got: dict = {}

        def job(c) -> int:
            got["launch"] = c.request("launch")
            before = len(signer.payloads)
            got["refused"] = [c.refused("pass", id=inv, **extra).code for extra in (
                {"grant": [["identity", "rw"]]}, {"grant": [["ticket", "r"], ["cmdb", "r"]]}, {"lifetime": 86400},
                {"note": "anything"})]
            got["signed_by_refusals"] = len(signer.payloads) - before
            got["asked_at"] = time.time()
            got["answer"] = c.request("pass", id=inv)
            return 0

        docker = ContainerStandIn(job)
        ran = drive_helper(three, argv, docker=docker, signer=signer)

        assert ran.raised is None, ran.raised
        assert docker.job_error is None, docker.job_error
        assert got["refused"] == ["bad-fields"] * 4, got["refused"]
        assert got["signed_by_refusals"] == 0, "a refused pass was signed"
        answer, launch = got["answer"], got["launch"]
        claims = claims_of(signer, answer["token"])
        assert claims["tenant"] == three.tenant
        assert claims["investigation"] == inv
        assert A.grant_of(claims) == [("identity", "r")], A.grant_of(claims)
        assert 590 <= claims["exp"] - got["asked_at"] <= 601, claims["exp"] - got["asked_at"]
        assert abs(float(answer["expires_at"]) - claims["exp"]) <= 1, (answer["expires_at"], claims["exp"])
        assert answer["proxy_url"] == launch["proxy_url"] == os.environ[PROXY_URL_ENV], (answer, launch)
        assert sorted(tuple(g) for g in launch["grant"]) == A.grant_of(claims), launch["grant"]


def test_o6_a_job_holding_the_row_gets_a_fresh_pass_each_time_it_asks(scene):
    """While the helper serves, each `pass` is signed anew for the same investigation: two asks, two distinct tokens, the
    second's expiry no earlier. (O6 refresh while held)"""
    inv, argv = _investigation(scene)
    signer = make_signer()
    got: dict = {}

    def job(c) -> int:
        got["first"], got["second"] = (c.request("pass", id=inv)["token"] for _ in range(2))
        return 0

    docker = ContainerStandIn(job)
    ran = drive_helper(scene, argv, docker=docker, signer=signer)

    assert ran.raised is None, ran.raised
    assert docker.job_error is None, docker.job_error
    assert got["first"] != got["second"]
    first, second = claims_of(signer, got["first"]), claims_of(signer, got["second"])
    assert second["investigation"] == first["investigation"] == inv
    assert second["exp"] >= first["exp"]




def test_o6_a_job_holding_the_row_still_gets_fresh_passes_while_the_database_is_in_an_outage(
        tmp_path, monkeypatch, migrated_database):
    """The scene's database login goes through a relay the test owns; cut mid-job, the login's own address refuses, and
    `pass` is still answered, signed anew for the same investigation. (O6: during an outage passes keep coming; control: the ask before)"""
    from defender.tests.support.shared._postgres1339 import execute

    relay = J.TcpRelay(migrated_database)
    try:
        with helper_scene(tmp_path, monkeypatch, relay.dsn) as scene:
            inv, argv = _investigation(scene)
            signer = make_signer()
            got: dict = {}

            def job(c) -> int:
                got["before"] = c.request("pass", id=inv)["token"]
                got["reached_before"] = execute(scene.dsn, "SELECT 1")
                relay.cut()
                try:
                    execute(scene.dsn, "SELECT 1")
                except Exception as refused:  # noqa: BLE001 — any driver refusal: the premise is a real outage
                    got["refused"] = refused
                got["during"] = [c.request("pass", id=inv)["token"] for _ in range(2)]
                return 0

            docker = ContainerStandIn(job)
            ran = drive_helper(scene, argv, docker=docker, signer=signer)
    finally:
        relay.cut()

    assert ran.raised is None, ran.raised
    assert docker.job_error is None, docker.job_error
    assert "reached_before" in got, "control: the login reached the database through the relay before the cut"
    assert "refused" in got, "premise: the scene's own database address refuses once the relay is cut"
    assert len({got["before"], *got["during"]}) == 3, "a pass during the outage was not signed anew"
    assert [claims_of(signer, t)["investigation"] for t in got["during"]] == [inv, inv]


def test_o5_a_publish_between_the_claim_and_a_later_pass_leaves_the_jobs_export_commit_and_grant_unchanged(scene):
    """A tenant publish that lands after the claim (a merge that takes the proxied grant away) changes what the tenant
    exports, but `launch` and a later `pass` still carry the commit and grant the job was claimed with. (O5)"""
    from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A

    inv, argv = _investigation(scene)
    signer = make_signer()
    got: dict = {}

    def job(c) -> int:
        got["first"] = A.grant_of(claims_of(signer, c.request("pass", id=inv)["token"]))
        scene.t.merge({"settings/verb-grants.yaml": _ungranted("identity")})
        got["published"] = scene.t.publish().commit
        got["launch"] = c.request("launch")
        got["later"] = A.grant_of(claims_of(signer, c.request("pass", id=inv)["token"]))
        return 0

    docker = ContainerStandIn(job)
    ran = drive_helper(scene, argv, docker=docker, signer=signer)

    assert ran.raised is None, ran.raised
    assert docker.job_error is None, docker.job_error
    assert got["published"] != scene.t.commit, "premise: the publish exported a new commit"
    assert got["first"] == [("identity", "r")]
    assert got["launch"]["export_commit"] == scene.t.commit
    assert got["later"] == got["first"]


@pytest.mark.parametrize("root_pad", [0, 110], ids=["control-short-root", "deep-root"])
def test_a3_a_job_socket_path_that_cannot_fit_a_unix_socket_ends_the_row_as_a_box_start_failure(
        tmp_path, monkeypatch, migrated_database, root_pad):
    """A data root so deep that the per-claim socket path overruns a unix socket's limit: no container is started and the
    end record says `box: start_failed`, not `setup: refused`. (r4.1 socket note, A3; control: a short root starts one.
    One scene per case: the fixture tenant registers once per database.)"""
    from defender.records.job_facts import BOX_START_FAILED, SETUP_REFUSED

    with helper_scene(tmp_path, monkeypatch, migrated_database, root_pad=root_pad) as deep:
        if not root_pad:
            _inv, docker, _ran, _s = _go(deep, lambda c: 0)
            assert len(docker.boxes) == 1, "control: the short-root scene starts its container"
            return
        assert len(str(deep.root / "x" / "job.sock")) > 108, "premise: the socket path cannot fit"
        inv, argv = _investigation(deep)
        docker = ContainerStandIn(lambda c: 0)
        ran = drive_helper(deep, argv, docker=docker, signer=make_signer())

        assert ran.raised is None, ran.raised
        assert docker.boxes == [], "a container was started with no socket to serve it"
        assert docker.creates() == []
        end = deep.end(inv)
        assert end is not None
        assert end.box == BOX_START_FAILED, end
        assert end.setup != SETUP_REFUSED


@pytest.mark.parametrize(("kind", "request_name", "fields"), [
    ("investigation", "pass", {"id": "<job>"}),
    ("investigation", "box.start", {"kind": "shell", "id": "<job>"}),
])
def test_a1_once_the_helper_is_signalled_it_refuses_passes_and_box_starts(
        scene, kind, request_name, fields):
    """Answered before SIGTERM (fence, stop and teardown all arrive so); after it the helper stops the container and refuses
    the same request, signing and creating nothing more; `copy.make` and `batch.start` refusals are the learning slice's. (A1, O6, O8)"""
    got = after_the_signal(scene, kind, request_name, fields)

    assert got["control"], "control: the request was answered before the signal"
    assert got["refusal"] is not None
    assert got["after"] == got["before"], "a pass was signed, a box created or a copy or draft made after the signal"


def test_a1_after_the_signal_launch_box_exec_and_box_stop_are_still_answered_during_the_graceful_stop(scene):
    """The job unwinding under the graceful stop still gets `launch`, a command's result and the box's stop proof.
    (A1; control: the same asks before the signal)"""
    from defender.tests.e2e._box665 import framed

    reply = framed(0, b"unwound").stdout
    writer = [sys.executable, "-c", f"import sys; sys.stdout.buffer.write(bytes.fromhex('{reply.hex()}'))"]
    got: dict = {}
    inv, argv = _investigation(scene)

    def job(c) -> int:
        handle = c.request("box.start", kind="shell", id=inv)["handle"]
        got["before"] = c.request("box.exec", handle=handle, frame=b"{}")
        os.kill(os.getpid(), signal.SIGTERM)
        assert c.stopping.wait(15), "the helper never stopped the container"
        got["launch"] = c.request("launch")
        got["exec"] = c.request("box.exec", handle=handle, frame=b"{}")
        got["stop"] = c.request("box.stop", handle=handle)
        return 143

    docker = ContainerStandIn(job, exec_writer=writer)
    ran = drive_helper(scene, argv, docker=docker, signer=make_signer())

    assert ran.raised is None, ran.raised
    assert docker.job_error is None, docker.job_error
    assert got["before"]["result"] == "ok"
    assert got["launch"]["export_commit"] == scene.t.commit
    assert got["exec"]["result"] == "ok", got["exec"]
    assert got["stop"], "box.stop was not answered during the graceful stop"


def test_a1_a_helper_signalled_before_it_starts_the_container_starts_none_and_ends_the_row_as_a_start_failure(scene):
    """SIGTERM lands during the first pass' signing: no `docker run`, and the end record says the box could not start.
    (A1, A3; control: claim flow starts exactly one)"""
    from defender.records.job_facts import BOX_START_FAILED, SETUP_REFUSED

    inv, argv = _investigation(scene)
    docker = ContainerStandIn(lambda c: 0)
    signer = SignalingSigner(make_signer())
    ran = drive_helper(scene, argv, docker=docker, signer=signer)

    assert ran.raised is None, ran.raised
    assert signer.sent, "premise: the signal was sent"
    assert docker.boxes == [], "a container was started after the signal"
    assert docker.creates() == []
    end = scene.end(inv)
    assert end is not None
    assert end.box == BOX_START_FAILED, end
    assert end.setup != SETUP_REFUSED


def test_a6_pass_and_box_start_name_only_ids_the_helper_minted_for_this_claim(scene):
    """The investigation's own id is answered for `pass` and `box.start`; an id the helper did not mint, and a host path in
    its place, are refused, signing and creating nothing. (A6, O9)"""
    inv, argv = _investigation(scene)
    foreign = [str(uuid.uuid4()), str(scene.root / OTHER_TENANT / "runs"), "../" + OTHER_TENANT]
    signer, got = make_signer(), {}

    def job(c) -> int:
        got["pass"] = c.request("pass", id=inv)
        got["box"] = c.request("box.start", kind="shell", id=inv)
        got["state"] = (len(signer.payloads), len(docker.creates()))
        got["refusals"] = [c.refused(r, kind="shell", id=other) for r in ("pass", "box.start") for other in foreign]
        got["after"] = (len(signer.payloads), len(docker.creates()))
        return 0

    docker = ContainerStandIn(job)
    ran = drive_helper(scene, argv, docker=docker, signer=signer)

    assert ran.raised is None, ran.raised
    assert docker.job_error is None, docker.job_error
    assert got["pass"], "control: the helper's own id was refused for pass"
    assert got["box"], "control: the helper's own id was refused for box.start"
    assert len(got["refusals"]) == 2 * len(foreign)
    assert got["after"] == got["state"], "an id the helper did not mint signed a pass or created a box"


def _tree(root: Path) -> dict[str, str]:
    """Every path under `root` (links not followed), relative, with its type: what a run left on the data root."""
    out = {}
    for path in sorted(root.rglob("*")):
        out[str(path.relative_to(root))] = "link" if path.is_symlink() else "dir" if path.is_dir() else "file"
    return out


def test_a6_h9_a_helper_run_leaves_on_the_data_root_only_its_run_folder_its_records_and_the_empty_socket_parent(scene):
    """The data root after a helper's run, against before it: what was added is the run folder `<T>/runs/<inv>/` and what
    the job wrote in it, the run's records beside it (`<T>/runs/<inv>.*`) and the shared socket parent `.job-sockets/`,
    empty (the claim's socket folder is gone, so no later claim finds one), beside the tenant lock's own files (no holder
    left) and the empty run-copy parent; nothing was removed. (A6, H9)"""
    inv, argv = _investigation(scene)
    tenant_runs = (scene.runs).relative_to(scene.root)
    before = _tree(scene.root)

    def job(c) -> int:
        (scene.runs / inv / "report.md").write_text("the report", encoding="utf-8")
        return 0

    docker = ContainerStandIn(job)
    ran = drive_helper(scene, argv, docker=docker, signer=make_signer())
    after = _tree(scene.root)

    assert ran.raised is None, ran.raised
    assert docker.job_error is None, docker.job_error
    assert sorted(set(before) - set(after)) == [], "the helper removed what it did not make"
    added = {p: kind for p, kind in after.items() if p not in before}
    assert added.get(".job-sockets") == "dir", f"control: the shared socket parent was made: {sorted(added)}"
    run = str(tenant_runs / inv)
    # #1214's own: the tenant's lock file and its holder folder, left with no holder recorded; the run copies' parent,
    # left empty (the copy itself is gone).
    locks = f".host-locks/{scene.tenant}"
    owned = {".host-locks", locks, f"{locks}/lock", f"{locks}/processes", f"{scene.tenant}/run-knowledge"}
    assert listing(scene.root / locks / "processes") == [], "a holder record outlived the helper"
    assert listing(scene.root / scene.tenant / "run-knowledge") == [], "a run copy outlived the helper"
    stray = sorted(p for p in added if p != ".job-sockets" and p not in owned and p != run
                   and not p.startswith(run + "/") and not (p.startswith(run + ".") and "/" not in p[len(run):]))
    assert stray == [], f"the helper left behind more than the run folder, its records and the socket parent: {stray}"
    assert added[run] == "dir"
    assert all(kind != "link" for kind in added.values()), added


def test_a6_the_helper_makes_the_run_folder_and_the_run_copy_owned_by_itself_and_removes_the_copy_at_the_end(scene):
    """Before the container runs: `<T>/runs/<inv>/` exists and `<T>/run-knowledge/<inv>/` is a copy whose owner is the helper's
    process. After: the copy is gone and what the job wrote in the run folder stays. (A6, C20)"""
    from defender.tests.tenancy.tenant_1108_p4._drain_support import owner_record

    inv, argv = _investigation(scene)
    copy, run = scene.root / scene.tenant / "run-knowledge" / inv, scene.runs / inv
    got: dict = {}

    def job(c) -> int:
        got["run_folder"], got["owner"] = run.is_dir(), owner_record(copy)["pid"]
        (run / "report.md").write_text("the report", encoding="utf-8")
        return 0

    docker = ContainerStandIn(job)
    ran = drive_helper(scene, argv, docker=docker, signer=make_signer())

    assert ran.raised is None, ran.raised
    assert docker.job_error is None, docker.job_error
    assert got == {"run_folder": True, "owner": os.getpid()}
    assert not copy.exists(), "the helper left the run copy it made"
    assert listing(copy.parent) == [], "the helper left a temporary in the run-knowledge folder"
    assert (run / "report.md").read_text(encoding="utf-8") == "the report", "the run's output did not survive the helper"


# --- H10: links in helper-made folders ------------------------------------------------------------------------------

def _swap_for_a_link_into_the_other_tenant(scene, folder: Path) -> Path:
    """Move `folder` aside and put a link to the other tenant's runs folder in its place; returns that target."""
    target = scene.root / OTHER_TENANT / "runs"
    folder.rename(folder.with_name(folder.name + ".moved"))
    folder.symlink_to(target, target_is_directory=True)
    return target


def test_h10_a_run_folder_replaced_by_a_link_into_another_tenant_gets_no_box_and_creates_nothing(scene):
    """The control box starts on the untouched folder; after the swap `box.start` is refused, no further container is
    created and the other tenant's folder is as it was. (H10, O9)"""
    inv, argv = _investigation(scene)
    got: dict = {}

    def job(c) -> int:
        first = c.request("box.start", kind="shell", id=inv)
        c.request("box.stop", handle=first["handle"])
        target = _swap_for_a_link_into_the_other_tenant(scene, scene.runs / inv)
        got["before"], got["listing"] = len(docker.creates()), listing(target)
        got["refusal"] = c.refused("box.start", kind="shell", id=inv)
        got["after"], got["listing_after"] = len(docker.creates()), listing(target)
        return 0

    docker = ContainerStandIn(job)
    ran = drive_helper(scene, argv, docker=docker, signer=make_signer())

    assert ran.raised is None, ran.raised
    assert docker.job_error is None, docker.job_error
    assert got["before"] == 1, "control: the first box was not created"
    assert got["refusal"] is not None
    assert got["after"] == got["before"], "a box was created over a link into another tenant's folder"
    assert got["listing_after"] == got["listing"]


def test_h10_the_helpers_removal_of_its_run_copy_does_not_follow_a_link_into_another_tenant(scene):
    """The run copy replaced by a link to the other tenant's runs folder (holding a canary file): at the end the other
    tenant's files are untouched. (H10; control: the untouched copy is removed, test above)"""
    inv, argv = _investigation(scene)
    other_runs = scene.root / OTHER_TENANT / "runs"
    (other_runs / "keep.txt").write_text(CANARY, encoding="utf-8")

    def job(c) -> int:
        _swap_for_a_link_into_the_other_tenant(scene, scene.root / scene.tenant / "run-knowledge" / inv)
        return 0

    docker = ContainerStandIn(job)
    ran = drive_helper(scene, argv, docker=docker, signer=make_signer())

    assert ran.raised is None, ran.raised
    assert docker.job_error is None, docker.job_error
    assert (other_runs / "keep.txt").read_text(encoding="utf-8") == CANARY
    assert listing(other_runs) == ["keep.txt"]
    assert (scene.root / OTHER_TENANT / "canary").read_text(encoding="utf-8") == CANARY


def test_h10_every_folder_from_the_tenant_down_to_each_bind_source_is_judged_and_an_unminted_id_is_refused(scene):
    """Each folder on the way from `<T>/` to each bind source of the run box (the source included), swapped in turn for a
    link into a folder of the other tenant that holds what lay below it, gets `box.start` refused as `confinement`, no
    further box, and the other tenant's folder unchanged; an id the helper did not mint is refused as `unknown-id`.
    Control: the untouched folders start the box, whose sources include the run folder and the run copy. (H10, A6, O9;
    the learning kinds' twin is `test_job_helper_learning`)"""
    from defender.tests.support.jobs._job_helper import swap_every_component

    inv, argv = _investigation(scene)
    got: dict = {}

    def job(c) -> int:
        got["sources"], got["arms"] = swap_every_component(scene, c, docker, {"kind": "shell", "id": inv})
        before = len(docker.creates())
        got["unminted"] = c.refused("box.start", kind="shell", id=str(uuid.uuid4())).code
        got["unminted_creates"] = (before, len(docker.creates()))
        return 0

    docker = ContainerStandIn(job)
    ran = drive_helper(scene, argv, docker=docker, signer=make_signer())

    assert ran.raised is None, ran.raised
    assert docker.job_error is None, docker.job_error
    tenant = scene.root / scene.tenant
    assert scene.runs / inv in got["sources"], f"control: the run box binds its run folder: {got['sources']}"
    assert any(s.is_relative_to(tenant / "run-knowledge" / inv) for s in got["sources"]), got["sources"]
    swapped = {a.component for a in got["arms"]}
    assert {tenant / "runs", scene.runs / inv, tenant / "run-knowledge"} <= swapped, swapped
    for arm in got["arms"]:
        assert arm.code == "confinement", f"{arm.component} swapped for a link: {arm.code}"
        assert arm.creates[1] == arm.creates[0], f"a box was created over the link at {arm.component}"
        assert arm.mirror[1] == arm.mirror[0], f"the other tenant's folder changed through {arm.component}"
    assert got["unminted"] == "unknown-id"
    assert got["unminted_creates"][1] == got["unminted_creates"][0]
    assert (scene.root / OTHER_TENANT / "canary").read_text(encoding="utf-8") == CANARY


# --- O9, O10: the helper decides every box's shape and bounds every command ----------------------------------------------

def test_o9_a_box_request_naming_another_tenants_folder_is_refused_and_a_plain_one_is_shaped_by_the_helper(scene):
    """`box.start(kind=shell, id=<inv>)` is started with the tenant's label and the launch record's box token (the worker
    reaps a leftover by it, #1342 r5 C1) and binds inside `<root>/<T>` or the code tree; a request carrying a host path or
    another tenant's folder is refused and creates nothing. (O9)"""
    from defender.box import START_TOKEN_LABEL, TENANT_LABEL

    inv, argv = _investigation(scene)
    got: dict = {}

    def job(c) -> int:
        got["ok"] = c.request("box.start", kind="shell", id=inv)
        got["state"] = len(docker.creates())
        got["refusals"] = [c.refused("box.start", kind="shell", id=inv, **extra) for extra in (
            {"run": str(scene.root / OTHER_TENANT / "runs")}, {"tenant": OTHER_TENANT}, {"mount": "/var/run/docker.sock"})]
        got["after"] = len(docker.creates())
        return 0

    docker = ContainerStandIn(job)
    ran = drive_helper(scene, argv, docker=docker, signer=make_signer())

    assert ran.raised is None, ran.raised
    assert docker.job_error is None, docker.job_error
    (create,) = docker.creates()
    assert parse_labels(create)[TENANT_LABEL] == scene.tenant
    token = json.loads((scene.runs / f"{inv}.launch.json").read_text(encoding="utf-8"))["box_token"]
    assert parse_labels(create).get(START_TOKEN_LABEL) == token, "the run box does not carry the worker's box token"
    code = Path(__file__).resolve().parents[3]
    (job_code,) = [m for m in docker.box.mounts if m["source"] and m["readonly"]]
    for m in (m for m in parse_mounts(create) if m["source"]):
        src = Path(m["source"])
        assert any(src.is_relative_to(ok) for ok in (scene.root / scene.tenant, code, Path(job_code["source"]))), m
    assert got["after"] == got["state"] == 1


def test_o10_a_box_writing_past_the_output_limit_gets_the_output_limit_result_from_the_helper(scene):
    """The helper relays `box.exec` under the box output bound: a real writer of one byte past the limit is answered
    `output-limit`, not its bytes. (O10, C5)"""
    from defender.execution.box_codec import BOX_OUTPUT_LIMIT

    inv, argv = _investigation(scene)
    got: dict = {}

    def job(c) -> int:
        handle = c.request("box.start", kind="shell", id=inv)["handle"]
        got["exec"] = c.request("box.exec", handle=handle, frame=b"{}")
        return 0

    writer = [sys.executable, "-c", f"import os; os.write(1, b'o' * {BOX_OUTPUT_LIMIT + 1})"]
    docker = ContainerStandIn(job, exec_writer=writer)
    ran = drive_helper(scene, argv, docker=docker, signer=make_signer())

    assert ran.raised is None, ran.raised
    assert docker.job_error is None, docker.job_error
    assert any(c[1] == "exec" for c in docker.calls), "premise: the helper relayed the frame to the box"
    assert got["exec"]["result"] == "output-limit", got["exec"]


# --- O7, H8, A2, A5: stopping ---------------------------------------------------------------------------------------

def test_h8_a_teardown_during_a_job_signals_the_recorded_helper_and_gets_the_lock_with_nothing_of_the_tenant_left(scene):
    """With a shell box started and a job that ignores the graceful stop, `take_exclusive` signals the recorded helper and
    force-removes the tenant's containers (the test's `containers`, as #1214 orders); the lock is taken well inside the
    helper's stop grace and no container of the tenant, box included, is left. (H8, O7, C17)"""
    from defender.box import TENANT_LABEL, remove_tenant_containers
    from defender.lifecycle._teardown import take_exclusive
    from defender.tenancy import host_lock

    got: dict = {}
    inv, argv = _investigation(scene)

    def teardown() -> None:
        def containers(tenant: str) -> None:
            assert remove_tenant_containers(tenant, docker=docker) is None
        got["started"] = time.monotonic()
        got["fd"] = take_exclusive(scene.root, scene.tenant, wait=60.0, containers=containers)
        got["took"] = time.monotonic() - got["started"]

    def job(c) -> int:
        got["box"] = c.request("box.start", kind="shell", id=inv)
        got["holders"] = [h.pid for h in host_lock.holders(scene.root, scene.tenant)]
        got["live"] = docker.left(TENANT_LABEL, scene.tenant)
        got["teardown"] = threading.Thread(target=teardown, daemon=True)
        got["teardown"].start()
        assert c.removed.wait(40), "the container was never force-removed"
        return 137

    docker = ContainerStandIn(job, stubborn=True)
    ran = drive_helper(scene, argv, docker=docker, signer=make_signer())
    got["teardown"].join(timeout=60)

    assert ran.raised is None, ran.raised
    assert docker.job_error is None, docker.job_error
    assert got["holders"] == [os.getpid()], "premise: the helper was the tenant's recorded holder"
    assert got["box"], "premise: the shell box was started"
    assert len(got["live"]) >= 2, f"premise: the job container and its box are the tenant's: {got['live']}"
    assert got.get("fd") is not None, "teardown did not get the tenant's lock"
    host_lock.release_lock(got["fd"])
    assert docker.left(TENANT_LABEL, scene.tenant) == []
    assert [h.pid for h in host_lock.holders(scene.root, scene.tenant)] == []
    stops = [c for c in docker.log if len(c) > 1 and c[1] == "stop"]
    grace = min((float(g) for c in stops for g in flag_values(c, "--time", "-t", "--timeout")), default=25.0)
    assert got["took"] < grace / 2, f"teardown waited for the helper's graceful stop ({got['took']:.1f} s, grace {grace})"


def test_o7_a_stop_from_the_worker_stops_the_container_gracefully_lets_the_job_write_its_end_then_removes_by_label(scene):
    """SIGTERM (fence or worker stop): `docker stop` first, with a grace the nesting allows; the job unwinds and writes its
    end record, which the helper leaves; then the leftovers go by label. Needs `learning/branch/cli._STOP_GRACE_SECONDS` lowered from 30 to A2's 20. (O7, A2)"""
    from defender.box import CLAIM_LABEL
    from defender.learning.branch import cli
    from defender.worker import Worker

    from defender.tenancy import host_lock

    inv, argv = _investigation(scene)
    got: dict = {}

    def job(c) -> int:
        os.kill(os.getpid(), signal.SIGTERM)
        assert c.stopping.wait(15), "the helper never stopped the container"
        # While the job unwinds the helper still holds the tenant (#1214: teardown signals it and waits for the lock).
        got["holders"] = [h.pid for h in host_lock.holders(scene.root, scene.tenant)]
        fd = host_lock.acquire(scene.root, scene.tenant, exclusive=True, timeout=0)
        got["exclusive"] = fd is not None
        host_lock.release_lock(fd)
        (scene.runs / f"{inv}.job-end.json").write_text('{"written": "while unwinding"}', encoding="utf-8")
        return 143

    docker = ContainerStandIn(job)
    ran = drive_helper(scene, argv, docker=docker, signer=make_signer())

    assert ran.raised is None, ran.raised
    assert docker.job_error is None, docker.job_error
    assert got["holders"] == [os.getpid()], "the helper was no recorded holder while its job unwound"
    assert got["exclusive"] is False, "the tenant's lock could be taken exclusively while the job unwound"
    touching = [c for c in docker.log if len(c) > 1 and docker.box.name in c and c[1] in ("stop", "kill", "rm")]
    assert [c[1] for c in touching][:1] == ["stop"], f"the container was not stopped gracefully first: {touching}"
    assert docker.left(CLAIM_LABEL, scene.claim) == []
    assert (scene.runs / f"{inv}.job-end.json").read_text(encoding="utf-8") == '{"written": "while unwinding"}'
    (grace,) = flag_values(touching[0], "--time", "-t", "--timeout")
    worker_grace = inspect.signature(Worker.__init__).parameters["stop_grace"].default
    assert cli._STOP_GRACE_SECONDS < float(grace) < worker_grace, "the grace budgets do not nest (A2)"


def test_o7_a_container_that_outlives_its_graceful_stop_is_removed_and_the_helper_exits_inside_the_workers_grace(scene):
    """`docker stop` returns but the container never ends (the job ignores it; the stand-in ends it only when removed):
    the helper removes it and exits, from the SIGTERM, in less than the worker's default stop grace, so the worker never
    has to kill a helper that is still unwinding. (O7, A2; control: the container was stopped gracefully first)"""
    from defender.worker import Worker

    inv, argv = _investigation(scene)
    got: dict = {}

    def job(c) -> int:
        got["signalled_at"] = time.monotonic()
        os.kill(os.getpid(), signal.SIGTERM)
        assert c.stopping.wait(15), "the helper never stopped the container"
        assert c.removed.wait(120), "the container was never removed"
        return 137

    docker = ContainerStandIn(job)
    ran = drive_helper(scene, argv, docker=docker, signer=make_signer())
    took = time.monotonic() - got["signalled_at"]

    assert ran.raised is None, ran.raised
    assert docker.job_error is None, docker.job_error
    touching = [c[1] for c in docker.log if len(c) > 1 and docker.box.name in c and c[1] in ("stop", "kill", "rm")]
    assert touching[:1] == ["stop"], touching
    assert "rm" in touching, f"the container that outlived its stop was not removed: {touching}"
    worker_grace = inspect.signature(Worker.__init__).parameters["stop_grace"].default
    assert took < worker_grace, f"the helper took {took:.1f} s from the signal, the worker's grace is {worker_grace}"


def test_a5_the_container_ends_when_its_helper_is_killed_without_any_worker_sweep(scene, tmp_path):
    """A real helper over a stand-in `docker`: the container is attached (`-i`), carries the job-container label, and
    stays up while the helper lives; SIGKILL the helper and the container sees EOF and exits within a bound.
    (A5; control: alive before the kill)"""
    from defender import job_host
    from defender.box import CLAIM_LABEL, TENANT_LABEL

    inv, _argv = _investigation(scene)
    helper = ProcessHelper(scene, tmp_path, scene.argv("investigation", inv, parent=os.getpid()))
    try:
        container = helper.container_pid()
        time.sleep(1.0)
        assert pid_alive(container), "the container ended with its helper alive"
        assert not (helper.state / "eof").exists()
        (record,) = helper.records().values()
        assert {job_host.JOB_LABEL, TENANT_LABEL, CLAIM_LABEL} <= set(record["labels"]), record["labels"]
        assert "-i" in record["argv"] or "--interactive" in record["argv"], "the container is not attached with stdin"

        os.kill(helper.proc.pid, signal.SIGKILL)
        helper.proc.wait(timeout=10)
        until(lambda: (helper.state / "eof").exists() and not pid_alive(container), "the container to end", 10.0)
    finally:
        helper.close()


def test_a5_killing_the_worker_ends_its_helper_and_the_helpers_container_goes_with_it(scene, tmp_path):
    """A real helper started by a process standing in for the worker (its `--parent-pid`): SIGKILL that process and the
    helper exits, and its container stand-in has ended by the death tie (EOF on its stdin, or the helper's stop) with no
    sweep. (A5, H7; that the worker's argv names its own pid is `test_worker`'s; control: both alive before the kill)"""
    inv, _argv = _investigation(scene)
    argv = scene.argv("investigation", inv)
    argv[-1] = "@worker"
    helper = ProcessHelper(scene, tmp_path, argv, worker=True)
    try:
        container = helper.container_pid()
        time.sleep(0.5)
        assert pid_alive(helper.helper_pid), "premise: the helper ended before its worker was killed"
        assert pid_alive(container), "premise: the container ended before its worker was killed"

        os.kill(helper.worker_pid, signal.SIGKILL)
        helper.proc.wait(timeout=10)
        until(lambda: not pid_alive(helper.helper_pid), "the helper to exit with its worker", 30.0)
        until(lambda: not pid_alive(container), "the container to end", 30.0)
        assert (helper.state / "eof").exists() or (helper.state / "terminated").exists()
    finally:
        helper.close()


# --- A3, O11: honest failures ---------------------------------------------------------------------------------------

def _tamper_the_alert(scene, inv):
    (scene.runs / f"{inv}.alert.json").write_bytes(b'{"not": "the alert the record digests"}')


def _offboarding(scene, _inv):
    from defender.tests.support.jobs._jobs1342 import restate_tenant

    restate_tenant(scene.dsn, scene.tenant, state="offboarding", data_root=scene.root)


def _refusing_premise(scene, inv, cause):
    """Makes setup refuse `inv` for `cause` (A3); the signer to run the helper with."""
    from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A

    if cause == "launch-check":
        _tamper_the_alert(scene, inv)
    elif cause == "admission":
        _offboarding(scene, inv)
    elif cause == "alert-mapping":
        scene.unmap()
    else:
        return A.RaisingSigner(RuntimeError("openbao is sealed"))
    return make_signer()


A3_CAUSES = ["launch-check", "admission", "alert-mapping", "sign"]


@pytest.mark.parametrize("cause", A3_CAUSES)
def test_a3_a_refusal_the_helper_decides_before_the_container_is_written_as_setup_refused(scene, cause):
    """Launch check, admission, alert mapping or first-pass signing refuses: no container, and the end record is
    `setup: refused`, nothing else true. (A3, O11)"""
    from defender.records.job_facts import BOX_NOT_STARTED, SETUP_REFUSED
    from defender.records.job_lane import JobEnd

    inv, argv = _investigation(scene)
    signer = _refusing_premise(scene, inv, cause)
    docker = ContainerStandIn(lambda c: 0)
    ran = drive_helper(scene, argv, docker=docker, signer=signer)

    assert ran.raised is None, ran.raised
    assert docker.boxes == [], "a container was started for a job that setup refused"
    assert scene.end(inv) == JobEnd(SETUP_REFUSED, BOX_NOT_STARTED, False, False, None)
    if cause == "sign":
        assert signer.asked >= 1, "premise: the helper tried to sign the first pass"


@pytest.mark.parametrize("cause", A3_CAUSES)
def test_a3_a_setup_refusal_names_its_cause_on_the_helpers_stderr(scene, capfd, cause):
    """The end record says only `setup: refused`; the operator reads why on the helper's stderr (the worker's child log): the
    launch check, the tenant's state, the missing alert mapping, the failed sign. (A3; the old job entry's refusal text,
    #1342 R6-8, #1345 O4. For `sign` the word is only "sign": the design fixes no text, the cause is the thing named.)"""
    from defender.records.formats import ALERT_MAPPING_MISSING

    names = {"launch-check": "launch", "admission": "offboarding", "alert-mapping": ALERT_MAPPING_MISSING, "sign": "sign"}[cause]
    inv, argv = _investigation(scene)
    signer = _refusing_premise(scene, inv, cause)
    capfd.readouterr()
    ran = drive_helper(scene, argv, docker=ContainerStandIn(lambda c: 0), signer=signer)
    err = " ".join(capfd.readouterr().err.lower().split())

    assert ran.raised is None, ran.raised
    assert getattr(scene.end(inv), "setup", None) == "refused", "premise: setup refused the job"
    assert " ".join(names.lower().split()) in err, f"the refusal does not name its cause ({cause}) on stderr: {err!r}"


@pytest.mark.parametrize("parent", ["control-the-workers-pid", "not-the-parent"])
def test_o7_a_helper_whose_parent_is_not_the_pid_it_was_handed_does_nothing_and_exits_non_zero(scene, parent):
    """`--parent-pid` naming a process that is not the helper's parent (the worker that spawned it is gone): the helper
    exits non-zero having taken no tenant lock, signed nothing, made no run folder, started no container and written no
    end record. Control: with the worker's pid it runs the job. (O7, A5)"""
    from defender.tenancy import host_lock
    from defender.tests.support.jobs._container_entry1170 import ThreadCalls

    inv = str(uuid.uuid4())
    scene.plant(inv)
    other = 1 if os.getppid() != 1 else os.getpid()
    argv = scene.argv("investigation", inv, parent=None if parent.startswith("control") else other)
    signer, docker = make_signer(), ContainerStandIn(lambda c: 0)
    with ThreadCalls({"hold_shared": host_lock.hold_shared, "acquire": host_lock.acquire}) as calls:
        ran = drive_helper(scene, argv, docker=docker, signer=signer)

    assert ran.raised is None, ran.raised
    locks = len(calls.by_thread["hold_shared"]) + len(calls.by_thread["acquire"])
    if parent.startswith("control"):
        assert (ran.rc, len(docker.boxes) == 1, locks >= 1) == (0, True, True), "control: the helper ran the job"
        return
    assert ran.rc != 0
    assert locks == 0, "the helper took the tenant's lock for a worker that is gone"
    assert docker.boxes == [], "the helper started a container for a worker that is gone"
    assert docker.creates() == [], "the helper started a box for a worker that is gone"
    assert signer.payloads == [], "the helper signed a pass for a worker that is gone"
    assert scene.end(inv) is None
    assert not (scene.root / scene.tenant / "run-knowledge" / inv).exists()


@pytest.mark.parametrize("rc", [1, 2, 137, 143])
def test_o7_a_container_that_ran_and_exited_without_an_end_record_gets_none_from_the_helper(scene, rc):
    """The job container ran the job and exited with `rc` writing no end record: the helper writes none either (the
    worker then ends the row as the job left no report); only a `docker run` that never ran the job is the helper's to
    record as a start failure (`test_a3_o11_a_container_that_cannot_start...`). (O7, A3)"""
    inv, docker, ran, _s = _go(scene, lambda c: rc)

    assert docker.job_ran, "control: the job ran in its container"
    assert ran.rc == rc, ran.rc
    assert scene.end(inv) is None, f"the helper wrote an end record for a job that ran: {scene.end(inv)}"


def test_o11_a_job_with_an_empty_grant_starts_though_the_signer_is_sealed(tmp_path, monkeypatch, migrated_database):
    """No `http-proxy` system, so no pass to sign: the sealed signer is never asked and the container starts. (O11 second
    bullet; control for the sign-failure arm above)"""
    from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A

    signer = A.RaisingSigner(RuntimeError("openbao is sealed"))
    with helper_scene(tmp_path, monkeypatch, migrated_database, proxied=()) as empty:
        inv, argv = _investigation(empty)
        docker = ContainerStandIn(lambda c: 0)
        ran = drive_helper(empty, argv, docker=docker, signer=signer)

        assert ran.raised is None, ran.raised
        assert docker.job_ran, "the helper refused a job that has nothing to sign"
        assert signer.asked == 0
        assert empty.end(inv) is None


@pytest.mark.parametrize("stderr", [
    "Unable to find image 'defender-job:latest' locally\n",
    "docker: Error response from daemon: unknown or invalid runtime name: runsc\n",
])
def test_a3_o11_a_container_that_cannot_start_ends_the_row_as_a_box_start_failure_and_nothing_runs_unconfined(
        scene, stderr):
    """docker refuses the start (an image missing, a runtime refused; rc 125): the end record says `box: start_failed`
    and the job runs nowhere else. (A3, O11 first bullet, A7, #1342 R2)"""
    from defender import run as run_py
    from defender.records.job_facts import BOX_START_FAILED, SETUP_REFUSED
    from defender.tests.support.tenancy._host1214 import counting_calls

    inv, argv = _investigation(scene)
    docker = ContainerStandIn(lambda c: 0, run_fault=(125, stderr))
    with counting_calls(job_main=run_py.job_main) as calls:
        ran = drive_helper(scene, argv, docker=docker, signer=make_signer())

    assert ran.raised is None, ran.raised
    assert len(docker.boxes) == 1, "premise: the container start was asked for"
    assert not docker.job_ran
    assert calls.counts["job_main"] == 0, "the job ran unconfined in the helper"
    end = scene.end(inv)
    assert end is not None
    assert end.box == BOX_START_FAILED, end
    assert end.setup != SETUP_REFUSED


def test_a3_an_investigations_helper_waits_for_a_busy_tenant_lock_and_then_runs(scene):
    """The tenant's lock held exclusive (prepare, teardown) for a while: the helper waits, writes no end record while it is
    held, and starts its container once the lock is free. (A3, O11; learning's 30 s is its own)"""
    from defender.tenancy import host_lock

    inv, argv = _investigation(scene)
    fd = host_lock.acquire(scene.root, scene.tenant, exclusive=True, timeout=0)
    assert fd is not None, "premise: the lock was taken"
    seen: dict = {}

    def release() -> None:
        seen["end_while_held"] = scene.end(inv)
        seen["boxes_while_held"] = len(docker.boxes)
        host_lock.release_lock(fd)

    timer = threading.Timer(1.5, release)
    timer.start()
    docker = ContainerStandIn(lambda c: 0)
    started = time.monotonic()
    try:
        ran = drive_helper(scene, argv, docker=docker, signer=make_signer())
    finally:
        timer.cancel()

    assert ran.raised is None, ran.raised
    assert time.monotonic() - started >= 1.4, "premise: the helper did not wait for the lock"
    assert docker.job_ran, "the helper did not run the job once the lock was free"
    assert ran.rc == 0
    assert scene.end(inv) is None
    assert seen["end_while_held"] is None, "the helper wrote an end record while the lock was held"
    assert seen["boxes_while_held"] == 0, "a container was started while the lock was held"


def test_premise_the_other_tenants_canary_is_planted(scene):
    """Fixture premise for O1's reachability cases: the canary exists on the host."""
    assert (scene.root / OTHER_TENANT / "canary").read_text(encoding="utf-8") == CANARY

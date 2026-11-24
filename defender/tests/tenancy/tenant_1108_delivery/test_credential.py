from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

import base64
import contextlib
import json
import os
import pty
import select
import signal
import subprocess
import sys
import tempfile
import shutil
import time
import uuid
from pathlib import Path

import pytest

from ._identity import VaultHTTP, token as identity_token

from ._revert_store import claimed_batch, reviewed
from ._support import (
    LANES,
    TOKEN,
    ForgeHTTP,
    bounded,
    deliver,
    delivery,
    fresh_process_env,
    git,
    git_config_home,
    in_a_fresh_process_finishing,
    opened,
    target,
)

#: #1618 (D4, K8): there is no host clone. A delivery's network git is its open (the one fetch of `main` and every
#: branch into its private repository under `<data root>/.repo-scratch/`, removed when the delivery closes) and its
#: deliver (the tick's push and PR, `_support.deliver`); what a clone's local configuration or hooks did
#: here, the per-user configuration (`git_config_home`) does, the one a fresh private repository's git still reads.


def _private_roots(tenant):
    """Where a delivery's private repositories live while it is open (`<data root>/.repo-scratch/`)."""
    return Path(location_path(tenant.data_root)) / ".repo-scratch"


def _global_config(http_repo):
    return git_config_home(http_repo.checkout.parent.parent).global_config


def _deliver_refused():
    """What a refused deliver raises: the tick's own verbs' errors (a push's `GitError`, a PR create's `ForgeError`) or
    `DeliveryRefused`. #1618: `TenantDelivery.finish`, whose `_refusals` wrapper turned the first two into the third, is
    deleted (test-only code); the production tick catches all three as forge faults (`store_tick._forge_faults`, round
    `repository.push` and the PR's find-or-open), so the promise held here is that it fails, never one type."""
    from defender._git import GitError
    from defender.learning.author.version_control.forgejo import ForgeError

    return (target().DeliveryRefused, GitError, ForgeError)


def _committed_batch(d, name):
    batch = d.start_batch(name, lanes=LANES)
    (batch.draft_root / f"agent/lessons/{name}.md").write_text("over http\n", encoding="utf-8")
    return batch, batch.commit(batch.change_set(), name)


def _state(path):
    st = os.lstat(path)
    return path.read_bytes(), st.st_ino, st.st_mtime_ns, st.st_mode, st.st_size


@pytest.fixture
def spies(http_repo, tmp_path, monkeypatch):
    """Spy helpers and prompt programs in the isolated configuration `http_repo` installed
    (system, global, `$HOME`, XDG) and in the prompt variables. Returns `(log, local spy)`."""
    log = tmp_path / "spies.log"

    def spy(label, *, reads_stdin):
        program = tmp_path / f"spy-{label}"
        body = f'{{ echo "{label} $*"; cat; }}' if reads_stdin else f'echo "{label} $*"'
        program.write_text(f'#!/bin/sh\n{body} >> "{log}"\nexit 0\n', encoding="utf-8")
        program.chmod(0o755)
        return program

    askpass = spy("askpass", reads_stdin=False)
    config = f"[credential]\n\thelper = {spy('global-helper', reads_stdin=True)}\n[core]\n\taskPass = {askpass}\n"
    isolated = git_config_home(tmp_path)
    for path in isolated.files():
        path.write_text(config, encoding="utf-8")
    isolated.system_config.write_text(
        f"[credential]\n\thelper = {spy('system-helper', reads_stdin=True)}\n", encoding="utf-8")
    monkeypatch.setenv("GIT_ASKPASS", str(askpass))
    monkeypatch.setenv("SSH_ASKPASS", str(askpass))
    monkeypatch.delenv("GIT_TERMINAL_PROMPT", raising=False)
    return log, spy("local-helper", reads_stdin=True)


def _armed(http_repo, spies):
    """Install a repository-local spy helper in the test's seed checkout and prove every spy live; returns the spy log.
    (#1618: there is no host clone whose local configuration git could read; the private repository a delivery opens is
    made fresh with no template, so the local spy is a liveness control only.)"""
    _tenant, _remote, _credentials, server = http_repo
    log, local = spies
    git(http_repo.checkout, "config", "credential.helper", str(local))
    _prove_spies_live(http_repo.checkout, server, log)
    return log


def _silent(log):
    seen = log.read_text(encoding="utf-8") if log.exists() else ""
    assert seen == "", f"a spy ran: {seen!r}"


def _prove_spies_live(clone, server, log):
    """Positive control: a plain `git credential fill` in the clone, under the test's
    environment, consults the system, global and local helper spies and then the askpass
    spy."""
    port = server.server.server_address[1]
    # lint-raw-git: test-only positive control of the spies, not the code under test.
    subprocess.run(["git", "credential", "fill"], cwd=clone, check=False, capture_output=True,
                   input=f"protocol=http\nhost=127.0.0.1:{port}\n\n".encode(), timeout=60)
    seen = log.read_text(encoding="utf-8") if log.exists() else ""
    for label in ("system-helper get", "local-helper get", "global-helper get", "askpass"):
        assert label in seen, f"the {label!r} spy is not live: {seen!r}"
    log.unlink()


@pytest.mark.parametrize("outcome", ["success", "fetch-refused", "push-refused"])
def test_git_never_stores_erases_prompts_for_or_shares_the_tenant_credential(
        http_repo, spies, outcome):
    """Bearer authentication succeeds or refuses without consulting ambient helpers,
    prompting, or changing an ignored legacy credential file."""
    tenant, remote, credentials, server = http_repo
    log = _armed(http_repo, spies)
    before = _state(credentials)
    http = ForgeHTTP()

    if outcome == "fetch-refused":
        server.refuse.add("git-upload-pack")
        _, error, hung = bounded(lambda: delivery(http_repo, http), seconds=90)
        assert not hung, "a refused fetch must fail, not wait on a prompt"
        assert isinstance(error, target().DeliveryRefused), error
        assert server.offered_and_refused("git-upload-pack")
    else:
        with delivery(http_repo, http) as d:
            assert server.authorized("git-upload-pack"), "the helper's token authenticated the fetch"
            batch, sha = _committed_batch(d, "credential")
            if outcome == "push-refused":
                server.refuse.add("git-receive-pack")
                _, error, hung = bounded(lambda: deliver(d, batch), seconds=90)
                assert not hung, "a refused push must fail, not wait on a prompt"
                assert isinstance(error, _deliver_refused()), error
                assert server.offered_and_refused("git-receive-pack")
                assert git(remote, "for-each-ref", "--format=%(refname)", "refs/heads") == "refs/heads/main"
                assert not http.creates
            else:
                opened(deliver(d, batch))
                assert server.authorized("git-receive-pack")
                assert git(remote, "rev-parse", f"refs/heads/{batch.branch}") == sha

    assert _state(credentials) == before, "a git operation changed the credential file"
    assert sorted(p.name for p in credentials.parent.iterdir()) == ["git-credentials"]
    assert not log.exists() or log.read_text(encoding="utf-8") == "", log.read_text(encoding="utf-8")


@pytest.mark.parametrize("change", ["emptied", "rewritten-for-another-host", "another-token"])
def test_git_ignores_changes_to_a_legacy_credential_file(http_repo, spies, change):
    """Changes to a legacy credential file cannot affect the explicit Vault identity.
    Real smart-HTTP authentication succeeds without helpers or argv/environment secrets. (#1618: the network git after
    the change is the delivery's push; its fetch is its open.)"""
    tenant, remote, credentials, server = http_repo
    log = _armed(http_repo, spies)
    port = server.server.server_address[1]
    with delivery(http_repo, ForgeHTTP()) as d:
        batch, sha = _committed_batch(d, "legacy")
        credentials.write_text({"emptied": "",
                                "rewritten-for-another-host": f"http://bot:{TOKEN}@other.invalid:{port}\n",
                                "another-token": f"http://bot:a-token-written-after-open@127.0.0.1:{port}\n"}[change],
                               encoding="utf-8")
        server.seen.clear()
        with _Spawns() as spawns:
            result, error, hung = bounded(lambda: deliver(d, batch), seconds=60)
    assert not hung, "git waited on a prompt"
    assert error is None, f"git did not use the identity open() was handed: {error!r}"
    opened(result)
    assert git(remote, "rev-parse", f"refs/heads/{batch.branch}") == sha
    assert server.authorized("git-receive-pack")
    assert sorted(p.name for p in credentials.parent.iterdir()) == ["git-credentials"]
    assert spawns.carrying(_secrets(TOKEN)) == [], "the token reached git through argv or environment"
    _silent(log)


@pytest.mark.postgres
def test_a_second_finish_never_store_erase_prompt_for_or_share_the_credential(
        http_repo, http_store, spies, tmp_path):
    """The retried deliver (the tick's push and PR; #1618: `finish` is deleted) authenticates without
    helpers or prompts, leaving the ignored legacy credential sentinel untouched."""
    tenant, remote, credentials, server = http_repo
    log = _armed(http_repo, spies)
    before = _state(credentials)
    http = ForgeHTTP()
    with delivery(http_repo, http) as d:
        batch, held = claimed_batch(http_repo, http_store, d, "routes")
        (batch.draft_root / "agent/lessons/routes.md").write_text("over http\n", encoding="utf-8")
        batch.commit(batch.change_set(), "over http")
        http.fail_create = True
        with pytest.raises(_deliver_refused()):
            deliver(d, batch)
        http.fail_create = False
        again = deliver(d, batch)
        opened(again)
        reviewed(http_store, held, again)
    assert server.authorized("git-receive-pack"), "the deliver pushed with the helper's token"
    assert _state(credentials) == before
    assert sorted(p.name for p in credentials.parent.iterdir()) == ["git-credentials"]
    _silent(log)


def _holding(roots, secret: bytes, since: float):
    """Files below `roots` (each a folder or a file) changed since `since` and holding
    `secret`; large and unreadable files are skipped."""
    found = []
    for root in roots:
        walk = [(str(root), [], [""])] if os.path.isfile(root) else os.walk(root)
        for folder, _dirs, files in walk:
            for name in files:
                path = os.path.join(folder, name) if name else folder
                try:
                    st = os.lstat(path)
                    if st.st_mtime < since or st.st_size > 1 << 20 or os.path.islink(path):
                        continue
                    with open(path, "rb") as handle:
                        if secret in handle.read():
                            found.append(path)
                except OSError:
                    continue
    return found


@pytest.mark.postgres
def test_no_second_copy_of_the_credential_is_written_anywhere(http_repo, http_store, tmp_path):
    """A fresh JWT never appears in a disk file after the delivery's open (its fetch), commit, refused deliver and retried
    deliver. (#1618: the after-scan cannot see a private repository, removed at close; the scan made while
    network git waits, below, is the one that reads its configuration.)"""
    tenant, _remote, credentials, server = http_repo
    token = identity_token(signature=uuid.uuid4().hex)
    server.token = token
    tmp = tempfile.gettempdir()
    started = time.time() - 1
    existing = set(os.listdir(tmp))
    http = ForgeHTTP()
    identity = VaultHTTP(value=token).identity()
    with delivery(http_repo, http, identity=identity) as d:
        batch, held = claimed_batch(http_repo, http_store, d, "no-copy")
        (batch.draft_root / "agent/lessons/no-copy.md").write_text("a lesson\n", encoding="utf-8")
        batch.commit(batch.change_set(), "claim")
        http.fail_create = True
        with pytest.raises(_deliver_refused()):
            deliver(d, batch)
        http.fail_create = False
        again = deliver(d, batch)
        opened(again)
        reviewed(http_store, held, again)
    assert server.authorized("git-receive-pack")
    new_in_tmp = [os.path.join(tmp, name) for name in sorted(set(os.listdir(tmp)) - existing)]
    copies = _holding([*new_in_tmp, location_path(tenant.tenant_root), _private_roots(tenant),
                       git_config_home(tmp_path).home], token.encode(), started)
    assert copies == [], copies


def _shm():
    return "/dev/shm" if os.path.isdir("/dev/shm") else None


def _new_entries(folder, existing):
    return [os.path.join(folder, name) for name in sorted(set(os.listdir(folder)) - existing)]


def _private_configs(tenant):
    """Every git configuration file of a private repository open now under `.repo-scratch/` (a bare one's `config`, a
    worktree's `.git/config`)."""
    root = _private_roots(tenant)
    return sorted(str(p) for p in root.rglob("config") if p.is_file()) if root.is_dir() else []


@pytest.mark.postgres
def test_no_file_holds_the_credential_while_network_git_waits_on_the_forge(http_repo, http_store, tmp_path):
    """A fresh JWT never appears on disk during authenticated fetch or push: the delivery's open (its fetch), and its
    deliver (the tick's push; #1618: `finish` is deleted). Each scan is made while git
    waits on the forge and reads the private repository's own git configuration under `.repo-scratch/` (#1618 K8: the
    clone whose `.git/config` this guarded is gone; the private repository is removed on exit, so it is observed during
    the operation): the credential is never written into a repository's configuration."""
    tenant, _remote, credentials, server = http_repo
    token = identity_token(signature=uuid.uuid4().hex)
    server.token = token
    tmp, shm = tempfile.gettempdir(), _shm()
    existing = {folder: set(os.listdir(folder)) for folder in (tmp, shm) if folder}
    started = time.time() - 1
    scans, configs, phase = {}, {}, ["open"]

    def scan(service):
        roots = [entry for folder, names in existing.items() for entry in _new_entries(folder, names)]
        configs[phase[0], service] = _private_configs(tenant)
        found = _holding([*roots, location_path(tenant.tenant_root), _private_roots(tenant),
                          git_config_home(tmp_path).home], token.encode(), started)
        scans[phase[0], service] = found
    server.on_service = scan
    http = ForgeHTTP()
    identity = VaultHTTP(value=token).identity()
    with delivery(http_repo, http, identity=identity) as d:
        batch, held = claimed_batch(http_repo, http_store, d, "during")
        (batch.draft_root / "agent/lessons/during.md").write_text("a lesson\n", encoding="utf-8")
        batch.commit(batch.change_set(), "claim")
        phase[0] = "deliver"
        server.rearm()
        finished = deliver(d, batch)
        opened(finished)
        reviewed(http_store, held, finished)
    required = {("open", "git-upload-pack"), ("deliver", "git-receive-pack")}
    assert required <= set(scans), sorted(required - set(scans))
    missing = sorted(moment for moment in required if not configs.get(moment))
    assert missing == [], f"premise: no private repository's configuration was there to read at {missing}: {configs}"
    assert {moment: found for moment, found in scans.items() if found} == {}, \
        "the token sat in a file while git waited on the forge"


def test_a_downgrade_to_plain_http_at_the_same_host_and_port_gets_no_token(http_repo, spies):
    """An origin rewritten from HTTPS to HTTP at the same host receives no Bearer
    token and cannot trigger a helper or prompt."""
    _tenant, _remote, credentials, server = http_repo
    log = _armed(http_repo, spies)
    port = server.server.server_address[1]
    # #1618: the origin is the recorded one (no clone to re-point), and the rewrite is planted where a fresh private
    # repository's git could still read one, the per-user configuration; the delivery's open is its first network git.
    with git_config_home(http_repo.checkout.parent.parent).global_config.open("a", encoding="utf-8") as config:
        config.write(f'[url "http://127.0.0.1:{port}/"]\n\tinsteadOf = https://127.0.0.1:{port}/\n')
    credentials.write_text(f"https://bot:{TOKEN}@127.0.0.1:{port}\n", encoding="utf-8")
    _, error, hung = bounded(lambda: delivery(http_repo, ForgeHTTP(), network_timeout=1,
                                              origin=f"https://127.0.0.1:{port}/tenants/blue.git"), seconds=60)
    assert not hung, "git waited on a prompt"
    assert error is None or isinstance(error, target().DeliveryRefused), error
    assert [auth for auth in server.authorizations if auth] == [], "the token went over plain http"
    _silent(log)


#: Where each spawn audit event carries its argv and its environment (`None`: this
#: process's own, inherited).
_SPAWN_FIELDS = {"subprocess.Popen": (1, 3), "os.posix_spawn": (1, 2), "os.exec": (1, 2),
                 "os.spawn": (2, 3), "os.system": (0, None)}


def _text(value):
    if isinstance(value, (str, bytes, os.PathLike)):
        return os.fsdecode(value)
    return " ".join(_text(item) for item in value)


class _Spawns:
    """Every process this one starts while active, as `(argv text, environment text)`,
    recorded by an audit hook: the environment passed to it, or this process's own when none
    is (the child inherits it). Audit hooks cannot be removed; this one only records."""

    def __init__(self):
        self.seen: list[tuple[str, str]] = []
        self.active = False
        sys.addaudithook(self._audit)

    def _audit(self, event, args):
        if not self.active or event not in _SPAWN_FIELDS:
            return
        argv_at, env_at = _SPAWN_FIELDS[event]
        env = args[env_at] if env_at is not None else None
        env = dict(os.environ) if env is None else env
        self.seen.append((_text(args[argv_at]),
                          "\n".join(f"{_text(k)}={_text(v)}" for k, v in env.items())))

    def __enter__(self):
        self.active = True
        return self

    def __exit__(self, *exc):
        self.active = False

    def carrying(self, secrets):
        """The spawns whose argv or environment holds any of `secrets`."""
        return [(argv, "environment" if not any(x in argv for x in secrets) else "argv")
                for argv, env in self.seen if any(x in argv or x in env for x in secrets)]


def _secrets(token):
    return {token, f"bot:{token}", base64.b64encode(f"bot:{token}".encode()).decode()}


@pytest.mark.postgres
def test_the_credential_never_rides_in_a_process_argument_or_environment(http_repo, http_store, tmp_path):
    spawns = _Spawns()
    with spawns:
        subprocess.run([sys.executable, "-c", "pass"], check=True,
                       env={**os.environ, "P3_CONTROL": TOKEN})
    assert spawns.carrying(_secrets(TOKEN)), "the audit hook must see a spawn and its environment"
    spawns.seen.clear()
    http = ForgeHTTP()
    with spawns, delivery(http_repo, http) as d:
        batch, held = claimed_batch(http_repo, http_store, d, "argv")
        (batch.draft_root / "agent/lessons/argv.md").write_text("a lesson\n", encoding="utf-8")
        batch.commit(batch.change_set(), "claim")
        http.fail_create = True
        with pytest.raises(_deliver_refused()):
            deliver(d, batch)
        http.fail_create = False
        again = deliver(d, batch)
        opened(again)
        reviewed(http_store, held, again)
    assert spawns.seen
    assert spawns.carrying(_secrets(TOKEN)) == []


def test_a_url_rewritten_to_another_server_gets_neither_the_token_nor_a_prompt(
        http_repo, spies, rewritten):
    """(#1618: the delivery's open is its first network git, so it is what meets the rewrite; the rewrite is the
    per-user configuration's, which the product's network git does not read at all, so the other server is never
    reached; were it read, the scoped credential must still not go there.)"""
    log = _armed(http_repo, spies)
    opened_d, error, hung = bounded(lambda: delivery(http_repo, ForgeHTTP()), seconds=60)
    if opened_d is not None:
        opened_d.close()
    assert not hung, "git waited on a prompt"
    assert error is None or isinstance(error, target().DeliveryRefused), error
    assert [auth for auth in rewritten.authorizations if auth] == [], "a credential went to another server"
    assert rewritten.seen == [], "the per-user rewrite steered the delivery's git to another server"
    _silent(log)


_ON_A_TERMINAL = """
import json, os, sys
from pathlib import Path
os.setsid()
os.open(sys.argv[1], os.O_RDWR)  # the controlling terminal of this new session
from defender.tests.support.tenancy import _tenants1106 as tenants
from defender.tests.tenancy.tenant_1108_delivery._support import DEFENDER, ForgeHTTP, target, fixture_identity
mod = target()
out = {}
try:
    tenant = tenants.accept(Path(sys.argv[2]), sys.argv[3])
    origin = sys.argv[4]
    http = ForgeHTTP(origin=origin)
    with mod.TenantDelivery.open(tenant, defender_dir=DEFENDER, client=http.client, identity=fixture_identity(str(tenant.id)), origin=origin):
        out["published"] = True
except mod.DeliveryRefused as refused:
    out["refused"] = str(refused)
print(json.dumps(out))
"""


def test_git_never_prompts_on_a_terminal(http_repo, tmp_path):
    """Git, refused whatever it sends (401 on the fetch), never prompts on the process's controlling terminal: the delivery's
    open is refused instead. #1618: the prompt path is reached by the forge rejecting the credential, not by a per-user
    `insteadOf` rewrite, which product git never reads (`transport.py`: `GIT_CONFIG_GLOBAL=/dev/null`). Control: git was
    asked for credentials (the forge saw the fetch)."""
    tenant, _remote, _credentials, server = http_repo
    server.refuse.add("git-upload-pack")
    before = len(server.seen)
    # This process keeps the terminal's other end open throughout, so reading it never ends
    # early (a terminal nobody holds reads as closed before the child has opened it).
    try:
        master, slave = pty.openpty()
    except OSError as no_terminal:
        pytest.skip(f"no pseudo-terminal on this host ({no_terminal}); the askpass spies remain")
    terminal = os.ttyname(slave)
    # The child's output goes to files, never to pipes nobody drains while the terminal is
    # watched, so a chatty child cannot stall until the deadline.
    out_path, err_path = tmp_path / "terminal.out", tmp_path / "terminal.err"
    with open(out_path, "wb") as out_file, open(err_path, "wb") as err_file:
        child = subprocess.Popen([sys.executable, "-c", _ON_A_TERMINAL, terminal, str(location_path(tenant.data_root)),
                                  str(tenant.id), http_repo.origin], stdout=out_file, stderr=err_file,
                                 stdin=subprocess.DEVNULL, env=fresh_process_env(tenant, tmp_path / "terminal"))
    written, deadline = b"", time.monotonic() + 60
    try:
        while child.poll() is None and time.monotonic() < deadline and not written:
            ready, _, _ = select.select([master], [], [], 0.2)
            if ready:
                try:
                    written += os.read(master, 4096)
                except OSError:
                    break
    finally:
        if not written:
            with contextlib.suppress(subprocess.TimeoutExpired):
                child.wait(timeout=max(1.0, deadline - time.monotonic()))
        if child.poll() is None:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                child.kill()
        child.wait(timeout=60)
        os.close(slave)
        os.close(master)
    assert written == b"", f"git prompted on the terminal: {written!r}"
    assert child.returncode == 0, err_path.read_bytes()
    verdict = json.loads(out_path.read_bytes().decode().strip().splitlines()[-1])
    assert "refused" in verdict, f"a forge refusing every credential let the open through: {verdict}"
    assert any(service == "git-upload-pack" for service, _sent, _ok in server.seen[before:]), \
        "premise: the open never reached the forge, so git never met the 401"


def test_clone_push_urls_do_not_select_a_delivery_destination(http_repo, spies):
    """Push URLs configured for `origin` do not select where a delivery pushes: it pushes to its tenant's remote,
    without helpers, prompts or disk writes. (#1618 K8: planted in the per-user configuration, there being no clone.)"""
    tenant, remote, credentials, server = http_repo
    log = _armed(http_repo, spies)
    before = _state(credentials)
    url = "http://127.0.0.1:1/tenants/other.git"
    for _ in range(3):
        git(http_repo.checkout, "config", "--file", str(_global_config(http_repo)), "--add", "remote.origin.pushurl", url)
    http = ForgeHTTP()
    with delivery(http_repo, http) as d:
        batch = d.start_batch("twice", lanes=LANES)
        (batch.draft_root / "agent/lessons/twice.md").write_text("pushed twice\n", encoding="utf-8")
        sha = batch.commit(batch.change_set(), "claim")
        result, error, hung = bounded(lambda: deliver(d, batch), seconds=90)
    assert not hung, "git waited on a prompt"
    assert error is None, f"a later credential get went unanswered: {error!r}"
    opened(result)
    assert git(remote, "rev-parse", f"refs/heads/{batch.branch}") == sha
    assert not server.offered_and_refused("git-receive-pack")
    assert _state(credentials) == before
    _silent(log)


#: A hook that logs whenever the git running it is a fetch or a push (`$PPID` is that git), and stays quiet for local
#: git (the commit-maker's own `update-ref`, say).
_NETWORK_HOOK = """#!/bin/sh
parent=$(tr '\\0' ' ' < /proc/$PPID/cmdline)
case " $parent " in
  *" fetch "*|*" push "*|*" ls-remote "*|*" pull "*) echo "{name}: $parent" >> {log} ;;
esac
cat > /dev/null
exit 0
"""


@pytest.mark.postgres
def test_network_git_runs_no_hook_the_configuration_names(http_repo, http_store, tmp_path):
    """Hooks never run under the delivery's network git: its deliver (refused, then retried).
    #1618 K8: there is no clone whose `.git/hooks` this guarded; the hooks are planted in the delivery's own private
    repository (`d.repository.path/hooks`, once it is open) and named by `core.hooksPath` in the per-user configuration.
    Control: a plain git under the same configuration runs them."""
    _tenant, remote = http_repo[0], http_repo[1]
    log = tmp_path / "hooks.log"
    hooks = tmp_path / "configured-hooks"
    hooks.mkdir()
    for name in ("pre-push", "reference-transaction"):
        (hooks / name).write_text(_NETWORK_HOOK.format(name=name, log=log), encoding="utf-8")
        (hooks / name).chmod(0o755)
    git(http_repo.checkout, "config", "--file", str(_global_config(http_repo)), "core.hooksPath", str(hooks))
    scratch = tmp_path / "control.git"
    git(tmp_path, "init", "--bare", "-q", scratch)
    git(http_repo.checkout, "push", "-q", scratch, "HEAD:refs/heads/control")
    git(http_repo.checkout, "fetch", "-q", scratch, "+refs/heads/control:refs/p3/control")
    seen = log.read_text(encoding="utf-8") if log.exists() else ""
    assert "pre-push:" in seen, f"the pre-push hook is not live: {seen!r}"
    assert "reference-transaction:" in seen, f"the reference-transaction hook is not live: {seen!r}"
    log.unlink()
    git(http_repo.checkout, "update-ref", "-d", "refs/p3/control")

    def plant(d):
        shutil.copytree(hooks, Path(d.repository.path) / "hooks", dirs_exist_ok=True)

    http = ForgeHTTP()
    with delivery(http_repo, http) as d:
        plant(d)
        batch, held = claimed_batch(http_repo, http_store, d, "hooked")
        (batch.draft_root / "agent/lessons/hooked.md").write_text("a lesson\n", encoding="utf-8")
        batch.commit(batch.change_set(), "claim")
        http.fail_create = True
        with pytest.raises(_deliver_refused()):
            deliver(d, batch)
        http.fail_create = False
        again = deliver(d, batch)
        opened(again)
        reviewed(http_store, held, again)
    assert git(remote, "rev-parse", f"refs/heads/{batch.branch}")
    seen = log.read_text(encoding="utf-8") if log.exists() else ""
    assert seen == "", f"a configured hook ran under network git: {seen}"


def test_delivery_needs_no_optional_python_linux_exports(http_repo):
    remote = http_repo[1]
    prelude = """
import fcntl, os
for module, names in (
    (os, ("memfd_create", "MFD_CLOEXEC", "MFD_ALLOW_SEALING")),
    (fcntl, ("F_ADD_SEALS", "F_GET_SEALS", "F_SEAL_SEAL", "F_SEAL_SHRINK", "F_SEAL_GROW", "F_SEAL_WRITE")),
):
    for name in names:
        if hasattr(module, name):
            delattr(module, name)
"""
    result = in_a_fresh_process_finishing(http_repo, "portable", python_prelude=prelude)
    assert result.get("status") == "opened", result
    assert len(result["creates"]) == 1
    assert git(remote, "rev-parse", f"refs/heads/{result['branch']}") == result["commit"]


def test_git_does_not_send_bearer_to_another_repository_on_the_same_server(http_repo, spies):
    """(#1618 K8: the rewrite is the per-user configuration's, there being no clone; the open is the fetch.)"""
    _tenant, _, _, server = http_repo
    log = _armed(http_repo, spies)
    origin = f"{server.url}/tenants/blue.git"
    git(http_repo.checkout, "config", "--file", str(_global_config(http_repo)),
        f"url.{server.url}/tenants/other.git.insteadOf", origin)
    server.seen.clear()
    _, error, hung = bounded(lambda: delivery(http_repo, ForgeHTTP()).close(), seconds=60)
    assert not hung, "git waited on a prompt"
    assert error is None, error
    assert server.authorizations
    assert all(auth == "Bearer " + TOKEN for auth in server.authorizations)
    _silent(log)


def test_git_refreshes_a_vault_identity_before_network_git_outlives_it(http_repo):
    """One identity across a delivery's network git: the open's fetch mints once; past the token's refresh point the
    push mints again and authenticates with the new token. (#1618: the second network git is the deliver's push, a
    delivery fetching only at its open.)"""
    vault = VaultHTTP()
    with delivery(http_repo, ForgeHTTP(), identity=vault.identity()) as d:
        assert len(vault.calls) == 1
        assert http_repo[3].authorized("git-upload-pack")
        batch, _sha = _committed_batch(d, "refresh")
        vault.now += 451
        http_repo[3].token = identity_token(issued=vault.now)
        http_repo[3].seen.clear()
        opened(deliver(d, batch))
    assert len(vault.calls) == 2
    assert http_repo[3].authorized("git-receive-pack")


def test_url_specific_configuration_cannot_enable_redirects(http_repo):
    """#1618: planted in the per-user configuration (there is no clone's local configuration any more); the delivery's
    open is the network git that meets the redirect."""
    from ._support import Trickle

    _tenant, _, _, server = http_repo
    origin = f"{server.url}/tenants/blue.git"
    with git_config_home(http_repo.checkout.parent.parent).global_config.open("a", encoding="utf-8") as config:
        config.write(f'[http "{origin}"]\n\tfollowRedirects = true\n')

    class Redirect(Trickle):
        def __init__(self):
            pass

        def send(self, handler):
            handler.send_response(302)
            handler.send_header("Location", f"{server.url}/tenants/other.git/info/refs?service=git-upload-pack")
            handler.send_header("Content-Length", "0")
            handler.end_headers()

    server.on_service = lambda service: Redirect()
    with pytest.raises(target().DeliveryRefused):
        delivery(http_repo, ForgeHTTP())
    assert len(server.authorizations) == 1, "git followed the redirect to another repository"

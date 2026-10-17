"""Bearer transport uses sealed memory, never ambient helpers, prompts or disk files.

Real smart-HTTP git checks fetch/push, failures, URL rewrites, clone hooks and secret leakage.
Legacy credential files are ignored sentinels: the only token source is explicit Vault HTTP.
"""
from __future__ import annotations

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
import time
import uuid

import pytest

from ._identity import VaultHTTP, token as identity_token

from ._support import (
    BARE_NO_UPKEEP,
    LANES,
    TOKEN,
    ForgeHTTP,
    GitHTTP,
    bounded,
    delivery,
    forge_pulls,
    fresh_process_env,
    git,
    git_config_home,
    in_a_later_process,
    merge_on_remote,
    opened,
    target,
)


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
    """Install the clone's own spy helper and prove every spy live; returns the spy log."""
    tenant, _remote, _credentials, server = http_repo
    log, local = spies
    git(tenant.knowledge, "config", "credential.helper", str(local))
    _prove_spies_live(tenant.knowledge, server, log)
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
    log, local = spies
    git(tenant.knowledge, "config", "credential.helper", str(local))
    _prove_spies_live(tenant.knowledge, server, log)
    before = _state(credentials)
    http = ForgeHTTP()
    d = delivery(http_repo, http)

    if outcome == "fetch-refused":
        server.refuse.add("git-upload-pack")
        _, error, hung = bounded(d.publish, seconds=90)
        assert not hung, "a refused fetch must fail, not wait on a prompt"
        assert isinstance(error, target().DeliveryRefused), error
        assert server.offered_and_refused("git-upload-pack")
    else:
        batch = d.start_batch("credential", lanes=LANES)
        assert server.authorized("git-upload-pack"), "the helper's token authenticated the fetch"
        (batch.draft_root / "agent/lessons/new.md").write_text("over http\n", encoding="utf-8")
        sha = batch.commit(batch.change_set(), "over http")
        if outcome == "push-refused":
            server.refuse.add("git-receive-pack")
            _, error, hung = bounded(lambda: d.finish(batch), seconds=90)
            assert not hung, "a refused push must fail, not wait on a prompt"
            assert isinstance(error, target().DeliveryRefused), error
            assert server.offered_and_refused("git-receive-pack")
            assert git(remote, "for-each-ref", "--format=%(refname)", "refs/heads") == "refs/heads/main"
            assert not http.creates
        else:
            opened(d.finish(batch))
            assert server.authorized("git-receive-pack")
            assert git(remote, "rev-parse", f"refs/heads/{batch.branch}") == sha

    assert _state(credentials) == before, "a git operation changed the credential file"
    assert sorted(p.name for p in credentials.parent.iterdir()) == ["git-credentials"]
    assert not log.exists() or log.read_text(encoding="utf-8") == "", log.read_text(encoding="utf-8")


@pytest.mark.parametrize("change", ["emptied", "rewritten-for-another-host", "another-token"])
def test_git_ignores_changes_to_a_legacy_credential_file(http_repo, spies, change):
    """Changes to a legacy credential file cannot affect the explicit Vault identity.
    Real smart-HTTP authentication succeeds without helpers or argv/environment secrets."""
    tenant, remote, credentials, server = http_repo
    log = _armed(http_repo, spies)
    d = delivery(http_repo, ForgeHTTP())
    port = server.server.server_address[1]
    credentials.write_text({"emptied": "",
                            "rewritten-for-another-host": f"http://bot:{TOKEN}@other.invalid:{port}\n",
                            "another-token": f"http://bot:a-token-written-after-open@127.0.0.1:{port}\n"}[change],
                           encoding="utf-8")
    with _Spawns() as spawns:
        export, error, hung = bounded(d.publish, seconds=60)
    assert not hung, "git waited on a prompt"
    assert error is None, f"git did not use the credential open() read: {error!r}"
    assert export.commit == git(remote, "rev-parse", "main")
    assert server.authorized("git-upload-pack")
    assert sorted(p.name for p in credentials.parent.iterdir()) == ["git-credentials"]
    assert spawns.carrying(_secrets(TOKEN)) == [], "the token reached git through argv or environment"
    _silent(log)


def test_deliver_and_revert_never_store_erase_prompt_for_or_share_the_credential(
        http_repo, spies, tmp_path):
    """Retained delivery and revert authenticate without helpers or prompts, leaving
    the ignored legacy credential sentinel untouched."""
    tenant, remote, credentials, server = http_repo
    log = _armed(http_repo, spies)
    before = _state(credentials)
    http = ForgeHTTP()
    d = delivery(http_repo, http)
    batch = d.start_batch("routes", lanes=LANES)
    (batch.draft_root / "agent/lessons/routes.md").write_text("over http\n", encoding="utf-8")
    batch.commit(batch.change_set(), "over http")
    http.fail_create = True
    with pytest.raises(target().DeliveryRefused):
        d.finish(batch)
    http.fail_create = False
    opened(d.deliver("routes"))
    merge_on_remote(http_repo, tmp_path, batch.branch)
    server.seen.clear()
    assert opened(d.revert("agent/lessons/routes.md", "routes"), None) == forge_pulls(remote)[-1]["html_url"]
    assert server.authorized("git-receive-pack"), "the revert pushed with the helper's token"
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


def test_no_second_copy_of_the_credential_is_written_anywhere(http_repo, tmp_path):
    """A fresh JWT never appears in a disk file after publish, commit, refused finish,
    retained delivery and revert."""
    tenant, _remote, credentials, server = http_repo
    token = identity_token(signature=uuid.uuid4().hex)
    server.token = token
    tmp = tempfile.gettempdir()
    started = time.time() - 1
    existing = set(os.listdir(tmp))
    http = ForgeHTTP()
    d = delivery(http_repo, http, identity=VaultHTTP(value=token).identity())
    batch = d.start_batch("no-copy", lanes=LANES)
    (batch.draft_root / "agent/lessons/no-copy.md").write_text("a lesson\n", encoding="utf-8")
    batch.commit(batch.change_set(), "claim")
    http.fail_create = True
    with pytest.raises(target().DeliveryRefused):
        d.finish(batch)
    http.fail_create = False
    opened(d.deliver("no-copy"))
    merge_on_remote(http_repo, tmp_path, batch.branch)
    assert opened(d.revert("agent/lessons/no-copy.md", "no-copy"), None) == forge_pulls(http_repo[1])[-1]["html_url"]
    assert server.authorized("git-receive-pack")
    new_in_tmp = [os.path.join(tmp, name) for name in sorted(set(os.listdir(tmp)) - existing)]
    copies = _holding([*new_in_tmp, tenant.dir, git_config_home(tmp_path).home], token.encode(), started)
    assert copies == [], copies


def _shm():
    return "/dev/shm" if os.path.isdir("/dev/shm") else None


def _new_entries(folder, existing):
    return [os.path.join(folder, name) for name in sorted(set(os.listdir(folder)) - existing)]


def test_no_file_holds_the_credential_while_network_git_waits_on_the_forge(http_repo, tmp_path):
    """A fresh JWT never appears on disk during authenticated fetch or push, including
    publish, batch start, finish and revert."""
    tenant, _remote, credentials, server = http_repo
    token = identity_token(signature=uuid.uuid4().hex)
    server.token = token
    tmp, shm = tempfile.gettempdir(), _shm()
    existing = {folder: set(os.listdir(folder)) for folder in (tmp, shm) if folder}
    started = time.time() - 1
    scans, phase = {}, ["publish"]

    def scan(service):
        roots = [entry for folder, names in existing.items() for entry in _new_entries(folder, names)]
        found = _holding([*roots, tenant.dir, git_config_home(tmp_path).home], token.encode(), started)
        scans[phase[0], service] = found
    server.on_service = scan
    http = ForgeHTTP()
    d = delivery(http_repo, http, identity=VaultHTTP(value=token).identity())
    d.publish()
    phase[0] = "start_batch"
    server.rearm()
    batch = d.start_batch("during", lanes=LANES)
    (batch.draft_root / "agent/lessons/during.md").write_text("a lesson\n", encoding="utf-8")
    batch.commit(batch.change_set(), "claim")
    phase[0] = "finish"
    server.rearm()
    opened(d.finish(batch))
    merge_on_remote(http_repo, tmp_path, batch.branch)
    phase[0] = "revert"
    server.rearm()
    opened(d.revert("agent/lessons/during.md", "during"), None)
    required = {("publish", "git-upload-pack"), ("start_batch", "git-upload-pack"),
                ("finish", "git-receive-pack"), ("revert", "git-receive-pack")}
    assert required <= set(scans), sorted(required - set(scans))
    assert {moment: found for moment, found in scans.items() if found} == {}, \
        "the token sat in a file while git waited on the forge"


def test_a_downgrade_to_plain_http_at_the_same_host_and_port_gets_no_token(http_repo, spies):
    """An origin rewritten from HTTPS to HTTP at the same host receives no Bearer
    token and cannot trigger a helper or prompt."""
    tenant, _remote, credentials, server = http_repo
    log = _armed(http_repo, spies)
    port = server.server.server_address[1]
    git(tenant.knowledge, "remote", "set-url", "origin", f"https://127.0.0.1:{port}/tenants/blue.git")
    git(tenant.knowledge, "config", f"url.http://127.0.0.1:{port}/.insteadOf", f"https://127.0.0.1:{port}/")
    credentials.write_text(f"https://bot:{TOKEN}@127.0.0.1:{port}\n", encoding="utf-8")
    d = delivery(http_repo, ForgeHTTP())
    _, error, hung = bounded(d.publish, seconds=60)
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


def test_the_credential_never_rides_in_a_process_argument_or_environment(http_repo, tmp_path):
    """Flow 5 (ruling: never in an environment, never in argv, never a second file, `open()`
    the single reader): the token never appears in a spawned process's arguments (any local
    user reads them in `/proc/<pid>/cmdline`), as a `-c http.extraHeader`, an inline helper or
    a URL, nor in the environment any spawned process is given or inherits; plain, as
    `bot:<token>` or base64; across publish, finish, a retained deliver and a revert. How the
    helper does receive it is not pinned. An audit hook sees every spawn; its positive
    control comes first."""
    spawns = _Spawns()
    with spawns:
        subprocess.run([sys.executable, "-c", "pass"], check=True,
                       env={**os.environ, "P3_CONTROL": TOKEN})
    assert spawns.carrying(_secrets(TOKEN)), "the audit hook must see a spawn and its environment"
    spawns.seen.clear()
    http = ForgeHTTP()
    with spawns:
        d = delivery(http_repo, http)
        batch = d.start_batch("argv", lanes=LANES)
        (batch.draft_root / "agent/lessons/argv.md").write_text("a lesson\n", encoding="utf-8")
        batch.commit(batch.change_set(), "claim")
        http.fail_create = True
        with pytest.raises(target().DeliveryRefused):
            d.finish(batch)
        http.fail_create = False
        opened(d.deliver("argv"))
    merge_on_remote(http_repo, tmp_path, batch.branch)
    with spawns:
        assert opened(d.revert("agent/lessons/argv.md", "argv"), None) == forge_pulls(http_repo[1])[-1]["html_url"]
    assert spawns.seen
    assert spawns.carrying(_secrets(TOKEN)) == []


@pytest.fixture
def rewritten(http_repo, tmp_path):
    """The clone's `url.<other>.insteadOf` sends origin's git traffic to ANOTHER smart-HTTP
    server (another port), so the one helper, scoped to the parsed forge address, has no
    answer and git reaches its prompt path. Yields that other server."""
    tenant, remote, _credentials, server = http_repo
    other_root = tmp_path / "other-served"
    (other_root / "tenants").mkdir(parents=True)
    git(tmp_path, "clone", "--bare", *BARE_NO_UPKEEP, remote, other_root / "tenants" / "blue.git")
    other = GitHTTP(other_root)
    try:
        git(tenant.knowledge, "config", f"url.{other.url}/.insteadOf", f"{server.url}/")
        yield other
    finally:
        other.close()


def test_a_url_rewritten_to_another_server_gets_neither_the_token_nor_a_prompt(
        http_repo, spies, rewritten):
    """Flow 5 (orchestrator ruling): the helper answers only for the protocol, host and port
    of the parsed forge address, so git traffic rewritten to another server carries no
    credential there; and with no answer, no prompt program runs (`GIT_ASKPASS` emptied,
    which also silences `core.askPass` and `SSH_ASKPASS`). The publish succeeds (an
    implementation that does not follow the rewrite) or refuses, never hangs."""
    log = _armed(http_repo, spies)
    d = delivery(http_repo, ForgeHTTP())
    _, error, hung = bounded(d.publish, seconds=60)
    assert not hung, "git waited on a prompt"
    assert error is None or isinstance(error, target().DeliveryRefused), error
    assert [auth for auth in rewritten.authorizations if auth] == [], "a credential went to another server"
    _silent(log)


_ON_A_TERMINAL = """
import json, os, sys
from pathlib import Path
os.setsid()
os.open(sys.argv[1], os.O_RDWR)  # the controlling terminal of this new session
from defender.tests import _tenants1106 as tenants
from defender.tests.tenant_1108_delivery._support import DEFENDER, ForgeHTTP, configured_origin, target, fixture_identity
mod = target()
out = {}
try:
    tenant = tenants.accept(Path(sys.argv[2]), sys.argv[3])
    http = ForgeHTTP(origin=configured_origin(tenant.knowledge))
    later = mod.TenantDelivery.open(tenant, defender_dir=DEFENDER, client=http.client, identity=fixture_identity(str(tenant.id)))
    later.publish()
    out["published"] = True
except mod.DeliveryRefused as refused:
    out["refused"] = str(refused)
print(json.dumps(out))
"""


def test_git_never_prompts_on_a_terminal(http_repo, rewritten, tmp_path):
    """Flow 5, `GIT_TERMINAL_PROMPT=0`: run where a terminal exists. A process whose session
    has a real pseudo-terminal as its controlling terminal publishes through the rewritten
    URL (the helper has no answer, no prompt program is configured), so git's next step
    would be its terminal prompt. Nothing is ever written to that terminal and the publish
    ends (refused, or done without the rewrite) instead of waiting for input."""
    tenant = http_repo[0]
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
        child = subprocess.Popen([sys.executable, "-c", _ON_A_TERMINAL, terminal, str(tenant.data_root),
                                  str(tenant.id)], stdout=out_file, stderr=err_file,
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
    assert verdict.get("published") or "refused" in verdict, verdict


def test_a_git_run_that_asks_for_the_credential_again_and_again_succeeds(http_repo, spies):
    """Every push URL in one git invocation receives the scoped Bearer header.
    The descriptor can be read repeatedly without helpers, prompts or disk writes."""
    tenant, remote, credentials, server = http_repo
    log = _armed(http_repo, spies)
    before = _state(credentials)
    url = f"{server.url}/tenants/blue.git"
    for _ in range(3):
        git(tenant.knowledge, "config", "--add", "remote.origin.pushurl", url)
    http = ForgeHTTP()
    d = delivery(http_repo, http)
    batch = d.start_batch("twice", lanes=LANES)
    (batch.draft_root / "agent/lessons/twice.md").write_text("pushed twice\n", encoding="utf-8")
    sha = batch.commit(batch.change_set(), "claim")
    result, error, hung = bounded(lambda: d.finish(batch), seconds=90)
    assert not hung, "git waited on a prompt"
    assert error is None, f"a later credential get went unanswered: {error!r}"
    opened(result)
    assert git(remote, "rev-parse", f"refs/heads/{batch.branch}") == sha
    assert not server.offered_and_refused("git-receive-pack")
    assert _state(credentials) == before
    _silent(log)


#: A clone hook that logs whenever the git running it is a fetch or a push (`$PPID` is that
#: git), and stays quiet for local git (the commit-maker's own `update-ref`, say).
_NETWORK_HOOK = """#!/bin/sh
parent=$(tr '\\0' ' ' < /proc/$PPID/cmdline)
case " $parent " in
  *" fetch "*|*" push "*|*" ls-remote "*|*" pull "*) echo "{name}: $parent" >> {log} ;;
esac
cat > /dev/null
exit 0
"""


def test_network_git_runs_no_hook_of_the_clones(repo, tmp_path):
    """C4 / O-E: network git runs with `core.hooksPath=/dev/null`, so no hook of the clone's
    runs while the token is within reach: `pre-push` never runs, nor `reference-transaction`
    under a fetch or a push, across publish, a batch, finish, a retained deliver and a
    revert. Positive control: the clone's own fetch and push run both hooks."""
    tenant, remote = repo[0], repo[1]
    clone = tenant.knowledge
    log = tmp_path / "hooks.log"
    hooks = clone / ".git" / "hooks"
    hooks.mkdir(exist_ok=True)
    for name in ("pre-push", "reference-transaction"):
        (hooks / name).write_text(_NETWORK_HOOK.format(name=name, log=log), encoding="utf-8")
        (hooks / name).chmod(0o755)
    scratch = tmp_path / "control.git"
    git(tmp_path, "init", "--bare", "-q", scratch)
    git(clone, "push", "-q", scratch, "HEAD:refs/heads/control")
    git(clone, "fetch", "-q", scratch, "+refs/heads/control:refs/p3/control")
    seen = log.read_text(encoding="utf-8") if log.exists() else ""
    assert "pre-push:" in seen, f"the pre-push hook is not live: {seen!r}"
    assert "reference-transaction:" in seen, f"the reference-transaction hook is not live: {seen!r}"
    log.unlink()
    git(clone, "update-ref", "-d", "refs/p3/control")

    http = ForgeHTTP()
    d = delivery(repo, http)
    d.publish()
    batch = d.start_batch("hooked", lanes=LANES)
    (batch.draft_root / "agent/lessons/hooked.md").write_text("a lesson\n", encoding="utf-8")
    batch.commit(batch.change_set(), "claim")
    http.fail_create = True
    with pytest.raises(target().DeliveryRefused):
        d.finish(batch)
    http.fail_create = False
    opened(d.deliver("hooked"))
    merge_on_remote(repo, tmp_path, batch.branch)
    d.revert("agent/lessons/hooked.md", "hooked")
    assert git(remote, "rev-parse", f"refs/heads/{batch.branch}")
    seen = log.read_text(encoding="utf-8") if log.exists() else ""
    assert seen == "", f"a clone hook ran under network git: {seen}"


def test_delivery_needs_no_optional_python_linux_exports(http_repo):
    """Standalone Python's build headers can omit memfd/seal exports even on a Linux host
    that supports them. A later drain must still authenticate and deliver; no credential
    channel is replaced with a disk file. Remove those optional names in the child only.
    """
    remote = http_repo[1]
    writer = delivery(http_repo, ForgeHTTP())
    batch = writer.start_batch("portable", lanes=LANES)
    (batch.draft_root / "agent/lessons/portable.md").write_bytes(b"portable lesson\n")
    commit = batch.commit(batch.change_set(), "claim")
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
    result = in_a_later_process(http_repo, "deliver", batch.id, python_prelude=prelude)
    assert result.get("status") == "opened", result
    assert len(result["creates"]) == 1
    assert git(remote, "rev-parse", f"refs/heads/{batch.branch}") == commit


def test_git_does_not_send_bearer_to_another_repository_on_the_same_server(http_repo, spies):
    tenant, _, _, server = http_repo
    log = _armed(http_repo, spies)
    origin = f"{server.url}/tenants/blue.git"
    git(tenant.knowledge, "config", f"url.{server.url}/tenants/other.git.insteadOf", origin)
    d = delivery(http_repo, ForgeHTTP())
    with pytest.raises(target().DeliveryRefused):
        d.publish()
    assert server.authorizations
    assert not any(server.authorizations)
    _silent(log)


def test_git_refreshes_a_vault_identity_before_a_fetch_outlives_it(http_repo):
    vault = VaultHTTP()
    d = delivery(http_repo, ForgeHTTP(), identity=vault.identity())
    d.publish()
    assert len(vault.calls) == 1
    vault.now += 451
    http_repo[3].token = identity_token(issued=vault.now)
    http_repo[3].seen.clear()
    d.publish()
    assert len(vault.calls) == 2
    assert http_repo[3].authorized("git-upload-pack")

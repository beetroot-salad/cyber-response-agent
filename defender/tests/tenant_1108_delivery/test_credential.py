"""O-E (amendment 2, flow 5): the tenant credential is read-only and non-interactive.

Git runs against a real smart-HTTP remote demanding the bot's credential, so its credential
path actually runs (local transport never consults a helper). K1 showed git's `store` helper
empties the credential file after an authentication failure; the failed fetch and failed push
here are that case. Spies sit wherever git looks for other helpers and for a prompt: the
clone's own config, the global config (by `GIT_CONFIG_GLOBAL`, `$HOME/.gitconfig` and
`$XDG_CONFIG_HOME/git/config`), the system config (by `GIT_CONFIG_SYSTEM`),
`GIT_ASKPASS`/`SSH_ASKPASS` and `core.askPass`. A positive control proves every spy is live
before delivery runs."""
from __future__ import annotations

import os
import subprocess
import time

import pytest

from ._support import LANES, TOKEN, ForgeHTTP, bounded, delivery, git, target


def _state(path):
    st = os.lstat(path)
    return path.read_bytes(), st.st_ino, st.st_mtime_ns, st.st_mode, st.st_size


@pytest.fixture
def spies(tmp_path, monkeypatch):
    log = tmp_path / "spies.log"

    def spy(label, *, reads_stdin):
        program = tmp_path / f"spy-{label}"
        body = f'{{ echo "{label} $*"; cat; }}' if reads_stdin else f'echo "{label} $*"'
        program.write_text(f'#!/bin/sh\n{body} >> "{log}"\nexit 0\n', encoding="utf-8")
        program.chmod(0o755)
        return program

    helper = spy("global-helper", reads_stdin=True)
    askpass = spy("askpass", reads_stdin=False)
    local = spy("local-helper", reads_stdin=True)
    system = tmp_path / "system.gitconfig"
    system.write_text(f"[credential]\n\thelper = {spy('system-helper', reads_stdin=True)}\n",
                      encoding="utf-8")
    config = f"[credential]\n\thelper = {helper}\n[core]\n\taskPass = {askpass}\n"
    home = tmp_path / "home"
    (home / "xdg" / "git").mkdir(parents=True)
    (home / ".gitconfig").write_text(config, encoding="utf-8")
    (home / "xdg" / "git" / "config").write_text(config, encoding="utf-8")
    global_config = tmp_path / "global.gitconfig"
    global_config.write_text(config, encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / "xdg"))
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(global_config))
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", str(system))
    monkeypatch.delenv("GIT_CONFIG_NOSYSTEM", raising=False)
    monkeypatch.setenv("GIT_ASKPASS", str(askpass))
    monkeypatch.setenv("SSH_ASKPASS", str(askpass))
    monkeypatch.delenv("GIT_TERMINAL_PROMPT", raising=False)
    return log, local


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
    """Flow 5: helpers reset, then one read-only helper answering only `get` from the tenant
    file; no prompt. Whether the fetch or push succeeds or the server refuses the bot's
    token, the credential file is byte-identical and untouched (same inode, mtime, mode),
    `forge/` gains nothing, and no spy is ever invoked. The server's record shows the bot's
    token was offered each time, so a refusal really is git's erase path (K1)."""
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
            assert d.finish(batch).endswith("/pulls/7")
            assert server.authorized("git-receive-pack")
            assert git(remote, "rev-parse", f"refs/heads/{batch.branch}") == sha

    assert _state(credentials) == before, "a git operation changed the credential file"
    assert sorted(p.name for p in credentials.parent.iterdir()) == ["git-credentials"]
    assert not log.exists() or log.read_text(encoding="utf-8") == "", log.read_text(encoding="utf-8")


@pytest.mark.parametrize("change", ["emptied", "rewritten-for-another-host"])
def test_a_credential_file_changed_after_open_never_leads_git_to_prompt(http_repo, spies, change):
    """Flow 5 with `open()` the single reader: after `open()` the credential file is emptied
    or rewritten for another host, so a helper that reads the file when git asks has no
    answer and git goes on to its prompts. Delivery then still succeeds on the credential
    `open()` read, or fails fast with a named refusal; either way no spy runs (no askpass,
    `core.askPass` or other helper), and `forge/` gains nothing. The in-process audit in
    `test_credentials_loaded_once_and_token_not_in_representation` cannot see a helper
    subprocess re-reading the file; this can."""
    tenant, remote, credentials, server = http_repo
    log, local = spies
    git(tenant.knowledge, "config", "credential.helper", str(local))
    _prove_spies_live(tenant.knowledge, server, log)
    d = delivery(http_repo, ForgeHTTP())
    port = server.server.server_address[1]
    credentials.write_text("" if change == "emptied" else f"http://bot:{TOKEN}@other.invalid:{port}\n",
                           encoding="utf-8")
    started = time.monotonic()
    export, error, hung = bounded(d.publish, seconds=60)
    assert not hung, "git waited on a prompt"
    assert time.monotonic() - started < 30
    if error is None:
        assert export.commit == git(remote, "rev-parse", "main")
    else:
        assert isinstance(error, target().DeliveryRefused), error
    assert sorted(p.name for p in credentials.parent.iterdir()) == ["git-credentials"]
    assert not log.exists() or log.read_text(encoding="utf-8") == "", log.read_text(encoding="utf-8")

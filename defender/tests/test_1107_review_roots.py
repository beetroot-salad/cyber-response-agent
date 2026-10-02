"""PR #1156 review — the five root causes behind eleven of its findings, one guard each.

1. How a system is reached is never guessed, and a missing Kibana container is a health-check
   RESULT, not a fault that discards the Elasticsearch answer and trips the breaker.
2. A stored fault is never re-raised as the same object, and no settings fault names a host path.
3. Every settings file is read one way: capped, single-linked, no-follow at the leaf, and split
   on the same line endings the connect validator reads with.
4. A call's secrets come from ONE read of `secrets.env`, and a placed secret can reach a request
   header (`{{NAME}}`), not only `-u`.
5. A receipt the box planted does not survive the run that planted it, however the run ends.

Each test fails on 755177b6 (the PR head these fixes land on).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from defender.scripts.adapters import _stub_transport as transport
from defender.scripts.adapters import elastic_adapter
from defender.scripts.adapters.faults import ConfigFault
from defender.tests.tenant_1107_settings import _spec1107 as S

_ES_HEALTH = S.answer(json.dumps({"status": "green", "number_of_nodes": 1}))
_POINTER = "the tenant's settings/"


def _tenant(tmp_path: Path, marker: str, **kw) -> tuple[Path, Path]:
    root = tmp_path / marker
    return root, S.plant(root, marker=marker, **kw)


def _ctx(record, where: Path, shim: S.DockerShim):
    run_dir = where / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    return S.verb_context(record, run_dir, shim.env())


# ======================================================================================
# 1 — reach is never guessed; Kibana is optional to the health check.
# ======================================================================================

def test_health_check_reports_missing_kibana_container_as_data(tmp_path):
    """An elastic config with no ELASTIC_KIBANA_CONTAINER: the health check still returns the
    green Elasticsearch answer, says Kibana is not configured, and spawns no Kibana call."""
    root, folder = _tenant(tmp_path, "kbn")
    S.drop_key(folder, "elastic", "ELASTIC_KIBANA_CONTAINER")
    shim = S.DockerShim(tmp_path / "shim", [_ES_HEALTH])
    ctx = _ctx(S.resolve(root), tmp_path, shim)

    out = elastic_adapter.health_check(ctx)

    assert out["elasticsearch"] == "green", out
    assert "not configured" in out["kibana"], out
    assert "ELASTIC_KIBANA_CONTAINER" in out["kibana"], out
    assert len(shim.calls()) == 1, [c["argv"] for c in shim.calls()]


@pytest.mark.parametrize("call", [
    lambda ctx: transport.docker_exec_curl(ctx, "bastion-x", "http://cmdb-x:8080/health"),
    lambda ctx: transport.docker_exec_raw(ctx, "web-1", ["true"]),
    lambda ctx: transport.docker_inspect_raw(ctx, "c0ffee"),
], ids=["curl", "raw", "inspect"])
def test_transport_lanes_require_a_named_system(tmp_path, call):
    """No lane picks a system for a caller that did not name one: not by URL prefix, not by a
    host-state default. Omitting `system=` is a call error, and no docker child runs."""
    root, _ = _tenant(tmp_path, "sys")
    shim = S.DockerShim(tmp_path / "shim")
    ctx = _ctx(S.resolve(root), tmp_path, shim)
    with pytest.raises(TypeError, match="system"):
        call(ctx)
    assert shim.calls() == []


# ======================================================================================
# 2 — faults: fresh on every raise, and worded without the host path.
# ======================================================================================

def test_settings_faults_name_no_host_path(tmp_path):
    """Every settings fault the resolver or an adapter words names the file by the settings
    pointer, never by its absolute path: a non-UTF-8 config, a missing system folder, a missing
    required key (stub and elastic), and an unreadable case-history mapping."""
    from defender.scripts.adapters import cmdb_adapter

    root, folder = _tenant(tmp_path, "pth")
    S.write_config(folder, "identity", b"IDENTITY_URL_BASE=\xff\n")
    S.drop_key(folder, "cmdb", "CMDB_URL_BASE")
    S.drop_key(folder, "elastic", "ELASTIC_EVENTS_INDEX")
    S.mapping_path(folder).write_text("- not\n- a mapping\n", encoding="utf-8")
    record = S.resolve(root)
    shim = S.DockerShim(tmp_path / "shim")
    ctx = _ctx(record, tmp_path, shim)

    texts = {
        "not utf-8": str(record.systems["identity"]),
        "missing key": str(_raised(cmdb_adapter.health_check, ctx)),
        "elastic key": str(_raised(elastic_adapter.query, ctx, native_query="*")),
        "no folder": str(_raised(transport.system_entry, ctx, "no-such-system")),
        "mapping": str(record.ticket_mapping),
    }
    host = str(tmp_path)
    for arm, text in texts.items():
        assert host not in text, f"{arm}: the fault names the host path: {text!r}"
        assert _POINTER in text, f"{arm}: the fault does not name the file by the pointer: {text!r}"


def test_stager_raises_a_fresh_fault_each_call(tmp_path):
    """The branch stager's index-less lookup on a tenant whose Elastic part is a fault raises a
    NEW fault each call: the record's own object is never raised (its traceback would grow)."""
    from defender.learning.branch.estate.stagers import elastic as stager

    root, folder = _tenant(tmp_path, "stg")
    S.drop_key(folder, "elastic", "ELASTIC_EVENTS_INDEX")
    record = S.resolve(root)
    stored = record.elastic
    assert isinstance(stored, ConfigFault)
    ctx = _ctx(record, tmp_path, S.DockerShim(tmp_path / "shim"))

    raised = [_raised(stager.source_pattern, "query", {}, ctx) for _ in range(3)]

    assert all(isinstance(r, ConfigFault) for r in raised), raised
    assert all(r is not stored for r in raised), "the record's stored fault was raised"
    assert stored.__traceback__ is None, "the stored fault picked up a traceback"


# ======================================================================================
# 3 — one way to read a settings file.
# ======================================================================================

def test_lone_cr_line_endings_parse_as_lines(tmp_path):
    """A config.env and a secrets.env written with lone-CR line endings parse line by line,
    the way the connect validator (universal newlines) reads them."""
    from defender.runtime.tenant_settings import parse_env

    assert parse_env("A=1\rB=2\r\nC=3\n") == {"A": "1", "B": "2", "C": "3"}
    assert parse_env("A=x\x0cy\n") == {"A": "x\x0cy"}, "only CR/LF end a line, as in the validator"

    root, folder = _tenant(tmp_path, "crx", secrets=b"API_A=alpha\rAPI_B=bravo\r")
    text = S.config_path(folder, "cmdb").read_text(encoding="utf-8").replace("\n", "\r")
    S.write_config(folder, "cmdb", text + 'A_SECRET_REF="API_A"\rB_SECRET_REF="API_B"\r')
    record = S.resolve(root)
    assert record.systems["cmdb"]["CMDB_TRANSPORT"] == S.DOCKER_EXEC
    assert record.secrets.get("API_A") == "alpha"
    assert record.secrets.get("API_B") == "bravo"


def test_oversized_config_is_that_system_down_not_a_crash(tmp_path):
    """A sparse config.env far larger than any settings file is that system's ConfigFault at
    resolve — the run goes on — never a MemoryError out of the resolver."""
    root, folder = _tenant(tmp_path, "big")
    with open(S.config_path(folder, "cmdb"), "r+b") as fh:
        fh.truncate(64 << 20)
    record = S.resolve(root)
    assert isinstance(record.systems["cmdb"], ConfigFault), record.systems["cmdb"]
    assert not isinstance(record.systems["identity"], ConfigFault), "a sibling went down with it"


@pytest.mark.parametrize("alias", ["hard link", "symlink"])
def test_the_config_reader_refuses_an_aliased_file(tmp_path, alias):
    """Tenant acceptance walks the folder for links before resolve, but a link swapped in after
    that walk reaches the reader: it refuses a hard-linked or symlinked config.env itself, as the
    secrets file and the run-dir readers do, rather than reading another file's bytes."""
    from defender.runtime import tenant_settings

    other = tmp_path / "other.env"
    other.write_text("CMDB_URL_BASE=http://elsewhere\n", encoding="utf-8")
    path = tmp_path / "config.env"
    if alias == "hard link":
        os.link(other, path)
    else:
        path.symlink_to(other)
    with pytest.raises(ConfigFault):
        tenant_settings.read_env_file(path, shown="the tenant's settings/systems/cmdb/config.env")


def test_an_opened_file_renamed_over_still_reads(tmp_path):
    """The rotation adapter.md prescribes renames a new secrets.env over the old: a read that
    opened the old one sees its link count drop to 0, and that is still a plain file to read —
    the repo's one rule (`_io.is_plain_entry`) refuses more than one name, never zero."""
    from defender.runtime import tenant_settings

    path = tmp_path / "secrets.env"
    path.write_text("A=1\n", encoding="utf-8")
    fd = os.open(path, os.O_RDONLY)
    try:
        path.unlink()
        assert os.fstat(fd).st_nlink == 0
        assert tenant_settings.read_plain_fd(fd) == b"A=1\n"
    finally:
        os.close(fd)


# ======================================================================================
# 4 — secrets: one read per call, and a header can carry one.
# ======================================================================================

def _secret_tenant(tmp_path: Path, marker: str, secrets: dict[str, str]):
    root, folder = _tenant(tmp_path, marker, secrets=secrets)
    for i, name in enumerate(secrets):
        S.set_key(folder, "cmdb", f"REF{i}_SECRET_REF", name)
    return S.resolve(root)


_FAKE_CURL = """\
import json, sys
argv = sys.argv[1:]
stdin_headers = []
for i, a in enumerate(argv[:-1]):
    if a == "-H" and argv[i + 1] == "@-":
        stdin_headers = sys.stdin.read().splitlines()
print(json.dumps({"argv": argv, "stdin_headers": stdin_headers}))
"""


def _in_container(call: dict, tmp_path: Path, **container_env: str) -> dict:
    """Replay the in-container half of a recorded `docker exec` the way docker runs it: the
    container's environment holds only the variables named by `-e NAME` (taken from the docker
    CLI's own environment) plus `container_env`, and a fake `curl` reports its argv — what a
    process list shows — and any headers it read on stdin (`-H @-`)."""
    fakebin = tmp_path / "incontainer"
    fakebin.mkdir(exist_ok=True)
    curl = fakebin / "curl"
    curl.write_text(f"#!{sys.executable}\n{_FAKE_CURL}", encoding="utf-8")
    curl.chmod(0o755)
    argv = call["argv"]
    rest = argv[argv.index("exec") + 1:]
    forwarded: dict[str, str] = {}
    while rest[0].startswith("-"):
        if rest[0] == "-e":
            name = rest[1]
            if name in call["env"]:
                forwarded[name] = call["env"][name]
            rest = rest[2:]
        else:
            rest = rest[1:]
    inner = rest[1:]  # past the container name
    proc = subprocess.run(inner, capture_output=True, text=True, check=True,
                          env={"PATH": f"{fakebin}{os.pathsep}{os.environ['PATH']}",
                               **forwarded, **container_env})
    return json.loads(proc.stdout)


def test_a_placed_secret_reaches_a_header_off_every_argv(tmp_path):
    """`{{NAME}}` in a header value is the declared secret NAME, forwarded into the container by
    `-e` and expanded there. curl reads the slotted header on stdin, so the value is on neither
    the docker argv nor curl's own (a process list in the bastion shows no token). Shell syntax
    in a slotted header's literal text is sent as written, never run."""
    value = "tok header-1156"
    record = _secret_tenant(tmp_path, "hdr", {"X_TOKEN": value})
    shim = S.DockerShim(tmp_path / "shim", [S.answer("{}", "200")])
    ctx = _ctx(record, tmp_path, shim)

    transport.docker_exec_curl(
        ctx, "bastion-hdr", "http://cmdb-hdr:8080/x", system="cmdb", secrets=("X_TOKEN",),
        headers={"Authorization": "Bearer {{X_TOKEN}}",
                 "X-Sig": "{{X_TOKEN}} $(echo pwned) `id -u` $HOME '\"",
                 "X-Lit": "$(echo lit)"})

    (call,) = shim.calls()
    assert all(value not in a for a in call["argv"]), "the secret is on the docker argv"
    seen = _in_container(call, tmp_path)
    assert all(value not in a for a in seen["argv"]), "the secret is on curl's argv"
    assert f"Authorization: Bearer {value}" in seen["stdin_headers"], seen
    assert f"X-Sig: {value} $(echo pwned) `id -u` $HOME '\"" in seen["stdin_headers"], seen
    assert "X-Lit: $(echo lit)" in seen["argv"], seen


def test_two_secrets_reach_their_own_headers(tmp_path):
    """Two placed secrets in two headers each arrive under their own header."""
    record = _secret_tenant(tmp_path, "two", {"X_TOKEN": "vx-1156", "Y_TOKEN": "vy-1156"})
    shim = S.DockerShim(tmp_path / "shim", [S.answer("{}", "200")])
    ctx = _ctx(record, tmp_path, shim)
    transport.docker_exec_curl(ctx, "b", "http://cmdb-two:8080/x", system="cmdb",
                               secrets=("X_TOKEN", "Y_TOKEN"),
                               headers={"A": "{{Y_TOKEN}}", "B": "{{X_TOKEN}}"})
    seen = _in_container(shim.calls()[0], tmp_path)
    assert seen["stdin_headers"] == ["A: vy-1156", "B: vx-1156"], seen


def test_auth_expands_container_vars_and_secrets_and_nothing_else(tmp_path):
    """`auth` still expands a container's own braced `${VAR}` there (the elastic read path), a
    `{{NAME}}` in it is a placed secret, and every other character — a quote, `$1`, a
    backslash — is literal."""
    value = "pw auth-1156"
    record = _secret_tenant(tmp_path, "ath", {"SVC_PASS": value})
    shim = S.DockerShim(tmp_path / "shim", [S.answer("{}", "200")])
    ctx = _ctx(record, tmp_path, shim)

    transport.docker_exec_curl(ctx, "b", "http://cmdb-ath:8080/x", system="cmdb",
                               auth="elastic:${ELASTIC_PASSWORD}")
    transport.docker_exec_curl(ctx, "b", "http://cmdb-ath:8080/x", system="cmdb",
                               secrets=("SVC_PASS",), auth='o"ps$1\\x:{{SVC_PASS}}')

    legacy, placed = shim.calls()
    argv = _in_container(legacy, tmp_path, ELASTIC_PASSWORD="container-pw")["argv"]
    assert argv[argv.index("-u") + 1] == "elastic:container-pw", argv
    argv = _in_container(placed, tmp_path)["argv"]
    assert argv[argv.index("-u") + 1] == f'o"ps$1\\x:{value}', argv


def test_an_unplaced_reference_is_refused_before_any_child(tmp_path):
    """`{{NAME}}` for a name the call did not place is a ConfigFault before docker runs — never a
    literal `{{NAME}}` sent upstream."""
    record = _secret_tenant(tmp_path, "unp", {"X_TOKEN": "v"})
    shim = S.DockerShim(tmp_path / "shim")
    ctx = _ctx(record, tmp_path, shim)
    with pytest.raises(ConfigFault, match="Y_TOKEN"):
        transport.docker_exec_curl(ctx, "b", "http://cmdb-unp:8080/x", system="cmdb",
                                   secrets=("X_TOKEN",), headers={"A": "{{Y_TOKEN}}"})
    assert shim.calls() == []


def test_one_call_reads_secrets_once(tmp_path):
    """A call placing two secrets resolves them in one lookup — one read of secrets.env — so a
    rotation landing mid-call cannot pair an old value with a new one."""
    from types import SimpleNamespace

    reads: list[tuple[str, ...]] = []

    class _Lookup:
        def get_many(self, names):
            reads.append(tuple(names))
            return [f"v-{n}" for n in names]

        def get(self, name):  # a second read path would show up here
            raise AssertionError("a per-name read")

    root, _ = _tenant(tmp_path, "one")
    record = S.resolve(root)
    fake = SimpleNamespace(**{f: getattr(record, f) for f in ("systems", "settings")},
                           secrets=_Lookup())
    shim = S.DockerShim(tmp_path / "shim", [S.answer("{}", "200")])
    ctx = _ctx(fake, tmp_path, shim)
    transport.docker_exec_curl(ctx, "b", "http://cmdb-one:8080/x", system="cmdb",
                               secrets=("A", "B"))
    assert reads == [("A", "B")]


# ======================================================================================
# 5 — a planted receipt does not outlive its run.
# ======================================================================================

def _planted_receipt(run_dir: Path) -> Path:
    path = S.receipt_path(run_dir)
    path.write_text(json.dumps({"key": "SOC-1", "status": "commented", "url": "http://x",
                                "ok": True, "reason": None}), encoding="utf-8")
    return path


@pytest.mark.parametrize("ending", ["investigation raises", "scrub taints"])
def test_planted_receipt_is_cleared_however_the_run_ends(tmp_path, ending):
    """The box writes a success receipt — and keeps writing it until it is stopped — then the
    run dies, in the investigation or in the scrub (RunTainted). The receipt is gone once the
    lifecycle unwinds: the clear runs after the box is down, so a re-render of the crashed run
    shows no ticket line the host never wrote."""
    from defender.runtime.scrub import RunTainted

    root, _ = _tenant(tmp_path, "rcp")
    record = S.resolve(root)
    run_dir = tmp_path / "runs" / "run-1"
    run_dir.mkdir(parents=True)

    def investigate(**_kw):
        _planted_receipt(run_dir)
        if ending == "investigation raises":
            raise RuntimeError("the drive died")
        return {}

    def scrub(_tree):
        if ending == "scrub taints":
            raise RunTainted("planted link")

    with pytest.raises((RuntimeError, RunTainted)):
        S.run_py()._run_investigation_lifecycle(
            run_dir=run_dir, model="m", model_override=None, defender_dir=S.DEFENDER,
            tenant=record, investigate=investigate, start_box=lambda *a, **k: object(),
            stop_box=lambda _box: _planted_receipt(run_dir), scrub=scrub)

    assert not S.receipt_path(run_dir).exists(), "the box's receipt survived the run"


def test_deeply_nested_receipt_is_unreadable_at_any_depth(tmp_path):
    """The page decodes the box-writable receipt with the repo's bounded JSON loader: a receipt
    with valid fields and one field nested past the limit is unreadable, not a ticket line."""
    from defender.scripts.visualize import visualize_run

    run_dir = tmp_path / "run"
    run_dir.mkdir()
    deep = "[" * 500 + "]" * 500
    S.receipt_path(run_dir).write_text(
        '{"key": "SOC-1", "status": "commented", "url": null, "ok": true, "reason": null, '
        f'"x": {deep}}}', encoding="utf-8")
    line = visualize_run.render_ticket_line(run_dir)
    assert visualize_run.RECEIPT_UNREADABLE in line, line


def test_rerender_shows_no_ticket_line_for_an_unverified_tree(tmp_path):
    """A run killed by a signal never reached the lifecycle's clear, and a run whose teardown
    faulted may have had a live box after it. Neither has a verified reap verdict, so a
    standalone re-render asked for `--update-ticket` shows no ticket line; a verified tree does."""
    from defender.runtime import scrub
    from defender.scripts.visualize import visualize_run

    run_dir = tmp_path / "runs" / "run-1"
    run_dir.mkdir(parents=True)
    _planted_receipt(run_dir)
    assert visualize_run.rerender_shows_ticket(run_dir, update_ticket=True) is False
    scrub.write_did_not_run(run_dir, "teardown faulted")
    assert visualize_run.rerender_shows_ticket(run_dir, update_ticket=True) is False
    scrub.scrub(run_dir)
    assert visualize_run.rerender_shows_ticket(run_dir, update_ticket=True) is True
    assert visualize_run.rerender_shows_ticket(run_dir, update_ticket=False) is False


# ======================================================================================
# Second review: routing, stored faults, the validator, the ignore rule.
# ======================================================================================

def test_elasticsearch_calls_never_route_to_kibana_by_url(tmp_path):
    """An Elasticsearch-only tenant whose KIBANA_URL equals its ELASTICSEARCH_URL (a placeholder
    for a required key) still has its searches run in the Elasticsearch container: which
    service a call addresses is the caller's statement, never a URL-prefix guess."""
    root, folder = _tenant(tmp_path, "kpx")
    S.drop_key(folder, "elastic", "ELASTIC_KIBANA_CONTAINER")
    es_url = S.config_path(folder, "elastic").read_text(encoding="utf-8").split(
        'ELASTICSEARCH_URL="', 1)[1].split('"', 1)[0]
    S.set_key(folder, "elastic", "KIBANA_URL", es_url)
    shim = S.DockerShim(tmp_path / "shim", [
        S.answer(json.dumps({"hits": {"total": {"value": 0}, "hits": []}}))])
    ctx = _ctx(S.resolve(root), tmp_path, shim)

    elastic_adapter.query(ctx, native_query="*")

    targets = [S.exec_target(c["argv"]) for c in shim.calls()]
    assert targets == [S.es_container("kpx")], targets


def test_stored_faults_carry_no_traceback_or_cause(tmp_path):
    """A fault the record keeps is text only: no traceback (whose frames hold the live dict
    behind the read-only view) and no cause (an OSError carrying the host path)."""
    root, folder = _tenant(tmp_path, "sfc")
    cfg = S.config_path(folder, "cmdb")
    cfg.unlink()
    cfg.mkdir()  # unreadable as a file: an OSError underneath the fault
    S.mapping_path(folder).write_text("- not a mapping\n", encoding="utf-8")
    record = S.resolve(root)
    for kept in (record.systems["cmdb"], record.ticket_mapping):
        assert isinstance(kept, Exception), kept
        assert kept.__traceback__ is None, f"{kept!r} keeps a traceback"
        assert kept.__cause__ is None, f"{kept!r} keeps its cause: {kept.__cause__!r}"
        assert kept.__context__ is None, f"{kept!r} keeps its context: {kept.__context__!r}"


def _validate(tmp_path: Path, extra: str) -> list[tuple[str, str]]:
    from defender.skills.connect import validate_scaffold

    settings = tmp_path / "settings"
    cfg = settings / "systems" / "mysys" / "config.env"
    cfg.parent.mkdir(parents=True)
    cfg.write_text('MYSYS_URL_BASE="http://mysys:8080"\nMYSYS_TRANSPORT="docker-exec"\n'
                   'MYSYS_DOCKER_CONTEXT="ctx"\n' + extra, encoding="utf-8")
    report = validate_scaffold.Report()
    validate_scaffold.check_config(report, settings, "mysys")
    return report.rows


@pytest.mark.parametrize("extra", [
    'export MYSYS_API_TOKEN="sk-live-9f8e7d6c5b4a3f2e1d0c"\n',
    'MYSYS_PASSWORD="hunter2-live"\nMYSYS_PASSWORD=""\n',
    'MYSYS_TOKEN_SECRET_REF="ghp-AbC!d3f@xyz"\nMYSYS_TOKEN_SECRET_REF=""\n',
], ids=["export line", "overridden duplicate", "overridden reference"])
def test_validator_finds_secrets_on_lines_the_run_ignores(tmp_path, extra):
    """A secret on an `export` line, or on a line a later duplicate overrides, is ignored by the
    run but still sits in the tracked file: the validator FAILs it and does not also claim the
    file carries no inline secrets."""
    rows = _validate(tmp_path, extra)
    assert any(s == "FAIL" for s, _ in rows), rows
    assert ("PASS", "config.env carries no inline secrets") not in rows, rows


def test_validator_no_pass_beside_a_pasted_reference(tmp_path):
    """A reference holding a pasted value FAILs, and the report does not also say the file
    carries no inline secrets."""
    rows = _validate(tmp_path, 'MYSYS_TOKEN_SECRET_REF="ghp-AbC!d3f@xyz"\n')
    assert any(s == "FAIL" and "not hold a value" in m for s, m in rows), rows
    assert ("PASS", "config.env carries no inline secrets") not in rows, rows


@pytest.mark.parametrize("name", ["secrets.env", "secrets.env.new", "secrets.env.old",
                                  ".secrets.env.0a1b2c"])
def test_rotation_leftovers_are_git_ignored(name):
    """Every file a secrets rotation can leave in a tenant's settings folder is ignored, not only
    the file itself; a system's config.env is not."""
    repo = S.REPO_ROOT
    rel = f"knowledge/tenants/acme/settings/{name}"
    ignored = subprocess.run(["git", "-C", str(repo), "check-ignore", "--no-index", "-q", rel],
                             check=False).returncode == 0
    assert ignored, f"{rel} is not git-ignored"
    cfg = "knowledge/tenants/acme/settings/systems/cmdb/config.env"
    assert subprocess.run(["git", "-C", str(repo), "check-ignore", "--no-index", "-q", cfg],
                          check=False).returncode == 1, "config.env is ignored"

def _raised(fn, *args, **kw):
    try:
        fn(*args, **kw)
    except Exception as exc:  # noqa: BLE001 — the test inspects whatever was raised
        return exc
    return None

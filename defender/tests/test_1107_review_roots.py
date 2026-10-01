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


def _run_inner(argv: list[str], env: dict[str, str], tmp_path: Path) -> list[str]:
    """Run the in-container half of a recorded `docker exec … sh -c <script> -- <args>` with a
    fake `curl` that prints its argv, and return what curl received."""
    fakebin = tmp_path / "incontainer"
    fakebin.mkdir(exist_ok=True)
    curl = fakebin / "curl"
    curl.write_text(f"#!{sys.executable}\nimport json, sys\nprint(json.dumps(sys.argv[1:]))\n",
                    encoding="utf-8")
    curl.chmod(0o755)
    inner = argv[argv.index("sh"):]
    proc = subprocess.run(inner, capture_output=True, text=True, check=True,
                          env={"PATH": f"{fakebin}{os.pathsep}{os.environ['PATH']}", **env})
    return json.loads(proc.stdout)


def test_a_placed_secret_reaches_a_header(tmp_path):
    """`{{NAME}}` in a header value is the declared secret NAME, delivered through the child's
    environment: curl receives the value in its -H, the docker argv never carries it, and the
    literal parts of the header are not shell-expanded."""
    value = "tok-header-1156"
    record = _secret_tenant(tmp_path, "hdr", {"X_TOKEN": value})
    shim = S.DockerShim(tmp_path / "shim", [S.answer("{}", "200")])
    ctx = _ctx(record, tmp_path, shim)

    transport.docker_exec_curl(
        ctx, "bastion-hdr", "http://cmdb-hdr:8080/x", system="cmdb", secrets=("X_TOKEN",),
        headers={"Authorization": "Bearer {{X_TOKEN}}", "X-Lit": "$(echo pwned) `id` $HOME"})

    (call,) = shim.calls()
    assert all(value not in a for a in call["argv"]), "the secret is on the docker argv"
    forwarded = {k: v for k, v in call["env"].items() if k.startswith(transport.SECRET_ENV_PREFIX)}
    curl_argv = _run_inner(call["argv"], forwarded, tmp_path)
    assert f"Authorization: Bearer {value}" in curl_argv, curl_argv
    assert "X-Lit: $(echo pwned) `id` $HOME" in curl_argv, curl_argv


def test_auth_keeps_container_expansion_and_takes_a_secret(tmp_path):
    """`auth` still expands a container's own `${VAR}` in the container (the elastic read path),
    and `{{NAME}}` in it is a placed secret."""
    value = "pw-auth-1156"
    record = _secret_tenant(tmp_path, "ath", {"SVC_PASS": value})
    shim = S.DockerShim(tmp_path / "shim", [S.answer("{}", "200")])
    ctx = _ctx(record, tmp_path, shim)

    transport.docker_exec_curl(ctx, "b", "http://cmdb-ath:8080/x", system="cmdb",
                               auth="elastic:${ELASTIC_PASSWORD}")
    transport.docker_exec_curl(ctx, "b", "http://cmdb-ath:8080/x", system="cmdb",
                               secrets=("SVC_PASS",), auth="svc:{{SVC_PASS}}")

    legacy, placed = shim.calls()
    assert "elastic:container-pw" in _run_inner(
        legacy["argv"], {"ELASTIC_PASSWORD": "container-pw"}, tmp_path)
    forwarded = {k: v for k, v in placed["env"].items()
                 if k.startswith(transport.SECRET_ENV_PREFIX)}
    assert f"svc:{value}" in _run_inner(placed["argv"], forwarded, tmp_path)


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
    """The box writes a success receipt, then the run dies — in the investigation, or in the
    scrub (RunTainted). The receipt is gone once the lifecycle unwinds, so a re-render of the
    crashed run shows no ticket line the host never wrote."""
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
            stop_box=lambda _box: None, scrub=scrub)

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


def _raised(fn, *args, **kw):
    try:
        fn(*args, **kw)
    except Exception as exc:  # noqa: BLE001 — the test inspects whatever was raised
        return exc
    return None

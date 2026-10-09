"""PR #1156 review — the five root causes behind eleven of its findings, one guard each.

1. How a system is reached is never guessed, and a missing Kibana container is a health-check
   RESULT, not a fault that discards the Elasticsearch answer and trips the breaker.
2. No settings fault names a host path. (Its other half — a stored fault is never re-raised as the
   same object — guarded the branch's elastic stager, retired with cluster staging in #1224.)
3. Every settings file is read one way: capped, single-linked, no-follow at the leaf, and split
   on the same line endings the connect validator reads with.
4. (Secret delivery — one read of `secrets.env`, `{{NAME}}` header slots — moved to #1163.)
5. A receipt the box planted does not survive the run that planted it, however the run ends.

Each test fails on 755177b6 (the PR head these fixes land on).
"""
from __future__ import annotations

import json
import os
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
# 2 — faults: worded without the host path.
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


# ======================================================================================
# 3 — one way to read a settings file.
# ======================================================================================

def test_lone_cr_line_endings_parse_as_lines(tmp_path):
    """A config.env written with lone-CR line endings parses line by line, the way the connect
    validator (universal newlines) reads it."""
    from defender.runtime.tenant_settings import parse_env

    assert parse_env("A=1\rB=2\r\nC=3\n") == {"A": "1", "B": "2", "C": "3"}
    assert parse_env("A=x\x0cy\n") == {"A": "x\x0cy"}, "only CR/LF end a line, as in the validator"

    root, folder = _tenant(tmp_path, "crx")
    text = S.config_path(folder, "cmdb").read_text(encoding="utf-8").replace("\n", "\r")
    S.write_config(folder, "cmdb", text)
    record = S.resolve(root)
    assert record.systems["cmdb"]["CMDB_TRANSPORT"] == S.DOCKER_EXEC
    assert record.systems["cmdb"]["CMDB_URL_BASE"] == "http://cmdb-crx:8080"


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
    run-dir readers do, rather than reading another file's bytes."""
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
    """A settings file replaced by write-then-rename while a read has it open: the reader sees
    its link count drop to 0, and that is still a plain file to read — the repo's one rule
    (`_io.is_plain_entry`) refuses more than one name, never zero."""
    from defender.runtime import tenant_settings

    path = tmp_path / "config.env"
    path.write_text("A=1\n", encoding="utf-8")
    fd = os.open(path, os.O_RDONLY)
    try:
        path.unlink()
        assert os.fstat(fd).st_nlink == 0
        assert tenant_settings.read_plain_fd(fd) == b"A=1\n"
    finally:
        os.close(fd)


# ======================================================================================
# 5 — the receipt is out of the box's reach (third review: it moved beside the run dir).
# ======================================================================================

def test_the_receipt_lives_beside_the_run_dir_where_the_box_cannot_reach(tmp_path):
    """The receipt is a sidecar in the runs base, never inside the run dir the box is root on.
    Whatever the box leaves in the run dir — a directory or a forged success at the old in-tree
    name — neither blocks the host's write nor reaches the page."""
    from defender.scripts.case_history import ticket_writer
    from defender.scripts.visualize import visualize_run

    run_dir = tmp_path / "runs" / "run-1"
    run_dir.mkdir(parents=True)
    path = S.receipt_path(run_dir)
    assert path.parent == run_dir.parent, f"the receipt is not beside the run dir: {path}"
    (run_dir / "ticket_write.json").mkdir()
    (run_dir / "ticket_write.json" / "x").write_text(json.dumps(
        {"key": "SOC-FORGED", "status": "commented", "url": None, "ok": True, "reason": None}),
        encoding="utf-8")
    ticket_writer._write_receipt(run_dir, None, "SOC-1", ticket_writer.RECEIPT_ERROR, "REASON-1")
    assert S.receipt(run_dir) == {"key": "SOC-1", "status": ticket_writer.RECEIPT_ERROR,
                                  "url": None, "ok": False, "reason": "REASON-1"}
    line = visualize_run.render_ticket_line(run_dir)
    assert "SOC-1" in line, line
    assert "REASON-1" in line, line
    assert "SOC-FORGED" not in line, line


def test_deeply_nested_receipt_is_unreadable_at_any_depth(tmp_path):
    """The page decodes the receipt with the repo's bounded JSON loader: a receipt
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


def _raised(fn, *args, **kw):
    try:
        fn(*args, **kw)
    except Exception as exc:  # noqa: BLE001 — the test inspects whatever was raised
        return exc
    return None


# ======================================================================================
# Third review: a verb over no record, env parameters, unreadable settings, one prefix.
# ======================================================================================

def test_a_verb_context_over_no_tenant_record_is_refused():
    """The old `settings_dir: Path` refused None at construction; the record field, typed loosely
    to dodge a circular import, must refuse it too, or the verb fails later inside the adapter."""
    from pydantic import ValidationError

    from defender.runtime.verbs import VerbContext

    with pytest.raises(ValidationError, match="tenant record"):
        VerbContext(defender_dir=S.DEFENDER, run_dir=S.DEFENDER, env={}, tenant=None)


def _env_lint():
    import importlib.util
    import sys

    path = S.REPO_ROOT / "scripts/lint/lint_tenant_env_reads.py"
    spec = importlib.util.spec_from_file_location("lint_tenant_env_reads_review3", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.parametrize(("src", "flagged"), [
    ("def f(*, tenant, env):\n    return env.get('CASE_HISTORY_URL_BASE')\n", True),
    ("def f(env):\n    return env['ELASTICSEARCH_URL']\n", True),
    ("def f(env):\n    return 'X' in env\n", True),
    ("import subprocess\n\ndef f(env):\n    subprocess.run(['true'], env=dict(env))\n", False),
], ids=["kw-only .get", "positional subscript", "in test", "handed to a child"])
def test_env_lint_follows_a_parameter_named_env(tmp_path, src, flagged):
    """The run's environment arrives as a parameter named `env` in the swept trees (the ticket
    writer, lead-zero): a read off it is a finding; handing it to a child is not."""
    tree = tmp_path / "defender/runtime/lead_zero"
    tree.mkdir(parents=True)
    (tree / "x.py").write_text(src, encoding="utf-8")
    assert _env_lint().main(["--root", str(tmp_path)]) == (1 if flagged else 0)


def _two_systems(tmp_path: Path) -> Path:
    settings = tmp_path / "settings"
    for name in ("alpha", "beta"):
        cfg = settings / "systems" / name / "config.env"
        cfg.parent.mkdir(parents=True)
        cfg.write_text(f'{name.upper()}_URL_BASE="http://{name}:1"\n', encoding="utf-8")
    return settings


def test_an_unlistable_systems_folder_configures_no_system(tmp_path, monkeypatch, caplog):
    """`settings/systems/` that has lost its read permission after acceptance: the resolver
    warns and configures no system, never a raw PermissionError out of run.py. (Tests run as root,
    where permission bits are ignored, so the refusal is induced at the listing call.)"""
    from defender.runtime import tenant_settings as ts

    settings = _two_systems(tmp_path)
    real = Path.iterdir

    def iterdir(self):
        if self == settings / "systems":
            raise PermissionError(13, "Permission denied", str(self))
        return real(self)

    monkeypatch.setattr(Path, "iterdir", iterdir)  # lint-monkeypatch: ok — EACCES cannot be induced as root
    with caplog.at_level("WARNING"):
        systems = ts.read_systems(settings)
    assert dict(systems) == {}
    assert "cannot be listed" in caplog.text
    assert str(tmp_path) not in caplog.text, "the warning names the host path"


def test_an_unexaminable_system_folder_is_that_system_down(tmp_path, monkeypatch):
    """A system folder that cannot be examined (search permission lost on `systems/`) is that
    system's ConfigFault; the other systems still resolve."""
    from defender.runtime import tenant_settings as ts

    settings = _two_systems(tmp_path)
    real = Path.is_dir

    def is_dir(self):
        if self == settings / "systems" / "beta":
            raise PermissionError(13, "Permission denied", str(self))
        return real(self)

    monkeypatch.setattr(Path, "is_dir", is_dir)  # lint-monkeypatch: ok — EACCES cannot be induced as root
    systems = ts.read_systems(settings)
    assert systems["alpha"]["ALPHA_URL_BASE"] == "http://alpha:1"
    assert isinstance(systems["beta"], ConfigFault), systems["beta"]
    assert str(tmp_path) not in str(systems["beta"]), "the fault names the host path"


def test_the_access_lines_are_named_after_the_folder_whatever_the_adapter_prefix():
    """An adapter may name its keys with its own prefix; the access lines are always named after
    the system folder. The docker transport judges those two keys (`load_config` does not: a
    directly-reached system declares none), so access lines spelled with the adapter's prefix are
    refused at the first docker call, naming the folder-named key."""
    from types import SimpleNamespace

    from defender.runtime.tenant_settings import SystemConfig
    from defender.runtime.verbs import VerbContext

    entry = SystemConfig({"MY_SYS_TRANSPORT": "docker-exec", "MY_SYS_DOCKER_CONTEXT": "ctx-a",
                          "MYPFX_URL_BASE": "http://mysys:1", "MYPFX_TIMEOUT_SEC": "5"})
    ctx = VerbContext(defender_dir=S.DEFENDER, run_dir=S.DEFENDER, env={},
                      tenant=SimpleNamespace(systems={"my-sys": entry}))
    assert transport.load_config(ctx, "my-sys", "MYPFX", ("URL_BASE", "TIMEOUT_SEC")) == {
        "URL_BASE": "http://mysys:1", "TIMEOUT_SEC": "5"}
    assert transport.docker_context(ctx, "my-sys") == "ctx-a"
    lacking = SimpleNamespace(systems={"my-sys": SystemConfig({
        "MYPFX_TRANSPORT": "docker-exec", "MYPFX_DOCKER_CONTEXT": "ctx-a",
        "MYPFX_URL_BASE": "http://mysys:1", "MYPFX_TIMEOUT_SEC": "5"})})
    ctx = VerbContext(defender_dir=S.DEFENDER, run_dir=S.DEFENDER, env={}, tenant=lacking)
    with pytest.raises(ConfigFault, match="MY_SYS_TRANSPORT"):
        transport.docker_context(ctx, "my-sys")

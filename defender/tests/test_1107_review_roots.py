"""PR #1156 review — the five root causes behind eleven of its findings, one guard each.

1. How a system is reached is never guessed, and a missing Kibana container is a health-check
   RESULT, not a fault that discards the Elasticsearch answer and trips the breaker.
2. A stored fault is never re-raised as the same object, and no settings fault names a host path.
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

"""Settings reading: no host path in faults, one capped no-follow reader, receipts live beside the run dir, health checks are data."""
from __future__ import annotations

from defender.tests.support.shared.contracts._spec1077 import fixture_run as _fixture_run_1165
from defender.tests.support.shared._fixture_uuid import fixture_uuid

import json
import os
from pathlib import Path

import pytest

from defender.kit import transport
from defender.kit.access import AccessDeclaration
from defender.integrations import elastic_adapter
from defender.kit.faults import ConfigFault
from defender.kit.settings import NOT_CONFIGURED
from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S

#: #1366 DC6: a record's fault is located "system <s> settings" (never a host path or the retired file).
def _locator(system: str) -> str:
    return f"system {system} settings"


def _tenant(tmp_path: Path, marker: str, **kw) -> tuple[Path, Path]:
    root = tmp_path / marker
    return root, S.plant(root, marker=marker, **kw)


def _ctx(record, where: Path):
    run_dir = where / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    return S.verb_context(record, run_dir, {})


# test_transport_lanes_require_a_named_system (curl/raw/inspect) is retired: #1391 O1 removed
# those Docker lanes; design r4's retire list names it (test_1107_review_roots.py:33-52).


def test_settings_faults_name_no_host_path(tmp_path):
    from defender.integrations import cmdb_adapter, identity_adapter

    root, folder = _tenant(tmp_path, "pth")
    # #1366 P2/O9: a settings file that is not UTF-8 cannot reach a run; the record that fails the judgement is a placeholder
    S.set_key(folder, "identity", "IDENTITY_TIMEOUT_SEC", "CHANGE-ME")
    S.drop_key(folder, "cmdb", "CMDB_TIMEOUT_SEC")
    S.drop_key(folder, "elastic", "ELASTIC_EVENTS_INDEX")
    record = S.resolve(root)
    ctx = _ctx(record, tmp_path)

    texts = {
        "placeholder": str(_raised(identity_adapter.check_settings, record)),  # the judgement of the stored settings
        "missing key": str(_raised(cmdb_adapter.health_check, ctx)),
        "elastic key": str(_raised(elastic_adapter.query, ctx, native_query="*")),
        "no folder": str(_raised(transport.system_entry, ctx, "no-such-system")),
    }
    located = {"placeholder": "identity", "missing key": "cmdb", "elastic key": "elastic", "no folder": "no-such-system"}
    host = str(tmp_path)
    for arm, text in texts.items():
        assert host not in text, f"{arm}: the fault names the host path: {text!r}"
        # a system with no record at all is "not configured" (kit.settings.NOT_CONFIGURED), also located by the record or not
        ok = (_locator(located[arm]) in text) or (arm == "no folder" and NOT_CONFIGURED in text)
        assert ok, f"{arm}: the fault does not locate the record as {_locator(located[arm])!r}: {text!r}"


def test_lone_cr_line_endings_parse_as_lines(tmp_path):
    """A config.env written with lone-CR line endings parses line by line, the way the connect
    validator (universal newlines) reads it."""
    from defender.tenancy.tenant_settings import parse_env

    assert parse_env("A=1\rB=2\r\nC=3\n") == {"A": "1", "B": "2", "C": "3"}
    assert parse_env("A=x\x0cy\n") == {"A": "x\x0cy"}, "only CR/LF end a line, as in the validator"

    root, folder = _tenant(tmp_path, "crx")
    text = S.config_path(folder, "ticket").read_text(encoding="utf-8").replace("\n", "\r")
    S.write_config(folder, "ticket", text)
    record = S.resolve(root)
    assert record.systems["ticket"]["TICKET_TIMEOUT_SEC"] == "10"
    assert record.systems["ticket"]["TICKET_KEY_PATTERN"] == "CRX-[0-9]+"


# test_oversized_config_is_that_system_down_not_a_crash moved (repair round 7, DC7/R10): the run no longer reads a
# `config.env`, so an oversized one cannot reach it. The only production folder reader left is the operator's
# `set-system` / `import`; its arm is `tenant_1108_p4/test_folder_reader_w_1366.py`.


@pytest.mark.parametrize("alias", ["hard link", "symlink"])
def test_the_config_reader_refuses_an_aliased_file(tmp_path, alias):
    from defender.tenancy import tenant_settings

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
    from defender.tenancy import tenant_settings

    path = tmp_path / "config.env"
    path.write_text("A=1\n", encoding="utf-8")
    fd = os.open(path, os.O_RDONLY)
    try:
        path.unlink()
        assert os.fstat(fd).st_nlink == 0
        assert tenant_settings.read_plain_fd(fd) == b"A=1\n"
    finally:
        os.close(fd)


def test_the_receipt_lives_beside_the_run_dir_where_the_box_cannot_reach(tmp_path):
    from defender.investigation import ticket_writer
    from defender.presentation import visualize_run

    # A run folder's name is its UUID run id.
    run_dir = tmp_path / "runs" / fixture_uuid("run-1")
    run_dir.mkdir(parents=True)
    path = S.receipt_path(run_dir)
    assert path.parent == run_dir.parent, f"the receipt is not beside the run dir: {path}"
    (run_dir / "ticket_write.json").mkdir()
    (run_dir / "ticket_write.json" / "x").write_text(json.dumps(
        {"key": "SOC-FORGED", "status": "commented", "url": None, "ok": True, "reason": None}),
        encoding="utf-8")
    ticket_writer._write_receipt(_fixture_run_1165(run_dir), None, "SOC-1", ticket_writer.RECEIPT_ERROR, "REASON-1")
    assert S.receipt(run_dir) == {"key": "SOC-1", "status": ticket_writer.RECEIPT_ERROR,
                                  "url": None, "ok": False, "reason": "REASON-1"}
    line = visualize_run.render_ticket_line(run_dir)
    assert "SOC-1" in line, line
    assert "REASON-1" in line, line
    assert "SOC-FORGED" not in line, line


def test_deeply_nested_receipt_is_unreadable_at_any_depth(tmp_path):
    """The page decodes the receipt with the repo's bounded JSON loader: a receipt
    with valid fields and one field nested past the limit is unreadable, not a ticket line."""
    from defender.presentation import visualize_run

    run_dir = tmp_path / "run"
    run_dir.mkdir()
    deep = "[" * 500 + "]" * 500
    S.receipt_path(run_dir).write_text(
        '{"key": "SOC-1", "status": "commented", "url": null, "ok": true, "reason": null, '
        f'"x": {deep}}}', encoding="utf-8")
    line = visualize_run.render_ticket_line(run_dir)
    assert visualize_run.RECEIPT_UNREADABLE in line, line


def test_stored_faults_carry_no_traceback_or_cause(tmp_path):
    """A fault the run's record keeps is text only: no traceback (whose frames hold the live structures behind the
    read-only view) and no cause or context (a parser error carrying the declaration's text). The fault production still
    keeps per system is the one for an access declaration that fails `parse_access` (a stored declaration is parsed once
    at run start and kept as its fault, DC6); the settings arm is retired with the stored settings fault (a system's
    settings are always a `SystemConfig`, judged by the adapter's check, repair round 7)."""
    root, folder = _tenant(tmp_path, "sfc")
    access = S.settings_of(folder) / "systems" / "cmdb" / "access.yaml"
    access.write_text("access: [\n", encoding="utf-8")  # unparseable YAML: a parser error underneath the fault
    record = S.resolve(root)
    kept = record.access["cmdb"]
    assert isinstance(kept, ConfigFault), kept
    assert kept.__traceback__ is None, f"{kept!r} keeps a traceback"
    assert kept.__cause__ is None, f"{kept!r} keeps its cause: {kept.__cause__!r}"
    assert kept.__context__ is None, f"{kept!r} keeps its context: {kept.__context__!r}"
    assert "system cmdb access" in str(kept), str(kept)
    assert str(tmp_path) not in str(kept), "the fault names the host path"
    assert isinstance(record.access["identity"], AccessDeclaration), "a sibling's declaration went down with it"


def _raised(fn, *args, **kw):
    try:
        fn(*args, **kw)
    except Exception as exc:  # noqa: BLE001 — the test inspects whatever was raised
        return exc
    return None


def _two_systems(tmp_path: Path) -> Path:
    settings = tmp_path / "settings"
    for name in ("alpha", "beta"):
        cfg = settings / "systems" / name / "config.env"
        cfg.parent.mkdir(parents=True)
        cfg.write_text(f'{name.upper()}_URL_BASE="http://{name}:1"\n', encoding="utf-8")
    return settings


def test_an_unlistable_systems_folder_configures_no_system(tmp_path, monkeypatch, caplog):
    from defender.tenancy import tenant_settings as ts

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
    from defender.tenancy import tenant_settings as ts

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

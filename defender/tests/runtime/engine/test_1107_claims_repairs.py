"""Regression tests for settings-reader findings: each fails without its fix."""
from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

from defender.tenancy import tenant_settings as ts
from defender.integrations import _stub_transport as transport
from defender.investigation import ticket_writer
from defender.presentation import visualize_run
from defender.tests.support.shared.filesystem import _spec1047
from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S

REPO = Path(__file__).resolve().parents[4]


def test_parse_env_splits_on_newline_only():
    # \x0c, \x1c and \x85 are not line ends of a config.env: the value is kept whole.
    assert ts.parse_env("A=x\x0cB=y\n") == {"A": "x\x0cB=y"}
    assert ts.parse_env("A=x\x85y\r\nB=z\r\n") == {"A": "x\x85y", "B": "z"}


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs mkfifo")
def test_a_fifo_at_a_config_path_is_a_fault_not_a_hang(tmp_path):
    fifo = tmp_path / "config.env"
    os.mkfifo(fifo)
    with pytest.raises(S.config_fault()):
        ts.read_env_file(fifo, shown="the tenant's settings/systems/x/config.env")
    # The case-record file's FIFO arm is retired, not moved: acceptance's special-file walk refuses
    # a FIFO anywhere in a tenant's knowledge (pinned by `tenancy/tenant_1120_piece1/
    # test_1120_accept_tenant.py::test_1120_accept_tenant_refuses_a_fifo_socket_or_device_inside_
    # either_half_without_opening_it`), and no export or run copy can hold one. The leg reads the
    # run-start record (D-18), so it never re-reads the file.


def test_huge_timeout_is_a_config_fault(tmp_path):
    root = tmp_path / "t"
    folder = S.plant(root)
    S.set_key(folder, "cmdb", "CMDB_TIMEOUT_SEC", "9" * 5000)
    record = S.resolve(root)
    ctx = S.verb_context(record, tmp_path / "run", {})
    with pytest.raises(S.config_fault()):
        transport.load_config(ctx, "cmdb", "CMDB")


@pytest.mark.parametrize("bomb", ["[" * 200000, '{"a":' * 100000])
def test_a_nested_receipt_renders_unreadable_not_a_crash(tmp_path, bomb):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    S.receipt_path(run_dir).write_text(bomb, encoding="utf-8")
    assert visualize_run.RECEIPT_UNREADABLE in visualize_run.render_ticket_line(run_dir)


def test_a_raising_record_step_writes_an_error_receipt(tmp_path, monkeypatch):
    def boom(*_a, **_k):
        raise PermissionError(13, "denied")

    monkeypatch.setattr(ticket_writer, "_post_comment", boom)  # lint-monkeypatch: ok — the seam is a private step with no deps hook; the test needs it to raise
    root = tmp_path / "tenants"
    S.plant(root)
    record = S.resolve(root)
    run_dir = _spec1047.closed_run_dir(tmp_path / "run")
    S.receipt_path(run_dir).write_text(
        json.dumps({"key": "K-1", "status": "commented", "url": None, "ok": True,
                    "reason": None}), encoding="utf-8")
    S.record_step(run_dir, record, env={})
    got = S.receipt(run_dir)
    assert got is not None, "the raising step left no receipt"
    assert got["ok"] is False, got
    assert got["status"] == "error", got
    assert "PermissionError" in got["reason"], got
    assert "denied" not in got["reason"], got


def _lint():
    path = REPO / "tooling/lint/lint_tenant_env_reads.py"
    spec = importlib.util.spec_from_file_location("lint_tenant_env_reads_1107", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.parametrize("src", [
    "def f(ctx):\n    env: dict = ctx.env\n    return env.get('A')\n",
    "def f(ctx):\n    return (e := ctx.env)['A']\n",
])
def test_lint_follows_annotated_and_walrus_bindings(tmp_path, src):
    tree = tmp_path / "defender/integrations"
    tree.mkdir(parents=True)
    (tree / "x.py").write_text(src, encoding="utf-8")
    assert _lint().main(["--root", str(tmp_path)]) == 1

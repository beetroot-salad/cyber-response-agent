"""Regression tests for the claims adversary's findings on #1107: each one fails without its fix."""
from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

from defender.runtime import tenant_settings as ts
from defender.scripts.adapters import _stub_transport as transport
from defender.scripts.case_history import case_ticket, ticket_writer
from defender.scripts.visualize import visualize_run
from defender.tests import _spec1047
from defender.tests.tenant_1107_settings import _spec1107 as S

REPO = Path(__file__).resolve().parents[2]


def test_parse_env_splits_on_newline_only():
    # \x0c, \x1c and \x85 are not line ends of a config.env: the value is kept whole.
    assert ts.parse_env("A=x\x0cB=y\n") == {"A": "x\x0cB=y"}
    assert ts.parse_env("A=x\x85y\r\nB=z\r\n") == {"A": "x\x85y", "B": "z"}


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs mkfifo")
def test_a_fifo_at_a_config_path_is_a_fault_not_a_hang(tmp_path):
    fifo = tmp_path / "config.env"
    os.mkfifo(fifo)
    with pytest.raises(S.config_fault()):
        ts.read_env_file(fifo)
    mapping = tmp_path / "mapping.yaml"
    os.mkfifo(mapping)
    with pytest.raises(case_ticket.CaseTicketError):
        case_ticket.load_case_mapping(tmp_path)  # looks for the mapping under `settings`


def test_elastic_transport_with_spaces_is_refused_by_the_view(tmp_path):
    root = tmp_path / "t"
    folder = S.plant(root)
    S.set_key(folder, "elastic", "ELASTIC_TRANSPORT", '" docker-exec "')
    record = S.resolve(root)
    assert isinstance(record.elastic, S.config_fault())


def test_scrub_replaces_the_longer_secret_first():
    assert transport._scrubbed("v=abcdef", ["abc", "abcdef"]) == f"v={transport.SECRET_MARKER}"


def test_huge_timeout_is_a_config_fault(tmp_path):
    root = tmp_path / "t"
    folder = S.plant(root)
    S.set_key(folder, "cmdb", "CMDB_TIMEOUT_SEC", "9" * 5000)
    record = S.resolve(root)
    ctx = S.verb_context(record, tmp_path / "run", {})
    with pytest.raises(S.config_fault()):
        transport.load_config(ctx, "cmdb", "CMDB")


def test_a_mapping_set_cannot_be_edited_through_plain():
    mapping = case_ticket.CaseMapping({"a": {"s": {"x"}}})
    mapping.plain()["a"]["s"].add("MUTATED")
    assert "MUTATED" not in mapping["a"]["s"]


@pytest.mark.parametrize("bomb", ["[" * 200000, '{"a":' * 100000])
def test_a_nested_receipt_renders_unreadable_not_a_crash(tmp_path, bomb):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    S.receipt_path(run_dir).write_text(bomb, encoding="utf-8")
    assert visualize_run.RECEIPT_UNREADABLE in visualize_run.render_ticket_line(run_dir)


def test_a_raising_record_step_clears_a_stale_receipt(tmp_path, monkeypatch):
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
    assert S.receipt(run_dir) is None, "a stale success receipt outlived a raising record step"


def _lint():
    path = REPO / "scripts/lint/lint_tenant_env_reads.py"
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
    tree = tmp_path / "defender/scripts/adapters"
    tree.mkdir(parents=True)
    (tree / "x.py").write_text(src, encoding="utf-8")
    assert _lint().main(["--root", str(tmp_path)]) == 1

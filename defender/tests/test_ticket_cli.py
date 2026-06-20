"""ticket_cli.py read-only adapter — the `--require-closed` scoped-read guard (#338).

The benign judge's closed-only read must refuse a non-closed (in-flight) ticket even
by key. Transport is stubbed, so no docker/network.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from defender.scripts.tools import ticket_cli
from defender.scripts.tools import _stub_transport as transport


def _args(**kw):
    base = dict(key="c", raw=True, require_closed=False)
    base.update(kw)
    return SimpleNamespace(**base)


def test_require_closed_passes_on_closed(monkeypatch, capsys):
    monkeypatch.setattr(transport, "http_get",
                        lambda c, p, params=None: {"key": "c", "status": "closed",
                                                   "resolution": "benign — r"})
    ticket_cli.cmd_get_ticket(_args(require_closed=True), config={})
    assert '"status": "closed"' in capsys.readouterr().out


def test_require_closed_rejects_open(monkeypatch):
    monkeypatch.setattr(transport, "http_get",
                        lambda c, p, params=None: {"key": "c", "status": "open"})
    with pytest.raises(SystemExit) as e:
        ticket_cli.cmd_get_ticket(_args(require_closed=True), config={})
    assert e.value.code == 1


def test_no_flag_allows_any_status(monkeypatch, capsys):
    # Without --require-closed the adapter is unchanged (open tickets still fetch).
    monkeypatch.setattr(transport, "http_get",
                        lambda c, p, params=None: {"key": "c", "status": "open"})
    ticket_cli.cmd_get_ticket(_args(require_closed=False), config={})
    assert '"status": "open"' in capsys.readouterr().out

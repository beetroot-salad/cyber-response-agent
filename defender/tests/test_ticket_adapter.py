"""ticket_adapter read-only adapter — the `--require-closed` scoped-read guard (#338).

Since #611 ticket_adapter is a VERBS registry (with the one surviving CLI). The guard's seam is now
the verb functions `get_ticket(ctx, key=…, require_closed=…)` and `list_tickets(ctx, status=…,
require_closed=…)` (the old `cmd_get_ticket(args, config)` / `cmd_list_tickets` wrappers are
gone). The refusal of a non-closed ticket now RAISES `UpstreamFault` (a query error the capture
layer maps to exit 1) instead of `SystemExit(1)` — the #338 answer-key guard is unchanged in
substance: the benign judge's closed-only read cannot reach the in-flight (open) ticket even by
key. The verbs RETURN the payload (the capture layer serializes it); they no longer print.

Transport is stubbed, so no docker/network. The CLI↔VERBS dual surface itself is pinned by
`tests/e2e/test_query_tool_611.py::test_ticket_cli_dual_surface_survives`.
"""
from __future__ import annotations

import pytest

from defender.runtime.verbs import VerbContext
from defender.scripts.adapters import _stub_transport as transport
from defender.scripts.adapters import ticket_adapter
from defender.scripts.adapters.faults import UpstreamFault


@pytest.fixture
def ctx(tmp_path):
    """A VerbContext over a throwaway tree; the transport is stubbed, so its config is never
    loaded for real (each test stubs `_config` via `load_config`)."""
    return VerbContext(defender_dir=tmp_path / "defender", run_dir=tmp_path / "run", env={})


@pytest.fixture(autouse=True)
def _stub_config(monkeypatch):
    # `_config(ctx)` → `transport.load_config`; stub it so the verbs reach the (also-stubbed)
    # http layer without a real config file.
    monkeypatch.setattr(transport, "load_config", lambda ctx, system, prefix: {"URL_BASE": "http://x"})  # lint-monkeypatch: ok — the docker-exec-curl transport has no in-process DI seam (this file's established pattern)


def test_require_closed_passes_on_closed(monkeypatch, ctx):
    monkeypatch.setattr(  # lint-monkeypatch: ok — transport has no in-process DI seam (this file's established pattern)
        transport, "http_get_obj",
                        lambda c, cfg, p, params=None: {"key": "c", "status": "closed",
                                                        "resolution": "benign — r"})
    payload = ticket_adapter.get_ticket(ctx, key="c", require_closed=True)
    assert payload["status"] == "closed"


def test_require_closed_rejects_open(monkeypatch, ctx):
    # #338/#611: the refusal of a non-closed ticket is a query error — now raised as UpstreamFault
    # (the capture layer maps it to exit 1), not SystemExit(1). The answer-key guard stands.
    monkeypatch.setattr(transport, "http_get_obj",  # lint-monkeypatch: ok — transport has no in-process DI seam (this file's established pattern)
                        lambda c, cfg, p, params=None: {"key": "c", "status": "open"})
    with pytest.raises(UpstreamFault):
        ticket_adapter.get_ticket(ctx, key="c", require_closed=True)


def test_no_flag_allows_any_status(monkeypatch, ctx):
    # Without require_closed the adapter is unchanged (open tickets still fetch).
    monkeypatch.setattr(transport, "http_get_obj",  # lint-monkeypatch: ok — transport has no in-process DI seam (this file's established pattern)
                        lambda c, cfg, p, params=None: {"key": "c", "status": "open"})
    payload = ticket_adapter.get_ticket(ctx, key="c", require_closed=False)
    assert payload["status"] == "open"


def test_list_require_closed_pins_status_over_widening(monkeypatch, ctx):
    # require_closed forces status=closed even when a (last-wins) status=open tries to widen the
    # list — the scoped read can't reach the in-flight OPEN ticket.
    seen = {}

    def fake_get(c, cfg, path, params=None):
        seen["params"] = params
        return {"tickets": [], "total": 0}

    monkeypatch.setattr(transport, "http_get", fake_get)  # lint-monkeypatch: ok — transport has no in-process DI seam (this file's established pattern)
    ticket_adapter.list_tickets(ctx, status="open", require_closed=True)
    assert seen["params"]["status"] == "closed"


def test_list_no_flag_passes_status_through(monkeypatch, ctx):
    seen = {}

    def fake_get(c, cfg, path, params=None):
        seen["params"] = params
        return {"tickets": [], "total": 0}

    monkeypatch.setattr(transport, "http_get", fake_get)  # lint-monkeypatch: ok — transport has no in-process DI seam (this file's established pattern)
    ticket_adapter.list_tickets(ctx, status="open", require_closed=False)
    assert seen["params"]["status"] == "open"

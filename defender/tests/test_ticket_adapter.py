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
from defender.scripts.adapters.faults import ConfigFault, UpstreamFault

#: Captured before the autouse `_stub_config` fixture swaps it out, so the config tests
#: below can drive the REAL loader against a config file in the throwaway tree.
_REAL_LOAD_CONFIG = transport.load_config


@pytest.fixture
def ctx(tmp_path):
    """A VerbContext over a throwaway tree; the transport is stubbed, so its config is never
    loaded for real (each test stubs `_config` via `load_config`)."""
    return VerbContext(defender_dir=tmp_path / "defender", run_dir=tmp_path / "run", env={})


@pytest.fixture(autouse=True)
def _stub_config(monkeypatch):
    # `_config(ctx)` → `transport.load_config`; stub it so the verbs reach the (also-stubbed)
    # http layer without a real config file. It serves whatever key set the adapter asks for,
    # so the stub cannot silently diverge from `ticket_adapter.REQUIRED_CONFIG_KEYS`.
    def _fake(ctx, system, prefix, required=transport.REQUIRED_CONFIG_KEYS_TEMPLATE):
        return {"URL_BASE": "http://x", **{k: f"stub-{k}" for k in required if k != "URL_BASE"}}

    monkeypatch.setattr(transport, "load_config", _fake)  # lint-monkeypatch: ok — the docker-exec-curl transport has no in-process DI seam (this file's established pattern)


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


# ── the key grammar as REQUIRED environment config (#684) ───────────────────────────────


def _write_config(ctx, **values) -> None:
    d = ctx.defender_dir / "knowledge" / "environment" / "systems" / "ticket"
    d.mkdir(parents=True, exist_ok=True)
    (d / "config.env").write_text(
        "\n".join(f'{k}="{v}"' for k, v in values.items()) + "\n", encoding="utf-8",
    )


_BASE_CONFIG = {
    "TICKET_URL_BASE": "http://x",
    "TICKET_BASTION_HOST": "web-1",
    "TICKET_TIMEOUT_SEC": "10",
}


@pytest.fixture
def real_config(monkeypatch):
    """Undo the autouse stub: these tests are ABOUT config loading, so they drive the real
    loader against a config file written into the throwaway tree."""
    monkeypatch.setattr(transport, "load_config", _REAL_LOAD_CONFIG)  # lint-monkeypatch: ok — restores the real function the autouse fixture stubs (this file's established pattern)


def test_key_pattern_verb_serves_the_configured_grammar(ctx, real_config):
    """The store's key grammar is an ENVIRONMENT fact, declared in its own config and served
    as a verb — so every consumer reaches it through the one registry seam, and swapping the
    environment for a tracker with another key vocabulary is a config edit, not a code
    change. The judge's closed-ticket screen (#672 Fork A) is the consumer."""
    _write_config(ctx, **_BASE_CONFIG, TICKET_KEY_PATTERN="SOC-[0-9]+")
    assert ticket_adapter.key_pattern(ctx) == "SOC-[0-9]+"
    assert ticket_adapter.VERBS["key-pattern"] is ticket_adapter.key_pattern


def test_key_pattern_is_required_config_and_absence_takes_the_system_down(ctx, real_config):
    """KEY_PATTERN is REQUIRED, on the same rule as URL_BASE: absent means the system is down
    — a ConfigFault (infra, exit 2) — never a silent built-in default. Because it is required
    at `_config`, the absence fails the WHOLE ticket surface closed, not just the screen that
    reads it: a consumer cannot get a store read out of an environment that has not said what
    its keys look like, and the fault names the missing key so the fix is obvious."""
    _write_config(ctx, **_BASE_CONFIG)  # no TICKET_KEY_PATTERN
    with pytest.raises(ConfigFault, match="TICKET_KEY_PATTERN"):
        ticket_adapter.key_pattern(ctx)
    with pytest.raises(ConfigFault, match="TICKET_KEY_PATTERN"):
        ticket_adapter.get_ticket(ctx, key="SOC-1042", require_closed=True)
    assert ConfigFault("x").exit_code == 2, "a missing environment fact is infra, not agent-fixable"


def test_run_env_overrides_the_declared_grammar(ctx, real_config):
    """The RUN's env overrides the file for the key grammar exactly as it does for every other
    config value (the ops-convenience lane load_config already documents) — so a CI run or a
    per-run override can point at a different store's vocabulary without editing the tree."""
    _write_config(ctx, **_BASE_CONFIG, TICKET_KEY_PATTERN="SOC-[0-9]+")
    over = VerbContext(defender_dir=ctx.defender_dir, run_dir=ctx.run_dir,
                       env={"TICKET_KEY_PATTERN": "CASE-[0-9]+"})
    assert ticket_adapter.key_pattern(over) == "CASE-[0-9]+"

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

import urllib.parse
from pathlib import Path

import pytest

from defender.runtime.verbs import VerbContext
from defender.scripts.adapters import _stub_transport as transport
from defender.scripts.adapters import ticket_adapter
from defender.scripts.adapters.faults import ConfigFault, UpstreamFault

_REAL_LOAD_CONFIG = transport.load_config


@pytest.fixture
def ctx(tmp_path):
    """A VerbContext over a throwaway tree; the transport is stubbed, so its config is never
    loaded for real (each test stubs `_config` via `load_config`)."""
    return VerbContext(defender_dir=tmp_path / "defender", run_dir=tmp_path / "run", env={})


@pytest.fixture(autouse=True)
def _stub_config(monkeypatch):
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
    monkeypatch.setattr(transport, "http_get_obj",  # lint-monkeypatch: ok — transport has no in-process DI seam (this file's established pattern)
                        lambda c, cfg, p, params=None: {"key": "c", "status": "open"})
    with pytest.raises(UpstreamFault):
        ticket_adapter.get_ticket(ctx, key="c", require_closed=True)


def test_no_flag_allows_any_status(monkeypatch, ctx):
    monkeypatch.setattr(transport, "http_get_obj",  # lint-monkeypatch: ok — transport has no in-process DI seam (this file's established pattern)
                        lambda c, cfg, p, params=None: {"key": "c", "status": "open"})
    payload = ticket_adapter.get_ticket(ctx, key="c", require_closed=False)
    assert payload["status"] == "open"


def test_list_require_closed_pins_status_over_widening(monkeypatch, ctx):
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
    _write_config(ctx, **_BASE_CONFIG)
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




@pytest.mark.parametrize(
    ("key", "expect_path"),
    [
        ("SOC-1042", "/tickets/SOC-1042"),
        ("20260720T0000Z-sshd-672", "/tickets/20260720T0000Z-sshd-672"),
        ("SOC 1", "/tickets/SOC%201"),
        ("SOC-1?x=1", "/tickets/SOC-1%3Fx%3D1"),
        ("SOC-1#frag", "/tickets/SOC-1%23frag"),
        ("a/b", "/tickets/a%2Fb"),
        ("../SOC-1", "/tickets/..%2FSOC-1"),
        ("SOC-1\r\nHost: evil", "/tickets/SOC-1%0D%0AHost%3A%20evil"),
        ("SOC-λ42", "/tickets/SOC-%CE%BB42"),
    ],
    ids=["plain", "minted-case-id", "space", "query-delimiter", "fragment", "separator",
         "dotdot", "crlf", "non-ascii"],
)
def test_get_ticket_percent_encodes_the_key_into_the_path(monkeypatch, ctx, key, expect_path):
    """The key is encoded into `/tickets/{key}`, so no key value can RESHAPE the request:
    `?` cannot start a query string, `#` cannot start a fragment, `/` cannot add a path
    segment, and CR-LF cannot break a header. The keys that need no encoding — the minted
    case id and the seeded `SOC-<n>` — pass through byte-identical, so this is not a
    behavior change for any key the store actually holds.

    This is what makes #672's key screen defense-in-depth rather than the only thing
    standing between a model-chosen string and a reshaped request (#684): the screen still
    refuses these keys first, with retry-class feedback, but the transport is now safe
    whether or not a consumer screens."""
    seen = {}

    def fake_get_obj(c, cfg, path, params=None):
        seen["path"] = path
        return {"key": key, "status": "closed"}

    monkeypatch.setattr(transport, "http_get_obj", fake_get_obj)  # lint-monkeypatch: ok — transport has no in-process DI seam (this file's established pattern)
    ticket_adapter.get_ticket(ctx, key=key)
    assert seen["path"] == expect_path


def test_reader_fetches_the_key_the_writer_minted(monkeypatch, ctx):
    """The reader asks for exactly the URL the writer wrote to, so a key the writer can mint
    is a key this reader can fetch. `ticket_writer` has always encoded the keys it mints
    (`urllib.parse.quote(case_id, safe="")`, ticket_writer.py:189/217/310); until #684 this
    reader interpolated raw, so for any case id needing encoding the two sides disagreed —
    the ticket was stored under one URL and requested at another, and the read 404'd on a
    ticket that exists.

    Both halves are bound so the pair cannot drift apart again: the reader's built path is
    compared against the writer's OWN encoding of the same id, and the writer is pinned at
    the source to still encode that way. Change either side alone and this fails."""
    from defender.scripts.case_history import ticket_writer

    seen = {}

    def fake_get_obj(c, cfg, path, params=None):
        seen["path"] = path
        return {"key": "k", "status": "closed"}

    monkeypatch.setattr(transport, "http_get_obj", fake_get_obj)  # lint-monkeypatch: ok — transport has no in-process DI seam (this file's established pattern)
    for case_id in ("20260720T0000Z-sshd-672", "SOC-1042", "case id/with space", "SOC-λ42"):
        ticket_adapter.get_ticket(ctx, key=case_id)
        writers_url = f"/tickets/{urllib.parse.quote(case_id, safe='')}"
        assert seen["path"] == writers_url, (
            f"the reader asks for {seen['path']} but the writer stores {case_id!r} at "
            f"{writers_url} — the two sides encode differently"
        )

    writer_src = Path(ticket_writer.__file__).read_text(encoding="utf-8")
    assert 'quote(case_id, safe="")' in writer_src, (
        "ticket_writer no longer encodes the keys it mints the way this test assumes — "
        "re-derive the reader's encoding from what the writer now does"
    )


@pytest.mark.parametrize(
    ("label", "q"),
    [
        ("a;b|c d", "$(reboot) & ../%2e"),
        ("brute-force", "sshd OR root"),
        ("x#frag", "a=b&c=d"),
    ],
    ids=["shell-metachars", "spaces-and-words", "url-delimiters"],
)
def test_list_filters_ride_urlencoded_not_raw(monkeypatch, ctx, label, q):
    """The OTHER half of the symmetry: `list_tickets`' filters reach the verb OPAQUELY —
    verbatim, no screen, #672's deliberate non-clause — and are then URLENCODED into the
    query string by the transport. That encoding is what made "label/q need no screen"
    true; it was asserted in prose across #672's artifacts and pinned nowhere, so this test
    makes it executable. The filter values arrive at `http_get` unchanged, and no
    metacharacter survives into the built URL as a delimiter."""
    seen = {}

    def fake_request(c, cfg, url, method="GET", body=None):
        seen["url"] = url
        return {"tickets": [], "total": 0}

    monkeypatch.setattr(transport, "_request", fake_request)  # lint-monkeypatch: ok — transport has no in-process DI seam (this file's established pattern)
    monkeypatch.setattr(transport, "load_config", lambda *a, **k: {"URL_BASE": "http://x"})  # lint-monkeypatch: ok — same
    ticket_adapter.list_tickets(ctx, label=label, q=q, require_closed=True)

    url = seen["url"]
    base, _, query = url.partition("?")
    assert base == "http://x/tickets", "a filter value escaped into the PATH"
    parsed = urllib.parse.parse_qs(query, strict_parsing=True)
    assert parsed["label"] == [label], "the label did not survive the round trip verbatim"
    assert parsed["q"] == [q], "the q value did not survive the round trip verbatim"
    assert parsed["status"] == ["closed"], "require_closed's pin left the wire"
    assert len(query.split("&")) == len(parsed), "a filter value injected a query parameter"

"""ticket_adapter verbs: the --require-closed scoped-read guard (#338: a non-closed ticket raises UpstreamFault so a closed-only reader cannot reach the in-flight ticket), key grammar, percent-encoding, and case_opened_at. Transport is stubbed."""
from __future__ import annotations

import urllib.parse

import pytest

from defender.systems.verbs import VerbContext
from defender.kit import transport
from defender.integrations import ticket_adapter
from defender.kit.faults import ConfigFault, ConfinementFault, TransportFault, UpstreamFault
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.tenancy import _tenants1106 as T1106
from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S1107

#: Captured before the autouse `_stub_config` fixture swaps it out, so the config tests
#: below can drive the REAL loader against a config file in the throwaway tree.
_REAL_LOAD_CONFIG = transport.load_config


@pytest.fixture
def ctx(tmp_path):
    """A VerbContext carrying the playground tenant's record; the autouse stub replaces
    `load_config`, so no config is read for real."""
    return T1106.verb_context(tmp_path / "defender", tmp_path / "run", {})


@pytest.fixture(autouse=True)
def _stub_config(monkeypatch):
    _SHAPED = {"TIMEOUT_SEC": "10"}

    def _fake(ctx, system, prefix, required=transport.REQUIRED_CONFIG_KEYS_TEMPLATE, **_kw):
        return {k: _SHAPED.get(k, f"stub-{k}") for k in required}

    monkeypatch.setattr(transport, "load_config", _fake)  # lint-monkeypatch: ok — the shared transport has no in-process DI seam (this file's established pattern)


class _Wire:
    """The transport's one send to the proxy, replaced: each request's method and URL, and the
    answer handed back."""

    def __init__(self) -> None:
        self.sent: list[tuple[str, str]] = []
        self.answer: object = {"key": "c", "status": "closed"}

    def __call__(self, ctx, url, *, system, method, body, timeout_sec, write=False, **_kw):
        self.sent.append((method, url))
        return {} if write else self.answer

    def paths(self) -> list[str]:
        return [urllib.parse.urlsplit(url).path for _, url in self.sent]

    def queries(self) -> list[dict[str, list[str]]]:
        return [urllib.parse.parse_qs(urllib.parse.urlsplit(url).query, strict_parsing=True)
                for _, url in self.sent]


@pytest.fixture
def wire(monkeypatch):
    sent = _Wire()
    monkeypatch.setattr(transport, "_proxy_request", sent)  # lint-monkeypatch: ok — transport has no in-process DI seam (this file's established pattern)
    return sent


def test_require_closed_passes_on_closed(wire, ctx):
    wire.answer = {"key": "c", "status": "closed", "resolution": "benign — r"}
    payload = ticket_adapter.get_ticket(ctx, key="c", require_closed=True)
    assert payload["status"] == "closed"


def test_require_closed_rejects_open(wire, ctx):
    # A non-closed ticket is a query error: `UpstreamFault`, which the capture layer maps to exit 1.
    wire.answer = {"key": "c", "status": "open"}
    with pytest.raises(UpstreamFault):
        ticket_adapter.get_ticket(ctx, key="c", require_closed=True)


def test_no_flag_allows_any_status(wire, ctx):
    # Without require_closed, open tickets still fetch.
    wire.answer = {"key": "c", "status": "open"}
    payload = ticket_adapter.get_ticket(ctx, key="c", require_closed=False)
    assert payload["status"] == "open"


def test_list_require_closed_pins_status_over_widening(wire, ctx):
    # require_closed forces status=closed even when a (last-wins) status=open tries to widen the
    # list — the scoped read can't reach the in-flight OPEN ticket.
    wire.answer = {"tickets": [], "total": 0}
    ticket_adapter.list_tickets(ctx, status="open", require_closed=True)
    assert [q["status"] for q in wire.queries()] == [["closed"]]


def test_list_no_flag_passes_status_through(wire, ctx):
    wire.answer = {"tickets": [], "total": 0}
    ticket_adapter.list_tickets(ctx, status="open", require_closed=False)
    assert [q["status"] for q in wire.queries()] == [["open"]]


# the key grammar as REQUIRED environment config (#684)


_BASE_CONFIG = {
    "TICKET_TIMEOUT_SEC": "10",
}


def _config_ctx(tmp_path, *, env=None, **values) -> VerbContext:
    """A VerbContext whose record is resolved from a tenant planted with `values` as the ticket
    system's whole `config.env`."""
    text = "\n".join(f'{k}="{v}"' for k, v in values.items()) + "\n"
    tenant_id = fixture_uuid("tenant:ticket-config")
    S1107.plant(tmp_path / "tenants", tenant_id, configs={"ticket": text})
    record = S1107.resolve(tmp_path / "tenants", tenant_id)
    return T1106.verb_context(tmp_path / "defender", tmp_path / "run", env or {}, tenant=record)


@pytest.fixture
def real_config(monkeypatch):
    """Undo the autouse stub: these tests are ABOUT config loading, so they drive the real
    loader against a tenant record resolved from a config file planted in a throwaway tenant."""
    monkeypatch.setattr(transport, "load_config", _REAL_LOAD_CONFIG)  # lint-monkeypatch: ok — restores the real function the autouse fixture stubs (this file's established pattern)


def test_key_pattern_verb_serves_the_configured_grammar(tmp_path, real_config):
    ctx = _config_ctx(tmp_path, **_BASE_CONFIG, TICKET_KEY_PATTERN="SOC-[0-9]+")
    assert ticket_adapter.key_pattern(ctx) == "SOC-[0-9]+"
    assert ticket_adapter.VERBS["key-pattern"] is ticket_adapter.key_pattern


def test_key_pattern_is_required_config_and_absence_takes_the_system_down(tmp_path, real_config):
    ctx = _config_ctx(tmp_path, **_BASE_CONFIG)  # no TICKET_KEY_PATTERN
    with pytest.raises(ConfigFault, match="TICKET_KEY_PATTERN"):
        ticket_adapter.key_pattern(ctx)
    with pytest.raises(ConfigFault, match="TICKET_KEY_PATTERN"):
        ticket_adapter.get_ticket(ctx, key="SOC-1042", require_closed=True)
    assert ConfigFault("x").exit_code == 2, "a missing environment fact is infra, not agent-fixable"


def test_run_env_does_not_override_the_declared_grammar(tmp_path, real_config):
    over = _config_ctx(tmp_path, env={"TICKET_KEY_PATTERN": "CASE-[0-9]+"}, **_BASE_CONFIG,
                       TICKET_KEY_PATTERN="SOC-[0-9]+")
    assert ticket_adapter.key_pattern(over) == "SOC-[0-9]+"


# the key/filter encoding symmetry


@pytest.mark.parametrize(
    ("key", "expect_path"),
    [
        ("SOC-1042", "/tickets/SOC-1042"),
        ("20260720T0000Z-sshd-672", "/tickets/20260720T0000Z-sshd-672"),
        ("SOC-λ42", "/tickets/SOC-%CE%BB42"),
        ("SOC:1@x", "/tickets/SOC%3A1%40x"),
    ],
    ids=["plain", "minted-case-id", "non-ascii", "reserved"],
)
def test_get_ticket_percent_encodes_the_key_into_the_path(wire, ctx, key, expect_path):
    """The key is percent-encoded into `/tickets/{key}`."""
    ticket_adapter.get_ticket(ctx, key=key)
    assert wire.paths() == [expect_path]


@pytest.mark.parametrize(
    "key", ["SOC 1", "SOC-1?x=1", "SOC-1#frag", "a/b", "../SOC-1", "SOC-1\r\nHost: evil", "50%"],
    ids=["space", "query-delimiter", "fragment", "separator", "dotdot", "crlf", "escape"])
def test_get_ticket_refuses_a_key_that_is_not_one_path_segment(wire, ctx, key):
    """The agent's key is exactly one path segment or the verb is refused before anything is
    sent, so no key can reshape the request (#1391 r5 T2)."""
    with pytest.raises(ConfinementFault, match="`key`"):
        ticket_adapter.get_ticket(ctx, key=key)
    assert wire.sent == []


def test_reader_fetches_the_key_the_comment_action_writes(wire, ctx):
    """The key is the alert's (the host mints none, #1359): the host's read-back asks for the very
    path segment the comment action posts to, whatever the key's URL-special characters. P3."""
    wire.answer = {"key": "k", "status": "open", "comments": []}
    for key in ("SOC-1042", "SOC#42", "a?b=c", "50%", 'q"uote', "a+b"):
        ticket_adapter.read_case_comments(ctx, key=key)
        ticket_adapter.add_case_comment(ctx, key=key, body="note")
        segment = f"/tickets/{urllib.parse.quote(key, safe='')}"
        read, written = wire.paths()[-2:]
        assert read == segment, f"the reader asks for {read}, not {segment}"
        assert written == f"{segment}/comments", (
            f"the comment action posts to {written}, not {segment}/comments — the two sides "
            "encode the key differently")
    assert [m for m, _ in wire.sent] == ["GET", "POST"] * 6, wire.sent


@pytest.mark.parametrize(
    ("label", "q"),
    [
        ("a;b|c d", "$(reboot) & ../%2e"),
        ("brute-force", "sshd OR root"),
        ("x#frag", "a=b&c=d"),
    ],
    ids=["shell-metachars", "spaces-and-words", "url-delimiters"],
)
def test_list_filters_ride_urlencoded_not_raw(wire, ctx, label, q):
    wire.answer = {"tickets": [], "total": 0}
    ticket_adapter.list_tickets(ctx, label=label, q=q, require_closed=True)

    [(_, url)] = wire.sent
    base, _, query = url.partition("?")
    assert urllib.parse.urlsplit(base).path == "/tickets", "a filter value escaped into the PATH"
    parsed = urllib.parse.parse_qs(query, strict_parsing=True)
    assert parsed["label"] == [label], "the label did not survive the round trip verbatim"
    assert parsed["q"] == [q], "the q value did not survive the round trip verbatim"
    assert parsed["status"] == ["closed"], "require_closed's pin left the wire"
    assert query.count("&") == 2, "a filter value injected a query-parameter separator"


# the case-opened boundary verb


def test_case_opened_at_yields_a_timestamp_and_never_the_record(wire, ctx):
    record = {
        "key": "20260720T0000Z-sshd-672",
        "status": "in_progress",
        "created": "2026-07-20T00:00:00+00:00",
        "summary": "ANSWER-KEY-SUMMARY",
        "description": "ANSWER-KEY-DESCRIPTION",
        "resolution": "ANSWER-KEY-RESOLUTION",
        "comments": [{"author": "soc", "body": "ANSWER-KEY-COMMENT"}],
    }
    wire.answer = record
    out = ticket_adapter.case_opened_at(ctx, key="20260720T0000Z-sshd-672")
    assert out == "2026-07-20T00:00:00+00:00"
    assert isinstance(out, str), "a non-scalar return would let the whole record through"
    for marker in ("SUMMARY", "DESCRIPTION", "RESOLUTION", "COMMENT"):
        assert f"ANSWER-KEY-{marker}" not in out


def test_case_opened_at_reads_the_key_like_every_other_reader(wire, ctx):
    """A reader interpolating the key raw would reopen the request-reshaping hole (#684): the key
    is one encoded segment, and one that is not a segment is refused unsent (#1391 r5 T2)."""
    wire.answer = {"created": "2026-01-01T00:00:00+00:00"}
    ticket_adapter.case_opened_at(ctx, key="SOC:42")
    assert wire.paths() == ["/tickets/SOC%3A42"]
    with pytest.raises(ConfinementFault):
        ticket_adapter.case_opened_at(ctx, key="SOC 42/x?y")
    assert len(wire.sent) == 1


def test_case_opened_at_faults_as_infra_when_the_store_cannot_date_the_case(wire, ctx):
    wire.answer = {"key": "SOC-1", "status": "open"}
    with pytest.raises(TransportFault):
        ticket_adapter.case_opened_at(ctx, key="SOC-1")

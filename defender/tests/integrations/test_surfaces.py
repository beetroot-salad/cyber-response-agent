"""#767 — no model role reaches a ticket write. Since #1391 O1 the ticket store is reached only
through the credential proxy, whose route check is its one guard (#1163 A6): the shipped ticket
declaration admits GETs as reads and the one comment POST as a write, which only the host's
write-back token may make."""
from __future__ import annotations

import json
import re
from pathlib import Path


from defender._paths import PATHS
from defender.systems import verb_dispositions
from defender.kit.access import Route
from defender.tests.support.runtime.engine._spec767 import (
    COMMENTS_SUFFIX,
    TICKETS_PATH,
    TRANSITIONS_SUFFIX,
)

DEFENDER_DIR = PATHS.defender_dir


def _shipped_rows():
    """The committed playground tenant's verb-disposition table."""
    from defender.tests.support.tenancy import _tenants1106 as T1106

    return verb_dispositions.load_dispositions(
        verb_dispositions.dispositions_path(T1106.FIXTURE_SETTINGS))
REPO_ROOT = PATHS.repo_root


def _shipped_ticket_declaration():
    """The committed playground tenant's `ticket` access declaration, parsed by the product.
    #1366 O9: the fixture's `settings/systems/ticket/access.yaml` is gone; the declaration is the
    ticket record the fixture tenant is seeded with (the retired file's text, `R.fixture_records()`)."""
    from defender import tenancy
    from defender.tests.support.tenancy import _systems1366 as R

    return tenancy.parse_access(R.fixture_records().systems["ticket"].access, system="ticket")


SHIPPED_PY = tuple(
    p for p in sorted(DEFENDER_DIR.rglob("*.py"))
    if "tests" not in p.relative_to(DEFENDER_DIR).parts
    and ".venv" not in p.relative_to(DEFENDER_DIR).parts
)


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _shipped_hits(pattern: str) -> dict[str, list[int]]:
    """Every shipped (non-test) source line matching `pattern`, by repo-relative path."""
    rx = re.compile(pattern)
    out: dict[str, list[int]] = {}
    for p in SHIPPED_PY:
        lines = [i for i, line in enumerate(_text(p).splitlines(), 1) if rx.search(line)]
        if lines:
            out[str(p.relative_to(REPO_ROOT))] = lines
    return out


def test_767_no_model_role_reaches_a_ticket_write(tmp_path):
    rows = _shipped_rows()
    for role in sorted(verb_dispositions.KNOWN_ROLES):
        grant = verb_dispositions.grant_for(role, rows)
        for system, verb, verb_class in grant.entries:
            assert verb_class == verb_dispositions.READ_CLASS, (
                f"{role} holds {system}.{verb} at class {verb_class!r}; every shipped verb is "
                "read-class"
            )
            if system == "ticket":
                assert verb in ("health-check", "list-tickets"), (
                    f"{role} holds an unexpected ticket verb {verb!r}"
                )

    declaration = _shipped_ticket_declaration()
    assert declaration.reads == (), (
        f"the ticket declaration admits a non-GET read, which a read token could send: "
        f"{declaration.reads}")
    assert declaration.writes == (Route("POST", f"{TICKETS_PATH}/*{COMMENTS_SUFFIX}"),), (
        f"the ticket declaration admits a write other than the host's one comment: "
        f"{declaration.writes}")

    from defender.investigation.permission.policies import _common

    programs = {g.program for g in _common.reader_grants(tmp_path, DEFENDER_DIR, raw=False)}
    assert programs, "the program set is empty — this assertion would pass over anything"
    for network in ("curl", "wget", "nc", "ncat", "socat", "ssh", "docker", "python3", "sh"):
        assert network not in programs, (
            f"the model's bash program set grants {network!r}: a network-capable program is a "
            "route to the store's write endpoints that no grant table can see"
        )

    policy = json.loads(_text(DEFENDER_DIR / "investigation" / "bash_policy.json"))
    assert set(policy) <= {"version", "read_deny", "_README"}, (
        "bash_policy.json carries a program set, which the `_common.reader_grants` check "
        "above does not see"
    )


def test_767_list_tickets_still_granted_to_gather():
    """The positive control for every reach negative in this file."""
    rows = _shipped_rows()
    by_pair = {d.pair: d for d in rows}
    gather = verb_dispositions.grant_for("gather", rows)

    assert ("ticket", "list-tickets") in {(s, v) for s, v, _ in gather.entries}
    for verb in ("get-ticket", "key-pattern", "case-opened-at"):
        row = by_pair[("ticket", verb)]
        assert row.roles == frozenset(), f"ticket.{verb} is granted to {sorted(row.roles)}"
        assert row.reason, f"ticket.{verb} is granted to nobody with no recorded reason"
    assert _shipped_ticket_declaration().base, "positive control: the shipped declaration parsed"


def test_767_transitions_route_is_not_in_the_ticket_declaration(tmp_path):
    declaration = _shipped_ticket_declaration()
    routes = (*declaration.reads, *declaration.writes)
    assert routes, "positive control: the declaration names the comment write"
    assert not any(r.path.endswith(TRANSITIONS_SUFFIX) for r in routes), (
        f"the ticket declaration names a transitions route: {routes}")

    rows = _shipped_rows()
    for d in rows:
        if d.system == "ticket":
            for word in ("transition", "close"):
                assert word not in d.verb, (
                    f"a lifecycle verb ({d.verb}) entered the grant table: closing is a "
                    "person's act, outside every role"
                )


# Retired by #1391 O1/O2: `test_767_adapter_http_confinement_and_capture_hold` pinned
# `guard_outbound` and the stub systems' read-endpoint allowlist, both deleted (design r4: "the stub
# systems' allowlist entries become dead once Docker goes (A6)"). What the proxy refuses is
# `credential_proxy_1163/test_proxy_scope.py`'s; that each request is captured once is
# `test_query_flow.py::test_1391_o3_each_elastic_request_is_captured_once_and_reaches_the_proxy_once`.


def test_767_query_tool_is_only_ticket_reader(tmp_path):
    """A census of the shipped source."""
    consumers = _shipped_hits(r"(?<!def )\bscreen_(?:list|get|release_list|release_get)\s*\(")
    assert consumers == {}, (
        f"a shipped module screens ticket replies: {consumers}"
    )
    assert not (DEFENDER_DIR / "investigation" / "ticket_screen.py").exists(), (
        "the removed read screen investigation/ticket_screen.py exists"
    )

    forward_dir = DEFENDER_DIR / "learning" / "author" / "verify_forward"
    for p in sorted(forward_dir.rglob("*.py")):
        assert "ticket" not in _text(p).lower(), (
            f"{p.name} reaches the ticket store"
        )

    subprocess_readers = _shipped_hits(r"get-ticket")
    allowed = {
        "defender/integrations/ticket_adapter.py",
        "defender/investigation/query_tool.py",
        "defender/learning/judge/family.py",
    }
    assert set(subprocess_readers) <= allowed, (
        "a shipped module outside the adapter and the query tool names `get-ticket`: "
        f"{sorted(set(subprocess_readers) - allowed)}"
    )

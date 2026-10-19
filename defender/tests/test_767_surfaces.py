"""#767 — no model role reaches a ticket write; the host writer stays inside confinement."""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from defender._paths import PATHS
from defender.runtime import verb_dispositions
from defender.scripts.adapters import confinement
from defender.scripts.adapters.confinement import ConfinementFault
from defender.tests._spec767 import (
    COMMENTS_SUFFIX,
    TICKETS_PATH,
    TRANSITIONS_SUFFIX,
)

DEFENDER_DIR = PATHS.defender_dir


def _shipped_rows():
    """The committed playground tenant's table (#1106 moved it out of `defender/`, and there
    is no per-process cached reader any more)."""
    from defender.tests import _tenants1106 as T1106

    return verb_dispositions.load_dispositions(
        verb_dispositions.dispositions_path(T1106.FIXTURE_SETTINGS))
REPO_ROOT = PATHS.repo_root
URL_BASE = "http://case-history.test"

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
    """o6_no_model_write_reach — NEGATIVE."""
    rows = _shipped_rows()
    for role in sorted(verb_dispositions.KNOWN_ROLES):
        grant = verb_dispositions.grant_for(role, rows)
        for system, verb, verb_class in grant.entries:
            assert verb_class == verb_dispositions.READ_CLASS, (
                f"{role} holds {system}.{verb} at class {verb_class!r} — every shipped verb is "
                "read-class, and a write class is what O6 forbids"
            )
            if system == "ticket":
                assert verb in ("health-check", "list-tickets"), (
                    f"{role} holds an unexpected ticket verb {verb!r}; a write verb in the "
                    "grant table is O6's own failure witness"
                )

    for path in (TICKETS_PATH, f"{TICKETS_PATH}/SOC-1{COMMENTS_SUFFIX}",
                 f"{TICKETS_PATH}/SOC-1{TRANSITIONS_SUFFIX}"):
        with pytest.raises(ConfinementFault):
            confinement.guard_outbound(None, "ticket", f"{URL_BASE}{path}", method="POST")
    with pytest.raises(ConfinementFault):
        confinement.guard_outbound(None, "case-history", f"{URL_BASE}{TICKETS_PATH}",
                                   method="GET")

    from defender.runtime.permission.policies import _common

    programs = {g.program for g in _common.reader_grants(tmp_path, DEFENDER_DIR, raw=False)}
    assert programs, "the program set is empty — this assertion would pass over anything"
    for network in ("curl", "wget", "nc", "ncat", "socat", "ssh", "docker", "python3", "sh"):
        assert network not in programs, (
            f"the model's bash program set grants {network!r}: a network-capable program is a "
            "route to the store's write endpoints that no grant table can see"
        )

    policy = json.loads(_text(DEFENDER_DIR / "runtime" / "bash_policy.json"))
    assert set(policy) <= {"version", "read_deny", "_README"}, (
        "bash_policy.json now carries a program set; D8 re-pointed this demand at "
        "`_common.reader_grants` precisely because it did not (c2)"
    )


def test_767_list_tickets_still_granted_to_gather():
    """o6_read_verb_still_granted — the POSITIVE CONTROL for every reach negative in this
    file."""
    rows = _shipped_rows()
    by_pair = {d.pair: d for d in rows}
    gather = verb_dispositions.grant_for("gather", rows)

    assert ("ticket", "list-tickets") in {(s, v) for s, v, _ in gather.entries}
    for verb in ("get-ticket", "key-pattern", "case-opened-at"):
        row = by_pair[("ticket", verb)]
        assert row.roles == frozenset(), f"ticket.{verb} is granted to {sorted(row.roles)}"
        assert row.reason, f"ticket.{verb} is granted to nobody with no recorded reason"

    confinement.guard_outbound(None, "ticket", f"{URL_BASE}{TICKETS_PATH}", method="GET")
    confinement.guard_outbound(None, "ticket", f"{URL_BASE}{TICKETS_PATH}/SOC-1", method="GET")


def test_767_transitions_route_is_not_on_the_confinement_allowlist(tmp_path):
    """d6_transitions_route_not_confined — NEGATIVE."""
    allowlist = confinement.READ_ENDPOINT_ALLOWLIST["ticket"]
    assert all(method == "GET" for _, method in allowlist), (
        f"the ticket allowlist is no longer GET-only: {allowlist}"
    )
    assert not any(pattern.endswith("transitions") for pattern, _ in allowlist)

    for method in ("POST", "PUT", "PATCH", "DELETE"):
        with pytest.raises(ConfinementFault):
            confinement.guard_outbound(
                None, "ticket", f"{URL_BASE}{TICKETS_PATH}/SOC-1{TRANSITIONS_SUFFIX}",
                method=method,
            )

    rows = _shipped_rows()
    for d in rows:
        if d.system == "ticket":
            for word in ("transition", "close"):
                assert word not in d.verb, (
                    f"a lifecycle verb ({d.verb}) entered the grant table: closing is a "
                    "person's act, outside every role"
                )


def test_767_adapter_http_confinement_and_capture_hold(tmp_path):
    """d_adapter_http_confinement_capture_positive_control — PARITY, and the baseline the two
    vias this design adds are a parity demand AGAINST."""
    capture = confinement.TransportCapture()
    ctx = type("Ctx", (), {"capture": capture})()

    confinement.guard_outbound(ctx, "ticket", f"{URL_BASE}{TICKETS_PATH}", method="GET")
    assert [(r.system, r.method) for r in capture.requests] == [("ticket", "GET")], (
        "the established via no longer records what it sent — `guard_outbound` is the capture "
        "recorder, so a door that stops calling it stops recording"
    )

    with pytest.raises(ConfinementFault):
        confinement.guard_outbound(
            ctx, "ticket", f"{URL_BASE}{TICKETS_PATH}/SOC-1{COMMENTS_SUFFIX}", method="POST")
    assert len(capture.requests) == 1, "a refused request was still recorded as sent"

    assert "case-history" not in confinement.READ_ENDPOINT_ALLOWLIST, (
        "the host writer's system gained an allowlist entry; g2/g3 record that it consults "
        "none, and RF4 bounds every witness in this file on that fact"
    )


def test_767_query_tool_is_only_ticket_reader(tmp_path):
    """s3p_single_model_facing_reader — NEGATIVE, the path census."""
    consumers = _shipped_hits(r"(?<!def )\bscreen_(?:list|get|release_list|release_get)\s*\(")
    assert consumers == {}, (
        f"a shipped module still screens ticket replies: {consumers} — #1221 removed both "
        "read screens"
    )
    assert not (DEFENDER_DIR / "runtime" / "ticket_screen.py").exists(), (
        "runtime/ticket_screen.py survives #1221's removal of both read screens"
    )

    forward_dir = DEFENDER_DIR / "learning" / "author" / "verify_forward"
    for p in sorted(forward_dir.rglob("*.py")):
        assert "ticket" not in _text(p).lower(), (
            f"{p.name} still reaches the ticket store: D5 deletes the whole lane, and its "
            "prompt section with it"
        )

    subprocess_readers = _shipped_hits(r"get-ticket")
    allowed = {
        "defender/scripts/adapters/ticket_adapter.py",
        "defender/runtime/query_tool.py",
        "defender/learning/judge/family.py",
    }
    assert set(subprocess_readers) <= allowed, (
        "a shipped module outside the adapter and the query tool names `get-ticket`: "
        f"{sorted(set(subprocess_readers) - allowed)}"
    )

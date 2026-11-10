"""Shared builders, a fake ticket store and drivers for the #767 case-ticket writer suite (#1359: the
record leg comments through the case system's adapter, which reaches the store through the
credential proxy (#1391 O1), so the store is a stand-in for the proxy, not a seam inside the
writer)."""
from __future__ import annotations

from defender.tests.support.shared.contracts._spec1077 import fixture_run as _run_handle_1165

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from defender.tests.support.tenancy import _tenants1106 as T1106
from defender.tests.support.storage._alert_plant import plant_alert
from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S1107
from defender.tests.support.shared._fixture_uuid import fixture_uuid, is_fixture_uuid_shape

# --------------------------------------------------------------------------------------
# Vendor spellings: the test's copy, used to build a case-record file and read the wire back.
# --------------------------------------------------------------------------------------

#: The store's own `closed` status (its stub accepts only `open`/`in_progress`/`closed`). A
#: store word, not a mapping one: no code reads it. Used as the closed case a writer still
#: comments on, and as a hostile value an alert might carry.
CLOSED_STATUS = "closed"

#: The state a seeded ticket is in (store records the gather tests read).
OPEN_STATUS = "open"

#: The agent identity the seeded store records spell as author.
AGENT_AUTHOR = "defender"

#: One bound: 4096 UTF-8 bytes on the rendered comment body. The cut rounds down to the last
#: whole character and the `…` sits inside the bound.
WIRE_BOUND_BYTES = 4096
ELLIPSIS = "…"

#: The empty-narrative marker.
NO_NOTES = "(no notes)"

COMMENTS_SUFFIX = "/comments"
TRANSITIONS_SUFFIX = "/transitions"
TICKETS_PATH = "/tickets"

#: The `ticket` system's settings the planted tenant carries: the keys the adapter reads (its
#: base is its access declaration's, #1391 P1).
CONFIG: dict[str, str] = {
    "TIMEOUT_SEC": "10",
    "KEY_PATTERN": "C767-[0-9]+",
}
#: The system that records cases, and the ticket the planted alerts name (their own `alert_id`).
CASE_SYSTEM = "ticket"
CASE_KEY = "C767-4471"

ALERT = {
    "alert_id": CASE_KEY,
    "rule": {"id": "5710", "description": "sshd: Attempt to login using a non-existent user"},
    "agent": {"name": "target-endpoint"},
    "timestamp": "2026-05-07T07:15:01.561+0000",
}

#: The rendered comment body. The em-dash separator is the mapping's, not a code literal.
COMMENT_BODY_TEMPLATE = "{disposition} — {cause}\n\n{narrative}"

#: The case-record file and the case system's config below a tenant's settings folder.
CASE_RECORD_RELPATH = T1106.CASE_RECORD_REL
CONFIG_RELPATH = f"systems/{CASE_SYSTEM}/config.env"

#: The tenant `use_case_record` plants under the test's root.
TENANT_ID = fixture_uuid("tenant:t767")
#: The base the planted tenant's `ticket` access declaration names.
TICKET_BASE = T1106.default_base(TENANT_ID, CASE_SYSTEM)


# --------------------------------------------------------------------------------------
# The case-record file — built as data, written to a settings folder (#1359 r4 Data)
# --------------------------------------------------------------------------------------


def case_record_doc(*, body: Any = COMMENT_BODY_TEMPLATE, system: Any = CASE_SYSTEM,
                    with_comment: bool = True) -> dict[str, Any]:
    """The case-record file as a dict (`system:`, `comment.body:`). `with_comment=False` drops the
    comment section; a `None` member is left out."""
    doc: dict[str, Any] = {}
    if system is not None:
        doc["system"] = system
    if with_comment:
        doc["comment"] = {} if body is None else {"body": body}
    return doc


def settings_of(root: Path) -> Path:
    """The settings folder `write_case_record` plants under `root` (`<root>/<T>/knowledge/settings`)."""
    return Path(root) / TENANT_ID / "knowledge" / "settings"


def write_case_record(root: Path, doc: dict[str, Any] | str) -> Path:
    """Write the case-record file into `settings_of(root)` (planting the rest of the tenant first,
    if the folder is new) and return its path."""
    import yaml

    settings = settings_of(root)
    if not (settings / "verb-grants.yaml").exists():
        S1107.plant(Path(root), TENANT_ID, marker=TENANT_ID)
    path = settings / CASE_RECORD_RELPATH
    text = doc if isinstance(doc, str) else yaml.safe_dump(doc, sort_keys=False, allow_unicode=True)
    path.write_text(text, encoding="utf-8")
    return path


#: The settings folder this test planted its mapping into, recorded via `monkeypatch.setitem`
#: (undone after each test) so the helpers below hand every call the same tenant.
_PLANTED: dict[str, Path] = {}


def use_case_record(monkeypatch, root: Path, doc: dict[str, Any] | str | None = None) -> Path:
    """Plant a case-record file of this test's choosing and return its settings folder. The
    leg's record is resolved from it at call time (`current_record`), so a second planted file
    reaches the next call, while a record taken before keeps the first."""
    write_case_record(root, case_record_doc() if doc is None else doc)
    monkeypatch.setitem(_PLANTED, "settings", settings_of(root))
    return settings_of(root)


def current_settings() -> Path:
    """The settings folder the running test planted (`use_case_record`), else the committed
    fixture tenant's."""
    return _PLANTED.get("settings", T1106.FIXTURE_SETTINGS)


#: Sentinel default for `config` (`current_record`/`record`/`open_ticket`), which has three
#: states: omitted (the fixture's `CONFIG`), explicit `None` (no `config.env`), or a dict.
_CONFIG_UNSET = object()


def _write_case_config(settings: Path, config: dict[str, str] | None) -> None:
    path = settings / CONFIG_RELPATH
    if config is None:
        path.unlink(missing_ok=True)
        return
    lines = [f'TICKET_{key}="{value}"' for key, value in config.items()]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def current_record(*, config: dict[str, str] | None | object = _CONFIG_UNSET) -> Any:
    """The run record of the tenant the running test planted (else the committed fixture
    tenant), resolved now through the real resolver, with `config` (the case system's
    `config.env`) as `_CONFIG_UNSET` says."""
    if "settings" not in _PLANTED:
        return T1106.fixture_run_tenant()
    settings = current_settings()
    _write_case_config(settings, CONFIG if config is _CONFIG_UNSET else config)
    return T1106.run_tenant(T1106.accept(settings.parents[2], TENANT_ID))


def shipped_case_record_doc() -> dict[str, Any]:
    """The case record the committed fixture tenant runs with, as the case-record file spells it
    (`system:`, `comment.body:`). #1366 O9: the checked-in `settings/case-record.yaml` is gone;
    the fixture tenant's case is the record its seeder holds (`R.fixture_records()`, read from
    the retired copy of that file), so this reads the seeded record, not a path in the checkout."""
    from defender.tests.support.tenancy import _systems1366 as R

    case = R.fixture_records().case
    assert case is not None, "the fixture tenant's records carry no case record"
    return {"system": case.system_id, "comment": {"body": case.comment_body}}


# --------------------------------------------------------------------------------------
# The run dir the writer reads
# --------------------------------------------------------------------------------------

HOST_CAUSE = "Disposition recorded by the close gate. outcome=holds"


def write_report(
    run_dir: Path,
    *,
    disposition: str | None = "benign",
    cause: str | None = HOST_CAUSE,
    confidence: str = "high",
    body: str = "The account is a decommissioned service identity; no egress followed.",
    text: str | None = None,
) -> Path:
    """Write a `report.md`. `text` writes raw bytes instead, for the unreadable members."""
    path = run_dir / "report.md"
    if text is not None:
        path.write_text(text, encoding="utf-8")
        return path
    lines = ["---", f"case_id: {run_dir.name}"]
    if disposition is not None:
        lines.append(f"disposition: {disposition}")
    lines.append(f"confidence: {confidence}")
    if cause is not None:
        lines.append(f"cause: {cause}")
    lines += ["---", body, ""]
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


#: The default run's id (a run id is a canonical UUID).
RUN_ID = fixture_uuid("767-sshd")


def make_run(tmp_path: Path, name: str = RUN_ID, *, alert: Any = None,
             **report_kw: Any) -> Path:
    """A run dir carrying the two files the writer reads: `report.md` and `alert.json`. `name`
    is a canonical UUID (used as is) or a label (the folder is `fixture_uuid(name)`), so read
    the run's id back from `run_dir.name`, never the label."""
    run_dir = tmp_path / (name if is_fixture_uuid_shape(name) else fixture_uuid(name))
    run_dir.mkdir(parents=True, exist_ok=True)
    write_report(run_dir, **report_kw)
    plant_alert(run_dir, ALERT if alert is None else alert, mapping=ALERT_MAPPING)
    return run_dir


#: The paths this suite's alerts carry their four facts at (`case_key`: the alert's own id).
ALERT_MAPPING = {"signature": "rule.id", "event_time": "timestamp", "summary": "rule.description",
                 "case_key": "alert_id"}


# --------------------------------------------------------------------------------------
# The store fake — a stand-in for the credential proxy (one per test), driven by canned answers
# --------------------------------------------------------------------------------------

#: The write-back token the record leg presents (the stand-in checks none).
WRITE_TOKEN = "write-token-767"


@dataclass(frozen=True)
class OutboundCall:
    """One request the store received (as the run sent it to the proxy): what shape assertions
    check, never the canned reply."""

    method: str
    path: str
    body: Any


class FakeStore:
    """The ticket store behind the proxy: a `ProxyStandIn` that records each request and answers
    `answers` in order (the last repeats). It injects a status and a body; it decides nothing."""

    def __init__(self, root: Path, *, status: str = "201", body: str = '{"id": 1}',
                 answers: list[dict[str, Any]] | None = None) -> None:
        self.stand_in = S1107.ProxyStandIn(
            Path(root), answers if answers is not None else [S1107.answer(body, status)])

    @property
    def url(self) -> str:
        return self.stand_in.url

    def env(self, base: Any) -> dict[str, str]:
        return dict(base)

    @property
    def calls(self) -> list[OutboundCall]:
        return [OutboundCall(method=r["method"], path=r["path"], body=r["body"])
                for r in self.stand_in.requests()]

    def writes(self) -> list[OutboundCall]:
        """Every call that could change the estate (any non-`GET`)."""
        return [c for c in self.calls if c.method != "GET"]

    def paths(self, suffix: str | None = None) -> list[str]:
        return [c.path for c in self.calls if suffix is None or c.path.endswith(suffix)]

    def bodies(self, suffix: str) -> list[Any]:
        return [c.body for c in self.calls if c.path.endswith(suffix)]

    @property
    def comment_payloads(self) -> list[Any]:
        return self.bodies(COMMENTS_SUFFIX)

    def only_comment(self) -> dict[str, Any]:
        payloads = self.comment_payloads
        assert len(payloads) == 1, (
            f"expected exactly one comment POST, saw {len(payloads)} "
            f"(every path the writer took: {[ (c.method, c.path) for c in self.calls ]})"
        )
        assert isinstance(payloads[0], dict), "the comment payload is not a JSON object"
        return payloads[0]

    def wire_body(self) -> str:
        """The comment body as it crossed the wire, agent tag line included (what the byte bound
        covers)."""
        body = self.only_comment().get("body")
        assert isinstance(body, str), "the comment payload carries no string `body`"
        return body

    def comment_body(self) -> str:
        """The rendered comment below the agent tag line."""
        from defender.tenancy.case_ticket import AGENT_TAG_PREFIX

        wire = self.wire_body()
        tag_line, newline, rest = wire.partition("\n")
        assert newline, f"the posted comment is one line, with no comment below a tag: {wire!r}"
        assert tag_line.startswith(AGENT_TAG_PREFIX), (
            f"the posted comment does not open with the agent tag line ({AGENT_TAG_PREFIX!r}): "
            f"{wire[:160]!r}"
        )
        return rest


def _handed(run_dir: Path, store: FakeStore, config: dict[str, str] | None | object) -> dict[str, Any]:
    """What run.py hands the leg: the record, the code tree, the run's env, and the proxy's
    address and write-back token (the store's stand-in)."""
    from defender import box as box_mod

    return {"tenant": current_record(config=config), "defender_dir": T1106.DEFENDER,
            "env": store.env(box_mod.run_env(T1106.DEFENDER, Path(run_dir))),
            "proxy_url": store.url, "request_token": WRITE_TOKEN}


def record(run_dir: Path, store: FakeStore, *,
           config: dict[str, str] | None | object = _CONFIG_UNSET, **kw: Any) -> Any:
    """Drive the record leg (`record_case_ticket`) over one run dir, through the real seam and
    the real shared transport, the store being behind `store`'s proxy stand-in."""
    from defender.investigation import ticket_writer

    return ticket_writer.record_case_ticket(
        _run_handle_1165(run_dir), **_handed(run_dir, store, config), **kw)


def posted_comment_body(run_dir: Path, scratch: Path) -> str:
    """The comment the record leg posts for a finished run dir that other suites planted WITHOUT
    a ticket key: the run gets this suite's `ALERT` (it names `CASE_KEY`, facts derived through
    `ALERT_MAPPING`), the leg runs against a fresh fake store under `scratch` over the committed
    fixture tenant, and the posted body below the agent tag line is returned. The boundary
    through which readers of a report see what the ticket lane makes of it (#1359: the comment
    builder is not a public function)."""
    plant_alert(run_dir, ALERT, mapping=ALERT_MAPPING)
    store = FakeStore(Path(scratch) / f"store-{len(list(Path(scratch).glob('store-*')))}")
    record(run_dir, store)
    return store.comment_body()


def receipt_path(run_dir: Path) -> Path:
    """The receipt's location: a sidecar beside (not inside) the box-writable run dir, keyed by
    the run's name."""
    return run_dir.parent / f"{run_dir.name}.ticket-write.json"


def receipt(run_dir: Path) -> dict[str, Any]:
    path = receipt_path(run_dir)
    assert path.is_file(), "no ticket receipt was written"
    return json.loads(path.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------------------
# The store's own records — what a ticket verb answers gather with
# --------------------------------------------------------------------------------------


def comment(body: str) -> dict[str, Any]:
    return {"body": body, "created": "2026-09-16T12:00:00Z", "author": AGENT_AUTHOR}


def ticket(key: str, *, labels: Any = (), comments: Any = (),
           status: Any = OPEN_STATUS) -> dict[str, Any]:
    return {
        "key": key,
        "summary": "a prior case",
        "description": "",
        "resolution": None,
        "reporter": AGENT_AUTHOR,
        "status": status,
        "labels": list(labels),
        "comments": list(comments),
    }


def listing(*tickets: dict[str, Any], source: str = "ticket-store") -> dict[str, Any]:
    return {"total": len(tickets), "tickets": list(tickets), "source": source}


def rendered(payload: Any, tmp_path: Path) -> str:
    """What gather's payload view hands the model for this payload."""
    from defender.investigation.payload_view import render

    return render(json.dumps(payload), None, tmp_path)

"""Shared builders, a fake ticket store and drivers for the #767 case-ticket writer suite."""
from __future__ import annotations

from defender.tests.support.shared.contracts._spec1077 import fixture_run as _run_handle_1165

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from defender.records._alert_input import AlertFacts
from defender.tests.support.tenancy import _tenants1106 as T1106
from defender.tests.support.storage._alert_plant import plant_alert
from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S1107
from defender.tests.support.shared._fixture_uuid import fixture_uuid, is_fixture_uuid_shape

# --------------------------------------------------------------------------------------
# Vendor spellings. They live in the mapping; these are the test's copy, used to build a
# mapping and to read the wire back, not a claim about what the writer may hardcode.
# --------------------------------------------------------------------------------------

#: The store's own `closed` status (its stub accepts only `open`/`in_progress`/`closed`). A
#: store word, not a mapping one: no code reads it. Used as the closed case a writer still
#: comments on, and as a hostile value an alert might carry.
CLOSED_STATUS = "closed"

#: The legacy `released:` section an un-migrated tenant's mapping may carry: the loader accepts
#: it and nothing reads it; the shipped mapping has none (`released=None`).
LEGACY_RELEASED: dict[str, Any] = {"status": CLOSED_STATUS}
#: The state the bridge opens a case in (`open.status`).
OPEN_STATUS = "open"

#: The agent identity the mapping spells at `open.reporter` and `comment.author`.
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

#: A case-history config the planted tenant carries — the three keys the writer itself requires.
CONFIG: dict[str, str] = {
    "URL_BASE": "http://case-history.test",
    "BASTION_HOST": "bastion.test",
    "TIMEOUT_SEC": "10",
}

ALERT = {
    "rule": {"id": "5710", "description": "sshd: Attempt to login using a non-existent user"},
    "agent": {"name": "target-endpoint"},
    "timestamp": "2026-05-07T07:15:01.561+0000",
}

#: The rendered comment body. The em-dash separator is the mapping's, not a code literal.
COMMENT_BODY_TEMPLATE = "{disposition} — {cause}\n\n{narrative}"

#: The mapping's path below a tenant's settings folder.
MAPPING_RELPATH = "systems/case-history/mapping.yaml"
CONFIG_RELPATH = "systems/case-history/config.env"

#: The tenant `use_mapping` plants under the test's root.
TENANT_ID = fixture_uuid("tenant:t767")


def require(obj: Any, name: str, why: str) -> Any:
    """The named attribute, or a failure that says `why` it is needed instead of an
    `AttributeError` inside a scenario about something else."""
    got = getattr(obj, name, None)
    assert got is not None, f"{getattr(obj, '__name__', obj)}.{name} does not exist — {why}"
    return got


# --------------------------------------------------------------------------------------
# The mapping — built as data, written to a settings folder, handed in explicitly (#1106)
# --------------------------------------------------------------------------------------


def mapping_doc(  # noqa: PLR0913 — one keyword per MEMBER a demand exercises, not per concept
    *,
    open_labels: tuple[str, ...] = ("sig:{signature}", "evt:{event_time}"),
    open_status: Any = OPEN_STATUS,
    comment_author: str | None = AGENT_AUTHOR,
    comment_body: str | None = COMMENT_BODY_TEMPLATE,
    released: Any = LEGACY_RELEASED,
    with_comment: bool = True,
    close_section: dict[str, Any] | None = None,
    extra_open: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """The mapping as a dict. `with_comment=False` drops the comment section; `open_status`
    feeds the loader's literal-status rule; `released` is the legacy section (`None` omits it,
    as shipped; any other value is written as-is and must be ignored); `close_section` is a
    stale close lane; `extra_open` an operator-added open field."""
    doc: dict[str, Any] = {
        "open": {
            "key": "{case_id}",
            "summary": "{summary}",
            "description": "Auto-created from alert {case_id} (rule {signature}).",
            "status": open_status,
            "reporter": AGENT_AUTHOR,
            "labels": list(open_labels),
        },
    }
    if extra_open:
        doc["open"].update(extra_open)
    if with_comment:
        section: dict[str, Any] = {}
        if comment_author is not None:
            section["author"] = comment_author
        if comment_body is not None:
            section["body"] = comment_body
        doc["comment"] = section
    if released is not None:
        doc["released"] = dict(released) if isinstance(released, dict) else released
    if close_section is not None:
        doc["close"] = close_section
    return doc


def settings_of(root: Path) -> Path:
    """The settings folder `write_mapping` plants under `root` (`<root>/<T>/knowledge/settings`)."""
    return Path(root) / TENANT_ID / "knowledge" / "settings"


def write_mapping(root: Path, doc: dict[str, Any] | str) -> Path:
    """Write a mapping into `settings_of(root)` (planting the rest of the tenant first, if the
    folder is new) and return the mapping file's path."""
    import yaml

    settings = settings_of(root)
    if not (settings / "verb-grants.yaml").exists():
        S1107.plant(Path(root), TENANT_ID, marker=TENANT_ID)
    path = settings / MAPPING_RELPATH
    text = doc if isinstance(doc, str) else yaml.safe_dump(doc, sort_keys=False, allow_unicode=True)
    path.write_text(text, encoding="utf-8")
    return path


#: The settings folder this test planted its mapping into, recorded via `monkeypatch.setitem`
#: (undone after each test) so the helpers below hand every call the same tenant.
_PLANTED: dict[str, Path] = {}


def use_mapping(monkeypatch, root: Path, doc: dict[str, Any] | str | None = None) -> Path:
    """Plant a mapping of this test's choosing and return its settings folder. The writer's
    record is resolved from it at call time (`current_record`), so a second planted mapping
    reaches the next call, while a record taken before keeps the first."""
    write_mapping(root, mapping_doc() if doc is None else doc)
    monkeypatch.setitem(_PLANTED, "settings", settings_of(root))
    return settings_of(root)


def current_settings() -> Path:
    """The settings folder the running test planted (`use_mapping`), else the committed
    fixture tenant's."""
    return _PLANTED.get("settings", T1106.FIXTURE_SETTINGS)


#: Sentinel default for `config` (`current_record`/`record`/`open_ticket`), which has three
#: states: omitted (the fixture's `CONFIG`), explicit `None` (no `config.env`), or a dict.
_CONFIG_UNSET = object()


def _write_case_history_config(settings: Path, config: dict[str, str] | None) -> None:
    path = settings / CONFIG_RELPATH
    if config is None:
        path.unlink(missing_ok=True)
        return
    lines = [f'CASE_HISTORY_{key}="{value}"' for key, value in config.items()]
    lines += [f'CASE_HISTORY_TRANSPORT="{S1107.DOCKER_EXEC}"',
              f'CASE_HISTORY_DOCKER_CONTEXT="{S1107.context_name(TENANT_ID, "case-history")}"']
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def current_record(*, config: dict[str, str] | None | object = _CONFIG_UNSET) -> Any:
    """The run record of the tenant the running test planted (else the committed fixture
    tenant), resolved now through the real resolver, with `config` as `_CONFIG_UNSET` says."""
    if "settings" not in _PLANTED:
        return T1106.fixture_run_tenant()
    settings = current_settings()
    _write_case_history_config(settings, CONFIG if config is _CONFIG_UNSET else config)
    return T1106.run_tenant(T1106.accept(settings.parents[2], TENANT_ID))


def current_mapping() -> Any:
    """The `ticket_mapping` of `current_record()` — a `CaseMapping`, or the `CaseTicketError`
    the record kept when the planted mapping could not stand."""
    return current_record().ticket_mapping


def shipped_comment_author() -> str:
    """The agent identity as the shipped mapping spells it (`comment.author`), read off the real
    file so whole-run scenarios assert about the file an operator edits, not a literal."""
    comment_section = shipped_mapping_doc().get("comment") or {}
    assert isinstance(comment_section.get("author"), str), (
        "the shipped mapping has no `comment: {author}` section"
    )
    return comment_section["author"]


def shipped_mapping_doc() -> dict[str, Any]:
    """The repo's own checked-in mapping (the committed fixture tenant's), read off the
    real file."""
    import yaml

    from defender.tests.support.tenancy import _tenants1106

    return yaml.safe_load(
        (_tenants1106.FIXTURE_SETTINGS / MAPPING_RELPATH).read_text(encoding="utf-8"))


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


#: The paths this suite's alerts carry their three facts at.
ALERT_MAPPING = {"signature": "rule.id", "event_time": "timestamp", "summary": "rule.description"}


def facts_of(alert: dict[str, Any]) -> AlertFacts:
    """The facts the front door records for `alert` under `ALERT_MAPPING` (what the mapper is
    handed instead of the alert), passed through unvalidated."""
    rule = alert.get("rule") if isinstance(alert.get("rule"), dict) else {}
    return AlertFacts(signature=rule.get("id") or None, event_time=alert.get("timestamp") or None,
                      summary=rule.get("description") or None)


# --------------------------------------------------------------------------------------
# The store fake — one fake per dependency, driven by a data fault-spec
# --------------------------------------------------------------------------------------


#: `ticket` on `FakeStore` distinguishes "omitted" (a default open case) from an
#: explicit `None` (the store holds no such key), the same way `_CONFIG_UNSET` does for `config`.
_TICKET_UNSET = object()


@dataclass(frozen=True)
class OutboundCall:
    """One request the writer handed the transport: what shape assertions check, never the
    fake's canned reply."""

    method: str
    path: str
    body: Any


class FakeStore:
    """The writer's `request` dependency: records what it receives, injects a stated fault."""

    def __init__(
        self,
        *,
        status: str = "201",
        body: str = '{"author": "defender", "body": "ok", "created": "2026-09-17T00:00:00Z"}',
        ticket: dict[str, Any] | None | object = _TICKET_UNSET,
        status_by_suffix: dict[str, str] | None = None,
        transport_fault_on: str | None = None,
        transport_error_on: str | None = None,
    ) -> None:
        self.status = status
        self.body = body
        self.ticket = (
            {"key": "any", "status": OPEN_STATUS, "labels": ["sig:5710"], "comments": []}
            if ticket is _TICKET_UNSET else ticket
        )
        self.status_by_suffix = dict(status_by_suffix or {})
        self.transport_fault_on = transport_fault_on
        self.transport_error_on = transport_error_on
        self.calls: list[OutboundCall] = []

    def __call__(self, config: dict[str, str], method: str, path: str,
                 body: Any = None, *, ctx: Any) -> tuple[str | None, str]:
        self.calls.append(OutboundCall(method=method, path=path, body=body))
        if self.transport_fault_on and path.endswith(self.transport_fault_on):
            from defender.kit.faults import TransportFault

            fault = TransportFault("injected: the bastion is unreachable")
            return None, f"transport error: {fault.detail}"
        if self.transport_error_on and path.endswith(self.transport_error_on):
            return None, "transport error: injected"
        for suffix, status in self.status_by_suffix.items():
            if path.endswith(suffix):
                return status, self.body
        if method == "GET":
            if self.ticket is None:
                return "404", '{"detail": "not found"}'
            return "200", json.dumps(self.ticket)
        return self.status, self.body

    # ---- what the fake recorded ---------------------------------------------------------

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

    @property
    def open_payloads(self) -> list[Any]:
        return [c.body for c in self.calls if c.path == TICKETS_PATH]

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


def writer_deps(store: FakeStore):
    """Bind the fake into the writer's real injection seam."""
    from defender.investigation import ticket_writer

    return ticket_writer.TicketWriterDeps(request=store)


def _handed(run_dir: Path, config: dict[str, str] | None | object) -> dict[str, Any]:
    """What run.py hands both legs: the record, the code tree and the run's env."""
    from defender import box as box_mod

    return {"tenant": current_record(config=config), "defender_dir": T1106.DEFENDER,
            "env": box_mod.run_env(T1106.DEFENDER, Path(run_dir))}


def record(run_dir: Path, store: FakeStore, *, config: dict[str, str] | None | object = _CONFIG_UNSET,
           **kw: Any) -> Any:
    """Drive the writer (`record_case_ticket`) over one run dir, through the real seam."""
    from defender.investigation import ticket_writer

    return ticket_writer.record_case_ticket(
        _run_handle_1165(run_dir), writer_deps(store), **_handed(run_dir, config), **kw)


def open_ticket(run_dir: Path, store: FakeStore) -> Any:
    from defender.investigation import ticket_writer

    return ticket_writer.open_case_ticket(
        _run_handle_1165(run_dir), writer_deps(store), **_handed(run_dir, _CONFIG_UNSET))


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

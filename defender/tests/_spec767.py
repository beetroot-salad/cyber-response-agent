"""Shared machinery for the #767 spec suite — NO test scripts.

Every test in `test_767_*.py` is one demand of
`spec-flow/specs/spec_graph_767-ticket-store-approval.yaml`, named by that demand's
`discharged_by`. RED against `a77335d5` is the expected state: `record_case_ticket`,
`case_record_to_comment`, the mapping's `comment:`/`released:` sections and the release
predicate are all COINED here — none of them exists yet. Where the implementation spells a
symbol otherwise, these names follow the code.

THE RELEASE SIGNAL IS THE CASE'S LIFECYCLE STATE, never a tag and never a comment's author.
A person closes a case once they have reviewed it; `status` is a closed vocabulary the
store itself enforces, so nothing rendered from an alert can move a case along it, and a
comment's `author` — whatever the posting client chose to send — decides nothing.

THE SEAMS THESE FAKES ENTER THROUGH ARE PRODUCTION'S OWN (the project profile forbids
`monkeypatch.setattr`, and CI ratchets new sites):

  * the writer's collaborators — `TicketWriterDeps{load_config, request}`, the frozen
    dataclass threaded as the second parameter of both writers (g16: there is no third);
  * the mapping file — the SETTINGS FOLDER every mapping reader is handed (#1106 D2: no
    reader finds it itself, so `$DEFENDER_DIR` is no longer a seam). `use_mapping` plants a
    mapping under `<root>/settings/` and returns that folder; the helpers below hand the
    folder the test planted (or, with none planted, the committed playground tenant's) to
    the real writer and screen, so a hostile-mapping control still needs no new seam;
  * the entrypoint's tail — `run.py main(..., ticket_writer=)`, the duck-typed seam
    `tests/_spec791.py` already implements (g10).

FAULT CONTENT IS PROBE-DERIVED, NEVER AUTHORED. `FakeStore`'s arms are exactly the shapes
the ledger observed on the real dependency: `TransportFault` and the `(None, detail)`
transport-error return are `ticket_writer._request`'s own two failure spellings (c14, g2);
the status words are what the real stub answered when it was driven (c8: create 201, a
duplicate create 409, an unknown key 404, PATCH/PUT 405). The fake injects and records; it
classifies nothing and decides no policy.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# --------------------------------------------------------------------------------------
# The vendor spellings this lane introduces. Every one of them lives in the MAPPING (O5) —
# these constants are the TEST's copy, used to build a mapping and to read the wire back,
# never a claim about what the writer or the screen may hardcode (that is
# o5_no_vendor_literals_in_code's own demand).
# --------------------------------------------------------------------------------------

#: The lifecycle state a person moves a reviewed case to — the store's own `closed` (c8: the
#: stub enforces `status ∈ {open, in_progress, closed}` as a Literal, rejecting anything else
#: with 422). The test's copy of the mapping's `released.status`; O5 owns that the code never
#: spells it.
RELEASED_STATUS = "closed"
#: The state the bridge opens a case in (`open.status`).
OPEN_STATUS = "open"

#: The agent identity `mapping.yaml` already spells at `open.reporter` and `close.author`
#: (c15/r6). D1's new `comment.author` carries it forward.
AGENT_AUTHOR = "defender"

#: §7 R2 (FK01, = 20-demands F4, MATERIAL): ONE bound, 4096 UTF-8 **bytes** on the rendered
#: comment body. `_TICKET_REASON_MAX` (472 characters, r2/c10) retires with `CaseRecord.reason`.
#: The cut rounds DOWN to the last whole character and the `…` sits INSIDE the bound.
WIRE_BOUND_BYTES = 4096
ELLIPSIS = "…"

#: D3's empty-narrative marker.
NO_NOTES = "(no notes)"

COMMENTS_SUFFIX = "/comments"
TRANSITIONS_SUFFIX = "/transitions"
TICKETS_PATH = "/tickets"

#: A config the writer's `load_config` seam can answer with — the three keys `_load_config`
#: itself requires.
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

#: D3's rendered comment body. The em-dash separator is the MAPPING's, not a code literal.
COMMENT_BODY_TEMPLATE = "{disposition} — {cause}\n\n{narrative}"

#: The mapping's home BELOW a tenant's settings folder (#1106: `<tenants root>/<id>/settings/`).
MAPPING_RELPATH = "systems/case-history/mapping.yaml"


def require(obj: Any, name: str, why: str) -> Any:
    """The named attribute, or a failure that names the DEMAND rather than surfacing as an
    `AttributeError` inside a scenario about something else.

    Deliberately not a module-level import: every one of these symbols is coined by this
    spec, and a module-level import of one would turn the whole suite into a collection
    error instead of a per-demand red."""
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
    released_status: Any = RELEASED_STATUS,
    with_comment: bool = True,
    with_released: bool = True,
    close_section: dict[str, Any] | None = None,
    extra_open: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """The post-#767 mapping as a dict. Every knob is a member some demand exercises:
    `with_comment`/`with_released` are FAM-1's missing sections, `released_status` carries
    FK18's non-string, `open_status` the open/released collision, `close_section` is FK27's
    stale lane and `extra_open` is an operator-added open field."""
    doc: dict[str, Any] = {
        "source": {
            "signature": "rule.id",
            "summary": "rule.description",
            "event_time": "timestamp",
        },
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
    if with_released:
        doc["released"] = {"status": released_status}
    if close_section is not None:
        doc["close"] = close_section
    return doc


def settings_of(root: Path) -> Path:
    """The settings folder `write_mapping` plants under `root`."""
    return Path(root) / "settings"


def write_mapping(root: Path, doc: dict[str, Any] | str) -> Path:
    """Write a mapping into `settings_of(root)` and return the mapping file's path."""
    import yaml

    path = settings_of(root) / MAPPING_RELPATH
    path.parent.mkdir(parents=True, exist_ok=True)
    text = doc if isinstance(doc, str) else yaml.safe_dump(doc, sort_keys=False, allow_unicode=True)
    path.write_text(text, encoding="utf-8")
    return path


#: The settings folder THIS test planted its mapping into, recorded through `monkeypatch`
#: (`setitem`, undone after every test) so the helpers below hand the same folder to the
#: writer and the screen. The test's own bookkeeping — production is handed the folder
#: explicitly by every one of these helpers; nothing in it reads this dict.
_PLANTED: dict[str, Path] = {}


def use_mapping(monkeypatch, root: Path, doc: dict[str, Any] | str | None = None) -> Path:
    """Plant a mapping of this test's choosing and return its SETTINGS FOLDER.

    #1106: the folder is handed to the ONE loader by every caller (`release_predicate(
    settings)`, `settings_dir=` on the writer and the screen) — the writer and the screen still
    read the same file through the same function, which is what
    `o5_no_vendor_literals_in_code` observes."""
    write_mapping(root, mapping_doc() if doc is None else doc)
    monkeypatch.setitem(_PLANTED, "settings", settings_of(root))
    return settings_of(root)


def current_settings() -> Path:
    """The settings folder the running test planted (`use_mapping`), else the committed
    playground tenant's — the file a driven run resolves when nothing repoints it."""
    from defender.tests import _tenants1106

    return _PLANTED.get("settings", _tenants1106.PLAYGROUND_SETTINGS)


def shipped_released_status_and_author() -> tuple[str, str]:
    """The released status and the agent identity as the SHIPPED mapping spells them.

    Read off the real file rather than taken from this module's constants, because the
    scenarios that do not plant their own mapping — anything driving the whole run — resolve
    the shipped mapping, and reading it here is what makes those tests a statement about the
    file an operator edits (O5) rather than about a literal."""
    doc = shipped_mapping_doc()
    released = doc.get("released") or {}
    comment_section = doc.get("comment") or {}
    assert isinstance(released.get("status"), str), (
        "the shipped mapping has no `released: {status}` section (D1)"
    )
    assert isinstance(comment_section.get("author"), str), (
        "the shipped mapping has no `comment: {author}` section (D1)"
    )
    return released["status"], comment_section["author"]


def shipped_mapping_doc() -> dict[str, Any]:
    """The repo's own checked-in mapping (the committed playground tenant's), read off the
    real file."""
    import yaml

    from defender.tests import _tenants1106

    return yaml.safe_load(
        (_tenants1106.PLAYGROUND_SETTINGS / MAPPING_RELPATH).read_text(encoding="utf-8"))


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


def make_run(tmp_path: Path, name: str = "20260917T000000Z-sshd", *, alert: Any = None,
             **report_kw: Any) -> Path:
    """A run dir carrying the two files the writer reads: `report.md` and `alert.json`."""
    run_dir = tmp_path / name
    run_dir.mkdir(parents=True, exist_ok=True)
    write_report(run_dir, **report_kw)
    run_dir.joinpath("alert.json").write_text(
        json.dumps(ALERT if alert is None else alert), encoding="utf-8"
    )
    return run_dir


# --------------------------------------------------------------------------------------
# The store fake — one fake per dependency, driven by a data fault-spec
# --------------------------------------------------------------------------------------


#: `ticket` on `FakeStore` distinguishes "omitted" (a default open, unreleased case) from an
#: explicit `None` (the store holds no such key), the same way `_CONFIG_UNSET` does for `config`.
_TICKET_UNSET = object()


@dataclass(frozen=True)
class OutboundCall:
    """One request the writer handed the transport — the CAPTURED INBOUND PAYLOAD every
    `kind: shape` demand here asserts against, never the fake's canned reply."""

    method: str
    path: str
    body: Any


class FakeStore:
    """The writer's `request` dependency: records what it receives, injects a stated fault.

    The fault vocabulary is data, and each arm cites the claim that observed that shape on
    the real dependency:

      * ``transport_fault`` — a `TransportFault` raised by the transport underneath
        `ticket_writer._request`, which `_request`'s own `except` clause converts to the
        `(None, "transport error: …")` return (c14, read at ticket_writer.py:62-77). The
        fake stands in for `deps.request` — i.e. for `_request` itself — so it answers with
        that converted shape rather than raising: no production `request` ever raises this,
        and a fake that did would exercise a path the writer cannot reach;
      * ``transport_error`` — the `(None, detail)` return `_request` produces when curl
        answered nothing parseable (c14);
      * ``status`` / ``status_by_suffix`` — HTTP status words the real stub answered when it
        was driven: 201 on create and on comment, 409 on a duplicate create, 404 on an
        unknown key, 405 on PATCH/PUT (c8, executed).
      * ``body`` — the reply text to a WRITE. A malformed one is FK31's arm; nothing reads
        it (c5), and no assertion in this suite is made against it.
      * ``ticket`` — the ticket object a `GET /tickets/{key}` answers with (200), which the
        writer reads back before it records so that it never appends behind a person's
        close. Defaults to an open, unreleased case; `None` answers the read with a 404.

    It classifies nothing and decides no policy: every branch here is "record, then answer".
    """

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
                 body: Any = None, *, settings_dir: Path) -> tuple[str | None, str]:
        self.calls.append(OutboundCall(method=method, path=path, body=body))
        if self.transport_fault_on and path.endswith(self.transport_fault_on):
            from defender.scripts.adapters.faults import TransportFault

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
        """Every call that could change the estate — the census the write-side demands
        count; the writer's own read-back (`GET`) is not one of them."""
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

    def comment_body(self) -> str:
        body = self.only_comment().get("body")
        assert isinstance(body, str), "the comment payload carries no string `body`"
        return body


#: `config` distinguishes THREE states across `writer_deps`/`record`/`open_ticket`: omitted
#: (use the fixture's own `CONFIG`), explicitly `None` (a run with no case-history config at
#: all — `deps.load_config(settings)` must answer `None`), or an explicit dict. Python gives both the
#: first two the same spelling if the default is `None` itself, so the default is this
#: sentinel instead — never `None` — and `None` is left free to mean what the writer's own
#: `TicketWriterDeps.load_config` contract says it means.
_CONFIG_UNSET = object()


def writer_deps(store: FakeStore, *, config: dict[str, str] | None | object = _CONFIG_UNSET):
    """Bind the fake into the writer's real injection seam (g16)."""
    from defender.scripts.case_history import ticket_writer

    resolved = CONFIG if config is _CONFIG_UNSET else config
    return ticket_writer.TicketWriterDeps(
        load_config=(lambda _settings_dir: None if resolved is None else dict(resolved)),
        request=store,
    )


def record(run_dir: Path, store: FakeStore, *, config: dict[str, str] | None | object = _CONFIG_UNSET,
           **kw: Any) -> Any:
    """Drive D2's writer over one run dir, through the real seam."""
    from defender.scripts.case_history import ticket_writer

    fn = require(
        ticket_writer, "record_case_ticket",
        "D2 renames `close_case_ticket` to `record_case_ticket`: one POST "
        "/tickets/{key}/comments, no transition",
    )
    kw.setdefault("settings_dir", current_settings())
    return fn(run_dir, writer_deps(store, config=config), **kw)


def open_ticket(
    run_dir: Path, store: FakeStore, *, config: dict[str, str] | None | object = _CONFIG_UNSET,
) -> Any:
    from defender.scripts.case_history import ticket_writer

    return ticket_writer.open_case_ticket(
        run_dir, writer_deps(store, config=config), settings_dir=current_settings())


def receipt(run_dir: Path) -> dict[str, Any]:
    path = run_dir / "ticket_write.json"
    assert path.is_file(), "no `ticket_write.json` receipt was written"
    return json.loads(path.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------------------
# The store's own records, and the screen the query tool applies to them
# --------------------------------------------------------------------------------------


def comment(body: str = "a prior run's notes", *, author: str | None = AGENT_AUTHOR,
            created: str = "2026-09-16T12:00:00Z", drop_author: bool = False) -> dict[str, Any]:
    out: dict[str, Any] = {"body": body, "created": created}
    if not drop_author:
        out["author"] = author
    return out


def ticket(key: str, *, labels: Any = (), comments: Any = (), summary: str = "a prior case",  # noqa: PLR0913 — one keyword per FIELD a demand drives, drop_* included
           status: Any = OPEN_STATUS, resolution: str | None = None,
           drop_labels: bool = False, drop_comments: bool = False,
           drop_status: bool = False) -> dict[str, Any]:
    out: dict[str, Any] = {
        "key": key,
        "summary": summary,
        "description": "",
        "resolution": resolution,
        "reporter": AGENT_AUTHOR,
    }
    if not drop_status:
        out["status"] = status
    if not drop_labels:
        out["labels"] = labels if labels is None or isinstance(labels, str) else list(labels)
    if not drop_comments:
        out["comments"] = (
            comments if comments is None or isinstance(comments, str) else list(comments)
        )
    return out


def listing(*tickets: dict[str, Any], source: str = "ticket-store") -> dict[str, Any]:
    return {"total": len(tickets), "tickets": list(tickets), "source": source}


SELF_KEY = "20260917T000000Z-the-current-case"
OTHER_KEY = "20260101T000000Z-a-prior-case"


def screen(payload: Any, *, verb: str, self_key: str = SELF_KEY) -> tuple[Any, int, str]:
    """Drive the REAL screen the way `QueryCapture._execute` drives it (r5/c6: the single
    insertion point, called after `handler(args)` and before `_record`/`_model_view`)."""
    from defender.runtime import query_tool

    return query_tool._screen_ticket_payload(
        self_key, "ticket", verb, payload, settings_dir=current_settings())


def screen_list(payload: Any, *, self_key: str = SELF_KEY) -> tuple[Any, int, str]:
    return screen(payload, verb="list-tickets", self_key=self_key)


def screen_get(payload: Any, *, self_key: str = SELF_KEY) -> tuple[Any, int, str]:
    return screen(payload, verb="get-ticket", self_key=self_key)


def served_tickets(payload: Any) -> list[dict[str, Any]]:
    assert isinstance(payload, dict), (
        f"the screen did not answer a ticket listing envelope: {payload!r}"
    )
    assert isinstance(payload.get("tickets"), list), (
        f"the screen's envelope carries no ticket list: {payload!r}"
    )
    return payload["tickets"]


def served_comments(t: dict[str, Any]) -> list[Any]:
    """The comment list a served record carries — the test's own reading of the wire, never
    the predicate under test. A record with no list serves no comments."""
    comments = t.get("comments")
    return list(comments) if isinstance(comments, list) else []


def rendered(payload: Any, tmp_path: Path, *, ceiling: int | None = None) -> str:
    """What gather's payload view hands the model for this payload (c7, executed)."""
    from defender.scripts.gather_tools.payload_view import render

    return render(json.dumps(payload), None, tmp_path, ceiling=ceiling)

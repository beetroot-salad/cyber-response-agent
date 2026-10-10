"""#1107 — the run page's ticket line (O6, NF-26, PG-2/PG-2a) and the record's case mapping (O2).

TWO SURFACES, ONE SLICE. The page half drives the REAL renderer: `run_common.visualize`, the
`visualize` seam `run.main` keeps at its production default, handed run.py's own `--update-ticket`
as an argument (PG-2a, coined keyword `update_ticket=` — `S.render_page`), and the standalone
`visualize_run.publish_page`, which is handed no flag. The observable is the rendered HTML: a
marker in a planted receipt either reaches `runtime.html` or it does not, and "no ticket line" is
the page being byte-equal to the page of the same run dir with no receipt at all (the base page is
deterministic across renders and carries no ticket text — measured before writing).

The mapping half drives the `case_ticket` consumers with the record's `ticket_mapping` (coined
keyword `mapping=` — `S.with_mapping`; `release_predicate`, once positional here, was removed by
#1221's amendment), the query tool's
ticket screen through the replay harness (`verbs=` / `tenant=`; the served payload is what the
gather model was shown), and a resumed sibling's `WorldRegistry` through `run.main --resume`,
whose `lifecycle` seam hands the REAL `_drive_investigation` a recording `investigate`. (#1224
retired the estate applier and the world patches it once judged against the mapping; a world
now carries facts its live oracle serves.) "After the record is built" is the `preflight` seam, which `run.main` calls after
`tenant = tenant_of()`.

Nothing here reaches the real docker: the only transport that forks (the record step in
`test_d_mapping_error_consumers`) is handed a `DockerShim` env, and every `run.main` drive puts the
shim first on this process's PATH before run.py builds its env.
"""
from __future__ import annotations

import copy
import json
import logging
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from defender import run_common
from defender.run_repository import RunPaths
from defender.learning.branch.estate.registry import EstateError
from defender.runtime import case_ticket
from defender.runtime import run_tenant
from defender.tests import _spec767 as M
from defender.tests import _tenants1106 as T1106
from defender.tests import _triplet_947 as T
from defender.tests._data_root_1078 import current_data_root, ensure_d9_tenant
from defender.tests.e2e._replay_harness import (
    GOLDEN_AB3,
    FakeVerbs,
    ReplayFn,
    Turn,
    drive,
    materialize,
)
from defender.tests.tenant_1078_pass_a import _spec1078 as H
from defender.run_repository import Run as _Run
from defender.tests.tenant_1107_settings import _spec1107 as S

#: The ticket system's gather grant — the table the screen tests' tenant carries, so the replayed
#: gather leg may call `list-tickets` at all.
TICKET_TABLE = """dispositions:
  ticket:
    get-ticket: {roles: [gather]}
    health-check: {roles: [gather]}
    list-tickets: {roles: [gather]}
"""


# ======================================================================================
# Fixture plumbing — returns, never asserts.
# ======================================================================================

def _seeded_run(tmp_path: Path, name: str) -> Path:
    """A run dir the renderer accepts: the alert and a real session store behind its pointer."""
    run_dir = tmp_path / "runs" / name
    run_dir.mkdir(parents=True, exist_ok=True)
    S.plant_alert(run_dir)
    S.seed_session_store(run_dir)
    return run_dir


def _write_receipt(run_dir: Path, doc: Any) -> Path:
    path = S.receipt_path(run_dir)
    path.write_text(doc if isinstance(doc, str) else json.dumps(doc), encoding="utf-8")
    return path


def _failure_receipt(key: str, reason: str) -> dict[str, Any]:
    # d0: a failure receipt carries status 'error', ok false, url null with no usable config, and
    # a non-empty reason.
    return {"key": key, "status": "error", "url": None, "ok": False, "reason": reason}


def _success_receipt(key: str) -> dict[str, Any]:
    # d0: a success receipt carries reason null.
    return {"key": key, "status": "commented", "url": f"http://case-history-1107/tickets/{key}",
            "ok": True, "reason": None}


def _header(run_dir: Path) -> str:
    """The page's own header line for this run — "the rest of the page renders"."""
    return f"defender run: {run_dir.name}"


class _ReceiptWriter:
    """`run.main`'s `ticket_writer` seam: records each call and, on the record step, writes the
    receipt it was given where the real writer writes its receipt. It decides nothing."""

    def __init__(self, receipt: dict[str, Any]) -> None:
        self.receipt = receipt
        self.calls: list[str] = []

    def open_case_ticket(self, run_dir: Path, *_a: Any, **_kw: Any) -> None:
        self.calls.append("open")

    def record_case_ticket(self, run_dir: Path, *_a: Any, **_kw: Any) -> None:
        self.calls.append("record")
        _write_receipt(Path(run_dir), self.receipt)


def _run_world(tmp_path: Path, monkeypatch: Any, name: str) -> tuple[Path, Path, S.DockerShim]:
    """A data-root row (#1078), a complete #1107 tenant set up under this test's data root (#1120:
    `run.py` reads its tenants from `DEFENDER_DATA_ROOT` alone), an alert, and the docker shim
    first on PATH. Returns (data root, alert, shim)."""
    ensure_d9_tenant()
    root = current_data_root()
    S.plant(root, marker=f"pg{name}")
    alert = S.plant_alert(tmp_path / f"alert-{name}")
    shim = S.DockerShim(tmp_path / f"docker-{name}")
    monkeypatch.setenv("PATH", shim.path_value())
    return root, alert, shim


def _screen_leg(tmp_path: Path, root: Path, name: str, tickets: list[dict[str, Any]], *,
                while_serving: Any = None) -> tuple[Path, ReplayFn, list[Any]]:
    """One replayed investigation whose gather leg calls `ticket list-tickets` once, answered by
    a fake verb returning `tickets` (after running `while_serving`, if given). Returns (run dir,
    the gather model — `.seen` is what it was shown — and the verb's recorded contexts)."""
    calls: list[Any] = []

    def list_tickets(ctx: Any) -> dict[str, Any]:
        calls.append(ctx)
        if while_serving is not None:
            while_serving()
        return M.listing(*copy.deepcopy(tickets))

    run_dir = materialize(tmp_path / name, GOLDEN_AB3)
    main = ReplayFn([
        Turn(tool_calls=[("gather", {"lead_id": "l-001", "system": "ticket",
                                     "goal": "measure the ticket lead",
                                     "what_to_summarize": ["what the system says"]})]),
        Turn(text="Investigation complete."),
    ])
    gather = ReplayFn([
        Turn(tool_calls=[("query", {"system": "ticket", "verb": "list-tickets", "params": {}})]),
        Turn(text="Summary: done."),
    ])
    drive(run_dir, run_id=f"r-{name}", main=main, gather=gather,
          verbs=FakeVerbs({"ticket": {"list-tickets": list_tickets}}),
          tenant=S.tenant_folder_of(root))
    return run_dir, gather, calls


def _shown(gather: ReplayFn, needle: str) -> bool:
    return any(needle in seen for seen in gather.seen)


def _plain(value: Any) -> Any:
    """A plain-data copy of a (possibly read-only) mapping, for before/after comparison."""
    if isinstance(value, Mapping):
        return {k: _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    return value


def _mapping_1107() -> str:
    """The `_tenants1106` mapping with every value a consumer answers from made distinctive:
    the signature read from `rule.name` (not the `rule.id` fallback), the reporter and the
    comment author. (It made the released status distinctive too, until #1221's amendment left
    nothing that reads one.)"""
    return (T1106.mapping_text(reporter="rep-1107")
            .replace("signature: rule.id", "signature: rule.name")
            .replace("author: defender", "author: author-1107"))


def _alert_1107(name: str, description: str) -> dict[str, Any]:
    return {"rule": {"id": "r-1107", "name": name, "description": description},
            "timestamp": "2026-09-28T01:02:03Z"}


# ======================================================================================
# The run page's ticket line.
# ======================================================================================

def test_o6_run_page_renders_receipt(tmp_path):
    """The run page renders a failure receipt's key, status and reason, and a success receipt's key and
    status. A run dir without the file renders no ticket line. At base no renderer reads the file
    (C9). The run is started with --update-ticket, which run.py passes to the renderer as an
    argument; without it the page shows no ticket line
    (s7pg_page_ticket_line_only_with_update_ticket)."""
    from defender.scripts.visualize import visualize_run

    run_dir = _seeded_run(tmp_path, "r-o6")
    # The page with no receipt and no flag — the standalone renderer, handed nothing.
    visualize_run.publish_page(_Run.at(run_dir))
    bare = S.page_html(run_dir)
    assert _header(run_dir) in bare, "the standalone page did not render"
    assert "commented" not in bare, "the bare page already says 'commented'; pick another probe"

    # No file, flag passed: no ticket line — the page is the bare page.
    no_file = S.render_page(run_dir, update_ticket=True)
    assert no_file == bare, "a run dir without ticket_write.json rendered a ticket line"

    _write_receipt(run_dir, _failure_receipt("SOC-FAIL-O6-1107", "REASON-O6-1107 store said 503"))
    failed = S.render_page(run_dir, update_ticket=True)
    assert "SOC-FAIL-O6-1107" in failed, "the failure receipt's key is not on the page"
    assert "REASON-O6-1107 store said 503" in failed, "the failure receipt's reason is not shown"
    assert failed.count("error") > bare.count("error"), (
        "the failure receipt's status ('error') is not on the page")

    _write_receipt(run_dir, _success_receipt("SOC-OK-O6-1107"))
    succeeded = S.render_page(run_dir, update_ticket=True)
    assert "SOC-OK-O6-1107" in succeeded, "the success receipt's key is not on the page"
    assert "commented" in succeeded, "the success receipt's status is not on the page"
    assert _header(run_dir) in succeeded, "the rest of the page did not render"


def test_s7_nf26_page_reads_receipt_without_following_links(tmp_path):
    """The run page reads ticket_write.json only as a regular file, never following a link: a symlink
    at that name, to a host settings file or any other file, renders "receipt unreadable" on the
    ticket line and none of the link target's bytes. (The secrets.env target moved with credential
    delivery to #1163; a system's config.env stands for the host-only settings here.)"""
    secret = "HOSTONLY-NF26-1107-do-not-render"
    folder = S.plant(tmp_path / "tenants", marker="nf26")
    settings_file = S.set_key(folder, "case-history", "CASE_HISTORY_MARKER_1107", secret)
    elsewhere = tmp_path / "elsewhere" / "receipt.json"
    elsewhere.parent.mkdir(parents=True)
    elsewhere.write_text(json.dumps(_failure_receipt("SOC-LINKED-NF26-1107",
                                                     "REASON-LINKED-NF26-1107")),
                         encoding="utf-8")

    # Positive control: the SAME bytes as a regular file at the receipt's name render, so the
    # absence below is the link rule's doing and not a page that never shows receipts.
    regular = _seeded_run(tmp_path, "r-nf26-regular")
    _write_receipt(regular, elsewhere.read_text(encoding="utf-8"))
    shown = S.render_page(regular, update_ticket=True)
    assert "SOC-LINKED-NF26-1107" in shown, "a regular receipt did not render (control)"
    assert secret in settings_file.read_text(encoding="utf-8"), "the marker was not planted"

    for label, target, needles in (
        ("a settings file", settings_file, (secret, "CASE_HISTORY_MARKER_1107")),
        ("another file", elsewhere, ("SOC-LINKED-NF26-1107", "REASON-LINKED-NF26-1107")),
    ):
        run_dir = _seeded_run(tmp_path, f"r-nf26-{target.stem}")
        S.receipt_path(run_dir).symlink_to(target)
        assert S.receipt_path(run_dir).is_symlink(), f"{label}: the link was not planted"
        page = S.render_page(run_dir, update_ticket=True)
        assert _header(run_dir) in page, f"{label}: the page did not render"
        assert S.RECEIPT_UNREADABLE in page, (
            f"{label}: a link at ticket_write.json did not render {S.RECEIPT_UNREADABLE!r}")
        for needle in needles:
            assert needle not in page, f"{label}: the link target's bytes ({needle!r}) rendered"


def test_s7_nf26_page_tolerates_and_escapes_receipt(tmp_path):
    """A receipt that is not JSON, or whose fields have the wrong types, renders "receipt unreadable"
    on the ticket line while the rest of the page still renders; every receipt field the page
    renders is escaped, so markup in a reason renders as inert text."""
    good = _failure_receipt("SOC-TYPES-1107", "REASON-TYPES-1107")
    bad: dict[str, str] = {
        "not JSON": '{"key": "SOC-TRUNC-1107", "status": "err',
        "a JSON list": json.dumps([good]),
        "key not a string": json.dumps({**good, "key": 7}),
        "status not a string": json.dumps({**good, "status": ["error"]}),
        "reason not a string": json.dumps({**good, "reason": {"x": "REASON-NESTED-1107"}}),
        "every field wrong": json.dumps({"key": 7, "status": ["error"], "url": 3, "ok": "false",
                                         "reason": {"x": 1}}),
    }
    # Positive control: the well-typed receipt renders its fields.
    control = _seeded_run(tmp_path, "r-types-control")
    _write_receipt(control, good)
    page = S.render_page(control, update_ticket=True)
    assert "SOC-TYPES-1107" in page, "a well-typed receipt did not render (control)"
    assert "REASON-TYPES-1107" in page, "a well-typed receipt did not render (control)"
    assert S.RECEIPT_UNREADABLE not in page, "a well-typed receipt rendered as unreadable"

    for i, (label, text) in enumerate(bad.items()):
        run_dir = _seeded_run(tmp_path, f"r-types-{i}")
        _write_receipt(run_dir, text)
        page = S.render_page(run_dir, update_ticket=True)
        assert S.RECEIPT_UNREADABLE in page, f"{label}: not rendered as {S.RECEIPT_UNREADABLE!r}"
        assert _header(run_dir) in page, f"{label}: the rest of the page did not render"
        assert "spec 1107" in page, f"{label}: the alert block did not render"

    markup = "<img src=x onerror=alert(1)>"
    run_dir = _seeded_run(tmp_path, "r-markup")
    _write_receipt(run_dir, _failure_receipt(f"{markup}KEY-MARKUP-1107",
                                             f"{markup}REASON-MARKUP-1107"))
    page = S.render_page(run_dir, update_ticket=True)
    assert "KEY-MARKUP-1107" in page, "the markup receipt's fields did not render at all"
    assert "REASON-MARKUP-1107" in page, "the markup receipt's fields did not render at all"
    assert markup not in page, "receipt markup reached the page live"
    assert "&lt;img src=x onerror=alert(1)&gt;" in page, "receipt markup was not escaped"


def test_s7pg_page_ticket_line_only_with_update_ticket(tmp_path, monkeypatch):
    """The run page shows a ticket line only when the run was started with --update-ticket, and it
    learns that from run.py directly: run.py renders the page after the box is torn down (RG7) and
    passes its own --update-ticket flag to the renderer as an argument. With the flag, a receipt in
    the run dir renders its key, status and reason; without it, any ticket_write.json (one an
    earlier attempt left, or a symlink) is ignored, the page renders no ticket line and none of the
    file's bytes, and the rest of the page renders. A render that is not handed the flag (the
    renderer run standalone) shows no ticket line. The renderer reads the flag from no manifest, no
    provenance stamp and no other run-dir file."""
    from defender.scripts.visualize import visualize_run

    root, alert, _shim = _run_world(tmp_path, monkeypatch, "pg")
    outside = tmp_path / "outside" / "left.json"
    outside.parent.mkdir(parents=True)
    outside.write_text(json.dumps(_failure_receipt("SOC-LINK-PG-1107", "REASON-LINK-PG-1107")),
                       encoding="utf-8")

    # --- WITH the flag: run.py renders after the lifecycle, handing the renderer its flag. ---
    writer = _ReceiptWriter(_failure_receipt("SOC-FLAG-PG-1107", "REASON-FLAG-PG-1107"))
    rec = S.RunRecorder(tmp_path / "runs" / "r-pg-flag")
    rc, refused = S.drive_run(S.run_argv(alert, root, update_ticket=True), rec,
                              ticket_writer=writer, visualize=run_common.visualize)
    run_dir = rec.run_dir_at
    assert (rc, refused) == (0, None), f"the flagged run did not finish: {refused}"
    assert writer.calls == ["open", "record"], f"the ticket lane ran {writer.calls}"
    assert S.receipt(run_dir) is not None, "the flagged run left no receipt"
    flagged = S.page_html(run_dir)
    # The standalone render of the SAME dir, receipt still present: handed no flag.
    visualize_run.publish_page(_Run.at(run_dir))
    standalone = S.page_html(run_dir)
    S.receipt_path(run_dir).unlink()
    visualize_run.publish_page(_Run.at(run_dir))
    no_receipt = S.page_html(run_dir)
    assert _header(run_dir) in no_receipt, "the receipt-less page did not render"
    assert "SOC-FLAG-PG-1107" in flagged, "with --update-ticket the receipt's key is not shown"
    assert "REASON-FLAG-PG-1107" in flagged, "with --update-ticket the receipt's reason is not shown"
    assert flagged.count("error") > no_receipt.count("error"), (
        "with --update-ticket the receipt's status ('error') is not shown")
    assert standalone == no_receipt, (
        "the renderer run standalone (no flag handed) showed a ticket line — it read the flag "
        "from somewhere other than its argument")

    # --- WITHOUT the flag: a receipt an earlier attempt left, and a link, are both ignored. ---
    for label, plant, needles in (
        ("an earlier attempt's receipt",
         lambda rd: _write_receipt(rd, _failure_receipt("SOC-LEFT-PG-1107",
                                                        "REASON-LEFT-PG-1107")),
         ("SOC-LEFT-PG-1107", "REASON-LEFT-PG-1107")),
        ("a symlink",
         lambda rd: S.receipt_path(rd).symlink_to(outside),
         ("SOC-LINK-PG-1107", "REASON-LINK-PG-1107")),
    ):
        tag = "left" if "earlier" in label else "link"
        rec = S.RunRecorder(tmp_path / "runs" / f"r-pg-{tag}", before_lifecycle=plant)
        rc, refused = S.drive_run(S.run_argv(alert, root, run_id=f"r-pg-{tag}"), rec,
                                  visualize=run_common.visualize)
        run_dir = rec.run_dir_at
        assert (rc, refused) == (0, None), f"{label}: the run did not finish: {refused}"
        at_name = S.receipt_path(run_dir)
        assert at_name.is_symlink() or at_name.is_file(), f"{label}: nothing was planted"
        page = S.page_html(run_dir)
        assert _header(run_dir) in page, f"{label}: the page run.py rendered is missing"
        for needle in needles:
            assert needle not in page, f"{label}: without --update-ticket {needle!r} rendered"
        at_name.unlink()
        visualize_run.publish_page(_Run.at(run_dir))
        assert page == S.page_html(run_dir), (
            f"{label}: without --update-ticket the page is not the receipt-less page")


def test_s7pg_box_planted_flag_and_receipt_render_no_ticket_line(tmp_path, monkeypatch):
    """A run started without --update-ticket whose box, while alive, wrote an update_ticket: true flag
    into the provenance stamp and into a manifest-shaped file in the run dir, and planted a forged
    ticket_write.json ({status: commented, ok: true}): the page run.py renders after teardown shows
    no ticket line and none of the receipt's bytes. Positive control, same planted run dir: rendered
    with run.py's flag passed as true, the page shows the ticket line, so the absence above is the
    argument's doing and not a renderer that never reads receipts."""
    from defender.scripts.visualize import visualize_run

    root, alert, _shim = _run_world(tmp_path, monkeypatch, "box")
    forged = {"key": "SOC-FORGED-BOX-1107", "status": "commented",
              "url": "http://forged-box-1107/tickets/x", "ok": True,
              "reason": "REASON-FORGED-BOX-1107"}

    def box_writes(run_dir: Path) -> None:
        # What the box, root on its rw bind while alive, can leave in the run dir: the flag in the
        # provenance stamp and in manifest-shaped files, and a forged receipt.
        RunPaths(run_dir).provenance.write_text(json.dumps(
            {**T.provenance_record(tenant_id=S.PLAYGROUND_ID), "update_ticket": True}),
            encoding="utf-8")
        (run_dir / "manifest.json").write_text(json.dumps({"update_ticket": True}),
                                               encoding="utf-8")
        (run_dir / "family.yaml").write_text("update_ticket: true\n", encoding="utf-8")
        _write_receipt(run_dir, forged)

    rec = S.RunRecorder(tmp_path / "runs" / "r-box", before_lifecycle=box_writes)
    rc, refused = S.drive_run(S.run_argv(alert, root, run_id="r-box"), rec,
                              visualize=run_common.visualize)
    run_dir = rec.run_dir_at
    assert (rc, refused) == (0, None), f"the run did not finish: {refused}"
    assert S.receipt(run_dir) == forged, "the forged receipt did not survive to the render"
    page = S.page_html(run_dir)
    assert _header(run_dir) in page, "the page run.py rendered after teardown is missing"
    for needle in ("SOC-FORGED-BOX-1107", "REASON-FORGED-BOX-1107", "forged-box-1107"):
        assert needle not in page, f"the forged receipt's bytes ({needle!r}) rendered"
    assert page.count("commented") == 0, "a ticket line ('commented') rendered without the flag"

    # The same dir without the receipt, standalone: the page run.py rendered is exactly that.
    S.receipt_path(run_dir).unlink()
    visualize_run.publish_page(_Run.at(run_dir))
    assert page == S.page_html(run_dir), "the page run.py rendered carries a ticket line"

    # Positive control, same planted run dir: handed run.py's flag as true, the line renders.
    _write_receipt(run_dir, forged)
    run_common.visualize(_Run.at(run_dir), update_ticket=True)
    flagged = S.page_html(run_dir)
    assert "SOC-FORGED-BOX-1107" in flagged, (
        "handed the flag, the renderer still shows no ticket line — the absence above proves "
        "nothing")


# ======================================================================================
# The record's case mapping and its consumers.
# ======================================================================================

def test_d_case_ticket_takes_mapping(tmp_path):
    """The case_ticket functions that consume the mapping (alert_to_open_payload,
    read_case_record, case_record_to_comment, escalation_comment_payload,
    unreadable_comment_payload — and release_predicate, until #1221's amendment removed it) take
    a CaseMapping instead of settings_dir. None of them reads
    mapping.yaml: called with a CaseMapping while no mapping file exists anywhere, they answer from
    it."""
    root = tmp_path / "tenants"
    folder = S.plant(root, marker="map")
    S.mapping_path(folder).write_text(_mapping_1107(), encoding="utf-8")
    record = run_tenant.resolve_tenant(root, S.PLAYGROUND_ID, defender_dir=S.DEFENDER,
                                       dispatches_lead_zero=False)
    mapping = record.ticket_mapping
    assert isinstance(mapping, S.record_type("CaseMapping")), f"ticket_mapping is {mapping!r}"
    S.mapping_path(folder).unlink()
    assert not S.mapping_path(folder).exists(), "the mapping file is still there"

    alert = _alert_1107("sig-name-1107", "summary-1107")
    payload = S.with_mapping(case_ticket.alert_to_open_payload, alert, "case-1107", mapping=mapping)
    assert payload["key"] == "case-1107", payload
    assert payload["reporter"] == "rep-1107", payload
    assert "sig:sig-name-1107" in payload["labels"], payload

    run_dir = M.make_run(tmp_path / "runs", "case-rec-1107", alert=alert)
    rec = S.with_mapping(case_ticket.read_case_record, run_dir, mapping=mapping)
    assert rec.signature_id == "sig-name-1107", rec
    comment = S.with_mapping(case_ticket.case_record_to_comment, rec, mapping=mapping)
    assert comment["author"] == "author-1107", comment
    assert comment["body"].startswith("benign — "), comment

    escalation = S.with_mapping(case_ticket.escalation_comment_payload, "aborted", mapping=mapping)
    assert escalation["author"] == "author-1107", escalation
    unreadable = S.with_mapping(case_ticket.unreadable_comment_payload, mapping=mapping)
    assert unreadable["author"] == "author-1107", unreadable


def test_s7_mf11_mutating_callers_copy_locally(tmp_path):
    """The case_ticket callers that mutate the mapping today (F11, the reason _MAPPING_CACHE hands out
    deep copies) still build their payloads correctly from a read-only CaseMapping, each working on
    a local copy."""
    root = tmp_path / "tenants"
    folder = S.plant(root, marker="mf11")
    S.mapping_path(folder).write_text(_mapping_1107(), encoding="utf-8")
    record = run_tenant.resolve_tenant(root, S.PLAYGROUND_ID, defender_dir=S.DEFENDER,
                                       dispatches_lead_zero=False)
    mapping = record.ticket_mapping
    before = _plain(mapping)

    first = _alert_1107("sig-one-1107", "first case")
    second = _alert_1107("sig-two-1107", "second case")
    one = S.with_mapping(case_ticket.alert_to_open_payload, first, "case-one", mapping=mapping)
    kept = copy.deepcopy(one)
    # A caller does what callers do with a payload: edits it.
    one["labels"].append("planted-1107")
    one["status"] = "planted-1107"
    two = S.with_mapping(case_ticket.alert_to_open_payload, second, "case-two", mapping=mapping)
    assert two["labels"] == ["sig:sig-two-1107", "evt:2026-09-28T01:02:03Z"], two
    assert two["status"] == "open", two
    assert two["key"] == "case-two", two
    again = S.with_mapping(case_ticket.alert_to_open_payload, first, "case-one", mapping=mapping)
    assert again == kept, "an edit to one payload reached the next built from the same mapping"

    run_dir = M.make_run(tmp_path / "runs", "case-mf11", alert=first)
    rec = S.with_mapping(case_ticket.read_case_record, run_dir, mapping=mapping)
    comment = S.with_mapping(case_ticket.case_record_to_comment, rec, mapping=mapping)
    comment["author"] = "planted-1107"
    escalation = S.with_mapping(case_ticket.escalation_comment_payload, "aborted", mapping=mapping)
    escalation["author"] = "planted-1107"
    unreadable = S.with_mapping(case_ticket.unreadable_comment_payload, mapping=mapping)
    assert unreadable["author"] == "author-1107", unreadable
    assert S.with_mapping(case_ticket.case_record_to_comment, rec,
                        mapping=mapping)["author"] == "author-1107", "a comment edit leaked"
    assert S.open_reporter(mapping) == "rep-1107"
    assert _plain(mapping) == before, "building payloads changed the record's mapping"


def test_d_mapping_error_consumers(tmp_path, caplog):
    """With record.ticket_mapping a CaseTicketError, the record step warns and writes an error
    receipt (CX21, as at base), and nothing else is touched by it: the query tool reads no
    mapping, so a ticket listing reaches gather whole — keys and comments, open or closed — with
    no warning about the mapping. (#1221 removed the query tool's release screen, which degraded
    to serving no comments here, and the estate applier's comment-patch refusal.)"""
    root = tmp_path / "tenants"
    # A templated `open.status`: the loader's own lifecycle refusal (#767; since #1221's amendment
    # its only one), a mapping file present (so the tenant is accepted, REQUIRED_SETTINGS) and
    # unusable.
    S.plant(root, marker="bad", table=TICKET_TABLE, open_status="{summary}")
    record = run_tenant.resolve_tenant(root, S.PLAYGROUND_ID, defender_dir=S.DEFENDER,
                                       dispatches_lead_zero=False)
    error = record.ticket_mapping
    assert isinstance(error, S.case_ticket_error()), f"ticket_mapping is {error!r}"
    said = str(error)

    # (a) The query tool: no mapping is read, so every ticket is served whole; no warning.
    caplog.set_level(logging.WARNING)
    tickets = [M.ticket("SOC-OPEN-1107", status="open", comments=[M.comment("MARK-OPEN-1107")]),
               M.ticket("SOC-CLOSED-1107", status="closed",
                        comments=[M.comment("MARK-CLOSED-1107")])]
    caplog.clear()
    run_dir, gather, calls = _screen_leg(tmp_path, root, "screen-err", tickets)
    assert len(calls) == 1, f"the ticket verb ran {len(calls)} times"
    for shown in ("SOC-OPEN-1107", "SOC-CLOSED-1107", "MARK-OPEN-1107", "MARK-CLOSED-1107"):
        assert _shown(gather, shown), f"{shown} was withheld from gather under a bad mapping"
    warned = [r for r in caplog.records
              if r.name == "defender.runtime.query_tool" and r.levelno >= logging.WARNING
              and said in r.getMessage()]
    assert warned == [], "the query tool still reads the case-history mapping"

    # (b) The record step: a warning and an error receipt, no comment sent.
    case_dir = M.make_run(tmp_path / "runs", "case-err-1107")
    # CX8: the shim on the child's PATH receives argv + env; it answers a POST as created, in
    # curl's body + status-line shape.
    shim = S.DockerShim(tmp_path / "docker", S.store_answers_ok(case_dir.name))
    caplog.clear()
    assert S.record_step(case_dir, record, env=shim.env()) is None
    got = S.receipt(case_dir)
    assert got is not None, "the record step left no receipt"
    assert got["status"] == "error", got
    assert got["ok"] is False, got
    assert got["reason"], got
    assert any(r.levelno >= logging.WARNING and said in r.getMessage()
               for r in caplog.records), "the record step did not warn naming the mapping error"
    assert not any("/comments" in " ".join(c["argv"]) for c in shim.calls()), (
        "a comment was sent off a bad mapping")


def test_o2_ticket_replies_ignore_the_mapping(tmp_path):
    """Neither the record's ticket_mapping nor an edit of mapping.yaml after the record is built
    changes what a ticket reply serves: the query tool reads no mapping, so a case closed under
    the mapping as built, one closed only under the edited file, and an open one all reach
    gather with their comments. (#1221 removed the release screen that once read the record's
    released status here; its amendment removed the released status itself, so the mid-run edit
    moves the reporter, and the "edited" case's status is one only that edit names.)"""
    root = tmp_path / "tenants"
    folder = S.plant(root, marker="o2", table=TICKET_TABLE)
    record = run_tenant.resolve_tenant(root, S.PLAYGROUND_ID, defender_dir=S.DEFENDER,
                                       dispatches_lead_zero=False)
    assert S.open_reporter(record.ticket_mapping) == "defender"

    def edit_mapping() -> None:
        # Mid-run, after the record was built: an operator edits the mapping.
        S.mapping_path(folder).write_text(
            T1106.mapping_text(reporter="done-edited-1107"), encoding="utf-8")

    tickets = [M.ticket("SOC-CLOSED-O2", status="closed", comments=[M.comment("MARK-CLOSED-O2")]),
               M.ticket("SOC-EDITED-O2", status="done-edited-1107",
                        comments=[M.comment("MARK-EDITED-O2")]),
               M.ticket("SOC-OPEN-O2", status="open", comments=[M.comment("MARK-OPEN-O2")])]
    run_dir, gather, calls = _screen_leg(tmp_path, root, "screen-o2", tickets,
                                         while_serving=edit_mapping)
    assert len(calls) == 1, f"the ticket verb ran {len(calls)} times"
    assert "done-edited-1107" in S.mapping_path(folder).read_text(encoding="utf-8"), (
        "the mid-run edit did not land")
    for marker in ("MARK-CLOSED-O2", "MARK-EDITED-O2", "MARK-OPEN-O2"):
        assert _shown(gather, marker), f"{marker} was withheld — a ticket reply read the mapping"
        assert S.holders(run_dir, marker), f"{marker} never reached the run's capture"


def test_c_estate_registry_takes_no_mapping(tmp_path, monkeypatch):
    """A resumed sibling's WorldRegistry, built in run.py, builds a world whose facts put a note
    on a case whatever status the case is in — the status the record was built with, or one only
    a mid-run edit of mapping.yaml names: no ticket reply is screened any more, so the registry
    consults no mapping. (#1221 removed the estate applier's refusal, which judged a comment
    patch against the record's ticket_mapping; #1224 replaced the patches with world facts.)"""
    # #1120: the resumed sibling reads its tenant from `DEFENDER_DATA_ROOT` alone.
    root = current_data_root()
    folder = S.plant(root, marker="est", table=TICKET_TABLE)
    probe = run_tenant.resolve_tenant(root, S.PLAYGROUND_ID, defender_dir=S.DEFENDER,
                                      dispatches_lead_zero=False)
    assert S.open_reporter(probe.ticket_mapping) == "defender"

    def note(entity: str, status: str) -> list[dict[str, Any]]:
        return [T.fact("f1", f"case {entity} is in status {status} and carries a defender note "
                             "that the same binary was benign last quarter", (entity,))]

    _base, src = T.runs_base(tmp_path)
    ep = T.episode(tmp_path, doc=T.family_doc(source_run_dir=str(src), worlds=[
        T.base_world(),
        T.world_doc("b", facts=note("SOC-1", "closed")),
        T.world_doc("c", facts=note("SOC-2", "done-edited-1107")),
    ]))
    shim = S.DockerShim(tmp_path / "docker")
    monkeypatch.setenv("PATH", shim.path_value())
    run = S.run_py()

    def resume(world: str) -> tuple[Any, list[dict[str, Any]], dict[str, Any]]:
        # The record is built from the file as planted; the edit lands after (preflight runs
        # after `tenant = tenant_of()`), each run afresh.
        S.mapping_path(folder).write_text(T1106.mapping_text(),
                                          encoding="utf-8")
        investigated: list[dict[str, Any]] = []
        handed: dict[str, Any] = {}

        def edit_after_record(_model: str | None = None, *, branching: bool = False) -> int:
            S.mapping_path(folder).write_text(
                T1106.mapping_text(reporter="done-edited-1107"), encoding="utf-8")
            return 0

        def lifecycle(**kw: Any) -> dict[str, Any]:
            handed.update(kw)
            rd = kw["run_dir"]
            return run._drive_investigation(
                alert_path=RunPaths(rd).alert, run_dir=rd, run_id=rd.name,
                defender_dir=kw["defender_dir"], model_name=kw["model"],
                model_override=kw["model_override"], box=None, tenant=kw["tenant"],
                world=kw["world"], episode=kw["episode"], serving=kw["serving"],
                investigate=lambda **ikw: investigated.append(ikw) or {
                    "output": "spec1107", "requests": 0, "truncated_by": None})

        rec = S.RunRecorder(tmp_path / "siblings" / world)
        try:
            outcome: Any = S.drive_run(
                H.resume_argv(ep / "family.yaml", world, "--tenant", S.PLAYGROUND_ID,
                              "--no-learn"),
                rec, preflight=edit_after_record, lifecycle=lifecycle)
        except EstateError as refused:
            outcome = refused
        return outcome, investigated, handed

    got_b, investigated_b, _ = resume("b")
    assert "done-edited-1107" in S.mapping_path(folder).read_text(encoding="utf-8"), (
        "the post-record edit did not land")
    assert got_b == (0, None), (
        f"world b (comments on a case moved to the status the record was built with) was "
        f"refused: {got_b}")
    assert len(investigated_b) == 1, "world b's WorldRegistry was built but nothing ran on it"

    got_c, investigated_c, _ = resume("c")
    assert got_c == (0, None), (
        f"world c (comments on a status only the edited file names) was refused: {got_c}")
    assert len(investigated_c) == 1, "world c's WorldRegistry was built but nothing ran on it"

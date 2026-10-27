"""#1108 P4 slice S-C — O-WARN (U8): a run that used stale tenant knowledge says so wherever its
result is read. This module holds the ticket write-back and the API halves (the run page's banner
is `test_run_page.py`, which imports the run-record helpers below).

- Ticket write-back: EVERY comment the run posts (verdict, unreadable-report and escalation
  branches alike) carries ONE fixed sentence: the investigation used the tenant's knowledge as of
  an earlier version, newer approved knowledge could not be loaded, the commit id, and the kind in
  customer words (temporary vs. awaiting operator action) — never the raw reason. Fresh and pinned
  runs carry no sentence. Observed on the payload the ticket store fake CAPTURES (inbound).
- API: `Investigation.knowledge = {status: current|stale|pinned, commit, stale_kind:
  transient|operator|null}`, carried through the store port and exercised by the stub's records.

The sentence's wording is not frozen: it is recovered as "what the stale comment adds to the fresh
comment of the same run", then held to the design's properties (one sentence, the same on every
branch, names the commit and the kind, leaks no reason).
"""
from __future__ import annotations

import html
import json
import re
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from defender.tests.support.runtime.engine._spec767 import (
    HOST_CAUSE,
    WIRE_BOUND_BYTES,
    FakeStore,
    make_run,
    record,
    use_mapping,
)

# ---------------------------------------------------------------------------------------------
# The run record's `knowledge_source` (O-STALE; slice S-B produces it at run start, this slice
# owns what its readers do with it). ONE place spells its shape, so the open representation
# question below is a one-line change for every S-C test.
# ---------------------------------------------------------------------------------------------

#: The run record's vocabulary (design O-STALE). The API says `current` where the record says
#: `fresh` (pinned on production by `test_o_warn_api_maps_the_run_records_knowledge_source_*`).
RECORD_KINDS = ("fresh", "stale", "pinned")
STALE_KINDS = ("transient", "operator")

#: Commits as the knowledge reader accepts them (40 lowercase hex). Distinct per role, and never
#: anything a page or comment shows today, so finding one in the output means a reader put it there.
STALE_COMMIT = "5e7a11c0ffee5e7a11c0ffee5e7a11c0ffee5e7a"
FRESH_COMMIT = "f4e5c0de0000f4e5c0de0000f4e5c0de0000f4e5"
PINNED_COMMIT = "91aced0091aced0091aced0091aced0091aced00"

#: Raw reasons as the publish child classifies them (O-STALE): an issuer outage (transient) and a
#: refused AppRole login (operator). Each carries a URL, error text and a credential hint, none
#: of which may reach a customer's ticket.
RAW_REASON = {
    "transient": ("issuer https://bao.dev.invalid:8200/v1/auth/approle/login timed out after 30s "
                  "(ConnectTimeout)"),
    "operator": ("auth refused: permission denied for secret_id 7f3e91c2 at "
                 "https://bao.dev.invalid:8200/v1/auth/approle/login"),
}
#: Fragments of either raw reason; none may appear in a posted comment.
#: The port only as `:8200`: a bare "8200" can occur in a random hex commit or run id.
REASON_FRAGMENTS = ("https://", "bao.dev.invalid", ":8200", "approle", "timed out",
                    "ConnectTimeout", "permission denied", "secret_id", "7f3e91c2")

#: The customer words for each stale kind (design O-WARN: "temporary vs. awaiting operator
#: action"), as case-insensitive stems.
CUSTOMER_WORD = {"transient": "temporar", "operator": "operator"}

#: How much of a commit id a reader must show to have "named the commit": git's own short form.
#: The full id satisfies it too. (Reported: the design says "the commit id"; a prefix is accepted.)
SHORT_COMMIT = 7


def knowledge_source(kind: str, *, stale_kind: str | None = None, commit: str | None = None,
                     reason: str | None = None) -> dict[str, Any]:
    """The run record's `knowledge_source` as its wire mapping (design O-STALE:
    `{kind: fresh|stale|pinned, commit, reason}`).

    GAP (reported, not settled by the design): where a stale record's transient/operator kind
    lives. Chosen HERE ONLY, so the choice is one edit: a `stale_kind` key beside `kind`, present
    for `stale` records, mirroring the API's field. Alternatives: `kind: "stale:transient"`, as
    the child reports it; or the reason prefixed with the kind."""
    assert kind in RECORD_KINDS, kind
    if kind == "stale":
        assert stale_kind in STALE_KINDS, stale_kind
    source: dict[str, Any] = {
        "kind": kind,
        "commit": commit if commit is not None else {
            "fresh": FRESH_COMMIT, "stale": STALE_COMMIT, "pinned": PINNED_COMMIT}[kind],
        "reason": reason if reason is not None else (RAW_REASON[stale_kind] if stale_kind else None),
    }
    if kind == "stale":
        source["stale_kind"] = stale_kind
    return source


def host_record_path(run_dir: Path) -> Path:
    """The HOST-HELD knowledge-source record (U12): a sidecar beside the run dir, keyed by the
    run's id, like the ticket receipt (`RunPaths.ticket_write`, `<run_id>.ticket-write.json`).
    ASSUMED SEAM (reported): `RunPaths(run_dir).knowledge_source(runs_base=None)` ->
    `<runs base>/<run_id>.knowledge-source.json`, JSON `{kind, commit, stale_kind?, reason}`."""
    from defender.records import RunPaths

    return Path(RunPaths(run_dir).knowledge_source())


def write_host_record(run_dir: Path, source: dict[str, Any]) -> Path:
    """Plant the host record as run start leaves it (slice S-B writes it; every reader reads it)."""
    path = host_record_path(run_dir)
    path.write_text(json.dumps(source, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def stamp_view(source: dict[str, Any]) -> dict[str, Any]:
    """What the box-readable provenance stamp may carry of a knowledge source (OD17): kind,
    commit, stale kind — never the raw reason."""
    return {k: v for k, v in source.items() if k != "reason"}


def stamp_knowledge_source(run_dir: Path, source: dict[str, Any] | None) -> None:
    """Write `source` as the `knowledge_source` field of the run's provenance stamp, keeping every
    other field; `None` removes it. The stamp sits in the box's rw bind (OD17: informational,
    authoritative for no reader), so the tests use this to play the BOX rewriting it."""
    from defender.records import RunPaths

    path = RunPaths(run_dir).provenance
    stamp = (json.loads(path.read_text(encoding="utf-8")) if path.is_file()
             else {"commit": "0" * 40, "dirty": False})
    if source is None:
        stamp.pop("knowledge_source", None)
    else:
        stamp["knowledge_source"] = source
    path.write_text(json.dumps(stamp, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def names_commit(text: str, commit: str) -> bool:
    return commit[:SHORT_COMMIT] in text


def _ws(text: str) -> str:
    return " ".join(text.split())


# ---------------------------------------------------------------------------------------------
# Ticket write-back
# ---------------------------------------------------------------------------------------------
#
# Entry: the REAL `ticket_writer.record_case_ticket` through its one store seam
# (`TicketWriterDeps.request` = `FakeStore`, which records every call it is handed). The run's
# knowledge source is the HOST record beside the run dir (U12, `write_host_record`), never the
# box-writable stamp. `test_run_main_*` below drive the run-start wiring that writes it.

#: The three branches a posted comment can take (`ticket_writer._build_comment_payload` and the
#: aborted arm of `record_case_ticket`): run-dir report text (None: a readable verdict) and the
#: exit class handed in.
BRANCHES = {
    "verdict": {"text": None, "truncated_by": None},
    "unreadable": {"text": "just prose, no fence\n", "truncated_by": None},
    "escalation-aborted": {"text": None, "truncated_by": "aborted"},
    "escalation-forced-close": {"text": "just prose, no fence\n", "truncated_by": "request-limit"},
}


def _posted(tmp_path: Path, branch: str, source: dict[str, Any], *, label: str,
            body: str | None = None) -> tuple[str, str]:
    """Drive the real writer over a fresh run dir on `branch` with `source` as the run's
    knowledge source; return (the comment body below the agent tag, the whole wire body), as the
    store fake received them."""
    spec = BRANCHES[branch]
    report_kw: dict[str, Any] = {}
    if spec["text"] is not None:
        report_kw["text"] = spec["text"]
    elif body is not None:
        report_kw["body"] = body
    run_dir = make_run(tmp_path, name=f"s-c-{branch}-{label}", **report_kw)
    write_host_record(run_dir, source)
    store = FakeStore()
    record(run_dir, store, truncated_by=spec["truncated_by"])
    return store.comment_body(), store.wire_body()


def _added(fresh: str, stale: str) -> str:
    """What `stale` adds to `fresh`: the one contiguous insertion, asserted to be all it does."""
    head = 0
    while head < min(len(fresh), len(stale)) and fresh[head] == stale[head]:
        head += 1
    tail = 0
    while (tail < min(len(fresh), len(stale)) - head
           and fresh[len(fresh) - 1 - tail] == stale[len(stale) - 1 - tail]):
        tail += 1
    added = stale[head:len(stale) - tail]
    assert stale[:head] + stale[len(stale) - tail:] == fresh, (
        "the stale run's comment changes the fresh run's comment instead of only adding the "
        f"stale sentence to it:\nfresh: {fresh!r}\nstale: {stale!r}")
    return added.strip()


def _stale_sentence(tmp_path: Path, stale_kind: str) -> str:
    fresh, _ = _posted(tmp_path, "verdict", knowledge_source("fresh"), label=f"fresh-{stale_kind}")
    stale, _ = _posted(tmp_path, "verdict", knowledge_source("stale", stale_kind=stale_kind),
                       label=f"stale-{stale_kind}")
    sentence = _added(fresh, stale)
    assert sentence, (
        f"O-WARN: a stale ({stale_kind}) run posted exactly the comment a fresh run posts — "
        "the ticket says nothing about the knowledge being out of date")
    return sentence


@pytest.mark.parametrize("stale_kind", STALE_KINDS)
def test_o_warn_a_stale_runs_verdict_comment_carries_the_fixed_sentence_naming_commit_and_kind(
        tmp_path, monkeypatch, stale_kind):
    """O-WARN: a stale run's verdict comment adds one sentence to what a fresh run posts; it
    names the commit used and the kind in customer words, and no part of the raw reason."""
    use_mapping(monkeypatch, tmp_path / "dfn")
    sentence = _stale_sentence(tmp_path, stale_kind)

    assert names_commit(sentence, STALE_COMMIT), (
        f"O-WARN: the stale sentence does not name the commit the run used ({STALE_COMMIT}): "
        f"{sentence!r}")
    assert CUSTOMER_WORD[stale_kind] in sentence.lower(), (
        f"O-WARN: the {stale_kind} sentence does not say, in customer words, that the cause is "
        f"{'temporary' if stale_kind == 'transient' else 'awaiting operator action'}: {sentence!r}")
    other = CUSTOMER_WORD[next(k for k in STALE_KINDS if k != stale_kind)]
    assert other not in sentence.lower(), (
        f"O-WARN: the {stale_kind} sentence uses the other kind's words ({other!r}): {sentence!r}")
    leaked = [f for f in REASON_FRAGMENTS if f.lower() in sentence.lower()]
    assert leaked == [], (
        f"O-WARN: the customer's ticket carries the raw publish reason ({leaked}): {sentence!r}")
    assert len(re.findall(r"[.!?](?:\s|$)", sentence)) <= 1, (
        f"O-WARN: one fixed sentence, not several: {sentence!r}")


def test_o_warn_transient_and_operator_sentences_differ_and_each_is_fixed_per_kind(
        tmp_path, monkeypatch):
    """O-WARN: the sentence is fixed per (kind, commit) — the same whatever the reason text —
    and the two kinds read differently."""
    use_mapping(monkeypatch, tmp_path / "dfn")
    first = {k: _stale_sentence(tmp_path / f"a-{k}", k) for k in STALE_KINDS}
    assert first["transient"] != first["operator"], (
        "O-WARN: a temporary outage and a fault awaiting operator action post the same sentence")

    fresh, _ = _posted(tmp_path, "verdict", knowledge_source("fresh"), label="fresh-other-reason")
    for k in STALE_KINDS:
        other_reason = knowledge_source("stale", stale_kind=k,
                                        reason=f"tenant lock busy (pid 4242) — {k} variant")
        stale, _ = _posted(tmp_path, "verdict", other_reason, label=f"other-reason-{k}")
        assert _added(fresh, stale) == first[k], (
            f"O-WARN: the {k} sentence changes with the raw reason — it is not one fixed "
            "sentence, and a reason reaches the ticket through it")


@pytest.mark.parametrize("branch", [b for b in BRANCHES if b != "verdict"])
@pytest.mark.parametrize("stale_kind", STALE_KINDS)
def test_o_warn_every_comment_branch_carries_the_same_stale_sentence(
        tmp_path, monkeypatch, branch, stale_kind):
    """O-WARN: the unreadable-report and escalation comments carry the very sentence the
    verdict comment carries; the fresh comment on the same branch carries none of it."""
    use_mapping(monkeypatch, tmp_path / "dfn")
    sentence = _stale_sentence(tmp_path / "verdict", stale_kind)

    fresh, _ = _posted(tmp_path, branch, knowledge_source("fresh"), label="fresh")
    stale, _ = _posted(tmp_path, branch, knowledge_source("stale", stale_kind=stale_kind),
                       label="stale")
    assert sentence not in fresh, f"positive control: the fresh {branch} comment has it: {fresh!r}"
    assert sentence in stale, (
        f"O-WARN: the {branch} comment of a stale ({stale_kind}) run lacks the stale sentence "
        f"the verdict comment carries.\nsentence: {sentence!r}\ncomment: {stale!r}")
    assert _ws(stale.replace(sentence, "", 1)) == _ws(fresh), (
        f"O-WARN: on the {branch} branch the stale comment differs from the fresh one by more "
        f"than the sentence.\nfresh: {fresh!r}\nstale: {stale!r}")
    leaked = [f for f in REASON_FRAGMENTS if f.lower() in stale.lower()]
    assert leaked == [], f"O-WARN: the {branch} comment leaks the raw reason: {leaked}"


@pytest.mark.parametrize("stale_kind", STALE_KINDS)
def test_o_warn_the_sentence_survives_the_wire_bound_on_a_long_verdict(
        tmp_path, monkeypatch, stale_kind):
    """O-WARN: "every comment carries" holds when the narrative fills the 4096-byte wire bound,
    which cuts from the end: the sentence is still whole in the posted body."""
    use_mapping(monkeypatch, tmp_path / "dfn")
    sentence = _stale_sentence(tmp_path / "short", stale_kind)

    long_narrative = "The account authenticated from a known bastion. " * 200
    assert len(long_narrative.encode("utf-8")) > WIRE_BOUND_BYTES
    _, fresh_wire = _posted(tmp_path, "verdict", knowledge_source("fresh"), label="long-fresh",
                            body=long_narrative)
    _, stale_wire = _posted(tmp_path, "verdict",
                            knowledge_source("stale", stale_kind=stale_kind),
                            label="long-stale", body=long_narrative)
    assert len(fresh_wire.encode("utf-8")) <= WIRE_BOUND_BYTES, "positive control: bound applies"
    assert len(stale_wire.encode("utf-8")) <= WIRE_BOUND_BYTES, (
        "the stale sentence pushed the posted comment past the wire bound")
    assert sentence in stale_wire, (
        "O-WARN: the wire bound cut the stale sentence off a long verdict comment — the customer "
        "is not told this investigation used out-of-date knowledge")


@pytest.mark.parametrize("branch", list(BRANCHES))
@pytest.mark.parametrize("kind", ["fresh", "pinned"])
def test_o_warn_fresh_and_pinned_runs_post_exactly_todays_comment(
        tmp_path, monkeypatch, branch, kind):
    """O-WARN: fresh and pinned runs carry no sentence: each branch posts exactly the comment it
    posts today (the shipped host sentences / the mapping's verdict rendering)."""
    from defender.tenancy import case_ticket

    use_mapping(monkeypatch, tmp_path / "dfn")
    body, _ = _posted(tmp_path, branch, knowledge_source(kind), label=kind)
    expected = {
        "verdict": f"benign — {HOST_CAUSE}\n\n"
                   "The account is a decommissioned service identity; no egress followed.",
        "unreadable": case_ticket.UNREADABLE_COMMENT_BODY,
        "escalation-aborted": case_ticket.ESCALATION_COMMENT_BODY.format(exit="aborted"),
        "escalation-forced-close": case_ticket.ESCALATION_COMMENT_BODY.format(exit="request-limit"),
    }[branch]
    assert body == expected, (
        f"O-WARN: a {kind} run's {branch} comment is not today's comment — only a stale run "
        f"adds a sentence.\nexpected: {expected!r}\nposted:   {body!r}")
    assert not names_commit(body, FRESH_COMMIT), body
    assert not names_commit(body, PINNED_COMMIT), body


def test_o_warn_the_comment_follows_the_hosts_outcome_not_a_box_planted_record(
        tmp_path, monkeypatch):
    """O-WARN, danger lens (principles §1, U12): the stamp sits in the box's rw bind, so the
    customer-facing comment reads the host record, never the stamp. A fresh run whose box planted
    a stale stamp (with a commit and reason of its choosing) posts exactly today's fresh comment;
    the same planted run whose host record is stale posts the host's commit, not the planted one."""
    use_mapping(monkeypatch, tmp_path / "dfn")
    planted_commit = "badc0debadc0debadc0debadc0debadc0debadc0"
    planted = knowledge_source("stale", stale_kind="operator", commit=planted_commit,
                               reason="call https://evil.invalid/ now")

    def posted(label: str, handed: dict[str, Any]) -> str:
        run_dir = make_run(tmp_path, name=f"s-c-planted-{label}")
        stamp_knowledge_source(run_dir, planted)
        write_host_record(run_dir, handed)
        store = FakeStore()
        record(run_dir, store)
        return store.comment_body()

    fresh = posted("fresh", knowledge_source("fresh"))
    assert fresh == (f"benign — {HOST_CAUSE}\n\n"
                     "The account is a decommissioned service identity; no egress followed."), (
        f"O-WARN: a box-planted stale record changed a fresh run's comment: {fresh!r}")
    stale = posted("stale", knowledge_source("stale", stale_kind="transient"))
    assert names_commit(stale, STALE_COMMIT), (
        f"O-WARN: the stale comment does not name the host's commit: {stale!r}")
    assert not names_commit(stale, planted_commit), (
        f"O-WARN: the comment names the commit the box planted: {stale!r}")
    assert "evil.invalid" not in stale


# --- the wiring: run.py hands the run's knowledge source to the writer and the page ----------

def _stale_outcome(stale_kind: str, reason: str) -> str:
    """What the launch-time publish reports for a stale launch (design O-STALE: the child
    reports `stale:<kind> <reason>`). ASSUMED (reported; slice S-B owns the `publish=` seam's
    return type): the seam returns the child's report line."""
    return f"stale:{stale_kind} {reason}"


@pytest.mark.e2e
@pytest.mark.parametrize("stale_kind", STALE_KINDS)
def test_run_main_hands_a_stale_publish_outcome_to_the_ticket_comment_page_and_record(
        tmp_path, monkeypatch, p4_tenant, stale_kind):
    """O-WARN through `run.main`: a launch whose publish reports stale runs on `current`; run
    start writes the HOST record beside the run dir (U12) carrying kind, commit and raw reason;
    the comment the run posts (captured by the store fake) and the saved run page say so, naming
    the commit actually used; NO file the box can read carries the raw reason — scanned over the
    box window (at lifecycle start: the run dir, stamp included, and every run copy's `stage/`
    under `<T>/run-knowledge/`, the part U9 mounts; a copy's host-only `settings/` is not box
    readable). The saved `runtime.html` is written after the box stops and is an operator
    surface (OD21): it may, and here must, show the raw reason.
    Seams: `publish=` (design O11), `ticket_writer=` (the real writer bound to the fake store),
    `lifecycle`/`preflight`/`enqueue` recorders."""
    from functools import partial

    from defender.investigation import ticket_writer
    from defender.records import RunPaths
    from defender.tests.support.runtime.engine._spec767 import write_report
    from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S1107

    store = FakeStore()
    deps = ticket_writer.TicketWriterDeps(request=store)
    writer = SimpleNamespace(
        open_case_ticket=partial(ticket_writer.open_case_ticket, deps=deps),
        record_case_ticket=partial(ticket_writer.record_case_ticket, deps=deps))
    publish_calls: list[tuple[tuple, dict]] = []

    def publish(*args: Any, **kwargs: Any) -> str:
        publish_calls.append((args, kwargs))
        return _stale_outcome(stale_kind, RAW_REASON[stale_kind])

    box_readable: dict[str, bytes] = {}

    def before_lifecycle(run_dir: Path) -> None:
        # The box window: everything under the run dir is what the box can read (and write),
        # plus every run copy's `stage/` (U9: the only part of a copy the box mounts). A copy's
        # `settings/` is host-only and legitimately carries the fixture's `https://` endpoints.
        from defender.tests.tenancy.tenant_1108_p4._s_b_support import run_copies

        stages = sorted(run_copies(p4_tenant).glob("*/stage"))
        for root in (Path(run_dir), *stages):
            for path in sorted(root.rglob("*")) if root.is_dir() else ():
                if path.is_file() and not path.is_symlink():
                    box_readable[str(path)] = path.read_bytes()
        write_report(run_dir)
        S1107.seed_session_store(run_dir)

    alert = S1107.plant_alert(tmp_path / "alert")
    rec = S1107.RunRecorder(tmp_path / "unused" / "s-c-wiring", before_lifecycle=before_lifecycle)
    argv = [str(alert), "--tenant", p4_tenant.tenant_id, "--update-ticket", "--no-learn"]
    # The real `materialize` (run start: resolve the export, copy it, stamp the record).
    seams = {k: v for k, v in rec.seams().items() if k != "materialize"}
    from defender import run as run_py

    rc = run_py.main(argv, publish=publish, ticket_writer=writer, **seams)

    assert rc == 0, f"a stale launch with a snapshot must run to the end (O-STALE); rc={rc}"
    assert len(publish_calls) == 1, f"the launch published {len(publish_calls)} times"
    comments = store.comment_payloads
    assert len(comments) == 1, [(c.method, c.path) for c in store.calls]
    body = store.comment_body()
    commit = p4_tenant.commit
    assert names_commit(body, commit), (
        f"O-WARN: the comment does not name the commit the stale run used ({commit}): {body!r}")
    assert CUSTOMER_WORD[stale_kind] in body.lower(), body
    assert [f for f in REASON_FRAGMENTS if f.lower() in body.lower()] == [], body

    run_dir = Path(rec.lifecycle_calls[0]["run"].run_dir)
    host = json.loads(host_record_path(run_dir).read_text(encoding="utf-8"))
    assert host.get("kind") == "stale", host
    assert host.get("stale_kind") == stale_kind, host
    assert host.get("commit") == commit, host
    assert host.get("reason") == RAW_REASON[stale_kind], (
        f"the host record does not keep the child's raw reason for operators: {host}")
    stamp = json.loads(RunPaths(run_dir).provenance.read_text(encoding="utf-8"))
    if "knowledge_source" in stamp:  # OD17: optional, informational, never the reason
        assert "reason" not in stamp["knowledge_source"], stamp

    assert box_readable, "fixture: the box window saw no run-dir files"
    assert [n for n in box_readable if "/stage/" in n], (
        "fixture: the box window saw no run copy's stage/ files")
    leaked = [(name, f) for name, data in box_readable.items() for f in REASON_FRAGMENTS
              if f.encode() in data]
    assert leaked == [], (
        f"U12: the raw publish reason sits in files the box can read: {leaked}")

    page = (run_dir / "runtime.html").read_text(encoding="utf-8")
    assert names_commit(page, commit), (
        "O-WARN: the saved run page of a stale run carries no banner naming its commit")
    assert stale_kind in page.lower(), (
        "O-WARN: the saved run page of a stale run carries no banner naming its kind")
    assert html.escape(RAW_REASON[stale_kind]) in page or RAW_REASON[stale_kind] in page, (
        "O-WARN: the run page does not show operators the raw reason from the host record")


@pytest.mark.e2e
def test_run_main_fresh_launch_posts_todays_comment(tmp_path, monkeypatch, p4_tenant):
    """Positive control for the wiring test: the same launch with a fresh publish posts a comment
    naming no commit and using neither kind's words."""
    from functools import partial

    from defender.investigation import ticket_writer
    from defender.tests.support.runtime.engine._spec767 import write_report
    from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S1107
    from defender import run as run_py

    store = FakeStore()
    deps = ticket_writer.TicketWriterDeps(request=store)
    writer = SimpleNamespace(
        open_case_ticket=partial(ticket_writer.open_case_ticket, deps=deps),
        record_case_ticket=partial(ticket_writer.record_case_ticket, deps=deps))

    def before_lifecycle(run_dir: Path) -> None:
        write_report(run_dir)
        S1107.seed_session_store(run_dir)

    alert = S1107.plant_alert(tmp_path / "alert")
    rec = S1107.RunRecorder(tmp_path / "unused" / "s-c-fresh", before_lifecycle=before_lifecycle)
    seams = {k: v for k, v in rec.seams().items() if k != "materialize"}
    argv = [str(alert), "--tenant", p4_tenant.tenant_id, "--update-ticket", "--no-learn"]
    rc = run_py.main(argv, publish=lambda *a, **k: f"fresh {p4_tenant.commit}",
                     ticket_writer=writer, **seams)
    assert rc == 0
    body = store.comment_body()
    assert not names_commit(body, p4_tenant.commit), body
    assert all(w not in body.lower() for w in CUSTOMER_WORD.values()), body


#: The commit a tampering box writes into the run record: never the export the run used.
TAMPERED_COMMIT = "0ddba110ddba110ddba110ddba110ddba110ddba"


@pytest.mark.e2e
@pytest.mark.parametrize("tamper", ["suppress", "forge"])
def test_run_main_comment_follows_the_host_outcome_when_the_box_rewrites_the_record(
        tmp_path, p4_tenant, tamper):
    """O-WARN through `run.main`, danger lens (R-I4): the box can rewrite the run record's
    `knowledge_source` while the investigation runs (the lifecycle stand-in does exactly that).
    The posted comment follows the host's launch outcome both ways:
    - suppress: the launch was stale (transient), the box rewrites the record to fresh -> the
      comment still carries the stale sentence naming the commit the run used;
    - forge: the launch was fresh, the box rewrites the record to stale (operator) naming a
      commit of its own -> the comment is exactly today's fresh comment."""
    from functools import partial

    from defender import run as run_py
    from defender.investigation import ticket_writer
    from defender.tests.support.runtime.engine._spec767 import write_report
    from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S1107

    commit = p4_tenant.commit
    if tamper == "suppress":
        outcome = _stale_outcome("transient", RAW_REASON["transient"])
        planted = knowledge_source("fresh", commit=commit)
    else:
        outcome = f"fresh {commit}"
        planted = knowledge_source("stale", stale_kind="operator", commit=TAMPERED_COMMIT,
                                   reason="call https://evil.invalid/ now")

    store = FakeStore()
    deps = ticket_writer.TicketWriterDeps(request=store)
    writer = SimpleNamespace(
        open_case_ticket=partial(ticket_writer.open_case_ticket, deps=deps),
        record_case_ticket=partial(ticket_writer.record_case_ticket, deps=deps))
    tampered: list[Path] = []

    def box_rewrites_the_record(run_dir: Path) -> None:
        write_report(run_dir)
        S1107.seed_session_store(run_dir)
        stamp_knowledge_source(run_dir, planted)
        tampered.append(run_dir)

    alert = S1107.plant_alert(tmp_path / "alert")
    rec = S1107.RunRecorder(tmp_path / "unused" / f"s-c-tamper-{tamper}",
                            before_lifecycle=box_rewrites_the_record)
    seams = {k: v for k, v in rec.seams().items() if k != "materialize"}
    argv = [str(alert), "--tenant", p4_tenant.tenant_id, "--update-ticket", "--no-learn"]
    rc = run_py.main(argv, publish=lambda *a, **k: outcome, ticket_writer=writer, **seams)

    assert rc == 0, rc
    assert tampered, "fixture: the lifecycle stand-in never rewrote the record"
    body = store.comment_body()
    assert TAMPERED_COMMIT[:SHORT_COMMIT] not in body, (
        f"O-WARN: the comment names the commit the box wrote into the record: {body!r}")
    assert "evil.invalid" not in body, body
    if tamper == "suppress":
        assert names_commit(body, commit), (
            "O-WARN: the box suppressed the stale sentence by rewriting the record to fresh — "
            f"the comment must follow the host's stale outcome: {body!r}")
        assert CUSTOMER_WORD["transient"] in body.lower(), body
    else:
        assert body == (f"benign — {HOST_CAUSE}\n\n"
                        "The account is a decommissioned service identity; no egress followed."), (
            "O-WARN: the box forged a stale sentence into a fresh run's comment by rewriting "
            f"the record: {body!r}")


# ---------------------------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------------------------

_NOW = "2026-10-22T12:00:00+00:00"
_TENANT = "6f1c3b9e-4a5d-4e8f-9a0b-1c2d3e4f5a6b"
_AUTH = {"Authorization": "Bearer tok"}


def _knowledge(status: str, stale_kind: str | None = None) -> dict[str, Any]:
    commit = {"current": FRESH_COMMIT, "stale": STALE_COMMIT, "pinned": PINNED_COMMIT}[status]
    return {"status": status, "commit": commit, "stale_kind": stale_kind}


def _investigation(investigation_id: str, knowledge: dict[str, Any] | None) -> Any:
    pytest.importorskip("fastapi")
    from defender.api.models import Investigation

    doc: dict[str, Any] = {
        "investigation_id": investigation_id, "alert_id": "al-1", "status": "completed",
        "disposition": "benign", "cost_usd": 1.0, "created_at": _NOW, "started_at": _NOW,
        "finished_at": _NOW,
    }
    if knowledge is not None:
        doc["knowledge"] = knowledge
    return Investigation.model_validate(doc)


def _client(*investigations: Any) -> Any:
    """The real app over the stub's own store (`InMemoryStore`, the store port's fake), seeded
    through its `add_investigation`."""
    import datetime as _dt

    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from defender.api.app import create_app
    from defender.api.fakes import (InMemorySecrets, InMemoryStore, StubArtifactLinks,
                                    StubSystemChecker, TokenAuthenticator)
    from defender.api.ports import ApiDeps, Principal
    from defender.tenancy._tenant import TenantId

    store = InMemoryStore(lambda: _dt.datetime(2026, 10, 22, 12, tzinfo=_dt.UTC))
    for inv in investigations:
        store.add_investigation(_TENANT, inv)
    deps = ApiDeps(
        authenticator=TokenAuthenticator({"tok": Principal(tenant_id=TenantId(_TENANT),
                                                           user_id="ann@example.invalid")}),
        alerts=store, investigations=store, learning_jobs=store, lessons=store, systems=store,
        writes=store, secrets=InMemorySecrets(), checker=StubSystemChecker(),
        artifact_links=StubArtifactLinks())
    return TestClient(create_app(deps))


CASES = [("stale", "transient"), ("stale", "operator"), ("current", None), ("pinned", None)]


@pytest.mark.parametrize(("status", "stale_kind"), CASES)
def test_o_warn_api_serves_investigation_knowledge_through_the_store_port(status, stale_kind):
    """O-WARN (API): an investigation's `knowledge` reaches `GET /investigations/{id}` and the
    list as the store holds it: status, the commit used, and the stale kind (null unless stale)."""
    inv = _investigation(f"inv-{status}-{stale_kind}", _knowledge(status, stale_kind))
    client = _client(inv)
    one = client.get(f"/investigations/{inv.investigation_id}", headers=_AUTH)
    assert one.status_code == 200, one.text
    assert one.json().get("knowledge") == _knowledge(status, stale_kind), one.json()
    listed = client.get("/investigations", headers=_AUTH).json()
    assert [i.get("knowledge") for i in listed["items"]] == [_knowledge(status, stale_kind)], listed


def test_o_warn_api_knowledge_vocabulary_is_the_apis_not_the_run_records():
    """O-WARN (API): the wire model refuses the run record's words (`fresh`, `stale:transient`)
    and an unknown stale kind; it accepts each of the API's own words (positive control)."""
    from pydantic import ValidationError

    for bad in ({"status": "fresh", "commit": FRESH_COMMIT, "stale_kind": None},
                {"status": "stale", "commit": STALE_COMMIT, "stale_kind": "outage"},
                {"status": "stale:transient", "commit": STALE_COMMIT, "stale_kind": None}):
        with pytest.raises(ValidationError):
            _investigation("inv-bad", bad)
    for status, stale_kind in CASES:
        assert _investigation("inv-ok", _knowledge(status, stale_kind)).knowledge is not None


#: Run record -> what the API serves, per the design (O-STALE record vocabulary, O-WARN wire).
RECORD_TO_WIRE = [
    (knowledge_source("fresh"), _knowledge("current")),
    (knowledge_source("stale", stale_kind="transient"), _knowledge("stale", "transient")),
    (knowledge_source("stale", stale_kind="operator"), _knowledge("stale", "operator")),
    (knowledge_source("pinned"), _knowledge("pinned")),
]


@pytest.mark.parametrize(("record", "wire"), RECORD_TO_WIRE,
                         ids=["fresh", "stale-transient", "stale-operator", "pinned"])
def test_o_warn_api_maps_the_run_records_knowledge_source_to_the_wire_through_the_store(
        tmp_path, record, wire):
    """O-WARN (API): the store turns the run record's `knowledge_source` into the API's
    `knowledge` — fresh -> current, stale -> stale + its kind, pinned -> pinned, the commit
    carried, the raw reason dropped — and the route serves it. Exercised on the stub store.

    ASSUMED SEAM (reported): `InMemoryStore.add_run_knowledge(tenant_id, investigation_id,
    record_text: str | None)` — the stub's seeding entry for a run's record (the `add_*` family;
    not a port method), applying the store's record->wire rule the port states. It is handed the
    HOST record (U12) as its file's text, raw reason included (`None`: no record), so the
    fail-closed rule for a missing or corrupt record (OD22) is the store's too."""
    # A placeholder the mapping must replace (whatever `knowledge`'s nullability turns out to be).
    inv = _investigation("inv-mapped", {"status": "pinned", "commit": "0" * 40, "stale_kind": None})
    client = _client(inv)
    store = client.app.state.deps.investigations
    run_dir = tmp_path / "runs" / "run-1"
    run_dir.mkdir(parents=True)
    text = write_host_record(run_dir, record).read_text(encoding="utf-8")
    store.add_run_knowledge(_TENANT, inv.investigation_id, text)

    served = client.get(f"/investigations/{inv.investigation_id}", headers=_AUTH).json()
    assert served.get("knowledge") == wire, (
        f"O-WARN: the record {record} is served as {served.get('knowledge')}, not {wire}")
    assert "reason" not in (served.get("knowledge") or {}), served


def test_o_warn_api_published_contract_declares_the_knowledge_field():
    """O-WARN (API): `/openapi.json` declares `Investigation.knowledge` with exactly the
    statuses current/stale/pinned and stale kinds transient/operator (or null)."""
    doc = _client().get("/openapi.json").json()
    schemas = doc["components"]["schemas"]
    inv = schemas.get("Investigation") or schemas["Investigation-Output"]
    assert "knowledge" in inv["properties"], sorted(inv["properties"])

    def resolve(node: dict[str, Any]) -> list[dict[str, Any]]:
        if "$ref" in node:
            return resolve(schemas[node["$ref"].rsplit("/", 1)[-1]])
        if "anyOf" in node or "oneOf" in node:
            return [n for part in node.get("anyOf", node.get("oneOf")) for n in resolve(part)]
        return [node]

    objects = [n for n in resolve(inv["properties"]["knowledge"]) if n.get("properties")]
    assert len(objects) == 1, objects
    props = objects[0]["properties"]
    assert set(props) == {"status", "commit", "stale_kind"}, sorted(props)

    def enum_of(node: dict[str, Any]) -> set[Any]:
        values: set[Any] = set()
        for n in resolve(node):
            values |= set(n.get("enum", ()))
            if n.get("type") == "null":
                values.add(None)
            if "const" in n:
                values.add(n["const"])
        return values

    assert enum_of(props["status"]) == {"current", "stale", "pinned"}, props["status"]
    assert enum_of(props["stale_kind"]) == {"transient", "operator", None}, props["stale_kind"]


def test_o_warn_the_stub_seed_exercises_stale_and_current_knowledge():
    """O-WARN (API): the stub's fake records exercise the field — the demo store serves at least
    one stale investigation with its kind and one current one."""
    from fastapi.testclient import TestClient

    from defender.api.app import create_app
    from defender.api.demo import demo_deps

    client = TestClient(create_app(demo_deps((_TENANT,))))
    items = client.get("/investigations", headers={"Authorization": f"Bearer {_TENANT}-analyst"}
                       ).json()["items"]
    knowledge = [i.get("knowledge") for i in items]
    stale = [k for k in knowledge if isinstance(k, dict) and k.get("status") == "stale"]
    assert stale, f"O-WARN: the stub seeds no stale investigation: {knowledge}"
    for k in stale:
        assert k.get("stale_kind") in STALE_KINDS, f"O-WARN: a stale seed names no kind: {k}"
        assert k.get("commit"), f"O-WARN: a stale seed names no commit: {k}"
    assert any(isinstance(k, dict) and k.get("status") == "current" for k in knowledge), knowledge


# ---------------------------------------------------------------------------------------------
# OD22' (fail closed where a record should exist)
#   (1) an investigation with no run yet: API `knowledge: null`;
#   (2) a run with no host record AND no `knowledge_source` in its stamp (a pre-P4 run, never
#       rewritten): no banner, API null, ticket unchanged;
#   (3) host record missing while the stamp carries `knowledge_source`, or the record is
#       unparseable: unreadable -> stale / operator, no commit.
# ---------------------------------------------------------------------------------------------

#: Case (3): how the host record fails while a record should exist (the stamp names a source).
UNREADABLE_RECORDS = {"missing-with-stamp": None, "corrupt": '{"kind": "fresh", "commit": '}
TODAYS_VERDICT_BODY = (f"benign — {HOST_CAUSE}\n\n"
                       "The account is a decommissioned service identity; no egress followed.")


def plant_unreadable_host_record(run_dir: Path, how: str) -> None:
    """Case (3): the stamp carries a (fresh) `knowledge_source` — so a host record should exist —
    and the host record is missing, or holds a truncated record (JSON that does not parse)."""
    stamp_knowledge_source(run_dir, stamp_view(knowledge_source("fresh")))
    path = host_record_path(run_dir)
    path.unlink(missing_ok=True)
    text = UNREADABLE_RECORDS[how]
    if text is not None:
        path.write_text(text, encoding="utf-8")


def plant_pre_p4_run(run_dir: Path) -> None:
    """Case (2): a run from before P4 — no host record, and no `knowledge_source` in its stamp."""
    host_record_path(run_dir).unlink(missing_ok=True)
    stamp_knowledge_source(run_dir, None)


@pytest.mark.parametrize("how", list(UNREADABLE_RECORDS))
def test_od22_an_unreadable_host_record_puts_the_operator_sentence_without_a_commit_on_the_ticket(
        tmp_path, monkeypatch, how):
    """OD22' (3): where a host record should exist but is missing or corrupt, the ticket claims
    no freshness: the comment adds the operator-kind sentence (awaiting operator action) and names
    no commit id. Control: the same run with a fresh record posts today's comment."""
    use_mapping(monkeypatch, tmp_path / "dfn")
    fresh, _ = _posted(tmp_path, "verdict", knowledge_source("fresh"), label=f"od22-fresh-{how}")
    assert fresh == TODAYS_VERDICT_BODY, fresh

    run_dir = make_run(tmp_path, name=f"s-c-od22-{how}")
    plant_unreadable_host_record(run_dir, how)
    store = FakeStore()
    record(run_dir, store)
    body = store.comment_body()

    sentence = _added(fresh, body)
    assert sentence, (
        f"OD22: a run whose host record is {how} posted a fresh run's comment — it claimed fresh")
    assert CUSTOMER_WORD["operator"] in sentence.lower(), (
        f"OD22: the {how}-record sentence is not the operator kind's: {sentence!r}")
    assert CUSTOMER_WORD["transient"] not in sentence.lower(), sentence
    for commit in (FRESH_COMMIT, STALE_COMMIT, PINNED_COMMIT):
        assert not names_commit(sentence, commit), (
            f"OD22: the {how}-record sentence names a commit id: {sentence!r}")
    assert not re.search(r"\b[0-9a-f]{7,64}\b", sentence), (
        f"OD22: the {how}-record sentence carries something shaped like a commit id: {sentence!r}")


def test_od22_a_pre_p4_run_posts_todays_comment(tmp_path, monkeypatch):
    """OD22' (2): a run with no host record and no `knowledge_source` in its stamp (pre-P4; old
    runs are not rewritten) posts exactly today's comment. Control on the same channel: the same
    shape of run whose stamp DOES name a source (case 3) gets the operator sentence."""
    use_mapping(monkeypatch, tmp_path / "dfn")
    old = make_run(tmp_path, name="s-c-od22-pre-p4")
    plant_pre_p4_run(old)
    store = FakeStore()
    record(old, store)
    assert store.comment_body() == TODAYS_VERDICT_BODY, (
        f"OD22': a pre-P4 run's comment changed: {store.comment_body()!r}")

    control = make_run(tmp_path, name="s-c-od22-pre-p4-control")
    plant_unreadable_host_record(control, "missing-with-stamp")
    store = FakeStore()
    record(control, store)
    assert store.comment_body() != TODAYS_VERDICT_BODY, (
        "positive control: a missing record where one should exist adds the operator sentence")


def test_od22_an_investigation_with_no_run_serves_null_knowledge():
    """OD22' (1): an investigation with no run yet serves `knowledge: null` — seeded without
    knowledge, and through `add_run_knowledge(..., None)` (no record, no stamp). Control: a
    fresh record's text on the same investigation is served `current`."""
    inv = _investigation("inv-no-run", None)
    client = _client(inv)
    served = client.get(f"/investigations/{inv.investigation_id}", headers=_AUTH).json()
    assert "knowledge" in served, served
    assert served["knowledge"] is None, served

    store = client.app.state.deps.investigations
    store.add_run_knowledge(_TENANT, inv.investigation_id, None)
    served = client.get(f"/investigations/{inv.investigation_id}", headers=_AUTH).json()
    assert served.get("knowledge", "absent") is None, (
        f"OD22': an investigation with no run is served {served.get('knowledge', 'absent')!r}")

    store.add_run_knowledge(_TENANT, inv.investigation_id,
                            json.dumps(knowledge_source("fresh")))
    served = client.get(f"/investigations/{inv.investigation_id}", headers=_AUTH).json()
    assert served.get("knowledge") == _knowledge("current"), served


#: The API seam's inputs for each OD22' run case: (host record text, the stamp's source).
API_RUN_CASES = {
    "pre-p4": (None, None, None),
    "missing-with-stamp": (None, stamp_view(knowledge_source("fresh")),
                           {"status": "stale", "commit": None, "stale_kind": "operator"}),
    "corrupt": (UNREADABLE_RECORDS["corrupt"], stamp_view(knowledge_source("fresh")),
                {"status": "stale", "commit": None, "stale_kind": "operator"}),
}


@pytest.mark.parametrize("case", list(API_RUN_CASES))
def test_od22_the_api_fails_closed_only_where_a_record_should_exist(case):
    """OD22' through the store: a pre-P4 run (no record, no stamp source) serves null; a missing
    record whose stamp names a source, or a corrupt record, serves `{status: stale, stale_kind:
    operator, commit: null}`. Control: a fresh record's text on the same path is `current`.

    ASSUMED SEAM (reported): `InMemoryStore.add_run_knowledge(tenant_id, investigation_id,
    record_text: str | None, *, stamp_knowledge_source: Mapping | None = None)` — the host
    record's text (`None`: no file) and the run stamp's `knowledge_source` (`None`: the stamp has
    none, or there is no run). Both `None` -> `knowledge: null`."""
    text, stamp_source, expected = API_RUN_CASES[case]
    inv = _investigation(f"inv-od22-{case}", None)
    client = _client(inv)
    store = client.app.state.deps.investigations

    store.add_run_knowledge(_TENANT, inv.investigation_id, json.dumps(knowledge_source("fresh")),
                            stamp_knowledge_source=stamp_view(knowledge_source("fresh")))
    served = client.get(f"/investigations/{inv.investigation_id}", headers=_AUTH).json()
    assert served.get("knowledge") == _knowledge("current"), served

    store.add_run_knowledge(_TENANT, inv.investigation_id, text,
                            stamp_knowledge_source=stamp_source)
    served = client.get(f"/investigations/{inv.investigation_id}", headers=_AUTH).json()
    assert served.get("knowledge", "absent") == expected, (
        f"OD22': the {case} run is served {served.get('knowledge', 'absent')!r}, not {expected!r}")

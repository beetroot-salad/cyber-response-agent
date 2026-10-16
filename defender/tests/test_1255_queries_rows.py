"""#1255 slice C — the model's query table names no call and no arm (G4, G5, O2), and the judge's
join of a table row to what the world served survives without it (G6, P3).

The design (issue #1255, design rev 4, "Query ids"): the `call_id` column leaves the
model-readable query table (`executed_queries.jsonl`). On an arm it is `<world token>/<n>` — the
episode token and the world's label, in a file the model reads with plain `cat` — and on every
run it is a column nothing model-facing uses (G5). The join between a query row and the served
ledger moves to a host-only record keyed by the row's `(lead_id, seq)`, holding the call id and
the world token; natural runs use the same shape (P1). A row's position in the table is not used:
the table is box-writable, and a refused view write leaves the run's memory and the file
disagreeing.

Where things enter (all real entry points, nothing monkey-patched):
  * a NATURAL run: the replay harness driving the real driver, query tool and record writer over
    the plain module registry (`_spec1224.plain_registry`);
  * an ARM's serving: the same drive over the real `WorldRegistry` of a #1224 fixture episode,
    in the control world and in a world with facts;
  * a whole ARM with inherited rows: #1234's `real_family` — the real launcher, real pre-flight,
    each sibling the real `run.main --tenant T --episode <id> --world L` in-process, the real
    seed, the real archive;
  * the JOIN: the judge's own render of that archived episode (`_spec1234.render_context`), the
    one reader of both call records.

The host-only join record's location and shape are NOT named here (the dossier leaves them to
the implementer); the join is observed only through the judge.
"""
from __future__ import annotations

import base64
import json
import re
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("pydantic_ai")

from defender.tests import _1255_identity as IDN  # noqa: E402
from defender.tests import _1255_world as W  # noqa: E402
from defender.tests.judge_contrast_1234 import _spec1234 as S34  # noqa: E402
from defender.tests.live_oracle_1224 import _spec1224 as S24  # noqa: E402

pytestmark = pytest.mark.e2e

ALICE = S24.query_params("user:alice")
BOB = S24.query_params("user:bob")
CAROL = S24.query_params("user:carol")
BASE_ALICE = {"rows": [{"action": "logon", "event_id": "e-100", "user": "alice"}]}
BOB_BASE = {"rows": [{"action": "logon", "event_id": "e-200", "user": "bob"}]}
#: A verb every fixture system declares and the fixture grant withholds from gather: the grant
#: refuses it, so it leaves a `∅.denied` table row and (on an arm) a `refused` ledger row.
WITHHELD = ("edr", "lookup")


@pytest.fixture(autouse=True)
def _roots(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    return W.configure_roots(tmp_path, monkeypatch)


#: What a run folder holds after a drive, by role — `run_repository._layout`'s record names at
#: base 4b3628ed, as LITERALS (never read off the layout under test): the stamp, the documents
#: and logs the model reads, the host's observability streams, and the box sentinel.
_ROOT_RECORDS = frozenset({
    "provenance.json", "investigation.md", "report.md", "executed_queries.jsonl",
    "source_refs.yaml", "tool_trace.jsonl", "policy_denials.jsonl", "lessons_loaded.jsonl",
    "runtime.html", ".box-sentinel"})
#: Record shapes keyed by something other than a lead: the case input (one folder, one level)
#: and the review gate's records.
_ROOT_SHAPES = (re.compile(r"alert_input/[^/]+"), re.compile(r"review_record\.[0-9]+\.json"),
                re.compile(r"wire_logs/[^/]+\.jsonl"))


def _unlisted(rel_paths: list[str], rows: list[dict]) -> list[str]:
    """The run-folder files (relative POSIX paths) that are none of the records a run holds
    (P3, contract-repair finding F-Q1): beyond `_ROOT_RECORDS` / `_ROOT_SHAPES`, the only
    lead-keyed files are each table lead's claim (`gather_raw/<lead>.lead.json`) and summary
    (`gather_summaries/<lead>.md`), and the payloads the table's rows name (`payload_path`) —
    so `gather_raw/` holds nothing the queries table does not account for. Anything else is a
    new file in the box's own mount: a new channel (O5), and where host-only bookkeeping such as
    the query join would hide; it fails until it is named here and argued in review."""
    leads = {str(r.get("lead_id")) for r in rows if r.get("lead_id")}
    payloads = {str(r["payload_path"]) for r in rows if r.get("payload_path")}
    keyed = ({f"gather_raw/{lead}.lead.json" for lead in leads}
             | {f"gather_summaries/{lead}.md" for lead in leads})
    return sorted(rel for rel in rel_paths
                  if rel not in _ROOT_RECORDS and rel not in payloads and rel not in keyed
                  and not any(shape.fullmatch(rel) for shape in _ROOT_SHAPES))


def _folder_files(run_dir: Path) -> list[str]:
    return sorted(p.relative_to(run_dir).as_posix() for p in Path(run_dir).rglob("*")
                  if p.is_file())


def _assert_only_listed_files(run_dir: Path, where: str) -> None:
    """Every file under `run_dir` is one of the records a run holds (`_unlisted`); positive
    control on the same listing: it does flag a planted join record under `gather_raw/` and at
    the root, so an empty answer is the folder's."""
    rel_paths, rows = _folder_files(run_dir), W.table_rows(run_dir)
    assert rows, f"fixture: {where} left no query table"
    assert rel_paths, f"fixture: {where} left no files"
    planted = ["gather_raw/.calls", ".query_join.jsonl", "gather_raw/l-001/.join.json"]
    assert set(planted) <= set(_unlisted([*rel_paths, *planted], rows)), (
        "positive control: the listing does not flag a planted join record")
    extra = _unlisted(rel_paths, rows)
    assert not extra, (
        f"{where}: the run folder (the box's own mount) holds files that are none of a run's "
        f"records — host bookkeeping such as the query join belongs outside it (P3): {extra}")


def _assert_no_call_id(rows: list[dict], where: str) -> None:
    carrying = [r for r in rows if W.CALL_ID in r]
    assert not carrying, (
        f"{where}: {len(carrying)} query row(s) carry `{W.CALL_ID}` — the model reads this "
        f"table, and the id is host bookkeeping it never uses (G4/G5): {carrying[:2]}")
    shaped = [tuple(r) for r in rows if tuple(r) != W.ROW_COLUMNS]
    assert not shaped, (
        f"{where}: query rows whose columns are not the writer's fourteen (a column carrying "
        f"the id under another name is the same leak): {shaped[:2]}")


# ======================================================================================
# G4 / P1 — a natural run's table carries no call id.
# ======================================================================================


def test_1255_a_natural_runs_query_rows_carry_no_call_id(tmp_path: Path) -> None:
    """G4, P1 — on a natural run every query-table row the run writes (an answered call, a
    rejected verb, a grant refusal) carries exactly the fourteen writer columns and no
    `call_id`: natural runs and arms share one table shape.

    Positive control on the same channel: the rows are there, one per call, keyed by
    `(lead_id, seq)` — so the absence is the column's, not an empty table's."""
    est = S24.estate(tmp_path, withheld=(WITHHELD,))
    est.answer("idp", "query", ALICE, BASE_ALICE)
    run_dir, _gather = W.drive_lead(tmp_path / "natural", verbs=S24.plain_registry(est), est=est,
                                    turns=[S24.query_turn("idp", "query", ALICE),
                                           S24.query_turn("idp", "no_such_verb", {}),
                                           S24.query_turn(*WITHHELD, {"entity": "alice"}),
                                           S24.done_turn()])
    rows = W.table_rows(run_dir)
    own = W.lead_rows(run_dir)
    assert len(own) == 3, f"fixture: three calls, three rows on the lead: {own}"
    assert [r["seq"] for r in own] == [0, 1, 2], "the rows are keyed by (lead_id, seq)"
    assert W.row_for(own, ALICE)["system"] == "idp"
    _assert_no_call_id(rows, "natural run")
    # P1/P3: natural runs keep the join in the same host-only place as arms — not in a file of
    # their own run folder under some other name.
    _assert_only_listed_files(run_dir, "natural run")


# ======================================================================================
# G4 / O2 — an arm's table names neither the call nor the arm.
# ======================================================================================


def _arm_drive(tmp_path: Path, label: str) -> tuple[Path, Path]:
    """World `label` of a #1224 fixture episode served through the real `WorldRegistry`, its
    investigator driven through the real query tool: a recorded call (ALICE), a call the source
    never asked (BOB) and a withheld verb (the grant refuses it). Every oracle turn passes the
    base unchanged. Returns `(episode dir, the arm's run dir)`."""
    est = S24.estate(tmp_path, withheld=(WITHHELD,))
    est.answer("idp", "query", BOB, BOB_BASE)
    ep = S24.episode_v2(tmp_path, base_rows=[S24.captured("idp", "query", ALICE, BASE_ALICE)])
    oracle = S34.Routed({"user:alice": S24.oracle(then=S24.submit(BASE_ALICE, S24.EMPTY_CLAIM)),
                         "user:bob": S24.oracle(then=S24.submit(BOB_BASE, S24.EMPTY_CLAIM))},
                        name="oracle-1255", last_wins=True)
    reg = S24.sandboxed_registry(ep, label, est, oracle=oracle, verifier=S24.passing_verifier())
    run_dir, _gather = W.drive_lead(tmp_path / "arm", verbs=reg, est=est, turns=[
        S24.query_turn("idp", "query", ALICE), S24.query_turn("idp", "query", BOB),
        S24.query_turn(*WITHHELD, {"entity": "alice"}), S24.done_turn()])
    assert len(W.lead_rows(run_dir)) == 3, "fixture: three calls, three rows"
    ledger = S24.ledger_rows(ep, label)
    assert len(ledger) == 3, f"fixture: the world served (or refused) all three calls: {ledger}"
    return ep, run_dir


def _positive_control_host_names_the_arm(ep: Path, label: str) -> list[str]:
    """The world's served ledger — host-side, outside the model's reach — names the world on
    every row (`world_id`) and carries each call's id: the identity detector does find an
    identity where one is written, and the host keeps what it joins on. Returns the
    identities."""
    identities = W.arm_identities(ep)
    ledger = S24.ledger_rows(ep, label)
    token = S24.world_token(label)
    assert all(r.get("world_id") == token for r in ledger), "positive control: the host names it"
    assert all(str(r.get(W.CALL_ID, "")).startswith(f"{token}/") for r in ledger), (
        "positive control: the host keeps each call's id")
    assert W.identities_in(json.dumps(ledger), identities), "positive control: the scan finds it"
    return identities


@pytest.mark.parametrize("label", ["a", "b"], ids=["control-world", "world-with-facts"])
def test_1255_an_arms_query_rows_carry_no_call_id_and_no_arm_identity(tmp_path: Path,
                                                                      label: str) -> None:
    """G4, O2 — an arm's query rows carry no `call_id`, and no row anywhere in the table names the
    episode or the world (its id, its token, any world's token), in the control world and in a
    world with facts alike.

    Today each row carries `<episode token>.<label>/<n>`: the arm's identity, in a file the model
    reads by `cat`. Positive control on the same detector: the world's served ledger still names
    the world and each call (`_positive_control_host_names_the_arm`)."""
    ep, run_dir = _arm_drive(tmp_path, label)
    identities = _positive_control_host_names_the_arm(ep, label)
    rows = W.table_rows(run_dir)
    _assert_no_call_id(rows, f"world {label}")
    leaked = W.identities_in(json.dumps(rows), identities)
    assert not leaked, f"world {label}'s query table names the arm: {leaked}"


def test_1255_no_file_in_an_arms_run_folder_names_the_arm_or_its_calls(tmp_path: Path) -> None:
    """P3, G6 — the join between a query row and the served ledger lives in a host-only record
    OUTSIDE the run folder (the tree the box mounts): after an arm's investigation no file
    anywhere under its run folder holds the episode id, the episode token, a world token or a
    call id the ledger carries — wherever the implementation keeps the join, it is not there.

    Held two ways, because a substring scan is lexical (contract-repair finding F-Q1: a join
    record base64-encoded into `gather_raw/.calls` passed it):

      * by ENCODING: each identity and call id is also looked for as a derived form (its hex
        and base64 bytes, its digests, uuid3/uuid5 over it) and inside every base64/hex run of
        every file, decoded (`_1255_identity.encoded_hits`);
      * by STRUCTURE: the folder holds no file that is not one of a run's records
        (`_unlisted`: the table, the payloads it names, each lead's claim and summary, the
        documents, logs and observability streams) — so the join cannot sit there under any
        name or in any encoding.

    Positive controls on the same scans: they read every file of the folder (the arm's own call
    params are found in it), the ledger they are compared against does carry the identities,
    the encoded scan finds a call id written base64-encoded inside a JSON record, and the
    listing flags a planted join record. Today the only file that names the arm is the query
    table (its `call_id` column)."""
    ep, run_dir = _arm_drive(tmp_path, "b")
    identities = _positive_control_host_names_the_arm(ep, "b")
    call_ids = [str(r[W.CALL_ID]) for r in S24.ledger_rows(ep, "b")]
    files = [(p.relative_to(run_dir).as_posix(), p.read_bytes())
             for p in sorted(run_dir.rglob("*")) if p.is_file()]
    texts = {rel: data.decode("utf-8", "replace") for rel, data in files}
    assert any("user:bob" in t for t in texts.values()), "positive control: the scan reads files"
    tokens = {**{f"identity {i}": ident for i, ident in enumerate(identities)},
              **{f"call id {cid}": cid for cid in call_ids}}
    encoded = base64.b64encode(json.dumps(
        {"lead_id": "l-001", "seq": 0, "call_id": call_ids[0]}).encode("utf-8")).decode("ascii")
    assert IDN.encoded_hits(json.dumps({"k": encoded}), tokens), (
        "positive control: the encoded scan does not find a call id base64-encoded in a record")
    named = IDN.files_carrying(files, tokens)
    assert not named, f"files in the arm's run folder name the arm or its calls: {named}"
    _assert_only_listed_files(run_dir, "the arm")


def test_1255_every_siblings_table_seeded_and_own_carries_no_call_id_or_arm_identity(
        tmp_path: Path) -> None:
    """G4, O2 — through the whole real path (launcher, pre-flight, each sibling's `run.main
    --episode --world`, the seed, the archive), no row of any world's query table — the rows
    seeded from the source and the rows the sibling wrote — carries `call_id` or names the
    episode or a world, in the sibling's own run folder and in the archived copy alike.

    Positive controls: every table holds the seeded prefix AND rows of its own (the default
    triad repeats the pre-branch call, asks the post-branch call and is refused one call), and
    every world's served ledger names that world on each row."""
    built = S34.real_family(tmp_path)
    assert built.rc == 0, f"fixture: the launch failed ({built.rc}, {built.message!r})"
    identities = W.arm_identities(built.ep)
    seeded = len(S34.source_calls(post=False))
    for label in ("a", "b", "c"):
        archived, live = built.table_rows(label), built.run_table_rows(label)
        assert len(archived) > seeded, (
            f"fixture: world {label}'s archived table holds the seeded prefix and rows of its own")
        assert len(live) > seeded, (
            f"fixture: world {label}'s run-folder table holds the seeded prefix and rows of its own")
        assert archived[:seeded] == built.table_rows("a")[:seeded], "fixture: one seeded prefix"
        ledger = built.ledger_rows(label)
        assert ledger, f"positive control: world {label} wrote ledger rows"
        assert W.identities_in(json.dumps(ledger), identities), (
            f"positive control: world {label}'s ledger names it")
        for where, rows in (("archived", archived), ("run folder", live)):
            _assert_no_call_id(rows, f"world {label} ({where})")
            leaked = W.identities_in(json.dumps(rows), identities)
            assert not leaked, f"world {label}'s {where} query table names the arm: {leaked}"


# ======================================================================================
# G6 — the judge's join reads the host, never a row's position in the table.
# ======================================================================================


def _contrast_row(built: Any, label: str) -> Any:
    ctx = S34.render_context(built, label)
    rows = ctx[S34.COINED["ctx.contrast"]] if isinstance(ctx, dict) else getattr(
        ctx, S34.COINED["ctx.contrast"])
    return rows[label]


def _field(row: Any, name: str) -> Any:
    key = S34.COINED[name]
    return row[key] if isinstance(row, dict) else getattr(row, key)


def test_1255_the_judges_join_survives_a_row_missing_from_the_middle_of_the_table(
        tmp_path: Path) -> None:
    """G6 ("a row's position in the table is not used") — when a row is missing from the MIDDLE
    of a sibling's archived query table (what a refused view write leaves: the call was made,
    served and rowed in the ledger, and its table line never landed), the judge still pairs
    every remaining row with its own served-ledger row: the altered call after the gap is named
    at its line in the table as it now stands, nothing is listed unserved, and the call whose
    line is gone is the one unmapped ledger row (`passthrough`, no call number).

    A join by position (the n-th own row is the n-th call) pairs the altered call's row with
    the missing call's ledger row instead; today's join by the id on the row holds, and so must
    the host-only record that replaces it. World b asks the pre-branch call again, a fresh call
    (CAROL) and the post-branch call its oracle alters; CAROL's line is then removed from the
    archived table (`_spec1234.rewrite_jsonl`)."""
    est = S34.Estate1234(tmp_path / "estate", withheld=(WITHHELD,))
    est.answer("idp", "query", CAROL, S34.BASE_ANSWER)
    built = S34.real_family(tmp_path, {"b": S34.RealWorld("b", turns=[
        S24.query_turn("idp", "query", S34.Q1), S24.query_turn("idp", "query", CAROL),
        S24.query_turn("idp", "query", S34.QP), S24.done_turn()],
        oracle=S34.altering_oracle())}, estate=est)
    assert built.rc == 0, f"fixture: the launch failed ({built.rc}, {built.message!r})"
    ledger = built.ledger_rows("b")
    carol_served = [r for r in ledger if S24.canonical(r["params"]) == S24.canonical(CAROL)]
    assert [r["source"] for r in carol_served] == ["passthrough"], "fixture: CAROL was served"
    assert [r for r in ledger if r.get("source") == "oracle"], "fixture: b's oracle altered QP"

    def drop_carol(rows: list[dict]) -> list[dict]:
        kept = [r for r in rows if S24.canonical(r.get("params") or {}) != S24.canonical(CAROL)]
        assert len(kept) == len(rows) - 1, "fixture: exactly CAROL's line is removed"
        return kept

    rows = S34.rewrite_jsonl(built.table_path("b"), drop_carol)
    qp_lines = [i for i, r in enumerate(rows)
                if S24.canonical(r.get("params") or {}) == S24.canonical(S34.QP)]
    qp_line = qp_lines[-1]
    q1_lines = [i for i, r in enumerate(rows)
                if S24.canonical(r.get("params") or {}) == S24.canonical(S34.Q1)]
    assert q1_lines[-1] < qp_line, "fixture: the gap sits between b's own Q1 and QP rows"

    b = _contrast_row(built, "b")
    assert _field(b, "contrast.first_altered") == qp_line, (
        "the altered call is named at its own line: the join did not shift with the gap")
    assert list(_field(b, "contrast.unserved")) == [], (
        "a remaining row lost its ledger partner to the gap")
    unmapped = list(_field(b, "contrast.unmapped"))
    sources = [e[S34.COINED["entry.source"]] if isinstance(e, dict)
               else getattr(e, S34.COINED["entry.source"]) for e in unmapped]
    calls = [e[S34.COINED["entry.call"]] if isinstance(e, dict)
             else getattr(e, S34.COINED["entry.call"]) for e in unmapped]
    assert (sources, calls) == (["passthrough"], [None]), (
        "the call whose line is gone is the one ledger row no table row joins")

"""Query rows hide call identities while the judge retains its host-side join."""
from __future__ import annotations

import base64
import gzip
import json
import zlib
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("pydantic_ai")

from defender.tests.support.runtime.state import _1255_identity as IDN
from defender.tests.support.runtime.state import _1255_run_records as RR
from defender.tests.support.runtime.state import _1255_world as W
from defender.tests.learning.judge.contrast_contracts import _spec1234 as S34  # noqa: E402
from defender.tests.learning.oracle.live_contracts import _spec1224 as S24  # noqa: E402

pytestmark = pytest.mark.e2e

ALICE = S24.query_params("user:alice")
BOB = S24.query_params("user:bob")
CAROL = S24.query_params("user:carol")
BASE_ALICE = {"rows": [{"action": "logon", "event_id": "e-100", "user": "alice"}]}
BOB_BASE = {"rows": [{"action": "logon", "event_id": "e-200", "user": "bob"}]}
WITHHELD = ("edr", "lookup")


@pytest.fixture(autouse=True)
def _roots(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    return W.configure_roots(tmp_path, monkeypatch)


def _assert_only_listed_files(run_dir: Path, where: str) -> None:
    """Reject unlisted records, including encoded join sidecars."""
    rows = W.table_rows(run_dir)
    assert rows, f"fixture: {where} left no query table"
    RR.assert_only_run_records(run_dir, where, rows)


def _assert_no_call_id(rows: list[dict], where: str) -> None:
    carrying = [r for r in rows if W.CALL_ID in r]
    assert not carrying, (
        f"{where}: {len(carrying)} query row(s) carry `{W.CALL_ID}` — the model reads this "
        f"table, and the id is host bookkeeping it never uses (G4/G5): {carrying[:2]}")
    shaped = [tuple(r) for r in rows if tuple(r) != W.ROW_COLUMNS]
    assert not shaped, (
        f"{where}: query rows whose columns are not the writer's fourteen (a column carrying "
        f"the id under another name is the same leak): {shaped[:2]}")


def test_1255_a_natural_runs_query_rows_carry_no_call_id(tmp_path: Path) -> None:
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
    _assert_only_listed_files(run_dir, "natural run")


def _arm_drive(tmp_path: Path, label: str) -> tuple[Path, Path]:
    """Serve a recorded call, a new call, and a grant refusal through the real registry."""
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
    """Verify the host ledger retains identities and the identity detector finds them."""
    identities = W.arm_identities(ep)
    ledger = S24.ledger_rows(ep, label)
    token = S24.T.world_id(ep, label)
    assert all(r.get("world_id") == token for r in ledger), "positive control: the host names it"
    assert all(str(r.get(W.CALL_ID, "")).startswith(f"{token}/") for r in ledger), (
        "positive control: the host keeps each call's id")
    assert W.identities_in(json.dumps(ledger), identities), "positive control: the scan finds it"
    return identities


@pytest.mark.parametrize("label", ["a", "b"], ids=["control-world", "world-with-facts"])
def test_1255_no_file_in_an_arms_run_folder_names_the_arm_or_its_calls(
        tmp_path: Path, label: str) -> None:
    ep, run_dir = _arm_drive(tmp_path, label)
    identities = _positive_control_host_names_the_arm(ep, label)
    rows = W.table_rows(run_dir)
    _assert_no_call_id(rows, f"world {label}")
    assert not W.identities_in(json.dumps(rows), identities)
    call_ids = [str(r[W.CALL_ID]) for r in S24.ledger_rows(ep, label)]
    _assert_only_listed_files(run_dir, "the arm")
    files = [(p.relative_to(run_dir).as_posix(), p.read_bytes())
             for p in sorted(run_dir.rglob("*")) if p.is_file()]
    texts = {rel: data.decode("utf-8", "replace") for rel, data in files}
    assert any("user:bob" in t for t in texts.values()), "positive control: the scan reads files"
    tokens = {**{f"identity {i}": ident for i, ident in enumerate(identities)},
              **{f"call id {cid}": cid for cid in call_ids}}
    record = json.dumps({"lead_id": "l-001", "seq": 0, "call_id": call_ids[0]}).encode("utf-8")
    deflate = zlib.compressobj(wbits=-15)
    for how, blob in (("base64", base64.b64encode(record).decode("ascii")),
                      ("base64 zlib", base64.b64encode(zlib.compress(record)).decode("ascii")),
                      ("hex gzip", gzip.compress(record).hex()),
                      ("base64 raw deflate", base64.b64encode(
                          deflate.compress(record) + deflate.flush()).decode("ascii"))):
        assert IDN.encoded_hits(json.dumps({"z": blob}), tokens), (
            f"positive control: the encoded scan does not find a call id in a record ({how})")
    named = IDN.files_carrying(files, tokens)
    assert not named, f"files in the arm's run folder name the arm or its calls: {named}"


def test_1255_every_siblings_table_seeded_and_own_carries_no_call_id_or_arm_identity(
        tmp_path: Path) -> None:
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

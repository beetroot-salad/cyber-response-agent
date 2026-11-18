"""#1543: the oracle hands in a JSON Patch on the call's base answer; the host applies it.

The host derives the served answer from the patch, so the oracle never restates what it changed.
Every operation names the fact it serves; the changes are shown through the call's own query to
the oracle (`check`), the verifier and the stored answer. And each verified serving is kept for
later calls, which start fresh conversations of their own.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("pydantic_ai")

from defender.tests.learning.oracle.live_contracts import _spec1224 as S  # noqa: E402

USERS = {"total": 3, "users": [{"username": "sre.alice", "realm_role": "sre-ops"},
                               {"username": "svc.monitoring", "realm_role": "service-account"},
                               {"username": "svc.deploy", "realm_role": "service-account"}]}
DIRECTORY = {"what": "users"}
ALICE = S.query_params("user:alice")
BOB = S.query_params("user:bob")
ALICE_ROW = {"action": "logon", "event_id": "e-100", "user": "alice"}
BOB_ROW = {"action": "logon", "event_id": "e-200", "user": "bob"}
FORGED = {"action": "tgt-issued", "event_id": "e-9001", "user": "alice"}
ESQL = {"columns": [{"name": "user", "type": "keyword"}, {"name": "n", "type": "long"}],
        "values": [["alice", 3], ["bob", 5]]}


def _registry(tmp_path: Path, *moves: Any, captured: list[dict], verifier: Any = None,
              box: Any = None, **answers: Any) -> tuple[Any, Any, Path, Any, Any]:
    est = S.estate(tmp_path)
    for (system, verb, params, payload) in answers.get("live", ()):
        est.answer(system, verb, params, payload)
    ep = S.episode_v2(tmp_path / "ep", base_rows=captured)
    oracle = S.oracle(*moves)
    verifier = verifier or S.passing_verifier()
    reg = S.sandboxed_registry(ep, "b", est, oracle=oracle, verifier=verifier,
                               **({"box": box} if box is not None else {}))
    return reg, est.ctx(tmp_path / "run"), ep, oracle, verifier


def _answers(ep: Path) -> list[dict]:
    path = S.oracle_dir(ep, "b") / "answers.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def _servings(ep: Path) -> list[dict]:
    path = S.oracle_dir(ep, "b") / "servings.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def test_removing_one_user_from_a_directory_list_needs_only_its_fact(tmp_path):
    """The lab's unservable case: no query selects one user, and none is needed. The removal
    names its fact; the verifier sees the removed row; the stored answer keeps the change."""
    remove = S.handin(S.op_remove("/users/1", fact_id="f1"),
                      S.op_replace("/total", 2, fact_id="f1"))
    reg, ctx, ep, oracle, verifier = _registry(
        tmp_path, S.submit(remove), captured=[S.captured("idp", "lookup", DIRECTORY, USERS)])

    served = S.call(reg, "idp", "lookup", ctx, **DIRECTORY)

    assert served == {"total": 2, "users": [USERS["users"][0], USERS["users"][2]]}
    assert oracle.submissions() == 1
    assert "svc.monitoring" in verifier.all_seen(), "the verifier was not shown the removed row"
    [answer] = _answers(ep)
    removal, total = answer["claim"]["changes"]
    assert removal["op"] == "remove"
    assert removal["fact_id"] == "f1"
    assert removal["row_before"]["username"] == "svc.monitoring"
    assert removal["proven"] is False
    assert total["before"] == 3
    assert total["after"] == 2
    assert answer["claim"]["query"] == {"system": "idp", "verb": "lookup", "params": DIRECTORY}
    assert answer["decision"] in ("oracle", "reconstructed")


@pytest.mark.parametrize(("bad", "said"), [
    ({"op": "remove", "path": "/users/9", "fact_id": "f1"}, "patch operation 0 (remove"),
    ({"op": "move", "from": "/users/0", "path": "/users/2", "fact_id": "f1"}, "no move or copy"),
    ({"op": "add", "path": "/extra", "value": 1, "fact_id": "f1", "forged_id": "x"},
     "never a new key"),
    ({"op": "remove", "path": "/users/0"}, "needs the fact_id"),
    ({"op": "remove", "path": "/users/0", "fact_id": "f9"}, "not this world's"),
    ({"op": "add", "path": "/users/-", "value": {"username": "x"}, "fact_id": "f1"},
     "without a forged_id"),
])
def test_a_patch_the_host_cannot_read_or_apply_is_refused_and_says_why(tmp_path, bad, said):
    reg, ctx, _ep, oracle, verifier = _registry(
        tmp_path, S.submit({"patch": [bad]}), S.submit(),
        captured=[S.captured("idp", "lookup", DIRECTORY, USERS)])

    assert S.call(reg, "idp", "lookup", ctx, **DIRECTORY) == USERS
    assert oracle.submissions() == 2
    assert said in oracle.seen[-1], oracle.seen[-1][-800:]
    assert verifier.requests == 1, "the verifier was paid for a refused hand-in"


def test_check_shows_the_changes_the_host_would_serve(tmp_path):
    remove = S.handin(S.op_remove("/users/1", fact_id="f1"))
    reg, ctx, _ep, oracle, _v = _registry(
        tmp_path, S.check(remove), S.submit(remove),
        captured=[S.captured("idp", "lookup", DIRECTORY, USERS)])

    S.call(reg, "idp", "lookup", ctx, **DIRECTORY)

    reply = oracle.seen[1]
    assert "The draft passes the host checks." in reply
    assert "The host would serve these changes" in reply
    assert "svc.monitoring" in reply


def test_a_forged_row_is_added_and_a_frozen_one_is_served_again_by_its_id(tmp_path):
    first = S.handin(S.op_add("/rows/-", FORGED, forged_id="fg-1", fact_id="f1"))
    again = S.handin(S.op_add_frozen("/rows/-", forged_id="fg-1", fact_id="f1"))
    reg, ctx, ep, _oracle, _v = _registry(
        tmp_path, S.submit(first), S.submit(again),
        captured=[S.captured("idp", "query", ALICE, {"rows": [ALICE_ROW]}),
                  S.captured("idp", "query", BOB, {"rows": [BOB_ROW]})])

    assert S.call(reg, "idp", "query", ctx, **ALICE) == {"rows": [ALICE_ROW, FORGED]}
    assert S.call(reg, "idp", "query", ctx, **BOB) == {"rows": [BOB_ROW, FORGED]}
    forged = [json.loads(line) for line in
              (S.oracle_dir(ep, "b") / "forged.jsonl").read_text().splitlines()]
    assert [r["forged_id"] for r in forged] == ["fg-1"], "the reused row was frozen twice"


def test_an_esql_change_is_shown_by_its_column_name(tmp_path):
    params = {"query": "FROM logs | STATS n = COUNT(*) BY user"}
    patch = S.handin(S.op_replace("/values/1/1", 4, fact_id="f1"))
    reg, ctx, ep, _oracle, _v = _registry(
        tmp_path, S.submit(patch), captured=[S.captured("siem-x", "query", params, ESQL)])

    served = S.call(reg, "siem-x", "query", ctx, **params)

    assert served["values"] == [["alice", 3], ["bob", 4]]
    [change] = _answers(ep)[0]["claim"]["changes"]
    assert change["column"] == "n"
    assert change["table"] == "values"
    assert change["row_index"] == 1
    assert change["row_before"] == {"user": "bob", "n": 5}
    assert change["row_after"] == {"user": "bob", "n": 4}


def test_a_proof_that_selects_no_removed_row_is_refused(tmp_path):
    proof = S.proof("idp", "query", S.query_params("role:sre-ops"))
    bad = S.handin(S.op_remove("/users/1", fact_id="f1"), proofs=[proof])
    reg, ctx, _ep, oracle, _v = _registry(
        tmp_path, S.submit(bad), S.submit(),
        captured=[S.captured("idp", "lookup", DIRECTORY, USERS)],
        live=[("idp", "query", S.query_params("role:sre-ops"),
               {"total": 1, "users": [USERS["users"][0]]})])

    S.call(reg, "idp", "lookup", ctx, **DIRECTORY)

    assert "check 5: proof 0 selects 1 row(s), none of them a row the patch removes" in oracle.seen[-1]


def test_a_proof_that_selects_the_removed_row_marks_it_proven(tmp_path):
    proof = S.proof("idp", "query", S.query_params("role:service-account"))
    good = S.handin(S.op_remove("/users/1", fact_id="f1"), proofs=[proof])
    reg, ctx, ep, _oracle, _v = _registry(
        tmp_path, S.submit(good), captured=[S.captured("idp", "lookup", DIRECTORY, USERS)],
        live=[("idp", "query", S.query_params("role:service-account"),
               {"total": 2, "users": USERS["users"][1:]})])

    S.call(reg, "idp", "lookup", ctx, **DIRECTORY)

    assert _answers(ep)[0]["claim"]["changes"][0]["proven"] is True


def test_each_call_starts_a_fresh_conversation(tmp_path):
    from pydantic_ai.messages import ModelResponse

    reg, ctx, _ep, oracle, _v = _registry(
        tmp_path, S.submit(), S.submit(),
        captured=[S.captured("idp", "query", ALICE, {"rows": [ALICE_ROW]}),
                  S.captured("idp", "query", BOB, {"rows": [BOB_ROW]})])

    S.call(reg, "idp", "query", ctx, **ALICE)
    S.call(reg, "idp", "query", ctx, **BOB)

    second = oracle.messages[1]
    assert not any(isinstance(m, ModelResponse) for m in second), (
        "the second call's conversation carried the first call's replies")


SERVING_CODE = """
import json
index = json.load(open("inputs/index.json"))
print(json.dumps({"patch": [], "entity_refs": [], "proofs": []}))  # MARK-FIRST-CODE
"""

#: Reads the earlier serving the host saved and fails unless it carries the first call's code.
REUSING_CODE = """
import json, sys
index = json.load(open("inputs/index.json"))
[serving] = index["servings"]
saved = json.load(open("inputs/" + serving["name"]))
if "MARK-FIRST-CODE" not in saved["code"] or serving["question"]["params"]["q"] != "user:alice":
    sys.exit(3)
print(json.dumps({"patch": [], "entity_refs": [], "proofs": []}))
"""


def test_an_earlier_serving_is_saved_for_the_next_calls_code_and_shown_in_its_prompt(tmp_path):
    box, _scratches = S.host_box(tmp_path)
    reg, ctx, ep, oracle, _v = _registry(
        tmp_path, S.code(SERVING_CODE), S.code(REUSING_CODE), box=box,
        captured=[S.captured("idp", "query", ALICE, {"rows": [ALICE_ROW]}),
                  S.captured("idp", "query", BOB, {"rows": [BOB_ROW]})])

    S.call(reg, "idp", "query", ctx, **ALICE)
    assert [s["params"] for s in _servings(ep)] == [ALICE]
    assert S.call(reg, "idp", "query", ctx, **BOB) == {"rows": [BOB_ROW]}

    assert oracle.submissions() == 2, "the second call's code did not find the saved serving"
    assert "MARK-FIRST-CODE" in oracle.seen[1], "the second call's prompt did not show it"
    assert len(_servings(ep)) == 2


def test_similar_servings_prefer_the_calls_own_system_and_verb():
    from defender.learning.branch.estate.oracle import similar_servings

    servings = [{"system": "idp", "verb": "query", "params": {"q": "user:alice"}, "code": None},
                {"system": "elastic", "verb": "esql", "params": {"query": "FROM x"}, "code": None},
                {"system": "idp", "verb": "list", "params": {}, "code": None},
                {"system": "idp", "verb": "query", "params": {"q": "user:carol"}, "code": None}]

    ranked = similar_servings(servings, ("idp", "query", {"q": "user:alice"}), k=3)

    assert [r["params"] for r in ranked] == [{"q": "user:alice"}, {"q": "user:carol"}, {}]

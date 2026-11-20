"""A large answer reaches the oracle and its verifier as a bounded view, never pasted whole.

An answer past the view's budget is shown the way gather shows one (`payload_view.walk`): its
shape kept, each dropped region marked where it was dropped, and the whole answer saved for code.
The oracle already works on its saved files with `python`; the verifier gets a sandboxed box of
its own, holding what it judges (the base, the served answer, the changes), so it can check every
row rather than read them all. The box here is `S.host_box`: it RUNS the code on the host, in a
scratch folder of its own, so a check really reads the files the host saved.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("pydantic_ai")

from defender.tests.learning.oracle.live_contracts import _spec1224 as S  # noqa: E402

ALICE = S.query_params("user:alice")
BOB = S.query_params("user:bob")
#: The mark gather's view leaves exactly where it dropped part of an answer (the prompts name the
#: bare `<<ELIDED` prefix too, so only a count after it shows a view was made).
ELIDED = re.compile(r"<<ELIDED \d+ of \d+")
#: Well past the view's budget and well under the old 200,000-character head cut, so an answer
#: of this size was pasted whole before: the size of the replay's ticket searches that cost most.
ROWS = 600


def _rows(user: str, mark: str, n: int = ROWS) -> dict:
    return {"rows": [{"user": user, "event_id": f"e-{user}-{k:05d}", "action": "logon",
                      "note": f"{mark}-{k:05d} " + "x" * 80} for k in range(n)]}


BIG_ALICE = _rows("alice", "BASEMARK")
#: The row the verifier's tests remove carries a value longer than a shown change keeps (2,000
#: characters), so only a whole changes file holds it as the base does.
BIG_ALICE["rows"][-1]["note"] += "y" * 3000
BIG_BOB = _rows("bob", "READMARK")


def _text(value: Any) -> str:
    return json.dumps(value, sort_keys=True)


def _setup(tmp_path: Path, oracle: Any, verifier: Any, base: Any = BIG_ALICE) -> tuple[Any, Any, list[Path]]:
    est = S.estate(tmp_path)
    est.answer("idp", "query", ALICE, base)
    est.answer("idp", "query", BOB, BIG_BOB)
    ep = S.episode_v2(tmp_path / "ep")
    box, scratches = S.host_box(tmp_path)
    reg = S.sandboxed_registry(ep, "b", est, oracle=oracle, verifier=verifier, box=box,
                               retry_cap=1)
    return reg, est, scratches


def _last_row_removed() -> dict:
    return S.handin(S.op_remove(f"/rows/{ROWS - 1}", fact_id="f1"))


def test_a_large_base_answer_reaches_the_oracle_as_a_marked_view_and_is_served_whole(tmp_path):
    """The base is shown bounded (its dropped regions marked, the saved file named); the empty
    patch still serves the whole answer, since the patch applies to the saved one."""
    assert len(_text(BIG_ALICE)) > 50_000, "the base fits a view: nothing to test"
    oracle = S.oracle(S.submit())
    reg, est, _scratches = _setup(tmp_path, oracle, S.passing_verifier())

    served = S.call(reg, "idp", "query", est.ctx(tmp_path / "run"), **ALICE)

    assert served == BIG_ALICE, "the view changed what was served"
    first = oracle.seen[0]
    assert ELIDED.search(first), "the base was not shown as a marked view"
    assert first.count("BASEMARK-") < ROWS // 4, "most of the base's rows were pasted into the prompt"
    assert "inputs/index.json" in first, "the view does not say where the whole answer is"


def test_a_large_run_query_answer_reaches_the_oracle_as_a_view_naming_its_saved_file(tmp_path):
    oracle = S.oracle(S.run_query("idp", "query", BOB), S.submit())
    reg, est, _scratches = _setup(tmp_path, oracle, S.passing_verifier())

    S.call(reg, "idp", "query", est.ctx(tmp_path / "run"), **ALICE)

    reply = oracle.seen[1]
    assert ELIDED.search(reply), "the read's answer was not shown as a marked view"
    assert reply.count("READMARK-") < ROWS // 4, "most of the read's rows were pasted into the reply"
    assert "Saved for your code as inputs/read-" in reply


#: The verifier's check: every row of the served answer, read from the file its box was given.
VERIFY_CODE = """
import json
index = json.load(open("inputs/index.json"))
served = json.load(open("inputs/" + index["served"]))
base = json.load(open("inputs/" + index["base"]))
print("SERVED-ROWS", len(served["rows"]), "BASE-ROWS", len(base["rows"]))
change = json.load(open("inputs/" + index["changes"]))["changes"][0]
print("CHANGES", change["op"], "WHOLE", change["row_before"] == base["rows"][-1])
print("KEYS", sorted(index))
"""


def test_the_verifier_judges_a_large_answer_by_a_view_and_checks_every_row_with_code(tmp_path):
    """The verifier is shown the base and the served answer as views, and its own python reads
    them whole, with the changes, from files the host saved for it."""
    verifier = S.verifier(S.python(VERIFY_CODE), then=S.verdict(True))
    reg, est, _scratches = _setup(tmp_path, S.oracle(S.submit(_last_row_removed())), verifier)

    served = S.call(reg, "idp", "query", est.ctx(tmp_path / "run"), **ALICE)

    assert len(served["rows"]) == ROWS - 1
    first = verifier.seen[0]
    assert ELIDED.search(first), "the verifier was not shown a marked view"
    assert first.count("BASEMARK-") < ROWS // 2, "the verifier was pasted the answers whole"
    assert len(verifier.seen) >= 2, "the verifier's python got no reply"
    reply = verifier.seen[1]
    assert f"SERVED-ROWS {ROWS - 1} BASE-ROWS {ROWS}" in reply, reply[-2000:]
    assert "CHANGES remove WHOLE True" in reply, f"the changes file is not whole: {reply[-2000:]}"


def test_the_verifiers_box_is_its_own_and_holds_none_of_the_oracles_reads(tmp_path):
    """The verifier judges in a cold context: its box is not the oracle's, and its saved files
    carry neither the oracle's own reads nor earlier servings' code. Both boxes end with the
    attempt."""
    probe = VERIFY_CODE + "\nimport os\nprint('FILES', sorted(os.listdir('inputs')))\n"
    verifier = S.verifier(S.python(probe), then=S.verdict(True))
    oracle = S.oracle(S.run_query("idp", "query", BOB), S.python("print('ORACLE-RAN')"),
                      S.submit(_last_row_removed()))
    reg, est, scratches = _setup(tmp_path, oracle, verifier)

    S.call(reg, "idp", "query", est.ctx(tmp_path / "run"), **ALICE)

    assert len(scratches) == 2, f"the oracle and the verifier did not each get a box: {scratches}"
    assert not any(p.exists() for p in scratches), "a box outlived its attempt"
    reply = verifier.seen[1]
    assert "KEYS ['base', 'changes', 'reads', 'served']" in reply, reply[-2000:]
    files = reply.split("FILES", 1)[1].split("]", 1)[0]
    assert "read-" not in files, f"the oracle's read reached the verifier's box: {files}"


def test_a_verifier_that_runs_no_python_starts_no_box(tmp_path):
    reg, est, scratches = _setup(tmp_path, S.oracle(S.submit(_last_row_removed())),
                                 S.passing_verifier())

    S.call(reg, "idp", "query", est.ctx(tmp_path / "run"), **ALICE)

    assert scratches == [], "a box was started though no python ran"


def test_a_small_answer_is_shown_whole_as_before(tmp_path):
    small = {"rows": BIG_ALICE["rows"][:3]}
    oracle = S.oracle(S.submit())
    verifier = S.passing_verifier()
    reg, est, _scratches = _setup(tmp_path, oracle, verifier, base=small)

    S.call(reg, "idp", "query", est.ctx(tmp_path / "run"), **ALICE)

    assert not ELIDED.search(oracle.seen[0])
    assert not ELIDED.search(verifier.seen[0])
    assert all(f"BASEMARK-{k:05d}" in oracle.seen[0] for k in range(3))

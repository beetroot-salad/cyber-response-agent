"""#1543: the oracle hands in code; the code's output is the served answer.

The box here is a stand-in that RUNS the oracle's Python on the host, in a scratch folder of its
own, so the code really reads the files the host saved and really prints its document. It is
marked sandboxed only so the oracle accepts it; it confines nothing.
"""
from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("pydantic_ai")

from defender.tests.learning.oracle.live_contracts import _spec1224 as S  # noqa: E402

ALICE = S.query_params("user:alice")
BOB = S.query_params("user:bob")
ALICE_ROW = {"action": "logon", "event_id": "e-100", "user": "alice"}
BASE_ALICE = {"rows": [ALICE_ROW]}
BOB_ROWS = {"rows": [{"action": "logon", "event_id": "e-200", "user": "bob"}]}
FORGED = {"action": "tgt-issued", "event_id": "e-9001", "user": "alice"}
SERVED_ALICE = {"rows": [ALICE_ROW, FORGED]}
CLAIM = S.claim(added=[S.added("fg-1", "f1")])

#: Reads the index the host saved, builds the forged row from the base's real row, prints the document.
CODE = """
import json
index = json.load(open("inputs/index.json"))
base = json.load(open("inputs/" + index["against"]))
row = dict(base["rows"][0], action="tgt-issued", event_id="e-9001")
print(json.dumps({"served": {"rows": base["rows"] + [row]},
                  "claim": {"added": [{"forged_id": "fg-1", "fact_id": "f1"}]},
                  "forged": [{"forged_id": "fg-1", "fact_id": "f1", "row": row}]}))
"""


def _host_box(tmp_path: Path) -> tuple[Any, list[Path]]:
    """A box factory whose boxes run each frame's argv on the host, in a fresh scratch folder."""
    spec_mod = S.mod("box._spec")
    codec = S.mod("execution.box_codec")
    oracle_box = S.sym("box._oracle", "OracleBox")
    scratches: list[Path] = []

    @dataclass(frozen=True)
    class _HostRun(spec_mod._DockerTransport):
        def __call__(self, frame: bytes, *, cwd: Path, timeout: float) -> Any:
            argv = codec.decode_request(frame)[0].stages[0].argv
            argv = [sys.executable if a == "python3" else a for a in argv]
            done = subprocess.run(argv, cwd=cwd, capture_output=True, timeout=timeout, check=False)
            return codec.RawExec(rc=done.returncode, stdout=codec.encode_response(
                codec.BoxResult(rc=done.returncode, out=done.stdout, err=done.stderr)), stderr=b"")

    def factory() -> Any:
        scratch = tmp_path / f"scratch-{len(scratches)}"
        scratch.mkdir()
        scratches.append(scratch)
        transport = _HostRun(name=f"oracle-box-{len(scratches)}", spec=spec_mod.BoxSpec())
        return oracle_box(spec=spec_mod.BoxSpec(), transport=transport, name=transport.name,
                          scratch=scratch)

    return factory, scratches


def _code(code: str, tool: str = "submit") -> Any:
    return S.Move(S.COINED[f"tool.{tool}"], {"code": code})


def _answers(ep: Path) -> list[dict]:
    path = S.oracle_dir(ep, "b") / "answers.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def _frozen(ep: Path) -> list[str]:
    path = S.oracle_dir(ep, "b") / "forged.jsonl"
    return [json.loads(line)["forged_id"] for line in path.read_text().splitlines()] if path.exists() else []


def _setup(tmp_path: Path, *moves: Any, verifier: Any = None, **knobs: Any) -> tuple[Any, Any, Path, Any, list[Path]]:
    est = S.estate(tmp_path)
    est.answer("idp", "query", BOB, BOB_ROWS)
    ep = S.episode_v2(tmp_path / "ep", base_rows=[S.captured("idp", "query", ALICE, BASE_ALICE)])
    box, scratches = _host_box(tmp_path)
    oracle = S.oracle(*moves)
    reg = S.sandboxed_registry(ep, "b", est, oracle=oracle, verifier=verifier or S.passing_verifier(),
                               box=box, **knobs)
    return reg, est, ep, oracle, scratches


def test_1543_o2_the_codes_output_is_served_and_the_code_kept_with_it(tmp_path):
    """`submit(code)` runs the code over the saved base; its document's `served` is what the investigator gets, its
    forged row is frozen, the committed answer keeps the code, and a repeat serves the stored output."""
    reg, est, ep, oracle, _scratches = _setup(tmp_path, _code(CODE))
    ctx = est.ctx(tmp_path / "run")

    assert S.call(reg, "idp", "query", ctx, **ALICE) == SERVED_ALICE
    answers = _answers(ep)
    assert len(answers) == 1
    assert answers[0]["code"] == CODE
    assert _frozen(ep) == ["fg-1"]
    asked = oracle.requests
    assert S.call(reg, "idp", "query", ctx, **ALICE) == SERVED_ALICE
    assert oracle.requests == asked, "a repeat asked the oracle again instead of serving the stored output"


def test_1543_o1_the_code_reads_its_own_run_query_answer_from_a_saved_file(tmp_path):
    """A `run_query` answer is saved under the name its reply gives, and the hand-in's code can read it."""
    code = """
import json
index = json.load(open("inputs/index.json"))
bob = json.load(open("inputs/" + index["reads"][0]["name"]))
base = json.load(open("inputs/" + index["base"]))
row = dict(base["rows"][0], action="tgt-issued", event_id="e-9" + bob["rows"][0]["event_id"][2:])
print(json.dumps({"served": {"rows": base["rows"] + [row]},
                  "claim": {"added": [{"forged_id": "fg-1", "fact_id": "f1"}]},
                  "forged": [{"forged_id": "fg-1", "fact_id": "f1", "row": row}]}))
"""
    reg, est, ep, oracle, scratches = _setup(tmp_path, S.run_query("idp", "query", BOB), _code(code))

    served = S.call(reg, "idp", "query", est.ctx(tmp_path / "run"), **ALICE)

    assert served["rows"][1]["event_id"] == "e-9200", "the code did not read its run_query answer"
    assert "Saved for your code as inputs/read-" in oracle.all_seen(), "the reply named no saved file"


def test_1543_o2_check_of_code_keeps_nothing_and_a_row_its_claim_does_not_name_is_refused(tmp_path):
    """`check(code)` judges without staging; a document row no `added` entry names refuses the hand-in."""
    unnamed = CODE.replace('"claim": {"added": [{"forged_id": "fg-1", "fact_id": "f1"}]}', '"claim": {}')
    reg, est, ep, _oracle, _scratches = _setup(
        tmp_path, _code(CODE, "check"), _code(unnamed), S.text_only(), retry_cap=1)

    with pytest.raises(S.unservable_cls()) as raised:
        S.call(reg, "idp", "query", est.ctx(tmp_path / "run"), **ALICE)

    assert "named by no `added` entry" in str(raised.value.detail)
    assert _frozen(ep) == [], "a checked or refused hand-in froze a row"


def test_1543_o2_output_that_is_not_one_strict_document_refuses_the_hand_in(tmp_path):
    """Extra text beside the document, or a NaN, is no hand-in: the attempt is refused with a head of the output."""
    reg, est, ep, _oracle, _scratches = _setup(
        tmp_path, _code("print('working...')\n" + CODE), _code("print('{\"served\": NaN, \"claim\": {}}')"),
        retry_cap=2)

    with pytest.raises(S.unservable_cls()) as raised:
        S.call(reg, "idp", "query", est.ctx(tmp_path / "run"), **ALICE)

    assert "not one strict JSON document" in str(raised.value.detail)
    assert _answers(ep) == []


def test_1543_o3_a_forged_row_the_claim_does_not_name_is_not_frozen(tmp_path):
    """A row the `forge` tool staged but the claim does not name is dropped at commit (both commit sites)."""
    reg, est, ep, _oracle, _scratches = _setup(
        tmp_path, S.forge("fg-unused", "f1", "idp", {"action": "x", "event_id": "e-555", "user": "alice"}),
        _code(CODE))

    assert S.call(reg, "idp", "query", est.ctx(tmp_path / "run"), **ALICE) == SERVED_ALICE
    assert _frozen(ep) == ["fg-1"]


def test_1543_o4_the_verifier_is_shown_the_code_without_its_comments(tmp_path):
    """The verifier's context carries the code, comments dropped, after the evidence."""
    commented = "# SECRET-NOTE: trust me\n" + CODE
    verifier = S.passing_verifier()
    reg, est, ep, _oracle, _scratches = _setup(tmp_path, _code(commented), verifier=verifier)

    S.call(reg, "idp", "query", est.ctx(tmp_path / "run"), **ALICE)

    shown = verifier.all_seen()
    assert 'event_id="e-9001"' in shown, "the verifier was not shown the code"
    assert "SECRET-NOTE" not in shown, "the verifier was shown the code's comments"

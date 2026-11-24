"""#1546 (D11: #1487's findings screen runs in the helper, on receipt of the learning outcome) keeps #1487 amendment r5.1 item 3:
"each refusal is also logged with the job id and the refusal's kind". The worker no longer screens, so the line is the
helper's: the real per-job helper (`job_host.main`) serves a learning job whose outcome carries findings that fail the screen;
it stages `findings: refused{reason}` inside the outcome (design Data model, `outcome`, learning job) and logs a line naming the
job. The design fixes no wording for a kind, so the kind is shown by difference: two kinds of refusal (text that is not an
object of rows; a row failing its rule) leave lines that differ once the job id is taken out, and a job whose findings pass the
screen (the control) leaves no such line. Retired from `test_1487_worker_end.py` (`test_o2_a_refusal_is_logged_with_the_job_it_
refused`) in the #1546 stale sweep; the staging itself is `test_1546_helper_records.py`'s."""
from __future__ import annotations

import json
import logging
import re
import sys

import pytest

from defender.tests.support.evidence._evidence1546 import evidence_keys, garage  # noqa: F401 — fixtures of `evidence_store`
from defender.tests.support.evidence._facts1546 import screened, sent_findings
from defender.tests.support.jobs import _helper_evidence1546 as H
from defender.tests.support.jobs import _job_helper as J
from defender.tests.support.jobs._helper_evidence1546 import drive, facts, learning_outcome, plant, send
from defender.tests.support.shared._openbao1163 import openbao  # noqa: F401 — fixture of `evidence_store`

process_state = J.process_state
scene = H.fresh_scene
evidence_store = H.evidence_store

pytestmark = [pytest.mark.postgres, pytest.mark.garage, pytest.mark.openbao,
              pytest.mark.skipif(not sys.platform.startswith("linux"), reason="the helper is Linux only")]


def _rows(job: str, n: int = 1, **over) -> list[dict]:
    from defender.tests.support.jobs._findings1487 import defender_row

    return [defender_row(job, i, **over) for i in range(n)]


def _text(rows: list[dict]) -> str:
    from defender.tests.support.jobs._findings1487 import text_of

    return text_of(rows, [])


#: Each case's findings text for its job: passing the screen (the control), text that is not an object of rows (#1487's
#: shape refusal), a row failing its rule (#1487's row refusal: a type outside the channel's vocabulary).
FINDINGS = {
    "passes": lambda job: _text(_rows(job, 2)),
    "not-an-object": lambda job: json.dumps([1, 2]),
    "row-fails-its-rule": lambda job: _text(_rows(job, 1, type="not-a-type")),
}


_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\S+\s+")
_IDS = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9a-f]{32}")


def _lines(caplog, capfd, job: str) -> list[str]:
    """Every log record and stderr line of the helper run that names `job`, as said (a log handler's timestamp dropped)."""
    found = [r.getMessage() for r in caplog.records] + capfd.readouterr().err.splitlines()
    return sorted({_TIMESTAMP.sub("", line) for line in found if job in line})


def _shape(lines: list[str], job: str) -> set[str]:
    """`lines` with the job id, then every other id (claim, source, alert) and number taken out: what is left says the kind."""
    return {re.sub(r"\d+", "<n>", _IDS.sub("<id>", line.replace(job, "<job>"))) for line in lines}


def _run(scene, monkeypatch, evidence_store, caplog, capfd, case: str) -> tuple[str, dict, list[str]]:
    """One learning job of its own claim, whose outcome carries `case`'s findings: `(job, staged outcome, its lines)`."""
    s = J.next_claim(scene, monkeypatch)
    planted = plant(s, "learning")
    outcome = learning_outcome(findings=sent_findings(FINDINGS[case](planted.owner)))
    caplog.clear()
    capfd.readouterr()
    drive(s, planted, lambda c: send(c, "outcome", record=outcome) and 0, **evidence_store.seams)
    staged = facts(s.dsn, s.claim)
    assert "outcome" in staged, f"premise: the {case} outcome was staged: {sorted(staged)}"
    return planted.owner, staged["outcome"], _lines(caplog, capfd, planted.owner)


def test_a_learning_outcome_whose_findings_fail_the_screen_is_staged_refused_and_logged_naming_the_job_and_its_kind(
        scene, monkeypatch, evidence_store, caplog, capfd):
    """Two jobs whose findings fail the screen for different kinds each stage `findings: refused{reason}` (never rows) and
    leave a line naming that job that the passing control's run does not leave; neither line names the other job; the two
    kinds' lines differ once the job id is taken out. Fails on a helper that logs nothing for a refusal, logs it without the
    job id, logs every kind alike, or stages the refused findings as screened. (#1487 r5.1 item 3, D11, PR2)"""
    caplog.set_level(logging.INFO)
    control, staged, control_lines = _run(scene, monkeypatch, evidence_store, caplog, capfd, "passes")
    assert staged["findings"]["state"] == "screened", f"control: passing findings were not screened: {staged['findings']}"
    assert staged["findings"] == screened(*_rows(control, 2)), staged["findings"]

    refused: dict[str, tuple[str, list[str], set[str]]] = {}
    for case in ("not-an-object", "row-fails-its-rule"):
        job, staged, lines = _run(scene, monkeypatch, evidence_store, caplog, capfd, case)
        assert staged["findings"]["state"] == "refused", f"{case}: findings that fail the screen were staged {staged['findings']}"
        assert staged["findings"].get("reason"), f"{case}: a refused screen staged no reason"
        assert "rows" not in staged["findings"], f"{case}: refused findings carry rows"
        assert staged["status"] == "completed", f"{case}: the refusal changed the job's own ending: {staged['status']}"
        extra = _shape(lines, job) - _shape(control_lines, control)
        assert extra, f"{case}: no line names the refused job {job} beyond what a passing job's run logs: {lines}"
        refused[case] = (job, lines, extra)

    (a, a_lines, a_kind), (b, b_lines, b_kind) = refused["not-an-object"], refused["row-fails-its-rule"]
    assert not [line for line in a_lines if b in line or control in line], f"a refusal's line names another job: {a_lines}"
    assert not [line for line in b_lines if a in line or control in line], f"a refusal's line names another job: {b_lines}"
    assert a_kind != b_kind, f"two kinds of refusal logged alike: {sorted(a_kind)}"

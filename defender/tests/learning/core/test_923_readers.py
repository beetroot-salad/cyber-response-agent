"""#923 - a malformed committed verdict is marked, never coerced, by every reader of a finished run."""
from __future__ import annotations

from pathlib import Path

from defender.tests.support.shared.contracts._spec1077 import fixture_run as _run_handle_1165
from defender.tests.support.runtime.engine._spec923 import finished_run
from defender.tests.support.tenancy._tenants1106 import fixture_run_tenant
from defender.tests.support.sandbox._spec791 import (  # noqa: F401 — session-scoped autouse guard
    worktree_package_guard,
)


def _reader_answers(run_dir: Path) -> dict[str, tuple[str, object]]:
    """Every consumer of a finished run's committed verdict, DRIVEN, with a refusal captured rather than raised"""
    from defender.records._report import read_report
    from evaluations.held_out import predicted_disposition
    from defender.learning.core.validate import normalize_disposition
    from defender.cli.learning.trace_lesson import _report_disposition
    from defender.tenancy import case_ticket

    report = run_dir / "report.md"

    def call(fn):
        try:
            return ("ok", fn())
        except Exception as e:  # noqa: BLE001 — the refusal's TYPE is the observation
            return ("refused", type(e).__name__)

    return {
        "report_reader": call(lambda: read_report(report).disposition),
        "learning_validate": call(lambda: normalize_disposition(report)),
        "held_out": call(lambda: predicted_disposition(run_dir)),
        "ticket_lane": call(lambda: case_ticket.read_case_record(_run_handle_1165(run_dir), mapping=fixture_run_tenant().ticket_mapping).disposition),
        "trace_lesson": call(lambda: _report_disposition(run_dir)),
    }


def test_a_malformed_committed_verdict_is_marked_not_coerced(tmp_path):
    """A committed verdict that is not a member of the vocabulary is never coerced into the member it resembles."""
    from defender.records._report import read_report
    from defender.tests.support.runtime.engine._spec923 import MALFORMED_MEMBER_SPELLINGS, NOT_A_MEMBER

    unknown = _reader_answers(finished_run(tmp_path / "unknown", disposition=NOT_A_MEMBER))

    for i, spelling in enumerate(MALFORMED_MEMBER_SPELLINGS):
        run_dir = finished_run(tmp_path / f"malformed-{i}", disposition=spelling)
        answers = _reader_answers(run_dir)
        assert answers == unknown, (
            f"{spelling!r} is read differently from a value that was never a member: "
            f"{ {k: v for k, v in answers.items() if unknown[k] != v} } — a verdict that only "
            f"becomes a member after something strips or folds it is exactly the close no "
            f"reader can tell from a clean one"
        )
        assert not any(v == ("ok", "malicious") for v in answers.values()), (
            f"a reader coerced {spelling!r} into the member it resembles: {answers}"
        )
        reason = read_report(run_dir / "report.md").reason or ""
        assert repr(spelling) in reason or spelling in reason, (
            f"the run is refused without quoting what it actually held ({reason!r}) — a person "
            f"asked to judge a malformed verdict cannot see an invisible character described "
            f"in prose"
        )

    # THE PAIRED POSITIVE CONTROL: the clean spelling, same fixture, same readers.
    clean = _reader_answers(finished_run(tmp_path / "clean", disposition="malicious"))
    assert clean != unknown, "the readers answer the same for a real verdict and a garbage one"
    for name, (status, value) in clean.items():
        assert (status, value) == ("ok", "malicious"), (
            f"{name} does not read an ordinary committed verdict back: {(status, value)}"
        )

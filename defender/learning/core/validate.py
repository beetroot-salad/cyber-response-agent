from __future__ import annotations

from pathlib import Path

from defender.records.formats import ReportRead, read_report
from defender.learning.core.config import RunUnprocessable




def normalize_disposition(report_path: Path) -> str:
    """The run's disposition, or `RunUnprocessable`.

    `_report.read_report` decides what the value means; this refuses an unreadable headline
    with a typed error the drain can dead-letter, never a guess. Each refusal carries the
    report's head, the operator's only view of what the model wrote.
    """
    read = read_report(report_path)
    if read.disposition is None:
        raise RunUnprocessable(_unprocessable_reason(read, report_path))
    return read.disposition


def _unprocessable_reason(read: ReportRead, report_path: Path) -> str:
    if not read.text:
        return str(read.reason)
    head = "\n".join(read.text.splitlines()[:30])
    return f"{read.reason}\n--- {report_path} (head) ---\n{head}"

"""The running test's fixture request, held by the suite's root conftest (`_running_request`, autouse) for support code that
must resolve a fixture on the test's behalf from outside a fixture: `_job_helper.drive_helper` and `ProcessHelper` configure
every helper they start with the real evidence store (`garage`, `openbao`, `evidence_keys`), whatever module the test is in
(#1546 design Flows: "an unconfigured store or evidence-key login is refused at helper setup, terminally"; rule R17: the
harness decides, not whether a module imported a fixture). Imports nothing, so the root conftest can hold it for every test."""
from __future__ import annotations

from typing import Any

#: The running test's request while it runs (set at its setup, cleared at its teardown); empty between tests.
REQUEST: list[Any] = []


def current() -> Any | None:
    return REQUEST[0] if REQUEST else None

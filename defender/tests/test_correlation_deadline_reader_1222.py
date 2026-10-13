"""The correlation deadline reader refuses every unusable value with its own error (#1222)."""
from __future__ import annotations

import pytest

from defender.runtime.lead_zero import CorrelationDeadlineError, correlation_deadline


@pytest.mark.parametrize("value", [10**400, -(10**400), float("nan"), float("inf"), 0, True, "5"])
def test_an_unusable_deadline_is_the_readers_own_error(value):
    with pytest.raises(CorrelationDeadlineError):
        correlation_deadline({"correlation_deadline": value})

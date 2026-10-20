"""#1222 suite fixtures: the configured roots a scenario must never share with the host."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

from defender.tests.support.learning.branch import _triplet_947 as T


@pytest.fixture(autouse=True)
def _configured_roots_1222(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    T.isolate_learning_state(tmp_path, monkeypatch)


@pytest.fixture(autouse=True)
def _checkout_corpus_1222(tmp_path: Path, request: pytest.FixtureRequest):
    """Lesson tests run the real product against an isolated checkout-owned corpus."""
    if request.module.__name__.rsplit(".", 1)[-1] not in {
            "test_1222_lessons_and_corpus", "test_1222_signature_sinks"}:
        yield
        return
    from defender.tests.tenancy.alert_front_door_1222 import _spec1222 as S
    from defender.tests.support.shared.contracts._repo import build_once_copy

    checkout = build_once_copy("1222.product-checkout", S.prepare_checkout,
                               tmp_path / "product" / "defender")
    token = S.LESSON_CHECKOUT.set(checkout)
    # Adapter bootstraps may prepend this checkout while loading their real modules.
    # Restore the import boundary before another test inspects the namespace package.
    original_path = list(sys.path)
    try:
        yield
    finally:
        sys.path[:] = original_path
        S.LESSON_CHECKOUT.reset(token)

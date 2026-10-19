"""#920 — the one private-framework symbol the resume seam depends on, pinned."""
from __future__ import annotations

import pytest

pytest.importorskip("pydantic_ai")

from defender.runtime import branch  # noqa: E402
from defender.tests.support.storage._session_store_705 import (  # noqa: E402
    complete_pair,
    text_response,
    user_request,
)


def test_the_framework_still_merges_adjacent_same_role_messages():
    requests = [user_request("orient"), *complete_pair(), user_request("correlation summary")]
    responses = [user_request("orient"), text_response("thinking"), *complete_pair()]

    assert len(branch.framework_view(responses)) == len(responses) - 1, (
        "adjacent ModelResponses merge too — a prefix ending on a text response before a tool "
        "call is an ordinary shape, and it moves the count the seam re-seeds from")

    view = branch.framework_view(requests)

    assert len(view) == len(requests) - 1, (
        f"the resume seam re-seeds `last_render_len` to what the framework holds; it held "
        f"{len(view)} of {len(requests)} and the seam expects exactly one merge here")


def test_a_prefix_the_framework_does_not_touch_survives_intact():
    prefix = [user_request("orient"), *complete_pair()]

    view = branch.framework_view(prefix)

    assert [type(m).__name__ for m in view] == [type(m).__name__ for m in prefix]
    assert len(view) == len(prefix)


def test_the_private_symbol_is_still_where_the_seam_reaches_for_it():
    from pydantic_ai._agent_graph import _clean_message_history

    assert callable(_clean_message_history)

"""#920 — the one private-framework symbol the resume seam depends on, pinned.

`branch.framework_view` calls `pydantic_ai._agent_graph._clean_message_history`. That is the
only private-framework import in the tree, against an unbounded `>=1.107` pin, and it is
function-local — so a framework that renamed it would fail MID-RESUME, inside a run that has
already forked a session and written a case pointer, rather than at collection.

This file is that collection-time failure. It asserts the symbol exists AND that it still does
the thing the seam depends on, because a symbol that survives a rename while changing behaviour
is the worse of the two failures: `fork` and `hydrate` count store rows, the framework counts
what it holds after normalising, and the resume works only while both numbers come from the
same call.
"""
from __future__ import annotations

import pytest

pytest.importorskip("pydantic_ai")

from defender.runtime import branch  # noqa: E402
from defender.tests._session_store_705 import (  # noqa: E402
    complete_pair,
    text_response,
    user_request,
)


def test_the_framework_still_merges_adjacent_same_role_messages():
    """    Two adjacent same-role messages come back as one.

    The store produces exactly this shape: #808's correlation lead is a synthesized
    `ModelRequest` written straight into MAIN's session, landing next to the tool-return
    `ModelRequest` before it — and RESPONSES merge the same way, measured here as a second
    arm, which is broader than the shape that first motivated the seam. If the framework stopped
    merging, `framework_view` would return
    the prefix unchanged and the re-seed it guards would become a no-op — harmless. If it
    started merging something ELSE, the count would drift the other way and a resume would
    underflow. Either way the seam's assumption is what this measures."""
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
    """    An alternating prefix has nothing to merge, so `framework_view` is the identity.

    This is the arm that keeps the merge measurement honest: if the function started dropping
    or rewriting messages generally, the case above would still pass on the count alone."""
    prefix = [user_request("orient"), *complete_pair()]

    view = branch.framework_view(prefix)

    assert [type(m).__name__ for m in view] == [type(m).__name__ for m in prefix]
    assert len(view) == len(prefix)


def test_the_private_symbol_is_still_where_the_seam_reaches_for_it():
    """    The import itself, at COLLECTION time.

    `framework_view` imports inside the function body — deliberately, because hoisting it
    would put `pydantic_ai._agent_graph` in the import graph of every process that imports the
    driver. The cost of that deferral is that a rename surfaces during a run; this test is what
    pays it back."""
    from pydantic_ai._agent_graph import _clean_message_history

    assert callable(_clean_message_history)

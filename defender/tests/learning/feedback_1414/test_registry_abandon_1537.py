"""#1537 (design r3, O3 and A4): the abandon of a parked registry batch settles it abandoned and leaves its PR open for a person.

Driven over the `fb` scene; the registry batch is parked as a person would find it (`_release1537.park`), a request made through
the store, and the lessons author's tick (which tends every lane, `reconcile_lanes`) is the real settle.
"""
from __future__ import annotations

import pytest

from defender.tests.learning.feedback_1414 import _spec1414 as S
from defender.tests.learning.feedback_1414._spec1414 import OWNER
from defender.tests.support.learning.core._release1537 import CREDENTIAL, park, row
from defender.tests.support.learning.core._store1278 import call
from defender.tests.tenancy.tenant_1108_p4._drain_support import BoxSpy, author_drain, remote_branches

pytestmark = pytest.mark.postgres


def _parked_registry(fb):
    number = fb.opened("case-approve")
    comment = fb.forge.add_comment(number, user=OWNER, body="expected: the nightly backup")
    assert fb.tick(S.Decider({comment["id"]: S.answer(approve=(0,))})) == 0
    [batch] = S.feedback_batches(fb)
    [(branch, tip)] = remote_branches(fb.t.remote, S.FEEDBACK_PREFIX).items()
    park(fb.dsn, batch.id)
    return batch, branch, tip


@pytest.mark.parametrize("requested", [False, True])
def test_o3_an_abandoned_registry_batch_ends_abandoned_with_its_pr_left_open_and_the_bot_never_closes_it(fb, requested):
    """With a request, a tick ends the parked registry batch `abandoned` (park cause kept), its PR still open, no PATCH, its branch at the same tip; with none, nothing moves. (O3, A4)"""
    batch, branch, tip = _parked_registry(fb)
    [pr] = [p for p in fb.forge.prs if p["head"]["ref"] == branch]
    assert row(fb.dsn, batch.id)["phase"] == "needs_person", "premise"
    if requested:
        call(fb.dsn, "request_abandon", fb.t.tenant_id, str(batch.id), actor="u-1537")

    for _ in range(2):
        assert author_drain(fb.t, fb.paths, trigger=None, box=BoxSpy()) == 0

    got = row(fb.dsn, batch.id)
    assert [r for r in fb.forge.requests if r.method == "PATCH"] == []
    assert [p["state"] for p in fb.forge.prs if p["number"] == pr["number"]] == ["open"]
    assert remote_branches(fb.t.remote, S.FEEDBACK_PREFIX) == {branch: tip}
    want = ("ended", "abandoned", CREDENTIAL, None) if requested else ("needs_person", None, CREDENTIAL, got["parked_at"])
    assert (got["phase"], got["outcome"], got["cause"], got["parked_at"]) == want

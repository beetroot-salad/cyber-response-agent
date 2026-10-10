"""#1221 O3 — gather is served a ticket reply as the store answered it.

The design (issue #1221, D3/M2): both read screens go — the own-case identity exclusion and the
comment-release screen (an open case's comments withheld until a person closes it). They were
lab-shaped (system `ticket`, verbs `get-ticket`/`list-tickets`, case key = run id), did not run
on any other tenant, hid enrichment in the lab, and missed branch runs anyway. Model-made
precedent is now handled by tagging (O1) and rule #27 (O2), not by filtering. After this,
product code applies no ticket-specific or content-based transform to a ticket reply; the
generic size view (`runtime/payload_view.py`) still applies, as for every system.

Every test here drives a REAL run (`e2e/_replay_harness.drive`): main dispatches one gather
lead, the gather model replays a `query` call, and everything between — dispatch, the query
tool, the grant decision, the capture, the payload view — is production code. The store is a
fake verb that records what it was handed and answers a fixed payload. Each test asserts on
the two places a reply lands: the capture (`gather_raw/<lead>/<seq>.json`, which must equal the
store's answer exactly) and the text the gather model was handed back.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("pydantic_ai")

from defender.runtime.verbs import VerbContext  # noqa: E402
from defender.tests import _tenants1106 as T1106  # noqa: E402
from defender.tests._verb_authorization_632 import (  # noqa: E402
    DONE,
    LEAD,
    ScopedFakeVerbs,
    q,
    run_gather,
)
from defender.tests.e2e._replay_harness import (  # noqa: E402
    GOLDEN_AB3,
    FakeVerbs,
    ReplayFn,
    Turn,
    VerbRecorder,
    drive,
    materialize,
)
from defender.tests.tenant_1107_settings import _spec1107 as S  # noqa: E402

#: The run's own id — and so the key of the case it is investigating (the lab's case key is
#: the run id).
OWN = "20261008T120000Z-1221-own-case"
OPEN_KEY = "SOC-OPEN-1221"
#: Comment text distinctive enough that its presence in the model's view is unambiguous.
OWN_NOTE = "OWN-CASE-ENRICHMENT-1221: the customer's own note on the alerted host"
OPEN_NOTE = "UNRELEASED-COMMENT-1221: an analyst's note on a case nobody has closed"

#: A tenant whose gather grant holds `get-ticket` — the committed fixture's withholds it
#: (`test_gather_is_denied_ticket_get_ticket`), and this test is about the reply, not the grant.
GET_TICKET_TABLE = """dispositions:
  ticket:
    get-ticket: {roles: [gather]}
    health-check: {roles: [gather]}
    list-tickets: {roles: [gather]}
"""


def _ticket(key: str, note: str, *, status: str = "open") -> dict[str, Any]:
    return {"key": key, "summary": f"case {key}", "status": status, "labels": ["sig:5710"],
            "comments": [{"author": "analyst", "body": note, "created": "2026-10-08T11:00:00Z"}]}


def _capture(run_dir: Path, seq: int = 0) -> Any:
    return json.loads((run_dir / "gather_raw" / LEAD / f"{seq}.json").read_text(encoding="utf-8"))


def _list_registry(rec: VerbRecorder, answer: Any) -> ScopedFakeVerbs:
    """`list-tickets` answering `answer`, under the committed fixture tenant's real gather
    grant."""

    def list_tickets(ctx: VerbContext, *, status: str | None = None, label: str | None = None,
                     q: str | None = None) -> Any:
        rec.record("list-tickets", ctx, {"status": status, "label": label, "q": q})
        return copy.deepcopy(answer)

    return ScopedFakeVerbs({"ticket": {"list-tickets": list_tickets}},
                           T1106.fixture_grants().gather)


def test_1221_list_tickets_serves_the_own_case_and_an_open_cases_comments(tmp_path):
    """A `list-tickets` reply carrying the run's OWN case (its key is the run id) and an OPEN
    case — one no person has closed — each with a comment, reaches gather whole: the capture
    equals what the store answered, `total` included, and the model's view carries both keys
    and both comments. Nothing is removed by identity and nothing is emptied by lifecycle
    state.

    The second drive is the shape half: a bare array (an undocumented envelope) is served as
    the store answered it, not refused as a malformed ticket reply — a ticket-specific shape
    rule was part of the screen, and the query tool has none for any other system."""
    listing = {"total": 2, "source": "ticket-store",
               "tickets": [_ticket(OWN, OWN_NOTE), _ticket(OPEN_KEY, OPEN_NOTE)]}
    rec = VerbRecorder()
    run = run_gather(tmp_path / "envelope", verbs=_list_registry(rec, listing), system="ticket",
                     turns=[q("ticket", "list-tickets", {}), DONE], run_id=OWN)

    assert [c.verb for c in rec.calls] == ["list-tickets"], "the store was not asked"
    assert [r["exit_code"] for r in run.own_rows] == [0], "the listing was refused"
    assert _capture(run.run_dir) == listing, (
        "the captured reply is not what the store answered — a ticket-specific transform ran"
    )
    seen = run.gather_delta
    for needle, what in ((OWN, "the run's own case"), (OWN_NOTE, "the own case's comment"),
                         (OPEN_KEY, "the open case"), (OPEN_NOTE, "the open case's comment")):
        assert needle in seen, f"{what} never reached the gather model"

    bare = [_ticket(OWN, OWN_NOTE), _ticket(OPEN_KEY, OPEN_NOTE)]
    shaped = VerbRecorder()
    run = run_gather(tmp_path / "bare", verbs=_list_registry(shaped, bare), system="ticket",
                     turns=[q("ticket", "list-tickets", {}), DONE], run_id=OWN)
    assert len(shaped.calls) == 1
    assert [r["exit_code"] for r in run.own_rows] == [0], (
        "a bare-array ticket reply was refused — the query tool keeps a ticket-only shape rule"
    )
    assert _capture(run.run_dir) == bare
    assert OWN_NOTE in run.gather_delta, "the own case's comment never reached the model"
    assert OPEN_NOTE in run.gather_delta, "the open case's comment never reached the model"


@pytest.mark.parametrize(("key", "note"), [(OWN, OWN_NOTE), (OPEN_KEY, OPEN_NOTE)],
                         ids=["own-case", "another-open-case"])
def test_1221_get_ticket_on_the_runs_own_key_is_served(tmp_path, key, note):
    """A `get-ticket` on the run's OWN key — and, the sibling surface, on ANOTHER open case's
    key — reaches the store and its reply (an open case with a comment) reaches gather whole:
    the verb ran with that key, the capture equals the store's answer, and the comment is in
    the model's view. No pre-call refusal by key, and no comment withheld because the case is
    open, whichever case it is.

    The grant is not the subject: the tenant planted here grants `get-ticket` to gather (the
    committed fixture withholds it), so a refusal could only come from the query tool."""
    root = tmp_path / "tenants"
    S.plant(root, marker="t1221", table=GET_TICKET_TABLE)
    case = _ticket(key, note)
    rec = VerbRecorder()

    def get_ticket(ctx: VerbContext, *, key: str) -> Any:
        rec.record("get-ticket", ctx, {"key": key})
        return copy.deepcopy(case)

    run_dir = materialize(tmp_path / "run", GOLDEN_AB3)
    main = ReplayFn([
        Turn(tool_calls=[("gather", {"lead_id": LEAD, "system": "ticket",
                                     "goal": "read the case's own ticket",
                                     "what_to_summarize": ["what the ticket says"]})]),
        Turn(text="Investigation complete."),
    ])
    gather = ReplayFn([q("ticket", "get-ticket", {"key": key}), DONE])
    drive(run_dir, run_id=OWN, main=main, gather=gather,
          verbs=FakeVerbs({"ticket": {"get-ticket": get_ticket}}),
          tenant=S.tenant_folder_of(root))

    assert [(c.verb, c.params) for c in rec.calls] == [("get-ticket", {"key": key})], (
        f"a get-ticket on {key} never reached the store"
    )
    assert _capture(run_dir) == case, "the captured reply is not what the store answered"
    head = gather.seen[0]
    assert gather.seen[-1].startswith(head)
    seen = gather.seen[-1][len(head):]
    assert note in seen, f"{key}'s comment never reached the gather model"


def test_1221_the_family_prompt_no_longer_demands_a_released_status_on_a_comment_patch():
    """The branch questioner's family prompt taught the refusal the estate applier enforced: a
    `ticket` patch writing `comments` had to move the case to `closed`, because an open case
    served no comments and the family was refused when parsed. #1221 removed both the screen
    and the refusal (`test_a_ticket_patch_writing_comments_on_an_unreleased_case_is_accepted`),
    so a prompt still teaching it would have the questioner close every case it annotates — a
    difference of its own in every sibling. The control: the prompt still teaches a world's
    `facts` (#1224 replaced the `patches` table this control once named with facts a live oracle
    serves)."""
    prompt = (Path(T1106.DEFENDER) / "learning" / "branch" / "questioner" / "family.md").read_text(
        encoding="utf-8")
    flat = " ".join(prompt.split())
    assert "`facts`" in flat, "the control failed: the family prompt no longer teaches facts"
    for stale in ("must also set that case's `status`", "serves NO comments"):
        assert stale not in flat, (
            f"the family prompt still teaches the removed release rule ({stale!r})"
        )

"""#934 — the fork shape §Sibling-fork uniqueness now asks for stays writable.

The SKILL used to demand a **topological** difference between sibling hypotheses
(`parent_type`/`parent_class`/`attached_to`/`rel`) while its own worked example forked on
the `?name` and the predictions alone. Agents resolved the contradiction by manufacturing a
class tuple: every tuple-class sibling pair in the corpus differed in all three slots, so a
CMDB row placing the source refuted a story about *rate* and the true world — internal AND
brute-force — was never a cell in the model.

The rewrite makes the predicted observable the distinctness axis and leaves the slots the
alert has not settled `??`, which means two live siblings now legitimately share
`parent_class`. Nothing in `validate.py` refuses that today; these pin that it stays so,
because rule #23 (fork distinctness, #933) is queued for implementation and the classification
-keyed spelling it is specified under would refuse exactly this document.
"""

from __future__ import annotations

from defender.skills.invlang.parser import parse_dense_companion
from defender.skills.invlang.validate import validate_companion

#: Siblings that share every topological column and an OPEN `parent_class`, forking on one
#: predicted observable apiece — the cadence a single lead over the failure series splits.
_OPEN_TUPLE_FORK = """\
```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|compute|ip-only/??/??|172.18.0.15|knowledge=partial

:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]
h-001|?credential-guessing|v-001|runs_on|compute|??/??/??||null|active
h-002|?scheduled-service-retry|v-001|runs_on|compute|??/??/??||null|active

:H h-001.preds [id|subject|claim]
p1|proposed_edge|"failures arrive in bursts, no fixed interval between them"

:H h-002.preds [id|subject|claim]
p1|proposed_edge|"failures repeat on a fixed interval"
```
"""

#: The same fork closing `benign`: the source's own class cell is resolved by the lead, and
#: the two proposed parents stay `??`. A proposed parent is not an observed vertex, so its
#: open slot must not reach the benign gate — the SKILL says so under §Open questions, and a
#: run that had to name one to close would be back to minting tuples.
_BENIGN_CLOSE_OVER_OPEN_PARENTS = """\
```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|compute|ip-only/??/??|172.18.0.15|knowledge=partial

:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]
h-001|?credential-guessing|v-001|runs_on|compute|??/??/??||null|active
h-002|?scheduled-service-retry|v-001|runs_on|compute|??/??/??||null|active

:H h-001.preds [id|subject|claim]
p1|proposed_edge|"failures arrive in bursts, no fixed interval between them"

:H h-002.preds [id|subject|claim]
p1|proposed_edge|"failures repeat on a fixed interval"

:L findings [id|loop|name|target|tests|system|window]
l-001|1|cmdb-source-lookup|v-001|h-001,h-002|cmdb|n/a

:R attr_updates [resolved_by|target|key|value]
l-001|v-001|class|monitoring/internal/known-corp
l-001|v-001|attrs.knowledge|full

:T conclude
termination.category   adversarial-refuted
disposition            benign
impact_verdict         none
confidence             high
matched_archetype      scheduled-service-retry
summary                "Failure series is the documented monitoring probe's fixed-interval retry"
```
"""


def test_siblings_sharing_an_open_parent_class_parse_and_validate_clean() -> None:
    _body, warnings = parse_dense_companion(_OPEN_TUPLE_FORK)
    assert warnings == []
    assert validate_companion(_OPEN_TUPLE_FORK, None) == []


def _blocked(doc: str) -> list[str]:
    return [str(e) for e in validate_companion(doc, None) if "disposition benign blocked" in str(e)]


def test_an_open_proposed_parent_does_not_block_a_benign_close() -> None:
    assert _blocked(_BENIGN_CLOSE_OVER_OPEN_PARENTS) == []


def test_the_benign_gate_is_live_on_that_document() -> None:
    """The control that keeps the pass above from being vacuous.

    Drop the one `:R attr_updates` row and the SAME document blocks — so the gate does walk
    this shape, and the clean result above is the proposed parents being out of its scope
    rather than the check never running.
    """
    control = _BENIGN_CLOSE_OVER_OPEN_PARENTS.replace(
        "l-001|v-001|class|monitoring/internal/known-corp\n", ""
    )
    blocked = _blocked(control)
    assert len(blocked) == 1
    assert "vertex v-001" in blocked[0]

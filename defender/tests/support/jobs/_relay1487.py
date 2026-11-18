"""#1487 sketch: the learning store reached from a job container through its helper (design r1, D1 (a) staged findings,
D2 adopted, D3 accepted with the helper's own settings).

Picked names (not settled by the design; each is a forced choice the sketch reports):

- the hand-in is one request `findings.publish(channels={<channel name>: [rows]})`, the channel names the episode
  sink's (`findings`, `questioner_findings`); its answer is `{"outcome": "published", "counts": {<store kind>: n}}` or
  `{"outcome": "refused", "reason": <text>}`;
- the store relay's client is `JobContainer.store()`: the store's synchronous face over the job socket (one request
  `store.<verb>` per call), raising the store's own exceptions for its typed refusals and `job_socket.Refused` for the
  helper's (`not-for-kind`, `signalled`);
- a staged item is listed by `work(tenant, statuses=["staged"])` and by no other view (`lane_work`, `claim`);
- the worker's end write carries the helper's outcome as `finish_learning_job(..., publish_state=)`; a staged row is
  inserted by `publish_findings(..., staged=True)`.

Nothing here implements the relay: helpers build rows the channel rules admit today and open the client by its name."""
from __future__ import annotations

from typing import Any

from defender.tests.support.learning.curation._drain719 import finding_row
from defender.tests.support.learning.curation._spec773 import world_row

#: The episode sink's channel names (`learning.core.state.FINDINGS`, `QUESTIONER_FINDINGS`) and each one's store kind.
FINDINGS, QUESTIONER = "findings", "questioner_findings"
KIND = {FINDINGS: "finding", QUESTIONER: "questioner_finding"}
_ANCHORED = {"subject_anchor": "the lead", "subject_topic": "the lead was never revisited"}


def defender_row(job_id: str, n: int = 0, **extra: Any) -> dict[str, Any]:
    """A held defender finding of the job's episode, as the judge leaves it: its id `<episode>/<world>/<draw>/<index>`."""
    return finding_row(f"{job_id}/w-b/0/{n}", run_id=job_id, subject="defender", **{**_ANCHORED, **extra})


def world_finding_row(job_id: str, n: int = 0, **extra: Any) -> dict[str, Any]:
    """A held questioner (world) finding of the job's episode."""
    return world_row(f"{job_id}/w-c/0/{n}", run_id=job_id, direction="world", type="mislabelled",
                     citations=["family.yaml#worlds"], **{**_ANCHORED, **extra})


def admitted(rows: dict[str, list[dict[str, Any]]]) -> None:
    """Premise: every row passes its channel's rule today (`judge.enqueue`), so a refusal is the helper's own."""
    from defender.learning.judge.enqueue import _validate_row, _validate_world_row

    for row in rows.get(FINDINGS, ()):
        _validate_row(row)
    for row in rows.get(QUESTIONER, ()):
        _validate_world_row(row)


def relay_store(container: Any, tenant: str) -> Any:
    """The store relay's client inside a job container stand-in (`_job_helper.Container`): `JobContainer` over the
    container's own socket (its `request` is the client's `ask`), then `.store()`."""
    from defender.learning.branch.container import JobContainer

    return JobContainer.connect(container.request, tenant=tenant).store()

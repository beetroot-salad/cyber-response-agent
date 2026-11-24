"""#1546 design r10 (c), owner decision H3: the drain container pulls and unpacks its own inputs; the helper pulls, parses
and unpacks nothing for it. Driven through the real helper (`job_host.main`, kind `drain`) over the real store and key login,
with the real drain entry (`learning.branch.drain_job.main`, its tick a recording seam) as the container's process.

The tick's own rules over the root it is handed (the run in the set served, the dead and the waiting) are
`learning/test_1546_drain_tick.py`'s; the drain's verbs (its pull allowed, `out_of_claim` outside its set) are
`test_job_helper_learning.py`'s."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

from defender.tests.support.evidence._evidence1546 import evidence_keys, garage  # noqa: F401 — fixtures
from defender.tests.support.jobs import _helper_evidence1546 as H
from defender.tests.support.jobs import _job_helper as J
from defender.tests.support.jobs._container_entry1170 import in_container_environment
from defender.tests.support.jobs._evidence_flows1546 import pack
from defender.tests.support.shared._openbao1163 import openbao  # noqa: F401 — fixture

evidence_store = H.evidence_store
process_state = J.process_state
scene = H.fresh_scene

pytestmark = [pytest.mark.postgres, pytest.mark.openbao, pytest.mark.garage,
              pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux only")]

#: The tick's status, distinct from 0 so the staged result is seen to be the tick's.
TICK_STATUS = 3


def _files(folder: Path) -> dict[str, bytes]:
    return {str(p.relative_to(folder)): p.read_bytes() for p in sorted(folder.rglob("*"))
            if p.is_file() and not p.is_symlink()} if folder.is_dir() else {}


def test_1546_r10_the_drain_helper_unpacks_nothing_and_the_container_pulls_and_unpacks_its_input_set(scene, evidence_store):
    """A drain claim over four in-set bundles: `first` and `second` (each its run folder, a session store at the same path
    with different bytes, and its own root `scrub-findings.json`), `broken` (stored bytes that are no bundle) and `absent`
    (nothing stored: its pull is refused). At the container's start the helper has placed no file in the drain's root or
    inputs (it unpacks nothing), and the launch facts name the claim's input set (`input_set`). By the tick, the drain entry
    has pulled and unpacked the set into `<root>/<T>/`: both runs are there; the clashing session store is `first`'s (the
    first placed is kept); no bundle's root `scrub-findings.json` was merged; `broken` and `absent` left nothing (a member
    whose pull or unpack fails is left out). The tick's status is the drain's staged `result` (control: the entry got past
    its unpack to the tick). (r10 (c) "The drain's inputs", H3; (f) 5)"""
    from defender.learning.branch import drain_job

    from defender.tests.support.shared._postgres1339 import execute

    owners = {name: H._make_investigation(scene)[0] for name in ("first", "second", "broken", "absent")}  # noqa: SLF001
    for owner in owners.values():  # finished runs, as a curation request's are (`plant`'s learning source)
        execute(scene.dsn, "UPDATE jobs.investigations SET stage = 'completed', disposition = 'benign', finished_at = now(), "
                           "evidence_state = 'complete', scrub = 'clean' WHERE id = %s", (owner,))
    clash = "sessions/clash.db"
    bundles = {
        "first": pack({f"runs/{owners['first']}/report.md": b"first's run\n", clash: b"first's store",
                       "scrub-findings.json": json.dumps({"findings": [], "of": "first"}).encode()}),
        "second": pack({f"runs/{owners['second']}/report.md": b"second's run\n", clash: b"second's store",
                        "scrub-findings.json": json.dumps({"findings": [], "of": "second"}).encode()}),
        "broken": b"these bytes are not a bundle",
    }
    for name, data in bundles.items():
        evidence_store.plant_accepted(scene, scene.tenant, owners[name], "bundle", data)
    in_set = [{"owner": owners[n], "object": "bundle"} for n in ("first", "second", "broken", "absent")]
    planted = H.plant(scene, "drain", inputs=in_set)
    root, inputs = H.job_root(scene), H.job_inputs(scene)
    seen: dict[str, Any] = {}

    def tick(_paths: Any, *, store: Any, runs: Any, unusable: Any) -> int:
        seen["at_tick"] = _files(root / scene.tenant)
        return TICK_STATUS

    def job(c) -> int:
        seen["at_start"] = {**_files(root), **_files(inputs)}
        seen["launch"] = c.request("launch")
        with in_container_environment(c.env):
            try:
                return int(drain_job.main(["--job", planted.owner, "--tenant", scene.tenant], tick=tick, environ=c.env))
            except SystemExit as stop:
                seen["exit"] = stop
                return 1

    H.drive(scene, planted, job, **evidence_store.seams)

    assert seen["at_start"] == {}, f"the helper placed files in the drain's root or inputs: {sorted(seen['at_start'])}"
    named = sorted((i.get("owner"), i.get("object")) for i in seen["launch"].get("input_set") or [])
    assert named == sorted((i["owner"], i["object"]) for i in in_set), f"the launch facts' input set: {seen['launch']}"
    assert "at_tick" in seen, f"the drain entry never reached its tick: {seen.get('exit')}"
    placed = seen["at_tick"]
    for name in ("first", "second"):
        assert placed.get(f"runs/{owners[name]}/report.md") == f"{name}'s run\n".encode(), (name, sorted(placed))
    assert placed.get(clash) == b"first's store", "on a clash the first file placed is not the one kept"
    assert "scrub-findings.json" not in placed, "a bundle's root `scrub-findings.json` was merged"
    for name in ("broken", "absent"):
        assert not [k for k in placed if owners[name] in k], f"the failed member `{name}` left files: {sorted(placed)}"
    assert H.facts(scene.dsn, scene.claim).get("result") == TICK_STATUS, H.facts(scene.dsn, scene.claim)

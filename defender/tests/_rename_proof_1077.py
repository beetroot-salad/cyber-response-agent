"""The archive round trip, addressed ONLY through the owners' accessors (#1077 D7).

NOT A TEST MODULE (the leading underscore keeps pytest from collecting it). It is the payload
`test_1077_rename_proof.py` runs in a subprocess, against a tree whose owner modules have had
every record name rewritten to something else.

Nothing in this file spells a record name, so it keeps working under any rename. Any module it
drives that DOES spell one stops finding its file — which is the whole point: the gate proves
no module SAYS a name, and this proves no module NEEDS to.

Run as `python -m defender.tests._rename_proof_1077 <work dir>`.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from defender._episode_paths import LAYOUT, EpisodePaths
from defender._io import bind
from defender._run_paths import RunPaths


def main(root: Path) -> int:
    episode_dir = root / "ep"
    run_dir = root / "runs" / "src-b"
    run = RunPaths(run_dir)
    run_dir.mkdir(parents=True)

    # Write one of everything the archive projects, each at the accessor that names it.
    run.report.write_text("---\ndisposition: benign\n---\n\nbody\n", encoding="utf-8")
    run.investigation.write_text("# investigation\n", encoding="utf-8")
    run.provenance.write_text(json.dumps({"commit": "abc"}), encoding="utf-8")
    run.alert.write_text(json.dumps({"alert_id": "a1", "rule": {"name": "r"}}), encoding="utf-8")
    run.lessons_loaded.write_text(json.dumps({"kind": "read"}) + "\n", encoding="utf-8")
    run.executed_queries.write_text(json.dumps({"query_id": "q1"}) + "\n", encoding="utf-8")
    run.gather_raw.mkdir(parents=True, exist_ok=True)
    run.gather_summaries.mkdir(parents=True, exist_ok=True)
    run.gather_summary("l-001").write_text("summary of l-001\n", encoding="utf-8")

    from defender.learning.branch.archive import archive_episode

    episode_dir.mkdir(parents=True)
    archived = archive_episode(episode_dir, {"b": run_dir})
    assert set(archived) == {"b"}, archived

    world = EpisodePaths(episode_dir).world("b")

    # THE ROUND TRIP: every record the archive projected, read back through the accessor that
    # names it — never a path this script composed.
    for label, path, want in (
        ("report", world.report, "body"),
        ("investigation", world.investigation, "# investigation"),
        ("provenance", world.provenance, "abc"),
        ("alert", world.alert, "a1"),
        ("lessons_loaded", world.lessons_loaded, "read"),
        ("gather_summary", world.gather_summaries / "l-001.md", "summary of l-001"),
    ):
        assert path.is_file(), f"{label}: the archive wrote nothing at {path}"
        assert want in path.read_text(encoding="utf-8"), f"{label}: wrong bytes at {path}"

    assert world.run_dir_pointer.is_file(), "no run-dir pointer"
    assert str(run_dir) in world.run_dir_pointer.read_text(encoding="utf-8")

    # And through the BOUND readers, which address by the owner's RELATIVE form — the half of
    # the tree the gate was blind to before D7, because a relative name carries no root a
    # dataflow pass can trace.
    with bind(episode_dir) as bound:
        rec = bound.read(LAYOUT.world("b").report)
        assert rec.text is not None, f"bound read of the report failed: {rec.reason}"
        assert "body" in rec.text, "the bound read returned the wrong bytes"
        summaries = bound.under(LAYOUT.world("b").gather_summaries).entries()
        assert summaries.files() == ["l-001.md"], summaries.files()

    from defender.learning.judge import family

    with bind(episode_dir) as bound:
        read = family.read_archived_report(bound, LAYOUT.world("b").report)
        assert read.disposition == "benign", f"the judge read no disposition: {read.reason}"

    # Say which tree this actually loaded. `python -m` puts the CWD first on
    # `sys.path`, so a harness that sets only PYTHONPATH silently drives the real
    # package and passes while exercising nothing — the failure mode this whole
    # file exists to rule out, so the caller is given the evidence to check.
    print(f"ALERT_NAME={run.alert.name}")
    print("ROUNDTRIP OK")
    return 0


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1])))

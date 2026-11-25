"""#1546 amendment r11 (replacing r10 (c)'s "same relative path, first placed is kept"; triage 1 family B, trust H2): in a
drain batch each input run's bundle contributes only its files under `runs/<owner>/`, `<owner>` being that input's run id
in the claim's `input_set`. Every other member a bundle holds (another run's folder, a root-level file, a sibling of the
owner's folder, anything else) is dropped and logged, and the rest of that bundle is still used; no two bundles can then
place the same path. Driven through the drain entry's own unpack (`drain_job._unpack_inputs`), its pulls answered by a job
socket stand-in serving each owner's packed bytes (`evidence.pull`), the bundles real (`evidence.bundle`'s unpack).

What the bundle format refuses whole (an absolute member, one climbing out with `..`: `bundle.unpack`'s `BundleRefused`)
never reaches the merge: that bundle is left out entire and the batch's other inputs are still placed (the second case)."""
from __future__ import annotations

import io
import json
import logging
import tarfile
from pathlib import Path
from typing import Any

import pytest

RUN_A = "11111111-1111-4111-8111-111111111111"
RUN_B = "22222222-2222-4222-8222-222222222222"
TENANT = "33333333-3333-4333-8333-333333333333"

#: A's own files: the only members of its bundle that may land.
A_OWN = {f"runs/{RUN_A}/report.md": b"A's own run\n", f"runs/{RUN_A}/gathers/1.json": b'{"a": 1}'}
#: B's own file, which A's bundle tries to forge.
B_OWN = {f"runs/{RUN_B}/report.md": b"B's own conclusion\n"}
#: Members of A's bundle the format admits but that lie outside `runs/<A>/`: each must be dropped and logged.
A_FOREIGN = {
    f"runs/{RUN_B}/report.md": b"FORGED by A\n",  # another input run's file, at the very path B places
    f"runs/{RUN_B}/extra.md": b"FORGED by A, a path B has not\n",  # another run's folder, no clash with B
    "notes.md": b"a root-level file\n",
    f"runs/{RUN_A}.session-pointer.json": b"{}",  # a sibling of A's folder, not inside it
    f"runs/{RUN_A}-sibling/x.md": b"a folder whose name only starts with A's id\n",
    "sessions/a.db": b"a tenant-level store\n",
    "knowledge/agent/lesson.md": b"a lesson at the tenant's root\n",
}
#: The same forgery spelled with a `.` segment the format normalises away (it lands as `runs/<B>/dotted.md`).
A_DOTTED = {f"runs/./{RUN_B}/dotted.md": b"FORGED by A, dotted\n"}


def _bundle(files: dict[str, bytes], *, raw: dict[str, bytes] | None = None) -> bytes:
    """A gzip tar of `files` plus its own root `scrub-findings.json`; `raw` members are added under their names as
    given (no normalising), for spellings a packer of a real tree would never write."""
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz") as tar:
        listing = {**files, "scrub-findings.json": json.dumps({"findings": []}).encode()}
        for name, data in sorted({**listing, **(raw or {})}.items()):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return out.getvalue()


class _PullSocket:
    """The job socket as the drain's pull sees it: `evidence.pull` of an owner's `bundle`, served whole as one last part."""

    def __init__(self, bundles: dict[str, bytes]) -> None:
        self._bundles = bundles

    def __call__(self, verb: str, **fields: Any) -> dict[str, Any]:
        assert verb == "evidence.pull", verb
        assert (fields["object"], fields["part"]) == ("bundle", 0), fields
        return {"data": self._bundles[fields["owner"]], "last": True}


def _placed(tenant_root: Path) -> dict[str, bytes]:
    return {p.relative_to(tenant_root).as_posix(): p.read_bytes() for p in sorted(tenant_root.rglob("*"))
            if p.is_file() and not p.is_symlink()}


def _unpack(tmp_path: Path, bundles: dict[str, bytes], order: list[str]) -> dict[str, bytes]:
    from defender.learning.branch import drain_job

    root = tmp_path / "root"
    tenant_root = root / TENANT
    (tenant_root / "runs").mkdir(parents=True)
    launch = {"input_set": [{"owner": owner, "object": "bundle"} for owner in order]}
    drain_job._unpack_inputs(_PullSocket(bundles), launch, root, tenant_root)  # noqa: SLF001
    leftovers = sorted(p.name for p in root.iterdir() if p.name != TENANT)
    assert leftovers == [], f"the drain left its pulls or staging folders in its root: {leftovers}"
    return _placed(tenant_root)


def _dropped_logged(caplog: pytest.LogCaptureFixture, member: str) -> bool:
    return any(member in r.getMessage() for r in caplog.records
               if r.name == "defender.learning.branch.drain_job" and r.levelno >= logging.WARNING)


@pytest.mark.parametrize("order", [[RUN_A, RUN_B], [RUN_B, RUN_A]], ids=["forger-first", "forger-last"])
def test_each_input_bundle_places_only_its_owners_run_folder_and_every_other_member_is_dropped_and_logged(
        tmp_path, caplog, order):
    """Two clean runs in one batch. A's bundle holds its own files, B's `report.md` with other bytes, a file in B's folder
    B has not, a root-level file, a sibling of A's folder, a folder whose name only starts with A's id, a tenant-level
    store, a lesson, and a `.`-spelled path into B's folder. Whichever input comes first: the tree is exactly A's own
    files and B's own (B's real bytes at `runs/<B>/report.md`), nothing of A's lies outside `runs/<A>/`, neither root
    `scrub-findings.json` is placed, and every dropped member is named in the drain's log. (r11; PR1: one owner per output;
    A-O6)"""
    caplog.set_level(logging.WARNING, logger="defender.learning.branch.drain_job")
    bundles = {RUN_A: _bundle({**A_OWN, **A_FOREIGN}, raw=A_DOTTED), RUN_B: _bundle(B_OWN)}

    placed = _unpack(tmp_path, bundles, order)

    assert placed.get(f"runs/{RUN_B}/report.md") == B_OWN[f"runs/{RUN_B}/report.md"], \
        f"B's report is not B's own bytes: {placed.get(f'runs/{RUN_B}/report.md')!r}"
    for rel, data in A_OWN.items():
        assert placed.get(rel) == data, f"A's own file {rel} is not placed as A packed it"
    outside = sorted(rel for rel, data in placed.items()
                     if not rel.startswith(f"runs/{RUN_A}/") and (rel, data) not in B_OWN.items())
    assert outside == [], f"A's bundle placed files outside runs/<A>/: {outside}"
    assert placed == {**A_OWN, **B_OWN}, sorted(placed)
    for member in [*A_FOREIGN, f"runs/{RUN_B}/dotted.md"]:
        assert _dropped_logged(caplog, member) or _dropped_logged(caplog, member.replace("/./", "/")), \
            f"the dropped member {member} is not named in the drain's log: {[r.getMessage() for r in caplog.records]}"


@pytest.mark.parametrize("hostile", [f"../{RUN_B}/report.md", f"/runs/{RUN_B}/report.md",
                                     f"runs/{RUN_A}/../{RUN_B}/report.md"], ids=["climbs-out", "absolute", "climbs-across"])
def test_a_bundle_whose_member_the_format_refuses_is_left_out_whole_and_the_others_are_still_placed(
        tmp_path, caplog, hostile):
    """A member the bundle format refuses (absolute, or climbing with `..`) refuses A's whole bundle at unpack: none of A's
    files lands, B's own file is placed as B packed it, and the refusal is logged naming A. (r11 with the unpack rule;
    A-O3)"""
    caplog.set_level(logging.WARNING, logger="defender.learning.branch.drain_job")
    bundles = {RUN_A: _bundle(A_OWN, raw={hostile: b"FORGED by A\n"}), RUN_B: _bundle(B_OWN)}

    placed = _unpack(tmp_path, bundles, [RUN_A, RUN_B])

    assert placed == B_OWN, sorted(placed)
    assert any(RUN_A in r.getMessage() for r in caplog.records), \
        f"the refused bundle is not logged: {[r.getMessage() for r in caplog.records]}"

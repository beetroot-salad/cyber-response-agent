"""#1105 PR 1 — the episode -> runs record (D3; amendment A and B; MF-12, MF-16, MF-22 reading B;
P2; NM-02, NM-04; OQ-5 (a)).

The record is `tenant.runs/_episodes/<episode_id>.json`, host-only, beside `_tenant.json`:
exactly `{episode_id, tenant_id, source_run_id, runs: {label: run_id}}`, run ids stored as
`RunId` text, at most 64 KiB (65536 bytes), in ONE canonical sorted-key serialisation. PR 1 has
no production writer (the launcher's write is PR 2's, D3.8), so every record here is written by
the test: through the writer where the demand says so, by hand (a host-written record) where it
pins the reader.

The interfaces this file drives (design D3; the injected seam is `_spec1105`'s `io=`):

    record_episode_runs(tenant, episode_id, source_run_id: RunId,
                        runs: Mapping[str, RunId], *, io=) -> None
    episode_runs(tenant, episode_id, *, io=) -> dict[str, RunId]
    sibling_run_ids(tenant, *, io=) -> set[RunId]
    episode_sibling_ids(runs: Bound) -> set[RunId]          # amendment B: a Bound, not a path

The writer refuses an arm whose name in the held listing already holds a run or a sidecar, so a
test that needs both a record and its arms' folders writes the record FIRST.

The reader's rule is D3.4's closed list (MF-12 reading A): an entry of `_episodes` is a regular
file named `<grammar-valid episode id>.json`, read no-follow and capped at 65536 bytes, strict
UTF-8 JSON with exactly the four fields, `tenant_id == tenant.id` (the tenant-keyed readers
only), `episode_id ==` the file name minus its final `.json` (MF-22), and run ids `RunId.parse`
admits. Anything else refuses with `RunRefused` naming it (P2) — a torn record fails closed until
an operator removes it, and a stray name in `_episodes` refuses rather than being ignored.

Red at base 80888efb: every test imports what it drives from `defender.run_repository`, which
does not exist, so each fails at its own import (`ModuleNotFoundError`).
"""
from __future__ import annotations

import json
import os
import threading
import time
import types
from collections import OrderedDict
from collections.abc import Iterator, Mapping
from pathlib import Path

from defender import _io, run_common
from defender._tenant import TenantRefused
from defender.runtime.branch._family import FamilyError
from defender.tests.tenant_1105_run_repository import _spec1105 as H


def _setup(tmp_path: Path, tenant_id: str = H.T_ID, root: Path | None = None):
    """An accepted tenant whose runs folder is a real folder holding its own `_tenant.json`."""
    t = H.tenant(root if root is not None else tmp_path / "data", tenant_id)
    return t, H.runs_folder(t)


def _ids(*texts: str) -> list:
    """`RunId.parse` of each text, in order."""
    from defender.run_repository import RunId

    return [RunId.parse(x) for x in texts]


def _rid(text: str):
    from defender.run_repository import RunId

    return RunId.parse(text)


def _listed(t) -> list:
    """`t.runs_repository().list()`'s ids (PR 1's `list_run_ids(t)`), as a list."""
    return list(t.runs_repository().list())


def _record(runs: Path, episode_id: str) -> Path:
    return Path(runs) / "_episodes" / f"{episode_id}.json"


def _padded(text: str, size: int) -> str:
    """`text` (one JSON document) padded with trailing JSON whitespace to exactly `size` bytes."""
    return text + " " * (size - len(text.encode("utf-8")))


def _cap_arms(n: int) -> dict:
    """`n` arms of episode 'cap', each label 40 characters (the writer's cap calibration)."""
    return {f"l{i:04d}{'x' * 35}": _rid(f"cap-l{i:04d}{'x' * 35}") for i in range(n)}


def _cap_size(t, runs: Path, arms: int, source: str) -> int | None:
    """The size the writer gives episode 'cap' with `arms` arms and source `source`, or None if
    it wrote no record; the record is removed again (the writer's state is the file)."""
    from defender.run_repository import record_episode_runs

    record_episode_runs(t, "cap", _rid(source), _cap_arms(arms))
    path = _record(runs, "cap")
    if not path.is_file():
        return None
    size = path.stat().st_size
    path.unlink()
    return size


class _Sub(str):
    """A plain `str` subclass: the same characters, a type that is not exactly `str` (FR-12)."""


class _FormatsAs(str):
    """A `str` subclass whose text is `data` but which formats as `shown` (RG-F3-b): the lying
    input FR-12 makes the writer refuse by type. It only returns values."""

    shown: str

    def __new__(cls, data: str, shown: str) -> _FormatsAs:
        obj = super().__new__(cls, data)
        obj.shown = shown
        return obj

    def __format__(self, spec: str) -> str:
        return self.shown


class _SecondViewDiffers(Mapping):
    """A runs mapping that lies (NM-02 A, RA15): its first iteration, and every lookup made
    before a second one starts, answer `first`; every iteration from the second on, and the
    lookups after it, answer `later`. A real input built from plain dicts, not a fault in I/O."""

    def __init__(self, first: Mapping, later: Mapping) -> None:
        self._first, self._later = dict(first), dict(later)
        self._active = self._first
        self.iterations = 0

    def __iter__(self) -> Iterator:
        self.iterations += 1
        if self.iterations > 1:
            self._active = self._later
        return iter(list(self._active))

    def __getitem__(self, key):
        return self._active[key]

    def __len__(self) -> int:
        return len(self._active)


def test_1105_record_episode_runs_writes_exactly_the_four_field_record_beside_the_tenant_record(
        tmp_path):
    """record_episode_runs(tenant, 'src-n1', RunId.parse('src'), {'a': RunId.parse('src-n1-a')})
    returns None and writes tenant.runs/_episodes/src-n1.json, a regular file beside _tenant.json
    (creating _episodes/ when it is absent), which episode_runs and sibling_run_ids then read
    back; a second episode's record lands beside the first, which is unchanged."""
    from defender.run_repository import episode_runs, record_episode_runs, sibling_run_ids

    t, runs = _setup(tmp_path)
    assert not (runs / "_episodes").exists(), "the fixture starts with no _episodes/"
    result = record_episode_runs(t, "src-n1", _rid("src"), {"a": _rid("src-n1-a")})
    assert result is None, f"record_episode_runs returns None, got {result!r}"
    first = _record(runs, "src-n1")
    assert first.is_file(), f"no record at {first}"
    assert not first.is_symlink(), f"no record at {first}"
    assert first.parent.parent == runs, "the record folder sits beside _tenant.json, in tenant.runs itself"
    assert (runs / "_tenant.json").is_file(), "the record folder sits beside _tenant.json, in tenant.runs itself"
    assert (runs / "_episodes").is_dir(), "_episodes/ was created as a real folder inside tenant.runs"
    assert not (runs / "_episodes").is_symlink(), "_episodes/ was created as a real folder inside tenant.runs"
    assert episode_runs(t, "src-n1") == {"a": _rid("src-n1-a")}, "episode_runs reads it back"
    assert sibling_run_ids(t) == {_rid("src-n1-a")}, "sibling_run_ids reads it back"
    first_bytes = first.read_bytes()
    record_episode_runs(t, "src-n2", _rid("src"), {"b": _rid("src-n2-b")})
    second = _record(runs, "src-n2")
    assert second.is_file(), f"the second episode's record did not land at {second}"
    assert first.read_bytes() == first_bytes, "the first record changed when a second landed"
    names = sorted(p.name for p in (runs / "_episodes").iterdir())
    assert names == ["src-n1.json", "src-n2.json"], f"two records side by side: {names}"
    assert sibling_run_ids(t) == {_rid("src-n1-a"), _rid("src-n2-b")}, "both records claim"


def test_1105_the_writer_refuses_an_unchecked_runs_folder_and_creates_only_episodes_inside_a_checked_one(
        tmp_path):
    """record_episode_runs raises TenantRefused and creates nothing when tenant.runs is absent and
    when its _tenant.json names another tenant; it never creates the runs folder or _tenant.json
    (ensure_runs_base_record stays that record's one writer). Positive control: over a checked
    folder with no _episodes/ it creates _episodes/ inside the held folder and writes the record;
    after run setup makes the folder and record for a tenant that had none, the same call
    succeeds."""
    from defender.run_repository import record_episode_runs

    root = tmp_path / "data"
    t = H.tenant(root, H.T_ID)
    before = H.tree_state(root)
    err = H.raised(record_episode_runs, t, "ep", _rid("src"), {"a": _rid("ep-a")})
    assert H.is_a(err, TenantRefused), f"an absent runs folder gave {err!r}, not TenantRefused"
    assert str(t.runs) in H.message(err), f"the refusal names tenant.runs: {H.message(err)!r}"
    assert not os.path.lexists(t.runs), "the writer created the runs folder"
    assert H.tree_state(root) == before, "the refused writer created something"

    record = H.plant_tenant_record(t.runs, H.U_ID)
    foreign = record.read_bytes()
    before = H.tree_state(root)
    err = H.raised(record_episode_runs, t, "ep", _rid("src"), {"a": _rid("ep-a")})
    assert H.is_a(err, TenantRefused), f"a record naming another tenant gave {err!r}"
    assert str(record) in H.message(err), f"the refusal names the record: {H.message(err)!r}"
    assert record.read_bytes() == foreign, "the writer touched _tenant.json"
    assert not (t.runs / "_episodes").exists(), "_episodes/ was created over a foreign record"
    assert H.tree_state(root) == before, "the refused writer created something"

    H.plant_tenant_record(t.runs, t.id)
    record_episode_runs(t, "ep", _rid("src"), {"a": _rid("ep-a")})
    assert _record(t.runs, "ep").is_file(), "over a checked folder the record is written"
    assert (t.runs / "_episodes").is_dir()
    assert not (t.runs / "_episodes").is_symlink()

    u = H.tenant(root, H.U_ID)
    err = H.raised(record_episode_runs, u, "ep", _rid("r1"), {"a": _rid("ep-a")})
    assert H.is_a(err, TenantRefused), f"U with no runs folder gave {err!r}"
    run_common.materialize_run(H.alert_file(tmp_path / "alerts"), "r1", tenant=u)
    assert (u.runs / "_tenant.json").is_file(), "run setup wrote U's record"
    record_episode_runs(u, "ep", _rid("r1"), {"a": _rid("ep-a")})
    assert _record(u.runs, "ep").is_file(), "after run setup the writer succeeds for U"


def test_1105_a_bad_episode_id_is_refused_as_run_refused_before_any_name_is_built(tmp_path):
    """record_episode_runs and episode_runs raise RunRefused, not FamilyError, for an episode id
    refuse_bad_episode_id refuses ('../x', 'a/b', '', '_x', 'Ep1', 5), write nothing, and do so
    even over an absent runs folder (the id is judged before any name is built or folder read);
    episode_runs refuses an episode id whose record name would pass 255 bytes the same way,
    without probing the disk (NM-02). Observed through the injected seam: no call reaches it."""
    from defender.run_repository import RunRefused, episode_runs, record_episode_runs

    root = tmp_path / "data"
    t = H.tenant(root, H.T_ID)  # no runs folder: a folder read would answer TenantRefused / {}
    before = H.tree_state(root)
    for bad in ("../x", "a/b", "", "_x", "Ep1", 5):
        for name, call in (
                ("record_episode_runs",
                 lambda io, b=bad: record_episode_runs(t, b, _rid("src"), {"a": _rid("src-a")},
                                                       io=io)),
                ("episode_runs", lambda io, b=bad: episode_runs(t, b, io=io))):
            rec = H.RecordingIO()
            err = H.raised(call, rec)
            assert H.is_a(err, RunRefused), f"{name}({bad!r}) gave {err!r}, not RunRefused"
            assert not isinstance(err, FamilyError), f"{name}({bad!r}) leaked FamilyError"
            assert rec.calls == [], f"{name}({bad!r}) reached the seam first: {rec.calls}"
    over = "e" * 251  # admitted by refuse_bad_episode_id; '<id>.json' is 256 bytes
    rec = H.RecordingIO()
    err = H.raised(episode_runs, t, over, io=rec)
    assert H.is_a(err, RunRefused), f"a 256-byte record name gave {err!r}, not RunRefused"
    assert rec.calls == [], f"the over-long record name was probed: {rec.calls}"
    assert episode_runs(t, "e" * 250) == {}, (
        "positive control: a 255-byte record name over an absent folder is the expected empty "
        "answer")
    assert H.tree_state(root) == before, "a refused episode id wrote something"


def test_1105_the_writer_refuses_every_input_that_would_hide_a_run_or_claim_an_id_twice(tmp_path):
    """record_episode_runs raises RunRefused and writes nothing for: an empty or non-mapping runs;
    a label the family model refuses (base, family, family_1, an unnameable label, labels equal
    under case folding); an arm id ending in a sidecar suffix or other than
    f'{episode_id}-{label}'; two labels on one id; an arm equal to the source; an arm another
    record already claims, or whose name in the held listing holds a run or a sidecar file; an
    episode id whose record name would exceed 255 bytes; and content over 65536 bytes, at the
    boundary: a record whose canonical bytes are exactly 65537 is refused and one of exactly
    65536 is written (the reader's cap, D3.4). Each input
    breaks only its own rule, except three that no input can isolate, because every arm must be
    a RunId (casefold-stable, at most 206 bytes) equal to f'{episode_id}-{label}': labels equal
    under case folding and two labels on one id each also break the arm-shape rule
    (w_writer_label_rules_unreachable_for_exact_str), and so does an over-long record name
    (w_writer_record_name_bound_unreachable); a label or episode id that is not exactly str is
    refused outright (FR-12), so no lying input isolates them either; those three pin only that
    the input is refused with nothing written. A runs mapping whose second view differs from its
    first is snapshotted once: the record written is the first view's (NM-02). Positive control:
    a valid mapping is written, and a source another record claims as an arm is admitted
    (refusing a claimed source is PR 2's launcher's)."""
    from defender.run_repository import RunRefused, record_episode_runs

    t, runs = _setup(tmp_path)
    src = _rid("src")
    big = {f"l{i:03d}{'x' * 186}": _rid(f"ep-l{i:03d}{'x' * 186}") for i in range(200)}
    cases = [
        ("an empty runs", "ep", src, {}),
        ("a non-mapping runs", "ep", src, [("a", _rid("ep-a"))]),
        ("reserved label base", "ep", src, {"base": _rid("ep-base")}),
        ("reserved label family", "ep", src, {"family": _rid("ep-family")}),
        ("reserved label family_1", "ep", src, {"family_1": _rid("ep-family_1")}),
        ("an unnameable label", "ep", src, {"x-y": _rid("ep-x-y")}),
        # Multi-fault by necessity: 'ep-A' is not casefold-stable, so no RunId spells A's arm.
        ("labels equal under case folding", "ep", src, {"a": _rid("ep-a"), "A": _rid("ep-a")}),
        # A label the family model admits (no '-'), so only the sidecar clause refuses it.
        ("a sidecar-suffixed arm", "ep", src,
         {"x.accounting_failures.json": _rid("ep-x.accounting_failures.json")}),
        ("an arm not shaped episode-label", "ep", src, {"a": _rid("other")}),
        # Multi-fault by necessity: two labels give two different f'{episode_id}-{label}' arms.
        ("two labels on one id", "ep", src, {"a": _rid("ep-a"), "b": _rid("ep-a")}),
        ("an arm equal to the source", "ep", _rid("ep-a"), {"a": _rid("ep-a")}),
        # Multi-fault by necessity: a 251-byte episode id has no shaped arm of at most 206 bytes.
        ("a record name over 255 bytes", "e" * 251, src, {"a": _rid("ep-a")}),
        ("content over 65536 bytes", "ep", src, big),
    ]
    for what, episode, source, mapping in cases:
        before = H.tree_state(runs)
        err = H.raised(record_episode_runs, t, episode, source, mapping)
        assert H.is_a(err, RunRefused), f"{what}: {err!r}, not RunRefused"
        assert H.tree_state(runs) == before, f"{what}: the refused writer wrote something"

    claimer = H.plant_record(runs, "zz", t.id, "zsrc", {"a": "ep-a"})
    before = H.tree_state(runs)
    err = H.raised(record_episode_runs, t, "ep", src, {"a": _rid("ep-a")})
    assert H.is_a(err, RunRefused), f"an arm another record claims: {err!r}"
    assert H.tree_state(runs) == before, "an arm another record claims: something was written"
    claimer.unlink()
    for what, plant, remove in (
            ("an arm whose name holds a run", lambda: H.make_run(runs, "ep-a"),
             lambda p: (p / "alert.json").unlink() or p.rmdir()),
            ("an arm whose name holds a sidecar file",
             lambda: H.plant_sidecars(runs, "ep-a", staged=False),
             lambda made: [p.unlink() for p in made])):
        planted = plant()
        before = H.tree_state(runs)
        err = H.raised(record_episode_runs, t, "ep", src, {"a": _rid("ep-a")})
        assert H.is_a(err, RunRefused), f"{what}: {err!r}"
        assert H.tree_state(runs) == before, f"{what}: something was written"
        remove(planted)

    record_episode_runs(t, "ep", src, {"a": _rid("ep-a")})
    assert _record(runs, "ep").is_file(), "positive control: a valid mapping is written"

    lying = _SecondViewDiffers({"a": _rid("lie-a")}, {"base": _rid("lie-base")})
    err = H.raised(record_episode_runs, t, "lie", src, lying)
    assert err is None, (
        f"a mapping whose first view is valid was refused, so a second view was judged: {err!r}")
    written = _record(runs, "lie")
    assert written.is_file(), f"the first view was not written at {written}"
    stored = json.loads(written.read_text(encoding="utf-8"))
    assert stored == H.record_doc("lie", t.id, "src", {"a": "lie-a"}), (
        f"the record is not the first view's (iterated {lying.iterations} times): {stored}")
    lied_bytes = written.read_bytes()
    written.unlink()
    record_episode_runs(t, "lie", src, {"a": _rid("lie-a")})
    assert written.is_file(), f"a plain dict of the first view was not written at {written}"
    assert written.read_bytes() == lied_bytes, (
        "the first view's record is not the canonical bytes a plain dict of it gives")

    H.plant_record(runs, "old", t.id, "osrc", {"a": "old-a"})
    record_episode_runs(t, "new", _rid("old-a"), {"a": _rid("new-a")})
    assert _record(runs, "new").is_file(), (
        "a source another record claims as an arm is admitted (PR 2's launcher refuses it)")

    # The cap at its boundary. The writer's canonical form is its own (sorted keys; the
    # separators are not pinned), so measure it: per arm, and per byte of the source's text.
    one, two = _cap_size(t, runs, 1, "c"), _cap_size(t, runs, 2, "c")
    assert one is not None, "a valid one-arm record was not written"
    assert two is not None, "a valid two-arm record was not written"
    per_arm = two - one
    arms = (H.RECORD_CAP - 60 - one) // per_arm + 1
    base, longer = _cap_size(t, runs, arms, "c"), _cap_size(t, runs, arms, "c0")
    assert base == one + (arms - 1) * per_arm, (
        f"the writer's size is not linear in its arms ({one}, {two}, {base} for {arms})")
    assert longer == base + 1, f"one more byte of source text gave {longer} bytes, not {base + 1}"
    pad = H.RECORD_CAP - base
    assert 0 <= pad < 200, f"calibration left {pad} bytes to fill with the source's text"
    before = H.tree_state(runs)
    err = H.raised(record_episode_runs, t, "cap", _rid("c" + "0" * (pad + 1)), _cap_arms(arms))
    assert H.is_a(err, RunRefused), f"a record of exactly 65537 bytes gave {err!r}, not RunRefused"
    assert H.tree_state(runs) == before, "the refused 65537-byte record left something behind"
    record_episode_runs(t, "cap", _rid("c" + "0" * pad), _cap_arms(arms))
    path = _record(runs, "cap")
    assert path.is_file(), "a record of exactly 65536 bytes was not written"
    assert path.stat().st_size == H.RECORD_CAP, (
        f"the at-cap record is {path.stat().st_size} bytes, not {H.RECORD_CAP}")


def test_1105_the_writer_refuses_a_label_or_episode_id_that_is_not_exactly_str_before_any_write(
        tmp_path):
    """record_episode_runs refuses, with RunRefused and before any write, a label or an episode
    id whose type is not exactly str (FR-12, owner: subclasses are refused, as RunId refuses
    subclassing): a plain subclass label, a label that formats unlike its text (x shown as a,
    arm ep-a), a plain subclass episode id, and a 251-byte episode id that formats as 'ep'; and a
    label or an episode id that is no str at all, an int, bytes or None (90 F3). Each leaves the
    runs folder unchanged and _episodes not created. Positive control: the same episode id and
    mapping as exact str are written."""
    from defender.run_repository import RunRefused, record_episode_runs

    t, runs = _setup(tmp_path)
    src = _rid("src")
    episodes = runs / "_episodes"
    assert not episodes.exists(), "precondition: no _episodes yet, so a write would show"
    cases = (
        ("a str-subclass label", "ep", {_Sub("a"): _rid("ep-a")}),
        ("a label that formats unlike its text", "ep", {_FormatsAs("x", "a"): _rid("ep-a")}),
        ("a str-subclass episode id", _Sub("ep"), {"a": _rid("ep-a")}),
        ("a 251-byte episode id that formats as 'ep'", _FormatsAs("e" * 251, "ep"),
         {"a": _rid("ep-a")}),
        *((f"a {type(bad).__name__} label", "ep", {bad: _rid("ep-a")}) for bad in (5, b"a", None)),
        *((f"a {type(bad).__name__} episode id", bad, {"a": _rid("ep-a")})
          for bad in (5, b"ep", None)),
    )
    for what, episode, mapping in cases:
        before = H.tree_state(runs)
        err = H.raised(record_episode_runs, t, episode, src, mapping)
        assert H.is_a(err, RunRefused), f"{what}: {err!r}, not RunRefused (FR-12)"
        assert H.tree_state(runs) == before, f"{what}: the refused writer wrote something"
        assert not episodes.exists(), f"{what}: _episodes was created before the refusal"
    record_episode_runs(t, "ep", src, {"a": _rid("ep-a")})
    written = _record(runs, "ep")
    assert written.is_file(), f"positive control: the exact-str twin was not written at {written}"
    stored = json.loads(written.read_text(encoding="utf-8"))
    assert stored == H.record_doc("ep", t.id, "src", {"a": "ep-a"}), (
        f"positive control: the exact-str twin's record is not its labels and arms: {stored}")


def test_1105_an_episode_record_is_written_once_an_identical_retry_is_a_no_op_and_a_different_one_refused(
        tmp_path):
    """A second record_episode_runs call with byte-identical content returns without error and
    leaves the record unchanged (today's create lane raises FileExistsError there); a call for
    the same episode with different content raises RunRefused and leaves the first record
    byte-identical; a call refused before writing leaves nothing, and the next valid call for
    that episode writes (the writer's state is the file)."""
    from defender.run_repository import RunRefused, record_episode_runs

    t, runs = _setup(tmp_path)
    record_episode_runs(t, "ep", _rid("src"), {"a": _rid("ep-a")})
    path = _record(runs, "ep")
    assert path.is_file(), f"the first call wrote no record at {path}"
    first = path.read_bytes()
    err = H.raised(record_episode_runs, t, "ep", _rid("src"), {"a": _rid("ep-a")})
    assert err is None, f"a byte-identical retry is a no-op success, got {err!r}"
    assert path.read_bytes() == first, "the identical retry rewrote the record"
    for different in ((_rid("src"), {"b": _rid("ep-b")}), (_rid("src2"), {"a": _rid("ep-a")})):
        err = H.raised(record_episode_runs, t, "ep", *different)
        assert H.is_a(err, RunRefused), f"different content for the same episode gave {err!r}"
        assert str(path) in H.message(err), f"the refusal names the record: {H.message(err)!r}"
        assert path.read_bytes() == first, "a refused rewrite changed the first record"
    err = H.raised(record_episode_runs, t, "ep2", _rid("src"), {})
    assert H.is_a(err, RunRefused), f"an empty runs gave {err!r}"
    assert not _record(runs, "ep2").exists(), "a call refused before writing left a file"
    record_episode_runs(t, "ep2", _rid("src"), {"a": _rid("ep2-a")})
    assert _record(runs, "ep2").is_file(), "the next valid call for that episode writes"


def test_1105_the_writer_never_writes_through_a_link_at_episodes(tmp_path):
    """With _episodes a link to an outside folder, record_episode_runs raises RunRefused naming
    _episodes, never a raw OSError, and the outside folder is byte-unchanged (no record lands
    there). Positive control: with _episodes absent the record lands inside tenant.runs."""
    from defender.run_repository import RunRefused, record_episode_runs

    t, runs = _setup(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "victim.json").write_text('{"keep": true}\n', encoding="utf-8")
    os.symlink(outside, runs / "_episodes")
    before = H.tree_state(outside)
    err = H.raised(record_episode_runs, t, "ep", _rid("src"), {"a": _rid("ep-a")})
    assert H.is_a(err, RunRefused), f"a linked _episodes gave {err!r}, not RunRefused"
    assert not isinstance(err, OSError), f"a raw OSError escaped: {err!r}"
    assert "_episodes" in H.message(err), f"the refusal names _episodes: {H.message(err)!r}"
    assert H.tree_state(outside) == before, "something landed in the outside folder"
    assert not (outside / "ep.json").exists(), "the record was written through the link"
    (runs / "_episodes").unlink()
    record_episode_runs(t, "ep", _rid("src"), {"a": _rid("ep-a")})
    assert _record(runs, "ep").is_file(), "positive control: the record lands inside tenant.runs"
    assert not (runs / "_episodes").is_symlink(), "_episodes is a real folder"
    assert H.tree_state(outside) == before, "the outside folder changed"


def test_1105_the_writer_never_removes_a_file_it_did_not_create(tmp_path):
    """When a regular file already stands at the record name with different bytes (another key
    order included), record_episode_runs compares it, raises RunRefused naming the file, and
    leaves it byte-identical: the writer removes only what its own create made. Positive control:
    with byte-identical content the call is a no-op success."""
    from defender.run_repository import RunRefused, record_episode_runs

    t, runs = _setup(tmp_path)
    doc = H.record_doc("ep", t.id, "src", {"a": "ep-a"})
    reordered = json.dumps(dict(reversed(list(doc.items()))))  # same mapping, keys unsorted
    other = H.record_text("ep", t.id, "src", {"b": "ep-b"})
    for planted in (other, reordered):
        path = H.plant_record(runs, "ep", t.id, "src", {}, raw=planted)
        err = H.raised(record_episode_runs, t, "ep", _rid("src"), {"a": _rid("ep-a")})
        assert H.is_a(err, RunRefused), f"a different file at the record name gave {err!r}"
        assert str(path) in H.message(err), f"the refusal names the file: {H.message(err)!r}"
        assert path.read_text(encoding="utf-8") == planted, "the writer altered a file it did not make"
        path.unlink()
    record_episode_runs(t, "ep", _rid("src"), {"a": _rid("ep-a")})
    path = _record(runs, "ep")
    assert path.is_file(), "the writer's own record was not written"
    mine = path.read_bytes()
    err = H.raised(record_episode_runs, t, "ep", _rid("src"), {"a": _rid("ep-a")})
    assert err is None, f"positive control: byte-identical content is a no-op success, got {err!r}"
    assert path.read_bytes() == mine, f"positive control: byte-identical content is a no-op success, got {err!r}"


def test_1105_a_record_over_64_kib_is_corrupt_and_read_no_further_than_the_cap_plus_one(tmp_path):
    """A good record of exactly 65536 bytes claims its ids; one of 65537 bytes, and a sparse file
    claiming 1 GiB, make sibling_run_ids raise RunRefused naming the file, having read it through
    Bound.read(max_bytes=65537), so no more than the cap plus one byte is read and the call
    returns promptly. (That no more than the cap plus one byte is read is pinned at the
    mechanism by io_bound_read_max_bytes; here the observable is the refusal and its promptness.)"""
    from defender.run_repository import RunRefused, sibling_run_ids

    t, runs = _setup(tmp_path)
    text = H.record_text("cap", t.id, "src", {"a": "cap-a"})
    at_cap = H.plant_record(runs, "cap", t.id, "src", {}, raw=_padded(text, H.RECORD_CAP))
    assert at_cap.stat().st_size == H.RECORD_CAP
    assert sibling_run_ids(t) == {_rid("cap-a")}, "a 65536-byte good record claims its ids"
    H.plant_record(runs, "cap", t.id, "src", {}, raw=_padded(text, H.RECORD_CAP + 1))
    assert at_cap.stat().st_size == H.RECORD_CAP + 1
    err = H.raised(sibling_run_ids, t)
    assert H.is_a(err, RunRefused), f"a 65537-byte record gave {err!r}, not RunRefused"
    assert str(at_cap) in H.message(err), f"the refusal names the file: {H.message(err)!r}"
    at_cap.unlink()
    huge = runs / "_episodes" / "huge.json"
    with open(huge, "wb") as fh:
        fh.truncate(1 << 30)  # sparse: claims 1 GiB, occupies nothing
    started = time.monotonic()
    err = H.raised(sibling_run_ids, t)
    elapsed = time.monotonic() - started
    assert H.is_a(err, RunRefused), f"a 1 GiB record gave {err!r}, not RunRefused"
    assert str(huge) in H.message(err), f"the refusal names the file: {H.message(err)!r}"
    assert elapsed < 5.0, f"refusing a 1 GiB record took {elapsed:.1f}s — it was read whole"


def test_1105_overlapping_claims_across_good_records_are_a_union(tmp_path):
    """Two good records claiming the same run id are not an error: sibling_run_ids returns the
    union, and runs.list (PR 1's list_run_ids) drops that id once."""
    from defender.run_repository import sibling_run_ids

    t, runs = _setup(tmp_path)
    H.plant_record(runs, "e1", t.id, "keep", {"a": "shared", "b": "x1"})
    H.plant_record(runs, "e2", t.id, "keep", {"a": "shared", "c": "y1"})
    for name in ("shared", "x1", "y1", "keep"):
        H.make_run(runs, name)
    claimed = sibling_run_ids(t)
    assert claimed == set(_ids("shared", "x1", "y1")), f"the union of both records: {claimed!r}"
    assert _listed(t) == _ids("keep"), "the shared id is dropped once; the source stays"


def test_1105_episode_runs_answers_from_that_episodes_own_record_only(tmp_path):
    """episode_runs(tenant, ep) returns that record's {label: RunId}; it returns {} when ep has no
    record (DV-7), answers unchanged when another episode's record is corrupt (it reads only ep's
    record), and raises RunRefused when ep's own record is corrupt."""
    from defender.run_repository import RunRefused, episode_runs, record_episode_runs

    t, runs = _setup(tmp_path)
    record_episode_runs(t, "ep", _rid("src"), {"a": _rid("ep-a"), "b": _rid("ep-b")})
    want = {"a": _rid("ep-a"), "b": _rid("ep-b")}
    assert episode_runs(t, "ep") == want, "episode_runs returns the record's {label: RunId}"
    assert episode_runs(t, "nope") == {}, "an episode with no record answers {} (DV-7)"
    H.plant_record(runs, "other", t.id, "src", {},
                   raw=H.truncated(H.record_text("other", t.id, "src", {"c": "other-c"})))
    assert episode_runs(t, "ep") == want, "another episode's corrupt record changed the answer"
    own = H.plant_record(runs, "ep3", t.id, "src", {},
                         raw=H.truncated(H.record_text("ep3", t.id, "src", {"c": "ep3-c"})))
    err = H.raised(episode_runs, t, "ep3")
    assert H.is_a(err, RunRefused), f"ep's own corrupt record gave {err!r}, not RunRefused"
    assert str(own) in H.message(err), f"the refusal names the record: {H.message(err)!r}"


def test_1105_sibling_run_ids_is_the_union_of_every_record_and_fails_closed(tmp_path):
    """sibling_run_ids(tenant) returns the set of every RunId any good record claims (arms only,
    not the source), the empty set with no _episodes/, and raises RunRefused when any one record
    is corrupt."""
    from defender.run_repository import RunRefused, record_episode_runs, sibling_run_ids

    t, runs = _setup(tmp_path)
    assert sibling_run_ids(t) == set(), "no _episodes/: the empty set"
    record_episode_runs(t, "e1", _rid("src"), {"a": _rid("e1-a")})
    record_episode_runs(t, "e2", _rid("src"), {"b": _rid("e2-b"), "c": _rid("e2-c")})
    claimed = sibling_run_ids(t)
    assert claimed == set(_ids("e1-a", "e2-b", "e2-c")), f"every arm, no source: {claimed!r}"
    assert _rid("src") not in claimed, "the source is not a claim"
    bad = H.plant_record(runs, "bad", t.id, "src", {},
                         raw=H.truncated(H.record_text("bad", t.id, "src", {"z": "bad-z"})))
    err = H.raised(sibling_run_ids, t)
    assert H.is_a(err, RunRefused), f"one corrupt record gave {err!r}: it must fail closed"
    assert str(bad) in H.message(err), f"the refusal names the record: {H.message(err)!r}"


def test_1105_both_listings_drop_exactly_the_ids_sibling_run_ids_claims(tmp_path):
    """With real run folders for a source and two arms and a record written by
    record_episode_runs, runs.list (PR 1's list_run_ids; bound_runs is gone, #1105 PR 2) drops
    exactly sibling_run_ids(tenant) and keeps the source; a record in tenant.runs/_episodes naming
    another tenant makes the listing raise RunRefused, and episode_runs(tenant, 'foreign') refuses
    that record as corrupt too."""
    from defender.run_repository import (
        RunRefused,
        episode_runs,
        record_episode_runs,
        sibling_run_ids,
    )

    t, runs = _setup(tmp_path)
    record_episode_runs(t, "src-n1", _rid("src"), {"a": _rid("src-n1-a"), "b": _rid("src-n1-b")})
    for name in ("src", "src-n1-a", "src-n1-b"):
        H.make_run(runs, name)
    claimed = sibling_run_ids(t)
    assert claimed == set(_ids("src-n1-a", "src-n1-b")), f"the record's arms: {claimed!r}"
    every = _ids("src", "src-n1-a", "src-n1-b")
    kept = [rid for rid in every if rid not in claimed]
    assert _listed(t) == kept == _ids("src"), "runs.list drops exactly the claims"
    foreign = H.plant_record(runs, "foreign", H.U_ID, "src", {"z": "foreign-z"})
    for name, call in (("runs.list", lambda: _listed(t)),
                       ("episode_runs", lambda: episode_runs(t, "foreign"))):
        err = H.raised(call)
        assert H.is_a(err, RunRefused), f"{name} over a foreign record gave {err!r}"
        assert str(foreign) in H.message(err), f"{name} names the record: {H.message(err)!r}"


def test_1105_the_record_folder_can_never_be_a_run_id(tmp_path):
    """RunId.parse refuses '_episodes' and every name with a leading '_', so no run folder can
    share the record folder's name, and a populated _episodes/ is never a runs.list entry (PR 1's
    list_run_ids)."""
    from defender.run_repository import RunId, RunRefused, record_episode_runs

    for name in ("_episodes", "_x", "_tenant.json", "_1", "__"):
        err = H.raised(RunId.parse, name)
        assert H.is_a(err, RunRefused), f"RunId.parse({name!r}) gave {err!r}, not RunRefused"
    t, runs = _setup(tmp_path)
    record_episode_runs(t, "ep", _rid("src"), {"a": _rid("ep-a")})
    H.make_run(runs, "r1")
    assert (runs / "_episodes").is_dir(), "the record folder is populated"
    assert _listed(t) == _ids("r1"), "_episodes/ is never a runs.list entry"


def test_1105_the_episode_record_has_its_own_kinds_registry_row(tmp_path):
    """defender/docs/run-records-kinds.tsv carries a row for the episode-to-runs record whose kind
    name is not 'episode_runs' (that kind stays the sibling run directories). The row's path
    template matches where record_episode_runs actually writes, relative to tenant.runs."""
    import csv
    import re

    from defender.run_repository import record_episode_runs

    registry = H.DEFENDER / "docs" / "run-records-kinds.tsv"
    with registry.open(encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh, delimiter="\t"))
    record_rows = [r for r in rows if (r.get("path") or "").startswith("_episodes/")]
    assert len(record_rows) == 1, (
        f"one kinds-registry row for the episode record (path _episodes/...): {record_rows}")
    row = record_rows[0]
    assert row["kind"] != "episode_runs", "the record has a DISTINCT kind name (F46)"
    sibling = [r for r in rows if r["kind"] == "episode_runs"]
    assert len(sibling) == 1, "kind episode_runs stays the sibling run directories"
    assert sibling[0]["path"].startswith("runs/"), "kind episode_runs stays the sibling run directories"
    t, runs = _setup(tmp_path)
    record_episode_runs(t, "ep", _rid("src"), {"a": _rid("ep-a")})
    written = [str(p.relative_to(runs)) for p in (runs / "_episodes").glob("*")]
    pattern = re.sub(r"<[^>]+>", "[^/]+", re.escape(row["path"]))
    assert written == ["_episodes/ep.json"], f"the registry's path {row['path']!r} names where the writer writes: {written}"
    assert re.fullmatch(pattern, written[0]), f"the registry's path {row['path']!r} names where the writer writes: {written}"


def test_1105_episode_sibling_ids_takes_only_a_bound_and_applies_the_file_rules_without_a_tenant_compare(
        tmp_path):
    """episode_sibling_ids(runs) takes a Bound and raises TypeError before any read for a Path, a
    str, a Held, a Tenant or None; over a Bound it reads runs.under('_episodes') with D3.4's file
    rules and no tenant compare (a record naming another tenant still claims its ids, and
    _tenant.json is never read), returns the empty set over a Bound of an absent runs folder and
    for an absent _episodes, and does not close the Bound it is handed. A record whose tenant_id
    is not text (7) is corrupt and refuses with RunRefused naming the file, and one whose
    tenant_id is the empty string is good and claims its ids (no compare; NM-03 A as amended by
    B)."""
    from defender.run_repository import RunRefused, episode_sibling_ids, record_episode_runs

    t, runs = _setup(tmp_path)
    with _io.hold(runs) as held:
        for what, arg in (("a Path", runs), ("a str", str(runs)), ("a Held", held),
                          ("a Tenant", t), ("None", None)):
            err = H.raised(episode_sibling_ids, arg)
            assert isinstance(err, TypeError), f"{what} gave {err!r}, not TypeError"
        assert episode_sibling_ids(held.view()) == set(), "an absent _episodes: the empty set"
    record_episode_runs(t, "ep", _rid("src"), {"a": _rid("ep-a")})
    H.plant_record(runs, "foreign", H.U_ID, "src", {"b": "foreign-b"})
    (runs / "_tenant.json").write_text("not json at all", encoding="utf-8")  # never read here
    bound = _io.bind(runs)
    try:
        claimed = episode_sibling_ids(bound)
        assert claimed == set(_ids("ep-a", "foreign-b")), (
            f"no tenant compare, and _tenant.json is not read: {claimed!r}")
        after = bound.entries()
        assert after.reason is None, f"the Bound it was handed still reads (it was not closed): {after!r}"
        assert "_episodes" in (after.entries or {}), f"the Bound it was handed still reads (it was not closed): {after!r}"
    finally:
        bound.close()
    nobody = H.tenant(tmp_path / "data", H.U_ID)  # no runs folder
    with _io.bind(nobody.runs) as absent:
        assert episode_sibling_ids(absent) == set(), "a Bound of an absent runs folder: empty"

    H.plant_record(runs, "blank", "", "src", {"e": "blank-e"})
    with _io.bind(runs) as view:
        claimed = episode_sibling_ids(view)
    assert claimed == set(_ids("ep-a", "foreign-b", "blank-e")), (
        f"an empty tenant_id is good on the path-only reader (no compare): {claimed!r}")
    numeric = H.plant_record(runs, "num", 7, "src", {"n": "num-n"})
    with _io.bind(runs) as view:
        err = H.raised(episode_sibling_ids, view)
    assert H.is_a(err, RunRefused), f"a non-text tenant_id (7) is corrupt, but gave {err!r}"
    assert str(numeric) in H.message(err), f"the refusal names the file: {H.message(err)!r}"


def test_1105_the_path_only_reader_and_sibling_run_ids_agree_on_every_good_and_corrupt_record(
        tmp_path):
    """Over the same records, episode_sibling_ids(<the held view of tenant.runs>) equals
    sibling_run_ids(tenant) for good records; both refuse a truncated record with RunRefused; and
    a record naming another tenant still claims its ids in episode_sibling_ids, which makes no
    tenant compare, while sibling_run_ids refuses it as corrupt."""
    from defender.run_repository import (
        RunRefused,
        episode_sibling_ids,
        record_episode_runs,
        sibling_run_ids,
    )

    t, runs = _setup(tmp_path)
    record_episode_runs(t, "e1", _rid("src"), {"a": _rid("e1-a")})
    H.plant_record(runs, "e2", t.id, "src", {"b": "e2-b"})
    with _io.hold(runs) as held:
        assert episode_sibling_ids(held.view()) == sibling_run_ids(t) == set(_ids("e1-a", "e2-b")), (
            "both readers agree on good records")
    torn = H.plant_record(runs, "e3", t.id, "src", {},
                          raw=H.truncated(H.record_text("e3", t.id, "src", {"c": "e3-c"})))
    with _io.hold(runs) as held:
        err_path_only = H.raised(episode_sibling_ids, held.view())
    err_tenant = H.raised(sibling_run_ids, t)
    assert H.is_a(err_path_only, RunRefused), f"episode_sibling_ids over a torn record: {err_path_only!r}"
    assert H.is_a(err_tenant, RunRefused), f"sibling_run_ids over a torn record: {err_tenant!r}"
    torn.unlink()
    H.plant_record(runs, "e4", H.U_ID, "src", {"d": "e4-d"})
    with _io.hold(runs) as held:
        assert episode_sibling_ids(held.view()) == set(_ids("e1-a", "e2-b", "e4-d")), (
            "the path-only reader makes no tenant compare: the foreign record claims")
    err = H.raised(sibling_run_ids, t)
    assert H.is_a(err, RunRefused), f"sibling_run_ids over a foreign record gave {err!r}"


def test_1105_the_record_is_exactly_four_fields_in_one_canonical_sorted_key_serialisation(tmp_path):
    """The stored record is exactly {episode_id, tenant_id, source_run_id, runs: {label: run_id}}
    with tenant_id == tenant.id and every run id stored as its RunId text, in one canonical
    serialisation with sorted keys: two calls with equal mappings given in different key orders
    (dict, OrderedDict, MappingProxyType) store byte-identical files."""
    from defender.run_repository import record_episode_runs

    t, runs = _setup(tmp_path)
    arms = {"b": _rid("ep-b"), "a": _rid("ep-a")}
    record_episode_runs(t, "ep", _rid("src"), arms)
    path = _record(runs, "ep")
    assert path.is_file(), f"no record at {path}"
    text = path.read_text(encoding="utf-8")
    assert json.loads(text) == {"episode_id": "ep", "tenant_id": t.id, "source_run_id": "src",
                                "runs": {"a": "ep-a", "b": "ep-b"}}, f"exactly the four fields: {text}"
    pairs = json.loads(text, object_pairs_hook=list)
    top = [k for k, _v in pairs]
    assert top == sorted(top), f"the top-level keys are sorted: {top}"
    inner = [k for k, _v in dict(pairs)["runs"]]
    assert inner == ["a", "b"], f"the runs map's keys are sorted: {inner}"
    canonical = path.read_bytes()
    for mapping in (OrderedDict([("a", _rid("ep-a")), ("b", _rid("ep-b"))]),
                    types.MappingProxyType({"b": _rid("ep-b"), "a": _rid("ep-a")})):
        err = H.raised(record_episode_runs, t, "ep", _rid("src"), mapping)
        assert err is None, f"an equal mapping in another order is the same bytes: {err!r}"
        path.unlink()
        record_episode_runs(t, "ep", _rid("src"), mapping)
        assert path.read_bytes() == canonical, f"{type(mapping).__name__} stored other bytes"


def test_1105_a_records_episode_id_must_equal_its_file_name_minus_the_final_json(tmp_path):
    """A record's stem is its file name minus the final '.json': _episodes/ep.json holding
    episode_id 'ep' is good, and so is _episodes/ep.1.json holding 'ep.1' (refuse_bad_episode_id
    admits it); a record whose episode_id differs from its stem in any way (ep-2, EP-1, 'ep-1 '
    at ep-1.json) makes sibling_run_ids, runs.list (PR 1's list_run_ids) and
    episode_runs(tenant, 'ep-1') raise RunRefused naming the file."""
    from defender.run_repository import RunRefused, episode_runs, sibling_run_ids

    t, runs = _setup(tmp_path)
    H.plant_record(runs, "ep", t.id, "src", {"a": "ep-a"})
    H.plant_record(runs, "ep.1", t.id, "src", {"a": "ep.1-a"})
    assert sibling_run_ids(t) == set(_ids("ep-a", "ep.1-a")), "both stems are good records"
    for wrong in ("ep-2", "EP-1", "ep-1 "):
        bad = H.plant_record(runs, wrong, t.id, "src", {"z": "z1"}, name="ep-1")
        for name, call in (("sibling_run_ids", sibling_run_ids), ("runs.list", _listed),
                           ("episode_runs", lambda tenant: episode_runs(tenant, "ep-1"))):
            err = H.raised(call, t)
            assert H.is_a(err, RunRefused), f"{name}: episode_id {wrong!r} at ep-1.json gave {err!r}"
            assert str(bad) in H.message(err), f"{name} names the file: {H.message(err)!r}"
        bad.unlink()


def test_1105_the_reader_applies_only_its_closed_list_so_a_writer_rule_breaker_claims(tmp_path):
    """The reader's rule is D3.4's closed list: a host-written record that breaks only writer rules
    (two labels on one id, an arm equal to the source, an arm not shaped f'{episode_id}-{label}',
    an arm another record claims) is good on read, so sibling_run_ids claims its ids and
    runs.list (PR 1's list_run_ids) hides them; in PR 1 'a record never hides an ordinary run'
    holds through the writer only (the owner accepts this, O4)."""
    from defender.run_repository import sibling_run_ids

    t, runs = _setup(tmp_path)
    H.plant_record(runs, "e1", t.id, "s0", {"a": "x", "b": "x"})  # two labels on one id
    H.plant_record(runs, "e2", t.id, "s", {"a": "s"})  # an arm equal to the source
    H.plant_record(runs, "e3", t.id, "s0", {"a": "other"})  # not shaped e3-<label>
    H.plant_record(runs, "e4", t.id, "s0", {"z": "x"})  # an arm another record claims
    for name in ("x", "s", "other", "plain", "s0"):
        H.make_run(runs, name)
    claimed = sibling_run_ids(t)
    assert claimed == set(_ids("x", "s", "other")), f"each writer-rule breaker claims: {claimed!r}"
    assert _listed(t) == _ids("plain", "s0"), "their ids are hidden; the rest are listed"


def test_1105_the_reader_refuses_each_content_rule_breaker_naming_the_file(tmp_path):
    """D3.4's content rules, one breaker each, planted by hand at _episodes/ep.json: bytes that
    are not strict UTF-8, a UTF-8 BOM before the JSON and text after it (neither is strict UTF-8
    JSON), a duplicate key, an extra field, a missing field (no source_run_id), a JSON array at
    the top level, runs that is not a map, an empty runs, an arm that is not text, a
    source_run_id RunId.parse refuses ('Src'), and a record whose runs nests 32,000 arrays deep
    yet fits under the 64 KiB cap (json.loads raises RecursionError on it; P2's one named error,
    92 FR-22); and, by name, a record at Bad.json, whose stem is not a grammar-valid episode id.
    Each makes sibling_run_ids raise RunRefused naming the file, never a raw RecursionError, on
    one line with no raw control character, and each at ep.json makes episode_runs(tenant, 'ep')
    refuse the same way. Positive control: the good twin claims its id and episode_runs answers
    it."""
    from defender.run_repository import RunRefused, episode_runs, sibling_run_ids

    t, runs = _setup(tmp_path)
    good = H.record_doc("ep", t.id, "src", {"a": "ep-a"})
    text = json.dumps(good, sort_keys=True)
    missing = {k: v for k, v in good.items() if k != "source_run_id"}
    nest = "[" * 32_000 + "]" * 32_000
    deep = json.dumps({**good, "runs": None}, sort_keys=True).replace('"runs": null', f'"runs": {nest}')
    assert nest in deep, "precondition: the deep record's runs is the 32,000-deep nest"
    assert len(deep.encode("utf-8")) < 65536, f"precondition: the deep record fits under the cap ({len(deep)})"
    breakers = (
        ("bytes that are not strict UTF-8", text.encode("utf-8").replace(b'"src"', b'"sr\xffc"')),
        ("a UTF-8 BOM before the JSON", b"\xef\xbb\xbf" + text.encode("utf-8")),
        ("text after the JSON", text + " x"),
        ("a duplicate key", text[:-1] + ', "episode_id": "ep"}'),
        ("an extra field", json.dumps({**good, "extra": 1}, sort_keys=True)),
        ("a missing field", json.dumps(missing, sort_keys=True)),
        ("a JSON array at the top level", json.dumps([good])),
        ("runs that is not a map", json.dumps({**good, "runs": [["a", "ep-a"]]}, sort_keys=True)),
        ("an empty runs", json.dumps({**good, "runs": {}}, sort_keys=True)),
        ("an arm that is not text", json.dumps({**good, "runs": {"a": 5}}, sort_keys=True)),
        ("a source_run_id RunId.parse refuses",
         json.dumps({**good, "source_run_id": "Src"}, sort_keys=True)),
        ("a record whose runs nests 32,000 arrays deep, under the cap", deep),
    )
    for what, raw in breakers:
        bad = H.plant_record(runs, "ep", t.id, "src", {}, raw=raw)
        for name, call in (("sibling_run_ids", lambda: sibling_run_ids(t)),
                           ("episode_runs", lambda: episode_runs(t, "ep"))):
            err = H.raised(call)
            assert not H.is_a(err, RecursionError), f"{name} over {what}: a raw RecursionError escaped"
            assert H.is_a(err, RunRefused), f"{name} over {what}: {err!r}, not RunRefused"
            text_of = H.message(err)
            assert str(bad) in text_of, f"{name} over {what} names the file: {text_of!r}"
            assert not H.has_raw_control(text_of), f"{name} over {what}: raw control in {text_of!r}"
        bad.unlink()
    stray = H.plant_record(runs, "Bad", t.id, "src", {"a": "bad-a"})
    err = H.raised(sibling_run_ids, t)
    assert H.is_a(err, RunRefused), f"a record at Bad.json gave {err!r}, not RunRefused"
    assert str(stray) in H.message(err), f"the refusal names Bad.json: {H.message(err)!r}"
    stray.unlink()
    H.plant_record(runs, "ep", t.id, "src", {"a": "ep-a"})
    assert sibling_run_ids(t) == set(_ids("ep-a")), "positive control: the good twin claims"
    assert episode_runs(t, "ep") == {"a": _rid("ep-a")}, "positive control: episode_runs answers"


def test_1105_a_truncated_episode_record_refuses_naming_the_file(tmp_path):
    """With _episodes/ep-1.json truncated (a good record cut short), sibling_run_ids,
    runs.list (PR 1's list_run_ids), episode_runs(tenant, 'ep-1') and episode_sibling_ids raise
    RunRefused naming that file, and it fails closed until an operator removes it; episode_runs
    for another episode with a good record still answers. Positive control: the untruncated
    record claims its ids."""
    from defender.run_repository import (
        RunRefused,
        episode_runs,
        episode_sibling_ids,
        record_episode_runs,
        sibling_run_ids,
    )

    t, runs = _setup(tmp_path)
    record_episode_runs(t, "ep-1", _rid("src"), {"a": _rid("ep-1-a")})
    record_episode_runs(t, "ep-2", _rid("src"), {"b": _rid("ep-2-b")})
    torn = _record(runs, "ep-1")
    assert torn.is_file(), f"the writer wrote no record at {torn}"
    assert sibling_run_ids(t) == set(_ids("ep-1-a", "ep-2-b")), "positive control: it claims"
    good_text = torn.read_text(encoding="utf-8")
    torn.write_text(H.truncated(good_text), encoding="utf-8")

    def _path_only():
        with _io.hold(runs) as held:
            return episode_sibling_ids(held.view())

    readers = (("sibling_run_ids", lambda: sibling_run_ids(t)),
               ("runs.list", lambda: _listed(t)),
               ("episode_runs", lambda: episode_runs(t, "ep-1")))
    for _attempt in range(2):  # fails closed: the same answer every time until removed
        for name, call in readers:
            err = H.raised(call)
            assert H.is_a(err, RunRefused), f"{name} over a torn record gave {err!r}"
            assert str(torn) in H.message(err), f"{name} names the file: {H.message(err)!r}"
        err = H.raised(_path_only)
        assert H.is_a(err, RunRefused), f"episode_sibling_ids over a torn record gave {err!r}"
        assert "ep-1.json" in H.message(err), f"episode_sibling_ids names it: {H.message(err)!r}"
    assert episode_runs(t, "ep-2") == {"b": _rid("ep-2-b")}, "another episode's record answers"
    torn.unlink()
    assert sibling_run_ids(t) == set(_ids("ep-2-b")), "removed by the operator, the rest stands"


def test_1105_a_stray_name_in_episodes_refuses_naming_it(tmp_path):
    """With a file named 'README' beside a good record in _episodes, sibling_run_ids, runs.list
    (PR 1's list_run_ids) and episode_sibling_ids raise RunRefused naming
    tenant.runs/_episodes/README.
    Positive control: with it removed the good record's claims stand."""
    from defender.run_repository import (
        RunRefused,
        episode_sibling_ids,
        record_episode_runs,
        sibling_run_ids,
    )

    t, runs = _setup(tmp_path)
    record_episode_runs(t, "ep", _rid("src"), {"a": _rid("ep-a")})
    assert _record(runs, "ep").is_file(), "the writer wrote the good record the stray sits beside"
    stray = runs / "_episodes" / "README"
    stray.write_text("notes\n", encoding="utf-8")

    def _path_only():
        with _io.hold(runs) as held:
            return episode_sibling_ids(held.view())

    for name, call in (("sibling_run_ids", lambda: sibling_run_ids(t)),
                       ("runs.list", lambda: _listed(t))):
        err = H.raised(call)
        assert H.is_a(err, RunRefused), f"{name} over a stray README gave {err!r}"
        assert str(stray) in H.message(err), f"{name} names {stray}: {H.message(err)!r}"
    err = H.raised(_path_only)
    assert H.is_a(err, RunRefused), f"episode_sibling_ids over a stray README gave {err!r}"
    assert "_episodes/README" in H.message(err), f"it names the entry: {H.message(err)!r}"
    stray.unlink()
    assert sibling_run_ids(t) == set(_ids("ep-a")), "positive control: the claims stand"
    assert _path_only() == set(_ids("ep-a")), "positive control: the path-only reader agrees"


def test_1105_an_absent_episodes_claims_nothing_and_the_writer_creates_it(tmp_path):
    """With no _episodes in a good runs folder, sibling_run_ids is the empty set, episode_runs
    returns {}, the listings exclude nothing, episode_sibling_ids returns the empty set, and a
    first-ever pinned run setup proceeds and creates no _episodes; the first record_episode_runs
    creates _episodes inside the held folder."""
    from defender.run_repository import (
        episode_runs,
        episode_sibling_ids,
        record_episode_runs,
        sibling_run_ids,
    )

    t, runs = _setup(tmp_path)
    H.make_run(runs, "r1")
    assert sibling_run_ids(t) == set(), "no _episodes: nothing is claimed"
    assert episode_runs(t, "ep") == {}, "no _episodes: an episode's record is absent"
    assert _listed(t) == _ids("r1"), "the listing excludes nothing"
    with _io.hold(runs) as held:
        assert episode_sibling_ids(held.view()) == set(), "the path-only reader: empty"
    run_common.materialize_run(H.alert_file(tmp_path / "alerts"), "r2", tenant=t)
    assert (runs / "r2").is_dir(), "a first-ever pinned run setup proceeds"
    assert not os.path.lexists(runs / "_episodes"), "run setup creates no _episodes"
    assert _listed(t) == _ids("r1", "r2"), "the listing still excludes nothing"
    record_episode_runs(t, "ep", _rid("r1"), {"a": _rid("ep-a")})
    assert (runs / "_episodes").is_dir(), "the first record_episode_runs creates _episodes inside tenant.runs"
    assert not (runs / "_episodes").is_symlink(), "the first record_episode_runs creates _episodes inside tenant.runs"
    assert _record(runs, "ep").is_file(), "and writes the record in it"


def test_1105_the_record_key_is_tenant_and_episode_so_no_record_is_read_by_another_episode_or_tenant(
        tmp_path):
    """the same episode_id recorded under tenants T and U (U hand-planted, F36) lands in two files;
    T's episode_runs, sibling_run_ids and runs.list (PR 1's list_run_ids) see only T's record and
    U's only U's; two
    episodes of one tenant, and 'ep' beside the dotted 'ep.1', never read each other's record; two
    writers racing one episode id with different content leave exactly one intact record and one
    RunRefused (serial both orders where a genuine interleaving cannot be forced); positive
    control: every read is non-empty"""
    from defender.run_repository import (
        RunRefused,
        episode_runs,
        record_episode_runs,
        sibling_run_ids,
    )

    root = tmp_path / "data"
    t, t_runs = _setup(tmp_path, H.T_ID, root)
    u, u_runs = _setup(tmp_path, H.U_ID, root)
    record_episode_runs(t, "ep", _rid("src"), {"a": _rid("ep-a")})
    record_episode_runs(u, "ep", _rid("src"), {"b": _rid("ep-b")})
    assert _record(t_runs, "ep").is_file(), "one episode id under two tenants lands in two files"
    assert _record(u_runs, "ep").is_file(), "one episode id under two tenants lands in two files"
    for runs in (t_runs, u_runs):
        H.make_run(runs, "ep-a")
        H.make_run(runs, "ep-b")
    assert episode_runs(t, "ep") == {"a": _rid("ep-a")}, "T sees only T's record"
    assert episode_runs(u, "ep") == {"b": _rid("ep-b")}, "U sees only U's record"
    assert sibling_run_ids(t) == set(_ids("ep-a"))
    assert sibling_run_ids(u) == set(_ids("ep-b"))
    assert _listed(t) == _ids("ep-b"), "each tenant's listing is filtered by its own record only"
    assert _listed(u) == _ids("ep-a"), "each tenant's listing is filtered by its own record only"

    record_episode_runs(t, "ep.1", _rid("src"), {"c": _rid("ep.1-c")})
    record_episode_runs(t, "ep2", _rid("src"), {"d": _rid("ep2-d")})
    assert episode_runs(t, "ep") == {"a": _rid("ep-a")}, "'ep' does not read 'ep.1' or 'ep2'"
    assert episode_runs(t, "ep.1") == {"c": _rid("ep.1-c")}, "'ep.1' reads its own record"
    assert episode_runs(t, "ep2") == {"d": _rid("ep2-d")}, "'ep2' reads its own record"

    x = (_rid("src"), {"x": _rid("race-x")})
    y = (_rid("src"), {"y": _rid("race-y")})
    barrier = threading.Barrier(2)
    results: dict[str, BaseException | None] = {}

    def _writer(key: str, args: tuple) -> None:
        barrier.wait()
        results[key] = H.raised(record_episode_runs, t, "race", *args)

    threads = [threading.Thread(target=_writer, args=(k, a)) for k, a in (("x", x), ("y", y))]
    for th in threads:
        th.start()
    for th in threads:
        th.join(timeout=60)
    outcomes = sorted((results.get("x") is None, results.get("y") is None))
    assert outcomes == [False, True], f"one writer wins, one is refused: {results!r}"
    loser = results["x"] if results["x"] is not None else results["y"]
    assert H.is_a(loser, RunRefused), f"the losing writer gets RunRefused: {loser!r}"
    winner = "x" if results["x"] is None else "y"
    stored = json.loads(_record(t_runs, "race").read_text(encoding="utf-8"))
    assert stored == H.record_doc("race", t.id, "src", {winner: f"race-{winner}"}), (
        f"exactly one intact record, the winner's: {stored}")
    for episode, first, second in (("serial-xy", x, y), ("serial-yx", y, x)):
        arms_first = {k: _rid(f"{episode}-{k}") for k in first[1]}
        arms_second = {k: _rid(f"{episode}-{k}") for k in second[1]}
        err = H.raised(record_episode_runs, t, episode, first[0], arms_first)
        assert err is None, f"{episode}: the first writer writes: {err!r}"
        err = H.raised(record_episode_runs, t, episode, second[0], arms_second)
        assert H.is_a(err, RunRefused), f"{episode}: the second writer gets RunRefused: {err!r}"
        assert episode_runs(t, episode) == arms_first, f"{episode}: the first record stands"


def test_1105_record_labels_are_returned_verbatim_as_untrusted_text_and_a_refusal_quoting_one_escapes_it(
        tmp_path):
    """a host-written record whose labels carry a newline, an escaped NUL, a 4,000-character string
    and non-ASCII text is good on read: episode_runs returns each label byte-for-byte as the key
    and its RunId as the value, sibling_run_ids and runs.list are unaffected, and a refusal
    that quotes such a label escapes it (a record at the cap with one such label still reads);
    positive control: the same record with plain labels returns the same ids. Pins that the
    repository does not sanitise labels, so PR 2 re-asks R6 at each renderer instead of assuming
    they were validated. The writer's refusal of a label holding a newline, a tab or an ESC
    quotes the label or the arm repr-escaped on one line; text read from disk is quoted the same
    way: a host-written record whose label and arm carry a newline and an ESC is corrupt (the
    reader judges no label, so it refuses on the arm RunId.parse refuses), and episode_runs and
    sibling_run_ids raise RunRefused naming the file on one line and, where they quote the label
    or the arm, quote it repr-escaped, never raw or stripped.
    The hostile labels and arm include DEL, a C1 control (U+009B) and U+2028 (91 BF-09)."""
    from defender.run_repository import (
        RunRefused,
        episode_runs,
        record_episode_runs,
        sibling_run_ids,
    )

    t, runs = _setup(tmp_path)
    labels = {"a\nb": "lab-1", "nul\u0000x": "lab-2", "l" * 4000: "lab-3", "wörld": "lab-4"}
    H.plant_record(runs, "lab", t.id, "src", labels)
    answer = episode_runs(t, "lab")
    assert set(answer) == set(labels), f"each label comes back verbatim: {sorted(map(repr, answer))}"
    for label, arm in labels.items():
        assert answer[label] == _rid(arm), f"{label[:12]!r}... maps to its RunId"
    for name in (*labels.values(), "plain"):
        H.make_run(runs, name)
    assert sibling_run_ids(t) == set(_ids(*labels.values())), "the claims are unaffected"
    assert _listed(t) == _ids("plain"), "the listing is unaffected"

    for odd in ("x\ny", "x\ty", "x\x1b[31m", "x\x7f\x9b\u2028y"):
        err = H.raised(record_episode_runs, t, "w1", _rid("src"), {odd: _rid("w1-x")})
        assert H.is_a(err, RunRefused), f"the writer refuses label {odd!r}: {err!r}"
        text = H.message(err)
        assert not H.has_raw_control(text), f"a refusal quoting label {odd!r} escapes it: {text!r}"
        # No arm spells f'w1-{odd}' (RunId refuses the control), so the refusal may name the
        # label or the arm it fails to match (NM-11); a quoted label is repr-escaped.
        assert repr(odd)[1:-1] in text or "w1-x" in text, (
            f"the refusal quotes neither the label repr-escaped nor the arm: {text!r}")

    text = H.record_text("capl", t.id, "src", {"a\nb": "capl-a"})
    H.plant_record(runs, "capl", t.id, "src", {}, raw=_padded(text, H.RECORD_CAP))
    assert episode_runs(t, "capl") == {"a\nb": _rid("capl-a")}, (
        "a record at the cap with an odd label still reads")
    plain = {f"p{i}": arm for i, arm in enumerate(labels.values())}
    H.plant_record(runs, "plainlab", t.id, "src", plain)
    assert sorted(map(str, episode_runs(t, "plainlab").values())) == sorted(
        map(str, answer.values())), "positive control: plain labels return the same ids"

    # Disk-read text: the reader judges no label, so the record is corrupt on its arm.
    label, arm = "lbl\nODD\x1b[31m\x7f\x9b\u2028", "arm\nODD\x1b[31m\x7f\x9b\u2028"
    hostile = H.plant_record(runs, "odd", t.id, "src", {label: arm})
    escaped = (repr(label)[1:-1], repr(arm)[1:-1])
    for name, call in (("episode_runs", lambda: episode_runs(t, "odd")),
                       ("sibling_run_ids", lambda: sibling_run_ids(t))):
        err = H.raised(call)
        assert H.is_a(err, RunRefused), f"{name} over a record with a hostile arm gave {err!r}"
        text = H.message(err)
        assert str(hostile) in text, f"{name}'s refusal does not name the file: {text!r}"
        assert not H.has_raw_control(text), f"{name} quotes disk-read text raw: {text!r}"
        assert "ODD" not in text or any(q in text for q in escaped), (
            f"{name} quotes the disk-read label or arm other than repr-escaped: {text!r}")

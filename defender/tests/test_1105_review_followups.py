"""#1105 PR 1 — the code review's findings, dissolved at their cause.

* The episode record's name rules come from `_world_label` and `_run_id`, which import nothing
  heavy, so the repository reads and writes records in a process without the model stack.
* `_io`'s bounded read is the one read step's prefix mode: byte-faithful (newlines kept), and an
  `ENOENT` while reading is a refusal, never "absent".
* `RunRefused` escapes its own message, and the package's tenant refusals go through one helper
  that does the same, so no site can splice a raw control character into a refusal.
* `lint_run_records` owns the whole package folder, so a module the package gains is an owner.
"""
from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import textwrap

import pytest

from defender import _io
from defender import run_repository as R
from defender.tests.tenant_1105_run_repository import _spec1105 as H

_FORGED = "x\nFORGED LINE: all good"


def test_the_repository_reads_and_writes_episode_records_without_the_model_stack(tmp_path):
    """With `pydantic_ai` unimportable, the repository answers over a tenant's runs folder (the
    review: its readers raised ModuleNotFoundError on first read).

    #1187 declared change 13 (R6, D-del): PR 1's `_episodes` record and its writer and readers
    (`record_episode_runs`, `episode_runs`, `sibling_run_ids`) are deleted — there is no record
    to write or read. The guard kept is the import weight: the repository lists a container
    holding one UUID run and no `_tenant.json` (declared change 6) in a process without the
    model stack. (Name kept.)"""
    import uuid

    t = H.tenant(tmp_path / "data")
    run_id = str(uuid.uuid4())
    H.make_run(t.runs, run_id)
    probe = textwrap.dedent(f'''
        import sys
        class _Block:
            def find_spec(self, name, path=None, target=None):
                if name == "pydantic_ai" or name.startswith("pydantic_ai."):
                    raise ModuleNotFoundError(name)
        sys.meta_path.insert(0, _Block())
        from defender import _tenant
        from defender import run_repository as R
        t = _tenant.accept_tenant({str(tmp_path / "data")!r}, {t.id!r},
                                  defender_dir={str(H.DEFENDER)!r})
        assert str(R.RunId.parse({run_id!r})) == {run_id!r}
        assert [str(i) for i in t.runs_repository().list()] == [{run_id!r}]
        assert "pydantic_ai" not in sys.modules and "defender.runtime.branch" not in sys.modules
        print("ok")
    ''')
    env = {**os.environ, "PYTHONPATH": str(H.WORKTREE)}
    proc = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True,
                          env=env, cwd=H.DEFENDER, timeout=120)
    assert proc.returncode == 0, proc.stderr[-2000:]
    assert proc.stdout.strip() == "ok", proc.stdout[-2000:]


def test_a_bounded_read_keeps_the_files_newlines(tmp_path):
    """`Bound.read(max_bytes=N)` is byte-faithful: a `\\r\\n` file reads back with its `\\r\\n`,
    since its caller judges bytes; the whole read keeps translating as `Path.read_text` does."""
    (tmp_path / "f.json").write_bytes(b"a\r\nb\rc")
    with _io.bind(tmp_path) as bound:
        assert bound.read("f.json", max_bytes=100).text == "a\r\nb\rc"
        assert bound.read("f.json").text == "a\nb\nc"


class _VanishingOS:
    """The real `os` whose `read` raises ENOENT, as a file deleted mid-read on some
    filesystems does."""

    def __getattr__(self, name):
        return getattr(os, name)

    def read(self, fd, n):
        raise FileNotFoundError(2, "No such file or directory")


def test_a_bounded_read_whose_file_vanishes_while_read_is_a_refusal(tmp_path):
    (tmp_path / "f.json").write_text("{}", encoding="utf-8")
    with _io.hold(tmp_path, os_=_VanishingOS()) as held:
        rec = held.view().read("f.json", max_bytes=10)
    assert rec.absent is False, f"an ENOENT from read() answered absent: {rec!r}"
    assert rec.reason, f"an ENOENT from read() was not a refusal: {rec!r}"


def test_a_run_refused_escapes_its_own_message():
    err = R.RunRefused("a\nb\x1b[2Jc")
    assert "\n" not in str(err), str(err)
    assert "\x1b" not in str(err), str(err)
    assert str(R.RunRefused(str(err))) == str(err), "escaping an escaped message changes it"


def _lint_run_records():
    path = H.WORKTREE / "scripts" / "lint" / "lint_run_records.py"
    sys.path.insert(0, str(path.parent))
    try:
        spec = importlib.util.spec_from_file_location("_lint_run_records_1105r", path)
        assert spec is not None
        assert spec.loader is not None
        mod = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = mod
        spec.loader.exec_module(mod)
        return mod
    finally:
        sys.path.remove(str(path.parent))


def test_run_records_owns_any_module_the_package_gains():
    lint = _lint_run_records()
    assert lint._is_owner_module("run_repository/_a_module_added_later.py")
    assert not lint._is_owner_module("runtime/run_repository/_lookup.py")
    package = {f"run_repository/{p.name}" for p in (H.PACKAGE).glob("*.py")}
    assert package <= set(lint.OWNER_MODULES), "every file on disk is in the owner set"


# -- the second review's findings ---------------------------------------------------------------


def test_a_huge_read_bound_allocates_nothing_up_front(tmp_path):
    """`max_bytes` far past any file's size reads the file, never a `MemoryError`: the prefix
    read asks for one chunk at a time, not for its whole budget."""
    (tmp_path / "f.json").write_text("{}", encoding="utf-8")
    with _io.bind(tmp_path) as bound:
        assert bound.read("f.json", max_bytes=10 ** 15).text == "{}"


def test_an_absent_runs_folder_refusal_carries_no_stale_error(tmp_path):
    """An open's `RunAbsent` over an absent runs folder (#1105 PR 2 review: an open answers an
    absent container as the run gone) is raised outside the hold's `except`, so it carries no
    `FileNotFoundError` as its context (a traceback that blamed the wrong error). Positive
    control: once the folder and the run exist, the same open hands the run out.

    #1187 declared changes 1 and 11 (R1b): the container half's vehicle, `runs.base_world_id()`,
    is deleted with `base_world_id`, so the open is the absent folder's refusal left to pin; the
    id is a UUID and the folder holds no `_tenant.json`. (Name kept.)"""
    import uuid

    t = H.tenant(tmp_path / "data")
    run_id = str(uuid.uuid4())
    with pytest.raises(R.RunAbsent) as absent:
        t.runs_repository().open(R.RunId.parse(run_id))
    assert absent.value.__context__ is None, repr(absent.value.__context__)
    H.make_run(t.runs, run_id)
    assert t.runs_repository().open(R.RunId.parse(run_id)).run_dir == t.runs / run_id


# -- the third review's findings ----------------------------------------------------------------


@pytest.mark.parametrize("name", ["\x00" * 50, "\x01" * 120, "a" * 500, "ab\nc" * 60])
def test_a_shown_name_is_bounded_by_what_is_shown(name):
    """`quoted` escapes first, then cuts: the shown text stays within the limit plus its marker,
    never ends inside an escape, and never reports a negative count."""
    from defender._shown import SHOWN_LIMIT, quoted
    text = quoted(name)
    head, _sep, marker = text.partition("…(+")
    assert len(head) <= SHOWN_LIMIT, text
    assert "-" not in marker, text
    assert head.endswith("'"), f"cut inside an escape: {text}"


def _family_doc(episode_id: str, label: str) -> dict:
    world = {"world_id": label, "role": "A", "story": "s", "axis": None,
             "disposition_declared": "malicious", "label_basis": "policy-rule", "facts": []}
    return {"episode_id": episode_id, "source_run_dir": "/runs/src", "source_run_id": "src",
            "branch_message_id": 1, "fences_at": 1, "as_of": "2026-07-28T16:18:45Z",
            "continuation_prompt": "go", "base_story": "b", "served_systems": ["elastic"],
            "discriminator": {"predicate": "p"}, "worlds": [world]}


def test_a_runs_folder_that_cannot_be_opened_is_not_called_a_link(tmp_path):
    """A hold failure other than a link says what the hold said (here: the name is too long),
    not 'it is a link … or not a directory'."""
    from defender._tenant import TenantRefused
    with pytest.raises(TenantRefused) as refused:
        R.hold_runs_folder(tmp_path / ("x" * 300), create=True)
    assert "link" not in str(refused.value), str(refused.value)
    assert "too long" in str(refused.value), str(refused.value)


def test_run_setup_and_the_lookups_refuse_a_linked_runs_folder_in_the_same_words(tmp_path):
    """Run setup holds its runs folder with the repository's own opener, so one state has one
    message wherever it is met."""
    from defender import run_common
    from defender._tenant import TenantRefused
    t = H.tenant(tmp_path / "data")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    os.symlink(elsewhere, t.runs)
    alert = tmp_path / "a" / "alert.json"
    alert.parent.mkdir()
    alert.write_text('{"alert": 1}', encoding="utf-8")
    with pytest.raises(TenantRefused) as setup:
        run_common.materialize_run(alert, "pinned-1", tenant=t)
    with pytest.raises(TenantRefused) as lookup:
        t.runs_repository().list()
    assert str(setup.value) == str(lookup.value), (str(setup.value), str(lookup.value))
    assert "is a link" in str(setup.value), str(setup.value)


def test_the_run_name_rule_is_one_answer_for_every_caller():
    """`run_name_fault` is the run-id rule plus the sidecar clause, and the sidecar clause is
    no `RunPaths` method (the records lint needs no carve-out).

    #1187 declared change 1: the run-id rule is canonical lowercase UUID text, so a UUID is a
    run name and an old id (`r1`) is not; a UUID plus a sidecar suffix, staged or not, is still
    no run name (which clause speaks is not pinned: it fails both). The 206-byte bound is gone,
    so an over-long id is refused for its shape, never for a byte count."""
    import uuid

    run_id = str(uuid.uuid4())
    assert R.run_name_fault(run_id) is None
    assert R.run_name_fault("r1"), "an old run id is still a run name"
    assert R.run_name_fault(f"{run_id}.run-end.json")
    assert R.run_name_fault(f"{run_id}.run-end.json.staged-0a")
    too_long = R.run_name_fault("r" * 207)
    assert too_long, "a 207-byte name is a run name"
    assert "206" not in too_long, f"the run-id rule still counts bytes: {too_long!r}"
    assert not hasattr(R.RunPaths, "sidecar_owner")


def test_a_sidecar_shaped_label_is_refused_at_the_family_gate():
    """The xhigh review's case: a label that passes the view and run-id rules but makes the
    sibling id sidecar-shaped is refused with the manifest, not by every child. (#1224: the
    world-token alphabet admits no '.', so such a label is refused by that rule first.)"""
    from defender.runtime.branch import _family
    with pytest.raises(_family.FamilyError, match="world-token alphabet"):
        _family.check_identities(_family.parse_family(
            _family_doc("ep", "x.accounting_failures.json")))  # lint-stale-ref: ok — the reserved sidecar suffix, not the removed `RunPaths.accounting_failures()`


def test_a_long_printable_path_keeps_its_file_name_when_cut():
    """The xhigh review's case: a knowledge-folder refusal over a deep path must still name the
    entry to remove, so `shown` cuts the middle and keeps the start and the end."""
    from defender._shown import shown
    path = "agent/" + "skills/very-long-skill-folder-name/" * 4 + "file.md"
    text = shown(path)
    assert text.endswith("folder-name/file.md"), text
    assert text.startswith("agent/skills/"), text
    assert "chars)" in text, text
    assert len(text) < len(path), text


# -- the second xhigh review's findings ---------------------------------------------------------


def test_a_tenant_refusal_escapes_its_own_message(tmp_path):
    """`TenantRefused` escapes what it is built with, so a repository refusal that quotes a path
    stays one line under a data root whose path carries a newline. Positive control: the
    refusal still shows the path's characters, escaped.

    #1187 declared changes 6 and 8 (R1, S-iso): `Run.for_tenant`, the run handle's tenant
    check that raised it directly over a pre-#1187 id, goes with the tenant record; the
    refusal pinned is the repository's at a link at `tenant.runs` (`TenantRefused` or
    `RunRefused`, naming the level), for `runs.list` and `runs.open` of a UUID. (Name kept.)"""
    import uuid

    from defender._tenant import TenantRefused
    assert "\n" not in str(TenantRefused("a\nb\x1b[2J"))
    root = tmp_path / _FORGED / "data"
    root.mkdir(parents=True)
    t = H.tenant(root)
    os.symlink(tmp_path, t.runs)
    run_id = R.RunId.parse(str(uuid.uuid4()))
    for what, call in (("runs.list", lambda: t.runs_repository().list()),
                       ("runs.open", lambda: t.runs_repository().open(run_id))):
        with pytest.raises((TenantRefused, R.RunRefused)) as refused:
            call()
        assert "\n" not in str(refused.value), f"{what}: {refused.value}"
        assert "FORGED LINE" in str(refused.value), f"{what} does not show the path: {refused.value}"


def test_a_runs_folder_fault_above_the_folder_is_not_blamed_on_the_folder(tmp_path):
    """An ancestor that is a symlink loop or a file is reported as the hold's own reason, not
    as 'the runs folder is a link' or 'is not a directory'."""
    from defender._tenant import TenantRefused
    loop = tmp_path / "loop"
    os.symlink(loop, loop)
    plain = tmp_path / "plain"
    plain.write_text("x", encoding="utf-8")
    for folder in (loop / "runs", plain / "runs"):
        with pytest.raises(TenantRefused) as refused:
            R.hold_runs_folder(folder)
        text = str(refused.value)
        assert "is a link" not in text, text
        assert "is not a directory" not in text, text


def test_creating_a_runs_folder_under_a_dangling_ancestor_is_a_refusal(tmp_path):
    """With `create`, nothing but a refusal leaves the hold: a dangling ancestor makes the
    create fail, which is `TenantRefused`, not a raw `FileNotFoundError` run.py cannot catch."""
    from defender._tenant import TenantRefused
    os.symlink(tmp_path / "nowhere", tmp_path / "dangling")
    with pytest.raises(TenantRefused):
        R.hold_runs_folder(tmp_path / "dangling" / "runs", create=True)


def test_a_capped_read_keeps_the_read_limit(tmp_path):
    """`max_bytes` above the read limit cannot read past it: a file over the limit is refused
    as the whole read refuses it (a sparse file, so the disk holds nothing)."""
    big = tmp_path / "big"
    with big.open("wb") as fh:
        fh.truncate(_io.READ_LIMIT + 10)
    with _io.bind(tmp_path) as bound:
        whole = bound.read("big")
        capped = bound.read("big", max_bytes=_io.READ_LIMIT * 2)
    assert whole.text is None, "the whole read refuses a file over the limit"
    assert capped.text is None, "a cap above the limit read past it"
    assert capped.reason == whole.reason, (capped.reason, whole.reason)

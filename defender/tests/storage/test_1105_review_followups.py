"""Run-record repository: name rules, bounded reads, escaped refusals, runs-folder link handling."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

import os
import subprocess
import sys
import textwrap

import pytest

from defender import _io
from defender import records as R
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.storage.tenant_1105_run_repository import _spec1105 as H


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
    H.make_run(location_path(t.runs), run_id)
    probe = textwrap.dedent(f'''
        import sys
        class _Block:
            def find_spec(self, name, path=None, target=None):
                if name == "pydantic_ai" or name.startswith("pydantic_ai."):
                    raise ModuleNotFoundError(name)
        sys.meta_path.insert(0, _Block())
        from defender.tenancy import _tenant
        from pathlib import Path
        from defender import records as R
        root = _tenant.data_root_from_path(Path({str(tmp_path / "data")!r}))
        t = _tenant.accept_tenant(root, {t.id!r},
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
    control: once the folder and the run exist, the same open hands the run out."""
    import uuid

    t = H.tenant(tmp_path / "data")
    run_id = str(uuid.uuid4())
    with pytest.raises(R.RunAbsent) as absent:
        t.runs_repository().open(R.RunId.parse(run_id))
    assert absent.value.__context__ is None, repr(absent.value.__context__)
    H.make_run(location_path(t.runs), run_id)
    assert t.runs_repository().open(R.RunId.parse(run_id)).run_dir == location_path(t.runs) / run_id


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
    world = {"label": label, "world_id": T.fixture_world_id(label),
             "role": "A", "story": "s", "axis": None,
             "disposition_declared": "malicious", "label_basis": "policy-rule", "facts": []}
    # #1255 (D1, P4): `T.family_doc` writes the continuation prompt and the fence count only while
    # `Family` still declares them, so this stays about the bound on both sides.
    return T.family_doc(episode_id=episode_id, source_run_dir="/runs/src", source_run_id="src",
                        branch_message_id=1, as_of="2026-07-28T16:18:45Z", base_story="b",
                        served_systems=["elastic"], discriminator={"predicate": "p"},
                        worlds=[world])


def test_a_runs_folder_that_cannot_be_opened_is_not_called_a_link(tmp_path):
    """A hold failure other than a link says what the hold said (here: the name is too long),
    not 'it is a link … or not a directory'."""
    from defender.tenancy._tenant import TenantRefused
    with pytest.raises(TenantRefused) as refused:
        R.hold_runs_folder(tmp_path / ("x" * 300), create=True)
    assert "link" not in str(refused.value), str(refused.value)
    assert "too long" in str(refused.value), str(refused.value)


def test_run_setup_and_the_lookups_refuse_a_linked_runs_folder_in_the_same_words(tmp_path):
    """Run setup holds its runs folder with the repository's own opener, so one state has one
    message wherever it is met.

    #1279 (A3): run setup takes no id, so it reaches its runs folder with the id it mints."""
    from defender import run_common
    from defender.tenancy._tenant import TenantRefused
    t = H.tenant(tmp_path / "data")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    os.symlink(elsewhere, location_path(t.runs))
    alert = tmp_path / "a" / "alert.json"
    alert.parent.mkdir()
    alert.write_text('{"alert": 1}', encoding="utf-8")
    with pytest.raises(TenantRefused) as setup:
        run_common.materialize_run(alert, tenant=t)
    with pytest.raises(TenantRefused) as lookup:
        t.runs_repository().list()
    assert str(setup.value) == str(lookup.value), (str(setup.value), str(lookup.value))
    assert "is a link" in str(setup.value), str(setup.value)


def test_a_sidecar_shaped_label_is_refused_at_the_family_gate():
    from defender.runtime.branch import _family
    with pytest.raises(_family.FamilyError, match="world-label alphabet"):
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


def test_a_runs_folder_fault_above_the_folder_is_not_blamed_on_the_folder(tmp_path):
    """An ancestor that is a symlink loop or a file is reported as the hold's own reason, not
    as 'the runs folder is a link' or 'is not a directory'."""
    from defender.tenancy._tenant import TenantRefused
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
    from defender.tenancy._tenant import TenantRefused
    os.symlink(tmp_path / "nowhere", tmp_path / "dangling")
    with pytest.raises(TenantRefused):
        R.hold_runs_folder(tmp_path / "dangling" / "runs", create=True)

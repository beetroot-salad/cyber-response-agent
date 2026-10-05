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
    """With `pydantic_ai` unimportable, the record writer and every record reader answer over a
    runs folder holding a record (the review: they raised ModuleNotFoundError on first read)."""
    t = H.tenant(tmp_path / "data")
    H.runs_folder(t)
    H.make_run(t.runs, "r0")
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
        R.record_episode_runs(t, "ep", R.RunId.parse("r0"), {{"a": R.RunId.parse("ep-a")}})
        assert R.episode_runs(t, "ep") == {{"a": R.RunId.parse("ep-a")}}
        assert R.sibling_run_ids(t) == {{R.RunId.parse("ep-a")}}
        assert [str(i) for i in R.list_run_ids(t)] == ["r0"]
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


def test_a_row_refusal_under_a_folder_with_a_newline_stays_one_line(tmp_path):
    """The review's site: a `bound_runs` row read that is refused, under a runs folder whose
    path carries a newline."""
    t = H.tenant(tmp_path / _FORGED)
    runs = H.runs_folder(t)
    run = H.make_run(runs, "r1")
    (run / "alert.json").unlink()
    os.symlink(tmp_path / "elsewhere.json", run / "alert.json")
    with R.bound_runs(t) as rows:
        (_rid, row), = list(rows)
        with pytest.raises(R.RunRefused) as refused:
            row.read("alert.json")
    assert "\n" not in str(refused.value), str(refused.value)


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


def test_a_record_over_the_cap_cut_mid_character_is_refused_as_over(tmp_path):
    """The cap is judged on the file's size, not on what a prefix decodes to: a record one byte
    over the cap whose last character is multibyte says it is over, not that it is unreadable."""
    t = H.tenant(tmp_path / "data")
    runs = H.runs_folder(t)
    body = H.record_text("ep", t.id, "r0", {"a": "ep-a"})
    pad = H.RECORD_CAP - 1 - len(body.encode("utf-8"))
    raw = (body + " " * pad + "é").encode("utf-8")  # the cap's last byte starts the "é"
    assert len(raw) == H.RECORD_CAP + 1
    H.plant_record(runs, "ep", t.id, "r0", {}, raw=raw)
    with pytest.raises(R.RunRefused) as refused:
        R.episode_runs(t, "ep")
    assert f"over {H.RECORD_CAP} bytes" in str(refused.value), str(refused.value)


def test_another_tenants_record_is_a_record_mismatch_everywhere(tmp_path):
    """`_tenant.json` naming another tenant is `TenantRecordMismatch` — what `Run.for_tenant`
    raises — from the lookups and the listings alike, not a bare `TenantRefused`."""
    from defender._tenant import TenantRecordMismatch
    t = H.tenant(tmp_path / "data")
    runs = H.runs_folder(t)
    H.make_run(runs, "r0")
    H.plant_tenant_record(runs, H.U_ID)
    for call in (lambda: R.open_run(t, R.RunId.parse("r0")), lambda: R.list_run_ids(t),
                 lambda: R.run_exists(t, R.RunId.parse("r0")), lambda: R.sibling_run_ids(t)):
        with pytest.raises(TenantRecordMismatch):
            call()


def test_an_absent_runs_folder_refusal_carries_no_stale_error(tmp_path):
    """The absent folder's refusal is raised outside the open's `except`, so it carries no
    `FileNotFoundError` as its context (a traceback that blamed the wrong error)."""
    from defender._tenant import TenantRefused
    t = H.tenant(tmp_path / "data")
    with pytest.raises(TenantRefused) as refused:
        R.open_run(t, R.RunId.parse("r0"))
    assert refused.value.__context__ is None, repr(refused.value.__context__)


@pytest.mark.parametrize(("label", "reason"), [
    ("base", "reserved name"), ("family_3", "family_<n>"), ("Upper", "upper case"),
    ("a-b", "carries '-'"), ("a b", "cannot hold")])
def test_a_refused_label_says_which_rule_it_broke(tmp_path, label, reason):
    t = H.tenant(tmp_path / "data")
    runs = H.runs_folder(t)
    H.make_run(runs, "r0")
    with pytest.raises(R.RunRefused) as refused:
        R.record_episode_runs(t, "ep", R.RunId.parse("r0"), {label: R.RunId.parse("ep-a")})
    assert reason in str(refused.value), str(refused.value)


def test_the_writer_names_a_record_that_vanished_or_cannot_be_read():
    """The writer lost the create race and then judges the record that won: gone again, or
    unreadable, each refuses saying so (not as 'different content')."""
    from pathlib import Path

    from defender.run_repository import _record
    path = Path("/runs/_episodes/ep.json")
    gone = _io.RecordRead(name="ep.json", text=None, absent=True, reason=None)
    with pytest.raises(R.RunRefused, match="gone again"):
        _record._judge_existing(gone, "{}", path=path, episode_id="ep")
    bad = _io.RecordRead(name="ep.json", text=None, absent=False, reason="not utf-8")
    with pytest.raises(R.RunRefused, match="cannot be read"):
        _record._judge_existing(bad, "{}", path=path, episode_id="ep")

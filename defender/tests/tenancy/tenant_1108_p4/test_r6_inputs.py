"""#1108 P4: malformed inputs, each case a wrong-but-green production variant.

#1618: knowledge comes only from the fetch child (flow 1), so the clone, `materialise_export` and the publish
vocabulary are gone (K8, D11). Ported: a commit missing one half is refused at run start (was: a clone missing one), a
non-UTF-8 name is refused by the fetch (was: by materialise), and the run side never reads a garbage or multi-line
line as `ok`. Retired, with their successors: "materialise takes only a full commit id"
(`knowledge_1618/test_refusal_classes_1618.py::test_d11_a_commit_that_is_not_a_full_id_is_refused_lasting_*` and
`test_run_start.py::test_o_pin_knowledge_commit_accepts_only_a_full_commit_id`) and "the launcher never passes on a
garbage fresh line" (`test_r6_launcher.py::test_1618_a_child_whose_line_is_not_the_fetch_vocabulary_is_a_failed_child_*`).
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B
from defender.tests.tenancy.tenant_1108_p4._support import git, push_to_remote

OID = "0123456789abcdef0123456789abcdef01234567"


def _vc():
    from defender.learning.author import version_control
    return version_control


# --- a whitespace-led name below the first component -----------------------------------------

@pytest.mark.parametrize("path", ["agent/lessons/ x.md", "agent/lessons/\tx.md",
                                  "agent/ lessons/x.md", "agent/lessons/ "])
def test_r6_a_whitespace_led_component_below_agent_is_refused_whole(p4_tenant, path):
    vc = _vc()
    batch = p4_tenant.open_delivery().start_batch("r6", lanes=("lessons",))
    with pytest.raises((vc.DeliveryRefused, ValueError, TypeError)):
        batch.commit(vc.ChangeSet((vc.AgentChange("agent/lessons/ok.md", b"ok\n"),
                                   vc.AgentChange(path, b"x\n"))), "forbidden")


def test_r6_a_draft_file_with_a_whitespace_led_name_refuses_the_whole_change_set(p4_tenant):
    vc = _vc()
    batch = p4_tenant.open_delivery().start_batch("r6", lanes=("lessons",))
    lane = batch.draft_root / "agent" / "lessons"
    lane.mkdir(parents=True, exist_ok=True)
    (lane / "ok.md").write_text("ok\n", encoding="utf-8")
    (lane / " x.md").write_text("led by a space\n", encoding="utf-8")
    with pytest.raises(vc.DeliveryRefused):
        batch.change_set()


# --- a commit with only one half of the tree is still judged ---------------------------------------------------------

@pytest.mark.parametrize("half", ["settings", "agent"])
def test_r6_a_commit_missing_one_half_of_its_tree_is_refused_at_run_start(tmp_path, data_root, half):
    """`main` loses `agent/` or `settings/` in a merge: run start refuses rather than run on half a tree. Control: the
    same tenant's run before the merge reaches its box. (#1618: was "a clone missing one half".)"""
    with B.run_tenant(tmp_path, data_root) as t:
        control = B.launch(t, tmp_path / "control", fetch=B.fetching(t))
        assert control.reached, control.text()
        assert control.rc == 0, control.text()

        def drop(w: Path) -> None:
            git(w, "rm", "-r", "-q", half)

        push_to_remote(t.p3, t.scratch, drop, f"drop {half}/", stage=False)
        out = B.launch(t, tmp_path / "broken", fetch=B.fetching(t))
        assert not out.reached, f"a run started over a commit with no {half}/: {out.text()}"
        assert out.raised is None, out.text()


# --- garbage and multi-line reports are never ok ----------------------------------------------------------------------

@pytest.mark.parametrize("line", ["ok notanoid", "ok abc123", f"ok {OID.upper()}", f"ok {OID}0", f"ok {OID} extra",
                                  "ok", f"ok {OID}\nok {OID}", f"ok {OID}\rmore",
                                  "refused transient a\nrefused lasting b", "refused a",
                                  f"fresh {OID}", "stale:transient a", "misconfigured a"])
def test_r6_read_publish_report_never_reads_garbage_or_multiple_lines_as_ok(line):
    """The run side re-reads the line (it may come from any seam): a garbage, multi-line or retired-vocabulary line (K9:
    `fresh`, `stale:*`, `misconfigured`) is the failed child, a lasting refusal with no commit. Control: `ok <oid>`."""
    from defender.tenancy.run_knowledge import OK, REFUSED, read_publish_report

    report = read_publish_report(line)
    assert report.kind == REFUSED, report
    assert report.kind != OK
    assert report.commit is None
    assert not report.transient, report
    assert "fetch child failed" in (report.reason or ""), report
    assert read_publish_report(f"ok {OID}").commit == OID, "control"


# --- a non-UTF-8 name in a merged tree is refused, not merged ---------------------------------------------------------

def test_r6_a_commit_holding_a_non_utf8_name_is_refused_by_the_fetch(p4_tenant, tmp_path):
    """Two names a lossy decode would merge: the fetch refuses the commit as lasting, leaving its folder empty.
    Control: the earlier good commit fetches by id. (#1618: was "refused by materialise".)"""
    t = p4_tenant

    def edit(w: Path) -> None:
        lessons = os.fsencode(w / "agent" / "lessons")
        for name in (b"bad-\xff.md", b"bad-\xfe.md"):  # two names a lossy decode would merge
            with open(os.path.join(lessons, name), "wb") as f:
                f.write(name)
        git(w, "add", "-A")

    commit = push_to_remote(t.p3, t.scratch, edit, "a merged non-UTF-8 name", stage=False)
    fetch = B.fetching(t)
    dest = tmp_path / "copy"
    dest.mkdir()
    line = fetch(t.tenant_id, dest, data_root=t.data_root, commit=commit)
    assert line.startswith("refused lasting "), line
    assert sorted(os.listdir(dest)) == [], "refused content was left in the folder"
    good = tmp_path / "good"
    good.mkdir()
    assert fetch(t.tenant_id, good, data_root=t.data_root, commit=t.commit) == f"ok {t.commit}", "control"

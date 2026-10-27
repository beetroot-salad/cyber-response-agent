"""#1108 P4 round 6 — malformed inputs the earlier rounds never fed (each case was a
wrong-but-green production variant): a whitespace-led name below `agent/`, a half-present clone
tree, a malformed forge binding, a malformed commit id handed to materialise, garbage and
multi-line publish reports (launcher and run side), and a non-UTF-8 name in a published tree."""
from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

import pytest

from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B
from defender.tests.tenancy.tenant_1108_p4._support import (
    _row_path,
    current_commit,
    export_dir,
    git,
    push_to_remote,
)
from defender.records._tenant_id import TenantRefused

OID = "0123456789abcdef0123456789abcdef01234567"


def _vc():
    from defender.learning.author import version_control
    return version_control


# --- inputs-02: a whitespace-led name below the first component -------------------------------

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


# --- inputs-06: a clone with only one half of the working tree is still judged ----------------

@pytest.mark.parametrize("half", ["settings", "agent"])
def test_r6_a_clone_missing_one_half_of_its_tree_is_refused_at_run_start(
        tmp_path, data_root, half):
    with B.run_tenant(tmp_path, data_root) as t:
        control = B.launch(t, tmp_path / "control", publish=lambda *a, **k: B.fresh(t.commit))
        assert control.reached, control.text()
        assert control.rc == 0, control.text()
        shutil.rmtree(Path(t.clone) / half)
        out = B.launch(t, tmp_path / "broken", publish=lambda *a, **k: B.fresh(t.commit))
        assert not out.reached, f"a run started over a clone with no {half}/: {out.text()}"


# --- inputs-07: a forge binding with an empty or non-string field ------------------------------

@pytest.mark.parametrize("field", ["origin", "audience", "issuer_role", "issuer_config"])
@pytest.mark.parametrize("bad", ["", None, 7, ["x"]])
def test_r6_a_forge_binding_with_an_empty_or_non_string_field_is_refused(p4_tenant, field, bad):
    from defender.tenancy import _tenant
    from defender.tests.tenancy.tenant_1108_p4._support import bind_forge

    binding = bind_forge(p4_tenant)
    assert _tenant.read_forge_binding(p4_tenant.tenant).origin == binding["origin"], "control"
    path = _row_path(p4_tenant)
    row = json.loads(path.read_text(encoding="utf-8"))
    row["forge"][field] = bad
    path.write_text(json.dumps(row), encoding="utf-8")
    with pytest.raises(TenantRefused):
        _tenant.read_forge_binding(p4_tenant.tenant)


def test_r6_a_forge_binding_naming_a_relative_issuer_config_is_refused(p4_tenant):
    """The binding names its tenant's issuer client config by an absolute path: a relative
    one would resolve against whatever directory a delivery process happens to run in."""
    from defender.tenancy import _tenant
    from defender.tests.tenancy.tenant_1108_p4._support import bind_forge

    bind_forge(p4_tenant)
    path = _row_path(p4_tenant)
    row = json.loads(path.read_text(encoding="utf-8"))
    row["forge"]["issuer_config"] = "playground-issuer/client/issuer.json"
    path.write_text(json.dumps(row), encoding="utf-8")
    with pytest.raises(TenantRefused, match="relative issuer_config"):
        _tenant.read_forge_binding(p4_tenant.tenant)


# --- inputs-08 / inputs-09: materialise takes only a full lowercase commit id -------------------

@pytest.mark.parametrize("commit", ["../drafts", "..", "a/b", "abcd", "abcdef0123456789",
                                    "A" * 40, "0" * 41, "0" * 63, "0" * 65, ""])
def test_r6_materialise_refuses_anything_but_a_full_commit_id(p4_tenant, commit):
    exports = export_dir(p4_tenant.tenant, p4_tenant.commit).parent
    before = sorted(os.listdir(exports))
    with pytest.raises(_vc().DeliveryRefused, match="not a full commit id"):
        _vc().materialise_export(p4_tenant.tenant, commit)
    assert sorted(os.listdir(exports)) == before
    assert current_commit(p4_tenant.tenant) == p4_tenant.commit


# --- inputs-24 / 26 / 27, surfaces-30 / 31: garbage and multi-line reports are never fresh -----

@pytest.mark.parametrize("line", ["fresh notanoid", "fresh abc123", f"fresh {OID.upper()}",
                                  f"fresh {OID}0", f"fresh {OID} extra", "fresh",
                                  f"fresh {OID}\nfresh {OID}", f"fresh {OID}\rmore",
                                  "stale:transient a\nstale:operator b", "misconfigured a\nb"])
def test_r6_read_publish_report_never_reads_garbage_or_multiple_lines_as_fresh(line):
    from defender.tenancy.run_knowledge import FRESH, read_publish_report

    report = read_publish_report(line)
    assert report.kind != FRESH, report
    assert report.commit is None
    if "\n" in line or "\r" in line or line.startswith("fresh"):
        assert (report.kind, report.stale_kind) == ("stale", "operator"), report
        assert "publish child failed" in (report.reason or ""), report
    assert read_publish_report(f"fresh {OID}").commit == OID, "control"


@pytest.mark.parametrize("said", ["fresh notanoid", "fresh abc123", f"fresh {OID.upper()}",
                                  f"fresh {OID} extra", "fresh"])
def test_r6_the_launcher_never_passes_on_a_garbage_fresh_line(tenant_id_only, said):
    """A child that exits 0 printing `said` is a failed child, `stale:operator`, from the launcher
    itself (the run side re-validates, so only the launcher's own line shows this)."""
    from defender.investigation.publish_launch import launch_publish

    tenant_id, root = tenant_id_only
    line = launch_publish(tenant_id, data_root=root, budget=30.0,
                          command=[sys.executable, "-c", f"print({said!r})"])
    assert line.startswith("stale:operator publish child failed"), line


@pytest.fixture
def tenant_id_only(tmp_path):
    return "r6-tenant", tmp_path


# --- inputs-51: a non-UTF-8 name in a published tree is refused, not merged --------------------

def test_r6_a_commit_holding_a_non_utf8_name_is_refused_by_materialise(p4_tenant):
    t = p4_tenant

    def edit(w: Path) -> None:
        lessons = os.fsencode(w / "agent" / "lessons")
        for name in (b"bad-\xff.md", b"bad-\xfe.md"):  # two names a lossy decode would merge
            with open(os.path.join(lessons, name), "wb") as f:
                f.write(name)
        git(w, "add", "-A")

    commit = push_to_remote(t.p3, t.scratch, edit, "a merged non-UTF-8 name", stage=False)
    git(t.clone, "fetch", str(t.remote), "+refs/heads/main:refs/remotes/origin/main")
    with pytest.raises(_vc().DeliveryRefused):
        _vc().materialise_export(t.tenant, commit)
    assert not export_dir(t.tenant, commit).exists()
    assert current_commit(t.tenant) == t.commit

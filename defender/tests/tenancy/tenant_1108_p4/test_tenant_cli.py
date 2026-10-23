"""#1108 P4 slice S-C — O-SEE: the operator can see a stalled publish.

- `tenant.py update <id>` (new) publishes: fetch, fast-forward, export, swap `current`.
- `tenant.py check <id>` also reports how far `current` trails `origin/main` and the last publish
  refusal — `stale:operator` causes (a merged commit refused on content, `main` unprotected) and a
  sealed issuer alike — so a stalled publish is visible, not silent.

Entry: `defender/cli/tenant.py`'s own functions (`update`, `check_tenant`), whose refusals and
findings are printed `[tenant.py] ...` on stderr (captured). The tenant is S0's fixture tenant,
published for real over P3's delivery path (`p4_tenant`), its forge and issuer the P3 fakes.

ASSUMED SEAMS (reported; the implementer provides them): `update(tenant_id, *, client=, identity=)`
— `client` the forge HTTP client, `identity` standing in for the issuer config file + AppRole
login (`TenantDelivery.open`'s own keywords). `check_tenant(tenant_id)` takes none: it reads local
state only. The forge binding is written into the tenant row as the design's data model spells it
(`forge: {origin, audience, issuer_role}`) through S0's `bind_forge`.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest

from defender.tests.tenancy.tenant_1108_delivery._identity import VaultHTTP
from defender.tests.tenancy.tenant_1108_p4._support import (
    bind_forge,
    current_commit,
    export_dir,
    git,
    index_entry,
    push_to_remote,
)

LINK_PATH = "agent/lessons/evil.md"


def _cli() -> Any:
    from defender.cli import tenant

    return tenant


def _update(p4: Any, capsys, *, identity: Any = None) -> tuple[int, list[str]]:
    capsys.readouterr()
    rc = _cli().update(p4.tenant_id, client=p4.forge.client,
                       identity=identity if identity is not None else p4.identity)
    return rc, _said(capsys)


def _check(p4: Any, capsys) -> list[str]:
    capsys.readouterr()
    _cli().check_tenant(p4.tenant_id)
    return _said(capsys)


def _said(capsys) -> list[str]:
    captured = capsys.readouterr()
    return [line for line in (captured.err + captured.out).splitlines() if line.strip()]


def _new(after: list[str], before: list[str]) -> list[str]:
    return [line for line in after if line not in before]


def _trails_by(lines: list[str], n: int) -> list[str]:
    """Lines reporting a trail of `n` commits: the count as a whole number beside `commit`."""
    return [line for line in lines
            if re.search(rf"(?<![\w.]){n}(?![\w.])", line) and "commit" in line.lower()]


def _sealed_identity(p4: Any) -> Any:
    vault = VaultHTTP(p4.tenant_id)
    vault.status = 503
    vault.body = {"errors": ["Vault is sealed"]}
    return vault.identity()


def test_o_see_tenant_py_has_an_update_command():
    """O-SEE: `tenant.py update` exists (today `update` is not a command: argparse exits 2)."""
    with pytest.raises(SystemExit) as done:
        _cli().main(["update", "--help"])
    assert done.value.code == 0, "tenant.py has no `update` command"


def test_o_see_tenant_py_update_publishes_the_merged_main(p4_tenant, capsys):
    """O-SEE / flow 1: `tenant.py update` publishes — after a merge on the origin, `current`
    names the merged commit and its export exists."""
    bind_forge(p4_tenant)
    before = p4_tenant.commit
    merged = p4_tenant.merge({"agent/lessons/merged-by-a-human.md":
                              "---\nname: merged-by-a-human\n---\n\nA reviewed lesson.\n"})
    assert current_commit(p4_tenant.tenant) == before, "positive control: nothing published yet"

    rc, said = _update(p4_tenant, capsys)
    assert rc == 0, said
    assert current_commit(p4_tenant.tenant) == merged, (
        "O-SEE: `tenant.py update` did not publish the merged `main`")
    assert (export_dir(p4_tenant.tenant, merged) / "agent" / "lessons"
            / "merged-by-a-human.md").is_file()


def test_o_see_check_reports_the_trail_and_a_content_refusal_until_a_publish_catches_up(
        p4_tenant, capsys):
    """O-SEE (`stale:operator`, a merged commit refused on content): after two merges whose tip
    holds a link, `update` refuses visibly; `check` then reports `current` trailing
    `origin/main` by 2 commits and names the refused path. Once a fix is merged and published,
    `check` reports no trail and no longer names the old refusal (the last publish succeeded)."""
    bind_forge(p4_tenant)
    published = p4_tenant.commit
    clean = _check(p4_tenant, capsys)
    assert _trails_by(clean, 2) == [], f"positive control: no trail reported yet: {clean}"
    assert not any(LINK_PATH in line for line in clean), f"positive control: {clean}"

    p4_tenant.merge({"agent/lessons/fine.md": "---\nname: fine\n---\n\nFine.\n"})
    push_to_remote(p4_tenant.p3, p4_tenant.scratch,
                   lambda w: index_entry(w, "120000", LINK_PATH, data=b"/etc/passwd"),
                   "a link merged by a human", stage=False)

    rc, said = _update(p4_tenant, capsys)
    assert rc != 0, f"`tenant.py update` published a commit holding a link: {said}"
    assert any(LINK_PATH in line for line in said), (
        f"`tenant.py update`'s refusal does not name the refused path: {said}")
    assert current_commit(p4_tenant.tenant) == published, "the refused publish moved `current`"
    assert git(p4_tenant.clone, "rev-list", "--count",
               f"{published}..refs/remotes/origin/main") == "2", "fixture: the fetch landed"

    stalled = _new(_check(p4_tenant, capsys), clean)
    assert _trails_by(stalled, 2), (
        f"O-SEE: `check` does not report `current` trailing `origin/main` by 2 commits: {stalled}")
    assert any(LINK_PATH in line for line in stalled), (
        f"O-SEE: `check` does not report the last publish refusal (the refused link): {stalled}")

    fixed = p4_tenant.merge({LINK_PATH: None}, "remove the link")
    rc, said = _update(p4_tenant, capsys)
    assert rc == 0, said
    assert current_commit(p4_tenant.tenant) == fixed, said
    caught_up = _check(p4_tenant, capsys)
    for n in (1, 2, 3):
        assert _trails_by(caught_up, n) == [], (
            f"O-SEE: `check` still reports a trail after the publish caught up: {caught_up}")
    assert not any(LINK_PATH in line for line in caught_up), (
        "O-SEE: `check` still reports the old link refusal after a later publish succeeded "
        f"(the last publish was not refused): {caught_up}")


def test_o_see_check_reports_an_unprotected_main_refusal(p4_tenant, capsys):
    """O-SEE (`stale:operator`, `main` unprotected): the refusal `update` meets is visible in
    `check` afterwards, as a line `check` did not print before it."""
    bind_forge(p4_tenant)
    before = _check(p4_tenant, capsys)

    p4_tenant.forge.protection = {"name": "main", "protected": False, "user_can_push": True}
    rc, said = _update(p4_tenant, capsys)
    assert rc != 0, f"`tenant.py update` published with `main` unprotected: {said}"

    after = _new(_check(p4_tenant, capsys), before)
    assert any("protect" in line.lower() for line in after), (
        f"O-SEE: `check` does not report the unprotected-`main` publish refusal: {after}")


def test_o_see_check_reports_a_sealed_issuer_refusal(p4_tenant, capsys):
    """O-SEE (`stale:transient`, a sealed issuer): publishing stops while the issuer is sealed
    (accepted), and `check` makes that visible: after `update` meets the sealed issuer, `check`
    reports the refusal naming the issuer, as a line it did not print before it."""
    bind_forge(p4_tenant)
    before = _check(p4_tenant, capsys)
    words = ("issuer", "identity", "vault", "openbao", "sealed")

    rc, said = _update(p4_tenant, capsys, identity=_sealed_identity(p4_tenant))
    assert rc != 0, f"`tenant.py update` published with the issuer sealed: {said}"
    assert current_commit(p4_tenant.tenant) == p4_tenant.commit

    after = _new(_check(p4_tenant, capsys), before)
    assert any(w in line.lower() for line in after for w in words), (
        f"O-SEE: `check` does not report the sealed-issuer publish refusal: {after}")


# ---------------------------------------------------------------------------------------------
# Every publish trigger feeds `check` (R-S3): the launch-time child and the drain start, not only
# `tenant.py update`.
# ---------------------------------------------------------------------------------------------

def _issuer_config(tmp_path: Path) -> Path:
    from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B

    return B.write_issuer_config(tmp_path / "operator")


def test_o_see_check_names_an_unprotected_main_met_by_the_launch_time_child(
        p4_tenant, tmp_path, capsys):
    """O-SEE: a launch-time publish (the child's in-process entry `publish_for_run`, S-B's seam)
    that meets an unprotected `main` reports `stale:operator`, and `check` afterwards names the
    refusal — a run launch is a publish trigger whose refusal must not stay silent."""
    from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B

    bind_forge(p4_tenant)
    config = _issuer_config(tmp_path)
    before = _check(p4_tenant, capsys)

    p4_tenant.forge.protection = {"name": "main", "protected": False, "user_can_push": True}
    line = B.run_child(p4_tenant, config)
    assert B.outcome_class(line) == "stale:operator", line

    after = _new(_check(p4_tenant, capsys), before)
    assert any("protect" in entry.lower() for entry in after), (
        f"O-SEE: `check` does not name the refusal the launch-time publish met: {after}")


def test_o_see_check_names_a_merged_link_refused_by_the_launch_time_child(
        p4_tenant, tmp_path, capsys):
    """O-SEE: a launch-time publish refused on content (a merged link) leaves `check` reporting
    the trail of 1 commit and the refused path."""
    from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B

    bind_forge(p4_tenant)
    config = _issuer_config(tmp_path)
    before = _check(p4_tenant, capsys)
    assert _trails_by(before, 1) == [], f"positive control: {before}"

    push_to_remote(p4_tenant.p3, p4_tenant.scratch,
                   lambda w: index_entry(w, "120000", LINK_PATH, data=b"/etc/passwd"),
                   "a link merged by a human", stage=False)
    line = B.run_child(p4_tenant, config)
    assert B.outcome_class(line) == "stale:operator", line
    assert current_commit(p4_tenant.tenant) == p4_tenant.commit

    after = _new(_check(p4_tenant, capsys), before)
    assert _trails_by(after, 1), f"O-SEE: `check` reports no trail of 1 commit: {after}"
    assert any(LINK_PATH in entry for entry in after), (
        f"O-SEE: `check` does not name the link the launch-time publish refused: {after}")


def test_o_see_check_names_an_unprotected_main_met_at_drain_start(
        p4_tenant, tmp_path, capsys, monkeypatch):
    """O-SEE: a drain whose start-of-tick publish meets an unprotected `main` refuses (O9, S-D's
    drain seams), and `check` afterwards names that refusal."""
    from defender.tests.support.learning.curation import _spec773 as S
    from defender.tests.tenancy.tenant_1108_p4._drain_support import (
        LESSON_NAME,
        BoxSpy,
        CuratorTrigger,
        author_drain,
        drain_paths,
        product_repo,
        queue,
    )

    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
    monkeypatch.setenv("LEARNING_QUESTIONER_THRESHOLD", "1")
    bind_forge(p4_tenant)
    before = _check(p4_tenant, capsys)

    p4_tenant.forge.protection = {"name": "main", "protected": False, "user_can_push": True}
    paths = drain_paths(p4_tenant, product_repo(tmp_path))
    queue(paths, [S.finding_row("f1", run_id="f1")])
    trigger = CuratorTrigger(author=S.FakeCurator(writes={LESSON_NAME: S.lesson("f1")}))
    rc = author_drain(p4_tenant, paths, trigger=trigger, box=BoxSpy())
    assert rc == 2, f"the drain did not refuse an unprotected `main` (rc={rc})"

    after = _new(_check(p4_tenant, capsys), before)
    assert any("protect" in entry.lower() for entry in after), (
        f"O-SEE: `check` does not name the refusal the drain-start publish met: {after}")

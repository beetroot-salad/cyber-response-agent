"""#1108 P4 slice S-D — flow 6 (connect's two-repo split) and O7 (connect's tenant half goes through
`TenantDelivery`): the adapter is staged in the product repo; the system skill, seed queries and
tacit entries are staged in a host directory; `tenant.py propose` turns that directory into a
`ChangeSet` -> commit-maker -> PR touching `agent/` only; `validate_scaffold` checks the staged
tenant half. Plus connect's model-facing instructions for that split (S-A owns the generic
model-text lint; this file owns connect's specific two-repo instructions).

ASSUMED SEAMS / SHAPES (reported; the implementer provides them):
  - `defender.cli.tenant.propose(tenant_id, staged: Path, *, client=None, identity=None) -> int`
    (the CLI verb `tenant.py propose <tenant> <dir>`), keywords as S-C's `update`. Refusals
    print `[tenant.py] ...` (the file's `_say`) and return non-zero.
  - The staged directory is shaped like the tenant's `agent/` root: `<dir>/skills/<system>/...`
    lands as `agent/skills/<system>/...`. Files are added or replaced; nothing absent from the
    staged directory is deleted (connect proposes one system's files, never the corpus).
  - `validate_scaffold.py <system> --tenant <T> --staged <dir>`: the skill and template checks
    read the staged directory (agent-root-shaped), the adapter checks the product repo.
"""
from __future__ import annotations

import importlib
import os
import re
import subprocess
import sys
from pathlib import Path
from collections.abc import Mapping
from typing import Any

import pytest

from defender._git import REPO_ROOT
from defender.tests.support.shared._locations_1210 import location_path
from defender.tests.tenancy.tenant_1108_p4._support import (
    DEFENDER,
    FIXTURE_AGENT,
    bind_forge,
    git,
)
from defender.tests.tenancy.tenant_1108_p4.test_drains import remote_branches, touched

SYSTEM = "acme-cmdb"
CONNECT = DEFENDER / "skills" / "connect"
STAGED_FILES = {
    f"skills/{SYSTEM}/SKILL.md": (
        f"---\nname: defender-{SYSTEM}\ndescription: Made-up CMDB for the P4 connect case.\n---\n\n"
        "# Visibility\n\nHost ownership only.\n\n## Execution\n\nSee execution.md.\n"),
    f"skills/{SYSTEM}/execution.md": "# Execution\n\nCall `list_verbs`.\n",
    f"skills/gather/queries/{SYSTEM}/host-owner.md": (
        f"---\nid: {SYSTEM}.host-owner\nverb: get-host\nparams: [host]\n---\n\n# Goal\n\nOwner.\n"),
    "skills/tacit-knowledge/registry.yaml": "entries: []\n# acme sanction pending review\n",
}


def _tenant_cli() -> Any:
    return importlib.import_module("defender.cli.tenant")


def _stage(root: Path, files: Mapping[str, str | bytes]) -> Path:
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content.encode() if isinstance(content, str) else content)
    return root


def _propose(t: Any, staged: Path) -> int:
    return _tenant_cli().propose(t.tenant_id, staged, client=t.forge.client,
                                 identity=t.vault.identity())


def _product_trace() -> dict:
    """What a product-repo landing of connect's tenant half would move: the system's folders
    in this checkout and any `connect/` branch."""
    return {
        "status": git(REPO_ROOT, "status", "--porcelain", "--untracked-files=all", "--",
                      f"defender/skills/{SYSTEM}", f"defender/skills/gather/queries/{SYSTEM}"),
        "refs": git(REPO_ROOT, "for-each-ref", "--format=%(refname)", "refs/heads/connect/"),
    }


# ---------------------------------------------------------------------------------------------
# tenant.py propose
# ---------------------------------------------------------------------------------------------


def test_flow6_propose_turns_a_staged_directory_into_one_agent_only_pr_on_the_tenant_forge(
        p4_tenant, tmp_path, capsys):
    """Flow 6 / O7: `propose` over the staged tenant half commits exactly the staged files, under
    `agent/`, as commit-maker commits on a branch of the tenant clone off the origin's `main`,
    pushes it to the tenant origin and opens one PR against `main` on the tenant forge. Nothing
    else in `agent/` changes, the clone stays clean on `main`, and the product checkout gains
    neither the system's files nor a `connect/` branch."""
    t = p4_tenant
    bind_forge(t)
    staged = _stage(tmp_path / "staged", STAGED_FILES)
    main = t.origin_main()
    product = _product_trace()

    rc = _propose(t, staged)

    assert rc == 0, capsys.readouterr()
    new = {b: tip for b, tip in remote_branches(t.remote, prefix="").items() if b != "main"}
    assert len(new) == 1, new
    (branch, tip), = new.items()
    assert git(t.remote, "merge-base", tip, "refs/heads/main") == main
    assert touched(t.remote, main, tip) == sorted(f"agent/{rel}" for rel in STAGED_FILES)
    for rel, content in STAGED_FILES.items():
        assert git(t.remote, "show", f"{tip}:agent/{rel}") + "\n" == content, rel
    assert [(c["head"], c["base"]) for c in t.forge.creates] == [(branch, "main")]
    assert git(t.clone, "symbolic-ref", "HEAD") == "refs/heads/main"
    assert git(t.clone, "status", "--porcelain", "--untracked-files=all") == ""
    assert _product_trace() == product


@pytest.mark.parametrize("plant", ["tenant-id", "symlink"])
def test_flow6_propose_refuses_a_staged_entry_a_change_set_cannot_carry(p4_tenant, tmp_path,
                                                                      capsys, plant):
    """Flow 6 / amendment 2 O-C: a staged directory holding `.tenant-id` or a link is
    refused whole — non-zero, the refusal naming the entry — and nothing is committed, pushed or
    opened. (Control: the previous case proposes the same files without the planted entry.)"""
    t = p4_tenant
    bind_forge(t)
    staged = _stage(tmp_path / "staged", STAGED_FILES)
    entry = {"tenant-id": ".tenant-id", "symlink": f"skills/{SYSTEM}/linked.md"}[plant]
    if plant == "tenant-id":
        (staged / entry).write_text("00000000-0000-0000-0000-000000000000\n", encoding="utf-8")
    else:
        os.symlink("/etc/passwd", staged / entry)
    refs = git(t.remote, "for-each-ref", "--format=%(refname) %(objectname)")
    clone_refs = git(t.clone, "for-each-ref", "--format=%(refname) %(objectname)")
    capsys.readouterr()

    rc = _propose(t, staged)

    said = capsys.readouterr()
    assert rc != 0
    assert Path(entry).name in said.err + said.out, said
    assert t.forge.creates == []
    assert git(t.remote, "for-each-ref", "--format=%(refname) %(objectname)") == refs
    assert git(t.clone, "for-each-ref", "--format=%(refname) %(objectname)") == clone_refs


# ---------------------------------------------------------------------------------------------
# validate_scaffold checks the staged tenant half
# ---------------------------------------------------------------------------------------------

#: A system whose adapter ships in the product repo (adapters stay there, #1172).
ADAPTER_SYSTEM = "cmdb"


def _validate(t: Any, staged: Path) -> tuple[int, list[str]]:
    env = {**os.environ, "PYTHONPATH": str(DEFENDER.parent),
           "DEFENDER_DATA_ROOT": str(location_path(t.data_root))}
    proc = subprocess.run(
        [sys.executable, str(CONNECT / "validate_scaffold.py"), ADAPTER_SYSTEM,
         "--tenant", t.tenant_id, "--staged", str(staged)],
        env=env, capture_output=True, text=True, timeout=300, check=False)
    return proc.returncode, (proc.stdout + proc.stderr).splitlines()


def _rows(lines: list[str], mark: str, needle: str) -> list[str]:
    return [line for line in lines if f"[{mark}]" in line and needle in line]


def _staged_cmdb(root: Path, *, skill: str | None) -> Path:
    files: dict[str, str | bytes] = {
        f"skills/{ADAPTER_SYSTEM}/execution.md":
            (FIXTURE_AGENT / "skills" / ADAPTER_SYSTEM / "execution.md").read_bytes(),
        f"skills/gather/queries/{ADAPTER_SYSTEM}/host-owner.md":
            (FIXTURE_AGENT / "skills/gather/queries" / ADAPTER_SYSTEM / "host-owner.md").read_bytes(),
    }
    if skill is not None:
        files[f"skills/{ADAPTER_SYSTEM}/SKILL.md"] = skill
    return _stage(root, files)


def test_flow6_validate_scaffold_judges_the_staged_skill_not_a_product_tree_copy(p4_tenant, tmp_path):
    """Flow 6: the scaffold validator reads the per-system skill from the STAGED tenant half: a
    staged `SKILL.md` naming the wrong skill FAILs, and one that is missing FAILs as missing,
    whatever the product checkout holds; a correct staged one PASSes (control: the same row read
    the same way)."""
    t = p4_tenant
    good = (FIXTURE_AGENT / "skills" / ADAPTER_SYSTEM / "SKILL.md").read_text(encoding="utf-8")
    wrong = re.sub(r"(?m)^name:.*$", "name: defender-not-cmdb", good)

    _rc, ok = _validate(t, _staged_cmdb(tmp_path / "good", skill=good))
    rc_wrong, bad = _validate(t, _staged_cmdb(tmp_path / "wrong", skill=wrong))
    rc_missing, missing = _validate(t, _staged_cmdb(tmp_path / "missing", skill=None))

    assert _rows(ok, "✓", f"skills/{ADAPTER_SYSTEM}/SKILL.md"), ok
    assert rc_wrong != 0, bad
    assert _rows(bad, "✗", f"skills/{ADAPTER_SYSTEM}/SKILL.md"), bad
    assert rc_missing != 0, missing
    assert _rows(missing, "✗", "missing"), missing


# ---------------------------------------------------------------------------------------------
# Connect's model-facing instructions (O-TEXT, connect's two-repo split)
# ---------------------------------------------------------------------------------------------

#: The product skills O1 keeps in `defender/skills/`; anything else there is tenant knowledge.
PRODUCT_SKILLS = ("gather", "invlang", "handbook", "advisory", "connect")
#: A product-tree spelling of tenant knowledge: a system skill, the query catalog, the tacit
#: registry under `defender/skills/`.
_TENANT_IN_PRODUCT = re.compile(
    r"defender/skills/(?:gather/queries\b|(?!(?:" + "|".join(PRODUCT_SKILLS) + r")\b)[\w{}-]+)")


def _connect_docs() -> dict[str, str]:
    return {p.name: p.read_text(encoding="utf-8") for p in sorted(CONNECT.glob("*.md"))}


def test_flow6_connect_never_tells_the_model_to_write_tenant_knowledge_into_the_product_repo():
    """Flow 6 / O-TEXT: no connect page names a product-tree home for tenant knowledge (a
    `defender/skills/<system>/` folder, `defender/skills/gather/queries/`, the tacit registry
    under `defender/skills/`). Positive control: the same matcher finds such a spelling in a line
    written the old way, and passes the product skills and the adapter's product path."""
    assert _TENANT_IN_PRODUCT.search("git add defender/skills/{system}/")
    assert _TENANT_IN_PRODUCT.search("defender/skills/gather/queries/{system}/")
    assert _TENANT_IN_PRODUCT.search("git add defender/skills/tacit-knowledge/registry.yaml")
    assert not _TENANT_IN_PRODUCT.search(
        "defender/skills/connect/validate_scaffold.py defender/skills/gather/query-schema.md "
        "defender/integrations/{system}_adapter.py")

    hits = [f"{name}:{n}: {line.strip()}" for name, text in _connect_docs().items()
            for n, line in enumerate(text.splitlines(), 1) if _TENANT_IN_PRODUCT.search(line)]
    assert hits == [], "connect still homes tenant knowledge in the product repo:\n" + "\n".join(hits)


def test_flow6_connect_routes_the_tenant_half_through_propose_and_keeps_the_adapter_in_product():
    """Flow 6: connect's main page and its tacit route both hand the tenant half to `tenant.py
    propose` (a staged directory, never a branch of the product repo), every scaffold-validator
    call passes the staged directory, and the adapter is still written into the product repo's
    `defender/integrations/`."""
    docs = _connect_docs()
    for name in ("SKILL.md", "tacit.md"):
        assert re.search(r"tenant\.py propose\b", docs[name]), f"{name} never routes through propose"
    assert "defender/integrations/{system}_adapter.py" in docs["SKILL.md"]
    calls = [line for text in docs.values() for line in text.splitlines()
             if "validate_scaffold.py" in line and "{system}" in line]
    assert calls, "control: connect runs the scaffold validator"
    assert all("--staged" in line for line in calls), calls

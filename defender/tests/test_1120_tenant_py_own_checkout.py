"""#1120 piece 1 — `tenant.py` imports the checkout it runs from, even when another checkout
comes first on `PYTHONPATH` (claims adversary, second pass on PR #1157: the old guard only
added this checkout when it was absent, so an earlier entry won). `defender` is a namespace
tree, so each module comes from the first path entry that holds it."""
from __future__ import annotations

import os
from pathlib import Path

from defender.scripts import tenant as tenant_py
from defender.tests.tenant_1120_piece1 import _spec1120 as H


def test_a_decoy_tree_earlier_on_pythonpath_is_not_imported(tmp_path: Path) -> None:
    """A decoy checkout — a `defender/` namespace tree whose `_tenant` refuses to import —
    placed BEFORE this checkout on `PYTHONPATH`: `check --folder` over the fixture still runs
    this checkout's code and exits 0. The precondition: with that path, a plain
    `import defender._tenant` does reach the decoy."""
    decoy = tmp_path / "decoy"
    (decoy / "defender").mkdir(parents=True)
    (decoy / "defender" / "_tenant.py").write_text(
        "raise ImportError('the decoy tree was imported')\n", encoding="utf-8")
    pythonpath = f"{decoy}{os.pathsep}{H.REPO_ROOT}"
    probe = decoy / "probe.py"
    probe.write_text("import defender._tenant\n", encoding="utf-8")
    shadowed = H.run_script(probe, root=None, PYTHONPATH=pythonpath)
    assert "the decoy tree was imported" in H.output(shadowed), (
        "precondition: the decoy does not shadow the checkout")

    root = tmp_path / "root"
    H.place_knowledge(root)
    H.assert_clean(H.check(tenant_py, None, "--folder", str(H.knowledge_dir(root)),
                           PYTHONPATH=pythonpath))

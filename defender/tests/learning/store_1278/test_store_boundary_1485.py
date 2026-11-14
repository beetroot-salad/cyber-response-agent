"""#1485 P1: the learning tables have one owner. Product code outside `defender/learning_store/` and the migrations
names none of the learning table classes (a census with planted controls), and `defender.learning.store` is gone.
"""
from __future__ import annotations

import ast
import os
import re
from collections.abc import Iterator
from pathlib import Path

from defender.jobs import learning_models
from defender.tests.support.learning.core._store1278 import store_mod
from defender.tests.tooling.layout_contracts import _spec1080 as S

MODELS = "defender.jobs.learning_models"
#: Where the tables may be named: the store that owns them and the migrations that create them.
OWNERS = ("defender/learning_store/", "defender/migrations/")
TABLE_CLASSES = sorted(n for n, c in vars(learning_models).items() if isinstance(c, type) and hasattr(c, "__tablename__"))
TABLE_NAMES = sorted(c.__tablename__ for c in vars(learning_models).values() if isinstance(c, type) and hasattr(c, "__tablename__"))
RAW = re.compile(rf"\blearning\.({'|'.join(TABLE_NAMES)})\b")


def _package(rel: str) -> list[str]:
    parts = S.dotted(rel).split(".")
    return parts if rel.endswith("__init__.py") else parts[:-1]


def _chain(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute) and (head := _chain(node.value)) is not None:
        return f"{head}.{node.attr}"
    return None


def table_references(rel: str, source: str) -> list[str]:
    """What `source` (the file `rel`) names of the learning tables: a table class imported or read off the models module
    in any spelling (from-import, star, module alias, dotted path, relative), or raw SQL naming `learning.<table>`."""
    tree = ast.parse(source, filename=rel)
    pkg, aliases, found = _package(rel), set(), []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            aliases |= {a.asname or a.name for a in node.names if a.name == MODELS}
        elif isinstance(node, ast.ImportFrom):
            base = pkg[: len(pkg) - (node.level - 1)] if node.level else []
            where = ".".join([*base, node.module] if node.module and node.level else base or [node.module or ""])
            if where == MODELS:
                found += [f"{rel}:{node.lineno}: imports {a.name}" for a in node.names if a.name in TABLE_CLASSES or a.name == "*"]
            elif where == "defender.jobs":
                aliases |= {a.asname or a.name for a in node.names if a.name == "learning_models"}
        elif isinstance(node, ast.Attribute) and node.attr in TABLE_CLASSES and _chain(node.value) in aliases:
            found.append(f"{rel}:{node.lineno}: reads {node.attr}")
        elif isinstance(node, ast.Constant) and isinstance(node.value, str) and RAW.search(node.value):
            found.append(f"{rel}:{node.lineno}: raw SQL on a learning table")
    return found


def census(root: Path) -> list[str]:
    """Every table reference in product code under `root/defender`, outside the owners and the models module."""
    out: list[str] = []
    for rel in S.py_files(root):
        if rel.startswith(OWNERS) or rel == MODELS.replace(".", "/") + ".py":
            continue
        out += table_references(rel, (root / rel).read_text(encoding="utf-8"))
    return out


def _plant(tmp_path: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return tmp_path


def test_p1_the_tables_are_found_by_the_census_in_every_spelling(tmp_path):
    """The census reports a planted reference in each spelling, and none in a file that takes only constants. (P1)"""
    assert {"WorkItemRow", "BatchRow", "FeedbackTickRow"} <= set(TABLE_CLASSES), "premise: the classes are found"
    planted = {
        "defender/learning/a.py": "from defender.jobs.learning_models import KINDS, WorkItemRow\n",
        "defender/learning/b.py": "from defender.jobs import learning_models as lm\nx = lm.BatchRow.__table__\n",
        "defender/learning/c.py": "import defender.jobs.learning_models\nx = defender.jobs.learning_models.CommitRow\n",
        "defender/learning/d.py": "from defender.jobs.learning_models import *\n",
        "defender/jobs/e.py": "from .learning_models import FeedbackTickRow\n",
        "defender/learning/f.py": "def f():\n    from defender.jobs.learning_models import CommitChangeRow\n",
        "defender/api/g.py": "from sqlalchemy import text\nq = text('SELECT 1 FROM learning.work_items')\n",
    }
    clean = {
        "defender/learning/ok1.py": "from defender.jobs.learning_models import KINDS, BRANCH_PREFIX, AUTHORING_KINDS, AUTHOR_LANE\n",
        "defender/learning/ok2.py": "from defender.jobs import learning_models\nx = learning_models.LANES\n",
        "defender/learning_store/own.py": "from defender.jobs.learning_models import WorkItemRow\n",
        "defender/migrations/own.py": "from defender.jobs.learning_models import BatchRow\n",
    }
    found = census(_plant(tmp_path, {**planted, **clean}))
    assert sorted({line.split(":")[0] for line in found}) == sorted(planted)


def test_p1_product_code_outside_the_store_and_migrations_names_no_learning_table():
    """No product module outside `defender/learning_store/` and `defender/migrations/` names a learning table class
    or Table, or runs raw SQL on one; constants such as `KINDS` and `BRANCH_PREFIX` are allowed. (P1)"""
    assert census(S.REPO_ROOT) == []


def _imports_of_old_store(root: Path) -> Iterator[str]:
    for top in ("defender", "tooling", "evaluations"):
        for dirpath, dirnames, filenames in os.walk(root / top):
            dirnames[:] = [d for d in dirnames if d not in S.JUNK_DIRS and d != "tests"]
            for name in filenames:
                rel = (Path(dirpath) / name).relative_to(root).as_posix()
                if not name.endswith(".py") or S.is_test_path(rel):
                    continue
                for stmt in S.import_statements(rel, (root / rel).read_bytes()):
                    old = stmt.module == "defender.learning.store" or stmt.module.startswith("defender.learning.store.")
                    if old or (stmt.module == "defender.learning" and "store" in stmt.names):
                        yield f"{rel}:{stmt.line}"


def test_p1_the_old_store_package_is_gone_and_nothing_imports_it():
    """`defender/learning/store/` does not exist, `defender/learning_store/` does, and no product module imports
    `defender.learning.store`, however spelled. (P1, Names)"""
    assert (S.DEFENDER / "learning_store" / "__init__.py").is_file()
    assert not (S.DEFENDER / "learning" / "store").exists(), "no shim"
    assert list(_imports_of_old_store(S.REPO_ROOT)) == []


def test_p1_the_import_census_finds_each_spelling_of_the_old_store(tmp_path):
    """Positive control: the census of imports of the old store reports each planted spelling. (P1)"""
    root = _plant(tmp_path, {
        "defender/x/a.py": "from defender.learning.store import LearningStore\n",
        "defender/x/b.py": "from defender.learning import store\n",
        "defender/x/c.py": "import defender.learning.store._store as s\n",
        "defender/x/d.py": "def f():\n    from defender.learning.store import blocking\n",
        "defender/x/ok.py": "from defender.learning_store import LearningStore\nfrom defender.learning import config\n",
    })
    found = sorted(line.split(":")[0] for line in _imports_of_old_store(root))
    assert found == ["defender/x/a.py", "defender/x/b.py", "defender/x/c.py", "defender/x/d.py"]



def test_p1_the_stores_public_names_are_exported_and_the_lanes_table_is_not_the_stores():
    """`ParkedBatchView`, `pitfall_key`, the lease and grace defaults and `MAX_ITEM_KEY_BYTES` come from
    `defender.learning_store`; `CommitRecord` has no `lanes` field and `lanes_of_branch` is not the store's. (P1, Names)"""
    import dataclasses

    S = store_mod()
    exported = ["ParkedBatchView", "pitfall_key", "DEFAULT_LEASE_SECONDS", "DEFAULT_GRACE_SECONDS", "MAX_ITEM_KEY_BYTES"]
    assert [n for n in exported if not hasattr(S, n)] == []
    assert S.MAX_ITEM_KEY_BYTES == 200
    assert "lanes" not in {f.name for f in dataclasses.fields(S.CommitRecord)}
    assert not hasattr(S, "lanes_of_branch")


def test_p1_the_queue_merge_and_the_pitfalls_curator_use_the_stores_one_mistake_key():
    """The mistake-key rule (`pitfall_key`, `is_reducer_row`, `_digest_diagnosis`) is defined once, in the store: every
    copy the queue's merge or the pitfalls curator holds, under any name, is the store's own function. (P1)"""
    import types

    from defender.learning.core import persist
    from defender.learning.leads import pitfalls_curator

    rule = ("pitfall_key", "is_reducer_row", "_digest_diagnosis")
    assert persist.pitfall_key is store_mod().pitfall_key
    held = {(mod.__name__, name): fn for mod in (persist, pitfalls_curator) for name, fn in vars(mod).items()
            if isinstance(fn, types.FunctionType) and fn.__name__ in rule}
    assert {fn.__name__ for fn in held.values()} >= {"pitfall_key", "is_reducer_row"}, held
    elsewhere = {k: fn.__module__ for k, fn in held.items() if not fn.__module__.startswith("defender.learning_store")}
    assert not elsewhere, f"a mistake-key function defined outside the store: {elsewhere}"

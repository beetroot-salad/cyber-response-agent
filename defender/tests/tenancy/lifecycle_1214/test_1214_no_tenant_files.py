"""#1214 O6: production code neither reads nor writes `tenant.json` or `publish-status.json`."""
from __future__ import annotations

import re
from pathlib import Path

DEFENDER = Path(__file__).resolve().parents[3]
RETIRED = re.compile(r"""["'](tenant\.json|publish-status\.json)["']""")


def _production_sources() -> list[Path]:
    return [p for p in DEFENDER.rglob("*.py")
            if "tests" not in p.relative_to(DEFENDER).parts and ".venv" not in p.parts]


def test_no_production_module_names_the_retired_tenant_files():
    """No production module spells either file name as a string (O6)."""
    sources = _production_sources()
    assert any(p.name == "run.py" for p in sources)  # control: the census sees production
    found = [f"{p.relative_to(DEFENDER)}:{n}" for p in sources
             for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1) if RETIRED.search(line)]
    assert found == []

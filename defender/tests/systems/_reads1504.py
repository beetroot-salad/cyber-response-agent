"""#1504 sketch: every name the draft design leaves open, in one place. FORCED CHOICES (the design names none of these;
the code stage supplies or corrects them here): the adapter's reads constant, the catalog entry's field, the API item's
field and its element shape, the words a mismatch fault uses for each side, the reference file's name and headings, and
the lint that holds it. NO test functions."""
from __future__ import annotations

import importlib
import textwrap
from pathlib import Path
from typing import Any

#: The module constant each catalog adapter declares (O1): a tuple of `(method, path)` routes, non-GET only, `()` for
#: none. FORCED: the name; and that `()` is declared explicitly rather than "absent means none".
READS_CONSTANT = "READ_ROUTES"
#: The `CatalogEntry` attribute the catalog reads it into, cold (O1). FORCED: name; a tuple of `(method, path)`.
ENTRY_FIELD = "reads"
#: The `GET /adapters` item field (O3). FORCED: name; each element `{"method", "path"}` (the access declaration's own
#: shape, so an admin copies it into `reads:` as is); `[]`, never null, for an adapter with none.
API_FIELD = "reads"
#: The `GET /adapters` item field holding the reference file's text verbatim (O5). FORCED: name and verbatim.
API_REFERENCE_FIELD = "reference"
#: Connect's example adapter's reference (O7): the seed a generated adapter copies. FORCED: path.
EXAMPLE_REFERENCE = "defender/skills/connect/examples/example_adapter.md"

#: The words a mismatch fault uses for each side (O2: "naming the missing and the extra routes"). FORCED: the design
#: says a fault names both, not how a reader tells them apart.
MISSING_WORD = "missing"
EXTRA_WORD = "extra"

#: The reference beside each catalog adapter (O4): `<module stem>.md`. FORCED: the stem (`elastic_adapter.md`, not
#: `elastic.md`), and level-2 headings with exactly these texts.
REFERENCE_SUFFIX = ".md"
SECTIONS = ("Credential", "Pitfalls")
#: The lint that holds the reference present (O5). FORCED: an extension of the catalog declarations gate, not a new one.
REFERENCE_GATE = "lint_catalog_declarations"

#: The validator's row for the reads (O4, given only the system): FORCED: the row says `reads`, and for an adapter that
#: declares none it says `none` (the code stage corrects the words here).
READS_ROW_WORD = "reads"
NO_READS_WORD = "none"

#: The declared reads the design's census (C3) finds today, spelled in the route syntax.
ELASTIC_READS = (("POST", "/*/_search"), ("POST", "/_query"))
THREAT_INTEL_READS = (("POST", "/lookup"),)


def reads_declaration(system: str) -> str:
    """The source line a planted stand-in for catalog adapter `system` appends to declare the reads its real adapter does
    (O1): a tenant's record of it carries those, so a stand-in without them would have its record refused (O3). Test data."""
    reads = {"elastic": ELASTIC_READS, "threat-intel": THREAT_INTEL_READS}.get(system, ())
    return f"\n{READS_CONSTANT} = {reads!r}\n"


def adapter(name: str) -> Any:
    """The catalog adapter module `name` (its system id)."""
    return importlib.import_module(f"defender.integrations.{name.replace('-', '_')}_adapter")


def declared_reads(name: str) -> tuple[tuple[str, str], ...]:
    """`name`'s declared reads as its module spells them (an AttributeError until O1 lands)."""
    return tuple(tuple(r) for r in getattr(adapter(name), READS_CONSTANT))


def shown(route: tuple[str, str]) -> str:
    """A route as a fault or a printed row names it: `METHOD path`."""
    return f"{route[0]} {route[1]}"


def plant_adapter(root: Path, name: str, *, reads: str | None, check: str = "return None") -> Path:
    """A checkout holding `<name>_adapter.py`: cold declarations, `reads` spelled as the source of its list constant (None:
    no list declared) and a `check_settings` whose body is `check`. Test data for a catalog the caller holds."""
    folder = root / "integrations"
    folder.mkdir(parents=True)
    prefix = name.upper()
    (folder / f"{name}_adapter.py").write_text(textwrap.dedent(f'''\
        PREFIX = "{prefix}"
        REQUIRED_CONFIG_KEYS = ("TIMEOUT_SEC",)
        DISPLAY_NAME = "{name}"
        EXAMPLE = False
        SAMPLE_SETTINGS = {{"{prefix}_TIMEOUT_SEC": "10"}}
        VERBS = {{}}
        {READS_CONSTANT + " = " + reads if reads is not None else ""}


        def check_settings(tenant):
            {check}
        '''))
    return root

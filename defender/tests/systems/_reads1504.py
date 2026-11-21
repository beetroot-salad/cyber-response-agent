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


# --- #1504 A6 (one route rule): names and data the amendment's tests share ----------------------------------------------

#: The `CatalogEntry` attribute holding why an adapter has no usable list (A6.2), and the `GET /adapters` item field
#: carrying it (A6.3). FORCED by the design: `reads_unusable`, text or None.
UNUSABLE_FIELD = "reads_unusable"

#: Readable-but-unusable `READ_ROUTES` sources (A6.2), each with the text its reason must name (the offending entry's
#: path as written). The paths are not any route a test record lists, so a fault naming one got it from the list.
#: (id, source of the list, needles).
UNUSABLE_LISTS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("get", "(('GET', '/widgets/_gone'),)", ("/widgets/_gone",)),
    ("head", "(('HEAD', '/widgets/_gone'),)", ("/widgets/_gone",)),
    ("lower-case-method", "(('post', '/widgets/_gone'),)", ("/widgets/_gone",)),
    ("no-leading-slash", "(('POST', 'widgets_gone'),)", ("widgets_gone",)),
    ("query-in-path", "(('POST', '/widgets/_gone?x=1'),)", ("/widgets/_gone",)),
    ("fragment-in-path", "(('POST', '/widgets/_gone#top'),)", ("/widgets/_gone",)),
    ("repeated-route", "(('POST', '/widgets/_gone'), ('POST', '/widgets/_gone'))", ("/widgets/_gone",)),
    ("non-pair-entry", "('POST /widgets/_gone',)", ("/widgets/_gone",)),
    ("triple-entry", "(('POST', '/widgets/_gone', 'x'),)", ("/widgets/_gone",)),
    ("good-route-beside-a-bad-one", "(('POST', '/widgets/_fine'), ('GET', '/widgets/_gone'))", ("/widgets/_gone",)),
    ("two-bad-entries", "(('GET', '/widgets/_one'), ('post', '/widgets/_two'))", ("/widgets/_one", "/widgets/_two")),
)
#: Lists the module does not hold readably (absent, or computed): (id, source, None for no declaration).
UNREADABLE_LISTS: tuple[tuple[str, str | None], ...] = (
    ("absent", None), ("computed", "tuple([('POST', '/widgets/_find')])"))

#: Route shapes (A6.1) as the tenant access parser, the lint and the catalog reader must each judge them.
SHAPE_BAD: tuple[tuple[str, tuple[str, str]], ...] = (
    ("lower-case-method", ("post", "/x/_a")), ("mixed-case-method", ("Post", "/x/_a")),
    ("two-letter-method", ("PO", "/x/_a")), ("eleven-letter-method", ("ABCDEFGHIJK", "/x/_a")),
    ("digit-in-method", ("PO5T", "/x/_a")), ("underscore-in-method", ("PO_ST", "/x/_a")),
    ("empty-method", ("", "/x/_a")), ("no-leading-slash", ("POST", "x/_a")), ("empty-path", ("POST", "")),
    ("query-in-path", ("POST", "/x/_a?y=1")), ("fragment-in-path", ("POST", "/x/_a#y")),
)
SHAPE_GOOD: tuple[tuple[str, tuple[str, str]], ...] = (
    ("post", ("POST", "/x/_a")), ("star-segment", ("PUT", "/x/*/b")), ("root", ("DELETE", "/")),
    ("three-letter-method", ("ABC", "/x")), ("ten-letter-method", ("ABCDEFGHIJ", "/x")),
    ("encoded-space", ("POST", "/x/a%20b")), ("trailing-slash", ("OPTIONS", "/x/")),
)
#: Methods the readers of the read-method list are asked about (all fit every reader's own method pattern).
METHOD_POOL = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT", "ABC")

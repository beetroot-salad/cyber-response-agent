"""Tests for the lint_catalog_declarations gate (#1366 K2, K8, C1; #1504 O1, O5, O6, O7).

The catalog is read cold: every catalog adapter and connect's example declare module-level `PREFIX`,
`REQUIRED_CONFIG_KEYS`, `PATH_KEYS`, `DISPLAY_NAME`, `EXAMPLE` and (#1504 O1) `READ_ROUTES`, the non-GET reads it sends
(explicit empty for none, upper-case non-GET/HEAD method, `/` path without `?`/`#`, no duplicates, empty when it declares
a comment route); an adapter offering a comment action declares `comment_route`; no declared settings key is secret-named;
a reference `<module stem>.md` with non-empty `## Credential` and `## Pitfalls` sits beside each (#1504 O5, O6; connect's
example too, O7: it is the seed a generated adapter is copied from). The gate is loaded inside each test, so a missing lint is
a red per test and not a collection error. Interface (invented by this contract): `main(["--root", <repo-shaped
tree>])` -> exit 0 clean, 1 findings (each line names the module's repo-relative path and the constant or key), 2
when the scan saw no adapter.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from _by_path import load_lint_gate

REPO = Path(__file__).resolve().parents[3]
ADAPTERS = "defender/integrations"
EXAMPLE_ADAPTER = "defender/skills/connect/examples/example_adapter.py"
CONSTANTS = ("PREFIX", "REQUIRED_CONFIG_KEYS", "PATH_KEYS", "DISPLAY_NAME", "EXAMPLE", "READ_ROUTES")
#: FORCED (#1504, mirrored from `defender/tests/systems/_reads1504.py`, which this tree cannot import): the reads
#: constant is `READ_ROUTES`; the reference is `<module stem>.md` beside the module with level-2 headings `Credential` and
#: `Pitfalls`, a section being empty when no non-blank line precedes the next heading.
SECTIONS = ("Credential", "Pitfalls")

GOOD = {
    "PREFIX": 'PREFIX = "WIDGET"',
    "REQUIRED_CONFIG_KEYS": 'REQUIRED_CONFIG_KEYS = ("TIMEOUT_SEC", "TABLE")',
    "PATH_KEYS": 'PATH_KEYS = ("TABLE",)',
    "DISPLAY_NAME": 'DISPLAY_NAME = "Widget"',
    "EXAMPLE": "EXAMPLE = False",
    "READ_ROUTES": "READ_ROUTES = ()",
}
COMMENT_ACTION = "def add_case_comment(ctx, *, key, body):\n    return None\n"


def _gate():
    return load_lint_gate("lint_catalog_declarations")


def _module(**override: str | None) -> str:
    """An adapter's text: the six declarations, each replaced by `override[name]` or left out when it is None."""
    lines = [override.get(name, GOOD[name]) for name in CONSTANTS]
    return "SYSTEM = \"widget\"\n" + "\n".join(line for line in lines if line is not None) + "\n"


def _tree(tmp_path: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return tmp_path


def _reference(**bodies: str | None) -> str:
    """A reference's text: each section with `bodies[name]` (a default line when not given; None leaves the section out)."""
    parts = ["# Widget\n"]
    for name in SECTIONS:
        body = bodies.get(name, f"What the {name.lower()} takes.\n")
        if body is not None:
            parts.append(f"## {name}\n\n{body}")
    return "\n".join(parts)


def _with_references(files: dict[str, str]) -> dict[str, str]:
    """`files` plus a good reference beside each adapter module that has none (the example included)."""
    out = dict(files)
    for rel in files:
        if (rel.startswith(f"{ADAPTERS}/") and rel.endswith("_adapter.py") and rel.count("/") == 2) or rel == EXAMPLE_ADAPTER:
            out.setdefault(rel.removesuffix(".py") + ".md", _reference())
    return out


def _run(tmp_path: Path, files: dict[str, str], capsys, *, referenced: bool = True) -> tuple[int, str]:
    root = _tree(tmp_path, _with_references(files) if referenced else files)
    capsys.readouterr()
    rc = _gate().main(["--root", str(root)])
    said = capsys.readouterr()
    return rc, said.out + said.err


def _lines_naming(out: str, *words: str) -> list[str]:
    return [line for line in out.splitlines() if all(w in line for w in words)]


# what it catches


def test_a_tree_whose_adapters_declare_everything_is_clean(tmp_path, capsys):
    """Positive control: the declared adapter, connect's example and a non-adapter helper report nothing. (#1366 K2)"""
    rc, out = _run(tmp_path, {f"{ADAPTERS}/widget_adapter.py": _module(),
                              EXAMPLE_ADAPTER: _module(),
                              f"{ADAPTERS}/helper.py": "VALUE = 1\n"}, capsys)
    assert rc == 0, out
    assert "helper" not in out, out


@pytest.mark.parametrize("name", CONSTANTS)
@pytest.mark.parametrize("where", [f"{ADAPTERS}/widget_adapter.py", EXAMPLE_ADAPTER], ids=["catalog", "connect-example"])
def test_an_adapter_lacking_a_declaration_is_reported_naming_it_and_the_constant(tmp_path, capsys, where, name):
    """Each of the six constants, missing, is a finding on that module naming the constant. (#1366 K2, O2; #1504 O1)"""
    rc, out = _run(tmp_path, {where: _module(**{name: None})}, capsys)
    assert rc == 1, out
    assert _lines_naming(out, where, name), out


@pytest.mark.parametrize(("name", "text"), [
    ("PREFIX", "PREFIX = _prefix()"),
    ("DISPLAY_NAME", "DISPLAY_NAME = _name()"),
    ("EXAMPLE", "EXAMPLE = _flag()"),
    ("REQUIRED_CONFIG_KEYS", "REQUIRED_CONFIG_KEYS = _keys()"),
    ("PATH_KEYS", "PATH_KEYS = _keys()"),
    ("PREFIX", 'if True:\n    PREFIX = "WIDGET"'),
    ("READ_ROUTES", "READ_ROUTES = _routes()"),
], ids=["prefix-call", "name-call", "example-call", "keys-call", "path-keys-call", "prefix-not-module-level",
        "reads-call"])
def test_a_declaration_that_is_not_readable_without_running_the_module_is_reported(tmp_path, capsys, name, text):
    """A constant computed by a call, or defined under a condition, cannot be read cold: reported. (#1366 K2)"""
    rc, out = _run(tmp_path, {f"{ADAPTERS}/widget_adapter.py": _module(**{name: text})}, capsys)
    assert rc == 1, out
    assert _lines_naming(out, "widget_adapter.py", name), out


def test_the_shapes_the_catalog_uses_today_are_cold_readable(tmp_path, capsys):
    """Control: a keys tuple that splats a shared template beside a literal, an alias of another declared constant and
    an annotated empty tuple are all declarations (the real adapters spell them so). (#1366 K2)"""
    text = _module(REQUIRED_CONFIG_KEYS='REQUIRED_CONFIG_KEYS = (*transport.REQUIRED_CONFIG_KEYS_TEMPLATE, "TABLE")',
                   PATH_KEYS="PATH_KEYS = REQUIRED_CONFIG_KEYS")
    empty = _module(REQUIRED_CONFIG_KEYS="REQUIRED_CONFIG_KEYS: tuple[str, ...] = ()", PATH_KEYS="PATH_KEYS = ()")
    rc, out = _run(tmp_path, {f"{ADAPTERS}/widget_adapter.py": text, f"{ADAPTERS}/other_adapter.py": empty}, capsys)
    assert rc == 0, out


def test_an_adapter_offering_a_comment_action_without_a_route_is_reported(tmp_path, capsys):
    """`add_case_comment` without `comment_route` is a finding; with it, or with neither, clean. (#1366 C1, K5)"""
    routed = _module() + COMMENT_ACTION + "def comment_route(settings):\n    return ('POST', '/c/*')\n"
    files = {f"{ADAPTERS}/routed_adapter.py": routed, f"{ADAPTERS}/plain_adapter.py": _module(),
             f"{ADAPTERS}/silent_adapter.py": _module() + COMMENT_ACTION}
    rc, out = _run(tmp_path, files, capsys)
    assert rc == 1, out
    assert _lines_naming(out, "silent_adapter.py", "comment_route"), out
    assert not _lines_naming(out, "routed_adapter.py"), out
    assert not _lines_naming(out, "plain_adapter.py"), out


# #1504 O1: the declared non-GET reads, held in shape

ROUTES_GOOD = 'READ_ROUTES = (("POST", "/*/_search"), ("POST", "/_query"), ("PUT", "/a/*/b"))'


@pytest.mark.parametrize("where", [f"{ADAPTERS}/widget_adapter.py", EXAMPLE_ADAPTER], ids=["catalog", "connect-example"])
@pytest.mark.parametrize("text", [
    "READ_ROUTES = ()", ROUTES_GOOD, 'READ_ROUTES: tuple[tuple[str, str], ...] = (("POST", "/lookup"),)',
], ids=["explicit-empty", "routes-with-star", "annotated"])
def test_a_well_shaped_reads_declaration_is_clean(tmp_path, capsys, where, text):
    """Positive control: an explicit empty list, routes with `*` segments, an annotated list. (#1504 O1)"""
    rc, out = _run(tmp_path, {where: _module(READ_ROUTES=text)}, capsys)
    assert rc == 0, out


@pytest.mark.parametrize("where", [f"{ADAPTERS}/widget_adapter.py", EXAMPLE_ADAPTER], ids=["catalog", "connect-example"])
@pytest.mark.parametrize("text", [
    'READ_ROUTES = (("post", "/lookup"),)',
    'READ_ROUTES = (("GET", "/lookup"),)',
    'READ_ROUTES = (("HEAD", "/lookup"),)',
    'READ_ROUTES = (("POST", "lookup"),)',
    'READ_ROUTES = (("POST", ""),)',
    'READ_ROUTES = (("POST", "/lookup?x=1"),)',
    'READ_ROUTES = (("POST", "/lookup#top"),)',
    'READ_ROUTES = (("POST", "/lookup"), ("POST", "/lookup"))',
    'READ_ROUTES = ("POST /lookup",)',
    'READ_ROUTES = (("POST", "/lookup", "extra"),)',
    'READ_ROUTES = (("POST", 7),)',
    'READ_ROUTES = "POST /lookup"',
], ids=["lower-case-method", "get", "head", "no-leading-slash", "empty-path", "query-in-path", "fragment-in-path",
        "duplicate", "one-string", "triple", "non-text-path", "bare-string"])
def test_a_reads_declaration_of_the_wrong_shape_is_reported_naming_the_constant(tmp_path, capsys, where, text):
    """Each way a route list breaks the access declaration's route shape, or repeats a route, is a finding naming
    `READ_ROUTES` on that module. (#1504 O1)"""
    rc, out = _run(tmp_path, {where: _module(READ_ROUTES=text)}, capsys)
    assert rc == 1, out
    assert _lines_naming(out, where, "READ_ROUTES"), out


def test_an_adapter_with_a_comment_route_declaring_reads_is_reported_and_one_declaring_none_is_clean(tmp_path, capsys):
    """A comment route beside a non-empty `READ_ROUTES` is a finding (a case system has only GET reads); beside `()` it
    is clean. (#1504 O1, C1)"""
    comment = COMMENT_ACTION + "def comment_route(settings):\n    return ('POST', '/c/*')\n"
    files = {f"{ADAPTERS}/case_adapter.py": _module(READ_ROUTES=ROUTES_GOOD) + comment,
             f"{ADAPTERS}/quiet_adapter.py": _module() + comment}
    rc, out = _run(tmp_path, files, capsys)
    assert rc == 1, out
    assert _lines_naming(out, "case_adapter.py", "READ_ROUTES"), out
    assert not _lines_naming(out, "quiet_adapter.py"), out


# #1504 O5, O6, O7: the reference beside each adapter

WIDGET_REFERENCE = f"{ADAPTERS}/widget_adapter.md"
EXAMPLE_REFERENCE = "defender/skills/connect/examples/example_adapter.md"


@pytest.mark.parametrize("bodies", [
    {}, {"Credential": "None known.\n", "Pitfalls": "None known.\n"},
    {"Pitfalls": "- one\n- two\n"},
], ids=["both-filled", "none-known", "a-list"])
def test_an_adapter_whose_reference_holds_both_sections_is_clean(tmp_path, capsys, bodies):
    """Positive control: a reference whose Credential and Pitfalls hold text, `None known.` included. (#1504 O5, O6)"""
    rc, out = _run(tmp_path, {f"{ADAPTERS}/widget_adapter.py": _module(), WIDGET_REFERENCE: _reference(**bodies)}, capsys)
    assert rc == 0, out


@pytest.mark.parametrize(("where", "reference"), [
    (f"{ADAPTERS}/widget_adapter.py", WIDGET_REFERENCE), (EXAMPLE_ADAPTER, EXAMPLE_REFERENCE),
], ids=["catalog", "connect-example"])
def test_an_adapter_with_no_reference_is_a_finding_naming_the_module_and_the_reference(tmp_path, capsys, where, reference):
    """No `<stem>.md` beside the module (the example's included) is a finding naming the reference it lacks. (#1504 O6, O7)"""
    rc, out = _run(tmp_path, {where: _module()}, capsys, referenced=False)
    assert rc == 1, out
    assert _lines_naming(out, reference), out


@pytest.mark.parametrize(("where", "reference"), [
    (f"{ADAPTERS}/widget_adapter.py", WIDGET_REFERENCE), (EXAMPLE_ADAPTER, EXAMPLE_REFERENCE),
], ids=["catalog", "connect-example"])
@pytest.mark.parametrize(("bodies", "named"), [
    ({"Pitfalls": None}, "Pitfalls"), ({"Credential": None}, "Credential"),
    ({"Credential": "\n"}, "Credential"), ({"Pitfalls": "   \n\n"}, "Pitfalls"),
], ids=["no-pitfalls", "no-credential", "empty-credential", "blank-pitfalls"])
def test_a_reference_lacking_a_section_or_leaving_one_empty_is_a_finding_naming_it(
        tmp_path, capsys, where, reference, bodies, named):
    """A reference without `## <section>`, or with one holding only blank lines, is a finding naming the reference and
    the section. (#1504 O6)"""
    rc, out = _run(tmp_path, {where: _module(), reference: _reference(**bodies)}, capsys, referenced=False)
    assert rc == 1, out
    assert _lines_naming(out, reference, named), out


def test_a_section_heading_of_another_level_is_not_the_section(tmp_path, capsys):
    """`### Credential` (level 3) does not satisfy the `## Credential` section. (#1504 O6)"""
    text = "# Widget\n\n### Credential\n\nSome text.\n\n## Pitfalls\n\nNone known.\n"
    rc, out = _run(tmp_path, {f"{ADAPTERS}/widget_adapter.py": _module(), WIDGET_REFERENCE: text}, capsys, referenced=False)
    assert rc == 1, out
    assert _lines_naming(out, WIDGET_REFERENCE, "Credential"), out


def test_text_under_a_subheading_belongs_to_the_enclosing_section(tmp_path, capsys):
    """A `## Credential` whose only text sits under `###` subheadings is not empty. (#1504 O6)"""
    text = ("# Widget\n\n## Credential\n\n### Cloud\n\nAn API token.\n\n### Server\n\nA basic user.\n\n"
            "## Pitfalls\n\nNone known.\n")
    rc, out = _run(tmp_path, {f"{ADAPTERS}/widget_adapter.py": _module(), WIDGET_REFERENCE: text}, capsys, referenced=False)
    assert rc == 0, out
    assert not _lines_naming(out, WIDGET_REFERENCE), out


def test_a_subheading_alone_is_not_text_of_its_section(tmp_path, capsys):
    """A `## Credential` holding only a `###` heading line is still empty. (#1504 O6)"""
    text = "# Widget\n\n## Credential\n\n### Cloud\n\n## Pitfalls\n\nNone known.\n"
    rc, out = _run(tmp_path, {f"{ADAPTERS}/widget_adapter.py": _module(), WIDGET_REFERENCE: text}, capsys, referenced=False)
    assert rc == 1, out
    assert _lines_naming(out, WIDGET_REFERENCE, "Credential"), out


@pytest.mark.parametrize(("fence", "inner"), [
    ("```", ""), ("~~~", ""),
    ("```", "~~~\n"),  # the other fence character does not close it
    ("````", "```\n"),  # a shorter fence does not close it
])
def test_a_heading_inside_a_fenced_block_is_not_a_section(tmp_path, capsys, fence, inner):
    """`## Pitfalls` inside a fenced block neither opens the section nor ends the one around it. (#1504 O6)"""
    text = f"# Widget\n\n## Credential\n\nA token.\n\n{fence}\n{inner}## Pitfalls\n\nlooks like one\n{fence}\n"
    rc, out = _run(tmp_path, {f"{ADAPTERS}/widget_adapter.py": _module(), WIDGET_REFERENCE: text}, capsys, referenced=False)
    assert rc == 1, out
    assert _lines_naming(out, WIDGET_REFERENCE, "Pitfalls"), out
    assert not _lines_naming(out, WIDGET_REFERENCE, "Credential"), out



def test_a_heading_after_a_closed_fence_is_a_section(tmp_path, capsys):
    """A fence closed by a marker of its own length ends there: the `## Pitfalls` after it counts. (#1504 O6)"""
    text = "# Widget\n\n## Credential\n\n```\n## Note\n```\n\n## Pitfalls\n\nNone known.\n"
    rc, out = _run(tmp_path, {f"{ADAPTERS}/widget_adapter.py": _module(), WIDGET_REFERENCE: text}, capsys, referenced=False)
    assert rc == 0, out


def test_a_fence_line_with_text_after_it_does_not_close_the_fence(tmp_path, capsys):
    """Only a bare marker closes a fence: ```` ```python ```` inside one leaves it open. (#1504 O6)"""
    text = "# Widget\n\n## Credential\n\nA token.\n\n```\ncode\n```python\n## Pitfalls\n\nlooks like one\n```\n"
    rc, out = _run(tmp_path, {f"{ADAPTERS}/widget_adapter.py": _module(), WIDGET_REFERENCE: text}, capsys, referenced=False)
    assert rc == 1, out
    assert _lines_naming(out, WIDGET_REFERENCE, "Pitfalls"), out


@pytest.mark.parametrize("line", [
    "```inline``` code",  # a backtick line whose info string holds a backtick is not a fence
    " ## Pitfalls",  # a heading may be indented up to three spaces
    "## Pitfalls ##",  # closing hashes are not part of the heading's name
])
def test_a_real_pitfalls_heading_is_found(tmp_path, capsys, line):
    """Each of these leaves a real, non-empty `## Pitfalls` section the lint must find. (#1504 O6)"""
    pitfalls = f"{line}\n\n## Pitfalls\n\nNone known.\n" if line.startswith("```") else f"{line}\n\nNone known.\n"
    text = f"# Widget\n\n## Credential\n\nA token.\n\n{pitfalls}"
    rc, out = _run(tmp_path, {f"{ADAPTERS}/widget_adapter.py": _module(), WIDGET_REFERENCE: text}, capsys, referenced=False)
    assert rc == 0, out


# K8: a declared key that would hold a secret

SECRET_NAMED = ["TOKEN", "API_TOKEN", "PASSWORD", "DB_PASSWD", "CLIENT_SECRET", "SERVICE_CREDENTIAL", "API_KEY",
                "APIKEY", "SIGNING_SECRET_REF"]
NOT_SECRET = ["TIMEOUT_SEC", "TABLE", "SERVICE_DESK", "KEY_PATTERN", "EVENTS_INDEX", "TOKEN_URL"]


@pytest.mark.parametrize("declared", ["REQUIRED_CONFIG_KEYS", "PATH_KEYS"])
@pytest.mark.parametrize("key", SECRET_NAMED)
def test_a_declared_settings_key_named_like_a_secret_is_reported(tmp_path, capsys, declared, key):
    """A secret-named key in the keys an adapter declares is a finding on that adapter naming the key. (#1366 K8)"""
    text = _module(**{declared: f'{declared} = ("TIMEOUT_SEC", "{key}")'})
    rc, out = _run(tmp_path, {f"{ADAPTERS}/widget_adapter.py": text}, capsys)
    assert rc == 1, out
    assert _lines_naming(out, "widget_adapter.py", key), out
    assert not _lines_naming(out, "TIMEOUT_SEC"), out


def test_keys_not_named_like_secrets_are_not_reported(tmp_path, capsys):
    """Control for K8 on the same channel: ordinary keys, `KEY_PATTERN` and `TOKEN_URL` included. (#1366 K8)"""
    keys = ", ".join(f'"{k}"' for k in NOT_SECRET)
    rc, out = _run(tmp_path, {f"{ADAPTERS}/widget_adapter.py": _module(REQUIRED_CONFIG_KEYS=f"REQUIRED_CONFIG_KEYS = ({keys},)")}, capsys)
    assert rc == 0, out


def test_a_scan_that_saw_no_adapter_proves_nothing(tmp_path, capsys):
    """A root holding no adapter is not a clean result. (#1366 K2)"""
    rc, out = _run(tmp_path, {f"{ADAPTERS}/helper.py": "VALUE = 1\n"}, capsys)
    assert rc == 2, out


# the real tree


def test_the_checkout_is_clean(capsys):
    """The product's own catalog and connect's example pass: every adapter declares all six, a reference sits beside each, case
    adapters declare their route, no key is secret-named. (#1366 K2, K8, C1)"""
    capsys.readouterr()
    rc = _gate().main([])
    said = capsys.readouterr()
    assert rc == 0, said.out + said.err


def _literal(path: Path, name: str):
    """The module-level `name` of `path` read without running it, or a marker when absent / not a literal."""
    for node in ast.parse(path.read_text(encoding="utf-8")).body:
        targets = node.targets if isinstance(node, ast.Assign) else [node.target] if isinstance(node, ast.AnnAssign) else []
        if any(isinstance(t, ast.Name) and t.id == name for t in targets):
            try:
                return ast.literal_eval(node.value)
            except ValueError:
                return "<not a literal>"
    return "<absent>"


REAL = {"elastic", "jira", "servicenow"}
EXAMPLES = {"change-mgmt", "cmdb", "host-state", "identity", "threat-intel", "ticket"}


def test_the_catalog_marks_the_lab_adapters_as_examples_and_names_each_adapter():
    """EXAMPLE is True for the six lab adapters and False for Elastic, Jira and ServiceNow, read cold; every adapter
    and connect's example has a non-blank string DISPLAY_NAME. (#1366 O2)"""
    modules = {p.name.removesuffix("_adapter.py").replace("_", "-"): p
               for p in sorted((REPO / ADAPTERS).glob("*_adapter.py"))}
    assert set(modules) == REAL | EXAMPLES, "the catalog changed: this test names its members"
    flags = {system: _literal(path, "EXAMPLE") for system, path in modules.items()}
    assert flags == {**{s: False for s in REAL}, **{s: True for s in EXAMPLES}}, flags
    names = {system: _literal(path, "DISPLAY_NAME") for system, path in {**modules, "connect-example": REPO / EXAMPLE_ADAPTER}.items()}
    blank = {s: n for s, n in names.items() if not (isinstance(n, str) and n.strip() and not n.startswith("<"))}
    assert blank == {}, blank

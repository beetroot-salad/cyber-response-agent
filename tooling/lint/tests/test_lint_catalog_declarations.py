"""Tests for the lint_catalog_declarations gate (#1366 K2, K8, C1).

The catalog is read cold: every catalog adapter and connect's example declare module-level `PREFIX`,
`REQUIRED_CONFIG_KEYS`, `PATH_KEYS`, `DISPLAY_NAME` and `EXAMPLE`; an adapter offering a comment action declares
`comment_route`; no declared settings key is secret-named. The gate is loaded inside each test, so a missing lint is
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
CONSTANTS = ("PREFIX", "REQUIRED_CONFIG_KEYS", "PATH_KEYS", "DISPLAY_NAME", "EXAMPLE")

GOOD = {
    "PREFIX": 'PREFIX = "WIDGET"',
    "REQUIRED_CONFIG_KEYS": 'REQUIRED_CONFIG_KEYS = ("TIMEOUT_SEC", "TABLE")',
    "PATH_KEYS": 'PATH_KEYS = ("TABLE",)',
    "DISPLAY_NAME": 'DISPLAY_NAME = "Widget"',
    "EXAMPLE": "EXAMPLE = False",
}
COMMENT_ACTION = "def add_case_comment(ctx, *, key, body):\n    return None\n"


def _gate():
    return load_lint_gate("lint_catalog_declarations")


def _module(**override: str | None) -> str:
    """An adapter's text: the five declarations, each replaced by `override[name]` or left out when it is None."""
    lines = [override.get(name, GOOD[name]) for name in CONSTANTS]
    return "SYSTEM = \"widget\"\n" + "\n".join(line for line in lines if line is not None) + "\n"


def _tree(tmp_path: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return tmp_path


def _run(tmp_path: Path, files: dict[str, str], capsys) -> tuple[int, str]:
    root = _tree(tmp_path, files)
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
    """Each of the five constants, missing, is a finding on that module naming the constant. (#1366 K2, O2)"""
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
], ids=["prefix-call", "name-call", "example-call", "keys-call", "path-keys-call", "prefix-not-module-level"])
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
    """The product's own catalog and connect's example pass: every adapter declares all five, case adapters declare
    their route, no key is secret-named. (#1366 K2, K8, C1)"""
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

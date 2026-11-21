"""#1540 F1/F6/F8, #1581 G9: the source check observed through the lint job's gate, one case per form and location (split from
`test_1161_build.py`)."""
import json
import re
from typing import Any

import pytest

from defender.tests.support.frontend._ingress1161 import FRONTEND

from defender.tests.frontend._gate_support import (  # noqa: F401
    ALLOWED_FORMS, CONTROL, CONTROL_TEST_SOURCE, LOCATION_FORM, LOCATIONS, NEVER_CALLED, REFUSED_FORMS, SCREEN_IMPORT,
    SHELL_IMPORT, _check, _extension, _gate, _lib_declares_navigation, _unit_tests, _with_source)


def test_1540_f8_the_gate_passes_on_the_unmodified_tree(checked):
    """`bun run check` then `bun run test` exit 0 on the copy. (F8, F6)"""
    gate = _gate(checked)
    assert not gate.refused, gate.output[-1500:]


def test_1540_f1_the_check_fails_on_a_plain_type_error(checked):
    """`bun run check` is generate + type check: an unrelated type error fails it. Kept on that one command, because F1
    defines it. (F1)"""
    gate = _with_source(checked, "screens/zz_type_error.ts", "export const bad: number = 'not a number';", _check)
    assert gate.refused, "check accepted a type error"


def test_1540_f6_the_unit_test_command_passes_on_the_unmodified_tree(checked):
    """`bun run test` alone exits 0 on a pristine copy: it is generate + `vitest run` (F1), so it needs no earlier
    `check`. Kept on that one command, because F1 defines it. (F6, F1)"""
    done = _unit_tests(checked)
    assert not done.refused, done.output[-1500:]


def test_1540_f6_a_unit_test_file_that_throws_at_load_fails_the_gate(checked):
    """A `src/shell/zz_fail.test.ts` whose module throws when loaded makes the gate refuse the tree, naming it; the
    unmodified tree passes it (control). (F6, F8)"""
    assert not _gate(checked).refused, "control: the unmodified tree passes the gate"
    text = 'export {};\nthrow new Error("zz_fail: refused at load");'
    failing = _with_source(checked, "shell/zz_fail.test.ts", text)
    assert failing.refused, "the gate ran no unit-test file, or let a failing one pass"
    assert "zz_fail.test.ts" in failing.output, failing.output[-1500:]


@pytest.mark.parametrize("form", REFUSED_FORMS)
def test_1540_f8_the_source_check_refuses_each_form_outside_the_shell_and_the_shell_may_hold_it(checked, form):
    """This one form in a screen file fails the gate, naming the file; the same file under `src/shell/` passes it
    (so it was the source check that refused, not a type error). (F8, PR2)"""
    name = f"{CONTROL}.{_extension(form)}"
    outside = _with_source(checked, f"screens/{name}", REFUSED_FORMS[form])
    assert outside.refused, f"the gate accepted {form}"
    assert name in outside.output, outside.output[-1500:]
    if form != "navigation" or _lib_declares_navigation(checked):  # else a type error refuses it in the shell too
        inside = _with_source(checked, f"shell/{name}", REFUSED_FORMS[form])
        assert not inside.refused, inside.output[-1500:]


def test_1540_f8_the_directories_the_location_cases_walk_cover_more_than_one_screen_folder():
    """The tree has a directory outside `src/shell/` and `src/generated/` besides `src/` itself, so the per-location
    test below is not a single case. (F8)"""
    assert len(LOCATIONS) > 2, LOCATIONS


@pytest.mark.parametrize("location", LOCATIONS.values(), ids=LOCATIONS.keys())
def test_1540_f8_the_source_check_applies_at_every_location_outside_the_shell(checked, location):
    """A refused form in a file at this location (`src/`, a directory outside the shell and the generated types, or a
    fresh one) fails the gate, naming the file. (F8)"""
    relative = f"{location}/{CONTROL}.ts" if location else f"{CONTROL}.ts"
    gate = _with_source(checked, relative, LOCATION_FORM)
    assert gate.refused, f"the gate accepted a refused form at src/{location}"
    assert f"{CONTROL}.ts" in gate.output, gate.output[-1500:]


@pytest.mark.parametrize("form", ALLOWED_FORMS)
def test_1540_f8_the_source_check_allows_what_a_screen_may_hold(checked, form):
    """A property named `location`, a path key and an `/api/auth/` comment pass the gate (twin of the refusals: matching
    is by resolved symbol and by string, never by name in comments). (F8)"""
    gate = _with_source(checked, f"screens/{CONTROL}.ts", ALLOWED_FORMS[form])
    assert not gate.refused, gate.output[-1500:]


def test_1540_f8_a_test_file_is_not_exempt_from_the_source_check(checked):
    """A passing unit-test file (the copy's own `decision.test.ts`) outside the shell passes the gate; with a never-called
    `fetch` appended it is refused naming the file; the same file under `src/shell/` passes. (F8)"""
    name = f"{CONTROL}.test.ts"
    original = (checked / "src" / CONTROL_TEST_SOURCE).read_text(encoding="utf-8")
    assert original.count(SHELL_IMPORT) == 1, f"{CONTROL_TEST_SOURCE} no longer imports its neighbour as {SHELL_IMPORT}"
    moved = original.replace(SHELL_IMPORT, SCREEN_IMPORT)
    assert SHELL_IMPORT not in moved, "the import was not rewritten"
    control = _with_source(checked, f"screens/{name}", moved)
    assert not control.refused, f"control: a passing test file outside the shell is refused:\n{control.output[-1500:]}"
    outside = _with_source(checked, f"screens/{name}", f"{moved}\n{NEVER_CALLED}")
    assert outside.refused, "the gate exempted a test file"
    assert name in outside.output, outside.output[-1500:]
    inside = _with_source(checked, f"shell/{name}", f"{original}\n{NEVER_CALLED}")
    assert not inside.refused, inside.output[-1500:]


# --- #1581 G9: `usePagedRead` refuses every read that is not a page -------------------------------------------------------

def _resolve(document: dict[str, Any], schema: dict[str, Any]) -> dict[str, Any]:
    while "$ref" in schema:
        node: Any = document
        for part in schema["$ref"].removeprefix("#/").split("/"):
            node = node[part]
        schema = node
    return schema


def _reads_of(document: dict[str, Any]) -> tuple[dict[str, str], dict[str, str]]:
    """The GET reads whose 200 answer is JSON, by path key, as the TypeScript call's params text: (those whose answer is
    `{items, next_cursor}`, all the others). Read from the document alone. Only the body decides: the design says "Only
    reads whose body is `{items, next_cursor}` qualify", and a page read whose query has no `cursor` is a page read."""
    paged: dict[str, str] = {}
    other: dict[str, str] = {}
    for path, item in document["paths"].items():
        operation = item.get("get")
        body = None if operation is None else operation["responses"].get("200", {}).get("content", {}).get("application/json")
        if body is None:
            continue
        schema = _resolve(document, body["schema"])
        parameters = [_resolve(document, p) for p in operation.get("parameters", [])]
        names = [p["name"] for p in parameters if p["in"] == "path"]
        params = "{ path: { " + ", ".join(f'{name}: ""' for name in names) + " } }" if names else "{}"
        is_page = {"items", "next_cursor"} <= set(schema.get("properties", {}))
        (paged if is_page else other)[path] = params
    return paged, other


def _paged_calls(paged: dict[str, str], other: dict[str, str]) -> tuple[str, set[int]]:
    """A source file calling `usePagedRead` once per read, each call on its own line with otherwise correct params, and
    the numbers of the lines that call a read that is not a page."""
    lines = ['import { usePagedRead } from "./provider";', "export function zzPagedCalls(): void {"]
    refused: set[int] = set()
    for path, params in {**paged, **other}.items():
        lines.append(f"  usePagedRead({json.dumps(path)}, {params});")
        if path in other:
            refused.add(len(lines))
    return "\n".join([*lines, "}"]), refused


def test_1581_g9_usepagedread_refuses_every_read_that_is_not_a_page(checked):
    """A file that calls `usePagedRead` once for each GET read of the document whose answer is JSON, with otherwise
    correct params, fails `bun run check` with a type error (of whatever code) on exactly the lines
    that call a read whose answer is not `{items, next_cursor}`, and on none that call a page read: the key is what is
    refused. The file is in `src/shell/`, where the source check allows what a screen could not hold; no
    `@ts-expect-error` is used, since the source check refuses it everywhere. (#1581 PagedKey)"""
    paged, other = _reads_of(json.loads((FRONTEND.parent / "api" / "openapi.json").read_text(encoding="utf-8")))
    assert len(other) >= 5, f"premise: reads that are not pages exist: {sorted(other)}"
    assert len(paged) >= 3, f"premise: page reads exist: {sorted(paged)}"
    assert "/api/tenants/{tenant_id}/alerts" in paged
    assert "/api/me" in other
    source, refused = _paged_calls(paged, other)
    gate = _with_source(checked, "shell/zz_paged_calls.ts", source, _check)
    errors = re.findall(r"zz_paged_calls\.ts:(\d+): TS\d+", gate.output)
    assert gate.refused, gate.output[-2000:]
    assert errors, gate.output[-2000:]
    assert {int(line) for line in errors} == refused, gate.output[-2000:]


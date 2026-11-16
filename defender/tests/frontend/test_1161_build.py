"""#1161 S2, Am-4, #1540 F1/F3/PR6/F8: the frontend build type-checks, reads the one shape list and the API's document (no
hand-kept copy), reads only its declared inputs, and the source check (`bun run check`) refuses what a screen may not do.
Every build runs in a `copy_frontend` copy, so the unmodified copy builds (control) and is also PR6's "the frontend
folder plus the declared inputs suffice"."""
from __future__ import annotations

import contextlib
import copy
import dataclasses
import json
import re
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from defender.tests.support.frontend._ingress1161 import FRONTEND, copy_frontend, node_modules_of, run_bun
from defender.tests.support.frontend._shapes1161 import REFUSED

LIST = FRONTEND.parent / "api" / "addresses.json"
ADDRESSES, OPENAPI = "../api/addresses.json", "../api/openapi.json"  # PR6's two inputs, as `package.json` writes them


def _add_one(document: Any) -> None:
    """Append a shape with a fresh name and a fresh literal template (the bound format, record "Chosen names")."""
    document["shapes"].append({"name": "zz-added", "template": "/zz-added", "returnable": False})


def _drop_one(document: Any) -> None:
    """Remove the `sign-in-failed` shape; exactly one entry goes."""
    before = len(document["shapes"])
    document["shapes"] = [s for s in document["shapes"] if s["name"] != "sign-in-failed"]
    assert before - len(document["shapes"]) == 1


EXAMPLE: dict[str, Any] = {"alphabets": {"hex": "0123456789abcdef"},
           "placeholders": {"uuid": [["hex", 8], "-", ["hex", 4], "-", ["hex", 4], "-", ["hex", 4], "-", ["hex", 12]]},
           "shapes": [{"name": "root", "template": "/", "returnable": True},
                      {"name": "investigation", "template": "/t/{uuid}/investigations/{uuid}", "returnable": True},
                      {"name": "sign-in-failed", "template": "/sign-in-failed", "returnable": False}]}


def test_the_list_edits_act_on_the_bound_format() -> None:
    """Machinery self-test, green without a frontend: each helper edits the bound example as intended."""
    added = copy.deepcopy(EXAMPLE)
    _add_one(added)
    assert {s["name"] for s in added["shapes"]} == {"root", "investigation", "sign-in-failed", "zz-added"}
    assert added["shapes"][-1]["template"] == "/zz-added"
    assert added["placeholders"] == EXAMPLE["placeholders"]
    dropped = copy.deepcopy(EXAMPLE)
    _drop_one(dropped)
    assert {s["name"] for s in dropped["shapes"]} == {"root", "investigation"}
    assert dropped["placeholders"] == EXAMPLE["placeholders"]


def _declared() -> list[str]:
    """`package.json`'s `defender.inputs` read at collection; the design's two names when it declares none yet (a red
    test, not a vanished parameter)."""
    with contextlib.suppress(OSError, ValueError, TypeError, KeyError):
        declared = json.loads((FRONTEND / "package.json").read_text(encoding="utf-8"))["defender"]["inputs"]
        if declared and all(isinstance(d, str) for d in declared):
            return list(declared)
    return [ADDRESSES, OPENAPI]


def _produced() -> dict[str, Any]:
    """What the API says about itself (grounding C3): `create_app` over a placeholder for every dependency."""
    from defender.api.app import create_app
    from defender.api.ports import ApiDeps

    deps: dict[str, Any] = {f.name: object() for f in dataclasses.fields(ApiDeps)}
    deps["frontend_origin"] = "http://localhost:1"
    return create_app(ApiDeps(**deps)).openapi()


def _bytes(document: Any) -> bytes:
    return json.dumps(document).encode("utf-8")


def _copy(tmp_path: Path, built: Path, **override: bytes | None) -> Path:
    """A `copy_frontend` copy sharing the built `node_modules`; `override` maps a declared input to bytes (or None)."""
    names = {"addresses": ADDRESSES, "openapi": OPENAPI}
    inputs = {names[k]: v for k, v in override.items()}
    return copy_frontend(tmp_path / "copy", inputs_override=inputs, node_modules_from=node_modules_of(built))


def _failing_build(frontend: Path) -> subprocess.CompletedProcess[str]:
    """`bun run build` over a copy holding a stale `dist/index.html`, which a failed build must leave gone (F1 b)."""
    (frontend / "dist").mkdir(exist_ok=True)
    (frontend / "dist" / "index.html").write_text("<html>stale</html>", encoding="utf-8")
    return run_bun(frontend, "run", "build")


def _no_index(frontend: Path) -> bool:
    return not (frontend / "dist" / "index.html").exists()


@pytest.mark.parametrize("edit", [None, _add_one, _drop_one], ids=["unmodified", "shape-added", "shape-removed"])
def test_1161_s2_the_build_follows_the_shape_list_and_fails_on_a_type_error(built_frontend, tmp_path, edit):
    """A copy builds as is; with one shape added to or removed from the list the build fails and leaves no
    `index.html`, so every shape has a route and every route a shape. (S2, F1 b)"""
    document = json.loads(LIST.read_text(encoding="utf-8"))
    if edit is not None:
        edit(document)
    frontend = _copy(tmp_path, built_frontend, addresses=_bytes(document))
    if edit is None:
        done = run_bun(frontend, "run", "build")
        assert done.returncode == 0, (done.stdout[-1500:], done.stderr[-1500:])
        assert (frontend / "dist" / "index.html").is_file()
    else:
        done = _failing_build(frontend)
        assert done.returncode != 0, "the build accepted a shape list its router does not match"
        assert _no_index(frontend)


#: Every TypeScript source of the app outside the generated types and declaration files (a `skipLibCheck` honestly skips
#: those) (F1 b: the type check is the whole project's).
SOURCES = sorted(p.relative_to(FRONTEND) for pattern in ("*.ts", "*.tsx") for p in (FRONTEND / "src").rglob(pattern)
                 if "generated" not in p.relative_to(FRONTEND).parts and not p.name.endswith(".d.ts"))


def test_1540_f1_the_source_set_the_type_error_test_walks_spans_the_shell_and_the_screens():
    """The glob finds sources both under `src/shell/` and outside it, so the per-file test below is not vacuous. (F1 b)"""
    shell = [s for s in SOURCES if s.parts[:2] == ("src", "shell")]
    assert shell, SOURCES
    assert len(SOURCES) > len(shell), SOURCES


@pytest.mark.parametrize("source", SOURCES, ids=[s.as_posix() for s in SOURCES])
def test_1161_s2_the_build_fails_on_a_type_error_in_any_source_file(built_frontend, tmp_path, source):
    """One unrelated type error put in this source file fails the build, and a stale `dist/index.html` is gone
    afterwards (`dist/` is removed first). The unmodified copy builds (control, above). (F1 b, S2, B8)"""
    frontend = _copy(tmp_path, built_frontend)
    with (frontend / source).open("a", encoding="utf-8") as handle:
        handle.write("\nexport const unrelatedTypeError: number = 'not a number';\n")
    done = _failing_build(frontend)
    assert done.returncode != 0, f"{source}: the build accepted a type error"
    assert _no_index(frontend), f"{source}: index.html remains"


@pytest.mark.parametrize(("document", "words"), [pytest.param(d, w, id=i) for i, d, w in REFUSED])
def test_1161_s2_the_build_refuses_every_list_the_api_refuses(built_frontend, tmp_path, document, words):
    """Each list in the shared table fails the build, in the same words as the API's reader, and leaves no
    `index.html` (a stale one included): a grammar that could match outside its segment, or a template that does not compile. (F1 c, S2)"""
    frontend = _copy(tmp_path, built_frontend, addresses=_bytes(document))
    done = _failing_build(frontend)
    assert done.returncode != 0, "the build accepted a list the API refuses"
    assert words in done.stderr + done.stdout, done.stderr[-1500:]
    assert _no_index(frontend)


@pytest.mark.parametrize("omitted", _declared())
def test_1540_pr6_a_build_missing_a_declared_input_fails(built_frontend, tmp_path, omitted):
    """The copy lacks this one input the build declares: the build fails and leaves no `index.html`, a stale one
    included (the unmodified copy above is the sufficiency control). (PR6, F1 b)"""
    frontend = copy_frontend(tmp_path / "copy", inputs_override={omitted: None},
                             node_modules_from=node_modules_of(built_frontend))
    done = _failing_build(frontend)
    assert done.returncode != 0, f"the build ran without {omitted}"
    assert _no_index(frontend)


def _drop_property(document: dict[str, Any], schema: str, prop: str) -> None:
    node = document["components"]["schemas"][schema]
    del node["properties"][prop]
    node["required"] = [r for r in node.get("required", []) if r != prop]


def _person_email(document: dict[str, Any]) -> None:
    """The home shows the person's email: `/api/me`'s person schema (`kind: person`) holds a user schema with `email`."""
    schemas = document["components"]["schemas"]
    [person] = [s for s in schemas.values() if s.get("properties", {}).get("kind", {}).get("const") == "person"]
    user = schemas[person["properties"]["user"]["$ref"].rsplit("/", 1)[1]]
    del user["properties"]["email"]
    user["required"] = [r for r in user.get("required", []) if r != "email"]


@pytest.mark.parametrize("edit", [None, lambda d: _drop_property(d, "Investigation", "disposition"),
                                  lambda d: _drop_property(d, "Investigation", "status"), _person_email],
                         ids=["produced-unedited", "no-disposition", "no-status", "no-person-email"])
def test_1540_f3_a_document_without_a_field_a_screen_reads_fails_the_build(built_frontend, tmp_path, edit):
    """Over the document the app produces: unedited it builds and writes `index.html` (control); without a field a
    screen reads (disposition, status, the person's email) the build fails and writes none. (F3, F1 b)"""
    document = _produced()
    if edit is not None:
        edit(document)
    frontend = _copy(tmp_path, built_frontend, openapi=_bytes(document))
    done = _failing_build(frontend) if edit is not None else run_bun(frontend, "run", "build")
    if edit is None:
        assert done.returncode == 0, (done.stdout[-1500:], done.stderr[-1500:])
        assert (frontend / "dist" / "index.html").is_file()
    else:
        assert done.returncode != 0, "the build accepted a document that lacks a field a screen reads"
        assert _no_index(frontend)


def test_1161_the_test_build_never_writes_the_checkout(built_frontend):
    """The built `dist/` is outside the checkout's frontend folder, so a build never replaces files another run is
    serving. (B11, test machinery)"""
    assert FRONTEND not in built_frontend.parents, built_frontend


# --- F8: the source check, observed through the lint job's gate (F6): `bun run check`, then `bun run test` ---------------

CONTROL = "zz_control"
#: One refused form each (F8's list, `navigation` included). Each is valid TypeScript but `navigation`, which the pinned
#: TypeScript's DOM library may not declare: then a type error also refuses it, and its shell twin below cannot pass.
REFUSED_FORMS: dict[str, str] = {
    "fetch": 'export const x = fetch("/x");',
    "XMLHttpRequest": "export const x = new XMLHttpRequest();",
    "EventSource": 'export const x = new EventSource("/x");',
    "WebSocket": 'export const x = new WebSocket("ws://x");',
    "sendBeacon": 'export const x = navigator.sendBeacon("/x");',
    "localStorage": 'export const x = localStorage.getItem("k");',
    "sessionStorage": 'export const x = sessionStorage.getItem("k");',
    "indexedDB": 'export const x = indexedDB.open("x");',
    "caches": "export const x = caches.keys();",
    "document.cookie": "export const x = document.cookie;",
    "bare location": "export const x = location.href;",
    "window.location": "export const x = window.location.href;",
    "document.location": "export const x = document.location;",
    "self.location": "export const x = self.location;",
    "globalThis.location": "export const x = globalThis.location;",
    "history": "history.back();\nexport const x = 1;",
    "navigation": "export const x = navigation;",
    "window.open": 'export const x = window.open("/x");',
    "destructured fetch": "const { fetch: f } = window;\nexport const x = f;",
    "auth path literal": 'export const x = "/api/auth/login";',
    "auth path JSX attribute": 'export const x = <a href="/api/auth/logout">out</a>;',
}
#: What a screen may hold: a property named `location`, a path key `read` takes, an `/api/auth/` comment.
ALLOWED_FORMS: dict[str, str] = {
    "location property": 'const r = { location: "x" };\nexport const x = r.location;',
    "path key": 'export const x = "/api/tenants/{tenant_id}/investigations/{investigation_id}";',
    "auth path in a comment": "// /api/auth/login\nexport const x = 1;",
}
#: The form every location is tried with, and the directory a copy has none of yet.
LOCATION_FORM = REFUSED_FORMS["fetch"]
FRESH = "zz_fresh"


def _locations() -> dict[str, str]:
    """Where under `src/` the source check applies: `src/` itself, every directory outside `shell/` and `generated/`
    (read from the tree), and one directory the tree does not have. id -> directory relative to `src/`."""
    src = FRONTEND / "src"
    found = {"src": ""}
    for path in sorted(p for p in src.rglob("*") if p.is_dir()):
        relative = path.relative_to(src)
        if not {"shell", "generated"} & set(relative.parts):
            found[f"src/{relative.as_posix()}"] = relative.as_posix()
    found["src/(a fresh directory)"] = FRESH
    return found


LOCATIONS = _locations()


@dataclasses.dataclass
class Gate:
    """The lint job's two commands run in order on a copy; it stops at the first that exits non-zero."""

    returncode: int
    output: str

    @property
    def refused(self) -> bool:
        return self.returncode != 0


def _output(done: subprocess.CompletedProcess[str]) -> str:
    return done.stdout + done.stderr


def _gate(frontend: Path) -> Gate:
    """`bun run check` then `bun run test` in `frontend`: refused when either exits non-zero (F6, F8)."""
    output = ""
    for script in ("check", "test"):
        done = run_bun(frontend, "run", script)
        output += f"$ bun run {script} -> {done.returncode}\n{_output(done)}"
        if done.returncode != 0:
            return Gate(done.returncode, output)
    return Gate(0, output)


def _check(frontend: Path) -> Gate:
    """`bun run check` alone, in the gate's shape."""
    done = run_bun(frontend, "run", "check")
    return Gate(done.returncode, _output(done))


def _unit_tests(frontend: Path) -> Gate:
    """`bun run test` alone, in the gate's shape."""
    done = run_bun(frontend, "run", "test")
    return Gate(done.returncode, _output(done))


@pytest.fixture(scope="module")
def checked(built_frontend, tmp_path_factory) -> Path:
    """One copy of the frontend for the source-check cases, sharing the built `node_modules`."""
    return copy_frontend(tmp_path_factory.mktemp("check"), node_modules_from=node_modules_of(built_frontend))


def _with_source(frontend: Path, relative: str, text: str, run: Callable[[Path], Gate] = _gate) -> Gate:
    """`run(frontend)` with `relative` (under `src/`) holding `text`; the file, and a directory made for it, go again."""
    path = frontend / "src" / relative
    fresh = [d for d in reversed(path.parents) if d != frontend / "src" and frontend / "src" in d.parents and not d.exists()]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text + "\n", encoding="utf-8")
    try:
        return run(frontend)
    finally:
        path.unlink()
        for directory in reversed(fresh):
            directory.rmdir()


def _lib_declares_navigation(frontend: Path) -> bool:
    """Whether the copy's TypeScript DOM library declares the global `navigation` (a form no valid file can hold if not)."""
    lib = frontend / "node_modules" / "typescript" / "lib" / "lib.dom.d.ts"
    return re.search(r"^declare var navigation\b", lib.read_text(encoding="utf-8"), re.M) is not None


def _extension(form: str) -> str:
    return "tsx" if "JSX" in form else "ts"


def test_1540_f8_the_gate_passes_on_the_unmodified_tree(checked):
    """`bun run check` then `bun run test` exit 0 on the copy. (F8, F6)"""
    gate = _gate(checked)
    assert not gate.refused, gate.output[-1500:]


def test_1540_f1_the_check_fails_on_a_plain_type_error(checked):
    """`bun run check` is generate + type check: an unrelated type error fails it. (F1)"""
    gate = _with_source(checked, "screens/zz_type_error.ts", "export const bad: number = 'not a number';", _check)
    assert gate.refused, "check accepted a type error"


def test_1540_f6_the_unit_test_command_passes_on_the_unmodified_tree(checked):
    """`bun run test` exits 0 on the copy: the gate's second half is something the tree passes. (F6, F1)"""
    done = _unit_tests(checked)
    assert not done.refused, done.output[-1500:]


def test_1540_f6_a_unit_test_file_that_throws_at_load_fails_the_unit_test_command(checked):
    """A `src/shell/zz_fail.test.ts` whose module throws when loaded makes `bun run test` exit non-zero, naming it, and
    the gate refuses the tree. (F6, F8)"""
    text = 'export {};\nthrow new Error("zz_fail: refused at load");'
    failing = _with_source(checked, "shell/zz_fail.test.ts", text, _unit_tests)
    assert failing.refused, "`bun run test` ran no unit-test file, or let a failing one pass"
    assert "zz_fail.test.ts" in failing.output, failing.output[-1500:]
    assert _with_source(checked, "shell/zz_fail.test.ts", text).refused, "the gate accepted a failing unit-test file"


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
    """The refused `fetch` in `*.test.ts` outside the shell fails `bun run check` naming that file; the same file under
    `src/shell/` passes it. Judged on `bun run check` alone: a unit-test file with no test fails `bun run test` by itself,
    and a passing test is written in a runner's own API, which this contract does not name. (F8)"""
    name = f"{CONTROL}.test.ts"
    outside = _with_source(checked, f"screens/{name}", REFUSED_FORMS["fetch"], _check)
    assert outside.refused, "check exempted a test file"
    assert name in outside.output, outside.output[-1500:]
    inside = _with_source(checked, f"shell/{name}", REFUSED_FORMS["fetch"], _check)
    assert not inside.refused, inside.output[-1500:]

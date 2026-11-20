"""#1161 S2, Am-4, #1540 F1/F3/PR6/F8: the frontend build type-checks, reads the one shape list and the API's document (no
hand-kept copy), reads only its declared inputs, and the source check refuses what a screen may not do (observed through
`_gate`, the lint job's `bun run check` then `bun run test`: no test decides which command hosts the check).
Every build runs in a `copy_frontend` copy, so the unmodified copy builds (control) and is also PR6's "the frontend
folder plus the declared inputs suffice"."""
from __future__ import annotations

import contextlib
import copy
import dataclasses
import json
import re
import shutil
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


PREVIOUS_BUILD = "<html>the previous build</html>"


def _failing_build(frontend: Path) -> subprocess.CompletedProcess[str]:
    """`bun run build` over a copy holding a previous build's `dist/index.html`, which a failed build leaves as it was
    (F1 b: the served folder is only ever one whole build)."""
    dist = frontend / "dist"
    if dist.is_symlink():  # an earlier build's link to its folder, which this previous build replaces with it
        dist.unlink()
    else:
        shutil.rmtree(dist, ignore_errors=True)
    shutil.rmtree(frontend / "dist-builds", ignore_errors=True)
    dist.mkdir()
    (frontend / "dist" / "index.html").write_text(PREVIOUS_BUILD, encoding="utf-8")
    return run_bun(frontend, "run", "build")


def _previous_build_kept(frontend: Path) -> bool:
    """The failed build left the previous build in `dist/` untouched, and nothing half-built anywhere (F1 b)."""
    index = frontend / "dist" / "index.html"
    leftovers = [p.name for p in frontend.iterdir() if p.name.startswith("dist") and p.name != "dist"]
    return index.read_text(encoding="utf-8") == PREVIOUS_BUILD and leftovers == [] and sorted(
        p.name for p in (frontend / "dist").iterdir()) == ["index.html"]


@pytest.mark.parametrize("edit", [None, _add_one, _drop_one], ids=["unmodified", "shape-added", "shape-removed"])
def test_1161_s2_the_build_follows_the_shape_list_and_fails_on_a_type_error(built_frontend, tmp_path, edit):
    """A copy builds as is; with one shape added to or removed from the list the build fails and leaves the
    previous build as it was, so every shape has a route and every route a shape. (S2, F1 b)"""
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
        assert _previous_build_kept(frontend)


def _own_assets(frontend: Path) -> set[str]:
    """The `assets/` files the served build wrote itself: its Vite manifest's."""
    manifest = json.loads((frontend / "dist" / ".vite" / "manifest.json").read_text(encoding="utf-8"))
    return {f for chunk in manifest.values() for f in (chunk["file"], *chunk.get("css", ()), *chunk.get("assets", ()))
            if f.startswith("assets/")}


def _served_assets(frontend: Path) -> set[str]:
    return {p.relative_to(frontend / "dist").as_posix() for p in (frontend / "dist" / "assets").iterdir()}


def test_1540_f1_b_a_build_is_swapped_in_whole_and_keeps_the_previous_builds_own_files_one_build_long(built_frontend, tmp_path):
    """Three builds of a copy, each with a changed screen: `dist` links to the newest build's folder, and nothing else
    is left (no other build folder, no link not swapped in); each build serves its own `assets/` files and the previous
    build's own, so a page that build served still loads; the build before that is gone. (F1 b)"""
    frontend = _copy(tmp_path, built_frontend)
    screen = frontend / "src" / "screens" / "NotFound.tsx"
    owns = []
    for n in range(3):
        screen.write_text(screen.read_text(encoding="utf-8").replace("</h1>", f" zz{n}</h1>", 1), encoding="utf-8")
        done = run_bun(frontend, "run", "build")
        assert done.returncode == 0, (done.stdout[-1500:], done.stderr[-1500:])
        assert (frontend / "dist").is_symlink(), "dist is a link to the served build"
        folders = list((frontend / "dist-builds").iterdir())
        assert [f.resolve() for f in folders] == [(frontend / "dist").resolve()], folders
        assert [p.name for p in frontend.iterdir() if p.name.startswith("dist-link-")] == []
        owns.append(_own_assets(frontend))
        assert owns[-1] <= _served_assets(frontend)
        if n > 0:
            assert owns[-2] - owns[-1], "positive control: the changed screen changed a file's name"
            assert owns[-2] <= _served_assets(frontend), "the previous build's own files are kept"
        if n > 1:
            assert not (owns[-3] - owns[-2] - owns[-1]) & _served_assets(frontend), "two builds back is gone"


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
    """One unrelated type error put in this source file fails the build, and the previous build in `dist/` is left as
    it was (the build writes to a staging folder). The unmodified copy builds (control, above). (F1 b, S2, B8)"""
    frontend = _copy(tmp_path, built_frontend)
    with (frontend / source).open("a", encoding="utf-8") as handle:
        handle.write("\nexport const unrelatedTypeError: number = 'not a number';\n")
    done = _failing_build(frontend)
    assert done.returncode != 0, f"{source}: the build accepted a type error"
    assert _previous_build_kept(frontend), f"{source}: the failed build touched dist/"


@pytest.mark.parametrize(("document", "words"), [pytest.param(d, w, id=i) for i, d, w in REFUSED])
def test_1161_s2_the_build_refuses_every_list_the_api_refuses(built_frontend, tmp_path, document, words):
    """Each list in the shared table fails the build, in the same words as the API's reader, and leaves the
    previous build as it was: a grammar that could match outside its segment, or a template that does not compile. (F1 c, S2)"""
    frontend = _copy(tmp_path, built_frontend, addresses=_bytes(document))
    done = _failing_build(frontend)
    assert done.returncode != 0, "the build accepted a list the API refuses"
    assert words in done.stderr + done.stdout, done.stderr[-1500:]
    assert _previous_build_kept(frontend)


@pytest.mark.parametrize("omitted", _declared())
def test_1540_pr6_a_build_missing_a_declared_input_fails(built_frontend, tmp_path, omitted):
    """The copy lacks this one input the build declares: the build fails and leaves the previous build as it
    was (the unmodified copy above is the sufficiency control). (PR6, F1 b)"""
    frontend = copy_frontend(tmp_path / "copy", inputs_override={omitted: None},
                             node_modules_from=node_modules_of(built_frontend))
    done = _failing_build(frontend)
    assert done.returncode != 0, f"the build ran without {omitted}"
    assert _previous_build_kept(frontend)


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
    """Over the document the app produces: unedited it builds and writes `index.html` (control); then, in that same
    copy, without a field a screen reads (disposition, status, the person's email) the build fails and writes none. (F3, F1 b)"""
    document = _produced()
    frontend = _copy(tmp_path, built_frontend, openapi=_bytes(document))
    done = run_bun(frontend, "run", "build")
    assert done.returncode == 0, (done.stdout[-1500:], done.stderr[-1500:])
    assert (frontend / "dist" / "index.html").is_file()
    if edit is not None:
        # The same copy, built once over the unedited document: its generated types must not outlive the edit.
        edit(document)
        (frontend / OPENAPI).write_bytes(_bytes(document))
        done = _failing_build(frontend)
        assert done.returncode != 0, "the build accepted a document that lacks a field a screen reads"
        assert _previous_build_kept(frontend)


#: The five outcome codes (alert list design O2, AP4); the document declares them once, whichever schema carries them.
OUTCOME_CODES = {"benign", "false-positive", "inconclusive", "malicious", "unresolved"}


def _each_code_list(document: Any, edit: Callable[[list[str]], None]) -> int:
    """`edit` applied to every `enum` list in the document that is exactly the five outcome codes; how many there were."""
    found = 0

    def walk(node: Any) -> None:
        nonlocal found
        if isinstance(node, dict):
            codes = node.get("enum")
            if isinstance(codes, list) and set(codes) == OUTCOME_CODES:
                edit(codes)
                found += 1
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(document)
    return found


@pytest.mark.parametrize("edit", [None, lambda codes: codes.append("zz-sixth"), lambda codes: codes.remove("benign")],
                         ids=["produced-unedited", "sixth-code-added", "code-removed"])
def test_ap4_a_document_whose_outcome_codes_the_screen_does_not_name_fails_the_build(built_frontend, tmp_path, edit):
    """The screen's labels and address check are keyed by the generated outcome union: over the produced document the
    build passes (control); with a sixth code added, or one removed, it fails and writes no `index.html`. (AP4)"""
    document = _produced()
    assert _each_code_list(document, lambda codes: None) >= 1, "the document declares the five outcome codes (O1, AP4)"
    frontend = _copy(tmp_path, built_frontend, openapi=_bytes(document))
    done = run_bun(frontend, "run", "build")
    assert done.returncode == 0, (done.stdout[-1500:], done.stderr[-1500:])
    if edit is not None:
        _each_code_list(document, edit)
        (frontend / OPENAPI).write_bytes(_bytes(document))
        done = _failing_build(frontend)
        assert done.returncode != 0, "the build accepted outcome codes the screen does not name"
        assert _previous_build_kept(frontend)


#: The investigation screen's read, as the document keys it.
INVESTIGATION_READ = "/api/tenants/{tenant_id}/investigations/{investigation_id}"


def _rename_path_parameter(document: dict[str, Any]) -> None:
    """The read's `investigation_id` parameter is renamed in its parameter list (the path key is left as it is)."""
    [parameter] = [p for p in document["paths"][INVESTIGATION_READ]["get"]["parameters"]
                   if p["in"] == "path" and p["name"] == "investigation_id"]
    parameter["name"] = "zz_investigation"


def _require_query_parameter(document: dict[str, Any]) -> None:
    """The read gains a required query parameter the screen does not send."""
    document["paths"][INVESTIGATION_READ]["get"]["parameters"].append(
        {"name": "zz_required", "in": "query", "required": True, "schema": {"type": "string"}})


@pytest.mark.parametrize("edit", [_rename_path_parameter, _require_query_parameter],
                         ids=["path-parameter-renamed", "required-query-parameter-added"])
def test_1540_f3_a_document_whose_read_takes_parameters_the_screen_does_not_send_fails_the_build(
        built_frontend, tmp_path, edit):
    """The investigation read's parameters change in the document (a path parameter renamed, a required query parameter
    added): the screen's call no longer type-checks, so the build fails and writes no `index.html`. The unedited
    document builds (control: the F3 field test above). (F3, Am-6: `read(key, params)` typed by the generated types)"""
    document = _produced()
    edit(document)
    frontend = _copy(tmp_path, built_frontend, openapi=_bytes(document))
    done = _failing_build(frontend)
    assert done.returncode != 0, "the build accepted a read whose parameters the screen does not send"
    assert _previous_build_kept(frontend)


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
    """`bun run check` alone, in the gate's shape: only for an obligation about that command's own definition (F1)."""
    done = run_bun(frontend, "run", "check")
    return Gate(done.returncode, _output(done))


def _unit_tests(frontend: Path) -> Gate:
    """`bun run test` alone, in the gate's shape: only for an obligation about that command's own definition (F1)."""
    done = run_bun(frontend, "run", "test")
    return Gate(done.returncode, _output(done))


@pytest.fixture
def checked(built_frontend, tmp_path) -> Path:
    """A pristine copy of the frontend for this test alone (the same helper as every build case: `_copy`), so no verdict
    depends on what an earlier test ran in it, such as whether `generated/` already exists."""
    return _copy(tmp_path, built_frontend)


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


#: A passing test file the copy already holds, and the import it makes of its neighbour in `src/shell/`.
CONTROL_TEST_SOURCE = "shell/decision.test.ts"
SHELL_IMPORT, SCREEN_IMPORT = 'from "./decision"', 'from "../shell/decision"'
#: A refused form that is never called, so the gate refuses the file by its source and not by what the runner does.
NEVER_CALLED = 'export function zzNeverCalled(): Promise<Response> { return fetch("/x"); }'


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


# --- F8: the corpus of refused and allowed forms, one gate run per corpus -----------------------------------------------

#: The DOM library's refused members of the window and global scope, each reachable from every window-like receiver.
_WINDOW_SYMBOLS = ("fetch", "XMLHttpRequest", "EventSource", "WebSocket", "localStorage", "sessionStorage", "indexedDB",
                   "caches", "location", "history", "open")


@dataclasses.dataclass(frozen=True)
class _Receiver:
    """Where a refused symbol is read from: `params` and `prelude` set it up, `expression` names it, `type` types it."""

    name: str
    expression: str
    type: str
    params: str = ""
    prelude: str = ""


def _receivers(home: str, type_: str) -> list[_Receiver]:
    """The receivers of a symbol whose home object is `home` (typed `type_`): itself, an alias, a typed parameter."""
    return [_Receiver(home, home, type_), _Receiver(f"alias of {home}", "zzAlias", type_, prelude=f"const zzAlias = {home};"),
            _Receiver(f"parameter typed {type_}", "zzParam", type_, params=f"zzParam: {type_}")]


def _window_type(symbol: str) -> str:
    """The type a parameter holding a window is given: `Window`, or for the constructors (declared on the global scope,
    not on the `Window` interface) the global scope's type."""
    return "typeof globalThis" if symbol in {"XMLHttpRequest", "EventSource", "WebSocket"} else "Window"


#: symbol -> its receivers: the window members from `window`, `self`, `globalThis`, an alias and a `Window` parameter;
#: `location` and `cookie` from `document`; `sendBeacon` from `navigator`.
_SYMBOL_RECEIVERS: dict[str, list[_Receiver]] = {
    **{symbol: [*_receivers("window", _window_type(symbol)), _Receiver("self", "self", _window_type(symbol)),
                _Receiver("globalThis", "globalThis", "typeof globalThis")] for symbol in _WINDOW_SYMBOLS},
    "document.location": _receivers("document", "Document"),
    "cookie": _receivers("document", "Document"),
    "sendBeacon": _receivers("navigator", "Navigator"),
}

#: How the symbol is reached from the receiver; `{S}` is the symbol, `{R}` the receiver expression.
_REACHES: dict[str, str] = {
    "access": "return {R}.{S};",
    "element access": 'return {R}["{S}"];',
    "shorthand destructure": "const {{ {S} }} = {R}; return {S};",
    "renamed destructure": "const {{ {S}: zzValue }} = {R}; return zzValue;",
    "nested destructure": "const {{ zzInner: {{ {S}: zzValue }} }} = {{ zzInner: {R} }}; return zzValue;",
    "for-of head": "for (const {{ {S}: zzValue }} of [{R}]) {{ return zzValue; }} return undefined;",
    "assignment destructure": "let zzValue: unknown; ({{ {S}: zzValue }} = {R}); return zzValue;",
}


def _refused_corpus() -> dict[str, str]:
    """Every refused form (F8): description -> one module's text. Symbols x receivers x reaches, a parameter destructured
    by type, the bare globals, `Reflect.get` on `globalThis`, an import of any shell module but the provider (static,
    side-effect, re-export, dynamic), and `/api/auth/` as a string, a template with no substitution, a template head and a JSX
    attribute. Left out: `for ({ fetch } of [window])` (an assignment pattern in a for-of head)."""
    corpus: dict[str, str] = {}
    for key, receivers in _SYMBOL_RECEIVERS.items():
        symbol = key.rsplit(".", 1)[-1]
        if key in _WINDOW_SYMBOLS:
            corpus[f"bare {symbol}"] = f"export const zzForm = () => {symbol};"
        for receiver in receivers:
            for reach, body in _REACHES.items():
                text = body.format(S=symbol, R=receiver.expression)
                corpus[f"{symbol} from {receiver.name}, {reach}"] = (
                    f"export const zzForm = ({receiver.params}) => {{ {receiver.prelude} {text} }};")
        for type_ in sorted({r.type for r in receivers}):
            corpus[f"{symbol} from a parameter of type {type_}, parameter destructure"] = (
                f"export const zzForm = ({{ {symbol}: zzValue }}: {type_}) => zzValue;")
    corpus.update({
        "auth path string": 'export const zzForm = "/api/auth/login";',
        "auth path template without substitution": "export const zzForm = `/api/auth/login`;",
        "auth path template head": "export const zzForm = (zzWhere: string) => `/api/auth/${zzWhere}`;",
        "auth path JSX attribute": 'export const zzForm = <a href="/api/auth/logout">out</a>;',
        # A DOM object a screen is handed (a React ref's element, an event's target) leads to the globals too.
        "cookie from an element's document, access": "export const zzForm = (zzEl: HTMLElement) => zzEl.ownerDocument.cookie;",
        "cookie from an element's document, element access": (
            'export const zzForm = (zzEl: HTMLElement) => zzEl.ownerDocument["cookie"];'),
        "cookie from an element's document, nested destructure": (
            "export const zzForm = (zzEl: HTMLElement) => { const { ownerDocument: { cookie } } = zzEl; return cookie; };"),
        "cookie from an element's document, assignment destructure": (
            "export const zzForm = (zzEl: HTMLElement) => { let zzValue: unknown;"
            " ({ ownerDocument: { cookie: zzValue } } = zzEl); return zzValue; };"),
        "cookie from an element's document, for-of head": (
            "export const zzForm = (zzEl: HTMLElement) => { for (const { ownerDocument: { cookie } } of [zzEl])"
            " { return cookie; } return undefined; };"),
        "fetch by Reflect.get on globalThis": 'export const zzForm = () => Reflect.get(globalThis, "fetch");',
        "auth path in a template's middle": "export const zzForm = (zzBase: string) => `${zzBase}/api/auth/logout`;",
        "fetch from an element's window": (
            'export const zzForm = (zzEl: HTMLElement) => zzEl.ownerDocument.defaultView?.fetch("/x");'),
        # PR2's other half: a module outside the shell reaches it through the provider alone.
        "an import of a shell module other than the provider": 'import { makeLoad } from "../../shell/load";\nexport const zzForm = makeLoad;',
        "a side-effect import of a shell module": 'import "../../shell/attempt";\nexport const zzForm = 1;',
        "a re-export from a shell module": 'export { record as zzForm } from "../../shell/attempt";',
        "a dynamic import of a shell module": 'export const zzForm = () => import("../../shell/attempt");',
        # Rule 5: markup the browser sends a request for, without the shell's client.
        "an image of an API path built in a template": (
            "export const zzForm = (zzId: string) => <img src={`/a${\"pi\"}/tenants/${zzId}`} alt=\"\" />;"),
        "a link to an API path in another case": 'export const zzForm = <a href="/API/me">me</a>;',
        "a link to an API path by a relative path": 'export const zzForm = <a href="../api/me">me</a>;',
        "a form posting to an address held in a variable": (
            'const zzWhere = "/home";\nexport const zzForm = <form method="post" action={zzWhere}><button /></form>;'),
        "a spread onto an HTML element": (
            "export const zzForm = (zzProps: { src: string }) => <img alt=\"\" {...zzProps} />;"),
        "raw HTML": ('export const zzForm = <div dangerouslySetInnerHTML={{ __html: "<img src=/api/me>" }} />;'),
        "an inline style": "export const zzForm = <div style={{ backgroundImage: \"url(/api/me)\" }} />;",
        "React's createElement imported": (
            'import { createElement } from "react";\nexport const zzForm = createElement("img", { src: "/api/me" });'),
        "React's createElement through its namespace": (
            'import * as React from "react";\nexport const zzForm = React.createElement("img", { src: "/api/me" });'),
        "React's JSX runtime": 'import { jsx } from "react/jsx-runtime";\nexport const zzForm = jsx("img", { src: "/api/me" });',
    })
    corpus.update(_api_spelling_corpus())
    return corpus


#: Rule 5 (#1581 R3): what the browser resolves to a path under `/api` however the markup spells it. The requests those
#: spellings make are the API's, so they are refused whichever attribute carries them. Checked against the URL standard's
#: parser: from `/home` or from any returnable address of `api/addresses.json` (`/t/<uuid>/investigations/<uuid>`), each
#: resolves to a path under `/api` (the percent-encoded letters are the ingress's to decode).
API_SPELLINGS: dict[str, str] = {
    "a dot segment": "/./api/me",
    "a segment and its parent": "/x/../api/me",
    "a parent of the root": "/../api/me",
    "a dot segment after the api": "/api/./me",
    "a percent-encoded letter": "/%61pi/me",
    "a percent-encoded capital": "/%41pi/me",
    "a percent-encoded dot": "/%2e/api/me",
    "a percent-encoded parent": "/%2e%2e/api/me",
    "a half-encoded parent": "/.%2e/api/me",
    "a backslash for a slash": "/a\\..\\api/me",
    "a tab inside the name": "/ap\ti/me",
    "a newline inside the name": "/ap\ni/me",
    "the api itself": "/api",
    "the api with a query": "/api?x=1",
    "the api with a fragment": "/api#f",
    "the api behind a home segment": "/home/../api/me",
    "relative from home, plain": "api/me",
    "relative from home, dot": "./api/me",
    "relative from home, parent": "../api/me",
    "relative from an investigation, up to the root": "../../../api/me",
    "relative from an investigation, past the root": "../../../../api/me",
}
#: One spelling in every attribute whose value the browser requests or navigates to, as the JSX that holds it.
API_ATTRIBUTE_FORMS: dict[str, str] = {
    "src": '<img alt="" src="{v}" />', "srcSet": '<img alt="" srcSet="{v} 2x" />', "href": '<a href="{v}">x</a>',
    "action": '<form action="{v}"><button /></form>', "formAction": '<form><button formAction="{v}" /></form>',
    "poster": '<video poster="{v}" />', "data": '<object data="{v}" />', "ping": '<a href="/home" ping="{v}">x</a>',
    "cite": '<blockquote cite="{v}" />', "xlinkHref": '<svg><use xlinkHref="{v}" /></svg>',
}


def _api_spelling_corpus() -> dict[str, str]:
    """description -> one module: every spelling in `href`, and the plain dot-segment spelling in every other attribute,
    plus a candidate list whose second candidate is the API's."""
    corpus = {f"{why} ({text!r}) in href": f"export const zzForm = {API_ATTRIBUTE_FORMS['href'].format(v=text)};"
              for why, text in API_SPELLINGS.items()}
    for attribute, form in API_ATTRIBUTE_FORMS.items():
        corpus[f"a dot segment into the api in {attribute}"] = f"export const zzForm = {form.format(v='/./api/me')};"
    corpus["an image candidate list whose second candidate is the api's"] = (
        'export const zzForm = <img alt="" srcSet="/home 1x, /./api/me 2x" />;')
    corpus["an image candidate list whose only candidate is the api's"] = (
        'export const zzForm = <img alt="" srcSet="/%61pi/me" />;')
    corpus.update(_any_attribute_corpus())
    return corpus


#: Rule 5 has no attribute list (#1581 r3.3): a string a screen writes in ANY attribute is refused when it resolves to the
#: API, including attributes no list of URL-bearing ones ever had; `srcDoc`, `dangerouslySetInnerHTML` and a `meta`
#: `httpEquiv` `content` carry HTML or a navigation instruction in a string, so they are refused outright.
ANY_ATTRIBUTE_FORMS: dict[str, str] = {
    "imageSrcSet on a link": '<link rel="preload" as="image" imageSrcSet="/api/me 1x" />',
    "imageSrcSet on a link, a dot segment": '<link rel="preload" as="image" imageSrcSet="/home 1x, /./api/me 2x" />',
    "a made-up data attribute": '<div data-zz-url="/api/me" />',
    "a made-up data attribute, a dot segment": '<div data-zz-url="/./api/me" />',
    "a made-up data attribute, a relative dot segment": '<div data-zz-url="./api/me" />',
    "a made-up data attribute, a percent-encoded relative name": '<div data-zz-url="%61pi/me" />',
    "a made-up data attribute, a named-entity slash": '<div data-zz-url="&sol;api/me" />',
    "a link, a named-entity slash": '<a href="&sol;api/me">x</a>',
    "href, a bare api": '<a href="api">x</a>',
    "src, a bare api": '<img alt="" src="api" />',
    "a made-up aria attribute": '<div aria-zz-url="/api/me" />',
    "aria-label": '<div aria-label="/api/me" />',
    "title": '<div title="/api/me" />',
    "a data attribute holding a string expression": '<div data-zz-url={"/api/me"} />',
    "a data attribute holding a template": '<div data-zz-url={`/api/me`} />',
    "the content of a refresh meta": '<meta httpEquiv="refresh" content="0;url=/api/me" />',
    "any content of a refresh meta": '<meta httpEquiv="refresh" content="0" />',
    "srcDoc": '<iframe srcDoc="<p>hello</p>" />',
    "srcDoc with no URL in it": '<iframe srcDoc="" />',
    "dangerouslySetInnerHTML": '<div dangerouslySetInnerHTML={{ __html: "<p>hello</p>" }} />',
}


def _any_attribute_corpus() -> dict[str, str]:
    return {f"{why} (any attribute)": f"export const zzForm = {form};" for why, form in ANY_ATTRIBUTE_FORMS.items()}


#: Paths that are not under `/api` however they are spelled, which stay allowed (the twin of API_SPELLINGS).
NOT_API_SPELLINGS: dict[str, str] = {
    "a longer first segment": "/apix",
    "a longer first segment with a dot segment": "/./apix",
    "a longer first segment, percent-encoded": "/%61pix",
    "a hyphenated first segment": "/api-docs",
    "an api path in a query": "/home?next=/api/me",
    "an api path in a fragment": "/home#/api/me",
    "a dot segment that stays in the app": "/./home",
    "a parent that leaves the api": "/api/../home",
    "an investigation address": "/t/0b1f2a3c-0000-4000-8000-000000000001/investigations/0b1f2a3c-0000-4000-8000-000000000002",
    "an alerts address": "/t/0b1f2a3c-0000-4000-8000-000000000001/alerts",
    "an alerts address with a query naming the api": "/t/0b1f2a3c-0000-4000-8000-000000000001/alerts?q=/api",
    "an api segment deeper in the path": "/t/0b1f2a3c-0000-4000-8000-000000000001/api",
}


#: Locals, parameters and properties merely named like the refused globals, and `/api/auth/` outside a string (F8: by
#: resolved symbol and by string value, never by name).
ALLOWED_CORPUS: dict[str, str] = {
    "a local array named history": "export const zzForm = () => { const history: number[] = []; history.push(1); return history; };",
    "a parameter named location": "export const zzForm = (location: string) => location;",
    "a local function named fetch": 'export const zzForm = () => { const fetch = (u: string) => u; return fetch("/x"); };',
    "a parameter named localStorage": 'export const zzForm = (localStorage: Map<string, string>) => localStorage.get("k");',
    "properties named like globals": ("export const zzForm = () => { const r = { location: \"x\", fetch: 1, cookie: \"c\" };"
                                      " return [r.location, r.fetch, r.cookie]; };"),
    "a destructure of a local object": ('export const zzForm = () => { const { location, open } = { location: "x", open: true };'
                                        " return [location, open]; };"),
    "a class with members named like globals": ("export class ZzForm { open = false; location = \"x\";"
                                                " toggle() { this.open = !this.open; return this.location; } }"),
    "an interface with members named like globals": "export interface ZzForm { fetch(): void; caches: string[]; history: number[] }",
    "a type field named location": "export type ZzForm = { location: string; sessionStorage: boolean };",
    "an api field read through a typed value": ("export const zzForm = (zzValue: { location: string; cookie: string })"
                                                " => zzValue.location + zzValue.cookie;"),
    "a DOM member named like a global": ("export const zzForm = (zzEvent: { currentTarget: HTMLElement }) =>"
                                         " zzEvent.currentTarget.focus();"),
    "a timer and the console": "export const zzForm = () => setTimeout(() => console.log(\"zz\"), 5);",
    "a const assertion": 'export const zzForm = ["a", "b"] as const;',
    "the provider's hooks": 'import { useMe } from "../../shell/provider";\nexport const zzForm = useMe;',
    "a type from another shell module": 'import type { ReadKey } from "../../shell/types";\nexport type ZzForm = ReadKey;',
    # Rule 5's three honest addresses, and names merely like the refused ones.
    "a link to an app path written out": 'export const zzForm = <a href="/home">home</a>;',
    "a link to a fragment": 'export const zzForm = <a href="#main">skip</a>;',
    "an imported image": ('import zzArt from "../../../keycloak-theme/login/resources/img/illustration.svg";\n'
                          'export const zzForm = <img src={zzArt} alt="" />;'),
    "a link made by the addresses module": ('import { literalAddress } from "../../addresses";\n'
                                            'export const zzForm = <a href={literalAddress("home")}>home</a>;'),
    "a spread onto a component": ("const ZzBox = (zzProps: { title: string }) => <p>{zzProps.title}</p>;\n"
                                  'export const zzForm = (zzProps: { title: string }) => <ZzBox {...zzProps} />;'),
    "a local function named createElement": "export const zzForm = () => { const createElement = () => 1; return createElement(); };",
}
ALLOWED_CORPUS.update({f"{why} ({text!r}) in href": f'export const zzForm = <a href="{text}">x</a>;'
                      for why, text in NOT_API_SPELLINGS.items()})
ALLOWED_CORPUS.update({
    "an ordinary string in className": 'export const zzForm = <div className="card wide" />;',
    "a label naming the API": 'export const zzForm = <div aria-label="API docs" />;',
    "a title that is a longer first segment": 'export const zzForm = <div title="/apix" />;',
    "a made-up data attribute holding an app path": 'export const zzForm = <div data-zz-url="/home" />;',
    "a made-up aria attribute holding words": 'export const zzForm = <div aria-zz-note="see the API" />;',
    "an image set of app paths on a link": 'export const zzForm = <link rel="preload" as="image" imageSrcSet="/home 1x, /apix 2x" />;',
    "an abbreviation titled with the bare word": 'export const zzForm = <abbr title="API">application programming interface</abbr>;',
    "an option valued with the bare word": 'export const zzForm = <option value="api">api</option>;',
    "a class named with the bare word": 'export const zzForm = <div className="api" />;',
    "a label that is the bare word": 'export const zzForm = <div aria-label="API" />;',
    "a made-up data attribute holding the bare word": 'export const zzForm = <div data-zz-kind="api" />;',
    "a title with a non-breaking space entity": 'export const zzForm = <button title="Load&nbsp;more" />;',
    "a label with an ellipsis entity": 'export const zzForm = <div aria-label="Loading&hellip;" />;',
    "a title with a dash entity": 'export const zzForm = <div title="a&mdash;b" />;',
    "a meta that is not a refresh": 'export const zzForm = <meta name="description" content="an ordinary description" />;',
})
ALLOWED_CORPUS["an image candidate list of app paths"] = 'export const zzForm = <img alt="" srcSet="/home 1x, /apix 2x" />;'


#: What could claim a value is anything (an `any`, a cast, a comment switching type checking off), so would reach what
#: a compile does not have: refused everywhere, the shell included (the shell's assertions need a `// trust:` line).
HONESTY_CORPUS: dict[str, str] = {
    "an element's document through an any cast": (
        "export const zzForm = (zzEl: HTMLElement) => (zzEl as any).ownerDocument.defaultView.localStorage;"),
    "an element's document through a cast to a made-up type": (
        "export const zzForm = (zzEl: HTMLElement) =>"
        " (zzEl as unknown as { ownerDocument: { cookie: string } }).ownerDocument.cookie;"),
    "a parsed value of type any": "export const zzForm = (zzText: string) => JSON.parse(zzText).fetch;",
    "type checking switched off by a comment": "// @ts-ignore\nexport const zzForm = window;",
    "a type predicate, which the compiler never checks": 'export const zzForm = (zzValue: unknown): zzValue is string => typeof zzValue === "number";',
}
#: The shell's two honest forms: an assertion under a `// trust: <reason>` line, and `JSON.parse` given `unknown`.
SHELL_ALLOWED: dict[str, str] = {
    "a trusted assertion": "// trust: the zz value is a number\nexport const zzForm = (1 as unknown) as number;",
    "a parse given unknown": "export const zzForm = (zzText: string) => { const zzValue: unknown = JSON.parse(zzText); return zzValue; };",
}


def test_1540_f8_the_honesty_rules_refuse_every_form_in_the_shell_and_outside_it_and_allow_the_shells_honest_forms(checked):
    """Each `any`, cast and type-checking switch, one module apiece, fails one gate run naming every file, under
    `src/screens/` and under `src/shell/` alike; under `src/shell/`, an assertion under a `// trust:` line and a parse
    given `unknown` pass; without the `// trust:` line the assertion is refused. (F8, PR2)"""
    names = _corpus_files(HONESTY_CORPUS, "zz_honesty_")
    texts = {name: HONESTY_CORPUS[description] for name, description in names.items()}
    for where in ("screens/zz_corpus", "shell/zz_corpus"):
        gate = _with_sources(checked, where, texts)
        assert gate.refused, f"the gate accepted the honesty corpus under src/{where}"
        missed = [description for name, description in names.items() if name not in gate.output]
        assert missed == [], f"forms not refused under src/{where}: {missed}"
    allowed = _corpus_files(SHELL_ALLOWED, "zz_shell_ok_")
    passed = _with_sources(checked, "shell/zz_corpus", {name: SHELL_ALLOWED[d] for name, d in allowed.items()})
    assert not passed.refused, passed.output[-3000:]
    untrusted = _with_source(checked, "shell/zz_untrusted.ts", SHELL_ALLOWED["a trusted assertion"].split("\n", 1)[1])
    assert untrusted.refused, "an assertion in the shell without a `// trust:` line passed"
    assert "zz_untrusted.ts" in untrusted.output, untrusted.output[-1500:]


def _corpus_files(corpus: dict[str, str], prefix: str) -> dict[str, str]:
    """file name -> description, one module per form (`.tsx`, so the JSX form type-checks with the rest)."""
    return {f"{prefix}{index:04d}.tsx": description for index, description in enumerate(corpus)}


def _with_sources(frontend: Path, directory: str, files: dict[str, str], run: Callable[[Path], Gate] = _gate) -> Gate:
    """`run(frontend)` with `files` (name -> text) in the fresh directory `src/<directory>`, which goes again."""
    folder = frontend / "src" / directory
    folder.mkdir(parents=True)
    for name, text in files.items():
        (folder / name).write_text(text + "\n", encoding="utf-8")
    try:
        return run(frontend)
    finally:
        shutil.rmtree(folder)


def test_1540_f8_the_source_check_refuses_every_form_of_the_corpus_outside_the_shell_and_allows_every_named_alike_form(
        checked):
    """Each refused form, one module apiece, under `src/screens/` fails one gate run that names every one of those files;
    the same modules under `src/shell/` pass it (no type error refused them); locals, parameters and properties merely
    named like a refused global, each in its own module, pass it. (F8)"""
    corpus = _refused_corpus()
    names = _corpus_files(corpus, "zz_refused_")
    texts = {name: corpus[description] for name, description in names.items()}
    inside = _with_sources(checked, "shell/zz_corpus", texts)
    assert not inside.refused, f"control: the corpus type-checks and the shell may hold it:\n{inside.output[-3000:]}"
    outside = _with_sources(checked, "screens/zz_corpus", texts)
    assert outside.refused, "the gate accepted the refused corpus"
    missed = [description for name, description in names.items() if name not in outside.output]
    assert missed == [], f"forms the source check did not refuse: {missed}"
    allowed = _corpus_files(ALLOWED_CORPUS, "zz_allowed_")
    passed = _with_sources(checked, "screens/zz_corpus", {name: ALLOWED_CORPUS[d] for name, d in allowed.items()})
    named = [description for name, description in allowed.items() if name in passed.output]
    assert not passed.refused, f"the gate refused forms only named like a refused global: {named}\n{passed.output[-3000:]}"


# --- F8: the source check names the file that holds the form, wherever it sits outside the shell -------------------------

#: Every existing source file outside `src/shell/` and `src/generated/` (declaration files aside: they hold no code).
PLACES = sorted(p.relative_to(FRONTEND / "src").as_posix() for pattern in ("*.ts", "*.tsx")
                for p in (FRONTEND / "src").rglob(pattern)
                if not {"shell", "generated"} & set(p.relative_to(FRONTEND / "src").parts) and not p.name.endswith(".d.ts"))


@pytest.mark.parametrize("place", PLACES)
def test_1540_f8_a_refused_form_appended_to_an_existing_source_file_fails_the_gate_naming_that_file_alone(checked, place):
    """A never-called `fetch` appended to this existing file fails the gate; the output names it and no other file of
    the tree it left untouched. (F8: every source outside the shell and the generated types)"""
    assert len({Path(p).name for p in PLACES}) == len(PLACES), f"file names repeat, so naming is ambiguous: {PLACES}"
    path = checked / "src" / place
    original = path.read_text(encoding="utf-8")
    path.write_text(f"{original}\n{NEVER_CALLED}\n", encoding="utf-8")
    try:
        gate = _gate(checked)
    finally:
        path.write_text(original, encoding="utf-8")
    assert gate.refused, f"the gate accepted a refused form in src/{place}"
    assert Path(place).name in gate.output, gate.output[-1500:]
    others = [p for p in PLACES if p != place and Path(p).name in gate.output]
    assert others == [], f"untouched files named as holding the form: {others}\n{gate.output[-1500:]}"


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

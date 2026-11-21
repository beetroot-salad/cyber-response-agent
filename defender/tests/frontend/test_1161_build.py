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
import shutil
import subprocess
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


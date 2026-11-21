"""Shared by `test_1161_build_gate.py` and `test_1161_build_corpus.py` (split from `test_1161_build.py`, whose gate
cases were ~750s on one worker): the gate's constants, its runner and the copy helpers."""
import dataclasses
import re
import subprocess
from collections.abc import Callable
from pathlib import Path


from defender.tests.support.frontend._ingress1161 import FRONTEND, copy_frontend, node_modules_of, run_bun

LIST = FRONTEND.parent / "api" / "addresses.json"
ADDRESSES, OPENAPI = "../api/addresses.json", "../api/openapi.json"  # PR6's two inputs, as `package.json` writes them


def _copy(tmp_path: Path, built: Path, **override: bytes | None) -> Path:
    """A `copy_frontend` copy sharing the built `node_modules`; `override` maps a declared input to bytes (or None)."""
    names = {"addresses": ADDRESSES, "openapi": OPENAPI}
    inputs = {names[k]: v for k, v in override.items()}
    return copy_frontend(tmp_path / "copy", inputs_override=inputs, node_modules_from=node_modules_of(built))



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


#: A passing test file the copy already holds, and the import it makes of its neighbour in `src/shell/`.
CONTROL_TEST_SOURCE = "shell/decision.test.ts"
SHELL_IMPORT, SCREEN_IMPORT = 'from "./decision"', 'from "../shell/decision"'
#: A refused form that is never called, so the gate refuses the file by its source and not by what the runner does.
NEVER_CALLED = 'export function zzNeverCalled(): Promise<Response> { return fetch("/x"); }'


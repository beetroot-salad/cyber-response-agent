"""#1540 F8: the corpus of refused and allowed forms, one gate run per corpus (split from `test_1161_build.py`)."""
import dataclasses
import shutil
from collections.abc import Callable
from pathlib import Path

import pytest

from defender.tests.support.frontend._ingress1161 import FRONTEND

from defender.tests.frontend._gate_support import (  # noqa: F401
    ALLOWED_FORMS, CONTROL, NEVER_CALLED, REFUSED_FORMS, Gate, _gate, _with_source)


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
    return corpus


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


# ruff: noqa: PT018 — each compound assert states one fact about one value
"""#1161 B3: the generated set decides membership for both readers (Node), and the pinned Chromium's treatment of a
seeded sample of it through the repo's ingress (the four outcomes, stated on the pathname the browser produced)."""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any

import pytest

from defender.tests.frontend._flow1161 import logins, screen, settle, shown, sign_in
from defender.tests.support.frontend import _shapes1161 as S

CASES = [c for c in S.generated_set() if c.value.startswith("/")]  # a path begins with `/`; the origin is prepended
NODE = ("import {pathToFileURL} from 'node:url'; const m = await import(pathToFileURL(process.argv[1]).href);"
        " const values = JSON.parse(await new Response(process.stdin).text());"
        " process.stdout.write(JSON.stringify(values.map((v) => m.match(v))));")


def _sample() -> list[S.GeneratedCase]:
    picked = S.sample(CASES, 1161, 30)
    return picked + S.special_picks(CASES, 1161, picked)


@pytest.fixture(scope="module")
def node_names(built_frontend: Path) -> dict[str, str | None]:
    """The built matcher's answer for every generated value (one Node process)."""
    values = [c.value for c in S.generated_set()]
    done = subprocess.run(["node", "--input-type=module", "-e", NODE, str(built_frontend / "addresses.mjs")],
                          input=json.dumps(values), capture_output=True, text=True, check=False, timeout=300)
    assert done.returncode == 0, done.stderr[-2000:]
    return dict(zip(values, json.loads(done.stdout), strict=True))


def test_1161_b3_the_built_matcher_names_the_same_shape_as_the_apis_reader_for_every_generated_value(node_names):
    """Node's `match` against `defender.api.addresses.match`, whole generated set. (B3, S2)"""
    from defender.api import addresses

    wrong = [(v, n, addresses.match(v)) for v, n in node_names.items() if n != addresses.match(v)]
    assert not wrong, f"{len(wrong)} of {len(node_names)} differ, e.g. {wrong[:3]}"


def test_1161_b3_the_built_matcher_agrees_with_the_shape_text_for_every_generated_value(node_names):
    """Node's `match` against the classifier written from S2's shape text. (B3, S2)"""
    wrong = [(v, n, S.classify(v)) for v, n in node_names.items() if n != S.classify(v)]
    assert not wrong, f"{len(wrong)} of {len(node_names)} differ, e.g. {wrong[:3]}"


def _produce(world: Any, browser: Any, value: str, *, cookies: Any = None) -> tuple[Any, Any, list[Any], str | None]:
    """Open `value` in a fresh tab of a new context; the first document request's path is the pathname the browser
    produced (the URL parser has stripped, resolved or converted what it does). Returns (context, page, requests, path)."""
    context = browser.new_context()
    context.set_default_timeout(30_000)
    if cookies:
        context.add_cookies(cookies)
    seen: list[Any] = []
    context.on("request", lambda r: seen.append(r))
    page = context.new_page()
    try:
        page.goto(f"{world.origin}{value}")
    except Exception as error:  # noqa: BLE001
        if "invalid url" not in str(error).lower():
            raise
        return context, page, seen, None
    first = next((r for r in seen if r.is_navigation_request()), None)
    produced = None if first is None else first.url.removeprefix(world.origin).split("?")[0].split("#")[0]
    return context, page, seen, produced


def _not_app(page: Any, seen: list[Any], produced: str | None) -> bool:
    """The ingress did not serve the app: a 400, or a path it routes to the API (outside S1 and the router)."""
    if produced is None or produced.lower() == "/api" or produced.lower().startswith("/api/"):
        return True
    first = next(r for r in seen if r.is_navigation_request())
    response = first.response()
    return response is not None and response.status == 400


@pytest.mark.parametrize("phase", ["signed-out", "signed-in"])
def test_1161_b3_a_seeded_sample_of_the_generated_set_in_the_pinned_chromium(world, context, browser, phase):
    """Each value's outcome by the pathname the browser produced: returnable member, the failed screen's, no member,
    or never served by the ingress (only: no sign-in starts). A shell-started sign-in never yields `bad-request`. (B3)"""
    problems = _outcomes(world, context, browser, phase, [case.value for case in _sample()])
    assert not problems, "\n".join(problems)


def _outcomes(world: Any, context: Any, browser: Any, phase: str, values: list[str]) -> list[str]:  # noqa: C901 — one table of the four outcomes
    """What each of `values` did that the design does not allow, in the pinned Chromium (`phase`: signed out or in)."""
    if phase == "signed-in":
        sign_in(world, context)
    problems: list[str] = []
    for value in values:
        cookies = context.cookies() if phase == "signed-in" else None
        ctx, page, seen, produced = _produce(world, browser, value, cookies=cookies)
        try:
            starts = logins(seen, world.origin)
            if _not_app(page, seen, produced):
                if starts:
                    problems.append(f"{value!r}: not served as the app, but sign-in started {starts}")
                continue
            assert produced is not None
            shape = S.classify(produced)
            if phase == "signed-in":
                want = "not-found" if shape is None else shape
                screen(page, want)
                settle(page, 300)
                starts = logins(seen, world.origin)  # after the shell's fetch and any redirect, not at the load event
                got = page.evaluate("location.pathname")
                if got != produced or starts:
                    problems.append(f"{value!r}: pathname {got!r} (browser produced {produced!r}), logins {starts}")
            elif shape == "sign-in-failed":
                screen(page, "sign-in-failed")
                settle(page, 300)
                starts = logins(seen, world.origin)
                if starts:
                    problems.append(f"{value!r}: the failed screen started a sign-in {starts}")
            else:
                landing = shape if shape in S.RETURNABLE else "root"
                screen(page, landing)
                settle(page, 300)
                starts = logins(seen, world.origin)  # read after the landing wait: the redirect happens after the load event
                want_login = produced if shape in S.RETURNABLE else None
                got = page.evaluate("location.pathname")
                if starts != [want_login] or got != (produced if shape in S.RETURNABLE else "/"):
                    problems.append(f"{value!r}: produced {produced!r}: logins {starts}, landed {got!r}")
                if shown(page) == "sign-in-failed":
                    problems.append(f"{value!r}: sign-in-failed shown")
        finally:
            ctx.close()
    return problems


def _respellings(member: str) -> list[str]:
    """Deterministic spellings of one member that are not members (S2: whole string, case-sensitive, no decoding, no
    trailing `/`): a trailing slash, letter case flipped (all of it, its words only, its uuids only) and each kind of
    character written as an escape (a letter, a digit, a hex digit inside a uuid, a hyphen, a slash)."""
    uuids = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
    words = member.replace("/t/", "/T/").replace("investigations", "Investigations").replace("sign-in-failed", "Sign-in-failed")
    out = [member + "/", member.upper(), words, uuids.sub(lambda m: m.group(0).upper(), member)]
    for pattern in (r"[a-z]", r"[0-9]"):
        found = re.search(pattern, member)
        if found:
            out.append(member[:found.start()] + f"%{ord(found.group(0)):02X}" + member[found.end():])
    inside = uuids.search(member)
    if inside:
        out.append(member[:inside.start() + 3] + f"%{ord(member[inside.start() + 3]):02X}" + member[inside.start() + 4:])
    if "-" in member:
        out.append(member.replace("-", "%2D", 1))
    if "/investigations/" in member:
        out += [member.replace("investigations", "%69nvestigations"), member.replace("/investigations/", "%2Finvestigations/")]
    return [v for v in dict.fromkeys(out) if v != member]


@pytest.mark.parametrize("phase", ["signed-out", "signed-in"])
def test_1161_s2_a_member_respelled_by_slash_case_or_escape_is_no_member_in_the_pinned_chromium(
        world, context, browser, phase):
    """Each shape's member, plus its trailing-slash, case-flipped and escaped spellings: the member (control) is a member,
    every respelling gets the not-found screen when signed in and a sign-in with no `return` when signed out. The router
    reads the raw pathname. (S2, B3)"""
    members = [m for shape in S.SHAPES for m in S.members(shape, 1161, 1)]
    values = [v for m in members for v in [m, *_respellings(m)]]
    assert len(values) > 15 and not [v for v in values if v not in members and S.classify(v) is not None], values
    problems = _outcomes(world, context, browser, phase, values)
    assert not problems, "\n".join(problems)

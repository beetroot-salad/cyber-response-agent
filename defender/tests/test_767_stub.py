"""#767 — D6's operator endpoint on the playground ticket stub.

One demand of `spec-flow/specs/spec_graph_767-ticket-store-approval.yaml`, named by its
`discharged_by`. `POST /tickets/{key}/labels` is genuinely new: g1 read `app.py` in full and
found exactly seven routes, none of them a label edit, and c8 drove the real server and
observed PATCH and PUT answering 405 by absence.

A KNOWN LIMIT OF THIS SUITE, stated here because the digest records it and an implementer
will meet it: `fastapi` is not in defender's `dev` extra, so the stub cannot be imported in
this test environment. The route's BEHAVIOUR (404 on an unknown key, idempotent accept on a
duplicate) is therefore driven only where `fastapi` is importable, and its DECLARATION —
path plus method, read off the module's own decorators — is asserted unconditionally. Adding
`fastapi` + `httpx` to the dev extra would let the behavioural half run everywhere; that is a
dependency decision, not a test decision, and it is left to the implementer.
"""
from __future__ import annotations

import ast

import pytest

from defender._paths import PATHS
from defender.tests._spec767 import APPROVED_LABEL

APP = PATHS.repo_root / "playground-v2" / "ticket-server" / "app.py"
LABELS_ROUTE = "/tickets/{key}/labels"


def _declared_routes() -> set[tuple[str, str]]:
    """Every `(METHOD, path)` the stub declares, read off its own route decorators."""
    tree = ast.parse(APP.read_text(encoding="utf-8"), filename=str(APP))
    out: set[tuple[str, str]] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            call = dec if isinstance(dec, ast.Call) else None
            func = call.func if call is not None else dec
            if not isinstance(func, ast.Attribute) or not isinstance(func.value, ast.Name):
                continue
            if func.value.id != "app" or not call or not call.args:
                continue
            path = call.args[0]
            if isinstance(path, ast.Constant) and isinstance(path.value, str):
                out.add((func.attr.upper(), path.value))
    return out


def test_767_stub_label_route_adds_one_label(tmp_path):
    """d6_stub_label_route — the playground stub gains `POST /tickets/{key}/labels`: it adds
    ONE label to an EXISTING ticket, it 404s on a key the store does not hold with no side
    effect and no ticket creation, and adding a label the ticket already carries is an
    idempotent accept.

    §7 FK38 settled the unknown key on the stub's own conventions (c8: `GET /tickets/{key}` is
    404 on an unknown key, and `POST /tickets` is the only creator, 409ing on a duplicate) and
    on O1: approval is an act on an EXISTING case, so a route that could conjure a ticket
    would let the approve action create the thing it approves.

    §7 FK39 settled the duplicate as SET semantics — a no-op accept. `is_approved` is a
    membership test, so a duplicate entry changes nothing about approval, but it does change
    the `labels` list a model reads back (settled premise 70) and the listing's byte size; and
    idempotency is what a person clicking "approve" twice expects, which matters because this
    is the one step with no automation behind it.

    The route is NOT on the adapter's confinement allowlist, which stays GET-only — that half
    is `d6_labels_route_not_confined`'s. On the playground nothing authenticates this route at
    all, which the clause `n6_approve_action_is_unattributable_on_the_playground` records."""
    routes = _declared_routes()
    assert routes, "no routes were read off the stub — re-site this demand"
    assert ("POST", LABELS_ROUTE) in routes, (
        f"the stub declares no `POST {LABELS_ROUTE}`: D6's operator endpoint is how a person "
        f"approves a case on the playground, and g1 confirmed it does not exist at HEAD "
        f"(declared: {sorted(routes)})"
    )
    assert ("POST", "/tickets") in routes, "the create route vanished — the reading is broken"

    pytest.importorskip(
        "fastapi",
        reason="fastapi is not in defender's dev extra, so the stub cannot be imported here; "
               "the route's declaration is asserted above and its behaviour below runs "
               "wherever fastapi is available",
    )
    import importlib.util

    spec = importlib.util.spec_from_file_location("spec767_ticket_stub", APP)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)

    from fastapi.testclient import TestClient

    client = TestClient(module.app)
    client.post("/admin/reset")
    created = client.post("/tickets", json={"key": "SOC-1", "summary": "a case"})
    assert created.status_code == 201

    added = client.post("/tickets/SOC-1/labels", json={"label": APPROVED_LABEL})
    assert added.status_code in (200, 201), added.text
    assert client.get("/tickets/SOC-1").json()["labels"] == [APPROVED_LABEL]

    again = client.post("/tickets/SOC-1/labels", json={"label": APPROVED_LABEL})
    assert again.status_code in (200, 201), "a duplicate label add was refused, not absorbed"
    assert client.get("/tickets/SOC-1").json()["labels"] == [APPROVED_LABEL], (
        "the duplicate label was appended: FK39 settled set semantics, and a duplicate "
        "changes the labels list a model reads back and the listing's byte size"
    )

    before = client.get("/tickets").json()
    missing = client.post("/tickets/SOC-NOPE/labels", json={"label": APPROVED_LABEL})
    assert missing.status_code == 404, "an unknown key was not a 404"
    assert client.get("/tickets").json() == before, (
        "the 404 had a side effect: a route that could conjure a ticket would let the approve "
        "action create the thing it approves"
    )

"""#1471 slice A, the routes as the app declares them (C8, P-H, A7) and as the checked-in OpenAPI document shows them. No
database: the app is built over a refusing port set, as `test_programs_1307_roles` reads its route table."""
from __future__ import annotations

import json
from typing import Any

import pytest

pytest.importorskip("fastapi")

from defender._git import REPO_ROOT  # noqa: E402
from defender.api.app import create_app, unauthenticated_routes, undeclared_routes  # noqa: E402
from defender.tests.support.api._routes1307a import _served, app_routes, normal, route_table_deps  # noqa: E402

API = "/api"
TENANT = f"{API}/tenants/{{}}"
ADMIN = f"{API}/admin/tenants/{{}}"
#: route -> the one permission or category it declares.
DECLARED = {
    ("POST", f"{TENANT}/readiness"): "config.write",
    ("GET", f"{TENANT}/readiness/{{}}"): "config.read",
    ("POST", f"{TENANT}/systems/{{}}/adoptions"): "config.write",
    ("GET", f"{TENANT}/adoptions/{{}}"): "config.read",
    ("POST", f"{ADMIN}/readiness"): "platform",
    ("GET", f"{ADMIN}/readiness/{{}}"): "platform",
    ("POST", f"{ADMIN}/systems/{{}}/adoptions"): "platform",
    ("GET", f"{ADMIN}/adoptions/{{}}"): "platform",
}
DOCUMENT = REPO_ROOT / "defender" / "api" / "openapi.json"


def _declarations(dependant: Any) -> set[str]:
    found = {getattr(dependant.call, "declares", None)} - {None}
    for sub in dependant.dependencies:
        found |= _declarations(sub)
    return found


def _app() -> Any:
    return create_app(route_table_deps())


def test_c8_the_four_tenant_and_four_admin_routes_are_served_with_these_methods_and_paths() -> None:
    """Every row of the table is a route of the app, by method and normalised path. (C8)"""
    served = {(m, normal(p)) for m, p in app_routes()}
    assert set(DECLARED) <= served, sorted(set(DECLARED) - served)


@pytest.mark.parametrize("route", sorted(DECLARED))
def test_c8_p_h_each_route_declares_exactly_its_permission_or_the_platform_category(route: tuple[str, str]) -> None:
    """Tenant routes declare `config.write` (starts) and `config.read` (polls); admin routes declare `platform`. (C8, P-H)"""
    # a list: an effective route context is not hashable (repair 5)
    wanted = [r for r in _served(_app().routes) if (min(r.methods - {"HEAD", "OPTIONS"}, default=""), normal(r.path)) == route]
    assert len(wanted) == 1, f"{route} is served {len(wanted)} times"
    assert _declarations(wanted[0].dependant) == {DECLARED[route]}


def test_c8_the_app_with_the_new_routes_has_none_undeclared_and_none_unauthenticated() -> None:
    """The route invariants run at app start over the new routes too: nothing undeclared, nothing outside `_router`. (C8, A7)"""
    app = _app()
    assert undeclared_routes(app) == []
    assert unauthenticated_routes(app) == []
    assert {(m, normal(p)) for m, p in app_routes()} >= set(DECLARED)  # control: the checks above ran over them


def _document() -> dict[str, Any]:
    return json.loads(DOCUMENT.read_text(encoding="utf-8"))


_PATHS = {
    ("post", "/api/tenants/{tenant_id}/readiness"): "readiness_id",
    ("get", "/api/tenants/{tenant_id}/readiness/{readiness_id}"): "readiness_id",
    ("post", "/api/tenants/{tenant_id}/systems/{system_id}/adoptions"): "adoption_id",
    ("get", "/api/tenants/{tenant_id}/adoptions/{adoption_id}"): "adoption_id",
    ("post", "/api/admin/tenants/{tenant_id}/readiness"): "readiness_id",
    ("get", "/api/admin/tenants/{tenant_id}/readiness/{readiness_id}"): "readiness_id",
    ("post", "/api/admin/tenants/{tenant_id}/systems/{system_id}/adoptions"): "adoption_id",
    ("get", "/api/admin/tenants/{tenant_id}/adoptions/{adoption_id}"): "adoption_id",
}


@pytest.mark.parametrize(("method", "path"), sorted(_PATHS), ids=[f"{m} {p}" for m, p in sorted(_PATHS)])
def test_c8_the_checked_in_openapi_document_has_each_route_with_its_served_shape(method: str, path: str) -> None:
    """Each route is in `api/openapi.json`; its 200 (poll) or 201 (start) answers the request object, whose schema names its
    id field and the shared fields; a start declares 409; the 404 is the problem document. (C8)"""
    doc = _document()
    operation = doc["paths"][path][method]
    answers = operation["responses"]
    ok = answers["201" if method == "post" else "200"]["content"]["application/json"]["schema"]["$ref"]
    properties = doc["components"]["schemas"][ok.rsplit("/", 1)[1]]["properties"]
    assert {_PATHS[(method, path)], "status", "created_at", "started_at", "finished_at", "result", "failure_reason",
            "failure_message"} <= set(properties)
    assert "404" in answers
    assert "401" in answers
    if method == "post":
        assert "409" in answers


def test_c7_only_the_readiness_poll_declares_the_secret_store_answers_503_and_500() -> None:
    """The readiness poll declares 503 and 500 (a completed poll asks the store); the adoption poll declares neither. (R2, A2, C7)"""
    paths = _document()["paths"]
    for path in ("/api/tenants/{tenant_id}/readiness/{readiness_id}", "/api/admin/tenants/{tenant_id}/readiness/{readiness_id}"):
        assert {"500", "503"} <= set(paths[path]["get"]["responses"]), path
    for path in ("/api/tenants/{tenant_id}/adoptions/{adoption_id}", "/api/admin/tenants/{tenant_id}/adoptions/{adoption_id}"):
        assert not {"503"} & set(paths[path]["get"]["responses"]), path


def test_r3_the_documents_readiness_result_is_a_union_on_outcome_and_adoptions_names_its_four_outcomes() -> None:
    """`result` is `refused | ready` for readiness (the knowledge field on `refused`, none on `ready`'s `commit`) and an
    `outcome` of the four adoption words with `pr_number` and a `pr_url` on the served adoption. (R3, A3)"""
    schemas = _document()["components"]["schemas"]
    # `ReadinessReady.warnings` reaches the warning kinds by `$ref` to `ReadinessWarning` (surface §2; repair 5)
    text = json.dumps({k: v for k, v in schemas.items() if k in {"Readiness", "SavedReadiness", "ReadinessRefused",
                                                                  "ReadinessReady", "ReadinessWarning", "Adoption",
                                                                  "AdoptionResult"}})
    for name in ("Readiness", "ReadinessRefused", "ReadinessReady", "ReadinessWarning", "Adoption", "AdoptionResult"):
        assert name in schemas, name
    assert "systems_without_credentials" in schemas["Readiness"]["properties"]
    assert "pr_url" in schemas["Adoption"]["properties"]
    assert "system_id" in schemas["Adoption"]["properties"]
    assert "commit" not in schemas["ReadinessReady"]["properties"]
    assert "knowledge" in schemas["ReadinessRefused"]["properties"]
    for word in ("opened", "already_open", "rejected", "nothing_to_adopt", "refused", "ready", "case_system"):
        assert f'"{word}"' in text, word

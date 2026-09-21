"""Injectable fakes for the chaos control plane (issue #401).

The controller never shells out from a test. Every mutation it makes travels
over an *exec seam* — a duck-typed object passed in as `execer=` (this repo's
convention: fakes enter through the entry point's parameter seam, never
`monkeypatch.setattr`). The real seam shells `docker --context soc-playground
exec`; this one records what it was asked to do so tests can assert on the
captured command/payload rather than on a canned return value.

Seam contract (chaos/seam.py — what `chaos/ctl.py` may call, and all it may call):

    execer.cmdb_request(method, path, body=None)      -> payload
        one `docker exec cmdb python3 -c <urllib>` round trip to
        http://127.0.0.1:8080<path>
    execer.es_request(method, path, body=None)        -> payload
        one `docker exec elasticsearch curl https://localhost:9200<path>`
    execer.read_container_file(container, path)       -> str
        `docker exec <container> cat <path>` — how the controller reads the
        *baked* /opt/cmdb/inventory.yaml rather than the working-tree copy

Each call returns the backend's payload or raises `SeamError` (`SeamNotFound`
for a 404). There is no return code for a caller to interpret — the real seam
cannot hand back "rc 0 with an error body", so neither does this one.
"""
from __future__ import annotations

import fnmatch
from pathlib import Path
from typing import Any, Optional

import yaml

from chaos.seam import SeamError, SeamNotFound

# The real container bakes playground-v2/hosts/inventory.yaml in at build
# time; the fake serves the same file by default. A test that wants the
# image to have drifted from the working tree passes its own `files=`.
BAKED_INVENTORY_PATH = "/opt/cmdb/inventory.yaml"
_REPO_INVENTORY = Path(__file__).resolve().parents[2] / "hosts" / "inventory.yaml"

OK: tuple[int, Any] = (200, {})
NOT_FOUND: tuple[int, Any] = (404, {})


class FakeExecSeam:
    """Records every exec-seam call; answers from a registered response table.

    Responses are keyed `"<METHOD> <path>"` and valued `(status, payload)`;
    the path half may be an fnmatch glob (`"GET /_ingest/pipeline/*"`), so a
    test does not have to guess the controller's exact wildcard. A 2xx (or
    0, for brevity) status returns the payload; 404 raises SeamNotFound; any
    other status raises SeamError — the same three outcomes the real seam
    has. Unregistered calls get `default`.
    """

    def __init__(
        self,
        *,
        cmdb: Optional[dict[str, tuple[int, Any]]] = None,
        es: Optional[dict[str, tuple[int, Any]]] = None,
        files: Optional[dict[str, str]] = None,
        default: tuple[int, Any] = OK,
    ) -> None:
        self.cmdb_responses = dict(cmdb or {})
        self.es_responses = dict(es or {})
        self.files = {BAKED_INVENTORY_PATH: _REPO_INVENTORY.read_text(), **(files or {})}
        self.default = default
        self.calls: list[dict[str, Any]] = []

    # -- seam surface -----------------------------------------------------
    def cmdb_request(self, method: str, path: str, body: Any = None) -> Any:
        self.calls.append({"target": "cmdb", "method": method.upper(), "path": path, "body": body})
        return self._deliver(self._answer(self.cmdb_responses, method, path), f"cmdb {method} {path}")

    def es_request(self, method: str, path: str, body: Any = None) -> Any:
        self.calls.append({"target": "es", "method": method.upper(), "path": path, "body": body})
        return self._deliver(self._answer(self.es_responses, method, path), f"es {method} {path}")

    def read_container_file(self, container: str, path: str) -> str:
        self.calls.append({"target": "file", "method": "READ", "path": path, "container": container})
        for pattern, text in self.files.items():
            if fnmatch.fnmatch(path, pattern):
                return text
        raise SeamError(f"fake exec seam has no {container}:{path}")

    # -- internals ----------------------------------------------------------
    def _answer(self, table: dict[str, tuple[int, Any]], method: str, path: str) -> tuple[int, Any]:
        key = f"{method.upper()} {path}"
        if key in table:
            return table[key]
        for pattern, response in table.items():
            want_method, _, want_path = pattern.partition(" ")
            if want_method.upper() == method.upper() and fnmatch.fnmatch(path, want_path):
                return response
        return self.default

    @staticmethod
    def _deliver(response: tuple[int, Any], what: str) -> Any:
        status, payload = response
        if status == 0 or 200 <= status < 300:
            return payload
        if status == 404:
            raise SeamNotFound(f"{what}: 404", status=status, payload=payload)
        raise SeamError(f"{what}: HTTP {status}: {payload}", status=status, payload=payload)

    # -- assertion helpers ------------------------------------------------
    def calls_for(
        self,
        target: Optional[str] = None,
        method: Optional[str] = None,
        path_contains: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        out = self.calls
        if target is not None:
            out = [c for c in out if c["target"] == target]
        if method is not None:
            out = [c for c in out if c["method"] == method.upper()]
        if path_contains is not None:
            out = [c for c in out if path_contains in c["path"]]
        return list(out)

    def mutating_calls(self) -> list[dict[str, Any]]:
        """Everything that is not a read — what a refused activation must not
        do. An Elasticsearch `_search` is a POST by convention but reads."""
        return [
            c for c in self.calls
            if c["method"] in {"PUT", "POST", "DELETE"} and not c["path"].endswith("/_search")
        ]


class FakeChaosCtl:
    """Stands in for `chaos.ctl` when driving `attacks/runner.py::run_scenario`.

    Deliberately tolerant about how the runner passes its arguments; the
    discriminating assertion is the captured *values* — above all that the
    ledger_ref handed to revert is the one apply returned, and that plan
    ran before the CR was posted while apply ran after.
    """

    def __init__(
        self,
        ledger_ref: str = "ledger-ref-0001",
        order: Optional[list[str]] = None,
    ) -> None:
        self.ledger_ref = ledger_ref
        self.order = order if order is not None else []
        self.plan_calls: list[dict[str, Any]] = []
        self.apply_calls: list[dict[str, Any]] = []
        self.revert_calls: list[dict[str, Any]] = []

    def plan(self, profile_id: Any = None, *args: Any, **kwargs: Any) -> dict[str, Any]:
        seed = kwargs.get("seed", args[0] if args else None)
        profile_id = profile_id if profile_id is not None else kwargs.get("profile")
        self.order.append("plan")
        self.plan_calls.append({"profile_id": profile_id, "seed": seed, "kwargs": kwargs})
        return {"profile_id": profile_id, "seed": seed, "mode": "cmdb-stale", "resolved_mutations": []}

    def apply(self, planned: Any = None, *args: Any, **kwargs: Any) -> dict[str, Any]:
        planned = planned if planned is not None else kwargs.get("planned") or {}
        self.order.append("apply")
        self.apply_calls.append({"profile_id": planned.get("profile_id"), "seed": planned.get("seed"), "kwargs": kwargs})
        return {
            **planned,
            "ledger_ref": self.ledger_ref,
            "status": "active",
            "activated_at": "2026-09-20T00:00:00+00:00",
        }

    def revert(self, ledger_ref: Any = None, *args: Any, **kwargs: Any) -> dict[str, Any]:
        ref = ledger_ref if ledger_ref is not None else kwargs.get("ledger_ref")
        self.order.append("revert")
        self.revert_calls.append({"ledger_ref": ref, "kwargs": kwargs})
        return {"ledger_ref": ref, "status": "reverted", "reverted_at": "2026-09-20T00:01:00+00:00"}


def write_profile(profiles_dir, profile_id: str, mode: str, params: dict, seed: int = 42) -> str:
    """Write one `chaos/profiles/<id>.yaml` (M2's committed-YAML schema)."""
    body = {
        "id": profile_id,
        "description": f"spec fixture for {mode}",
        "mode": mode,
        "seed": seed,
        "params": params,
        "cover": "ordinary environmental decay; documentation only",
    }
    (profiles_dir / f"{profile_id}.yaml").write_text(yaml.safe_dump(body, sort_keys=False))
    return profile_id

"""Injectable fakes for the chaos control plane (issue #401).

The controller never shells out from a test. Every mutation it makes travels
over an *exec seam* — a duck-typed object passed in as `execer=` (this repo's
convention: fakes enter through the entry point's parameter seam, never
`monkeypatch.setattr`). The real seam shells `docker --context soc-playground
exec`; this one records what it was asked to do so tests can assert on the
captured command/payload rather than on a canned return value.

Seam contract (what `chaos/ctl.py` may call, and all it may call):

    execer.cmdb_request(method, path, body=None)      -> (rc, payload)
        one `docker exec cmdb python3 -c <urllib>` round trip to
        http://127.0.0.1:8080<path>
    execer.es_request(method, path, body=None)        -> (rc, payload)
        one `docker exec elasticsearch curl https://localhost:9200<path>`
    execer.read_container_file(container, path)       -> str
        `docker exec <container> cat <path>` — how M5's status reads the
        *baked* /opt/cmdb/inventory.yaml rather than the working-tree copy

`rc` is 0 on success, non-zero otherwise, mirroring runner.py's `_post_cr`.
"""
from __future__ import annotations

import fnmatch
from typing import Any, Optional

import yaml

NOT_FOUND = (1, {"error": "not found"})


class FakeExecSeam:
    """Records every exec-seam call; answers from a registered response table.

    Responses are keyed `"<METHOD> <path>"`; the path half may be an fnmatch
    glob (`"GET /_ingest/pipeline/*"`), so a test does not have to guess the
    controller's exact wildcard. Unregistered calls get `default`.
    """

    def __init__(
        self,
        *,
        cmdb: Optional[dict[str, tuple[int, Any]]] = None,
        es: Optional[dict[str, tuple[int, Any]]] = None,
        files: Optional[dict[str, str]] = None,
        default: tuple[int, Any] = (0, {}),
    ) -> None:
        self.cmdb_responses = dict(cmdb or {})
        self.es_responses = dict(es or {})
        self.files = dict(files or {})
        self.default = default
        self.calls: list[dict[str, Any]] = []

    # -- seam surface -----------------------------------------------------
    def cmdb_request(self, method: str, path: str, body: Any = None) -> tuple[int, Any]:
        self.calls.append({"target": "cmdb", "method": method.upper(), "path": path, "body": body})
        return self._answer(self.cmdb_responses, method, path)

    def es_request(self, method: str, path: str, body: Any = None) -> tuple[int, Any]:
        self.calls.append({"target": "es", "method": method.upper(), "path": path, "body": body})
        return self._answer(self.es_responses, method, path)

    def read_container_file(self, container: str, path: str) -> str:
        self.calls.append({"target": "file", "method": "READ", "path": path, "container": container})
        for pattern, text in self.files.items():
            if fnmatch.fnmatch(path, pattern):
                return text
        raise FileNotFoundError(f"fake exec seam has no {container}:{path}")

    # -- assertion helpers ------------------------------------------------
    def _answer(self, table: dict[str, tuple[int, Any]], method: str, path: str) -> tuple[int, Any]:
        key = f"{method.upper()} {path}"
        if key in table:
            return table[key]
        for pattern, response in table.items():
            want_method, _, want_path = pattern.partition(" ")
            if want_method.upper() == method.upper() and fnmatch.fnmatch(path, want_path):
                return response
        return self.default

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
        """Everything that is not a read — what a refused activation must not do."""
        return [c for c in self.calls if c["method"] in {"PUT", "POST", "DELETE"}]


class FakeChaosCtl:
    """Stands in for `chaos.ctl` when driving `attacks/runner.py::run_scenario`.

    Deliberately tolerant about how the runner passes its arguments; the
    discriminating assertion is the captured *values* — above all that the
    ledger_ref handed to revert is the one activate returned.
    """

    def __init__(
        self,
        ledger_ref: str = "ledger-ref-0001",
        order: Optional[list[str]] = None,
    ) -> None:
        self.ledger_ref = ledger_ref
        self.order = order if order is not None else []
        self.activate_calls: list[dict[str, Any]] = []
        self.revert_calls: list[dict[str, Any]] = []

    def activate(self, profile_id: Any = None, *args: Any, **kwargs: Any) -> dict[str, Any]:
        seed = kwargs.get("seed", args[0] if args else None)
        profile_id = profile_id if profile_id is not None else kwargs.get("profile")
        self.order.append("activate")
        self.activate_calls.append({"profile_id": profile_id, "seed": seed, "kwargs": kwargs})
        return {
            "profile_id": profile_id,
            "seed": seed,
            "mode": "cmdb-stale",
            "ledger_ref": self.ledger_ref,
            "activated_at": "2026-09-20T00:00:00+00:00",
        }

    def revert(self, ledger_ref: Any = None, *args: Any, **kwargs: Any) -> dict[str, Any]:
        ref = ledger_ref if ledger_ref is not None else kwargs.get("ledger_ref")
        self.order.append("revert")
        self.revert_calls.append({"ledger_ref": ref, "kwargs": kwargs})
        return {"ledger_ref": ref, "reverted_at": "2026-09-20T00:01:00+00:00"}


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

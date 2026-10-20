"""Fixtures for query-row and world-serving tests."""
from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from defender.tests.e2e._replay_harness import ReplayFn
from defender.tests.learning.oracle.live_contracts import _spec1224 as S24

ROW_COLUMNS = (
    "lead_id", "seq", "system", "verb", "query_id", "params", "raw_command", "payload_path",
    "exit_code", "error_class", "payload_status", "payload_digest", "payload_sha256",
    "system_key",
)

#: The column name the design removes from the model's table (G4/G5).
CALL_ID = "call_id"

FORK_TIME = S24.T.AS_OF


def configure_roots(tmp_path: Path, monkeypatch: Any) -> Path:
    """Isolate episode and learning roots; disable oracle throttling."""
    root = tmp_path / "episodes-root"
    root.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv(S24.T.EPISODES_BASE_ENV, str(root))
    S24.T.isolate_learning_state(tmp_path, monkeypatch)
    monkeypatch.setenv(S24.KNOB_RATE, "1e6")
    return root


class OrderedEstate(S24.Estate):
    """Preserve adapter key order so byte comparisons detect reserialization."""

    def _put(self, key: str, entry: dict) -> None:
        table = self._table()
        table[key] = entry
        (self.state / "answers.json").write_text(json.dumps(table), encoding="utf-8")


def ordered_estate(tmp_path: Path, **kw: Any) -> OrderedEstate:
    return OrderedEstate(Path(tmp_path) / "estate", **kw)


def is_key_sorted(text: str) -> bool:
    """Check whether JSON keys already have canonical order."""
    return text == json.dumps(json.loads(text), sort_keys=True)


def _part_text(part: Any) -> str:
    """Render a request part as the model sees it."""
    for name in ("model_response_str", "model_response"):
        render = getattr(part, name, None)
        if callable(render):
            try:
                return str(render())
            except Exception:  # noqa: BLE001 — a part that cannot render reads as its content
                break
    content = getattr(part, "content", "")
    return content if isinstance(content, str) else json.dumps(content, default=str)


class ReturnsSeen(ReplayFn):
    """Replay scripted turns and record inbound tool returns and retry prompts."""

    __name__ = "ReturnsSeen"

    def __init__(self, turns: list[Any]) -> None:
        super().__init__(turns)
        self.returns: list[list[str]] = []

    def __call__(self, messages: Any, info: Any) -> Any:
        last = messages[-1] if messages else None
        parts = list(getattr(last, "parts", None) or [])
        self.returns.append([_part_text(p) for p in parts
                             if getattr(p, "part_kind", "") in ("tool-return", "retry-prompt")])
        return super().__call__(messages, info)

    def handed_back(self) -> list[str]:
        """Every tool return / retry prompt the model was handed, in order."""
        return [text for request in self.returns for text in request]


_SALT = re.compile(r"run-[0-9a-f]+-untrusted")


def normalized(text: str, *run_dirs: Path) -> str:
    """Normalize frame salts and run paths, replacing longer paths first."""
    out = _SALT.sub("run-SALT-untrusted", text)
    for run_dir in sorted({str(d) for d in run_dirs}, key=len, reverse=True):
        out = out.replace(run_dir, "<RUN>")
    return out


def drive_lead(tmp_path: Path, *, verbs: Any, est: Any, turns: list[Any], system: str = "idp",
               run_id: str = "run-1255") -> tuple[Path, ReturnsSeen]:
    """Drive one lead through the real query tool and record model-visible returns."""
    H = S24.replay_harness()
    run_dir = H.materialize(Path(tmp_path) / run_id, H.GOLDEN_AB3, run_id=run_id)
    main = H.ReplayFn([
        H.Turn(tool_calls=[("gather", {
            "lead_id": S24.LEAD, "system": system, "goal": f"measure the {system} lead",
            "what_to_summarize": ["what the system says"]})]),
        H.Turn(text="Investigation complete."),
    ])
    gather = ReturnsSeen(list(turns))
    H.drive(run_dir, run_id=run_id, main=main, gather=gather, verbs=verbs, tenant=est.place())
    return run_dir, gather


def table_rows(run_dir: Path) -> list[dict]:
    """The run's model-readable query table, read raw off disk."""
    return S24.read_jsonl(Path(run_dir) / "executed_queries.jsonl")


def lead_rows(run_dir: Path, lead: str = S24.LEAD) -> list[dict]:
    return [r for r in table_rows(run_dir) if r.get("lead_id") == lead]


def sidecar_bytes(run_dir: Path, row: Mapping[str, Any]) -> bytes:
    """The payload sidecar a table row names, as bytes on disk."""
    return (Path(run_dir) / str(row["payload_path"])).read_bytes()


def row_for(rows: Iterable[Mapping[str, Any]], params: Mapping[str, Any]) -> dict:
    """The one evidence row (exit 0) of `rows` asked with `params`."""
    want = S24.canonical(params)
    hits = [dict(r) for r in rows if isinstance(r.get("params"), dict)
            and S24.canonical(r["params"]) == want and r.get("exit_code") == 0]
    assert len(hits) == 1, f"fixture: expected one answered row for {params}, got {len(hits)}"
    return hits[0]


def arm_identities(episode_dir: Path, labels: Iterable[str] = S24.WORLDS) -> list[str]:
    """Return the persisted episode and selected world identities."""
    return [Path(episode_dir).name, *(S24.T.world_id(episode_dir, label) for label in labels)]


def identities_in(text: str, identities: Iterable[str]) -> list[str]:
    return [i for i in identities if i in text]


def world_registry_with_source(ep: Path, label: str, est: Any, *, source_run: Any,
                               oracle: Any, verifier: Any, **knobs: Any) -> Any:
    """Build the fixture registry with its source-run context."""
    box, _log = S24.sandboxed_box()
    rt = est.run_tenant()
    world = S24.load_world(ep, label)
    ledger = S24.world_ledger(ep, label)
    knobs.setdefault("retry_cap", 3)
    seams = S24.registry_seams(world, ledger, oracle_dir=S24.oracle_dir(ep, label),
                               oracle=oracle.model, verifier=verifier.model, box=box, **knobs)
    return S24.sym(S24.REGISTRY, "WorldRegistry")(
        est.roster(), rt.grants.gather, world=world, ledger=ledger, as_of=S24.AS_OF_DT,
        tenant=rt, grant_home=rt.table_pointer, source_run=source_run, **seams)

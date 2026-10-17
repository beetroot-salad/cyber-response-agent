"""#1255 slice C shared machinery — query ids, served bytes and the control world's oracle.

NO test functions; underscore-prefixed so pytest never collects it. Imported as
`from defender.tests import _1255_world as W` by `test_1255_queries_*.py` and
`test_1255_world_*.py`.

Everything here is a FIXTURE or a RECORDING DOUBLE; none of it decides anything the design
assigns to production:

  * `OrderedEstate` is #1224's fixture estate (`_spec1224.Estate`) with one change: its answers
    table is written WITHOUT `sort_keys`, so a stub adapter hands back each payload in the key
    order the scenario wrote it — the order a real adapter's own output has. #1224's estate
    sorts every stored answer, which makes "served byte-for-byte as the adapter produced it"
    (G8) and "re-serialised with sorted keys" indistinguishable; every served-bytes demand here
    first asserts its payload is NOT key-sorted (the fixture's own discriminating power).
  * `ReturnsSeen` is the replay harness's `ReplayFn` that also records, per model request, the
    tool returns and retry prompts the request opens with — what the model was handed back for
    its previous calls. It records; it answers exactly as `ReplayFn` does.
  * `normalized` removes the two things two otherwise-identical runs differ by on the model's
    channel and nothing else: the per-frame untrusted salt (random by #680's design) and each
    run's own run-dir path (the two runs sit in different tmp folders; the model-view mapping
    that makes those paths equal is slice B's).
  * `world_registry_with_source` is `_spec1224.build_registry` plus the registry's existing
    `source_run=` keyword (the seam through which a sibling's registry already reads the source
    run's alert), which `_spec1224.build_registry` does not pass.

Every model double is #1224's `ScriptedModel` (`_spec1224.oracle` / `passing_verifier`) or
#1234's `Routed`; every fault is a real input. Nothing here uses `monkeypatch.setattr`.
"""
from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from defender.tests.e2e._replay_harness import ReplayFn
from defender.tests.live_oracle_1224 import _spec1224 as S24

#: The query table's columns once the call id leaves it (G4): #1017's fourteen writer columns,
#: without the fifteenth (`call_id`) #1234 A12 added — in writer order. A literal, never read off
#: the writer under test, so a column that carries the id under another name fails too.
ROW_COLUMNS = (
    "lead_id", "seq", "system", "verb", "query_id", "params", "raw_command", "payload_path",
    "exit_code", "error_class", "payload_status", "payload_digest", "payload_sha256",
    "system_key",
)

#: The column name the design removes from the model's table (G4/G5).
CALL_ID = "call_id"

#: The fork time every #1224 fixture episode records (`_triplet_947.AS_OF`) as the oracle is
#: told it: an ISO-8601 instant with a `Z`.
FORK_TIME = S24.T.AS_OF


def configure_roots(tmp_path: Path, monkeypatch: Any) -> Path:
    """The configured roots a #1224 / #1234 scenario needs, under the test's own `tmp_path`:
    the episodes root (created, as #1234's conftest does), the learning-state root, and an
    oracle rate high enough that no oracle-side query sleeps. The same three settings the two
    suites' own conftests apply; this file's tests sit at the suite root, outside them."""
    root = tmp_path / "episodes-root"
    root.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv(S24.T.EPISODES_BASE_ENV, str(root))
    S24.T.isolate_learning_state(tmp_path, monkeypatch)
    monkeypatch.setenv(S24.KNOB_RATE, "1e6")
    return root


class OrderedEstate(S24.Estate):
    """#1224's fixture estate whose stub adapters answer in the key order the scenario wrote.

    The parent writes its answers table with `sort_keys=True`, so every stub answer comes back
    key-sorted whatever the scenario wrote. This one writes it as written; `json.loads` keeps a
    file's key order, so the adapter returns the payload exactly as scripted."""

    def _put(self, key: str, entry: dict) -> None:
        table = self._table()
        table[key] = entry
        (self.state / "answers.json").write_text(json.dumps(table), encoding="utf-8")


def ordered_estate(tmp_path: Path, **kw: Any) -> OrderedEstate:
    return OrderedEstate(Path(tmp_path) / "estate", **kw)


def is_key_sorted(text: str) -> bool:
    """Whether `text` (one JSON document) already spells every object's keys sorted — the
    fixture check every served-bytes demand makes before it can mean anything."""
    return text == json.dumps(json.loads(text), sort_keys=True)


def _part_text(part: Any) -> str:
    """One request part as the model reads it: a tool return's or retry prompt's own
    model-facing rendering when the part offers one, else its content."""
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
    """`ReplayFn` that also records, for each model request, the tool returns and retry prompts
    it carries in its LAST message — what the model was handed back for its previous turn's
    calls, in call order. `returns[i]` is request i's list."""

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
    """`text` with the frame salt spelled alike and each of `run_dirs` written `<RUN>` (longest
    first, so a run dir nested in another is replaced whole)."""
    out = _SALT.sub("run-SALT-untrusted", text)
    for run_dir in sorted({str(d) for d in run_dirs}, key=len, reverse=True):
        out = out.replace(run_dir, "<RUN>")
    return out


def drive_lead(tmp_path: Path, *, verbs: Any, est: Any, turns: list[Any], system: str = "idp",
               run_id: str = "run-1255") -> tuple[Path, ReturnsSeen]:
    """One investigation through the replay harness (`_spec1224.drive_gather`'s shape) whose
    gather model is a `ReturnsSeen`: main dispatches ONE lead on `system`, the lead runs
    `turns`. Returns `(run dir, the gather double)`."""
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
    """The arm-identity strings O2 names, for a #1224 fixture episode: its id, its token and
    each world's token (`<episode token>.<label>`)."""
    token = S24.sym(S24.FAMILY, "episode_token_for")(Path(episode_dir).name)
    return [Path(episode_dir).name, token, *(f"{token}.{label}" for label in labels)]


def identities_in(text: str, identities: Iterable[str]) -> list[str]:
    return [i for i in identities if i in text]


def world_registry_with_source(ep: Path, label: str, est: Any, *, source_run: Any,
                               oracle: Any, verifier: Any, **knobs: Any) -> Any:
    """`WorldRegistry` for world `label` of episode `ep` exactly as `_spec1224.world_registry`
    builds it (the fixture estate's roster and gather grant, the doubles through the settled
    oracle side, a recording sandboxed box), plus `source_run=` — the registry's own keyword
    for the source run it serves the sibling of (today it reads that run's alert there)."""
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

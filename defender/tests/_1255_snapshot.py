"""#1255 slice A — machinery for the fork-snapshot / branch-point / no-injected-opening contract.

NO tests here (underscore-prefixed, never collected). Three things, all observing production
through its real entry points:

1. **`Recorder`** — a scripted MAIN (or gather) model that keeps every request's raw message list
   (deep copies). "The arm resumes with no user message" and "the model's next request is
   exactly the natural one" are statements about message OBJECTS — which part kinds the last
   request carries, which `tool_call_id`s it answers — so the flattened text `ReplayFn.seen`
   holds is not enough. It still fills `seen`, so the harness's text idioms work too.

2. **`drive_source`** — a REAL source run through the replay harness (`drive`): the correlation
   lead issues one real call against an injected elastic backend (so the source has a capture,
   which `validate` requires), then MAIN runs its script. The fork snapshot is whatever
   production writes while that run is driven; nothing here plants, names or reads one. A
   source built any other way (store rows written directly, as `_branch_947.legal_source`
   does) is the shape of a run recorded BEFORE #1255 — N4's refused case.

3. **`tool_calling_responses` / `spec_for` / `drive_arm`** — where a branch may be taken (D1: a
   MAIN response that called tools), the `BranchSpec` for it (no continuation prompt), and the
   arm driven through `drive(resume=spec)`, i.e. `driver.run_investigation(resume=…)`. The
   production arm (`run.main --episode … --world …`) composes exactly that call; the composed
   path is driven by `test_1255_snapshot_instrument.py` (P3: what an arm's run folder holds).

Paths in the scripts: every tool call a script makes here is PATHLESS (`append_block`,
`fix_row`, `gather`, `close_investigation`, `bash echo`). Slice B moves the model's view of
paths (`/runs/current/…`); a script that spelled host paths would break on B's change for a
reason this slice is not about. Where a test must hand a path, it derives the path from what
the model was shown.
"""
from __future__ import annotations

import copy
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai.messages import (  # noqa: E402
    ModelRequest,
    ModelResponse,
    RetryPromptPart,
    SystemPromptPart,
    TextPart,
    ToolCallPart,
    ToolReturnPart,
    UserPromptPart,
)

from defender.run_repository import RunPaths  # noqa: E402
from defender.tests._branch_947 import spec_at  # noqa: E402
from defender.tests._session_store_705 import sql, store_factory, store_mod  # noqa: E402
from defender.tests.e2e._lead_zero_808 import (  # noqa: E402
    CORRELATION_SUMMARY,
    VerbRecorder,
    alert_doc,
    answer_hits,
    elastic_backend,
    hit,
    materialize_alert,
)
from defender.tests.e2e._replay_harness import (  # noqa: E402
    GOLDEN,
    ReplayFn,
    Turn,
    _split_at_fences,
    drive,
    messages_text,
)

#: The correlation lead's reserved id: the one lead every source run dispatches before MAIN.
CORRELATION_LEAD = "l-00c"

#: `l-00c`'s script: one real call (so the source has a capture — `validate` refuses a branch
#: without one) and its summary.
CORRELATION_TURNS = (
    Turn(tool_calls=[("query", {"system": "elastic", "verb": "alerts",
                                "params": {"native_query": "user.name:dev.dana"}})]),
    Turn(text=CORRELATION_SUMMARY),
)

#: What the source's backend answers by default.
DOCS = [hit(ts="2026-05-25T15:20:00.000Z"), hit(ts="2026-05-25T15:21:00.000Z")]

#: The golden investigation every source authors, cut on fence boundaries so every running
#: concatenation is a document the gate accepts (`_replay_harness._split_at_fences`).
GOLDEN_DOCUMENT = (GOLDEN / "investigation.md").read_text(encoding="utf-8")

#: Matches the dispatch block every gather lead's first request carries (the harness's own
#: `_DISPATCHED_LEAD` shape): how a router tells which lead is asking.
_DISPATCHED_LEAD = re.compile(r"\n## Dispatch\n```yaml\n(?:.*\n)*?lead_id: (\S+)\n")

#: Every frame delimiter (`<run-<salt>-<kind>>`): `wrap_fresh` mints a fresh salt per frame, a
#: fresh random id O4 names as an allowed difference between any two runs.
_FRAME_TAG = re.compile(r"<(/?)run-[0-9a-f]+-([a-z_-]+)>")


def chunks(n: int) -> list[str]:
    """The golden document in `n` fence-boundary pieces."""
    return _split_at_fences(GOLDEN_DOCUMENT, n)


def append(text: str) -> Turn:
    return Turn(tool_calls=[("append_block", {"text": text})])


def echo(word: str) -> Turn:
    """A pathless, always-granted MAIN call (`echo` is one of the inert programs every role
    may run): a tool-calling response with a deterministic result."""
    return Turn(tool_calls=[("bash", {"command": f"echo {word}"})])


def dispatch(lead: str, *, system: str = "elastic") -> Turn:
    return Turn(tool_calls=[("gather", {
        "lead_id": lead, "system": system, "goal": f"measure what {lead} asks",
        "what_to_summarize": ["auth events for the alert's user"]})])


def close(disposition: str = "malicious") -> Turn:
    return Turn(tool_calls=[("close_investigation", {"disposition": disposition})])


def done(text: str = "Holding here; the evidence is in hand.") -> Turn:
    return Turn(text=text)


# --------------------------------------------------------------------------------------
# The recording models.
# --------------------------------------------------------------------------------------


class Recorder(ReplayFn):
    """`ReplayFn` that also keeps each request's raw messages, deep-copied at the call."""

    __name__ = "Recorder"

    def __init__(self, turns: Iterable[Turn]):
        super().__init__(list(turns))
        self.requests: list[list[Any]] = []

    def __call__(self, messages, info) -> ModelResponse:
        self.requests.append(copy.deepcopy(list(messages)))
        return super().__call__(messages, info)


class Forever(Recorder):
    """A MAIN that never stops calling tools: after its `opening` turns, every request answers
    with one `bash echo`, so the loop only ends at the request ceiling. `calls` is the number of
    model requests made. A source opens with a fence (so the frontier is open where it is
    branched); an arm needs no opening."""

    __name__ = "Forever"

    def __init__(self, opening: Iterable[Turn] = ()) -> None:
        super().__init__(list(opening))

    def __call__(self, messages, info) -> ModelResponse:
        if self.calls < len(self._turns):
            return super().__call__(messages, info)
        self.requests.append(copy.deepcopy(list(messages)))
        self.seen.append(messages_text(messages))
        self.calls += 1
        return ModelResponse(parts=[ToolCallPart(
            tool_name="bash", args={"command": f"echo turn-{self.calls}"})])


class LeadRouter:
    """The gather model for a run with several leads: routes each request to its lead's own
    scripted `Recorder` by the lead id the dispatch block names.

    `serves_correlation` tells the harness this router answers `l-00c` itself (it does — the
    correlation script is one of its leads), so the harness does not wrap it in its default."""

    __name__ = "LeadRouter"
    serves_correlation = True

    def __init__(self, scripts: dict[str, Any]):
        #: Each lead's model: its script as a `Recorder`, or a model passed as is (a callable).
        self.leads: dict[str, Any] = {
            lead: script if callable(script) else Recorder(script) for lead, script in scripts.items()}
        #: Every lead id that asked, in order of its FIRST request.
        self.asked: list[str] = []

    def __call__(self, messages, info) -> ModelResponse:
        found = _DISPATCHED_LEAD.search(messages_text(messages))
        lead = found.group(1) if found is not None else "?"
        if lead not in self.asked:
            self.asked.append(lead)
        if lead not in self.leads:
            return ModelResponse(parts=[TextPart(content=f"(no script for {lead})")])
        return self.leads[lead](messages, info)


# --------------------------------------------------------------------------------------
# A driven source and its branch points.
# --------------------------------------------------------------------------------------


@dataclass
class Driven:
    """One driven run: its folder, its models, the backend recorder, the harness's result and
    the store handle the run wrote (a source's; an arm shares its source's database)."""

    run_dir: Path
    main: Any
    gather: Any
    rec: VerbRecorder
    result: dict
    store: Any = None
    extra: dict = field(default_factory=dict)

    @property
    def summary(self) -> dict:
        return {k: v for k, v in self.result.items() if k != "run_state"}

    @property
    def state(self) -> Any:
        return self.result["run_state"]

    @property
    def paths(self) -> RunPaths:
        """The run folder's records, through the layout owner (never a spelled path)."""
        return RunPaths(self.run_dir)

    @property
    def document(self) -> str:
        """`investigation.md` as it stands ("" when absent)."""
        return read_text(self.paths.investigation)


def correlation_backend(rec: VerbRecorder, *, answer: Callable[[str, dict], Any] | None = None):
    """The elastic registry every source is driven with: the correlation lead's real call lands
    a captured row. `answer` overrides what calls 2..n return (the shell fetch is answered by
    the backend itself)."""
    return elastic_backend(rec, answer if answer is not None else answer_hits(DOCS))


def drive_source(  # noqa: PLR0913 — one keyword per seam a source scenario varies
        root: Path, main_turns: Iterable[Turn], *, leads: dict[str, Any] | None = None,
        verbs: Any = None, answer: Callable[[str, dict], Any] | None = None,
        limits: dict | None = None, bounds: Any = None, review_stages: Any = None,
        defender_dir: Path | None = None, main: Any = None, run_id: str = "src-1255",
        before: Callable[[Path], None] | None = None) -> Driven:
    """Drive a REAL source run (see the module docstring). `main` overrides the scripted
    `Recorder` built from `main_turns` (e.g. a `Forever`). `before(run_dir)` runs on the
    materialized folder just before the driver starts."""
    run_dir = materialize_alert(root / "source", alert_doc())
    rec = VerbRecorder()
    registry = verbs if verbs is not None else correlation_backend(rec, answer=answer)
    model = main if main is not None else Recorder(main_turns)
    gather = LeadRouter({CORRELATION_LEAD: CORRELATION_TURNS, **(leads or {})})
    if before is not None:
        before(run_dir)
    sink: list = []
    kw: dict[str, Any] = {"verbs": registry, "store_factory": store_factory(root, sink=sink)}
    for name, value in (("limits", limits), ("bounds", bounds),
                        ("review_stages", review_stages), ("defender_dir", defender_dir)):
        if value is not None:
            kw[name] = value
    result = drive(run_dir, run_id=run_id, main=model, gather=gather, **kw)
    assert sink, "the source run opened no store — nothing below is about branching"
    return Driven(run_dir, model, gather, rec, result, store=sink[0])


def main_rows(store: Any, session_id: str | None = None) -> list[tuple[int, Any]]:
    """`(row id, message)` for every row on a MAIN session's path, in order (the source's own
    main session when `session_id` is omitted)."""
    ss = store_mod()
    session = session_id if session_id is not None else ss.main_session_id(store)
    ids = ss.path_row_ids(store, session)
    messages = ss.hydrate(store, session, role="analysis")
    assert len(ids) == len(messages), (ids, len(messages))
    return list(zip(ids, messages, strict=True))


def calls_of(message: Any) -> list[ToolCallPart]:
    return [p for p in getattr(message, "parts", []) if isinstance(p, ToolCallPart)]


def tool_calling_responses(store: Any) -> list[int]:
    """The row ids of every MAIN response that called tools — D1's admissible branch points
    (before the retry-streak and snapshot conditions), in order. Index `k-1` is the response to
    MAIN's `k`-th model request."""
    return [rid for rid, m in main_rows(store)
            if isinstance(m, ModelResponse) and calls_of(m)]


def responses(store: Any) -> list[int]:
    """Every MAIN response row id, tool-calling or not, in order."""
    return [rid for rid, m in main_rows(store) if isinstance(m, ModelResponse)]


def message_at(store: Any, row_id: int) -> Any:
    return dict(main_rows(store))[row_id]


def spec_for(source: Driven, row_id: int) -> Any:
    """The `BranchSpec` for branching `source` at `row_id`: source, branch point and the
    derived moment (`_branch_947.spec_at`) — and no continuation prompt (D1)."""
    return spec_at(source.store, source.run_dir, row_id)


def drive_arm(  # noqa: PLR0913 — one keyword per seam an arm scenario varies
        root: Path, spec: Any, main: Any, *, leads: dict[str, Iterable[Turn]] | None = None,
        verbs: Any = None, limits: dict | None = None, bounds: Any = None,
        review_stages: Any = None, defender_dir: Path | None = None,
        name: str = "arm", run_id: str = "arm-1255",
        before: Callable[[Path], None] | None = None) -> Driven:
    """Drive an arm of `spec` through `run_investigation(resume=spec)`.

    No `store_factory=`: a resume derives its store from the spec (the harness refuses the two
    together). Escapes are NOT turned into failures here — a refusal at launch is something
    several tests assert — so a caller that expects the arm to run checks `summary` itself.
    `before(run_dir)` runs on the arm's materialized folder just before the driver starts."""
    run_dir = materialize_alert(root / name, alert_doc())
    if before is not None:
        before(run_dir)
    rec = VerbRecorder()
    gather = LeadRouter(dict(leads or {}))
    kw: dict[str, Any] = {}
    for key, value in (("verbs", verbs), ("limits", limits), ("bounds", bounds),
                       ("review_stages", review_stages), ("defender_dir", defender_dir)):
        if value is not None:
            kw[key] = value
    result = drive(run_dir, run_id=run_id, main=main, gather=gather, resume=spec, **kw)
    return Driven(run_dir, main, gather, rec, result)


def child_sessions(store: Any) -> list[str]:
    """The sessions forked off the source's main session (one per arm driven from it)."""
    ss = store_mod()
    source_session = sql(
        store, "SELECT session_id FROM session WHERE agent_id = 'main' "
               "AND parent_session_id IS NULL ORDER BY rowid")[0][0]
    del ss
    return [row[0] for row in sql(
        store, "SELECT session_id FROM session WHERE parent_session_id = ? ORDER BY rowid",
        (source_session,))]


def launched(arm: Driven) -> bool:
    """Did the arm get past launch — reach its model at all?"""
    return bool(getattr(arm.main, "calls", 0))


def refused_at_launch(arm: Driven) -> str | None:
    """`None` when the arm launched; otherwise a description of how it was stopped, for a
    failure message. A refusal at launch is: the model never asked for a turn, and the run's
    summary names the branch refusal as its exit (`BranchError`, the class every branch
    refusal is raised as)."""
    if launched(arm):
        return None
    return f"exit_reason={arm.summary.get('exit_reason')!r} truncated_by={arm.summary.get('truncated_by')!r}"


# --------------------------------------------------------------------------------------
# Comparing requests: the projection that drops only what is never sent or always differs.
# --------------------------------------------------------------------------------------


def _norm(text: str, replace: dict[str, str]) -> str:
    out = _FRAME_TAG.sub(r"<\1run-<SALT>-\2>", text)
    for old, new in sorted(replace.items(), key=lambda kv: -len(kv[0])):
        if old:
            out = out.replace(old, new)
    return out


def _content(part: Any) -> str:
    content = getattr(part, "content", None)
    if content is None:
        return ""
    return content if isinstance(content, str) else repr(content)


def project(messages: list[Any], *, replace: dict[str, str] | None = None) -> list[tuple]:
    """A request as the provider receives it, minus what is never sent (part timestamps,
    response metadata) and with O4's fresh frame salts normalised. `replace` maps host
    spellings to a placeholder (each test says which and why)."""
    rep = replace or {}
    out: list[tuple] = []
    for m in messages:
        parts: list[tuple] = []
        for p in m.parts:
            if isinstance(p, ToolCallPart):
                parts.append(("call", p.tool_name, p.tool_call_id,
                              _norm(repr(p.args_as_dict()), rep)))
            elif isinstance(p, ToolReturnPart):
                parts.append(("return", p.tool_name, p.tool_call_id, _norm(_content(p), rep)))
            elif isinstance(p, RetryPromptPart):
                parts.append(("retry", p.tool_name, p.tool_call_id, _norm(_content(p), rep)))
            elif isinstance(p, UserPromptPart):
                parts.append(("user", _norm(_content(p), rep)))
            elif isinstance(p, SystemPromptPart):
                parts.append(("system", _norm(_content(p), rep)))
            elif isinstance(p, TextPart):
                parts.append(("text", _norm(p.content, rep)))
            else:
                parts.append((type(p).__name__, _norm(_content(p), rep)))
        if isinstance(m, ModelRequest):
            out.append(("request", _norm(m.instructions or "", rep), tuple(parts)))
        else:
            out.append(("response", tuple(parts)))
    return out


def user_prompts(messages: list[Any]) -> list[str]:
    """Every `UserPromptPart`'s text in a request, in order."""
    return [_content(p) for m in messages if isinstance(m, ModelRequest)
            for p in m.parts if isinstance(p, UserPromptPart)]


def read_text(path: Path) -> str:
    """A record's text, or "" when it is absent (a fixture reader, not production's)."""
    return path.read_text(encoding="utf-8") if path.is_file() else ""


def read_bytes(path: Path) -> bytes:
    return path.read_bytes() if path.is_file() else b""


__all__ = [
    "CORRELATION_LEAD", "CORRELATION_TURNS", "DOCS", "GOLDEN_DOCUMENT",
    "Driven", "Forever", "LeadRouter", "Recorder",
    "append", "calls_of", "child_sessions", "chunks", "close", "correlation_backend",
    "dispatch", "done", "drive_arm", "drive_source", "echo", "launched", "main_rows",
    "message_at", "project", "read_bytes", "read_text", "refused_at_launch", "responses",
    "spec_for", "tool_calling_responses", "user_prompts",
]

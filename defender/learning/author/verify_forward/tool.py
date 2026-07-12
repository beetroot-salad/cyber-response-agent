"""The curators' ``forward_check`` tool: a batch-shaped in-process check (#558).

The four lesson curators used to type a ``python3 verify_forward/batch.py …`` bash command.
That lane could not be made safe: the bash allowlist pins the *program* token and admits
arbitrary trailing arguments, so ``batch.py``'s first positional — a script path it then
executed — turned the curator's ``.md``-only write grant into arbitrary code execution
(#565 pinned it as an interim guard). Here the check is bound onto the deps at spawn, so the
operand simply does not exist, and the two operands that remain are gated:

* ``lesson_path`` takes WRITE-TOOL PARITY — resolve before containment, the secret /
  ground-truth denylist, the corpus confine, the ``.md`` suffix. It must name a file this
  curator could itself have authored. An escape is a policy DENY (``ModelRetry``), matching
  every other tool in ``runtime/tools.py``; the whole call retries.
* ``source_id`` is confined to the batch's own queued rows. An unqueued id is that pair's
  ERROR line, NOT a deny — one bad id must not abort a batch of good ones. Either way the
  unrelated case's bundle is never read.

Fan-out is one bounded gather. Each check is a *sync* callable (the verify transport bridges
to the model with its own ``asyncio.run``), so it runs on a worker thread: awaiting it on the
curator's own running loop would raise the nested-``asyncio.run`` ``RuntimeError``. A raising
check must not take the batch down with it, so per-pair faults are caught inside the worker
and rendered as that pair's ERROR line, while a systemic ``StageAbort`` / ``FatalConfigError``
propagates — the systemic-versus-per-run split every other in-process stage makes.

The return value is the text protocol ``batch.py`` printed, byte for byte: one
``GOOD``/``BAD``/``ERROR`` line per input pair in input order, then a ``BATCH:`` summary. All
three curator prompts already parse exactly that, so nothing downstream moves.
"""
from __future__ import annotations

import asyncio
import itertools
import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal, cast

from pydantic.dataclasses import dataclass as pydantic_dataclass
from pydantic_ai import RunContext
from pydantic_ai.exceptions import ModelRetry

from defender.learning.author.verify_forward.checks import CheckContext
from defender.learning.core import config
from defender.learning.core.config import FatalConfigError, StageAbort
from defender.runtime import permission
from defender.runtime.tools import AgentDeps, _resolve_operand

if TYPE_CHECKING:  # importing the curator deps eagerly would close a module cycle
    from defender.learning.author.curator_engine import CuratorDeps

# A process-wide counter, not a per-batch index: two batches against one source bundle would
# otherwise re-issue index 0 and clobber the first batch's trace (RequestLogger truncates).
_CHECK_SEQ = itertools.count()

_DETAIL_MAX = 200

# Any whitespace run in a model-supplied operand. `lesson_path` and `source_id` are echoed back
# into a whitespace-delimited, newline-separated protocol, so an operand carrying a space or a
# newline would forge extra result lines (`_field`).
_WHITESPACE = re.compile(r"\s+")

# The verdict tokens that lead every result line. Also the render-time `counts` keys.
_VERDICTS = ("GOOD", "BAD", "ERROR")


class _ProtocolError(RuntimeError):
    """The rendered batch broke its own one-line-per-pair grammar — a BUILD bug (a result field
    rendered without `_field`/`_one_line`), never a bad input. Raised so a forged verdict can
    never reach the curator: the run quarantines rather than acting on a batch the tool cannot
    vouch for."""


# One lesson to check against one source row. Deliberately UNDOCUMENTED as far as the JSON
# schema goes: a class docstring becomes the schema's `description`, and everything the model
# needs to know about a pair is already in the tool's own description — where it costs one copy
# per tool rather than one per operand type. Note there is no script, program or interpreter
# field here and cannot be one: which check runs is bound onto the deps at spawn (#558).
@pydantic_dataclass(frozen=True)
class Pair:
    lesson_path: str
    source_id: str
    direction: Literal["adversarial", "benign"] = "adversarial"


@dataclass(frozen=True)
class _Prepared:
    """A gated pair: either ready to run, or already resolved to an ERROR detail."""

    pair: Pair
    lesson_path: Path | None = None
    lesson_text: str = ""
    check_index: int = -1
    detail: str | None = None


@dataclass(frozen=True)
class _Result:
    pair: Pair
    verdict: str
    detail: str


def _one_line(text: str) -> str:
    """One line, bounded — an ERROR detail is the result line's trailing free-text field, so a
    newline in it would forge a result line and an unbounded one would flood the model's
    context. Interior spaces are fine: nothing is parsed past this field."""
    return " ".join(text.split())[:_DETAIL_MAX]


def _detail(exc: BaseException) -> str:
    """This exception as one bounded ERROR detail."""
    return _one_line(str(exc)) or _one_line(repr(exc))


def _field(value: str) -> str:
    """One model-supplied operand, rendered as exactly ONE field of the result protocol.

    ``lesson_path`` and ``source_id`` are echoed back verbatim into ``<verdict> <path> <id>``
    lines that the three curator prompts read positionally, whitespace-separated. Both operands
    are model-controlled, and neither the corpus ``write_allow`` (``<corpus>/[^\\x00]*\\.md`` —
    ``[^\\x00]`` matches a newline) nor the ``queued_ids`` membership test constrains whitespace,
    so a raw echo lets the curator forge its own ``GOOD`` verdicts and ``BATCH:`` summary. A real
    lesson path or queue id carries no whitespace, so any is escaped rather than emitted."""
    return _WHITESPACE.sub(r"\\s", value)[:_DETAIL_MAX] or "<empty>"


def _gate_lesson_path(deps: CuratorDeps, operand: str) -> Path:
    """Resolve the lesson operand against the agent's own tree and refuse anything the
    curator could not have written there.

    ``decide_write`` is the exact predicate: this lesson is a file the curator authored into
    its own corpus, so the write gate's constraint set — resolve-before-containment (a
    symlink or ``..`` cannot escape a textual prefix), the secret / ground-truth denylist,
    the corpus confine, the ``.md`` suffix — is what confinement means for reading it back.
    Calling the same decision function makes that parity structural rather than remembered.
    """
    path = _resolve_operand(deps, operand)
    decision = permission.decide_write(
        path, run_dir=deps.run_dir, defender_dir=deps.defender_dir, policy=deps.policy,
    )
    if not decision.allow:
        raise ModelRetry(
            f"forward_check: {operand} is not a lesson in this curator's own corpus. "
            f"{decision.reason}"
        )
    return path


def _prepare(deps: CuratorDeps, pair: Pair) -> _Prepared:
    """Gate one pair before any check runs. The policy deny raises (whole call); a data
    fault becomes this pair's ERROR so its siblings still get real verdicts."""
    path = _gate_lesson_path(deps, pair.lesson_path)
    if pair.source_id not in deps.queued_ids:
        return _Prepared(pair, detail=_one_line(
            f"source id {pair.source_id!r} is not in this batch's queued rows"
        ))
    try:
        if not path.is_file():
            return _Prepared(pair, detail=_one_line(f"lesson not found: {path}"))
        text = path.read_text(encoding="utf-8")
    except (StageAbort, FatalConfigError):
        raise  # systemic: never demoted to one pair's ERROR
    except (OSError, ValueError) as e:
        # Reading the lesson is per-pair data, not policy: a file that vanished between the
        # stat and the read, an unreadable mode, a non-UTF-8 body (`UnicodeDecodeError` is a
        # `ValueError`). `_run_one` isolates the check itself; this read runs before the
        # worker thread, so without this it would abort the batch its siblings are in.
        return _Prepared(pair, detail=_detail(e))
    return _Prepared(pair, lesson_path=path, lesson_text=text, check_index=next(_CHECK_SEQ))


def _run_one(deps: CuratorDeps, item: _Prepared) -> _Result:
    """Run one check to a verdict on a worker thread. Never raises for a per-run fault — the
    caller's gather would otherwise cancel this check's still-in-flight siblings."""
    assert item.lesson_path is not None  # _prepare returns a detail instead
    ctx = CheckContext(
        check=deps.check,
        lesson_path=item.lesson_path,
        lesson_text=item.lesson_text,
        source_id=item.pair.source_id,
        direction=item.pair.direction,
        runs_dir=deps.runs_dir,
        pending=deps.pending,
        corpus_dir=deps.corpus_dir,
        repo_root=deps.defender_dir.parent,
        check_index=item.check_index,
        run_verify=deps.run_verify,
    )
    try:
        return _Result(item.pair, deps.check.run(ctx), "")
    except (StageAbort, FatalConfigError):
        raise  # systemic: the deployment is broken, doom the whole stage
    except SystemExit as e:
        # The verify_forward helpers signal a per-run data fault with SystemExit (their CLI
        # heritage): an unparseable verdict, a missing bundle artifact, a torn queue row.
        # In-process that is this pair's ERROR, never a process exit.
        return _Result(item.pair, "ERROR", _detail(e))
    except Exception as e:  # noqa: BLE001 — a per-run fault is this pair's ERROR, not the batch's
        return _Result(item.pair, "ERROR", _detail(e))


def _render_batch(results: list[_Result]) -> str:
    """The text protocol the three curator prompts parse: one line per pair in input order,
    then the summary. Spacing is load-bearing only in that the prompts read whitespace-
    separated fields; it matches what ``batch.py`` printed. Every model-supplied field goes
    through ``_field`` (and every detail through ``_one_line``), so a pair can render exactly
    one line and cannot forge a sibling verdict or the summary."""
    lines: list[str] = []
    counts = {v: 0 for v in _VERDICTS}
    for r in results:
        counts[r.verdict] += 1
        lp, idv = _field(r.pair.lesson_path), _field(r.pair.source_id)
        if r.verdict == "GOOD":
            lines.append(f"GOOD  {lp}  {idv}")
        elif r.verdict == "BAD":
            lines.append(f"BAD   {lp}  {idv}")
        else:
            lines.append(f"ERROR {lp}  {idv}  {r.detail}")
    lines.append(
        f"BATCH: n_good={counts['GOOD']} n_bad={counts['BAD']} n_error={counts['ERROR']}"
    )
    text = "\n".join(lines) + "\n"
    _assert_wellformed(text, len(results))
    return text


def _assert_wellformed(text: str, n_results: int) -> None:
    """Output-grammar tripwire: the rendered batch MUST be exactly one line per pair plus the
    BATCH summary, each result line led by a verdict token. `_field` / `_one_line` make that true
    by construction, so this never fires in a correct build — it exists to catch a FUTURE result
    field rendered without escaping, before the extra line it produces can be read as a forged
    verdict. `splitlines()` is deliberately the broadest notion of a line (it breaks on `\\x1c`,
    `\\u2028`, … as well as `\\n`), so the check refutes any line break an escaper missed; every
    one of those characters is inside `_field`'s `\\s` and `_one_line`'s `str.split`, so a real
    render stays within it. A violation raises rather than returns — a batch the tool cannot
    vouch for must not reach the curator."""
    lines = text.splitlines()
    if len(lines) != n_results + 1:
        raise _ProtocolError(
            f"rendered {len(lines)} lines for {n_results} pair(s) + summary — a result field "
            "carried an unescaped line break"
        )
    if not lines[-1].startswith("BATCH:"):
        raise _ProtocolError(f"summary line missing or displaced: {lines[-1]!r}")
    for line in lines[:-1]:
        if not line.startswith(tuple(f"{v} " for v in _VERDICTS)):
            raise _ProtocolError(f"result line without a leading verdict token: {line!r}")


async def run_forward_check(deps: CuratorDeps, pairs: list[Pair]) -> str:
    """Check every pair against the curator's bound forward check and return the batch text.

    A one-off recheck is this called with a single pair; an empty list is an empty batch. The
    concurrency bound is read at CALL time so an operator (or a test) can drive it, and a
    zero bound fails loud — ``asyncio.Semaphore(0)`` would otherwise wait forever where the
    retired ``ThreadPoolExecutor(0)`` raised at once.
    """
    workers = config.verify_batch_workers()
    prepared = [_prepare(deps, p) for p in pairs]  # every deny raises before any check runs
    sem = asyncio.Semaphore(workers)

    async def _one(item: _Prepared) -> _Result:
        if item.detail is not None:
            return _Result(item.pair, "ERROR", item.detail)
        async with sem:  # released on raise, so a failing check cannot starve the queue
            return await asyncio.to_thread(_run_one, deps, item)

    settled = await asyncio.gather(*(_one(i) for i in prepared), return_exceptions=True)
    results: list[_Result] = []
    for outcome in settled:
        if isinstance(outcome, BaseException):
            raise outcome  # systemic — surfaced only after every sibling ran to completion
        results.append(outcome)  # every non-exception outcome is a verdict; none is dropped
    return _render_batch(results)


def register_forward_check_tool(agent) -> None:
    """Register the curator's ``forward_check`` tool. Lives here, not in ``runtime/tools.py``,
    so the tool's operand type resolves in this module's namespace and nothing curator-
    specific leaks into the runtime — the shape ``register_gather_tool`` already uses."""

    @agent.tool
    async def forward_check(ctx: RunContext[AgentDeps], pairs: list[Pair]) -> str:
        """Forward-check the lessons you wrote. Write every lesson file first, then check the
        whole set in ONE call, passing one pair per file: `lesson_path`, the source row's
        `source_id`, and — for findings lessons — that row's own `direction` (`adversarial`,
        the lesson must preserve the case's benign call; `benign`, it must drive the agent off
        the over-escalated malicious one). Returns one `GOOD`/`BAD`/`ERROR <reason>` line per
        pair plus a `BATCH:` summary — read that single return value, do not poll."""
        return await run_forward_check(cast("CuratorDeps", ctx.deps), pairs)

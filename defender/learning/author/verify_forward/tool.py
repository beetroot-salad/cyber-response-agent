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

if TYPE_CHECKING:
    from defender.learning.author.curator_engine import CuratorDeps

_CHECK_SEQ = itertools.count()

_DETAIL_MAX = 200

_WHITESPACE = re.compile(r"\s+")

_VERDICTS = ("GOOD", "BAD", "ERROR")


class _ProtocolError(RuntimeError):
    pass


@pydantic_dataclass(frozen=True)
class Pair:
    lesson_path: str
    source_id: str
    direction: Literal["adversarial", "benign"] = "adversarial"


@dataclass(frozen=True)
class _Prepared:

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
    return " ".join(text.split())[:_DETAIL_MAX]


def _detail(exc: BaseException) -> str:
    return _one_line(str(exc)) or _one_line(repr(exc))


def _field(value: str) -> str:
    return _WHITESPACE.sub(r"\\s", value)[:_DETAIL_MAX] or "<empty>"


def _gate_lesson_path(deps: CuratorDeps, operand: str) -> Path:
    if deps.tool_config is None:
        raise ModelRetry(
            "forward_check: this curator spawn's tool_config is not set — attach a "
            "ForwardCheckConfig before calling forward_check."
        )
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
        raise
    except (OSError, ValueError) as e:
        return _Prepared(pair, detail=_detail(e))
    return _Prepared(pair, lesson_path=path, lesson_text=text, check_index=next(_CHECK_SEQ))


def _run_one(deps: CuratorDeps, item: _Prepared) -> _Result:
    assert item.lesson_path is not None
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
        raise
    except SystemExit as e:
        return _Result(item.pair, "ERROR", _detail(e))
    except Exception as e:  # noqa: BLE001 — a per-run fault is this pair's ERROR, not the batch's
        return _Result(item.pair, "ERROR", _detail(e))


def _render_batch(results: list[_Result]) -> str:
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
    workers = config.verify_batch_workers()
    prepared = [_prepare(deps, p) for p in pairs]
    sem = asyncio.Semaphore(workers)

    async def _one(item: _Prepared) -> _Result:
        if item.detail is not None:
            return _Result(item.pair, "ERROR", item.detail)
        async with sem:
            return await asyncio.to_thread(_run_one, deps, item)

    settled = await asyncio.gather(*(_one(i) for i in prepared), return_exceptions=True)
    results: list[_Result] = []
    for outcome in settled:
        if isinstance(outcome, BaseException):
            raise outcome
        results.append(outcome)
    return _render_batch(results)


def register_forward_check_tool(agent) -> None:

    @agent.tool
    async def forward_check(ctx: RunContext[AgentDeps], pairs: list[Pair]) -> str:
        """Forward-check the lessons you wrote. Write every lesson file first, then check the
        whole set in ONE call, passing one pair per file: `lesson_path`, the source row's
        `source_id`, and — for findings lessons — that row's own `direction` (`adversarial`,
        the lesson must preserve the case's benign call; `benign`, it must drive the agent off
        the over-escalated malicious one). Returns one `GOOD`/`BAD`/`ERROR <reason>` line per
        pair plus a `BATCH:` summary — read that single return value, do not poll."""
        return await run_forward_check(cast("CuratorDeps", ctx.deps), pairs)

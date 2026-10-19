"""Oracle state and query admission."""
from __future__ import annotations

import contextlib



import json

import logging


import threading

import time

import uuid

from collections.abc import Callable, Mapping

from dataclasses import dataclass

from pathlib import Path

from typing import Any


from defender.episodes._episode_paths import OracleStorePaths

from defender._io import guarded_mkdir, read_bytes_capped, read_jsonl_rows, write_guarded

from defender.configuration._pricing import usage_cost


from defender.learning.branch.ledger import request_key








from defender.learning.branch.estate.checks import Refused
from defender.learning.branch.estate.limiter import LimiterStateError, RateLimiter


_logger = logging.getLogger(__name__)




# --------------------------------------------------------------------------------------------
# The world's oracle-side store (one writer per world, S19).
# --------------------------------------------------------------------------------------------



def _ends_torn(path: Path) -> bool:
    try:
        data = read_bytes_capped(path)
    except OSError:
        return False
    return bool(data) and not data.endswith(b"\n")




def _trace_spent(rows: list[dict]) -> float:
    """The spend the trace records, each row counted once by its `id` (a charge whose append
    failed part-way is rewritten whole by the next one). A row without an id counts as it is."""
    seen: set[str] = set()
    total = 0.0
    for row in rows:
        rid = row.get("id")
        if isinstance(rid, str):
            if rid in seen:
                continue
            seen.add(rid)
        total += float(row.get("cost_usd") or 0.0)
    return total




class OracleStore:
    """`oracle/<label>/`: frozen forged rows, recorded facts, the served-answer cache, the
    oracle-side ledger, this world's live base answers and the oracle's spend trace."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self._lock = threading.Lock()
        #: Files whose last line is torn (a crash mid-append): the next append starts on a
        #: line of its own, so the torn record stays unread rather than swallowing a new one.
        self.paths = OracleStorePaths(self.root)
        self._torn = {path for path in self.paths.all() if _ends_torn(path)}
        self.frozen: dict[str, dict] = {}
        for row in read_jsonl_rows(self.paths.forged):
            if isinstance(row.get("forged_id"), str):
                self.frozen.setdefault(row["forged_id"], row)
        self.facts: dict[tuple[str, str], Any] = {}
        for row in read_jsonl_rows(self.paths.facts):
            if isinstance(row.get("entity"), str) and isinstance(row.get("field"), str):
                self.facts.setdefault((row["entity"], row["field"]), row.get("value"))
        self.answers: dict[str, dict] = {}
        for row in read_jsonl_rows(self.paths.answers):
            if isinstance(row.get("system"), str) and isinstance(row.get("verb"), str):
                key = request_key(row["system"], row["verb"], row.get("params") or {})
                self.answers.setdefault(key, row)
        self.base: dict[str, str] = {}
        #: The same answers as `(system, text)`, in the order they were read live.
        self.base_answers: list[tuple[str, str]] = []
        for row in read_jsonl_rows(self.paths.base):
            text = row.get("payload_text")
            if isinstance(text, str) and isinstance(row.get("system"), str):
                key = request_key(row["system"], str(row.get("verb")), row.get("params") or {})
                if key not in self.base:
                    self.base[key] = text
                    self.base_answers.append((row["system"], text))
        self.spent = _trace_spent(read_jsonl_rows(self.paths.trace))
        #: Trace rows charged to `spent` whose append failed; the next charge writes them first.
        #: Each row carries its own `id`: a failed append may have landed some of them whole,
        #: and the rewrite of those is counted once (`_trace_spent`).
        self._unwritten: list[dict] = []
        #: The `(forged_id, column, value)` of every collision already recorded.
        self._collided = {(r.get("forged_id"), r.get("column"), r.get("value"))
                          for r in read_jsonl_rows(self.paths.collisions)}

    def _append(self, path: Path, rows: list[dict]) -> None:
        guarded_mkdir(self.root, base=self.root.parent)
        text = "".join(json.dumps(row) + "\n" for row in rows)  # lint-jsonl-io: ok — whole rows, one guarded append
        if path in self._torn:
            text = "\n" + text
        write_guarded(path, text, mode="append")
        self._torn.discard(path)

    def log_query(self, actor: str, system: str, verb: str, params: Mapping[str, Any]) -> None:
        with self._lock:
            self._append(self.paths.ledger, [{"actor": actor, "system": system, "verb": verb,
                                   "params": dict(params)}])

    def keep_base(self, system: str, verb: str, params: Mapping[str, Any], text: str) -> None:
        with self._lock:
            key = request_key(system, verb, params)
            if key in self.base:
                return
            self._append(self.paths.base, [{"system": system, "verb": verb, "params": dict(params),
                                 "payload_text": text}])
            self.base[key] = text
            self.base_answers.append((system, text))

    def charge(self, actor: str, model_name: str, usage: Mapping[str, Any], *,
               priced_as: str) -> float:
        """Record one response's spend: `model_name` as the provider reported it, its cost at
        the `priced_as` pricing row. The cost counts toward `spent` whatever the trace write
        does: a row whose append fails is kept and written ahead of the next one, and the
        response it prices is used as it is (a paid answer is not a failed request)."""
        cost = usage_cost(priced_as, dict(usage))
        row = {"id": uuid.uuid4().hex, "actor": actor, "model": model_name,
               "input_tokens": usage.get("input_tokens", 0),
               "output_tokens": usage.get("output_tokens", 0), "cost_usd": cost, "at": time.time()}
        with self._lock:
            self.spent += cost
            self._unwritten.append(row)
            try:
                self._append(self.paths.trace, self._unwritten)
            except OSError as unwritable:
                # A partial append may have left a torn line: the retry starts on its own. Rows
                # it landed whole are written again, and read once (each by its `id`).
                self._torn.add(self.paths.trace)
                _logger.warning(f"the oracle's spend trace could not record "
                                f"{len(self._unwritten)} row(s) ({unwritable!r}); they are "
                                "counted and retried with the next charge")
            else:
                self._unwritten = []
        return cost

    def record_collisions(self, entries: list[dict]) -> None:
        """Append each frozen-row collision not already recorded (M12=A), keyed on
        `(forged_id, column, value)` — the judge reads them off `collisions.jsonl`.

        @owns collisions — the shipped `oracle/<label>/collisions.jsonl` rows are produced here."""
        with self._lock:
            new = [e for e in entries
                   if (e["forged_id"], e["column"], e["value"]) not in self._collided]
            if new:
                self._append(self.paths.collisions, new)
                self._collided.update((e["forged_id"], e["column"], e["value"]) for e in new)

    def commit(self, *, forged: list[dict], facts: list[dict], answer: dict | None) -> None:
        """Freeze this attempt's forged rows and facts with the verified answer (M15=B): rows
        and facts first, then the answer that cites them. `answer=None` is pre-flight's
        calibration (Amendment 2, S1): the rows and facts are frozen, no served answer is
        cached."""
        with self._lock:
            new_rows = [r for r in forged if r["forged_id"] not in self.frozen]
            new_facts = [f for f in facts if (f["entity"], f["field"]) not in self.facts]
            if new_rows:
                self._append(self.paths.forged, new_rows)
            if new_facts:
                self._append(self.paths.facts, new_facts)
            if answer is not None:
                self._append(self.paths.answers, [answer])
            for r in new_rows:
                self.frozen[r["forged_id"]] = r
            for f in new_facts:
                self.facts[(f["entity"], f["field"])] = f["value"]
            if answer is not None:
                key = request_key(answer["system"], answer["verb"], answer["params"])
                self.answers[key] = answer




# --------------------------------------------------------------------------------------------
# The run-query door: every query branching issues on its own behalf (M7, M13; O6, O9).
# --------------------------------------------------------------------------------------------


class LimiterWaits:
    """One attempt's time waiting on the rate limiter, which its deadline excludes (M11=A).

    Each attempt holds its own, and its tools (the verifier's and the host checks' queries
    included) wait into it: a thread an earlier attempt abandoned still holds that attempt's
    record, so it can neither end nor add to this one's. Overlapping waits count once."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._done = 0.0
        self._open = 0
        self._since = 0.0

    @contextlib.contextmanager
    def waiting(self) -> Any:
        with self._lock:
            if not self._open:
                self._since = time.monotonic()
            self._open += 1
        try:
            yield
        finally:
            with self._lock:
                self._open -= 1
                if not self._open:
                    self._done += time.monotonic() - self._since

    def excluded(self) -> float:
        """Every second of limiter wait so far, a wait in progress included."""
        with self._lock:
            return self._done + (time.monotonic() - self._since if self._open else 0.0)




@dataclass
class QueryDoor:
    """Grant-decided (read verbs only), at the branch-point clock, rate-limited, recorded in
    the world's oracle-side ledger and nowhere else."""

    decide: Callable[[str, str], Any]
    real_verbs: Callable[[str], Mapping[str, Any]]
    limiter: RateLimiter
    store: OracleStore
    context: Callable[[], Any]

    def run(self, actor: str, system: Any, verb: Any, params: Any, *,
            waits: LimiterWaits) -> Any:
        """The real answer, or `Refused` naming why not. Time waiting on the limiter goes to
        `waits`, the asking attempt's own record."""
        if not isinstance(system, str) or not isinstance(verb, str):
            raise Refused(f"run_query needs a system and a verb name; got {system!r}.{verb!r}")
        if params is None:
            params = {}
        if not isinstance(params, Mapping):
            raise Refused(f"run_query {system}.{verb}: params must be a mapping")
        try:
            decision = self.decide(system, verb)
        except Exception as exc:  # noqa: BLE001 — a grant/declaration disagreement refuses
            raise Refused(f"run_query {system}.{verb} was refused: {exc}") from None
        if decision.outcome != "GRANTED":
            raise Refused(f"run_query {system}.{verb} was refused: {decision.refusal}")
        from defender.runtime.verbs import verb_class_of

        fn = self.real_verbs(system).get(verb)
        if fn is None or verb_class_of(fn) != "r":
            raise Refused(f"run_query {system}.{verb} was refused: only read verbs are served "
                          "to the oracle")
        with waits.waiting():
            try:
                self.limiter.acquire()
            except LimiterStateError:
                # The limiter failed closed: the oracle's own machinery, not the tenant, so
                # the attempt fails (M03=A) rather than handing the oracle feedback; the
                # limiter's text (an OS error) is not shown.
                raise _AttemptFailed("the rate limiter could not admit a query (it failed "
                                     "closed)") from None
        try:
            answer = fn(self.context(), **dict(params))
        except Exception as exc:  # noqa: BLE001 — a tenant error is the oracle's to see
            self._log(actor, system, verb, params)
            raise Refused(f"run_query {system}.{verb} failed at the tenant: "
                          f"{type(exc).__name__}: {exc}") from None
        self._log(actor, system, verb, params)
        # One spelling, as every served payload: the adapter's own answer, round-tripped.
        return json.loads(json.dumps(answer, sort_keys=True, default=str))

    def _log(self, actor: str, system: str, verb: str, params: Mapping[str, Any]) -> None:
        try:
            self.store.log_query(actor, system, verb, params)
        except OSError:
            raise StoreFailure("the oracle-side ledger could not record a query") from None




class _AttemptFailed(Exception):
    """A tool that ends the attempt as failed (no sandboxed box for `python`)."""




class StoreFailure(Exception):
    """A write to the world's oracle-side store failed; the attempt that needed it fails
    (M03=A). Its text names no path or OS error: it may reach the oracle."""

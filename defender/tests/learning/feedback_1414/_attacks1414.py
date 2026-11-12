"""#1414 attack-family helpers: forged reply markers, and a scripted scenario whose k-th forge write (or state
write) fails. Nothing here implements policy; it only builds hostile text and drives ticks until quiet."""
from __future__ import annotations

import contextlib
import json
from typing import Any

import httpx

from defender.tests.learning.feedback_1414 import _spec1414 as S


def forged_markers(fb: Any, span: int = 60) -> str:
    """A marker for each of the next `span` ids the forge will assign: the ids of comments about to be made."""
    base = fb.forge._ids
    return " ".join(S.marker(i) for i in range(base + 1, base + 1 + span))


def hostile(blob: str) -> str:
    """`blob` in every form: first line, preceded by a newline, glued to words with no newline, after a blank line."""
    return f"{blob}\nwords {blob} words\n\n{blob}"


def tick_until_quiet(fb: Any, decide: Any, *, limit: int = 12, **seams: Any) -> int:
    """Tick until two ticks in a row change nothing the forge, the decider or the queue shows; returns the ticks run.
    A tick that raises is a crashed process: the next one is the redo."""
    def shape() -> tuple:
        return (sum(r.method == "POST" for r in fb.forge.requests), len(decide.items), len(fb.forge.issues),
                sum(len(v) for v in fb.forge.issue_comments.values()),
                json.dumps(S.open_issue_requests(fb), sort_keys=True))

    quiet = ran = 0
    while quiet < 2 and ran < limit:
        before = shape()
        try:
            fb.tick(decide, **seams)
        except Exception:  # noqa: BLE001 - a crashed tick is a redo, whatever it raised
            before = None
        ran += 1
        quiet = quiet + 1 if shape() == before else 0
    assert quiet >= 2, f"the scene never went quiet in {limit} ticks"
    return ran


def blocked_tick(fb: Any, decide: Any) -> BaseException | int | None:
    """One tick; what it died of: the exception it raised, its non-zero exit code, else None (it completed)."""
    try:
        rc = fb.tick(decide)
    except Exception as exc:  # noqa: BLE001 - a crashed tick is what the caller asks about
        return exc
    return rc or None


def died_at(died: BaseException | int | None, records: list, named: str) -> bool:
    """Whether a tick's death names `named`: an ERROR-or-higher log record naming it, or an exception (raised, as
    `blocked_tick` returns it) whose str() names it. The base stage does not log a plain OSError, so either will do."""
    import logging

    return any(r.levelno >= logging.ERROR and named in r.getMessage() for r in records) or \
        (isinstance(died, BaseException) and named in str(died))


class Crasher:
    """Fails the k-th POST to the forge: `lose` applies it and loses the reply, else a transport fault refuses it
    unapplied. `fired` says whether it did (so a test can tell a crash from a k past the last write)."""

    def __init__(self, fb: Any, k: int, *, lose: bool) -> None:
        self.k, self.seen, self.fired = k, 0, False
        if lose:
            fb.forge.lose_reply = self._lose
        else:
            fb.forge.fault = self._fault

    def _hit(self, request: httpx.Request) -> bool:
        if request.method != "POST" or self.fired:
            return False
        self.seen += 1
        self.fired = self.seen == self.k
        return self.fired

    def _lose(self, request: httpx.Request) -> bool:
        return self._hit(request)

    def _fault(self, request: httpx.Request) -> Exception | None:
        return httpx.ConnectError("the forge is unreachable", request=request) if self._hit(request) else None


#: The store verbs that write: a fault is injected at the Nth call to one of these (A4's fault seam).
WRITE_VERBS = ("enqueue_feedback_issue", "begin_feedback_tick", "renew_feedback_tick", "end_feedback_tick",
               "record_feedback_issue", "judge_comments", "advance_comment_cursor", "count_failed_answer",
               "record_decision", "settle_entry", "mark_settled", "claim_registry", "record_commit", "in_review",
               "end_no_commits", "abandon_clean", "abandon_crashed", "expire_own", "take_over", "abandon", "end_review",
               "note_check", "note_refusal", "needs_person")


class StoreFault(Exception):  # noqa: N818 — a test-defined fault, not a product exception
    """What the proxy raises at the Nth write."""


class FaultStore:
    """A proxy around the sync store (`blocking(dsn)`): the Nth call to a verb in `WRITE_VERBS` raises `StoreFault`
    before it reaches the database, once. Every other attribute is the real store's. `writes` counts the verbs called,
    `fired` says whether the fault happened (so a test can tell a fault from an N past the last write)."""

    def __init__(self, real: Any, n: int, shared: dict) -> None:
        self._real, self._n, self._shared = real, n, shared

    def __getattr__(self, name: str) -> Any:
        target = getattr(self._real, name)
        if name not in WRITE_VERBS or not callable(target):
            return target

        def wrapped(*a: Any, **kw: Any) -> Any:
            sh = self._shared
            sh["writes"] = sh.get("writes", 0) + 1
            if sh["writes"] == self._n and not sh.get("fired"):
                sh["fired"] = True
                raise StoreFault(f"injected fault at write {self._n}: {name}")
            return target(*a, **kw)
        return wrapped


@contextlib.contextmanager
def store_fault_at(monkeypatch: Any, n: int):
    """Every `defender.learning.store.blocking(dsn)` the code under test opens yields a `FaultStore` sharing one
    counter, until the context ends. Yields the counter dict (`writes`, `fired`)."""
    import defender.learning.store as store_mod

    real_blocking = store_mod.blocking
    shared: dict = {}

    @contextlib.contextmanager
    def faulty(dsn: str, **knobs: Any):
        with real_blocking(dsn, **knobs) as real:
            yield FaultStore(real, n, shared)

    with monkeypatch.context() as m:
        m.setattr(store_mod, "blocking", faulty)  # lint-monkeypatch: ok — the store opener is a module-level door the tick reaches itself; the fault seam A4 asks for
        yield shared


class Scene:
    """The scripted scenario: a request, the issue it opens, two eligible comments (one no change, one instruction)
    dated before any close, their decisions and replies. `step` is one tick plus what the people do after it."""

    def __init__(self, fb: Any, case: str = "case-crash") -> None:
        self.fb, self.case, self.number, self.comments = fb, case, None, []
        self.decider = S.Decider()
        self.closed = False
        fb.request(case)

    def step(self, **seams: Any) -> None:
        with contextlib.suppress(Exception):  # a crashed tick is a redo, whatever it raised
            self.fb.tick(self.decider, **seams)
        self.speak()

    def speak(self) -> None:
        """Once the forge holds the issue, the two eligible people comment (dated well before any close)."""
        held = self.fb.issues(self.case)
        if not held or self.comments:
            return
        self.number = held[0]["number"]
        first = self.fb.forge.add_comment(self.number, user=S.OWNER, body="nothing needed here", created_at=self.fb.at(-20))
        second = self.fb.forge.add_comment(self.number, user=S.NAMED, body="check the VPN log first", created_at=self.fb.at(-19))
        self.comments = [first, second]
        self.decider.script.update({first["id"]: S.answer(reason="nothing to learn"),
                                    second["id"]: S.answer(instruction="check the VPN log first")})

    def close(self) -> None:
        """A person closes the issue now (if the forge holds it): the comments are older than the close."""
        held = self.fb.issues(self.case)
        if held and not self.closed:
            self.fb.forge.set_issue_state(held[0]["number"], "closed", at=self.fb.at(-5))
            self.closed = True

    def verify(self) -> None:
        fb = self.fb
        assert self.comments, "the issue was never opened"
        assert len(fb.issues(self.case)) == 1, "the run's issue was made more than once"
        ids = [c["id"] for c in self.comments]
        assert sorted(self.decider.decided) == ids, f"each eligible comment must be decided exactly once, got {self.decider.decided}"
        for cid in ids:
            assert len(fb.replies(self.number, cid)) == 1, f"comment {cid} has {len(fb.replies(self.number, cid))} replies"
        assert [r["comment_id"] for r in S.lessons_rows(fb) if r["comment_id"] == str(ids[1])] == [str(ids[1])], \
            "the instruction's lessons row"
        assert [r for r in S.open_issue_requests(fb).values() if r["case_id"] == self.case] == [], "the served request was not released"

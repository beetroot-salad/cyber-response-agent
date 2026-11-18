"""Slice b helpers: the real close over a per-test store, and the committed record read back through the lookup (no tests).

`production names that do not exist yet are imported inside functions`, as in `_spec1534`."""
from __future__ import annotations

import asyncio
import contextlib
import sqlite3
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any, NamedTuple

from defender.records._store_errors import StoreError
from defender.tests.storage.verdict_1534 import _spec1534 as V
from defender.tests.support.runtime.engine import _spec992 as S9
from defender.tests.support.shared.contracts import _tacit983 as scene

CASE = "closing-1534-close"

#: An `inconclusive` document (it pays its price with a `query-empty` receipt) carrying one baseline: one parse that
#: gives the close a summary row, a ceiling receipt and a baseline whatever disposition it commits.
DOC = scene.inconclusive_document(rows=scene.consult_block(scene.consultation_row()))
DOC_SUMMARY = "container UID 0 rewriting the CA bundle could not be tied to the image build."
DOC_RECEIPT = ("query-empty", "l-002", None, "host-state proc-tree came back empty for the build container")
#: The baseline row `scene.consultation_row()` writes, as the record keeps it (host in the result defanged).
DOC_BASELINE = (
    "l-001", "runtime-evidence", "telemetry-baseline", "tk-baseline-30d",
    "1500 occurrences over 30d; actor uid-0 and host build-runner-07[.]prod throughout",
    "no adverse outcome fell inside the window",
)


class Closed(NamedTuple):
    result: Any
    deps: Any
    run_dir: Path
    record: Any
    database: Path


@contextlib.contextmanager
def opened(tmp_path: Path, companion: str | bytes | None, *, case_id: str = CASE) -> Iterator[tuple[Any, Path, Any]]:
    """MAIN deps carrying the run's own open store, the run folder under this test's runs base."""
    deps, run_dir = V.closing_deps(tmp_path, companion if isinstance(companion, str) else None)
    if isinstance(companion, bytes):
        (run_dir / "investigation.md").write_bytes(companion)
    with V.run_store(V.runs_base(tmp_path), case_id) as store:
        yield V.with_store(deps, store), run_dir, store


def committed_record(run_dir: Path, store: Any) -> Any:
    """The run's closing record through the run-handle lookup (the pointer is written here, as the driver writes it)."""
    from defender.records import closing as C

    V.point(run_dir, store)
    found = C.for_run(V.handle(run_dir))
    assert isinstance(found, C.Record), f"the close left no readable record: {found!r}"
    return found.record


def close_run(tmp_path: Path, disposition: str, companion: str | bytes | None, *, stages: Any = None,
              bounds: Any = None, forced: bool = False) -> Closed:
    """The real close, once, with `stages` (default: a composer that holds), then the record read back."""
    with opened(tmp_path, companion) as (deps, run_dir, store):
        bundle = S9.recording(S9.holds()) if stages is None else stages
        result = S9.close_with(deps, disposition, bundle, bounds=bounds, forced=forced)
        return Closed(result, deps, run_dir, committed_record(run_dir, store), Path(store.path))


def forced_close(tmp_path: Path, companion: str | bytes | None) -> Closed:
    """The host's forced close of a run cut short, over `companion`."""
    return close_run(tmp_path, "unresolved", companion, forced=True)


def ceiling_of(record: Any) -> list[tuple]:
    return [(e.state, e.ref, e.cap, e.note) for e in record.ceiling_test]


def baselines_of(record: Any) -> list[tuple]:
    return [(e.lead, e.anchor_kind, e.grounding_kind, e.anchor_id, e.result, e.reasoning)
            for e in record.runtime_evidence]


def plain(n: int) -> str:
    """`n` characters of plain words (no dot, no URL, nothing `treat` changes), ending in a letter."""
    text = ("alpha beta gamma " * (n // 17 + 2))[:n].rstrip()
    return text + "x" * (n - len(text))


def expanding(n: int) -> str:
    """Text whose treated form is exactly `n` characters while the raw text is shorter: each `ab.cd` token is
    host-shaped and becomes `ab[.]cd` (two characters longer)."""
    units = n // 8 - 1
    text = "ab.cd " * units
    return text + "x" * (n - 8 * units)


def forced_doc(*, ceiling: tuple[str, ...] = (), summary: str = "a summary", disposition: str = "malicious") -> str:
    """A document the forced close reads without any gate: `:T conclude` with `ceiling` receipt rows."""
    from defender.tests.support.runtime.engine import _spec923 as S

    return S.doc(S.PROLOGUE, S.LEADS, S.LEAD_RESULT, S.conclude(
        disposition=disposition, confidence="medium", **{"termination.category": "data-ceiling"},
        summary=f'"{summary}"', ceiling_test=ceiling,
    ))


def capability_rows(count: int, note: Any) -> tuple[str, ...]:
    """`count` distinct `nothing-to-try` receipts (each pays: the capability is not in the roster); `note(i)` is row i's note."""
    return tuple(f"state=nothing-to-try cap=fake-system-{i:03d}.fake-verb note={note(i)}" for i in range(count))


def with_ceiling(disposition: str, rows: tuple[str, ...] | list[str]) -> str:
    """`_spec923.pays_every_price(disposition)` with its `ceiling_test` rows replaced by `rows` (any model disposition)."""
    from defender.tests.support.runtime.engine import _spec923 as S

    out = []
    for line in S.pays_every_price(disposition).split("\n"):
        if line.startswith("ceiling_test"):
            continue
        out.append(line)
        if line.startswith("summary "):
            out.extend(f'{"ceiling_test":<22} "{row}"' for row in rows)
    return "\n".join(out)


def fill_sizes(probe_lines: list[str], bound: int, extra: int = 0) -> list[int]:
    """Note sizes, one per row, so the rendered lines (each probe line carries a one-character note) joined by "\\n"
    come to exactly `bound + extra` characters."""
    count = len(probe_lines)
    total = bound + extra - (count - 1) - sum(len(p) - 1 for p in probe_lines)
    return [total // count + (1 if i < total % count else 0) for i in range(count)]


def model_dispositions() -> list[str]:
    """Every disposition a model close may commit: the whole vocabulary but the host's own."""
    from defender._vocab import DISPOSITION_VALUES
    from defender.tests.support.runtime.engine import _spec923 as S

    return sorted(d for d in DISPOSITION_VALUES if d != S.MEMBER)


# --- OD16 / M3: documents carrying every bounded field, for every model disposition -------------------------------------

_ALERT_EDGE = (
    "\n:E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]\n"
    "e-000|attempted_auth|v-002|v-001|2026-05-05T03:42:11Z|siem-event:elastic|\n"
)


def _with_alert(text: str) -> str:
    """`_spec923`'s prologue gains an alerted edge (the baseline guard needs one); a document without that prologue is unchanged."""
    from defender.tests.support.runtime.engine import _spec923 as S

    if S.PROLOGUE not in text:
        return text
    vertices = S.PROLOGUE.replace("os=linux\n", "os=linux\nv-002|identity|user/known-corp|svc.alert|\n")
    return text.replace(S.PROLOGUE, vertices[: -len("```\n")] + _ALERT_EDGE + "```\n")


def _before_conclude(text: str, block: str) -> str:
    at = text.rfind("```invlang\n:T conclude")
    assert at >= 0, "fixture control: the document has a conclude fence"
    return text[:at] + "```invlang\n" + block + "```\n" + text[at:]


def baseline_document(disposition: str, rows: list[str], *, lead: str | None = None, ceiling: tuple[str, ...] | None = None) -> str:
    """`_spec923.pays_every_price(disposition)` carrying `rows` as `:R consultations`; `lead`, when not `l-001`, is declared;
    `ceiling` replaces the document's own receipt rows."""
    from defender.tests.support.runtime.engine import _spec923 as S

    text = _with_alert(S.pays_every_price(disposition) if ceiling is None else with_ceiling(disposition, ceiling))
    if lead is not None and lead != scene.LEAD:
        text = _before_conclude(
            text, f":L findings [id|loop|name|target|tests|system|window]\n{lead}|1|long-lead|v-001||elastic|n/a\n")
    return _before_conclude(text, scene.consult_block(*rows)) if rows else text


class Case(NamedTuple):
    """One generated document: the bound it probes, the names a refusal may call the field, the document at the bound
    (`at`) and one over (`over`), each with the entries a close must store for it (`over` has none)."""

    name: str
    bound: int
    names: tuple[str, ...]
    at: Any
    over: Any


class Doc(NamedTuple):
    build: Any  # disposition -> document text
    ceiling: list[tuple]  # expected (state, ref, cap, note), host text defanged
    baselines: list[tuple]  # expected (lead, anchor_kind, grounding_kind, anchor_id, result, reasoning)


def _treated(text: str) -> str:
    from defender.records import closing as C

    return C.treat(text, None)


def _one_baseline(**cells: str) -> Doc:
    import inspect

    lead = cells.pop("resolved_by", scene.LEAD)
    row = scene.consultation_row(resolved_by=lead, **cells)
    given = {k: v.default for k, v in inspect.signature(scene.consultation_row).parameters.items()} | cells
    result, reasoning, anchor = given["result"], given["reasoning"], given["anchor_id"]
    return Doc(lambda d: baseline_document(d, [row], lead=lead), [],
               [(lead, "runtime-evidence", "telemetry-baseline", anchor, _treated(result), _treated(reasoning))])


def _ceiling_doc(rows: tuple[str, ...], expected: list[tuple]) -> Doc:
    return Doc(lambda d: with_ceiling(d, rows), expected, [])


CASE_NAMES = ("note", "lead", "anchor_id", "result", "reasoning", "ceiling-count", "ceiling-aggregate",
              "baseline-aggregate")


def case(name: str) -> Case:
    return next(c for c in _cases() if c.name == name)


def _cases() -> list[Case]:
    """Every bounded field of both entry types, the ceiling count cap and both aggregates, from the constants in `closing`."""
    from defender.records import closing as C

    def note(n: int) -> Doc:
        text = expanding(n)
        return _ceiling_doc(capability_rows(1, lambda _i: text),
                            [("nothing-to-try", None, "fake-system-000.fake-verb", _treated(text))])

    def token(prefix: str, n: int) -> str:
        return prefix + "x" * (n - len(prefix))

    def count(n: int) -> Doc:
        return _ceiling_doc(capability_rows(n, lambda i: f"n{i}"),
                            [("nothing-to-try", None, f"fake-system-{i:03d}.fake-verb", f"n{i}") for i in range(n)])

    def ceiling_aggregate(extra: int) -> Doc:
        probes = [C.ceiling_line(C.CeilingEntry("nothing-to-try", None, f"fake-system-{i:03d}.fake-verb", "x")) for i in range(6)]
        sizes = fill_sizes(probes, C.CEILING_LINES_BOUND, extra)
        assert max(sizes) <= C.NOTE_BOUND, "fixture control: each note fits its own bound"
        return _ceiling_doc(capability_rows(6, lambda i: plain(sizes[i])),
                            [("nothing-to-try", None, f"fake-system-{i:03d}.fake-verb", plain(sizes[i])) for i in range(6)])

    def baseline_aggregate(extra: int) -> Doc:
        window = ("2026-04-04T00:00:00Z", "2026-05-04T00:00:00Z")
        ids = [f"tk-b-{i:03d}" for i in range(6)]
        probes = [C.baseline_line(C.BaselineEntry(scene.LEAD, "runtime-evidence", "telemetry-baseline", a, *window, "x", "r"))
                  for a in ids]
        sizes = fill_sizes(probes, C.BASELINE_LINES_BOUND, extra)
        assert max(sizes) <= C.RESULT_BOUND, "fixture control: each result fits its own bound"
        rows = [scene.consultation_row(anchor_id=a, result=plain(s), reasoning="r") for a, s in zip(ids, sizes, strict=True)]
        return Doc(lambda d: baseline_document(d, rows), [],
                   [(scene.LEAD, "runtime-evidence", "telemetry-baseline", a, plain(s), "r") for a, s in zip(ids, sizes, strict=True)])

    def lead(n: int) -> Doc:
        return _one_baseline(resolved_by="l-" + "1" * (n - 2))

    return [
        Case("note", C.NOTE_BOUND, ("note",), note(C.NOTE_BOUND), note(C.NOTE_BOUND + 1)),
        Case("lead", C.LEAD_BOUND, ("resolved_by", "lead"), lead(C.LEAD_BOUND), lead(C.LEAD_BOUND + 1)),
        Case("anchor_id", C.ANCHOR_ID_BOUND, ("anchor_id",),
             _one_baseline(anchor_id=token("tk-", C.ANCHOR_ID_BOUND)), _one_baseline(anchor_id=token("tk-", C.ANCHOR_ID_BOUND + 1))),
        Case("result", C.RESULT_BOUND, ("result",),
             _one_baseline(result=expanding(C.RESULT_BOUND)), _one_baseline(result=expanding(C.RESULT_BOUND + 1))),
        Case("reasoning", C.REASONING_BOUND, ("reasoning",),
             _one_baseline(reasoning=expanding(C.REASONING_BOUND)), _one_baseline(reasoning=expanding(C.REASONING_BOUND + 1))),
        Case("ceiling-count", C.CEILING_COUNT_CAP, ("ceiling_test",), count(C.CEILING_COUNT_CAP), count(C.CEILING_COUNT_CAP + 1)),
        Case("ceiling-aggregate", C.CEILING_LINES_BOUND, ("ceiling_test",), ceiling_aggregate(0), ceiling_aggregate(1)),
        Case("baseline-aggregate", C.BASELINE_LINES_BOUND, ("runtime_evidence", "consultations"),
             baseline_aggregate(0), baseline_aggregate(1)),
    ]


def refusal_names(text: str, names: tuple[str, ...], bound: int) -> bool:
    """The text names one of the field's names and the bound's number as a whole number (not a bare 16 inside a row index)."""
    import re

    return any(n in text for n in names) and re.search(rf"(?<![\d.]){bound}(?![\d.])", text) is not None


# --- V-FINAL: a write the database refuses that is not the duplicate ---------------------------------------------------

class SqliteFault(sqlite3.Error):
    """A test's own `sqlite3.Error` subclass, raised where the database refuses a write."""


class StoreFault(StoreError):
    """A test's own `StoreError` subclass, raised where the database refuses a write."""


#: Each write fault that is not `ClosingRecordExists`: `PRAGMA query_only` as the database raises it, and the same
#: refusal re-raised as each test-defined class.
WRITE_FAULTS = {"query-only": sqlite3.OperationalError, "sqlite3-error-subclass": SqliteFault,
                "store-error-subclass": StoreFault}


def _translating(raised: type[BaseException] | None, seen: list[int] | None) -> type[sqlite3.Connection]:
    """A connection class re-raising any `sqlite3.Error` of its statements as `raised` (None: as the database raised it);
    with `seen`, it records the connection's `busy_timeout` as each statement naming the `closing_record` table starts."""

    def run(cursor: sqlite3.Cursor, call: Any, sql: str, *a: Any) -> Any:
        if seen is not None and V.TABLE in sql:
            seen.append(sqlite3.Connection.execute(cursor.connection, "PRAGMA busy_timeout").fetchone()[0])
        try:
            return call(sql, *a)
        except sqlite3.Error as e:
            if raised is None or isinstance(e, raised):
                raise
            raise raised(str(e)) from e

    class Cursor(sqlite3.Cursor):
        def execute(self, sql: str, *a: Any) -> Any:
            return run(self, super().execute, sql, *a)

        def executemany(self, sql: str, *a: Any) -> Any:
            return run(self, super().executemany, sql, *a)

    class Connection(sqlite3.Connection):
        def cursor(self, factory: Any = Cursor) -> Any:
            return super().cursor(factory)

        def execute(self, sql: str, *a: Any) -> Any:
            return self.cursor().execute(sql, *a)

        def executemany(self, sql: str, *a: Any) -> Any:
            return self.cursor().executemany(sql, *a)

    return Connection


@contextlib.contextmanager
def second_handle(store: Any, fault: str | None, *, seen: list[int] | None = None) -> Iterator[Any]:
    """The run's store handle over a second connection to its database, at the store's ordinary busy timeout; with
    `fault`, the database refuses every write on it (`PRAGMA query_only`), raised as `WRITE_FAULTS[fault]`. None: a
    healthy second connection (the control). `seen`: see `_translating`."""
    from defender.records.session_store import STORE_BUSY_TIMEOUT_MS

    conn = sqlite3.connect(str(store.path), timeout=STORE_BUSY_TIMEOUT_MS / 1000, isolation_level=None,
                           factory=_translating(None if fault is None else WRITE_FAULTS[fault], seen))
    try:
        if fault is not None:
            conn.execute("PRAGMA query_only = ON")
        yield replace(store, connection=conn)
    finally:
        conn.close()


def drive_forced_close_over(deps: Any, store: Any, close_store: Any) -> str | None:
    """The driver's own forced close of a run cut short: the driver holds `store`, the close gets `close_store` on MAIN's
    deps (`AgentDeps.session_store`). Returns the exit reason."""
    from defender.investigation import challenge_gate, driver
    from defender.tests.support.invlang.validation._invlang_warn_836 import build_main_agent
    from defender.tests.support.runtime.engine._spec923 import StuckModel

    session = store.new_session(agent_id="main")
    _run, _end, exit_reason = asyncio.run(driver._drive_agent(
        build_main_agent(StuckModel()), "go", V.with_store(deps, close_store), store, session,
        challenge_gate.default_bounds(),
    ))
    return exit_reason

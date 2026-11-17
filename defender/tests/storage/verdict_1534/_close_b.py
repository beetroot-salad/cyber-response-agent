"""Slice b helpers: the real close over a per-test store, and the committed record read back through the lookup (no tests).

`production names that do not exist yet are imported inside functions`, as in `_spec1534`."""
from __future__ import annotations

import contextlib
from collections.abc import Iterator
from pathlib import Path
from typing import Any, NamedTuple

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

"""#1618 K9 (OD22'): a run's knowledge record that is missing where one should exist, or garbled, reads `unreadable`, and
every surface that shows a run's knowledge says so: the run page's banner and the ticket's sentence. A stored `stale`
record still reads back as it was stored (history); a fresh run, and a run from before #1108 P4, show nothing.

Driven over a run folder laid out as `records.RunPaths` lays it out (the host record beside the run folder, the stamp in
it), through the two readers' own entry points (`ticket_writer.stale_sentence`, `visualize_run.render_knowledge_banner`).
"""
from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest

COMMIT = "5e7a11c0ffee5e7a11c0ffee5e7a11c0ffee5e7a"


def _run(tmp_path: Path, *, stamp_names_source: bool, record: str | None) -> Path:
    """A run folder whose stamp does / does not carry a knowledge source, with host record text `record` (None: absent)."""
    from defender.records import RunPaths

    run_dir = tmp_path / "runs" / str(uuid.uuid4())
    run_dir.mkdir(parents=True)
    paths = RunPaths(run_dir)
    stamp = {"commit": "0" * 40, "dirty": False}
    if stamp_names_source:
        stamp["knowledge_source"] = {"kind": "fresh", "commit": COMMIT}
    Path(paths.provenance).write_text(json.dumps(stamp), encoding="utf-8")
    if record is not None:
        Path(paths.knowledge_source()).write_text(record, encoding="utf-8")
    return run_dir


def _shown(run_dir: Path) -> tuple[str | None, str]:
    from defender.investigation import ticket_writer
    from defender.presentation import visualize_run

    return ticket_writer.stale_sentence(run_dir), visualize_run.render_knowledge_banner(run_dir)


#: Records that read `unreadable` (K9): missing where the stamp says one should exist, a truncated record, a record of no
#: known kind.
UNREADABLE = {"missing-where-expected": None, "truncated": '{"kind": "fresh", "commit": ',
              "unknown-kind": json.dumps({"kind": "current", "commit": COMMIT})}


@pytest.mark.parametrize("case", sorted(UNREADABLE))
def test_1618_k9_an_unreadable_knowledge_record_shows_unreadable_on_the_ticket_and_the_run_page(tmp_path, case):
    """The ticket carries the fixed unreadable sentence (naming no commit) and the run page an unreadable banner; neither
    stays silent, and neither calls it fresh. Controls: a fresh record and a pre-P4 run show nothing. (K9, OD22')"""
    from defender.investigation import ticket_writer

    sentence, banner = _shown(_run(tmp_path, stamp_names_source=True, record=UNREADABLE[case]))
    assert sentence == ticket_writer.UNREADABLE_SENTENCE, f"the ticket of a run whose record is {case} says {sentence!r}"
    assert "unreadable" in banner.lower(), f"the run page of a run whose record is {case} shows {banner!r}"
    assert COMMIT not in sentence
    fresh = json.dumps({"kind": "fresh", "commit": COMMIT, "reason": None})
    assert _shown(_run(tmp_path, stamp_names_source=True, record=fresh)) == (None, ""), "control: a fresh run shows nothing"
    assert _shown(_run(tmp_path, stamp_names_source=False, record=None)) == (None, ""), "control: a pre-P4 run shows nothing"


def test_1618_k9_a_stored_stale_record_reads_back_as_it_was_stored(tmp_path):
    """A `stale` record stored before #1618 is history: the ticket still carries that kind's sentence naming the commit
    the run read, and the page its stale banner; it is not turned into `unreadable`. (K9)"""
    from defender.investigation import ticket_writer

    stored = json.dumps({"kind": "stale", "commit": COMMIT, "stale_kind": "transient", "reason": "issuer timed out"})
    sentence, banner = _shown(_run(tmp_path, stamp_names_source=True, record=stored))
    assert sentence is not None, "a stored stale record shows nothing on the ticket"
    assert sentence != ticket_writer.UNREADABLE_SENTENCE, sentence
    assert COMMIT[:7] in sentence, sentence
    assert "stale" in banner.lower(), banner
    assert COMMIT in banner, banner

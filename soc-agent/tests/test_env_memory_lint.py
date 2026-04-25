"""Unit tests for scripts/env_memory_lint.py.

Drives the lint helpers against a synthetic knowledge/environment/ tree and
synthetic runs/ corpus.
"""

from __future__ import annotations

import sys
import textwrap
from datetime import date
from pathlib import Path

import pytest

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))
sys.path.insert(0, str(SOC_AGENT_ROOT / "scripts"))

from scripts import env_memory_lint as lint  # noqa: E402
from scripts.handlers import env_memory  # noqa: E402


def _atoms_section(yaml_body: str) -> str:
    return f"# Header\n\n## Atoms\n\n```yaml\n{yaml_body}\n```\n"


def _write(root: Path, rel: str, body: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body)
    return p


# ---------------------------------------------------------------------------
# _check_schema
# ---------------------------------------------------------------------------


class TestCheckSchema:
    def test_valid_corpus(self, tmp_path: Path):
        body = textwrap.dedent("""\
            - id: a1
              body: x
              anchors: {mechanic: [process-exec]}
              valid: {from: 2026-01-01, to: 2027-01-01}
        """).strip()
        _write(tmp_path, "knowledge/environment/fleet/d/x.md", _atoms_section(body))
        atoms, errors = lint._check_schema(tmp_path)
        assert errors == []
        assert len(atoms) == 1

    def test_collects_errors_across_files(self, tmp_path: Path):
        bad_a = "- id: a1\n  body: x\n  anchors: {mechanic: [process-exec]}"  # missing valid
        bad_b = "- id: b1\n  anchors: {}\n  valid: {from: 2026-01-01, to: 2027-01-01}"  # missing body
        _write(tmp_path, "knowledge/environment/fleet/a.md", _atoms_section(bad_a))
        _write(tmp_path, "knowledge/environment/systems/b.md", _atoms_section(bad_b))
        atoms, errors = lint._check_schema(tmp_path)
        assert atoms == []
        assert len(errors) == 2
        assert all(e.startswith("SCHEMA:") for e in errors)


# ---------------------------------------------------------------------------
# _check_references
# ---------------------------------------------------------------------------


class TestCheckReferences:
    def _make_atom(self, mechs: list[str] | None = None, sigs: list[str] | None = None) -> env_memory.Atom:
        anchors = {}
        if mechs is not None:
            anchors["mechanic"] = tuple(mechs)
        if sigs is not None:
            anchors["signature_id"] = tuple(sigs)
        return env_memory.Atom(
            id="x",
            body="b",
            anchors=anchors,
            valid_from=date(2026, 1, 1),
            valid_to=date(2027, 1, 1),
            status="live",
            source_file=Path("/x"),
        )

    def test_unknown_mechanic_blocks(self):
        atoms = [self._make_atom(mechs=["bogus-mechanic"])]
        blocking, _ = lint._check_references(atoms)
        assert any("not in MECHANIC_VOCAB" in b for b in blocking)

    def test_short_signature_blocks(self):
        atoms = [self._make_atom(sigs=["123"])]
        blocking, _ = lint._check_references(atoms)
        assert any("≥4 contiguous digits" in b for b in blocking)

    def test_long_signature_passes(self):
        atoms = [self._make_atom(sigs=["100001"])]
        blocking, _ = lint._check_references(atoms)
        assert blocking == []


# ---------------------------------------------------------------------------
# _check_freshness
# ---------------------------------------------------------------------------


class TestCheckFreshness:
    def _atom(self, **kw):
        defaults = dict(
            id="a", body="b", anchors={}, valid_from=date(2026, 1, 1),
            valid_to=date(2027, 1, 1), status="live", source_file=Path("/x"),
        )
        defaults.update(kw)
        return env_memory.Atom(**defaults)

    def test_window_expired_warning(self):
        a = self._atom(valid_to=date(2025, 1, 1))
        warns = lint._check_freshness([a], today=date(2026, 6, 1))
        assert any("WINDOW-EXPIRED" in w for w in warns)

    def test_no_warning_inside_window(self):
        a = self._atom()
        warns = lint._check_freshness([a], today=date(2026, 6, 1))
        # No window-expired; default-window may or may not flag (default is fine)
        assert not any("WINDOW-EXPIRED" in w for w in warns)

    def test_default_window_overage_warning(self):
        # 5y window for what infers as mechanism-context (default 365d) → flag.
        a = self._atom(
            anchors={"mechanic": ("process-exec",)},
            valid_from=date(2026, 1, 1),
            valid_to=date(2031, 1, 1),
        )
        warns = lint._check_freshness([a], today=date(2026, 6, 1))
        assert any("DEFAULT-WINDOW" in w for w in warns)

    def test_non_live_skipped(self):
        a = self._atom(status="tombstoned", valid_to=date(2024, 1, 1))
        warns = lint._check_freshness([a], today=date(2026, 6, 1))
        assert not any("WINDOW-EXPIRED" in w for w in warns)


# ---------------------------------------------------------------------------
# _check_conflict_candidates
# ---------------------------------------------------------------------------


class TestCheckConflict:
    def _atom(self, aid: str, mechs=(), classes=(), sigs=()):
        return env_memory.Atom(
            id=aid, body="b",
            anchors={
                "mechanic": tuple(mechs),
                "vertex_classification": tuple(classes),
                "signature_id": tuple(sigs),
            },
            valid_from=date(2026, 1, 1),
            valid_to=date(2027, 1, 1),
            status="live",
            source_file=Path("/x"),
        )

    def test_overlapping_scope_flagged(self):
        atoms = [
            self._atom("a1", mechs=["process-exec"], classes=["host-x"]),
            self._atom("a2", mechs=["process-exec"], classes=["host-x"]),
        ]
        warns = lint._check_conflict_candidates(atoms)
        assert any("CONFLICT-CANDIDATE" in w for w in warns)
        assert any("a1" in w and "a2" in w for w in warns)

    def test_distinct_scope_not_flagged(self):
        atoms = [
            self._atom("a1", mechs=["process-exec"], classes=["host-x"]),
            self._atom("a2", mechs=["network-connect"], classes=["host-x"]),
        ]
        warns = lint._check_conflict_candidates(atoms)
        assert not any("CONFLICT-CANDIDATE" in w for w in warns)


# ---------------------------------------------------------------------------
# _check_triple_coverage
# ---------------------------------------------------------------------------


class TestCheckTripleCoverage:
    def test_uncovered_triple_warning(self, tmp_path: Path):
        runs = tmp_path / "runs"
        run_dir = runs / "run-1"
        run_dir.mkdir(parents=True)
        inv = textwrap.dedent("""\
            ```yaml
            prologue:
              vertices:
                - id: v-001
                  type: novel-type
                  classification: foo
                  identifier: x
              edges: []
            ```

            ```yaml
            hypothesize:
              hypotheses:
                - id: h-001
                  attached_to_vertex: v-001
                  proposed_edge:
                    relation: novel-relation
                    parent_vertex: {type: novel-parent, classification: bar}
                  weight: null
            ```
        """)
        (run_dir / "investigation.md").write_text(inv)
        warns = lint._check_triple_coverage(tmp_path, runs)
        assert any("TRIPLE-COVERAGE" in w for w in warns)
        assert any("novel-parent" in w and "novel-relation" in w and "novel-type" in w for w in warns)

    def test_known_triple_no_warning(self, tmp_path: Path):
        runs = tmp_path / "runs"
        run_dir = runs / "run-1"
        run_dir.mkdir(parents=True)
        inv = textwrap.dedent("""\
            ```yaml
            prologue:
              vertices:
                - id: v-001
                  type: process
                  classification: shell
                  identifier: p1
              edges: []
            ```

            ```yaml
            hypothesize:
              hypotheses:
                - id: h-001
                  attached_to_vertex: v-001
                  proposed_edge:
                    relation: spawned
                    parent_vertex: {type: process, classification: cron}
                  weight: null
            ```
        """)
        (run_dir / "investigation.md").write_text(inv)
        warns = lint._check_triple_coverage(tmp_path, runs)
        assert warns == []

    def test_missing_runs_dir_returns_empty(self, tmp_path: Path):
        assert lint._check_triple_coverage(tmp_path, tmp_path / "nonexistent") == []

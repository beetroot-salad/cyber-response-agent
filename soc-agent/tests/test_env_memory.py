"""Unit tests for scripts/handlers/env_memory.py.

Covers:
  - parse_atoms_from_file: schema parsing happy + each error permutation
  - derive_mechanics_for_edge: hits, misses, ambiguous returns
  - extract_anchors: prologue + findings + hypothesis-derived mechanic
  - retrieve: scoring, top-K, stale / pre_window flagging, status filter
  - format_env_memory_block: empty + populated rendering
  - loop-N: mechanic surfaces only when a triple-matching hypothesis is active
"""

from __future__ import annotations

import sys
import textwrap
from dataclasses import dataclass
from datetime import date
from pathlib import Path

import pytest

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from scripts.handlers.env_memory import (  # noqa: E402
    Atom,
    AtomParseError,
    derive_mechanics_for_edge,
    extract_anchors,
    format_env_memory_block,
    parse_atoms_from_file,
    retrieve,
)
from tests._dense_fixture_helpers import companion_to_invlang_fence  # noqa: E402


# ---------------------------------------------------------------------------
# Synthetic Context (subset of scripts.orchestrate.Context fields the
# env_memory module reads — keeps the tests independent of that module).
# ---------------------------------------------------------------------------


@dataclass
class FakeCtx:
    run_dir: Path
    signature_id: str = "wazuh-rule-100001"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_atom_file(path: Path, body: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body)
    return path


def _atoms_section(yaml_body: str) -> str:
    return f"# Header\n\nFreeform prose.\n\n## Atoms\n\n```yaml\n{yaml_body}\n```\n"


VALID_ATOM_YAML = textwrap.dedent("""\
    - id: a1
      body: |
        body line 1
        body line 2
      anchors:
        mechanic: [process-exec]
        vertex_classification: [host-with-wazuh-indexer-jdk]
      valid: {from: 2026-01-01, to: 2027-01-01}
      status: live
""").strip()


# ---------------------------------------------------------------------------
# parse_atoms_from_file
# ---------------------------------------------------------------------------


class TestParseAtoms:
    def test_happy_path(self, tmp_path: Path):
        f = _write_atom_file(tmp_path / "f.md", _atoms_section(VALID_ATOM_YAML))
        atoms = parse_atoms_from_file(f)
        assert len(atoms) == 1
        atom = atoms[0]
        assert atom.id == "a1"
        assert "body line 1" in atom.body
        assert atom.anchors["mechanic"] == ("process-exec",)
        assert atom.valid_from == date(2026, 1, 1)
        assert atom.valid_to == date(2027, 1, 1)
        assert atom.status == "live"
        assert atom.source_file == f

    def test_no_atoms_section(self, tmp_path: Path):
        f = _write_atom_file(tmp_path / "f.md", "# Just prose\nno atoms here\n")
        assert parse_atoms_from_file(f) == []

    def test_empty_atoms_block(self, tmp_path: Path):
        f = _write_atom_file(tmp_path / "f.md", "## Atoms\n\n```yaml\n```\n")
        assert parse_atoms_from_file(f) == []

    def test_atoms_must_be_list(self, tmp_path: Path):
        f = _write_atom_file(tmp_path / "f.md", "## Atoms\n\n```yaml\nfoo: bar\n```\n")
        with pytest.raises(AtomParseError, match="must be a YAML list"):
            parse_atoms_from_file(f)

    def test_missing_id(self, tmp_path: Path):
        body = "- body: x\n  anchors: {mechanic: [process-exec]}\n  valid: {from: 2026-01-01, to: 2027-01-01}"
        f = _write_atom_file(tmp_path / "f.md", _atoms_section(body))
        with pytest.raises(AtomParseError, match="missing non-empty `id`"):
            parse_atoms_from_file(f)

    def test_missing_body(self, tmp_path: Path):
        body = "- id: a1\n  anchors: {mechanic: [process-exec]}\n  valid: {from: 2026-01-01, to: 2027-01-01}"
        f = _write_atom_file(tmp_path / "f.md", _atoms_section(body))
        with pytest.raises(AtomParseError, match="missing non-empty `body`"):
            parse_atoms_from_file(f)

    def test_unknown_anchor_key(self, tmp_path: Path):
        body = "- id: a1\n  body: x\n  anchors: {nonsense: [foo]}\n  valid: {from: 2026-01-01, to: 2027-01-01}"
        f = _write_atom_file(tmp_path / "f.md", _atoms_section(body))
        with pytest.raises(AtomParseError, match="unknown anchor key"):
            parse_atoms_from_file(f)

    def test_anchor_not_list(self, tmp_path: Path):
        body = "- id: a1\n  body: x\n  anchors: {mechanic: process-exec}\n  valid: {from: 2026-01-01, to: 2027-01-01}"
        f = _write_atom_file(tmp_path / "f.md", _atoms_section(body))
        with pytest.raises(AtomParseError, match="must be a list"):
            parse_atoms_from_file(f)

    def test_missing_valid(self, tmp_path: Path):
        body = "- id: a1\n  body: x\n  anchors: {mechanic: [process-exec]}"
        f = _write_atom_file(tmp_path / "f.md", _atoms_section(body))
        with pytest.raises(AtomParseError, match="missing `valid"):
            parse_atoms_from_file(f)

    def test_invalid_date_order(self, tmp_path: Path):
        body = "- id: a1\n  body: x\n  anchors: {}\n  valid: {from: 2027-01-01, to: 2026-01-01}"
        f = _write_atom_file(tmp_path / "f.md", _atoms_section(body))
        with pytest.raises(AtomParseError, match="valid.from > valid.to"):
            parse_atoms_from_file(f)

    def test_bad_status(self, tmp_path: Path):
        body = "- id: a1\n  body: x\n  anchors: {}\n  valid: {from: 2026-01-01, to: 2027-01-01}\n  status: garbage"
        f = _write_atom_file(tmp_path / "f.md", _atoms_section(body))
        with pytest.raises(AtomParseError, match="status must be"):
            parse_atoms_from_file(f)

    def test_category_inference(self, tmp_path: Path):
        # Mechanism-context: has mechanic
        f = _write_atom_file(tmp_path / "m.md", _atoms_section(VALID_ATOM_YAML))
        assert parse_atoms_from_file(f)[0].category() == "mechanism-context"
        # Entity-status: classification only, no mechanic, no source
        body = "- id: e1\n  body: x\n  anchors: {vertex_classification: [vip-user]}\n  valid: {from: 2026-01-01, to: 2026-04-01}"
        f = _write_atom_file(tmp_path / "e.md", _atoms_section(body))
        assert parse_atoms_from_file(f)[0].category() == "entity-status"
        # Source-quirk: data_source/signature only
        body = "- id: s1\n  body: x\n  anchors: {data_source: [wazuh]}\n  valid: {from: 2026-01-01, to: 2027-01-01}"
        f = _write_atom_file(tmp_path / "s.md", _atoms_section(body))
        assert parse_atoms_from_file(f)[0].category() == "source-quirk"


# ---------------------------------------------------------------------------
# derive_mechanics_for_edge
# ---------------------------------------------------------------------------


class TestDeriveMechanics:
    def test_known_triple_single_mechanic(self):
        assert derive_mechanics_for_edge("process", "spawned", "process") == frozenset({"process-exec"})

    def test_ambiguous_triple_returns_set(self):
        result = derive_mechanics_for_edge("process", "wrote", "file")
        assert "file-write" in result
        assert "data-transfer" in result

    def test_unknown_triple_returns_empty(self):
        assert derive_mechanics_for_edge("foo", "bar", "baz") == frozenset()

    def test_none_returns_empty(self):
        assert derive_mechanics_for_edge(None, "spawned", "process") == frozenset()
        assert derive_mechanics_for_edge("process", None, "process") == frozenset()
        assert derive_mechanics_for_edge("process", "spawned", None) == frozenset()


# ---------------------------------------------------------------------------
# extract_anchors
# ---------------------------------------------------------------------------


class TestExtractAnchors:
    def test_signature_only_when_no_investigation(self, tmp_path: Path):
        ctx = FakeCtx(run_dir=tmp_path, signature_id="wazuh-rule-100001")
        a = extract_anchors(ctx)
        # Both the full string and the embedded digit-run land — atoms can
        # anchor on either form (vendor-specific or vendor-neutral).
        assert a["signature_id"] == {"wazuh-rule-100001", "100001"}
        assert a["mechanic"] == set()

    def test_signature_no_digit_run_only_keeps_full_string(self, tmp_path: Path):
        ctx = FakeCtx(run_dir=tmp_path, signature_id="custom-no-digits")
        a = extract_anchors(ctx)
        assert a["signature_id"] == {"custom-no-digits"}

    def test_pulls_prologue_vertices(self, tmp_path: Path):
        fence = companion_to_invlang_fence({
            "prologue": {
                "vertices": [
                    {"id": "v-001", "type": "endpoint",
                     "classification": "host-with-wazuh-indexer-jdk",
                     "identifier": "tgt-01"},
                    {"id": "v-002", "type": "process",
                     "classification": "shell-process",
                     "identifier": "bash-pid-1234"},
                ],
                "edges": [],
            },
        })
        (tmp_path / "investigation.md").write_text(
            "## CONTEXTUALIZE\n\n" + fence + "\n"
        )
        ctx = FakeCtx(run_dir=tmp_path)
        a = extract_anchors(ctx)
        assert "host-with-wazuh-indexer-jdk" in a["vertex_classification"]
        assert "shell-process" in a["vertex_classification"]
        assert "tgt-01" in a["vertex_identifier"]
        assert "bash-pid-1234" in a["vertex_identifier"]

    def test_derives_mechanic_from_hypothesis_triple(self, tmp_path: Path):
        inv = (
            "## CONTEXTUALIZE\n\n"
            + companion_to_invlang_fence({
                "prologue": {
                    "vertices": [{
                        "id": "v-001", "type": "process",
                        "classification": "shell-process",
                        "identifier": "bash-1",
                    }],
                    "edges": [],
                },
            })
            + "\n\n## PREDICT (loop 1)\n\n"
            + companion_to_invlang_fence({
                "hypothesize": {"hypotheses": [{
                    "id": "h-001", "name": "?spawned-by-cron",
                    "attached_to_vertex": "v-001",
                    "proposed_edge": {
                        "relation": "spawned",
                        "parent_vertex": {
                            "type": "process",
                            "classification": "cron-daemon",
                        },
                    },
                }]},
            })
            + "\n"
        )
        (tmp_path / "investigation.md").write_text(inv)
        ctx = FakeCtx(run_dir=tmp_path)
        a = extract_anchors(ctx)
        assert "process-exec" in a["mechanic"]
        # Proposed parent classification surfaces as a candidate anchor.
        assert "cron-daemon" in a["vertex_classification"]

    def test_skips_shelved_hypotheses(self, tmp_path: Path):
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
                    parent_vertex: {type: process, classification: cron-daemon}
                  weight: null
                  status: refuted
              shelved: []
            ```
        """)
        (tmp_path / "investigation.md").write_text(inv)
        ctx = FakeCtx(run_dir=tmp_path)
        a = extract_anchors(ctx)
        assert a["mechanic"] == set()


# ---------------------------------------------------------------------------
# retrieve
# ---------------------------------------------------------------------------


class TestRetrieve:
    def _setup_corpus(self, root: Path) -> None:
        """Build a synthetic knowledge/environment/ tree with a few atoms."""
        envdir = root / "knowledge" / "environment" / "fleet" / "demo"
        # mechanism-context atom — should match a process-exec hypothesis
        atoms = textwrap.dedent("""\
            - id: pe-baseline
              body: |
                process-exec baseline atom
              anchors:
                mechanic: [process-exec]
                vertex_classification: [host-with-wazuh-indexer-jdk]
              valid: {from: 2026-01-01, to: 2027-01-01}

            - id: net-baseline
              body: |
                network-connect baseline atom
              anchors:
                mechanic: [network-connect]
                vertex_classification: [host-with-wazuh-indexer-jdk]
              valid: {from: 2026-01-01, to: 2027-01-01}

            - id: stale-atom
              body: |
                expired atom
              anchors:
                mechanic: [process-exec]
                vertex_classification: [host-with-wazuh-indexer-jdk]
              valid: {from: 2024-01-01, to: 2024-06-01}

            - id: tombstoned-atom
              body: |
                tombstoned atom — should never retrieve
              anchors:
                mechanic: [process-exec]
                vertex_classification: [host-with-wazuh-indexer-jdk]
              valid: {from: 2026-01-01, to: 2027-01-01}
              status: tombstoned
        """).strip()
        _write_atom_file(envdir / "co-fire.md", _atoms_section(atoms))

    def _build_ctx_with_hypothesis(self, run_dir: Path, *, with_process_exec: bool) -> FakeCtx:
        run_dir.mkdir(parents=True, exist_ok=True)
        if with_process_exec:
            # Hypothesis whose triple maps to process-exec
            companion = {
                "prologue": {
                    "vertices": [{
                        "id": "v-001", "type": "process",
                        "classification": "host-with-wazuh-indexer-jdk",
                        "identifier": "p1",
                    }],
                    "edges": [],
                },
                "hypothesize": {"hypotheses": [{
                    "id": "h-001", "name": "?spawned-by-cron",
                    "attached_to_vertex": "v-001",
                    "proposed_edge": {
                        "relation": "spawned",
                        "parent_vertex": {
                            "type": "process",
                            "classification": "cron-daemon",
                        },
                    },
                }]},
            }
        else:
            # Loop-1 case: prologue only, no hypothesis yet
            companion = {
                "prologue": {
                    "vertices": [{
                        "id": "v-001", "type": "endpoint",
                        "classification": "host-with-wazuh-indexer-jdk",
                        "identifier": "ep1",
                    }],
                    "edges": [],
                },
            }
        (run_dir / "investigation.md").write_text(companion_to_invlang_fence(companion) + "\n")
        return FakeCtx(run_dir=run_dir)

    def test_returns_matched_atom_with_flags(self, tmp_path: Path):
        self._setup_corpus(tmp_path)
        ctx = self._build_ctx_with_hypothesis(tmp_path / "run", with_process_exec=True)
        # Pin "today" inside the live window so non-stale atoms surface clean.
        results = retrieve(tmp_path, ctx, today=date(2026, 6, 1))
        ids = [a.id for a, _ in results]
        # process-exec atom matches mechanic + classification → highest score
        assert "pe-baseline" in ids
        # net-baseline matches classification only → still surfaces (lower)
        assert "net-baseline" in ids
        # tombstoned filtered
        assert "tombstoned-atom" not in ids
        # stale-atom is `live` status with valid_to in the past — should still
        # surface with stale=True
        for atom, flags in results:
            if atom.id == "stale-atom":
                assert flags["stale"] is True
            else:
                assert flags["stale"] is False
            assert flags["pre_window"] is False

    def test_pre_window_flag(self, tmp_path: Path):
        self._setup_corpus(tmp_path)
        ctx = self._build_ctx_with_hypothesis(tmp_path / "run", with_process_exec=True)
        # Pin "today" before the live window's start
        results = retrieve(tmp_path, ctx, today=date(2025, 6, 1))
        for atom, flags in results:
            if atom.id in ("pe-baseline", "net-baseline", "tombstoned-atom") and atom.id != "tombstoned-atom":
                assert flags["pre_window"] is True

    def test_top_k_truncation(self, tmp_path: Path):
        self._setup_corpus(tmp_path)
        ctx = self._build_ctx_with_hypothesis(tmp_path / "run", with_process_exec=True)
        results = retrieve(tmp_path, ctx, k=1, today=date(2026, 6, 1))
        assert len(results) == 1
        # mechanic+classification scores higher than classification alone → pe wins
        assert results[0][0].id == "pe-baseline"

    def test_loop_n_emergence(self, tmp_path: Path):
        """Loop 1: no hypothesis, mechanic anchor empty → mechanic-only atoms
        do NOT surface. Loop 2 with process-exec hypothesis → they do."""
        self._setup_corpus(tmp_path)
        # Loop 1 — only classification anchor. mechanic-keyed atoms STILL
        # match because classification alone scores > 0. To test true
        # mechanic-emergence, write an atom that's mechanic-only.
        envdir = tmp_path / "knowledge" / "environment" / "fleet" / "mech-only"
        mech_only = textwrap.dedent("""\
            - id: mech-only-atom
              body: |
                only the mechanic anchor — should not match without hypothesis
              anchors:
                mechanic: [process-exec]
              valid: {from: 2026-01-01, to: 2027-01-01}
        """).strip()
        _write_atom_file(envdir / "x.md", _atoms_section(mech_only))

        loop1_ctx = self._build_ctx_with_hypothesis(tmp_path / "run1", with_process_exec=False)
        loop2_ctx = self._build_ctx_with_hypothesis(tmp_path / "run2", with_process_exec=True)

        loop1_ids = {a.id for a, _ in retrieve(tmp_path, loop1_ctx, today=date(2026, 6, 1))}
        loop2_ids = {a.id for a, _ in retrieve(tmp_path, loop2_ctx, today=date(2026, 6, 1))}
        assert "mech-only-atom" not in loop1_ids
        assert "mech-only-atom" in loop2_ids

    def test_no_matches_returns_empty(self, tmp_path: Path):
        # No knowledge dir at all
        ctx = FakeCtx(run_dir=tmp_path / "run", signature_id="sig-x")
        (tmp_path / "run").mkdir()
        assert retrieve(tmp_path, ctx) == []

    def test_malformed_file_isolated_from_corpus(self, tmp_path: Path, capsys):
        """A single malformed atom file is skipped (with stderr note) so the
        rest of the corpus still surfaces. Retrieval must not collapse to
        empty just because one file is broken."""
        self._setup_corpus(tmp_path)
        # Drop a broken atom file alongside the good ones.
        bad = "## Atoms\n\n```yaml\n- id: bad\n  anchors: {nonsense: [foo]}\n  valid: {from: 2026-01-01, to: 2027-01-01}\n```\n"
        _write_atom_file(tmp_path / "knowledge" / "environment" / "fleet" / "broken" / "x.md", bad)
        ctx = self._build_ctx_with_hypothesis(tmp_path / "run", with_process_exec=True)
        results = retrieve(tmp_path, ctx, today=date(2026, 6, 1))
        ids = [a.id for a, _ in results]
        # Good atoms still surface
        assert "pe-baseline" in ids
        captured = capsys.readouterr()
        assert "skipping malformed atom file" in captured.err


# ---------------------------------------------------------------------------
# format_env_memory_block
# ---------------------------------------------------------------------------


class TestFormatBlock:
    def test_empty_returns_empty_string(self):
        assert format_env_memory_block([]) == ""

    def test_renders_atoms_with_flags(self):
        atom = Atom(
            id="a1",
            body="hello world",
            anchors={"mechanic": ("process-exec",)},
            valid_from=date(2026, 1, 1),
            valid_to=date(2027, 1, 1),
            status="live",
            source_file=Path("/x"),
        )
        out = format_env_memory_block([(atom, {"stale": False, "pre_window": False})])
        assert "## Environment memory" in out
        assert 'atom_id="a1"' in out
        assert 'stale="false"' in out
        assert 'pre_window="false"' in out
        assert "hello world" in out

    def test_stale_true_renders(self):
        atom = Atom(
            id="a1", body="x", anchors={}, valid_from=date(2024, 1, 1),
            valid_to=date(2024, 6, 1), status="live", source_file=Path("/x"),
        )
        out = format_env_memory_block([(atom, {"stale": True, "pre_window": False})])
        assert 'stale="true"' in out

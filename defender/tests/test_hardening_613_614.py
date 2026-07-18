"""Executable spec for #613 + #614 — the two seams the #596/#609 review extracted.

#613: ``defender._yaml.safe_load`` is the one place ``RecursionError`` (PyYAML's
bare-exception response to a nesting flood) folds into ``yaml.YAMLError``, so every
call site's existing degrade posture — dead-letter, skip, warn, typed re-raise —
covers the whole malformed class. These tests pin the seam itself and the postures
of the sites the #609 pass left exposed (oracle reply, ground-truth reads, the
held-out walks, the visualize shim).

#614: ``defender._tsv.flatten_cell`` is the one breaker set for a value that must
stay inside one cell of a ``splitlines()``-parsed TSV. These tests pin the set
against ``str.splitlines`` itself (executable derivation, not a hand-copied list)
and pin the three sibling emitters that previously used the 2-char replace.

The demand list lives in ``spec_graph_613_614.yaml`` beside this file.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
import yaml

from defender._tsv import _BREAKERS, flatten_cell
from defender._yaml import safe_load
from defender.evals.held_out import load_held_out_fixtures
from defender.learning.core.config import RunUnprocessable
from defender.learning.pipeline.oracle.sample import parse_lead_events
from defender.scripts.visualize.visualize_primitives import load_yaml

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts" / "lessons"

_FLOW_FLOOD = "a: " + "[" * 3000
_BLOCK_FLOOD = "\n".join(" " * i + f"k{i}:" for i in range(3000))

# The same hostile scalar as test_hardening_596_609: every splitlines breaker + tab.
_HOSTILE_VALUE = '"a\\tb\\nc\\rd\\x0Be\\x0Cf\\x85g\\u2028h\\u2029i"'
_HOSTILE_FLAT = "a b c d e f g h i"


def _load_script(stem: str):
    # Distinct module names so these loads can't clobber the sibling test files'
    # loads of the same scripts in sys.modules within one pytest session.
    spec = importlib.util.spec_from_file_location(f"{stem}_614", SCRIPTS / f"{stem}.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# #613 — the seam (demands s1–s2)
# ---------------------------------------------------------------------------


def test_d_s1_seam_folds_flood_into_yamlerror_and_recovers():
    """d: s1 — flow AND block floods surface as ``yaml.YAMLError`` (never a bare
    ``RecursionError``), the message stays bounded (it lands in warns and
    dead-letters), and a healthy doc still parses in the same process after."""
    for flood in (_FLOW_FLOOD, _BLOCK_FLOOD):
        with pytest.raises(yaml.YAMLError) as ei:
            safe_load(flood)
        assert len(str(ei.value)) < 500
    assert safe_load("name: ok") == {"name": "ok"}


def test_d_s2_healthy_yaml_is_untouched():
    """d: s2 (control) — the seam is a drop-in: values, types, and None-on-empty
    behave exactly like ``yaml.safe_load``."""
    assert safe_load("a: [1, 2]") == {"a": [1, 2]}
    assert safe_load("") is None


# ---------------------------------------------------------------------------
# #613 — the previously exposed call sites (demands s3–s7)
# ---------------------------------------------------------------------------


def test_d_s3_oracle_flood_reply_is_run_unprocessable():
    """d: s3 — a flooded LLM oracle reply raises the typed, debuggable
    ``RunUnprocessable`` the docstring promises, not a bare ``RecursionError``."""
    with pytest.raises(RunUnprocessable):
        parse_lead_events(_FLOW_FLOOD, "lead1")


# d: s4 — DELETED. Its subject, `orchestrate.read_ground_truth`, no longer exists: the
# learning loop does not read eval-fixture YAML at all, so a flooded ground_truth.yaml
# cannot reach — let alone dead-letter — a learning run. The failure mode is removed
# rather than handled.
#
# d: s5 — FOLDED INTO s6. It pinned walk-survival on `evals/held_out.held_out_runs`, a
# scan of run dirs for copied-in labels. The eval now walks FIXTURES via
# `load_held_out_fixtures` — which is exactly s6's subject — so the two demands have one
# subject and one test.


def test_d_s6_fixture_walk_survives_flood_ground_truth(tmp_path, capsys):
    """d: s6 (absorbing s5) — walk-survival at the ONE fixture loader both metrics now
    share: the flooded fixture is skipped with a warn, the healthy one loads."""
    good = tmp_path / "good"
    good.mkdir()
    (good / "alert.json").write_text("{}", encoding="utf-8")
    (good / "ground_truth.yaml").write_text("held_out: true\n", encoding="utf-8")
    bad = tmp_path / "bad"
    bad.mkdir()
    (bad / "alert.json").write_text("{}", encoding="utf-8")
    (bad / "ground_truth.yaml").write_text(_FLOW_FLOOD, encoding="utf-8")

    fixtures = load_held_out_fixtures(tmp_path)
    assert [f.slug for f in fixtures] == ["good"]
    err = capsys.readouterr().err
    assert "bad" in err
    assert "ground_truth" in err


def test_d_s7_visualize_load_yaml_flood_degrades_to_none(tmp_path):
    """d: s7 — the renderer shim treats a flooded run YAML like any malformed one:
    ``None``, not a crash of the whole visualization."""
    p = tmp_path / "doc.yaml"
    p.write_text(_FLOW_FLOOD, encoding="utf-8")
    assert load_yaml(p) is None


# ---------------------------------------------------------------------------
# #614 — the breaker set and the sibling emitters (demands t1–t2)
# ---------------------------------------------------------------------------


def test_d_t1_breaker_set_is_exactly_splitlines_plus_tab():
    """d: t1 — the set is DERIVED, not asserted: every codepoint ``str.splitlines``
    treats as a boundary, plus tab, and nothing else. A Python version that widens
    splitlines fails this test instead of silently reopening the forgery."""
    boundaries = {
        cp for cp in range(0x110000) if len(f"a{chr(cp)}b".splitlines()) > 1
    }
    assert set(_BREAKERS) == boundaries | {ord("\t")}
    for cp in sorted(boundaries | {ord("\t")}):
        assert flatten_cell(f"a{chr(cp)}b") == "a b"
    assert flatten_cell("plain text — untouched") == "plain text — untouched"


@pytest.mark.parametrize(
    ("stem", "fm", "argv"),
    [
        ("lessons_fm",
         f"name: L\ndescription: {_HOSTILE_VALUE}",
         ["prog"]),
        ("lessons_env_retrieve",
         f"subject: s\nrelevance_criteria: {_HOSTILE_VALUE}",
         None),  # --corpus is an arg, filled in below
        ("lessons_actor_index",
         f"subject: s\nrelevance_criteria: {_HOSTILE_VALUE}",
         ["prog"]),
    ],
)
def test_d_t2_sibling_emitters_flatten_every_breaker(tmp_path, capsys, stem, fm, argv):
    """d: t2 — the three sibling TSV emitters (previously on the 2-char replace)
    hold the same property as trace_lesson: a hostile LLM-authored value forges
    no extra row and no extra column."""
    corpus = tmp_path / "lessons"
    corpus.mkdir()
    (corpus / "L.md").write_text(f"---\n{fm}\n---\nbody\n", encoding="utf-8")

    mod = _load_script(stem)
    if stem == "lessons_fm":
        mod.LESSONS_DIR = corpus
    elif stem == "lessons_actor_index":
        mod.LESSONS_ROOT = corpus
    else:
        argv = ["prog", "--corpus", str(corpus)]
    assert mod.main(argv) == 0

    out = capsys.readouterr().out
    [row] = out.splitlines()
    assert row.count("\t") == 1
    assert row.split("\t")[1] == _HOSTILE_FLAT

"""Issue #719, part 4/5 — the fold itself: one drain body (O3), no private cross-module
reach (O4), unchanged per-direction gating (O5), and the written record the change has to
rewrite (D6, A4, F1, F2).

Executable spec, pre-implementation. O3's oracle is deliberately STRENGTHENED past the lint:
`lint_duplicate_helpers` keys on the bare name, so a rename alone satisfies it (the lint's own
limitation note). Passing the lint is necessary, not sufficient — the direction modules must
also carry no batch-driver body, which is what makes the rename justified rather than merely
performed.
"""
from __future__ import annotations

import ast
import json
import re
import subprocess
from pathlib import Path


from defender.learning.author import curator  # type: ignore[import-not-found]
from defender.learning.author import shared as author_shared  # type: ignore[import-not-found]
from defender.learning.author.lessons import run as lessons_run  # type: ignore[import-not-found]

#: The five names the curator/lessons pair owns exclusively in the duplicate-helper baseline.
PAIR_EXCLUSIVE = (
    "_author_to_author",
    "_partition_pre_author",
    "_run_batch_inner",
    "read_batch",
    "rotate_queue",
)

#: The six delegators D6 deletes from `curator.py`.
DELEGATORS = (
    "git_head_sha",
    "changes_outside_corpus",
    "commit_corpus",
    "corpus_dir_clean",
    "_result_list",
    "_commit_message",
)


def repo_root() -> Path:
    import defender  # type: ignore[import-not-found]

    # `defender` is a PEP-420 NAMESPACE package (deliberately: no top-level
    # `__init__.py`), so `__file__` is None and `Path(...)` on it raises. `__path__[0]`
    # is the same directory this helper meant to name.
    return Path(defender.__path__[0]).resolve().parent


def tracked_files() -> list[Path]:
    root = repo_root()
    out = subprocess.run(
        ["git", "-C", str(root), "ls-files"], capture_output=True, text=True, check=True
    ).stdout.splitlines()
    return [root / p for p in out if p.strip()]


def drain_modules() -> dict[str, Path]:
    import defender.learning.author.curator as _c  # type: ignore[import-not-found]

    author_dir = Path(_c.__file__).resolve().parent
    return {
        "curator.py": author_dir / "curator.py",
        "lessons/run.py": author_dir / "lessons" / "run.py",
        "drain.py": author_dir / "drain.py",
        "malicious_actor/run.py": author_dir / "malicious_actor" / "run.py",
        "benign_actor/run.py": author_dir / "benign_actor" / "run.py",
    }


def module_level_defs(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return {
        n.name for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


# O3 — one drain body


def test_duplicate_helper_baseline_drops_the_five_pair_exclusive_names(tmp_path: Path):
    """O3's necessary half. The five names the curator/lessons pair owns exclusively leave the
    duplicate-helper baseline, taking it from 18 entries to 13 (C17/G14/C30). Four go because
    the shared drain body deletes them; `_partition_pre_author` goes only under the
    direction-specific rename A3 resolved, and without that rename the arithmetic is 14.

    The lint itself must also report no NEW finding, so the fold cannot buy the shrink by
    introducing a fresh duplicate name in the shared module."""
    root = repo_root()
    baseline = json.loads((root / "scripts" / "lint" / "lint_duplicate_helpers_baseline.json")
                          .read_text(encoding="utf-8"))
    entries = baseline["entries"]
    assert [n for n in PAIR_EXCLUSIVE if n in entries] == []
    # #774 added one further accepted entry (`render_report`: close_tool.py's report.md
    # renderer collided in NAME ONLY with evals/judge_equivalence.py's), which took the
    # arithmetic to 14. Retiring the judge A/B harness removed the other half of that
    # collision, so `render_report` is no longer a duplicate name at all and the entry left
    # the baseline — back to the 13 this demand's own fold arrived at. #808's harness-executed
    # lead-0 step then added `_render_section` (lead_zero.py's untrusted-frame wrapper collides
    # in NAME ONLY with invlang/advisory.py's AdvisorySection renderer), taking it to 14 again,
    # and `_rows_for` (lead_zero.py's own executed_queries.jsonl reader collides in NAME ONLY
    # with #832's payload_view.py in-memory reducer helper, merged into main concurrently),
    # taking it to 15.
    assert len(entries) == 15, f"baseline is {len(entries)} entries, expected 15"

    proc = subprocess.run(
        ["python3", "scripts/lint/lint_duplicate_helpers.py"],
        cwd=str(root), capture_output=True, text=True,
    )
    assert proc.returncode == 0, f"the fold introduced a NEW duplicate name:\n{proc.stdout}"




def test_gates_carry_direction_specific_names(tmp_path: Path):
    """A3's resolution, stated: the two gates stay SEPARATE functions — they are policies, not
    flags (C11) — but under direction-specific names, because the shared name was a collision
    rather than debt. `_gate_observations` in the observation builder, `_gate_findings` in the
    findings one, and `_partition_pre_author` nowhere."""
    mods = drain_modules()
    assert "_gate_observations" in module_level_defs(mods["curator.py"])
    assert "_gate_findings" in module_level_defs(mods["lessons/run.py"])
    for name, path in mods.items():
        if path.exists():
            assert "_partition_pre_author" not in module_level_defs(path), name


def test_no_underscore_attribute_reference_across_drain_modules(tmp_path: Path):
    """O4, re-scoped by fork 4: the oracle keys on `<mod>._name` ATTRIBUTE access, not on the
    literal wording. The nine `from defender._io / defender._yaml / … import` lines are a
    repo-wide convention, not the defect (C26) — an unscoped oracle fails on the convention
    instead of on the reach, and would be satisfied by moving the reach rather than removing
    it.

    Today there are exactly five such attribute reaches, `lessons/run.py:348`'s
    `_curator._dead_letter_or_bump` among them; after the fold there are none."""
    offenders: dict[str, list[str]] = {}
    for name, path in drain_modules().items():
        if not path.exists():
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Attribute)
                and node.attr.startswith("_")
                and not node.attr.startswith("__")
                and isinstance(node.value, ast.Name)
            ):
                offenders.setdefault(name, []).append(f"{node.value.id}.{node.attr}")
    assert offenders == {}, f"private cross-module attribute reach survives: {offenders}"


def test_curator_no_longer_re_exports_the_shared_git_helpers(tmp_path: Path):
    """D6: the six delegators go. Their stated justification was wrong on two of them —
    `curator.py` calls its own `_result_list` and `_commit_message` — but D6 survives because
    the fold deletes the module role that kept them alive. `corpus_dir_clean` had no callers
    at all.

    Asserted as absence of the re-export, paired with the control that the shared module still
    provides each one, so the deletion cannot be satisfied by removing the behaviour."""
    for name in DELEGATORS:
        assert not hasattr(curator, name), f"curator still re-exports {name}"
    for name in ("git_head_sha", "commit_corpus", "verify_agent_state"):
        assert hasattr(author_shared, name), f"shared lost {name}"


# O5 — per-direction gating semantics unchanged














# The written record the fold makes normative


def test_the_three_do_not_fold_comments_record_their_reversal(tmp_path: Path):
    """A4: D1 overturns three written in-code decisions the design never named — the
    `findings_lock_file` docstring in `core/config.py`, the same text on `AuthorConfig` in
    `lessons/run.py`, and the "NOT unified here" note in `author/_config.py`. D1 is still
    right, but an implementer hitting "the code says don't" needs the authority written down,
    so the reversal has to be recorded where the prohibition was.

    F7: the `core/config.py` site carries BOTH halves of the overturned sentence — "Two locks,
    two jobs" and the "do not fold this into the channel" tail — and only the tail was banned
    here, so deleting the tail and leaving the premise standing passed. Each site now bans every
    half it carries."""
    import defender.learning.core.config as core_config  # type: ignore[import-not-found]
    import defender.learning.author._config as author_config  # type: ignore[import-not-found]

    sites = {
        "core/config.py": (
            Path(core_config.__file__),
            ("do not fold this into the channel", "Two locks, two jobs"),
        ),
        "lessons/run.py": (Path(lessons_run.__file__), ("Two locks, two jobs",)),
        "author/_config.py": (Path(author_config.__file__), ("NOT unified here: the drains",)),
    }
    for label, (path, prohibitions) in sites.items():
        text = path.read_text(encoding="utf-8")
        for prohibition in prohibitions:
            assert prohibition not in text, f"{label} still states: {prohibition!r}"
        assert "#719" in text, f"{label} does not record what overturned it"


def test_surviving_baseline_reasons_no_longer_cite_the_curator_lessons_split(tmp_path: Path):
    """`run_batch` and `invoke_agent` stay baselined — their remaining sites are per-direction
    seams across the actor authors and `lead_author`, which this fold does not touch — but
    both rationales currently justify themselves by the curator/lessons split that is being
    deleted. A surviving entry whose stated reason no longer exists is how the next scan
    re-litigates a settled decision."""
    root = repo_root()
    baseline = json.loads((root / "scripts" / "lint" / "lint_duplicate_helpers_baseline.json")
                          .read_text(encoding="utf-8"))
    for name in ("run_batch", "invoke_agent"):
        reason = baseline["entries"].get(name, "")
        assert reason, f"{name} left the baseline unexpectedly"
        assert "lessons/run.py" not in reason, f"{name}'s reason still cites the deleted split"
        assert "curator" not in reason.lower(), f"{name}'s reason still cites the curator drain"


def test_the_error_disposition_design_doc_no_longer_states_the_overturned_base_catch_principle(
    tmp_path: Path,
):
    """F1, REWRITTEN at §7 round 2. The previous oracle banned three identifiers across every
    tracked doc and hit nothing — 62 files scanned, zero offenders — so it discharged F1 by
    firing on no document at all. The demand now names the document the way A4 named its three
    files.

    `defender/docs/error-disposition-types-design.md` states as its load-bearing principle that
    the drain clauses catch `StageAbort` AS A BASE so "any future systemic type re-raises for
    free". Decision 8 contradicts that for the author channels more sharply than decision 6's
    carve-out did: an enumerated retire set means a future class gets NOTHING for free — it
    falls through uncaught and the row stays queued. A reader who takes the doc at its word will
    add a base class and expect handling that will not arrive.

    So the doc must stop stating the principle unqualified and must record where it no longer
    holds. The two halves are separate assertions because deleting the sentence without saying
    what replaced it leaves the same reader with no answer."""
    doc = repo_root() / "defender" / "docs" / "error-disposition-types-design.md"
    assert doc.is_file(), "the doc F1 names is gone — the demand needs re-pointing, not deleting"
    text = doc.read_text(encoding="utf-8")

    assert "re-raising for free" not in text, "the overturned base-catch principle still stands"
    assert "#719" in text, "the doc does not record where the principle stopped holding"
    assert "retire set" in text.lower(), "the doc does not name what replaced it"


def test_no_tracked_non_python_file_still_names_a_deleted_symbol(tmp_path: Path):
    """F2: the tracked non-Python files naming a deleted symbol are rewritten in the SAME
    change, not left for a later reader to trip over. Scoped to what the fold actually
    deletes — the five pair-exclusive names and the six delegators — and to tracked
    non-Python files, so the check is about the written record rather than about code."""
    doomed = set(PAIR_EXCLUSIVE) | {"corpus_dir_clean", "changes_outside_corpus"}
    root = repo_root()
    offenders: dict[str, list[str]] = {}
    for path in tracked_files():
        if path.suffix in (".py", ".pyc") or not path.is_file():
            continue
        rel = str(path.relative_to(root))
        if rel.startswith(".spec-flow/") or "spec_graph_719" in rel:
            continue  # the spec's own frontier record, which is about the deletion
        text = path.read_text(encoding="utf-8", errors="replace")
        hits = sorted(s for s in doomed if re.search(rf"\b{re.escape(s)}\b", text))
        if hits:
            offenders[rel] = hits
    assert offenders == {}, f"tracked non-Python files still name deleted symbols: {offenders}"

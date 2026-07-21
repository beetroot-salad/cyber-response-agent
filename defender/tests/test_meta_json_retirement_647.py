"""Executable spec (written BEFORE the code) for design #647 — delete the inert run-dir
`meta.json`, mint the per-run salt in-process, and retire `hooks/tag_tool_results.py`.

The demand list, structure, claims and gate live in `spec_graph_647.yaml` beside this file.
**The demand list is the spec**: one test per `form: test` demand, named by its
`discharged_by`, and the demand's observable-outcome prose lives in the test's docstring.

This module carries the demands that do NOT need a driven run: the relocation seam, the
surviving-module and accessor-set survival demands, the repo-wide caller/orphan/prose
sweeps, and the env boundary. The driven-run demands (the origin pin, salt coherence, the
message-0 listing) live in `test_salt_origin_647.py` beside it.

RED AGAINST HEAD IS THE EXPECTED STATE. `defender/runtime/untrusted.py` does not exist yet,
`materialize_run_dir` still returns a bare `Path`, `RunPaths.meta` is still declared, and
`scripts/testing/gather_only.py` is still on disk. Each target import is done INSIDE the
test that needs it, so a missing module reds exactly one demand instead of taking the whole
module down at collection.

**Every repo-wide census here is DERIVED WITH A TOOL from the REPO ROOT** (`git grep`, and
an AST walk over the deleted module as it stood at the base commit) — never from a list
typed into this file. That is not stylistic: this change's enumeration was wrong on every
hand-written attempt (`materialize_run_dir`'s caller set twice, the orphan-symbol count
six→seven, the prose-site count four→nine), and the repo's own instruments are structurally
blind to the misses — `pyrefly-refs` is rooted at `configDir: defender` and silently omits
`scripts/`, `lint_stale_refs` drops identifiers under 8 characters and excludes `docs/`.
"""
from __future__ import annotations

import ast
import os
import re
import subprocess
from pathlib import Path

import pytest

from defender._run_paths import RunPaths
from defender.hooks import _run_dir as hooks_run_dir

DEFENDER = Path(__file__).resolve().parents[1]
REPO_ROOT = DEFENDER.parent
BASE = "be8d2c27"

DELETED_HOOK = "defender/hooks/tag_tool_results.py"
NEW_HOME = "defender/runtime/untrusted.py"

UNRELATED_TREES = (
    "experiments/",
    "playground-v2/",
    "defender/evals/run_judge_ab",
    "defender/evals/test_run_judge_ab",
    "docs/archive/",
    "defender/docs/runtime-per-loop-compaction-design.md",
    ".claude/",
    "defender/tests/spec_graph_",
    "defender/tests/e2e/spec_graph_",
)
HISTORICAL_RECORD = UNRELATED_TREES

SUITE_FILES = (
    "defender/tests/test_meta_json_retirement_647.py",
    "defender/tests/test_salt_origin_647.py",
)




def repo_grep(pattern: str, *pathspecs: str) -> list[str]:
    """Every tracked line in the repo matching `pattern`, as `path:lineno:text`.

    `git grep` from the REPO ROOT, not from `defender/`: the cwd is exactly what hid
    `scripts/testing/gather_only.py` from two prior censuses. Tracked files only, so a
    stale `__pycache__` or an untracked scratch file cannot fake a hit or a miss.
    """
    cmd = ["git", "grep", "-n", "-I", "-E", pattern]
    if pathspecs:
        cmd += ["--", *pathspecs]
    r = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True, check=False)
    if r.returncode not in (0, 1):
        raise AssertionError(f"git grep failed ({r.returncode}): {r.stderr.strip()}")
    return [line for line in r.stdout.splitlines() if line.strip()]


def live_hits(hits: list[str], *, extra_excludes: tuple[str, ...] = ()) -> list[str]:
    """`hits` minus the historical-record and unrelated trees, minus this suite's own files."""
    excluded = HISTORICAL_RECORD + SUITE_FILES + extra_excludes
    return [h for h in hits if not any(h.startswith(p) for p in excluded)]


def module_level_names_at_base(repo_path: str) -> set[str]:
    """Every module-level name a file DEFINED at the base commit, derived by walking its AST.

    Tool-derived on purpose. The hand-written orphan census for this change was wrong twice
    (six symbols became seven when `_subagent_is_untrusted` turned up), so the closure is
    re-derived from the file itself rather than restated here.

    SKIPS rather than errors when the base object is not in the local object store. CI checks
    out shallow, so `git show <base>:<path>` there is an absent object, not a failing
    assertion — a hard error would report "the census broke" as if it were "the closure
    leaked". A best-effort `git fetch --depth` of the base is attempted first.
    """
    def show() -> subprocess.CompletedProcess:
        return subprocess.run(
            ["git", "show", f"{BASE}:{repo_path}"],
            cwd=REPO_ROOT, capture_output=True, text=True, check=False,
        )

    r = show()
    if r.returncode != 0:
        subprocess.run(
            ["git", "fetch", "--depth=1", "origin", BASE],
            cwd=REPO_ROOT, capture_output=True, text=True, check=False,
        )
        r = show()
    if r.returncode != 0:
        pytest.skip(
            f"base object {BASE}:{repo_path} is unavailable in this checkout (shallow clone?); "
            f"the orphan census is derived from it and cannot run: {r.stderr.strip()}"
        )
    src = r.stdout
    names: set[str] = set()
    for node in ast.parse(src).body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            names.update(t.id for t in node.targets if isinstance(t, ast.Name))
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
    return names




def test_run_py_unpacks_the_pair_and_threads_both_elements_onward():
    """`run.py`'s call to `materialize_run_dir` binds BOTH elements of the returned pair in
    order — the run dir first, the salt second — and hands each onward to `run_investigation`
    (`run_dir=` and `salt=`). No disk re-read of the salt survives between the two: the value
    the builder returned is the value threaded, not a round-trip through a file the same
    function just wrote."""
    tree = ast.parse((DEFENDER / "run.py").read_text(encoding="utf-8"))

    unpacks = [
        n for n in ast.walk(tree)
        if isinstance(n, ast.Assign)
        and isinstance(n.value, ast.Call)
        and isinstance(n.value.func, ast.Attribute)
        and n.value.func.attr == "materialize_run_dir"
    ]
    assert len(unpacks) == 1, f"expected exactly one materialize_run_dir call site, got {len(unpacks)}"
    target = unpacks[0].targets[0]
    assert isinstance(target, ast.Tuple), (
        "run.py still binds materialize_run_dir's result to a single name — the builder now "
        "returns (run_dir, salt) and the caller must unpack both elements"
    )
    bound = [e.id for e in target.elts if isinstance(e, ast.Name)]
    assert bound == ["run_dir", "salt"], (
        f"unpack order must match the return order (run_dir, salt); got {bound}"
    )

    calls = [
        n for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "run_investigation"
    ]
    assert len(calls) == 1, "expected exactly one run_investigation call site in run.py"
    threaded = {
        kw.arg: kw.value.id for kw in calls[0].keywords if isinstance(kw.value, ast.Name)
    }
    assert threaded.get("run_dir") == "run_dir", "run.py must thread the unpacked run dir onward"
    assert threaded.get("salt") == "salt", (
        "run.py must thread the UNPACKED salt onward — not a value re-read from disk"
    )

    src = (DEFENDER / "run.py").read_text(encoding="utf-8")
    assert '.get("salt"' not in src, (
        "run.py still reads the salt back out of a JSON blob (double-quoted .get(\"salt\")); "
        "the in-process round-trip through meta.json is exactly what this change deletes"
    )
    assert ".get('salt'" not in src, (
        "run.py still reads the salt back out of a JSON blob (single-quoted .get('salt')); "
        "the in-process round-trip through meta.json is exactly what this change deletes"
    )




def test_learning_curator_leg_mints_a_fresh_uuid4_salt_distinct_from_the_run_token(tmp_path):
    """The curator leg binds with `salt=None`, which is a DOCUMENTED alternative that crosses
    validation: the learning stages legitimately mint their own trust token (a 32-hex uuid4)
    rather than inheriting the run's. The token the curator's `lesson_read` surface would wrap
    with is therefore a real, live, second token — distinct from the run lane's. This is the
    positive control for the negatives that assert no SECOND token reaches the run lane: the
    fresh-mint channel demonstrably works, so a clean run-lane sweep is not vacuous."""
    pytest.importorskip("pydantic_ai")
    from defender.learning.author.curator_engine import CuratorDeps
    from defender.learning.author.verify_forward.checks import FINDINGS_CHECK

    repo = tmp_path / "wt"
    corpus = repo / "defender" / "lessons"
    corpus.mkdir(parents=True)
    runs = tmp_path / "runs"
    runs.mkdir()
    pending = tmp_path / "findings.jsonl"
    pending.write_text("", encoding="utf-8")
    curdir = tmp_path / "curator-run"
    curdir.mkdir()

    deps = CuratorDeps.for_run(
        curdir, repo, corpus,
        check=FINDINGS_CHECK, runs_dir=runs, pending=pending, queued_ids=frozenset(),
    )
    other = CuratorDeps.for_run(
        curdir, repo, corpus,
        check=FINDINGS_CHECK, runs_dir=runs, pending=pending, queued_ids=frozenset(),
    )

    assert re.fullmatch(r"[0-9a-f]{32}", deps.salt), (
        f"the curator leg must mint a fresh uuid4 token, got {deps.salt!r}"
    )
    assert deps.salt != other.salt, (
        "two curator spawns must not share a token — each stage mints its own"
    )




def test_wrap_is_importable_from_defender_runtime_untrusted():
    """`wrap` has a live home at `defender/runtime/untrusted.py` — the quarantine-delimiter
    concern its four peers share, rather than a hook module whose `main()` nothing calls. The
    new seam must exist before any importer can be said to survive the deletion."""
    from defender.runtime.untrusted import wrap

    assert callable(wrap)
    assert (REPO_ROOT / NEW_HOME).is_file(), f"{NEW_HOME} must be a real module on disk"


def test_relocated_wrap_emits_the_same_delimiter_bytes_for_the_same_inputs():
    """The relocation changes the delimiter's home, never its bytes. For the same content,
    tag and salt, `wrap` emits the open frame, the raw content and the matching close frame
    byte-for-byte as before — an open tag, a newline, the untouched body, a newline, the close
    tag. A single byte of drift here silently invalidates every salted surface MAIN is told to
    distrust.

    RECORDED, so a future reader does not infer otherwise: `siem-data` has NO LIVE PRODUCER
    after this change. Its sole producer was the deleted hook's `context_annotation` path
    (`hooks/tag_tool_results.py:75`), and the only other occurrences repo-wide are three
    assertions in `tests/test_tag_tool_results.py`, which is deleted with the module. The tag's
    byte-identity is still asserted here deliberately: the relocation must not change `wrap`'s
    behaviour for ANY tag it is called with, and `wrap` takes the tag as a free parameter — its
    contract is not "the tags currently in use". So this arm pins the function's domain, not a
    live surface. The live tag after this change is `untrusted`, the one all five wrap call
    sites pass."""
    from defender.runtime.untrusted import wrap

    salt = "aabbccddeeff0011"
    assert wrap("BODY", "untrusted", salt) == (
        f"<run-{salt}-untrusted>\nBODY\n</run-{salt}-untrusted>"
    )
    assert wrap("BODY", "siem-data", salt) == (
        f"<run-{salt}-siem-data>\nBODY\n</run-{salt}-siem-data>"
    )
    assert wrap("a\nb", "untrusted", salt) == f"<run-{salt}-untrusted>\na\nb\n</run-{salt}-untrusted>"
    assert wrap("", "untrusted", salt) == f"<run-{salt}-untrusted>\n\n</run-{salt}-untrusted>"


def test_every_importer_of_the_relocated_wrap_resolves_after_the_move():
    """Every module that reached `wrap` through the retired hook resolves it from the new home
    after the move, and each holds the SAME function object — the four direct importers
    (orient, the generic tools, the query tool, gather dispatch) plus `lesson_read`, which
    reaches it transitively through the shared read back-half. This is the positive control
    for the orphan sweep: the import channel demonstrably resolves, so an empty orphan set is
    a real result rather than a broken query."""
    pytest.importorskip("pydantic_ai")
    from defender.runtime import orient, query_tool, tools, tools_gather
    from defender.runtime.untrusted import wrap
    from defender.learning.author import lesson_read

    assert orient.wrap is wrap
    for mod in (tools, query_tool, tools_gather):
        assert mod._wrap is wrap, f"{mod.__name__} holds a different wrap object"
    assert lesson_read is not None

    importers = live_hits(repo_grep(r"from defender\.runtime\.untrusted import|runtime\.untrusted"))
    assert importers, "no importer of the new module found — the relocation did not land"




def test_no_symbol_survives_whose_only_reachability_was_the_deleted_entrypoint():
    """Deleting the never-wired hook entrypoint orphans every module-level symbol whose only
    caller it was; none of them may survive anywhere in the repo. The symbol set is DERIVED
    from the deleted module's own AST at the base commit, never from a list — the hand-written
    census of this exact set was undercounted once already. `wrap` is the one exception: it is
    the live symbol, and it survives at its new home."""
    defined = module_level_names_at_base(DELETED_HOOK)
    assert "wrap" in defined, (
        f"the AST walk did not recover the deleted module's `wrap` symbol: {sorted(defined)}"
    )
    assert "main" in defined, (
        f"the AST walk did not recover the deleted module's `main` symbol: {sorted(defined)}"
    )
    orphans = {n for n in defined if not n.startswith("__")} - {"wrap"}
    assert len(orphans) >= 7, (
        f"expected at least the seven orphaned symbols plus main(), derived {sorted(orphans)}"
    )

    survivors: dict[str, list[str]] = {}
    for name in sorted(orphans):
        if name == "main":
            continue
        hits = live_hits(repo_grep(rf"\b{re.escape(name)}\b"))
        if hits:
            survivors[name] = hits
    assert not survivors, (
        "symbols orphaned by the deleted entrypoint still have live references:\n"
        + "\n".join(f"{k}: {v}" for k, v in survivors.items())
    )

    assert not (REPO_ROOT / DELETED_HOOK).exists(), f"{DELETED_HOOK} is still on disk"
    assert not (DEFENDER / "tests" / "test_tag_tool_results.py").exists(), (
        "the deleted module's own test file must go with it"
    )


def test_no_module_in_the_repo_still_imports_the_deleted_hook_module():
    """No module anywhere still imports the retired hook. A missed importer does not fail
    politely: it raises at IMPORT time, which under pytest is a collection error that takes
    every unrelated test in that module down with it. The sweep runs over tracked files from
    the repo root, so it sees `scripts/` — the tree `pyrefly-refs`, rooted at the defender
    package, structurally cannot report on."""
    hits = live_hits(repo_grep(r"^\s*(from|import)\s+.*tag_tool_results", "*.py"))
    hits += live_hits(repo_grep(r"hooks\.tag_tool_results|hooks import tag_tool_results", "*.py"))
    hits = sorted(set(hits))
    assert not hits,"the retired hook module is still imported:\n" + "\n".join(hits)
    assert not (REPO_ROOT / DELETED_HOOK).exists(), (
        "the module is still on disk, so a stale importer would still resolve and hide"
    )

    from defender.runtime.untrusted import wrap

    assert wrap("x", "untrusted", "0" * 16).startswith("<run-")




def test_update_json_locked_survives_the_sibling_removal(tmp_path):
    """The hooks run-dir module loses its salt reader but not itself: the flock'd
    read-modify-write behind the per-run budget and circuit-breaker files remains importable
    AND functional. Removing a member is not removing the module.

    It has two live consumers (the budget enforcer, the circuit breaker), asserted below on
    the BINDING rather than on the module object — a module is truthy whether or not it
    consumes anything, which made the old assertion vacuous. `resolve_run_dir` was this
    module's other survivor and the lesson-load recorder its third consumer, until #667
    deleted the `claude -p` entrypoint that was the only reason either existed; both left
    d21 with it."""
    assert not hasattr(hooks_run_dir, "read_meta_salt"), (
        "read_meta_salt survived — its only caller was the deleted hook entrypoint, and its "
        "fail-open minted a token no other surface knew"
    )

    target = tmp_path / "budget.json"
    hooks_run_dir.update_json_locked(target, lambda s: s.__setitem__("tool_calls", 1))
    state = hooks_run_dir.update_json_locked(
        target, lambda s: s.__setitem__("tool_calls", s["tool_calls"] + 1)
    )
    assert state["tool_calls"] == 2, "the locked read-modify-write no longer accumulates"

    assert not hasattr(hooks_run_dir, "resolve_run_dir"), (
        "resolve_run_dir survived — its last consumer was record_lesson_load's deleted "
        "entrypoint, and the in-process gates take the run dir from AgentDeps"
    )

    from defender.hooks import budget_enforcer
    from defender.runtime import circuit_breaker

    assert budget_enforcer.update_json_locked is hooks_run_dir.update_json_locked, (
        "the budget_enforcer consumer no longer binds update_json_locked"
    )
    assert circuit_breaker.update_json_locked is hooks_run_dir.update_json_locked, (
        "the circuit_breaker consumer no longer binds update_json_locked"
    )


def test_run_paths_accessor_set_is_five_after_the_meta_accessor_is_removed(tmp_path):
    """`RunPaths` exposes five artifact accessors once the one pointing at the removed file is
    gone — the alert, the report, the investigation log, the queries table and the raw-payload
    dir — plus the learning-leg re-root. No accessor may survive naming a file no consumer
    reads, and the class docstring's own count must agree with the accessors it enumerates."""
    accessors = {n for n, v in vars(RunPaths).items() if isinstance(v, property)}
    artifacts = accessors - {"learning"}
    assert artifacts == {"alert", "report", "investigation", "executed_queries", "gather_raw"}, (
        f"the artifact accessor set drifted: {sorted(artifacts)}"
    )
    assert not hasattr(RunPaths(tmp_path), "meta"), "RunPaths still resolves a meta.json path"

    doc = " ".join((RunPaths.__doc__ or "").split())
    assert "five artifact accessors" in doc, (
        "the class docstring still counts the accessors it no longer has"
    )
    assert "meta" not in doc, "the docstring still enumerates the removed accessor"


def test_no_call_site_anywhere_still_reaches_run_paths_meta_or_the_literal_meta_json():
    """No call site reaches the removed run-dir metadata file under EITHER spelling — neither
    the `RunPaths` accessor nor the bare `meta.json` string literal. Both spellings are swept
    because a symbol-scoped census structurally cannot see a string literal, and that is the
    exact trap that hid a caller from two prior sweeps. Unrelated trees that carry their own
    `meta.json` vocabulary — the experiment fixtures, the judge A/B snapshots, the attack
    playground — keep theirs untouched and are excluded by name."""
    accessor_hits = live_hits(
        repo_grep(r"RunPaths\([^)]*\)\.meta\b|\)\.meta\.write_text|\bpaths\.meta\b", "*.py")
    )
    assert not accessor_hits, (
        "the RunPaths.meta accessor is still reached:\n" + "\n".join(accessor_hits)
    )

    literal_hits = live_hits(repo_grep(r"meta\.json", "*.py", "*.md", "*.yaml", "*.json"))
    assert not literal_hits, (
        "the meta.json literal survives in live code or prose:\n" + "\n".join(literal_hits)
    )




def test_no_module_outside_the_defender_package_imports_run_common():
    """Nothing outside the defender package imports the changed builder's module. This is the
    property the manual harness's deletion buys, and it is stronger than an enumeration of
    call sites: an enumeration was wrong twice, because every reference instrument in this
    repo is rooted inside `defender/` and structurally could not see the caller that lived
    under `scripts/`. The sweep therefore runs from the repo root over tracked files, and the
    surviving caller set is a property of the tree rather than of a list."""
    hits = live_hits(repo_grep(r"\brun_common\b"))
    outside = [h for h in hits if not h.startswith("defender/")]
    assert not outside, (
        "run_common is imported from outside the defender package:\n" + "\n".join(outside)
    )

    caller_hits = live_hits(repo_grep(r"\bmaterialize_run_dir\b"))
    outside_callers = [
        h for h in caller_hits
        if not h.startswith("defender/")
    ]
    assert not outside_callers, (
        "a caller of the changed builder survives outside defender/:\n" + "\n".join(outside_callers)
    )


def test_the_deleted_manual_gather_harness_leaves_no_dependent_behind():
    """The manual, live-billed gather harness is gone from disk and nothing depends on it. It
    was a second driver of the changed builder that no gate instrument reached — not pytest,
    not vulture, not the actors check — so a break in it would have shipped silently. Its only
    surviving textual match anywhere is an unrelated demand id in another spec graph, about the
    gather agent's toolset rather than this file."""
    assert not (REPO_ROOT / "scripts" / "testing" / "gather_only.py").exists(), (
        "scripts/testing/gather_only.py is still on disk"
    )
    hits = live_hits(
        repo_grep(r"gather_only"),
        extra_excludes=("defender/tests/e2e/test_540_scrub_lifecycle.py",),
    )
    assert not hits, "a dependent on the deleted harness survives:\n" + "\n".join(hits)




def test_no_live_model_facing_prose_names_a_mechanism_with_no_producer():
    """No live model-facing prose describes a mechanism nothing produces. The runtime SKILL is
    a behavioral contract loaded into MAIN's system prompt, not documentation: the marker
    clause it carries lost its sole producer with the deleted entrypoint, so the clause is
    excised. The sweep covers live prose generally — the SKILL, the architecture docs, the
    source comments — because every fixed list of sites this change produced was wrong."""
    skill = (DEFENDER / "SKILL.md").read_text(encoding="utf-8")
    assert "[UNTRUSTED-" not in skill, (
        "SKILL.md still instructs MAIN to honor a marker no code emits"
    )

    marker_hits = live_hits(repo_grep(r"\[UNTRUSTED-", "*.md", "*.py"))
    assert not marker_hits, (
        "live prose still names the producerless marker:\n" + "\n".join(marker_hits)
    )


def test_skill_md_run_delimiter_clause_survives_with_its_producer_intact():
    """The sibling trust cue in the same SKILL sentence KEEPS its producer and must survive
    intact: content inside the run-scoped delimiters is still tagged external data, and `wrap`
    still emits exactly those delimiters from its new home. Excising too much would silently
    drop a live behavioral contract from MAIN's system prompt — which is why this is the
    positive control for the producerless-prose sweep."""
    skill = (DEFENDER / "SKILL.md").read_text(encoding="utf-8")
    assert "<run-{salt}-" in skill, (
        "the surviving delimiter clause was excised along with the dead marker clause"
    )

    from defender.runtime.untrusted import wrap

    salt = "aabbccddeeff0011"
    produced = wrap("payload", "untrusted", salt)
    assert produced.startswith(f"<run-{salt}-"), (
        "the clause MAIN is told to honor no longer matches what the producer emits: "
        "the opening delimiter is not the salted one"
    )
    assert produced.endswith(f"</run-{salt}-untrusted>"), (
        "the clause MAIN is told to honor no longer matches what the producer emits: "
        "the closing delimiter is not the salted one"
    )


def test_prose_site_sweep_is_derived_from_the_repo_not_from_a_fixed_list():
    """The prose-site set is derived by sweeping the repository, never by binding a list. The
    same sweep that must find NO surviving reference to the removed file or the retired module
    must still FIND the surviving delimiter clause — a sweep that matches nothing would pass
    every negative vacuously, and CI's stale-reference lint catches only one of these sites
    (it drops short generic identifiers and excludes the docs tree entirely), so nothing
    upstream backstops this."""
    surviving = live_hits(repo_grep(r"<run-\{salt\}-", "*.md", "*.py"))
    assert surviving, (
        "the sweep matched nothing at all — every absence assertion below would be vacuous"
    )

    stale = live_hits(
        repo_grep(
            r"meta\.json|tag_tool_results|read_meta_salt|\[UNTRUSTED-|persisted (salt|trust token)",
            "*.md", "*.py", "*.yaml", "*.json",
        )
    )
    assert not stale, (
        "live sites still describe a removed mechanism as live:\n" + "\n".join(stale)
    )


def test_the_three_predecessor_codebase_docs_are_archived_rather_than_corrected():
    """The three repo-root docs that describe a PREDECESSOR codebase are ARCHIVED, not edited
    in place. `docs/design-v3-init-and-connect.md`, `docs/handlers-refactor-map.md` and
    `docs/evaluation-and-chaos-design.md` each name the removed metadata file, but correcting
    that one line would leave a document whose every other implementation path — the hooks-based
    architecture, `scripts/setup_run.py`, the handler tree — also no longer exists, i.e. a doc
    that reads current and is wrong throughout. The human's decision is therefore to archive all
    three under `docs/archive/` behind a stale banner, following the precedent #650 set for
    `docs/security-model.md`: each file exists at its archived path, no longer exists at its
    repo-root path, and carries a banner in its opening block marking it superseded. Archiving
    is also what makes the prose sweep's `docs/archive/` exclusion legitimate for them — an
    excluded path must be excluded because it is a record, not because it is inconvenient."""
    archived = (
        "design-v3-init-and-connect.md",
        "handlers-refactor-map.md",
        "evaluation-and-chaos-design.md",
    )
    for name in archived:
        old = REPO_ROOT / "docs" / name
        new = REPO_ROOT / "docs" / "archive" / name
        assert not old.exists(), (
            f"docs/{name} is still at its repo-root path — the decision is to ARCHIVE it, "
            "not to correct it in place"
        )
        assert new.is_file(), f"docs/archive/{name} does not exist — the doc was not archived"

        head = new.read_text(encoding="utf-8").splitlines()[:15]
        banner = [ln for ln in head if ln.lstrip().startswith(">") and "rchiv" in ln]
        assert banner, (
            f"docs/archive/{name} carries no stale banner in its opening block; the #650 "
            "precedent is a blockquote marking the doc archived and superseded"
        )

    precedent = (REPO_ROOT / "docs" / "archive" / "security-model.md").read_text(encoding="utf-8")
    assert "rchiv" in precedent[:600], "the #650 precedent doc no longer carries its banner"




def test_defender_run_dir_still_crosses_the_subprocess_boundary_for_its_reader(
    tmp_path, monkeypatch
):
    """The run-dir env var survives the removal of the only mechanism that ever turned it into
    a salt. The bash tool's subprocess environment still exports it, and its live reader still
    resolves it across that boundary: the ticket adapter, building its verb context from the
    ambient environment. (The hooks' run-dir resolver was the second reader until #667 — it
    served hook subprocesses, which no longer exist; the adapter reads the var directly.)"""
    from defender import run_common
    from defender.scripts.adapters import ticket_adapter

    run_dir = tmp_path / "runs" / "r1"
    run_dir.mkdir(parents=True)
    env = run_common.run_env(DEFENDER, run_dir)
    assert env["DEFENDER_RUN_DIR"] == str(run_dir)

    for key, value in env.items():
        monkeypatch.setenv(key, value)
    assert ticket_adapter._cli_context().run_dir == run_dir


def test_the_subprocess_environment_carries_no_path_to_the_run_salt(tmp_path):
    """The subprocess environment carries no path to the run's trust token. The env via was
    the salt's one out-of-process channel — the deleted resolver turned the run-dir var into a
    token by reading a file out of that directory — and with both the reader and the file gone
    the environment names no salt, holds no salt value, and points at no directory from which
    one could be recovered AT MATERIALIZATION TIME — which is the scope of this pin, and is
    when the env is built. It is deliberately NOT a claim about the run dir for all time: a
    DRIVEN run streams the model transcript into `llm_requests.jsonl`, delimiters and all, so
    the token has a pre-existing on-disk presence there that this change neither creates nor
    removes. The run-dir var itself still crosses (its positive control), so an empty result
    here is not just an empty environment."""
    from defender import run_common

    alert = tmp_path / "alert.json"
    alert.write_text("{}", encoding="utf-8")
    os.environ["DEFENDER_RUNS_BASE"] = str(tmp_path / "runs")
    try:
        run_dir, salt = run_common.materialize_run_dir(alert, "env-boundary-647")
    finally:
        os.environ.pop("DEFENDER_RUNS_BASE", None)

    env = run_common.run_env(DEFENDER, run_dir)
    assert env["DEFENDER_RUN_DIR"] == str(run_dir), "the positive-control channel is empty"
    assert not [k for k in env if "SALT" in k.upper()], "an env var names the salt"
    assert salt not in "\n".join(env.values()), "the salt's value leaked into the subprocess env"
    assert not list(run_dir.glob("*.json")) or not any(
        salt in p.read_text(encoding="utf-8", errors="ignore") for p in run_dir.rglob("*")
        if p.is_file()
    ), "the salt is recoverable from a file inside the exported run dir"



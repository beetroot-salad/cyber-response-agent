"""#1025 O8 (prep 2) — one episode reader and one home for each file name.

O8 (maintainer): the page, the grading pass and the judge input builder read the episode
archive through ONE reader — one spelling of each file name, one home for each derived
accessor. The observed failing is a fourth `REVIEW_NAME = "review.yaml"` (there are four
today, plus a fifth under another name), or the page re-implementing a lead chain the
input builder already computes. Three decisions are pinned here:

1. **The file names live in `learning/branch/archive.py`** — `REVIEW_NAME`, `SAMPLES_NAME`,
   `JUDGE_NAME` — and NOWHERE ELSE: across the shipped code roots the strings `review.yaml`,
   `samples.yaml` and `judge.yaml` each occur INSIDE a code string constant in exactly one
   module (a docstring may mention them; a pointer, a prompt example or a message may not
   spell them), the three names are BOUND only there, and every module that reads a record
   holds `archive`'s own object (an import, `is`-identical). O8's observable IS a name census,
   so this is the one suite where a walk over the tree's syntax is the honest test rather than
   a proxy for one — over the AST, because a text regex misses `"review" ".yaml"` and its
   cousins, and by CONTAINMENT, because the spellings that actually drift are embedded ones
   (`f"{ep}/review.yaml#..."`, "for example `review.yaml#worlds.b...`").
2. **The derived accessors live in `learning/judge/family.py` under PUBLIC names** —
   `raw_manifest` and, moved off `render.py`, `leads_by_id`, `lead_chain` and `json_mapping`
   (the overlay, holding-system and review accessors retired with #1224). Those private
   spellings are gone, the input builder IMPORTS the lead-chain trio
   (its attributes are `family`'s objects, and no constant in `render.py` names the queries
   table or the lead files), and the `leads` view a real `render()` produces equals what
   `family.lead_chain` answers over the same world. `leads_by_id` is the canonical
   `lead_repository.joined` surface indexed once (#1017) — the judge keeps no parser of the
   queries table of its own, so the table's own screens and partitions are the surface's and
   tested there. Each accessor's behaviour is driven on the public name against a real
   archived world, so the move is a move and not a rename plus a rewrite.
3. **The tolerant `judge.yaml` reader is public: `judge.read_grade(episode_dir)`** — `None`
   for an ungraded episode, a refusal for a planted link or a non-mapping (real faults through
   the real primitive), a pre-#1224 record read with today's defaults and nothing invented,
   and the SAME record `grade_episode` returns on an already-graded episode.

RED AGAINST THE PRE-CHANGE TREE was the expected state (the constants and the public names
did not exist; the census found five modules spelling `review.yaml`), and the tests
were then tightened against an adversarial implementation. Every import goes through `J.mod`
/ `J.sym` PER TEST so a missing target is one failure per test, never a collection error.
"""
from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest
import yaml

from defender._io import bind
from defender.run_repository import RunPaths
from defender.tests import _judge_921 as J
from defender.tests._spec791 import PROJECT_PROFILE
from defender.tests import _state1135

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    """Every configured root inside `tmp_path`, so a pass this file drives lands in this test's
    own tree — never the checkout's runs base or its real `learning/_pending/`."""
    monkeypatch.setenv(J.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(J.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    _state1135.set_state_dir(monkeypatch, tmp_path / "learning-state")


def _judge():
    return J.mod("learning.judge")


def _family():
    return J.mod("learning.judge.family")


def _world(ep: Path, label: str):
    """The reader `lead_chain` takes: the episode's bound primitive, bound one directory down
    at `worlds/<label>` by derivation (#1049 D-V2) — never a path it could format."""
    return J.mod("_io").bind(ep).under(f"worlds/{label}")


def _render():
    return J.mod("learning.judge.render")


def _io():
    return J.mod("_io")


def _archive():
    return J.mod("learning.branch.archive")


def _refused():
    """The judge's own refusal class, resolved BEFORE the `raises` block opens — a missing
    target fails at the call rather than satisfying `raises(Exception)`."""
    return J.sym("learning.judge", "JudgeRefused")


def _grade(ep: Path, tmp_path: Path):
    """The real grading pass over `ep`, through its own seams — never a live provider."""
    judge = J.FakeJudge(default=J.as_reply_text(J.reply_doc()))
    return J.grade_at(ep, judge=judge, state=_state1135.env_state())


def _write_issued(world_dir: Path, rows: list[dict]) -> Path:
    """The world's queries table, written the one way this file writes it: one JSON object per
    line at the writer's own path (`RunPaths.executed_queries`), so the four scenarios that
    need a table spell neither the name nor the JSONL join."""
    table = RunPaths(world_dir).executed_queries
    table.write_text(
        "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows), encoding="utf-8")
    return table


# ---------------------------------------------------------------------------------------
# Decision 1 — the file names: one home, one spelling
# ---------------------------------------------------------------------------------------

#: The shipped code roots — the project profile's `specGraph.codeRoots`, READ from the profile
#: rather than re-spelled so a root added there is censused here — relative to the `defender/`
#: package the code under test is actually IMPORTED from, so a worktree census reads the
#: worktree, never the checkout the shared venv's editable install points at.
_CODE_ROOTS = tuple(
    Path(root).relative_to("defender").as_posix()
    for root in json.loads(PROJECT_PROFILE.read_text(encoding="utf-8"))["specGraph"]["codeRoots"])
#: The ONE home of the three names — `_episode_paths.py`, the episode-layout owner (#1077 D1
#: re-homed them off `learning/branch/archive.py`, which now binds them by import). The
#: run-level owner is censused beside it: the family stamp's name is its `PROVENANCE`.
_OWNER_MODULE = "_episode_paths.py"
#: The run-layout owner, by its path under `defender/` since #1105 moved it into the runs
#: repository package (D1.1). A stale path here would silently drop it from the census (`rglob`
#: of a missing path yields nothing), so `_shipped_modules` asserts the census saw it.
_LAYOUT_MODULE = "run_repository/_layout.py"
_OWNER_MODULES = (_OWNER_MODULE, _LAYOUT_MODULE)
_ARCHIVE_MODULE = "learning/branch/archive.py"
#: The three names and the three files, one mapping.
_RECORD_NAMES = {"REVIEW_NAME": "review.yaml", "SAMPLES_NAME": "samples.yaml",
                 "JUDGE_NAME": "judge.yaml"}

#: Every shipped module that reads one of the three records, and the attribute it reads the
#: name through. Each must be `archive`'s OWN object — an import, never a re-spelling.
_IMPORTERS: tuple[tuple[str, str], ...] = (
    ("learning.branch.cli", "REVIEW_NAME"),
    ("learning.branch.cli", "SAMPLES_NAME"),
    ("learning.branch.episode", "REVIEW_NAME"),
    ("learning.judge.enqueue", "SAMPLES_NAME"),
    ("learning.judge.family", "REVIEW_NAME"),
    ("learning.judge.family", "SAMPLES_NAME"),
    ("learning.judge.run", "REVIEW_NAME"),
    ("learning.judge.run", "SAMPLES_NAME"),
    ("learning.judge.run", "JUDGE_NAME"),
    ("learning.judge", "JUDGE_NAME"),
    ("learning.judge", "REVIEW_NAME"),
)


def _shipped_modules() -> dict[str, str]:
    """`{relative posix path: source text}` for every `.py` under the shipped roots. The
    package dir is the one `archive.py` was imported from (`defender` is a namespace package
    and has no `__file__` of its own), so the tree censused is the tree under test."""
    package = Path(_archive().__file__).resolve().parents[2]
    assert package.name == "defender", f"the census root is not the package: {package}"
    out: dict[str, str] = {}
    for root in (*_CODE_ROOTS, *_OWNER_MODULES):
        base = package / root
        files = [base] if base.is_file() else sorted(base.rglob("*.py"))
        for path in files:
            out[path.relative_to(package).as_posix()] = path.read_text(encoding="utf-8")
    assert _ARCHIVE_MODULE in out, f"the census never saw {_ARCHIVE_MODULE}: {sorted(out)[:5]}"
    assert _OWNER_MODULE in out, f"the census never saw {_OWNER_MODULE}"
    assert _LAYOUT_MODULE in out, (
        f"the census never saw the run-layout owner {_LAYOUT_MODULE} — a stale owner path drops "
        "it from the census silently")
    return out


def _folded_string(node: ast.AST) -> str | None:
    """The string a node denotes when it is a constant expression, else `None`.

    The parser already folds `"review" ".yaml"` into ONE `Constant`; this folds the two other
    spellings that survive parsing as an expression over constants — `"review" + ".yaml"` and
    `f"review.yaml"` — so a literal dressed up as arithmetic is still the literal.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _folded_string(node.left), _folded_string(node.right)
        return None if left is None or right is None else left + right
    if isinstance(node, ast.JoinedStr):
        parts = [_folded_string(v) for v in node.values]
        return None if any(p is None for p in parts) else "".join(parts)
    return None


def _census(source: str, path: str) -> tuple[set[str], set[str]]:
    """`(code strings, bound names)` for one module, off ONE parse.

    The code strings are every string the AST denotes as a constant expression (see
    `_folded_string`) EXCEPT docstrings — a module, class or function docstring is prose and
    may mention a file by name; a pointer, a prompt example or a message is code and may not.
    The bound names are every `Name` in Store context — an assignment, an annotated or tuple
    assignment, a walrus, a loop or `with` target — which is what "this module DEFINES the
    name" means; an import is an `alias`, not a `Name`, so a re-export never counts.
    """
    tree = ast.parse(source, filename=path)
    docstrings = {
        id(node.value) for node in ast.walk(tree)
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    }
    strings: set[str] = set()
    bound: set[str] = set()
    for node in ast.walk(tree):
        if id(node) in docstrings:
            continue
        if (folded := _folded_string(node)) is not None:
            strings.add(folded)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            bound.add(node.id)
    return strings, bound


def _string_constants(source: str, path: str) -> set[str]:
    """Every code string a module's AST denotes as a constant expression — see `_census`."""
    return _census(source, path)[0]


def test_the_episode_path_owner_is_the_one_home_for_the_three_episode_record_names():
    """`_episode_paths.py` owns the three episode-level record names, with the values every
    reader used to spell for itself.

    THE HOME MOVED, and this test's name moved with it (#1077 D7). It used to assert
    `archive.py` was the home, because archive.py re-bound each name off the owner and every
    reader bound it off archive.py in turn. That re-export was the disease D7 removes: the day
    archive.py stopped exporting them, six modules broke at once with no gate having seen
    anything. archive.py now holds no record name at all.

    Observably true: `_episode_paths.REVIEW_NAME == "review.yaml"`, `SAMPLES_NAME ==
    "samples.yaml"`, `JUDGE_NAME == "judge.yaml"`, and none of the three is an attribute of
    `archive.py`.
    """
    owner, archive = J.mod("_episode_paths"), _archive()

    for name, value in _RECORD_NAMES.items():
        assert getattr(owner, name) == value, (
            f"_episode_paths.{name} is {getattr(owner, name)!r}, not {value!r}")
        assert not hasattr(archive, name), (
            f"archive.py still re-exports {name} — a second home is what D7 removes")


def test_each_episode_record_name_is_spelled_in_exactly_one_shipped_module():
    """O8's census, run over the tree's SYNTAX: across the shipped code roots the strings
    `review.yaml`, `samples.yaml` and `judge.yaml` each occur INSIDE a code string in ONE
    module — `_episode_paths.py`, the episode-layout owner (#1077 D1; it was `archive.py`
    before, which now imports them) — and a BINDING of `REVIEW_NAME` / `SAMPLES_NAME` /
    `JUDGE_NAME` occurs only there. Every other module imports the name; an import is not a
    binding.

    Through `ast`, not a regex over the text: a regex sees `"review.yaml"` and misses
    `"review" ".yaml"` (folded by the parser into one constant), `"review" + ".yaml"` and
    `f"review.yaml"` — every one of which is the same second home wearing a disguise. And by
    CONTAINMENT, not equality: the spellings that drift are the embedded ones — a pointer
    written into `judge.yaml` (`f"{ep}/review.yaml#..."`), the family prompt's worked example,
    an unqueueable reason — which an exact-match census walked straight past while the
    allowlist beside them followed the constant. Docstrings are exempt: prose may name a file.
    Bindings off the same AST, in Store context, so `NAME: str = ...`, a tuple target and a
    walrus all count and a docstring line that merely looks like an assignment does not.

    Observably true: the set of modules whose code strings contain each name is
    `{_episode_paths.py}`, and so is the set of modules binding any of the three constants.

    What failure looks like: before the change, `family.py`, `branch/episode.py`,
    `branch/review.py`, `branch/cli.py` and `branch/staging.py` (as `REVIEW_FILENAME`) each
    spelled `review.yaml`, and `judge/__init__.py` / `judge/run.py` spelled `judge.yaml` and
    `samples.yaml` inline. A fourth definition is exactly O8's named failing: a rename of the
    file reaches some readers and not others, and the page reads a record the pass never wrote.
    """
    modules = _shipped_modules()
    census = {path: _census(text, path) for path, text in modules.items()}

    for file_name in _RECORD_NAMES.values():
        spelled_in = sorted(
            m for m, (strings, _bound) in census.items() if any(file_name in s for s in strings))
        assert spelled_in == [_OWNER_MODULE], (
            f"{file_name!r} is spelled inside a code string in {spelled_in}; O8 wants exactly "
            f"one home, {_OWNER_MODULE}, with every other module importing the name — a "
            "pointer, a prompt example or a message spells it as f\"...{REVIEW_NAME}...\"")

    bound_in = sorted(
        m for m, (_strings, bound) in census.items() if bound & _RECORD_NAMES.keys())
    assert bound_in == [_OWNER_MODULE], (
        f"REVIEW_NAME / SAMPLES_NAME / JUDGE_NAME are BOUND in {bound_in}; only "
        f"{_OWNER_MODULE} may define them — a re-export is an import, not a binding")


def test_no_reader_of_a_record_name_holds_one_at_all():
    """No shipped module outside the owner BINDS any of the three record names — not even as
    an import.

    THE INVERSE OF WHAT THIS TEST USED TO ASSERT, deliberately (#1077 D7). It used to require
    that every reader hold `archive`'s OWN object, on the reasoning that sharing one object
    is what keeps a rename honest. The object was shared and the rename was still not honest:
    a held name is a name that outlives its home, and when `archive.py` stopped exporting
    these, six modules broke at once with nothing having warned. A reader that asks the owner
    for a path holds nothing, so there is nothing left to strand.

    Observably true: for each `(module, attribute)` in `_IMPORTERS` — the modules that used to
    hold one — the attribute is simply absent.

    What failure looks like: a module re-acquires one, by import or by re-spelling, and the
    two-homes shape is back.
    """
    for module_name, attribute in _IMPORTERS:
        module = J.mod(module_name)
        assert not hasattr(module, attribute), (
            f"{module_name} holds {attribute} — D7's rule is that nothing outside the owner "
            "holds a record name; ask for the accessor instead")


# ---------------------------------------------------------------------------------------
# Decision 2 — the derived accessors: one home, public names, the same behaviour
# ---------------------------------------------------------------------------------------

#: The `family.py` private `render.py` imported across the module line, and the two
#: `render.py` privates the page needs — each as `(private spelling, public spelling)`. The
#: overlay and holding-system accessors (`staged_patterns`, `world_pattern`, `own_h_rows`) and
#: the review join retired with #1224.
_MOVED = (
    ("_raw_manifest", "raw_manifest"),
    ("_leads_by_id", "leads_by_id"),
    ("_lead_chain", "lead_chain"),
)


def test_family_is_the_one_home_for_the_derived_accessors_under_public_names():
    """The episode reader's derived accessors have ONE home, `judge/family.py`, and public
    names — nothing crosses a module line as a private any more.

    Observably true: `family` exposes `raw_manifest`, `leads_by_id`, `lead_chain` and
    `json_mapping` as callables; neither `family` nor `render` carries the underscore spelling of any of them;
    the input builder IMPORTS the lead-chain pair — `render.lead_chain` and
    `render.json_mapping` are `family`'s own objects (since #860's finalize the leads
    themselves reach the render on `WorldFacts.leads`, the pass's one read, so `render`
    calls `leads_by_id` nowhere) — and no constant in `render.py` OR `family.py` names
    `executed_queries.jsonl` or `gather_raw`, the two reads that belong to `lead_repository`,
    the canonical surface `leads_by_id` indexes (#1017).

    This is a name census over the accessors the design named that survive #1224 (`render.py`'s other
    readers — `episode_alert`, `_read_provenance` — and `enqueue.draws_on_disk` stay where they
    are for now), which is what O8's observable is. What failure looks like: the page
    imports `render._lead_chain` (a private, across a module line — the state before this
    change), or a second copy of the chain lives on in `render.py` under fresh private names
    with `family.lead_chain` called by nothing, so the prompt and the page drift.
    """
    family, render = _family(), _render()

    for private, public in _MOVED:
        assert callable(getattr(family, public, None)), (
            f"family.{public} is absent — the accessor still lives under {private!r}")
        for module, name in ((family, private), (render, private)):
            assert not hasattr(module, name), (
                f"{module.__name__}.{name} still exists; the private spelling crosses a module "
                f"line and O8 wants one public home, family.{public}")
    assert callable(getattr(family, "json_mapping", None)), (
        "family.json_mapping is absent — the JSON tolerance policy has no home in the reader")
    for name in ("lead_chain", "json_mapping"):
        assert getattr(render, name, None) is getattr(family, name), (
            f"render.{name} is not family.{name} — the input builder does not import the "
            "accessor it renders the per-lead chain with; that IS the one-home observable")

    for module in (render, family):
        source = Path(module.__file__).read_text(encoding="utf-8")
        leftover = {"executed_queries.jsonl", "gather_raw"} & _string_constants(
            source, module.__file__)
        assert not leftover, (
            f"{module.__name__} still names {sorted(leftover)} as a constant — the queries "
            "table and the lead files are lead_repository's to read, so a spelling here is a "
            "second reader")


def test_the_input_builders_leads_view_is_what_family_lead_chain_answers(tmp_path):
    """The per-lead chain the judge is SHOWN is the chain `family.lead_chain` computes — the
    behavioural half of "one home": a real `render()` over an archived world produces a
    `leads` view equal, lead for lead, to `lead_chain` over the same world's own facts.

    Observably true: `render(ep, "b").leads["l-001"]` equals `family.lead_chain(world,
    "l-001", facts.resolutions_by_lead, leads=family.leads_by_id(world_dir))`,
    with a real lead file and two issued queries on disk so every link carries a value.

    What failure looks like: the builder keeps its own chain (a private copy) and the page,
    reading through `family`, describes a lead the judge was never shown.
    """
    family = _family()
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []})
    world_dir = ep / "worlds" / "b"
    rows = [
        {"lead_id": "l-001", "query_id": "q1", "params": {"index": "logs-*"},
         "payload_digest": "d1"},
        {"lead_id": "l-001", "query_id": "q2", "params": {"index": "logs-2"},
         "payload_digest": "d2"},
    ]
    _write_issued(world_dir, rows)
    (world_dir / "gather_raw" / "l-001.lead.json").write_text(
        json.dumps({"lead_id": "l-001", "goal": "find the pivot"}), encoding="utf-8")
    base, _src = J.runs_base(tmp_path)

    shown = _render().render(ep, "b").leads
    facts = family.read_world_facts(J.mod("_io").bind(ep), "b", episode_token=J.EPISODE_TOKEN)
    expected = family.lead_chain(_world(ep, "b"), "l-001", facts.resolutions_by_lead,
                                 leads=family.leads_by_id(world_dir))

    assert expected["goal"] == "find the pivot", "the fixture's lead file was not read"
    assert expected["payload"] == ["d1", "d2"], "the fixture's queries were not read"
    assert shown["l-001"] == expected, (
        "the judge is shown a per-lead chain that differs from family.lead_chain's over the "
        f"same world:\n{shown['l-001']}\n!=\n{expected}")


def test_leads_by_id_is_the_canonical_surface_indexed_once(tmp_path):
    """`leads_by_id(world_dir)` is `lead_repository.joined` over the archived world, keyed by
    lead id — the judge keeps NO parser of the queries table of its own (#1017 D3/N8), so the
    surface's partitions and screens are what the chain sees.

    Observably true: the issued rows group under their leads in seq order with the `∅.`
    sentinel row in `sentinels`, not `queries`; a lead with a lead file and no rows is present
    with its goal; and with the table replaced by a symlink the leads are still present with
    their goals and NO queries — the two halves refused separately, the surface's own posture.

    What failure looks like: a second grouping of the raw rows lives in the judge and drifts
    from the surface on the sentinel split, the seq order or the link posture.
    """
    family = _family()
    ep = J.accepted_episode(tmp_path)
    world_dir = ep / "worlds" / "b"
    rows = [
        {"lead_id": "l-001", "seq": 2, "query_id": "q2", "params": {"index": "logs-2"},
         "payload_digest": "d2"},
        {"lead_id": "l-001", "seq": 1, "query_id": "q1", "params": {"index": "logs-*"},
         "payload_digest": "d1"},
        {"lead_id": "l-001", "seq": 3, "query_id": "∅.above-repeat-guard", "params": {},
         "payload_digest": "dx"},
    ]
    table = _write_issued(world_dir, rows)
    for lid, goal in (("l-001", "find the pivot"), ("l-002", "queryless")):
        (world_dir / "gather_raw" / f"{lid}.lead.json").write_text(
            json.dumps({"lead_id": lid, "goal": goal}), encoding="utf-8")

    by_id = family.leads_by_id(world_dir)

    assert [q.query_id for q in by_id["l-001"].queries] == ["q1", "q2"], (
        "the sentinel reached the issued queries, or seq order was lost")
    assert [q.query_id for q in by_id["l-001"].sentinels] == ["∅.above-repeat-guard"]
    assert (by_id["l-002"].goal, by_id["l-002"].queries) == ("queryless", [])

    outside = tmp_path / "planted.jsonl"
    outside.write_text(table.read_text(encoding="utf-8"), encoding="utf-8")
    table.unlink()
    table.symlink_to(outside)
    linked = family.leads_by_id(world_dir)
    assert {lid: lead.goal for lid, lead in linked.items()} == {
        "l-001": "find the pivot", "l-002": "queryless"}, (
        "a link at the table cost the leads their goals — the two halves are refused "
        "separately")
    assert all(not lead.queries for lead in linked.values()), (
        "a symlink at the queries table's name was followed and its target's rows read as "
        "this world's issued queries")


def test_lead_chain_joins_goal_params_payload_summary_rows_and_resolutions_per_lead(tmp_path):
    """`lead_chain(world, lead_id, resolutions_by_lead, *, leads=...)` — `world` the
    episode's bound reader derived at `worlds/<label>` (#1049) — is the
    per-lead join the page needs and the input builder already computes: goal (the surface's,
    off the lead's own `gather_raw/<lead>.lead.json`), params (the first issued query's),
    payload digests (in issue order), the gather summary, and this lead's resolutions — and
    NOT the raw rows: `document_rows` put every column of every query into the prompt as bytes
    the judge cannot act on (#1017 D3/O3).

    Observably true: each link carries the value the archived world actually holds. A lead
    with queries but no lead file and no summary reads `goal: None`, `summary: None` — absence
    stays absence.

    What failure looks like: the page re-implements the chain and reads one link differently
    from the prompt (O8's second named failing).
    """
    family = _family()
    ep = J.accepted_episode(tmp_path)
    world_dir = ep / "worlds" / "b"
    rows = [
        {"lead_id": "l-001", "query_id": "q1", "params": {"index": "logs-*"},
         "payload_digest": "d1"},
        {"lead_id": "l-001", "query_id": "q2", "params": {"index": "logs-2"},
         "payload_digest": "d2"},
        {"lead_id": "l-002", "query_id": "q3", "params": {"index": "alerts-*"},
         "payload_digest": "d3"},
    ]
    _write_issued(world_dir, rows)
    (world_dir / "gather_raw" / "l-001.lead.json").write_text(
        json.dumps({"lead_id": "l-001", "goal": "find the pivot"}), encoding="utf-8")
    resolutions = {"l-001": [{"before": "open", "after": "held"}]}
    by_id = family.leads_by_id(world_dir)

    chain = family.lead_chain(_world(ep, "b"), "l-001", resolutions, leads=by_id)

    assert chain["goal"] == "find the pivot"
    assert chain["params"] == {"index": "logs-*"}, "params is not the FIRST issued query's"
    assert chain["payload"] == ["d1", "d2"]
    assert chain["summary"] == (world_dir / "gather_summaries" / "l-001.md").read_text(
        encoding="utf-8")
    assert "document_rows" not in chain, "the raw rows are back in the chain"
    assert chain["resolutions"] == resolutions["l-001"]

    bare = family.lead_chain(_world(ep, "b"), "l-002", resolutions, leads=by_id)
    assert (bare["goal"], bare["summary"], bare["resolutions"]) == (None, None, [])
    assert bare["payload"] == ["d3"], "a lead with queries but no lead file lost its payload"


def test_lead_chain_never_reads_outside_the_graded_world_for_a_traversing_lead_id(tmp_path):
    """A lead id is MODEL-authored text that becomes a path. One that would read outside the
    graded world reads nothing — not the sibling's lead file, not the sibling's summary.

    Observably true: with world `c`'s `gather_raw/l-001.lead.json` and `gather_summaries/
    l-001.md` both really on disk, a lead id that resolves to EACH of them from `b` — the two
    joins read different subdirectories, so one id cannot reach both — yields `goal: None` for
    the one aimed at the lead file and a summary that is not `c`'s text for the one aimed at
    the summary. Positive control: the honest id reads `b`'s own lead file and summary.

    What failure looks like: a counterfactual sibling's report enters this world's prompt as
    a fact about the world being graded (O5/J14).
    """
    family = _family()
    ep = J.accepted_episode(tmp_path)
    b_dir, c_dir = ep / "worlds" / "b", ep / "worlds" / "c"
    (b_dir / "gather_raw" / "l-001.lead.json").write_text(
        json.dumps({"lead_id": "l-001", "goal": "OWN GOAL"}), encoding="utf-8")
    (c_dir / "gather_raw" / "l-001.lead.json").write_text(
        json.dumps({"lead_id": "l-001", "goal": "SIBLING GOAL"}), encoding="utf-8")
    sibling_summary = (c_dir / "gather_summaries" / "l-001.md").read_text(encoding="utf-8")
    assert "world c" in sibling_summary, "the fixture's sibling summary does not name world c"

    by_id = family.leads_by_id(b_dir)
    world_b = _world(ep, "b")
    honest = family.lead_chain(world_b, "l-001", {}, leads=by_id)
    leaked_goal = family.lead_chain(world_b, "../../c/gather_raw/l-001", {}, leads=by_id)
    leaked_summary = family.lead_chain(world_b, "../../c/gather_summaries/l-001", {},
                                       leads=by_id)

    assert honest["goal"] == "OWN GOAL", "positive control: b's own lead file not read"
    assert "world b" in (honest["summary"] or ""), "positive control: b's own summary not read"
    assert leaked_goal["goal"] is None, (
        f"a traversing lead id read world c's lead file: {leaked_goal['goal']!r}")
    assert "world c" not in (leaked_summary["summary"] or ""), (
        "a traversing lead id read world c's gather summary into world b's chain")


def test_json_mapping_answers_a_mapping_and_none_for_everything_else(tmp_path):
    """`json_mapping(bound, name)` is the ONE tolerance policy for a JSON artifact: a mapping,
    or `None` for an absent file, a corrupt one, or a JSON document that is not a mapping.

    Observably true: four inputs through the real file, four answers.

    What failure looks like: a fifth reader spells its own `except` set and a class one site
    survives takes another site's whole grade down.
    """
    family = _family()
    path = tmp_path / "artifact.json"
    bound = _io().bind(tmp_path)

    path.write_text(json.dumps({"alert_id": "a-1"}), encoding="utf-8")
    assert family.json_mapping(bound, "artifact.json") == {"alert_id": "a-1"}
    path.write_text(json.dumps([1, 2]), encoding="utf-8")
    assert family.json_mapping(bound, "artifact.json") is None, "a JSON list was answered as a mapping"
    path.write_text("{not json", encoding="utf-8")
    assert family.json_mapping(bound, "artifact.json") is None, "a corrupt document raised or was answered"
    assert family.json_mapping(bound, "absent.json") is None


def test_json_mapping_refuses_a_planted_link_and_reads_the_same_bytes_as_a_regular_file(
        tmp_path):
    """`json_mapping` is ONE home for the link policy as well as the tolerance policy: three of
    its five callers (`_world_alert_id`, `episode_alert`, `_read_provenance`) have no `lstat`
    screen of their own, and `provenance.json` is screened nowhere else in the judge — so a
    bare `read_text` here followed a link planted at `worlds/<X>/provenance.json` and handed the
    pass an attacker-chosen `commit` to `git show` every lesson at.

    Observably true: a regular file reads as its mapping (positive control); the same bytes
    behind a real symlink at the same name read as `None`; and `render._read_provenance` over a
    world whose stamp is such a link — or whose DIRECTORY is (#1049: the walk follows no
    component) — answers `{}` — no commit, rather than the planted one.
    """
    family, render = _family(), _render()
    outside = tmp_path / "planted.json"
    outside.write_text(json.dumps({"commit": "a" * 40, "dirty": False}), encoding="utf-8")
    regular = tmp_path / "artifact.json"
    regular.write_text(outside.read_text(encoding="utf-8"), encoding="utf-8")
    bound = _io().bind(tmp_path)
    assert family.json_mapping(bound, "artifact.json") == {"commit": "a" * 40, "dirty": False}, (
        "positive control: a regular file did not read")

    linked = tmp_path / "linked.json"
    linked.symlink_to(outside)
    assert family.json_mapping(bound, "linked.json") is None, "a symlink at the artifact's name was followed"

    ep = J.accepted_episode(tmp_path)
    stamp = ep / "worlds" / "b" / "provenance.json"
    stamp.unlink()
    stamp.symlink_to(outside)
    episode = _io().bind(ep)
    assert render._read_provenance(episode.under("worlds/b")) == {}, (
        "a planted link at provenance.json handed the pass the planted commit")
    (ep / "worlds" / "b").rename(ep / "worlds" / "b-real")
    (ep / "worlds" / "b-real" / "provenance.json").unlink()
    (ep / "worlds" / "b-real" / "provenance.json").write_text(outside.read_text(encoding="utf-8"), encoding="utf-8")
    (ep / "worlds" / "b").symlink_to(ep / "worlds" / "b-real")
    assert render._read_provenance(episode.under("worlds/b")) == {}, (
        "a planted link at worlds/<X> handed the pass the planted commit")


def test_lead_chain_refuses_a_planted_link_at_the_gather_raw_directory(tmp_path):
    """The lead file is screened at the DIRECTORY as well as the leaf, and the screen is the
    surface's own: `lead_repository.load_leads` `artifact_dir`s `gather_raw/` before it reads
    a lead file, so a link planted at the directory itself cannot put another tree's regular
    `.lead.json` through a leaf check that passes. The judge used to keep its own leaf-only
    read of the lead file beside the surface's, and the two disagreed here.

    Observably true: a real `gather_raw/l-001.lead.json` reads its goal through the chain
    (positive control); with `gather_raw/` replaced by a symlink to a directory holding the
    same file, the chain reads `goal: None`.
    """
    family = _family()
    ep = J.accepted_episode(tmp_path)
    world_dir = ep / "worlds" / "b"
    (world_dir / "gather_raw" / "l-001.lead.json").write_text(
        json.dumps({"lead_id": "l-001", "goal": "find the pivot"}), encoding="utf-8")
    chain = family.lead_chain(_world(ep, "b"), "l-001", {}, leads=family.leads_by_id(world_dir))
    assert chain["goal"] == "find the pivot", "positive control: the real lead file was not read"

    outside = tmp_path / "planted-gather_raw"
    outside.mkdir()
    (outside / "l-001.lead.json").write_text(
        json.dumps({"lead_id": "l-001", "goal": "SIBLING GOAL"}), encoding="utf-8")
    import shutil
    shutil.rmtree(world_dir / "gather_raw")
    (world_dir / "gather_raw").symlink_to(outside, target_is_directory=True)

    chain = family.lead_chain(_world(ep, "b"), "l-001", {}, leads=family.leads_by_id(world_dir))
    assert chain["goal"] is None, (
        "a link planted at gather_raw/ was followed to another tree's lead file")


def test_raw_manifest_reads_the_screened_manifest_and_refuses_a_link_or_a_non_mapping(tmp_path):
    """`raw_manifest(episode_dir)` is the judge's own screened read of `family.yaml`: the
    document as a mapping, or this design's refusal.

    Observably true: the episode's real manifest reads back with its `episode_id`; a real
    symlink planted at the manifest's name (to a byte-identical file outside the episode) and
    a manifest that parses to a list both raise `JudgeRefused`.

    What failure looks like: the grader honours a link the launcher refuses, and decides which
    worlds exist off a document the model planted.
    """
    family, refused = _family(), _refused()
    ep = J.accepted_episode(tmp_path)
    manifest = ep / "family.yaml"
    assert family.raw_manifest(ep)["episode_id"] == J.EPISODE_ID

    outside = tmp_path / "planted-family.yaml"
    outside.write_text(manifest.read_text(encoding="utf-8"), encoding="utf-8")
    manifest.unlink()
    manifest.symlink_to(outside)
    with pytest.raises(refused):
        family.raw_manifest(ep)

    manifest.unlink()
    manifest.write_text("- not\n- a mapping\n", encoding="utf-8")
    with pytest.raises(refused):
        family.raw_manifest(ep)


# ---------------------------------------------------------------------------------------
# Decision 3 — the tolerant grade reader, public
# ---------------------------------------------------------------------------------------


def test_read_grade_is_none_before_a_grade_and_the_same_record_grade_episode_returns_after(
        tmp_path):
    """`judge.read_grade(episode_dir)` is the ONE reader of `judge.yaml`: `None` for an
    ungraded episode, and afterwards the record — the same one `grade_episode` hands back on
    an already-graded episode, because that path reads through the same function.

    Observably true: before any pass `read_grade` is `None`; after one, `read_grade`'s
    `worlds`, `verdict_word`, `family_outcome` and `dispositions` equal the live pass's,
    and a second `grade_episode` (the existing-record path) equals `read_grade`.

    What failure looks like: the page parses YAML itself and disagrees with the pass on a
    truncated or pre-#1007 record — two readers of one file (O8).
    """
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []})
    read_grade = J.sym("learning.judge", "read_grade")
    assert read_grade(ep) is None, "an ungraded episode read as a grade"

    live = _grade(ep, tmp_path)
    stored = read_grade(ep)
    again = _grade(ep, tmp_path)

    assert stored is not None
    for field in ("worlds", "verdict_word", "family_outcome", "dispositions"):
        assert getattr(stored, field) == getattr(live, field), (
            f"read_grade's {field!r} differs from the pass that wrote it")
        assert getattr(again, field) == getattr(stored, field), (
            f"grade_episode's existing-record path and read_grade disagree on {field!r}")


def test_read_grade_refuses_a_planted_link_a_non_mapping_and_a_torn_record(tmp_path):
    """The idempotency record is read through the screened read AND the pass's own conversion:
    a link at `judge.yaml`'s name, a document that is not a mapping, and a document torn
    mid-write are all `JudgeRefused` — this design's one refusal class — never a grade and
    never a bare `yaml.YAMLError`.

    Observably true: the same mapping bytes as a regular `judge.yaml` read back (positive
    control); as a real symlink to that file outside the episode they raise `JudgeRefused`;
    a `judge.yaml` holding a YAML list raises `JudgeRefused`; a `judge.yaml` cut off inside
    an open flow mapping (`worlds: [\n  {world: b`) raises `JudgeRefused`.

    What failure looks like: a planted document parses as a mapping and `grade_episode` hands
    back an attacker-supplied grade without running the pass at all; or `read_grade` is a
    second parser that lets the YAML library's own error out past the boundary every other
    reader in this package converts at, so the page meets a traceback where the pass meets a
    refusal.
    """
    read_grade, refused = J.sym("learning.judge", "read_grade"), _refused()
    ep = J.accepted_episode(tmp_path)
    record = ep / "judge.yaml"
    outside = tmp_path / "planted-judge.yaml"
    outside.write_text(yaml.safe_dump(
        {"worlds": [{"world": "b", "bucket": None}], "verdict_word": "survived"}),
        encoding="utf-8")

    record.write_text(outside.read_text(encoding="utf-8"), encoding="utf-8")
    assert read_grade(ep).verdict_word == "survived", "positive control: a regular record"

    record.unlink()
    record.symlink_to(outside)
    with pytest.raises(refused):
        read_grade(ep)

    record.unlink()
    record.write_text("- not\n- a grade\n", encoding="utf-8")
    with pytest.raises(refused):
        read_grade(ep)

    record.write_text("worlds: [\n  {world: b", encoding="utf-8")
    with pytest.raises(refused):
        read_grade(ep)


def test_read_grade_reads_a_pre_oracle_record_with_defaults_and_invents_nothing(tmp_path):
    """A record in the pre-#1224 shape — no `validity`, no `family_outcome`, no
    `world_enqueued_rows`, a retired `withheld_findings` list, world rows carrying the retired
    ladder flags and no `systems` — reads without raising, with the reader's defaults for the
    family-level absences, the retired key ignored, and NOTHING invented on the rows.

    Observably true: `validity is None`, `family_outcome is None`, `world_enqueued_rows == 0`,
    `graded_worlds == {"b", "c"}`, and BOTH world rows come back as written — no `systems` the
    archive never stored. Row `c` is the TEMPTING one: `bucket: None` and no `systems`, the
    shape a reply that named no system would leave; a reader that back-fills `systems: []`
    there is inventing an answer the judge model never gave. Positive control: the same
    record carrying the fields reads them back.
    """
    read_grade = J.sym("learning.judge", "read_grade")
    ep = J.accepted_episode(tmp_path)
    old_row = {"world": "b", "bucket": "lead-quality", "holding_queried": True,
               "doctored_answer_served": False, "difference_shown": False,
               "withheld_reason": None}
    tempting_row = {"world": "c", "bucket": None, "holding_queried": True,
                    "doctored_answer_served": False, "difference_shown": False,
                    "withheld_reason": None}
    old = {"worlds": [old_row, tempting_row], "verdict_word": "caught",
           "episode_outcome": "gradable",
           "enqueued_rows": 0, "enqueued_to": "", "draws": {"completed": 1}, "knobs": {},
           "lessons_commit": None, "discard_evidence": {}, "queue_malformed_rows": 0,
           "unqueueable_findings": [], "withheld_findings": [{"world": "b"}]}
    (ep / "judge.yaml").write_text(yaml.safe_dump(old, sort_keys=False), encoding="utf-8")

    grade = read_grade(ep)

    assert grade.validity is None
    assert grade.family_outcome is None
    assert grade.world_enqueued_rows == 0
    assert grade.graded_worlds == frozenset({"b", "c"})
    assert J.rows(grade)["b"] == old_row, (
        "the reader rewrote a pre-#1224 world row — it invented a fact the archive never stored")
    assert J.rows(grade)["c"] == tempting_row, (
        "the reader rewrote a bucket-None row — it back-filled a `systems` answer the archive "
        f"never stored: {J.rows(grade)['c']}")
    for label in ("b", "c"):
        assert "systems" not in J.rows(grade)[label]

    new = dict(old, family_outcome="gradable", validity="usable",
               worlds=[dict(old_row, systems=["elastic"]), dict(tempting_row, systems=[])])
    (ep / "judge.yaml").write_text(yaml.safe_dump(new, sort_keys=False), encoding="utf-8")
    grade = read_grade(ep)
    assert (grade.family_outcome, grade.validity) == ("gradable", "usable")
    assert J.rows(grade)["b"]["systems"] == ["elastic"], (
        "positive control: a stored answer read back")
    assert J.rows(grade)["c"]["systems"] == [], (
        "a stored empty `systems` on a bucket-None row was overridden by the reader")


def test_read_grade_reads_back_a_not_graded_stamp(tmp_path):
    """An episode the pass declined to grade leaves a `not_graded` stamp, and the reader hands
    it back as one — `not_graded` set, `episode_outcome` the not-graded word — so a page can
    say "not graded, and here is why" rather than "graded, undecidable".

    Observably true: after a pass over an episode whose `outcome.yaml` says `refused`,
    `read_grade(ep).not_graded` is the `NotGradedStamp` the pass wrote, carrying that outcome
    word, and
    `episode_outcome == judge.NOT_GRADED`; positive control — a graded episode reads
    `not_graded is None`.
    """
    judge = _judge()
    read_grade = J.sym("learning.judge", "read_grade")
    skipped = J.accepted_episode(tmp_path, outcome="refused")
    graded = J.accepted_episode(tmp_path / "graded")

    _grade(skipped, tmp_path)
    _grade(graded, tmp_path)

    stamp = read_grade(skipped)
    assert stamp.not_graded is not None, "the not-graded stamp did not read back"
    assert stamp.not_graded.outcome == "refused", repr(stamp.not_graded)
    assert stamp.episode_outcome == judge.NOT_GRADED
    assert read_grade(graded).not_graded is None, "positive control: a graded episode"


@pytest.mark.parametrize("damage", [
    pytest.param({"world_findings": 5}, id="scalar-for-list"),
    pytest.param({"draws": 5}, id="scalar-for-mapping"),
    pytest.param({"verdict_word": None}, id="null-for-str"),
    pytest.param({"enqueued_rows": "3"}, id="numeric-text-for-int"),
    pytest.param({"worlds": [{"bucket": None}]}, id="row-naming-no-world"),
    pytest.param({"not_graded": {}}, id="empty-stamp"),
    pytest.param({"not_graded": "yes"}, id="non-mapping-stamp"),
    pytest.param({"not_graded": {"outcome": "refused", "reason": "x"},
                  "episode_outcome": "not-graded", "world_findings": 5}, id="damaged-stamp"),
    # A YAML mapping may key on `1:` — splatted as keywords that is `TypeError: keywords must
    # be strings` out of the constructor, a class no handler on the path converts.
    pytest.param({1: "planted"}, id="non-string-key"),
])
def test_a_record_of_the_wrong_shape_is_refused_not_defaulted_and_not_re_graded(
        tmp_path, damage):
    """The record is validated against `EpisodeGrade`'s own schema, strictly, and one that fails
    is `JudgeRefused` — from `read_grade` and from `grade_episode` alike — never a field
    defaulted to hide the damage, never a scalar passed through into a `dict`-typed field,
    never a bare `TypeError` (`list(5)`) past the docstring's promise of a refusal, and never a
    silent re-grade: the writer stages and `os.replace`s, so a record the pass could not have
    written is a planted or hand-edited file in a tree a box can reach, and a planted record
    must not buy three model calls per launch.

    Observably true: for each damage — a scalar where a list or a mapping belongs, `null`
    where a word belongs, `"3"` where a count belongs (no coercion), a world row naming no
    world, a `not_graded` stamp that is empty, not a mapping, or beside a damaged field, a
    top-level key that is not a string — the positive control (the same record without the
    damage) reads, the damaged record raises `JudgeRefused` from both entry points, and the
    file on disk is left exactly as planted.
    """
    read_grade, refused = J.sym("learning.judge", "read_grade"), _refused()
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []})
    sound = {"worlds": [{"world": "b", "bucket": None}], "verdict_word": "caught"}
    record = ep / "judge.yaml"

    record.write_text(yaml.safe_dump(sound), encoding="utf-8")
    assert read_grade(ep).verdict_word == "caught", "positive control: the sound record"

    planted = yaml.safe_dump({**sound, **damage})
    record.write_text(planted, encoding="utf-8")
    with pytest.raises(refused):
        read_grade(ep)
    with pytest.raises(refused):
        _grade(ep, tmp_path)
    assert record.read_text(encoding="utf-8") == planted, (
        "the pass re-graded past a record it could not read, replacing the planted file")


def test_read_grade_hands_back_the_same_record_for_a_str_episode_dir(tmp_path):
    """`read_grade` coerces its argument as `grade_episode` does, so a caller holding the path
    as text (a page reading it off YAML) gets a record whose `Path`-typed `episode_dir` IS a
    `Path` — and equal to the one `grade_episode` returns for the same episode.
    """
    read_grade = J.sym("learning.judge", "read_grade")
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []})
    live = _grade(ep, tmp_path)

    stored = read_grade(str(ep))

    assert isinstance(stored.episode_dir, Path), type(stored.episode_dir)
    assert stored == live, "read_grade(str) is not the record grade_episode returned"


def test_the_draws_directory_has_one_name_and_one_public_reader(tmp_path):
    """The per-draw documents `worlds/<X>/judge/<n>.yaml` are the page's findings source (design
    §3), so their reader is PUBLIC — `enqueue.draws_on_disk`, in `__all__` — and the directory
    is `archive.DRAWS_DIRNAME`, held by the writer and the reader as the archive's own object.

    Observably true: after a real pass, `draws_on_disk(ep / WORLDS_DIRNAME / "b" /
    DRAWS_DIRNAME)` answers that world's completed draws keyed by draw index — the reader finds
    the directory the writer wrote.
    """
    enqueue = J.mod("learning.judge.enqueue")
    assert "draws_on_disk" in enqueue.__all__, "the per-draw reader is not exported"
    # NO MODULE HOLDS THE NAME ANY MORE (#1077 D7). The old form of this check asserted the
    # writer and the reader held the same OBJECT as `archive.DRAWS_DIRNAME` — which was true,
    # and was still a second home. Now neither module binds either name at all; both ask the
    # owner for a path, so there is nothing left for a rename to strand.
    for module_name in ("learning.judge", "learning.judge.enqueue",
                        "learning.branch.cli", "learning.branch.archive"):
        module = J.mod(module_name)
        for held in ("DRAWS_DIRNAME", "WORLDS_DIRNAME", "WORLDS_SUBDIR"):
            assert not hasattr(module, held), f"{module_name} still binds {held}"
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []})

    grade = _grade(ep, tmp_path)
    # `draws_on_disk` now takes the episode-root view plus the label (#1133 rev 2), never a
    # draws dir path directly.
    with bind(ep) as view:
        draws = enqueue.draws_on_disk(view, "b")

    assert grade.draws["completed"] > 0, "positive control: the pass completed no draw"
    assert sorted(draws) == list(range(grade.draws["completed"])), (
        f"the reader did not find the draws the pass wrote: {sorted(draws)}")


def test_draws_on_disk_skips_a_link_planted_at_a_draws_name(tmp_path):
    """The one reader of the draw files reads each leaf through the screened read, like every
    other reader of the episode tree: a symlink planted at `worlds/<X>/judge/<n>.yaml` — a
    tree a sibling's box can write — is SKIPPED, never followed, so the bare re-enqueue path
    cannot queue another file's findings as this episode's own.

    Observably true: a directory holding a regular `0.yaml` and a `1.yaml` that is a link to
    a document outside the world answers `{0: ...}` — the link's target's findings are absent;
    positive control — the same bytes as a regular `1.yaml` are read.
    """
    enqueue = J.mod("learning.judge.enqueue")
    owner = J.mod("_episode_paths")
    # `draws_on_disk` now takes the episode-root view plus the label (#1133 rev 2): the draws
    # dir it reads is `worlds/<label>/judge`, derived from the episode root, never handed in
    # directly as a path.
    episode_dir = tmp_path / "ep"
    label = "b"
    draw_dir = owner.EpisodePaths(episode_dir).world(label).draws
    draw_dir.mkdir(parents=True)
    outside = tmp_path / "outside.yaml"
    outside.write_text("findings: [{bucket: planted}]\n", encoding="utf-8")
    (draw_dir / "0.yaml").write_text("findings: []\n", encoding="utf-8")
    (draw_dir / "1.yaml").symlink_to(outside)

    with bind(episode_dir) as view:
        assert enqueue.draws_on_disk(view, label) == {0: {"findings": []}}, (
            "a link planted at a draw's name was followed: its target's findings were read "
            "back as this episode's draw")

    (draw_dir / "1.yaml").unlink()
    (draw_dir / "1.yaml").write_text(outside.read_text(encoding="utf-8"), encoding="utf-8")
    with bind(episode_dir) as view:
        assert sorted(enqueue.draws_on_disk(view, label)) == [0, 1], (
            "positive control: the same bytes as a regular file were not read")

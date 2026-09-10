"""#1025 O8 (prep 2 / 2b) — one episode reader, one home for each file name, and the stored
`has_refused` flag.

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
   `world_review_block`, `staged_patterns`, `world_pattern`, `own_h_rows`, `raw_manifest`, and,
   moved off `render.py`, `queries_by_lead`, `lead_chain` and `json_mapping`. Those seven
   private spellings are gone, the input builder IMPORTS the lead-chain trio
   (its attributes are `family`'s objects, and no constant in `render.py` names the queries
   table or the lead files), and the `leads` view a real `render()` produces equals what
   `family.lead_chain` answers over the same world. Each accessor's behaviour is driven on the
   public name against a real archived world, so the move is a move and not a rename plus a
   rewrite.
3. **The tolerant `judge.yaml` reader is public: `judge.read_grade(episode_dir)`** — `None`
   for an ungraded episode, a refusal for a planted link or a non-mapping (real faults through
   the real primitive), a pre-#1007 record read with today's defaults and nothing invented,
   and the SAME record `grade_episode` returns on an already-graded episode.

Prep 2b / O3: the `lead-quality` vs `None` branch of the bucket ladder turns on `has_refused`,
which the pass computed and never wrote. It is now on every world row `judge.yaml` writes
that carries the other ladder flags (a tier-1/tier-2 ungradable early return carries none of
them, as before) — true iff the world's served ledger holds a row on the holding system
whose `source` is the ledger's own `refused` — and it survives the round trip through
`read_grade`. The ladder pairing (a refused H row buckets `None`, the same world without one
buckets `lead-quality`) is the positive/negative control, driven through the real pass; the
flag is then pinned as a fact about the ROWS on every ladder branch where a bucket-derived
reading would answer differently (doctored + refused, fault-only, `" Elastic "`), and J3's
first-row-wins dedup — a refused row sharing the served row's pair-key never reaches the
ladder — is made explicit so a change to it is visible here.

RED AGAINST THE PRE-CHANGE TREE was the expected state (the constants, the public names and
the field did not exist; the census found five modules spelling `review.yaml`), and the tests
were then tightened against an adversarial implementation. Every import goes through `J.mod`
/ `J.sym` PER TEST so a missing target is one failure per test, never a collection error.
"""
from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest
import yaml

from defender._run_paths import RunPaths
from defender.tests import _judge_921 as J
from defender.tests._spec791 import PROJECT_PROFILE

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    """Every configured root inside `tmp_path`, so a pass this file drives lands in this test's
    own tree — never the checkout's runs base or its real `learning/_pending/`."""
    monkeypatch.setenv(J.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(J.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    monkeypatch.setenv(J.STATE_DIR_ENV, str(tmp_path / "learning-state"))


def _judge():
    return J.mod("learning.judge")


def _family():
    return J.mod("learning.judge.family")


def _render():
    return J.mod("learning.judge.render")


def _archive():
    return J.mod("learning.branch.archive")


def _refused():
    """The judge's own refusal class, resolved BEFORE the `raises` block opens — a missing
    target fails at the call rather than satisfying `raises(Exception)`."""
    return J.sym("learning.judge", "JudgeRefused")


def _grade(ep: Path, tmp_path: Path):
    """The real grading pass over `ep`, through its own seams — never a live provider."""
    judge = J.FakeJudge(default=J.as_reply_text(J.reply_doc()))
    return _judge().grade_episode(ep, judge=judge, runs_base=tmp_path / "defender-runs")


def _passthrough(label: str) -> dict:
    """A queried-and-undoctored H row: the shape that lands in `lead-quality` on its own."""
    return J.ledger_row(source="passthrough", world_label=label)


def _write_issued(world_dir: Path, rows: list[dict]) -> Path:
    """The world's queries table, written the one way this file writes it: one JSON object per
    line at the writer's own path (`RunPaths.executed_queries`), so the four scenarios that
    need a table spell neither the name nor the JSONL join."""
    table = RunPaths(world_dir).executed_queries
    table.write_text(
        "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows), encoding="utf-8")
    return table


def _refused_row(label: str, *, system: str = J.HOLDING_SYSTEM) -> dict:
    """The ledger's own `refused` word, imported rather than re-spelled — the flag keys on it.

    Its OWN params: the ledger reader is first-row-wins on a duplicate pair-key (J3), so a
    refused row sharing the passthrough row's query would be read as that row's duplicate and
    never reach the flag — a real refusal is of a different query than the one that was served.
    """
    refused = J.sym("learning.branch.ledger", "REFUSED")
    return J.ledger_row(source=refused, world_label=label, system=system,
                        params={"index": f"{J.EVENTS_PATTERN},audit-*"},
                        payload="this ES|QL query's FROM clause addresses several corpora")


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
    ("learning.branch.review", "REVIEW_NAME"),
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
    for root in _CODE_ROOTS:
        base = package / root
        files = [base] if base.is_file() else sorted(base.rglob("*.py"))
        for path in files:
            out[path.relative_to(package).as_posix()] = path.read_text(encoding="utf-8")
    assert _ARCHIVE_MODULE in out, f"the census never saw {_ARCHIVE_MODULE}: {sorted(out)[:5]}"
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


def test_archive_is_the_one_home_for_the_three_episode_record_names():
    """`archive.py` — which already owns `WORLDS_DIRNAME`, `ALERT_NAME` and the other archived
    names — owns the three episode-level record names too, with the values every reader today
    spells for itself.

    Observably true: `archive.REVIEW_NAME == "review.yaml"`, `SAMPLES_NAME == "samples.yaml"`,
    `JUDGE_NAME == "judge.yaml"`.

    What failure looks like: the constants are absent (four modules keep their own), or one is
    present under a different value than the file the launcher actually writes.
    """
    archive = _archive()

    for name, value in _RECORD_NAMES.items():
        assert getattr(archive, name) == value, (
            f"archive.{name} is {getattr(archive, name)!r}, not {value!r}")


def test_each_episode_record_name_is_spelled_in_exactly_one_shipped_module():
    """O8's census, run over the tree's SYNTAX: across the shipped code roots the strings
    `review.yaml`, `samples.yaml` and `judge.yaml` each occur INSIDE a code string in ONE
    module — `archive.py` — and a BINDING of `REVIEW_NAME` / `SAMPLES_NAME` / `JUDGE_NAME`
    occurs only there. Every other module imports the name; an import is not a binding.

    Through `ast`, not a regex over the text: a regex sees `"review.yaml"` and misses
    `"review" ".yaml"` (folded by the parser into one constant), `"review" + ".yaml"` and
    `f"review.yaml"` — every one of which is the same second home wearing a disguise. And by
    CONTAINMENT, not equality: the spellings that drift are the embedded ones — a pointer
    written into `judge.yaml` (`f"{ep}/review.yaml#..."`), the family prompt's worked example,
    an unqueueable reason — which an exact-match census walked straight past while the
    allowlist beside them followed the constant. Docstrings are exempt: prose may name a file.
    Bindings off the same AST, in Store context, so `NAME: str = ...`, a tuple target and a
    walrus all count and a docstring line that merely looks like an assignment does not.

    Observably true: the set of modules whose code strings contain each name is `{archive.py}`,
    and so is the set of modules binding any of the three constants.

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
        assert spelled_in == [_ARCHIVE_MODULE], (
            f"{file_name!r} is spelled inside a code string in {spelled_in}; O8 wants exactly "
            f"one home, {_ARCHIVE_MODULE}, with every other module importing the name — a "
            "pointer, a prompt example or a message spells it as f\"...{REVIEW_NAME}...\"")

    bound_in = sorted(
        m for m, (_strings, bound) in census.items() if bound & _RECORD_NAMES.keys())
    assert bound_in == [_ARCHIVE_MODULE], (
        f"REVIEW_NAME / SAMPLES_NAME / JUDGE_NAME are BOUND in {bound_in}; only "
        f"{_ARCHIVE_MODULE} may define them — a re-export is an import, not a binding")


def test_every_reader_of_a_record_name_holds_the_archives_own_object():
    """Every shipped module that names one of the three records holds `archive`'s OWN string
    — the attribute `is` the archive's, which only an import produces. A module that
    re-spelled the value under the same name would compare `==` and not `is`.

    Observably true: for each `(module, attribute)` in `_IMPORTERS`, the attribute exists and
    is identical to the archive's constant it stands for.

    What failure looks like: `cli.REVIEW_NAME == "review.yaml"` holds while `cli` never
    imported it — the census above catches the spelling; this catches the object.
    """
    archive = _archive()

    for module_name, attribute in _IMPORTERS:
        module = J.mod(module_name)
        assert hasattr(module, attribute), f"{module_name}.{attribute} is gone"
        assert getattr(module, attribute) is getattr(archive, attribute), (
            f"{module_name}.{attribute} is not archive.{attribute}'s own object — a "
            "re-spelling, not an import")


# ---------------------------------------------------------------------------------------
# Decision 2 — the derived accessors: one home, public names, the same behaviour
# ---------------------------------------------------------------------------------------

#: The five `family.py` privates `render.py` imported across the module line, and the two
#: `render.py` privates the page needs — each as `(private spelling, public spelling)`.
_MOVED = (
    ("_world_review_block", "world_review_block"),
    ("_staged_patterns", "staged_patterns"),
    ("_world_pattern", "world_pattern"),
    ("_own_h_rows", "own_h_rows"),
    ("_raw_manifest", "raw_manifest"),
    ("_queries_by_lead", "queries_by_lead"),
    ("_lead_chain", "lead_chain"),
)


def test_family_is_the_one_home_for_the_derived_accessors_under_public_names():
    """The episode reader's derived accessors have ONE home, `judge/family.py`, and public
    names — nothing crosses a module line as a private any more.

    Observably true: `family` exposes `world_review_block`, `staged_patterns`, `world_pattern`,
    `own_h_rows`, `raw_manifest`, `queries_by_lead`, `lead_chain` and `json_mapping` as
    callables; neither `family` nor `render` carries the underscore spelling of any of them;
    the input builder IMPORTS the lead-chain trio — `render.lead_chain`, `render.queries_by_
    lead` and `render.json_mapping` are `family`'s own objects — and no constant in `render.py`
    names `executed_queries.jsonl` or `gather_raw`, the two reads that belong to the accessors
    (which spell them through `RunPaths`, the writer's own accessor, not as literals).

    This is a name census over the seven accessors the design named (`render.py`'s other
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
    for name in ("lead_chain", "queries_by_lead", "json_mapping"):
        assert getattr(render, name, None) is getattr(family, name), (
            f"render.{name} is not family.{name} — the input builder does not import the "
            "accessor it renders the per-lead chain with; that IS the one-home observable")

    render_source = Path(render.__file__).read_text(encoding="utf-8")
    leftover = {"executed_queries.jsonl", "gather_raw"} & _string_constants(
        render_source, render.__file__)
    assert not leftover, (
        f"render.py still names {sorted(leftover)} as a constant — the queries table and the "
        "lead files are read by family's accessors now, so a spelling here is a second reader")


def test_the_input_builders_leads_view_is_what_family_lead_chain_answers(tmp_path):
    """The per-lead chain the judge is SHOWN is the chain `family.lead_chain` computes — the
    behavioural half of "one home": a real `render()` over an archived world produces a
    `leads` view equal, lead for lead, to `lead_chain` over the same world's own facts.

    Observably true: `render(ep, "b").leads["l-001"]` equals `family.lead_chain(world_dir,
    "l-001", facts.resolutions_by_lead, issued=family.queries_by_lead(world_dir))`,
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

    shown = _render().render(ep, "b", runs_base=base).leads
    facts = family.read_world_facts(ep, "b", episode_token=J.EPISODE_TOKEN)
    expected = family.lead_chain(world_dir, "l-001", facts.resolutions_by_lead,
                                 issued=family.queries_by_lead(world_dir))

    assert expected["goal"] == "find the pivot", "the fixture's lead file was not read"
    assert expected["payload"] == ["d1", "d2"], "the fixture's queries were not read"
    assert shown["l-001"] == expected, (
        "the judge is shown a per-lead chain that differs from family.lead_chain's over the "
        f"same world:\n{shown['l-001']}\n!=\n{expected}")


def test_queries_by_lead_groups_issued_rows_and_drops_conduct_rows_in_one_parse(tmp_path):
    """`queries_by_lead(world_dir)` reads the world's `executed_queries.jsonl` ONCE and hands
    back `{lead_id: [rows in file order]}` — the issued queries only.

    Observably true: two rows for `l-001` and one for `l-002` group under their leads in file
    order; a `∅.`-prefixed sentinel row (the writer's own conduct partition, `is_reserved_query_
    id`) and a row with no `lead_id` are in neither group.

    What failure looks like: the sentinel reaches VIEW 1 as a query the world issued — a
    defender failure invented out of a call the defender was refused (the bug
    `family.queries_by_lead`'s docstring records being fixed once already, for the actor).
    """
    ep = J.accepted_episode(tmp_path)
    world_dir = ep / "worlds" / "b"
    rows = [
        {"lead_id": "l-001", "query_id": "q1", "params": {"index": "logs-*"},
         "payload_digest": "d1"},
        {"lead_id": "l-002", "query_id": "q3", "params": {"index": "alerts-*"},
         "payload_digest": "d3"},
        {"lead_id": "l-001", "query_id": "q2", "params": {"index": "logs-2"},
         "payload_digest": "d2"},
        {"lead_id": "l-001", "query_id": "∅.above-repeat-guard", "params": {},
         "payload_digest": "dx"},
        {"query_id": "q9", "params": {}},
    ]
    _write_issued(world_dir, rows)

    grouped = _family().queries_by_lead(world_dir)

    assert {lead: [r["query_id"] for r in group] for lead, group in grouped.items()} == {
        "l-001": ["q1", "q2"], "l-002": ["q3"]}, (
        f"the sentinel or the lead-less row reached a lead's group, or order was lost: {grouped}")


def test_queries_by_lead_refuses_a_planted_link_at_the_table_name(tmp_path):
    """The queries table is read through the archive's own `lstat` posture: a link at
    `executed_queries.jsonl` reads as NO table, not as the target's rows.

    Observably true: the same bytes as a regular file group into leads (positive control); as
    a real symlink to a file outside the world they group into nothing.

    What failure looks like: another tree's rows enter VIEW 1 as this world's own conduct.
    """
    ep = J.accepted_episode(tmp_path)
    world_dir = ep / "worlds" / "b"
    row = {"lead_id": "l-001", "query_id": "q1", "params": {}}
    table = _write_issued(world_dir, [row])
    assert list(_family().queries_by_lead(world_dir)) == ["l-001"], (
        "positive control: a regular table did not group")

    outside = tmp_path / "planted.jsonl"
    outside.write_text(table.read_text(encoding="utf-8"), encoding="utf-8")
    table.unlink()
    table.symlink_to(outside)

    assert _family().queries_by_lead(world_dir) == {}, (
        "a symlink at the queries table's name was followed and its target's rows read as this "
        "world's issued queries")


def test_lead_chain_joins_goal_params_payload_summary_rows_and_resolutions_per_lead(tmp_path):
    """`lead_chain(world_dir, lead_id, resolutions_by_lead, *, issued=...)` is the
    per-lead join the page needs and the input builder already computes: goal (off the lead's
    own `gather_raw/<lead>.lead.json`), params (the first issued query's), payload digests (in
    issue order), the gather summary, the document rows, and this lead's resolutions.

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
    grouped = family.queries_by_lead(world_dir)

    chain = family.lead_chain(world_dir, "l-001", resolutions, issued=grouped)

    assert chain["goal"] == "find the pivot"
    assert chain["params"] == {"index": "logs-*"}, "params is not the FIRST issued query's"
    assert chain["payload"] == ["d1", "d2"]
    assert chain["summary"] == (world_dir / "gather_summaries" / "l-001.md").read_text(
        encoding="utf-8")
    assert chain["document_rows"] == grouped["l-001"]
    assert chain["resolutions"] == resolutions["l-001"]

    bare = family.lead_chain(world_dir, "l-002", resolutions, issued=grouped)
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

    honest = family.lead_chain(b_dir, "l-001", {}, issued={})
    leaked_goal = family.lead_chain(b_dir, "../../c/gather_raw/l-001", {}, issued={})
    leaked_summary = family.lead_chain(b_dir, "../../c/gather_summaries/l-001", {}, issued={})

    assert honest["goal"] == "OWN GOAL", "positive control: b's own lead file not read"
    assert "world b" in (honest["summary"] or ""), "positive control: b's own summary not read"
    assert leaked_goal["goal"] is None, (
        f"a traversing lead id read world c's lead file: {leaked_goal['goal']!r}")
    assert "world c" not in (leaked_summary["summary"] or ""), (
        "a traversing lead id read world c's gather summary into world b's chain")


def test_json_mapping_answers_a_mapping_and_none_for_everything_else(tmp_path):
    """`json_mapping(path)` is the ONE tolerance policy for a JSON artifact: a mapping, or
    `None` for an absent file, a corrupt one, or a JSON document that is not a mapping.

    Observably true: four inputs through the real file, four answers.

    What failure looks like: a fifth reader spells its own `except` set and a class one site
    survives takes another site's whole grade down.
    """
    family = _family()
    path = tmp_path / "artifact.json"

    path.write_text(json.dumps({"alert_id": "a-1"}), encoding="utf-8")
    assert family.json_mapping(path) == {"alert_id": "a-1"}
    path.write_text(json.dumps([1, 2]), encoding="utf-8")
    assert family.json_mapping(path) is None, "a JSON list was answered as a mapping"
    path.write_text("{not json", encoding="utf-8")
    assert family.json_mapping(path) is None, "a corrupt document raised or was answered"
    assert family.json_mapping(tmp_path / "absent.json") is None


def test_json_mapping_refuses_a_planted_link_and_reads_the_same_bytes_as_a_regular_file(
        tmp_path):
    """`json_mapping` is ONE home for the link policy as well as the tolerance policy: three of
    its five callers (`_world_alert_id`, `episode_alert`, `_read_provenance`) have no `lstat`
    screen of their own, and `provenance.json` is screened nowhere else in the judge — so a
    bare `read_text` here followed a link planted at `worlds/<X>/provenance.json` and handed the
    pass an attacker-chosen `commit` to `git show` every lesson at.

    Observably true: a regular file reads as its mapping (positive control); the same bytes
    behind a real symlink at the same name read as `None`; and `render._read_provenance` over a
    world whose stamp is such a link answers `{}` — no commit, rather than the planted one.
    """
    family, render = _family(), _render()
    outside = tmp_path / "planted.json"
    outside.write_text(json.dumps({"commit": "a" * 40, "dirty": False}), encoding="utf-8")
    regular = tmp_path / "artifact.json"
    regular.write_text(outside.read_text(encoding="utf-8"), encoding="utf-8")
    assert family.json_mapping(regular) == {"commit": "a" * 40, "dirty": False}, (
        "positive control: a regular file did not read")

    linked = tmp_path / "linked.json"
    linked.symlink_to(outside)
    assert family.json_mapping(linked) is None, "a symlink at the artifact's name was followed"

    ep = J.accepted_episode(tmp_path)
    stamp = ep / "worlds" / "b" / "provenance.json"
    stamp.unlink()
    stamp.symlink_to(outside)
    assert render._read_provenance(ep / "worlds" / "b") == {}, (
        "a planted link at provenance.json handed the pass the planted commit")


def test_lead_chain_refuses_a_planted_link_at_the_gather_raw_directory(tmp_path):
    """The lead file is screened at the DIRECTORY as well as the leaf: `artifact_file` lstats
    the entry it is given, so a link planted at `gather_raw/` itself put another tree's regular
    `.lead.json` through a leaf check that passes — the opposite posture from
    `lead_repository.load_leads`, which `artifact_dir`s the same directory.

    Observably true: a real `gather_raw/l-001.lead.json` reads its goal (positive control);
    with `gather_raw/` replaced by a symlink to a directory holding the same file, the chain
    reads `goal: None`.
    """
    family = _family()
    ep = J.accepted_episode(tmp_path)
    world_dir = ep / "worlds" / "b"
    (world_dir / "gather_raw" / "l-001.lead.json").write_text(
        json.dumps({"lead_id": "l-001", "goal": "find the pivot"}), encoding="utf-8")
    assert family.lead_chain(world_dir, "l-001", {}, issued={})["goal"] == "find the pivot", (
        "positive control: the real lead file was not read")

    outside = tmp_path / "planted-gather_raw"
    outside.mkdir()
    (outside / "l-001.lead.json").write_text(
        json.dumps({"lead_id": "l-001", "goal": "SIBLING GOAL"}), encoding="utf-8")
    import shutil
    shutil.rmtree(world_dir / "gather_raw")
    (world_dir / "gather_raw").symlink_to(outside, target_is_directory=True)

    assert family.lead_chain(world_dir, "l-001", {}, issued={})["goal"] is None, (
        "a link planted at gather_raw/ was followed to another tree's lead file")


def test_world_review_block_joins_by_label_and_answers_none_for_an_absent_or_odd_entry():
    """`world_review_block(review, label)` is this world's `reachability` sub-block off the
    review record, joined BY NAME — or `None` when there is no mapping there to read.

    Observably true: a labelled entry with a mapping block is returned; an entry that is a
    string, an entry whose block is a list, a label the review never names, and a `worlds`
    that is not a mapping all read `None`.
    """
    family = _family()
    review = {"worlds": {
        "b": {"reachability": {"reachable_by_capture": True}},
        "c": "not an entry",
        "d": {"reachability": [1]},
    }}

    assert family.world_review_block(review, "b") == {"reachable_by_capture": True}
    for label in ("c", "d", "zz"):
        assert family.world_review_block(review, label) is None, (
            f"label {label!r} read a block where the review holds none")
    assert family.world_review_block({"worlds": []}, "b") is None


def test_staged_patterns_and_world_pattern_read_the_overlay_the_same_way():
    """`staged_patterns(overlay)` is EVERY staged pattern in a stable (sorted) order — O5's
    per-pattern domain; `world_pattern(overlay, *, holding_system=)` is the single
    representative anchor: the first of those, or the holding system's own name for a
    patch-only world; and `sample_patterns(overlay, *, holding_system=)` is the list the row's
    `sample_unavailable_patterns` and the prompt's sample section BOTH quantify over — every
    staged pattern, or the fallback — spelled ONCE (at each site as `staged_patterns(o) or
    [...]`, the patch-only fallback could change in one and not the other with no test between).

    Observably true: a two-pattern overlay enumerates both, sorted, and anchors on the first;
    a patch-only overlay enumerates nothing and anchors on `holding_system`; an overlay that is
    not a mapping enumerates nothing; `sample_patterns` is the enumeration or `[holding_system]`,
    and `world_pattern` is its first element for both shapes.
    """
    family = _family()
    two = J.overlay(elastic={
        **J.elastic_overlay("logs-b", inject=[{"_id": 1}]),
        **J.elastic_overlay("alerts-a", exclude={"term": {"x": 1}}),
    })
    patch_only = J.overlay(patches={"p": "patched"})

    assert family.staged_patterns(two) == ["alerts-a", "logs-b"]
    assert family.world_pattern(two, holding_system="elastic") == "alerts-a"
    assert family.staged_patterns(patch_only) == []
    assert family.world_pattern(patch_only, holding_system="elastic") == "elastic"
    assert family.staged_patterns(None) == []
    assert family.staged_patterns({"elastic": {}}) == []
    assert family.sample_patterns(two, holding_system="elastic") == ["alerts-a", "logs-b"]
    assert family.sample_patterns(patch_only, holding_system="elastic") == ["elastic"]
    for overlay in (two, patch_only):
        assert family.world_pattern(overlay, holding_system="elastic") == (
            family.sample_patterns(overlay, holding_system="elastic")[0])


def test_own_h_rows_selects_the_holding_systems_rows_after_strip_and_casefold():
    """`own_h_rows(rows, holding_system)` is the world's rows ON H — `system` compared after
    strip+casefold, the same normalisation J1 validated H under; a row with no usable `system`
    is not H's.
    """
    family = _family()
    rows = [{"system": "elastic", "n": 1}, {"system": " Elastic ", "n": 2},
            {"system": "cmdb", "n": 3}, {"system": None, "n": 4}, {"n": 5}]

    assert [r["n"] for r in family.own_h_rows(rows, "elastic")] == [1, 2]


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
    `worlds`, `verdict_word`, `family_outcome` and `withheld_findings` equal the live pass's,
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
    for field in ("worlds", "verdict_word", "family_outcome", "withheld_findings"):
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


def test_read_grade_reads_a_pre_1007_record_with_defaults_and_invents_nothing(tmp_path):
    """A record in the pre-#1007 shape — no `family_outcome`, no `world_enqueued_rows`, no
    `withheld_findings`, world rows without `has_refused` — reads without raising, with the
    reader's defaults for the family-level absences and NOTHING invented on the rows.

    Observably true: `family_outcome is None`, `world_enqueued_rows == 0`,
    `withheld_findings == []`, `graded_worlds == {"b", "c"}`, and BOTH world rows come back
    as written — no `has_refused` key the archive never stored (O3: where the ladder's branch
    depends on a fact the archive does not store, the page says so rather than inventing one).
    Row `c` is the TEMPTING one: queried, undoctored, `bucket: None` — exactly the shape the
    ladder's refused branch produces, and exactly the shape a fault-adjacent or pre-#1007 row
    also has; a reader that back-fills `has_refused: True` there is inventing the fact, and
    the page then reports a refusal the archive never recorded. Positive control: the same
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
           "unqueueable_findings": []}
    (ep / "judge.yaml").write_text(yaml.safe_dump(old, sort_keys=False), encoding="utf-8")

    grade = read_grade(ep)

    assert grade.family_outcome is None
    assert grade.world_enqueued_rows == 0
    assert grade.withheld_findings == []
    assert grade.graded_worlds == frozenset({"b", "c"})
    assert J.rows(grade)["b"] == old_row, (
        "the reader rewrote a pre-#1007 world row — it invented a fact the archive never stored")
    assert J.rows(grade)["c"] == tempting_row, (
        "the reader rewrote a queried, undoctored, bucket-None row — it back-filled a "
        f"`has_refused` the archive never stored: {J.rows(grade)['c']}")
    for label in ("b", "c"):
        assert "has_refused" not in J.rows(grade)[label]

    new = dict(old, family_outcome="gradable", withheld_findings=[{"world": "b"}],
               worlds=[dict(old_row, has_refused=True), dict(tempting_row, has_refused=False)])
    (ep / "judge.yaml").write_text(yaml.safe_dump(new, sort_keys=False), encoding="utf-8")
    grade = read_grade(ep)
    assert (grade.family_outcome, grade.withheld_findings) == ("gradable", [{"world": "b"}])
    assert J.rows(grade)["b"]["has_refused"] is True, "positive control: a stored flag read back"
    assert J.rows(grade)["c"]["has_refused"] is False, (
        "a stored `has_refused: False` on a bucket-None row was overridden by the reader")


def test_read_grade_reads_back_a_not_graded_stamp(tmp_path):
    """An episode the pass declined to grade leaves a `not_graded` stamp, and the reader hands
    it back as one — `not_graded` set, `episode_outcome` the not-graded word — so a page can
    say "not graded, and here is why" rather than "graded, undecidable".

    Observably true: after a pass over an `incomplete` review, `read_grade(ep).not_graded` is
    the `NotGradedStamp` the pass wrote, carrying the review's outcome word, and
    `episode_outcome == judge.NOT_GRADED`; positive control — a graded episode reads
    `not_graded is None`.
    """
    judge = _judge()
    read_grade = J.sym("learning.judge", "read_grade")
    skipped = J.accepted_episode(tmp_path, outcome="incomplete")
    graded = J.accepted_episode(tmp_path / "graded")

    _grade(skipped, tmp_path)
    _grade(graded, tmp_path)

    stamp = read_grade(skipped)
    assert stamp.not_graded is not None, "the not-graded stamp did not read back"
    assert stamp.not_graded.outcome == "incomplete", repr(stamp.not_graded)
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
    pytest.param({"not_graded": {"outcome": "incomplete", "reason": "x"},
                  "episode_outcome": "not-graded", "world_findings": 5}, id="damaged-stamp"),
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
    world, a `not_graded` stamp that is empty, not a mapping, or beside a damaged field — the
    positive control (the same record without the damage) reads, the damaged record raises
    `JudgeRefused` from both entry points, and the file on disk is left exactly as planted.
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
    archive, enqueue = _archive(), J.mod("learning.judge.enqueue")
    assert "draws_on_disk" in enqueue.__all__, "the per-draw reader is not exported"
    for module_name in ("learning.judge", "learning.judge.enqueue"):
        module = J.mod(module_name)
        assert module.DRAWS_DIRNAME is archive.DRAWS_DIRNAME, f"{module_name} re-spells it"
        assert module.WORLDS_DIRNAME is archive.WORLDS_DIRNAME, f"{module_name} re-spells it"
    assert not hasattr(J.mod("learning.branch.cli"), "WORLDS_SUBDIR"), (
        "cli.py still carries a second constant for the worlds directory")
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []})

    grade = _grade(ep, tmp_path)
    draws = enqueue.draws_on_disk(ep / archive.WORLDS_DIRNAME / "b" / archive.DRAWS_DIRNAME)

    assert grade.draws["completed"] > 0, "positive control: the pass completed no draw"
    assert sorted(draws) == list(range(grade.draws["completed"])), (
        f"the reader did not find the draws the pass wrote: {sorted(draws)}")


# ---------------------------------------------------------------------------------------
# Prep 2b / O3 — `has_refused`, stored beside the flags the ladder reads
# ---------------------------------------------------------------------------------------


def test_every_graded_world_row_stores_has_refused_beside_the_other_flags(tmp_path):
    """`has_refused: bool` is on every world row the pass writes that carries the other ladder
    flags — beside `holding_queried`, `doctored_answer_served` and `difference_shown`; a tier-1
    or tier-2 ungradable early return carries none of the four — true iff the world's served
    ledger holds
    a row on the HOLDING SYSTEM whose `source` is the ledger's `refused`.

    Observably true, three worlds through the real pass: `b` (a passthrough plus a refused row
    on H) stores `True`; `c` (the passthrough alone) stores `False`; `d` (the passthrough plus
    a refused row on ANOTHER system) stores `False` — the flag keys on H, as the ladder does.
    Every row carrying `holding_queried` carries `has_refused` as a bool, in the returned
    record and in the `judge.yaml` on disk.

    What failure looks like: the bucket ladder branches on a fact the record never shows, so a
    page reading the row cannot say why an undoctored, queried world has no bucket (O3).
    """
    ep = J.accepted_episode(
        tmp_path, labels=("a", "b", "c", "d"),
        dispositions={"a": "benign", "b": "malicious", "c": "malicious", "d": "malicious"},
        ledgers={
            "b": [_passthrough("b"), _refused_row("b")],
            "c": [_passthrough("c")],
            "d": [_passthrough("d"), _refused_row("d", system="cmdb")],
        })

    grade = _grade(ep, tmp_path)

    for rows in (J.rows(grade), J.world_rows(J.judge_record(ep))):
        for label, row in rows.items():
            if "holding_queried" in row:
                assert isinstance(row.get("has_refused"), bool), (
                    f"world {label!r} carries holding_queried but no bool has_refused: "
                    f"{sorted(row)}")
        assert rows["b"]["has_refused"] is True, "a refused row on H did not set the flag"
        assert rows["c"]["has_refused"] is False, "no refused row anywhere, yet the flag is set"
        assert rows["d"]["has_refused"] is False, (
            "a refused row on a system that is NOT H set the flag; the ladder keys on H's rows")


def test_a_refused_h_row_is_the_stored_fact_that_turns_lead_quality_into_no_bucket(tmp_path):
    """The ladder's own pairing, driven through the real pass: a queried, undoctored world
    buckets `lead-quality`; the same world with one `refused` row on H buckets `None` (F-1) —
    and the row now SAYS which case it is.

    Observably true: `c` (`has_refused: False`) reads `bucket: "lead-quality"`; `b`
    (`has_refused: True`) reads `bucket: None`; both have `holding_queried: True` and
    `doctored_answer_served: False`, so `has_refused` is the one stored fact that separates
    them.

    What failure looks like: the bucket and the flag disagree — a row saying `has_refused:
    True` under `lead-quality`, or `False` under no bucket — which is a flag computed from
    something other than what the ladder read.
    """
    ep = J.accepted_episode(tmp_path, ledgers={
        "b": [_passthrough("b"), _refused_row("b")],
        "c": [_passthrough("c")],
    })

    rows = J.rows(_grade(ep, tmp_path))

    for label in ("b", "c"):
        assert rows[label]["holding_queried"] is True
        assert rows[label]["doctored_answer_served"] is False
        assert rows[label].get("ungradable") is not True
    assert (rows["c"]["has_refused"], rows["c"]["bucket"]) == (False, "lead-quality")
    assert (rows["b"]["has_refused"], rows["b"]["bucket"]) == (True, None), (
        f"a refused H row: {rows['b'].get('has_refused')!r} / {rows['b']['bucket']!r}")


def test_has_refused_is_read_off_the_refused_rows_on_every_ladder_branch(tmp_path):
    """`has_refused` is a fact about the ROWS — "is there a `refused` row on H" — and not a
    reading of the bucket the ladder landed in. Three worlds through the real pass, one per
    branch where a bucket-derived flag would answer differently:

    * `b` — a `staged` row AND a `refused` row on H: the ladder takes the DOCTORED branch (the
      refused row plays no part in its bucket), and the row still stores `has_refused: True`.
    * `c` — a `fault` row as its ONLY H interaction: J5's tier rule makes it ungradable with
      `bucket: None`, `holding_queried: True`, `doctored_answer_served: False` — the exact shape
      a refused world has — and it stores `has_refused: False`, because nothing was refused.
    * `d` — a `refused` row whose `system` is spelled `" Elastic "`: `own_h_rows`' own
      strip+casefold rule makes it an H row, so it stores `has_refused: True` and buckets
      `None`.

    What failure looks like: `has_refused = holding_queried and not doctored and bucket is
    None` — a flag re-derived from the bucket, which reads `False` on `b` and `True` on `c`,
    and reports the ladder's OUTPUT as the fact it was supposed to have branched on (O3).
    """
    fault = J.sym("learning.branch.ledger", "FAULT")
    ep = J.accepted_episode(
        tmp_path, labels=("a", "b", "c", "d"),
        dispositions={"a": "benign", "b": "malicious", "c": "malicious", "d": "malicious"},
        ledgers={
            "b": [J.staged_row("b"), _refused_row("b")],
            "c": [J.ledger_row(source=fault, world_label="c",
                               payload="missing required config keys: ELASTIC_EVENTS_INDEX")],
            "d": [_passthrough("d"), _refused_row("d", system=" Elastic ")],
        })

    rows = J.rows(_grade(ep, tmp_path))

    assert rows["b"]["doctored_answer_served"] is True, "the doctored branch was not taken"
    assert rows["b"]["has_refused"] is True, (
        "a refused H row beside a staged one was not recorded — the flag follows the bucket, "
        "not the rows")
    assert rows["c"]["ungradable"] is True, "positive control: the faulted world is ungradable"
    assert (rows["c"]["holding_queried"], rows["c"]["doctored_answer_served"],
            rows["c"]["bucket"]) == (True, False, None)
    assert rows["c"]["has_refused"] is False, (
        "a world whose only H row FAULTED stores has_refused: True — the flag was read off the "
        "bucket-None shape, and a fault is not a refusal")
    assert (rows["d"]["has_refused"], rows["d"]["bucket"]) == (True, None), (
        "a refused row on `\" Elastic \"` did not count as H's — the flag compares `system` "
        "differently from own_h_rows' strip+casefold rule")


def test_a_refused_row_sharing_a_served_rows_key_is_the_duplicate_j3_drops(tmp_path):
    """J3's first-row-wins reading, made explicit so a later change to the dedup rule is
    visible here rather than silently moving this flag: a `refused` row that carries the SAME
    pair-key as the `passthrough` row before it is read as that row's duplicate and never
    reaches the ladder — `has_refused: False`, bucket `lead-quality`.

    This is TODAY's reading, pinned, not a claim that it is the right one: a refusal of the
    very query that was also served is a shape the seam does not produce (a call is refused
    or answered, not both), and the fixture in `_refused_row` gives the refused row its own
    params for that reason. Positive control: the same two rows with distinct params read
    `has_refused: True`, bucket `None`.
    """
    refused = J.sym("learning.branch.ledger", "REFUSED")
    same_key = J.ledger_row(source=refused, world_label="b",
                            payload="this ES|QL query's FROM clause addresses several corpora")
    key_of = _family().mapping_key
    assert key_of(same_key) == key_of(_passthrough("b")), "the fixture's keys do not collide"
    assert key_of(_refused_row("c")) != key_of(_passthrough("c")), "the control's keys collide"
    ep = J.accepted_episode(tmp_path, ledgers={
        "b": [_passthrough("b"), same_key],
        "c": [_passthrough("c"), _refused_row("c")],
    })

    rows = J.rows(_grade(ep, tmp_path))

    assert (rows["c"]["has_refused"], rows["c"]["bucket"]) == (True, None), (
        "positive control: a refused row with its own key did not reach the ladder")
    assert (rows["b"]["has_refused"], rows["b"]["bucket"]) == (False, "lead-quality"), (
        "a refused row sharing the served row's pair-key reached the ladder — J3's first-row-"
        f"wins dedup changed: {rows['b'].get('has_refused')!r} / {rows['b']['bucket']!r}")


def test_has_refused_survives_the_round_trip_through_read_grade(tmp_path):
    """The flag is WRITTEN, not re-derived: the `judge.yaml` on disk carries it, and
    `read_grade` hands back the same value on every row the pass returned.

    Observably true: after one pass, the raw document's world rows carry `has_refused` with
    the pass's values, and `read_grade(ep)`'s rows equal the live pass's rows key for key.

    What failure looks like: the field is on the returned record and not in the file, so a
    re-read episode (the existing-record path, the page) grades as if the fact was never known.
    """
    read_grade = J.sym("learning.judge", "read_grade")
    ep = J.accepted_episode(tmp_path, ledgers={
        "b": [_passthrough("b"), _refused_row("b")],
        "c": [_passthrough("c")],
    })

    live = J.rows(_grade(ep, tmp_path))
    on_disk = J.world_rows(J.judge_record(ep))
    stored = J.rows(read_grade(ep))

    assert {label: row.get("has_refused") for label, row in on_disk.items()} == {
        "b": True, "c": False}, "judge.yaml does not carry the flag the pass computed"
    assert stored == live, (
        "a per-world field written to judge.yaml did not survive the re-read through read_grade")

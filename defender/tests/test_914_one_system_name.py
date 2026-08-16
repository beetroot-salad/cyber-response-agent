"""#914 — one system-name predicate, and every channel answers from it.

WHY THIS EXISTS. `is_system_name` was four things. `runtime.verbs._SYSTEM_RE` held the
dispatch seam to `[a-z0-9][a-z0-9-]*`; `runtime.tools_gather` kept a VERBATIM second copy of
that pattern; the 64-character ceiling was stated twice under two names
(`tools_gather._SYSTEM_MAX_LEN`, `query_tool._ECHO_SYSTEM_MAX_LEN`); and
`declared_systems._is_system_name` refused only the empty string, a leading dot, `/`, `\\`
and NUL — while its own docstring claimed to be holding names to the dispatch pattern.

That last divergence is the one with teeth, and it is not hypothetical: #908's alphabet probe
found `_marker_names` admitting `my sys` and an accented name, both of which `_adapter_path`
then refuses. A name could be DECLARED a system and fail to RESOLVE as one — the resolver
answering yes to a question the dispatch seam answers no to.

The three suites that already pin the shape (`test_869_pitfalls_gate`, `test_869_resolver`,
`test_gather_template_discovery`) each pin it at ONE site. This file pins the thing none of
them can see on its own: that the sites AGREE, and that the agreement survives a future
edit to any one of them.
"""
from __future__ import annotations

import contextlib
import re
import sys
from pathlib import Path

if (_root := str(Path(__file__).resolve().parents[2])) not in sys.path:
    sys.path.insert(0, _root)

import pytest

from defender.learning.leads import declared_systems, pitfalls_curator
from defender.runtime import query_tool, tools_gather, verbs
from defender.runtime.verbs import SYSTEM_MAX_LEN, is_system_name

#: The names every real source in this repo carries, and the shapes #869/#868 pinned as
#: refused. `gather` and `fakesys` are deliberately in the ADMITTED column: they are
#: well-formed names that no source declares, and keeping shape apart from membership is what
#: lets a drop be attributed to the right one.
ADMITTED = ("elastic", "cmdb", "change-mgmt", "host-state", "threat-intel", "ticket",
            "identity", "gather", "fakesys", "a", "s3", "a-b-c")
REFUSED = ("", "..", ".", ".hidden", "a/b", "a\\b", "a\x00b", "my sys", "wazuh-café",
           "Elastic", "HOST-STATE", "host_state", "-lead", "a" * (SYSTEM_MAX_LEN + 1),
           " elastic", "elastic ", "elastic\n", "\n", "élastic")


@pytest.mark.parametrize("name", ADMITTED)
def test_the_predicate_admits_every_well_formed_name(name):
    assert is_system_name(name) is True, name


@pytest.mark.parametrize("name", REFUSED)
def test_the_predicate_refuses_every_malformed_name(name):
    assert is_system_name(name) is False, name


def test_every_real_system_in_the_tree_passes_the_predicate():
    """The predicate is not stricter than the tree it governs.

    A tightening that refused a name this repo actually ships would take the whole
    lead-author lane down on the next tick, so the alignment is measured against all three
    real sources rather than against a remembered list: adapter filenames (via `_system_of`'s
    `_`->`-` mapping), committed `execution.md` markers, and the gather catalog's directories.
    """
    root = Path(__file__).resolve().parents[2]
    adapters = {
        verbs._system_of(p)
        for p in (root / "defender" / "scripts" / "adapters").glob("*" + verbs.ADAPTER_SUFFIX)
    }
    markers = {p.parent.name for p in (root / "defender" / "skills").glob("*/execution.md")}
    catalog = {
        p.name for p in (root / "defender" / "skills" / "gather" / "queries").iterdir()
        if p.is_dir()
    }
    assert adapters, "no adapters found — the comparison would be vacuous"
    assert markers, "no markers found — the comparison would be vacuous"
    assert catalog, "no catalog systems found — the comparison would be vacuous"
    for source, names in (("adapter", adapters), ("marker", markers), ("catalog", catalog)):
        for name in names:
            assert is_system_name(name), f"{source} source carries {name!r}, which the predicate refuses"


def test_the_resolver_and_the_dispatch_seam_cannot_disagree(tmp_path):
    """THE defect this issue closes, driven end to end rather than asserted about.

    For every refused shape, `_adapter_path` returns None — so if the resolver admitted one,
    it would declare a system that cannot dispatch. Driven over a real adapters directory
    holding a real file for each name, so a None here is the PREDICATE's answer and not a
    missing file's.
    """
    adapters = tmp_path / "adapters"
    adapters.mkdir()
    for name in ADMITTED:
        (adapters / (name.replace("-", "_") + verbs.ADAPTER_SUFFIX)).write_text("VERBS = {}\n")
        assert verbs._adapter_path(adapters, name) is not None, name

    for name in REFUSED:
        # A name the resolver must not declare is a name dispatch must not resolve. The file
        # is planted for every shape that can BE one — INCLUDING the separator-bearing `a/b`,
        # whose parent directory is created first. Without the mkdir that one assertion is
        # vacuous: `_adapter_path` returns None for the missing file, so it passes just as
        # well against a predicate that admits everything, and the traversal shape is the one
        # FK-5 is most about. `a\x00b` is the single shape no filesystem can hold.
        planted = adapters / (name.replace("-", "_") + verbs.ADAPTER_SUFFIX)
        with contextlib.suppress(OSError, ValueError):
            planted.parent.mkdir(parents=True, exist_ok=True)
            planted.write_text("VERBS = {}\n")
        assert verbs._adapter_path(adapters, name) is None, name


def test_no_module_restates_the_shape_or_the_bound():
    """The duplicates are GONE, not merely unused — a second copy of a predicate is a second
    thing to edit, and this repo has already paid for one (`_SYSTEM_RE` in two modules, `64`
    under two names). Read as source text, because an import of the shared symbol and a
    freshly-compiled local copy are indistinguishable at runtime.
    """
    root = Path(__file__).resolve().parents[1]
    # The two restatements this issue retired, each read as SOURCE TEXT: a second copy of the
    # pattern, and a second constant naming the same 64. The bound half is what makes this
    # test answer to its own name — the `hasattr` probes below only refuse the two spellings
    # that existed, and a third `_FOO_MAX_LEN = 64` would have walked past them.
    shape = re.compile(r"re\.compile\(\s*r?['\"](?:\\A)?\[a-z0-9\]")
    bound = re.compile(r"^\s*_?[A-Z][A-Z0-9_]*MAX_LEN[A-Z0-9_]*\s*=\s*64\b", re.M)
    # Exempted by PATH, not by basename: `p.name != "verbs.py"` would silently pardon any
    # future module that happened to be called that.
    home = (root / "runtime" / "verbs.py").resolve()

    def restates(path: Path) -> bool:
        text = path.read_text(encoding="utf-8", errors="replace")
        return bool(shape.search(text) or bound.search(text))

    offenders = [
        str(p.relative_to(root)) for p in root.rglob("*.py")
        if ".venv" not in p.parts and p.resolve() != home and p.name != Path(__file__).name
        and restates(p)
    ]
    assert offenders == [], f"the system-name shape or bound is restated in: {offenders}"

    assert not hasattr(tools_gather, "_SYSTEM_RE")
    assert not hasattr(tools_gather, "_SYSTEM_MAX_LEN")
    assert not hasattr(query_tool, "_ECHO_SYSTEM_MAX_LEN")
    assert not hasattr(declared_systems, "_is_system_name")


def test_every_consumer_answers_from_the_shared_predicate():
    """Each site reaches the SAME function object, so a change to it reaches all of them.

    Identity, not equality: two functions that agree today are exactly the state this issue
    started from.
    """
    for module in (declared_systems, pitfalls_curator, tools_gather):
        assert module.is_system_name is is_system_name, module.__name__
    assert query_tool.is_system_name is is_system_name
    assert query_tool.SYSTEM_MAX_LEN == SYSTEM_MAX_LEN


def test_the_bound_is_the_predicate_s_own():
    """The ceiling travels WITH the shape — the bug pattern was a site that matched the
    pattern and forgot the length (`verbs._adapter_path` did exactly that)."""
    assert is_system_name("a" * SYSTEM_MAX_LEN) is True
    assert is_system_name("a" * (SYSTEM_MAX_LEN + 1)) is False
    # And the raw pattern alone does NOT bound it, which is why it is PRIVATE and why no
    # caller outside `verbs` may reach for it: matching the shape and forgetting the bound is
    # the defect this issue closed, so the pattern must not be re-exported as a second answer.
    assert verbs._SYSTEM_RE.match("a" * (SYSTEM_MAX_LEN + 1)) is not None
    assert "SYSTEM_RE" not in verbs.__all__

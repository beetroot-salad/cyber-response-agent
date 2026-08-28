"""#691 — the corpus-name DOMAIN (M7 + MD-6). The per-spawn corpus name is a bind INPUT
(F89: the corpus-scoped policy must exist when ``bind`` returns), so its validity is decided AT
BIND. M7 is the single-segment shape rule (``len(Path(name).parts) == 1``, refusing ``""`` / ``"."``
/ multi-segment / absolute / ``..``-bearing); §7's D2 pins MD-6 on top — an EXACT-MATCH membership
rule against the three shipped corpora. A rejected name RAISES ``ValueError`` at bind; an accepted
name binds and resolves its corpus dir under the worktree tree.

RED against HEAD by construction: the corpus name rides on ``RunScope`` (the M1/#0 bind input,
absent today), so ``bind_curator`` dies at ``RunScope(corpus_name=…)`` with a ``TypeError`` — the
missing mechanism — before M7 ever runs. Once #0 builds the field + M7/MD-6, each test discriminates
on its own member address. Every reject is paired with an accept control on the same address (a
shipped name binds and roots its corpus where the name says).

Reconciliation applied (70-resolutions D2, MD-6): a name that shape-normalises to a single but
NON-shipped segment (``"./x"`` → ``"x"``) is a MEMBERSHIP reject, not an accept — so the ``./``
normalisation demand is exercised on a shipped name (``"./lessons"``), where normalisation and
membership agree. The spec_graph's ``distinguished[./x]`` member is the shape probe (x7/f14); MD-6
subsumes the non-shipped tail.
"""
from __future__ import annotations

import pytest

pytest.importorskip("pydantic_ai")

from _curator_691_harness import (  # noqa: E402
    bind_curator,
    corpus,
    make_worktree,
    pending_run_dir,
    write_file,
)

# Any sane M7/MD-6 refusal names the corpus/name/segment problem; a permissive disjunction pins
# that the raise is name-related without over-fitting the not-yet-written message wording.
_NAME_REJECT_TOKENS = (
    "corpus", "segment", "relative", "single", "name", "membership", "shipped", "clean",
)


def _assert_bind_rejects_name(wt, run_dir, name: str) -> None:
    """The OBSERVABLE reject: binding the curator with `name` raises ValueError at bind, and the
    message is about the name (not an unrelated crash). RED at HEAD (TypeError from the missing
    RunScope.corpus_name field surfaces instead — the #0 mechanism that is not built)."""
    with pytest.raises(ValueError) as exc:  # noqa: PT011 - message shape asserted below
        bind_curator(wt, run_dir, name)
    msg = str(exc.value)
    assert any(tok in msg.lower() for tok in _NAME_REJECT_TOKENS) or repr(name) in msg, (
        f"bind rejected {name!r} but the message is not name-related: {exc.value!r}"
    )


def _assert_bind_accepts(wt, run_dir, name: str, expect_corpus_name: str):
    """The OBSERVABLE accept: binding resolves the spawn's corpus under the worktree tree at
    <wt>/defender/<expect_corpus_name>. RED at HEAD (bindable=False / RunScope.corpus_name absent)."""
    deps = bind_curator(wt, run_dir, name)
    assert deps.corpus_dir.resolve() == corpus(wt, expect_corpus_name).resolve()
    return deps


# M7 : the corpus_name domain
# Each row supplies one degenerate `corpus_name` and the shipped name that must still bind
# beside it. The control is not decoration: a bind that rejected EVERYTHING would satisfy the
# rejection half of every row here.
@pytest.mark.parametrize(("case", "rejected", "control"), [
    # F86: M7 owns the supplied-but-degenerate value ``""`` (M8 owns only ``None``). ``""``
    # normalises to ``defender_dir`` itself (g14), the forbidden whole-tree scope (g23).
    ("corpus_name is the empty string", [""], "lessons"),

    # ``"."`` normalises to ``defender_dir`` itself the same way (g14); M7-as-corrected (K4)
    # refuses it.
    ("corpus_name is a single dot", ["."], "lessons-actor"),

    # M7's single-segment rule (``len(Path(name).parts) == 1``) refuses ``"a/b"``, closing
    # c16/g9's rm sibling-mismatch: under a nested name the rm grant matched a SIBLING
    # (``defender/b/...``) and missed the real corpus (``defender/a/b/...``). Refusing the name
    # at construction is also the front door's answer to being handed a corpus nested below
    # the tree — the same refusal whether the nested name arrives from a caller or a config.
    ("corpus_name has two segments", ["a/b"], "lessons"),

    # ``"/etc/passwd"`` is a name, not a Path; an absolute carrier reintroduces the mis-rooting
    # the refusal warns of (c14/g14 executed).
    ("corpus_name is an absolute path", ["/etc/passwd"], "lessons"),

    # A ``..``-bearing name in either spelling; no tree escape was found under any probed
    # input (c14/g14 executed, unrefuted).
    ("corpus_name contains parent directory segments",
     ["lessons/../..", "../x"], "lessons-environment"),
], ids=lambda v: v if isinstance(v, str) else "")
def test_a_degenerate_corpus_name_is_rejected_at_bind(tmp_path, case, rejected, control):
    """A degenerate ``corpus_name`` raises ValueError at bind rather than composing a scope
    from it: the empty string ``""``, a single dot ``"."``, a two-segment ``"a/b"``, an
    absolute ``"/etc/passwd"``, and any ``".."``-bearing spelling are all refused — while a
    shipped single-segment name still binds to its own sub-tree corpus."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    for name in rejected:
        _assert_bind_rejects_name(wt, rd, name)
    _assert_bind_accepts(wt, rd, control, control)


@pytest.mark.parametrize(("case", "name"), [
    # x7/f14: ``'./x'`` has ``parts == 1`` and resolves under the tree. Tested on a SHIPPED
    # name because MD-6 (D2) makes a normalised non-shipped tail a membership reject —
    # normalisation and membership agree here.
    ("corpus_name has a leading dot slash", "./lessons"),
    # a trailing slash normalises away and the name is still one segment (g14 executed)
    ("corpus_name has a trailing slash", "lessons/"),
], ids=lambda v: v if isinstance(v, str) else "")
def test_a_corpus_name_that_normalises_to_one_segment_binds_the_same_dir(tmp_path, case, name):
    """Normalisation is part of the ``corpus_name`` domain, not a separate rule: a spelling
    that reduces to one segment binds the SAME corpus_dir as the bare name it reduces to."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    deps = _assert_bind_accepts(wt, rd, name, "lessons")
    assert deps.corpus_dir.resolve() == bind_curator(wt, rd, "lessons").corpus_dir.resolve()


def test_the_names_that_resolve_to_the_tree_itself(tmp_path):
    """Exactly ``""`` and ``"."`` normalise away to ``defender_dir`` itself (g14/PF); M7-as-corrected
    (K4) must reject BOTH, or the corpus the spawn is scoped to is the whole tree above every corpus.
    Complementary condition (positive control): a shipped name binds to a strict sub-tree corpus."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    _assert_bind_rejects_name(wt, rd, "")
    _assert_bind_rejects_name(wt, rd, ".")
    deps = _assert_bind_accepts(wt, rd, "lessons", "lessons")
    # the accepted corpus is strictly BELOW the tree, never the tree itself
    assert deps.corpus_dir.resolve() != (wt / "defender").resolve()


def test_the_standing_prohibition_on_a_whole_tree_authoring_scope(tmp_path):
    """A committed demand (curator-glm-port.yaml:112, g23) already forbids a whole-``defender_dir``
    write_allow; this change is the FIRST able to produce that shape FROM A NAME (via M1's corpus
    carrier). M7-as-corrected must keep it unreachable: ``""`` / ``"."`` are rejected at bind, and no
    accepted name roots the write scope at ``defender_dir`` — a shipped bind ADMITS an in-corpus
    ``.md`` write but DENIES a top-of-tree ``defender/<x>.md`` write (the scope is a strict subdir)."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    _assert_bind_rejects_name(wt, rd, "")
    _assert_bind_rejects_name(wt, rd, ".")
    deps = bind_curator(wt, rd, "lessons")
    write_file(deps, "defender/lessons/lesson.md")  # in-corpus write lands (positive control)
    assert (wt / "defender" / "lessons" / "lesson.md").is_file()
    with pytest.raises(Exception):  # noqa: PT011, B017 - the write surface may raise ModelRetry or ValueError
        write_file(deps, "defender/toplevel.md")


def test_a_single_segment_name_that_is_not_a_shipped_corpus_is_rejected(tmp_path):
    """MD-6 (§7 D2, closing F30/P64/P109/F108): M7 as a SHAPE rule accepts a single clean segment
    naming a real NON-lesson dir — ``skills`` compiles a write_allow byte-identical to LEAD_AUTHOR's
    with no key between the two roles, and ``learning`` roots the write scope over
    ``defender/learning/_pending``, a production state tree. §7 D2 ADDS an EXACT-MATCH membership rule
    against the three shipped corpora, so such a name is now REJECTED at bind (a homoglyph of a
    shipped name is not an exact match either — closes F108). Positive control: every shipped name is
    an exact match and binds. RED today: the membership rule is unbuilt and the curator is unbindable
    (the reject surfaces as the missing RunScope.corpus_name field / bindable=False)."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    # real single-segment dirs the worktree carries (make_worktree creates skills/) — shape-admitted,
    # membership-rejected. ``learning`` is the dangerous instance (the production state tree's parent).
    for name in ("skills", "learning"):
        _assert_bind_rejects_name(wt, rd, name)
    for shipped in ("lessons", "lessons-actor", "lessons-environment"):
        _assert_bind_accepts(wt, rd, shipped, shipped)

"""#810 — the write lane for an append-only artifact.

Four mechanisms, one issue. The measured failure was that a refused write said "fix and
rewrite" and never said the file was unchanged; `SKILL.md` tells the model its own context IS
the document, so that wording sent it anchoring later edits at text the gate had refused to
write. Six of nine recovery episodes across three runs opened exactly that way.

What ships:

  * `diagnose()` returns typed `Diagnostic`s, and every refusing branch of the investigation
    gate states that nothing was written.
  * `append_block` is MAIN's only writer — no path, no anchor — because investigation.md is
    validator-enforced append-only and the general verbs offered a capability it never had.
  * `read_file(tail=N)` is how the model re-syncs when its context no longer holds the
    document, which is real after a frontier fold.
  * No SKILL frontmatter reaches a system prompt, so the roster has one owner
    (`MAIN_DEF.tools`) instead of a prose copy that drifts.

The last section covers #825, found reviewing this PR: the `:R attr_updates` correction was
built against a column order the grammar does not enforce.

The registration half (MAIN's roster, the tier table, the write-allowlist census) lives with
the suites that already owned those properties; this file owns the new behaviour.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

DEFENDER = Path(__file__).resolve().parents[1]
if str(DEFENDER.parent) not in sys.path:  # pragma: no cover - import bootstrap
    sys.path.insert(0, str(DEFENDER.parent))

from defender._artifact_schema import (  # noqa: E402
    INVESTIGATION_FILE_MAX,
    UNCHANGED_NOTICE,
    validate_investigation,
)
from defender.runtime.tools import _tail_chars  # noqa: E402
from defender.skills.invlang.validate import diagnose, validate_companion  # noqa: E402

# A minimal document carrying one bad `:R attr_updates` key. The lead is declared with the
# real `:L findings` column list AND the target vertex with the real `:V prologue.vertices`
# one, so the ONLY complaint is the refinement key — asserted by
# test_the_bad_key_is_the_documents_only_fault below, because a fixture that quietly carried
# a parse error alongside would let a weaker implementation pass these.
#
# The bad key is `owner`, not the `ident` this suite was written with: #836 made `ident` a
# LEGAL third refinement key, and a fixture keyed on it stops being a bad key at all. `owner`
# is outside `class` / `ident` / `attrs.*` and keeps exercising exactly what these tests
# assert — the family names its row and offers both corrections in the header's own column
# order. The `:V` block is the same migration from the other side: #836 refuses a refinement
# naming a vertex no `:V` declares, and an undeclared target would be a SECOND fault in a
# fixture whose whole job is to carry one.
_BAD_ATTR_KEY = """```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-003|compute|workstation/internal/known-corp|office-ws-1|

:L findings [id|loop|name|target|tests|system|window]
l-003|1|cmdb-lookup-office-ws-1|v-001||cmdb|n/a
```

```invlang
:R attr_updates [resolved_by|target|key|value]
l-003|v-003|owner|svc.config-mgmt
```
"""


#: The same shape as `_BAD_ATTR_KEY` but ERROR severity — the refinement row cites a lead the
#: document never declares. Minted for #836: the branches below that need "a document the
#: invlang validator REFUSES" can no longer use a bad refinement key, which now warns and lands.
_ERROR_INVLANG = """```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-003|compute|workstation/internal/known-corp|office-ws-1|

:L findings [id|loop|name|target|tests|system|window]
l-003|1|cmdb-lookup-office-ws-1|v-001||cmdb|n/a
```

```invlang
:R attr_updates [resolved_by|target|key|value]
l-404|v-003|class|svc.config-mgmt
```
"""


def _only(diags, predicate):
    hits = [d for d in diags if predicate(d)]
    assert len(hits) == 1, f"expected exactly one match, got {[d.message for d in hits]}"
    return hits[0]


# the typed diagnostic

def test_the_bad_key_is_the_documents_only_fault():
    """Guards the fixture the rest of this file leans on. An earlier draft declared the lead
    with invented columns, so the document also carried a parse error and an undeclared-lead
    error — and every `_only` assertion below still passed, because they filter. A fixture
    with extra faults would hide a renderer that mangles the diagnostics it was not asked
    about."""
    messages = [d.message for d in diagnose(_BAD_ATTR_KEY, None)]

    assert len(messages) == 1, messages
    assert "refinement key" in messages[0]


def test_attr_update_key_diagnostic_quotes_its_row_and_both_legal_forms():
    """The `:R attr_updates` family can name the offending row and render its corrections.

    This is the row the issue was filed about, verbatim: the validator knew `v-003` and
    `ident` but not the lead or the value, so the model was handed a rule and left to
    reconstruct the row from it. The row now comes off the parser (`AttrRowOrigin`) rather
    than being rebuilt — see the #825 section below for why rebuilding was not safe."""
    d = _only(diagnose(_BAD_ATTR_KEY, None), lambda d: "refinement key" in d.message)

    assert d.locus is not None
    assert d.locus.block == ":R attr_updates"
    assert d.locus.row_text == "l-003|v-003|owner|svc.config-mgmt"
    assert d.fix == (
        "l-003|v-003|class|svc.config-mgmt",
        "l-003|v-003|attrs.owner|svc.config-mgmt",
    )


def test_a_document_global_failure_carries_no_locus():
    """The seven families with no single offending row leave `locus` None and read exactly as
    they did before. The point of the field being optional is that most checks cannot fill it;
    an implementation that special-cased `attr_updates` and called the job done would pass a
    test written only against the case above, so this is the other half of that oracle."""
    orphan = "```invlang\n:R attr_updates [resolved_by|target|key|value]\nl-404|v-001|class|x\n```\n"
    d = _only(diagnose(orphan, None), lambda d: "undeclared lead" in d.message)

    assert d.locus is None
    assert d.fix == ()


def test_parse_warnings_keep_the_structure_format_used_to_destroy():
    """A parse warning always knew its block, ordinal and raw row; `format()` folded them into
    prose and the string was all anyone got. The prose is unchanged — it is what the suites
    match on — and the structure now survives beside it."""
    malformed = "```invlang\n:R attr_updates [resolved_by|target|key|value]\nl-001|v-001\n```\n"
    d = _only(diagnose(malformed, None), lambda d: d.message.startswith("parse error:"))

    assert d.locus is not None
    assert d.locus.row_text == "l-001|v-001"
    assert d.locus.row_index == 0
    assert d.locus.block == ":R attr_updates"


def test_validate_companion_still_returns_the_same_strings():
    """The `list[str]` surface is unchanged in both type and content. Two production callers
    and thirteen assertion sites across five suites do substring work on these elements; the
    typing went in underneath them, not through them.

    #836 narrowed the CONTENT to error severity — the list reads as "reasons to refuse", and
    persist dead-letters a run on any element, which a warn-family row must not do. So the
    parity asserted is against the error-severity diagnostics, and the warn half is asserted
    genuinely dropped rather than accidentally absent."""
    strings = validate_companion(_ERROR_INVLANG, None)
    diags = diagnose(_ERROR_INVLANG, None)

    assert all(isinstance(s, str) for s in strings)
    assert strings == [d.message for d in diags if d.severity != "warning"]
    assert strings, "the fixture stopped producing an error at all"

    # ...and the warn-only document comes back empty through this surface.
    assert validate_companion(_BAD_ATTR_KEY, None) == []
    assert [d.severity for d in diagnose(_BAD_ATTR_KEY, None)] == ["warning"]


# the refusal says nothing landed

@pytest.mark.parametrize(("kind", "text", "current"), [
    # `_ERROR_INVLANG`, not `_BAD_ATTR_KEY`: since #836 a bad refinement key WARNS and the
    # document lands, so it no longer reaches a refusing branch at all. The branch under test
    # is unchanged; only the fixture that reaches it had to move.
    ("invlang", _ERROR_INVLANG, None),
    ("byte-bound", "x" * (INVESTIGATION_FILE_MAX + 1), None),
])
def test_every_refusing_branch_states_the_file_is_unchanged(kind, text, current):
    """EVERY branch, not just the invlang one. The size branch short-circuits before the
    validator ever runs, so it is a separate return with its own text — and a model that is
    told only "trim it and rewrite" is left with the same wrong belief about disk that the
    invlang wording created."""
    reason = validate_investigation(text, current)

    assert reason is not None, f"the {kind} branch did not refuse"
    assert UNCHANGED_NOTICE in reason


def test_the_refusal_carries_the_row_and_the_correction_to_the_model():
    """The rendered refusal, which is the `ModelRetry` body verbatim. The row and both legal
    forms have to reach the MODEL, not merely exist on a dataclass the gate never prints.

    #836 moved WHICH refusal carries them, not whether one does. A bad refinement key now
    WARNS and lands, so it no longer refuses through `validate_investigation`; the refusal that
    names the row is the repair-window gate, which blocks the NEXT write until the landed row
    is repaired. Same renderer, same three lines, same obligation — read off the gate that now
    owns it rather than off the branch that stopped producing it.

    The error-severity branch keeps its own half, asserted in the last block."""
    from defender.runtime.tools import flagged_write_refusal
    from defender.skills.invlang.validate import warn_diagnostics

    reason = flagged_write_refusal("append_block", warn_diagnostics(_BAD_ATTR_KEY))

    assert "row: l-003|v-003|owner|svc.config-mgmt" in reason
    assert "use: l-003|v-003|class|svc.config-mgmt" in reason
    assert "l-003|v-003|attrs.owner|svc.config-mgmt" in reason
    assert UNCHANGED_NOTICE in reason

    # ...and an error-severity document still refuses through the validator, carrying the
    # substring six suites assert on.
    assert "invlang validation" in validate_investigation(_ERROR_INVLANG, None)


def test_a_located_row_is_not_printed_twice():
    """A parse warning's prose already embeds its row, so the renderer suppresses the locus
    line there. Cheap to get wrong, and the result is a refusal that says everything twice."""
    malformed = "```invlang\n:R attr_updates [resolved_by|target|key|value]\nl-001|v-001\n```\n"
    reason = validate_investigation(malformed, None)

    assert reason.count("l-001|v-001") == 1


def test_a_row_with_escapes_is_still_not_printed_twice():
    """The sibling of the test above, and the reason it needed one. `ParseWarning.format()`
    embeds the row as a `repr()`, so a row carrying a backslash or a quote is spelled
    `'C:\\temp'` in the message and a raw-substring test does not find it. Both spellings
    have to be checked or the escape-carrying rows — the ones most likely to be malformed
    in the first place — get their row printed twice."""
    # One cell too MANY, so the row fails to parse and the PARSE-warning family — the one that
    # embeds its row as a `repr()` — is what renders it. #836 turned the bad-refinement-key
    # family into a warning the write gate no longer returns, so the escape-carrying row is
    # routed through the error-severity family that still reaches this renderer.
    malformed = ("```invlang\n:R attr_updates [resolved_by|target|key|value]\n"
                 "l-001|v-001|note|C:\\temp|extra\n```\n")
    reason = validate_investigation(malformed, None)

    assert "C:" in reason, "the fixture stopped reaching the renderer"
    assert reason.count("l-001|v-001|note") == 1


def test_an_over_bound_document_says_what_cannot_be_taken_back(tmp_path):
    """Under append-only, "trim it" is advice the model may be unable to take: it has no
    editor, so once the committed prefix fills the bound no block is small enough. The
    refusal names the committed share, which is what distinguishes "send less" from "you are
    out of room and should close"."""
    committed = "x" * (INVESTIGATION_FILE_MAX - 100)
    reason = validate_investigation(committed + "y" * 200, committed)

    assert reason is not None
    assert UNCHANGED_NOTICE in reason
    assert f"{len(committed)} of those bytes are already committed" in reason
    assert "close the investigation" in reason
    # ...and on a CREATE there is nothing committed, so the old advice still stands.
    fresh = validate_investigation("x" * (INVESTIGATION_FILE_MAX + 1), None)
    assert "Trim it and re-send." in fresh


def test_an_accepted_document_still_returns_no_reason():
    """The notice rides on refusals only — an accepted write says nothing at all."""
    good = ("```invlang\n:L findings [id|loop|name|target|tests|system|window]\n"
            "l-001|1|cmdb-lookup|v-001||cmdb|n/a\n```\n")

    assert validate_investigation(good, None) is None
    assert validate_investigation("", None) is None


# the bounded tail

def test_tail_never_starts_mid_row():
    """An invlang row is `|`-delimited and a half row reads as truncated data, so the window
    trims FORWARD to a line start. `n` is therefore a ceiling: at most `n`, never more."""
    doc = "l-001|a|b|c\nl-002|d|e|f\nl-003|g|h|i\n"

    out = _tail_chars(doc, 20)
    assert out.startswith("l-0")
    assert len(out) <= 20
    assert doc.endswith(out)


def test_tail_edges():
    """`n <= 0` yields nothing; a document shorter than `n` comes back whole; a window with no
    newline in it falls back to a plain cut rather than returning the entire file."""
    assert _tail_chars("abc", 0) == ""
    assert _tail_chars("abc", -1) == ""
    assert _tail_chars("abc", 99) == "abc"
    assert _tail_chars("abcdef", 3) == "def"


def test_tail_of_a_real_investigation_is_a_fraction_of_the_whole():
    """The reason the tail exists. The read cap equals INVESTIGATION_FILE_MAX, so an
    unfiltered read of investigation.md never truncates and returns the whole document —
    thousands of tokens. `SKILL.md` banned reading it back on that cost, while
    `compaction.RESUME_RESTART_SHAPED` sends the model to disk after a fold. The tail is what
    makes both true at once."""
    doc = "".join(f"l-{i:03d}|goal|cmdb|resolved\n" for i in range(400))

    out = _tail_chars(doc, 2000)
    assert len(out) <= 2000
    assert len(out) < len(doc) / 4
    assert doc.endswith(out)
    assert out.startswith("l-")


# append_block, at the handler

def _main_deps(tmp_path):
    """MAIN deps through the real `bind` seam — real compiled policy, real gate."""
    from defender.agents import MAIN_DEF
    from defender.runtime.agent_definition import bind

    run = tmp_path / "run"
    run.mkdir()
    dfn = tmp_path / "defender"
    dfn.mkdir()
    return bind(MAIN_DEF, run, defender_dir=dfn), run


def test_append_creates_then_grows_the_transcript(tmp_path):
    """Creation is an append onto nothing, which is why `write_file` was redundant for MAIN
    rather than merely unused: the first call establishes the document, later calls extend it,
    and no call ever rewrites a byte that is already there."""
    from defender.runtime.tools import _tool_append_block

    deps, run = _main_deps(tmp_path)
    inv = run / "investigation.md"

    _tool_append_block(deps, "+ first\n")
    assert inv.read_text() == "+ first\n"

    _tool_append_block(deps, "+ second\n")
    assert inv.read_text() == "+ first\n+ second\n"


def test_append_separates_when_the_document_does_not_end_in_a_newline(tmp_path):
    """A separator is inserted rather than the previous content being tidied — existing bytes
    are never rewritten, or an append could itself trip the append-only check it is about to
    face."""
    from defender.runtime.tools import _tool_append_block

    deps, run = _main_deps(tmp_path)

    _tool_append_block(deps, "+ no trailing newline")
    _tool_append_block(deps, "+ next\n")

    assert (run / "investigation.md").read_text() == "+ no trailing newline\n+ next\n"


def test_a_repeating_last_line_is_not_an_obstacle(tmp_path):
    """The anchor failure this verb exists to delete. `edit_file` needed a unique `old_string`,
    so appending after a line that legitimately repeats failed with `old_string is not unique`
    — measured in `reviewer-measure-0807-b`, where the repeating line was ordinary prose the
    model had written twice. `append_block` has no anchor, so the repetition is irrelevant."""
    from defender.runtime.tools import _tool_append_block

    deps, run = _main_deps(tmp_path)
    repeated = "Dispatching all three in parallel.\n"

    _tool_append_block(deps, repeated)
    _tool_append_block(deps, repeated)
    _tool_append_block(deps, "+ landed after the repeat\n")

    assert (run / "investigation.md").read_text() == repeated * 2 + "+ landed after the repeat\n"


def test_an_empty_append_changes_nothing(tmp_path):
    """The separator is computed before `text` is looked at, so an empty append used to add a
    newline the model never sent — on a call whose own result says "appended 0 bytes". The
    replay harness reaches this: `_split_at_fences` pads with empty chunks when the target has
    fewer fences than write sites."""
    from defender.runtime.tools import _tool_append_block

    deps, run = _main_deps(tmp_path)
    _tool_append_block(deps, "+ no trailing newline")
    before = (run / "investigation.md").read_text()

    _tool_append_block(deps, "")

    assert (run / "investigation.md").read_text() == before


def test_the_reported_count_is_utf8_bytes_not_characters(tmp_path):
    """The SKILL tells the model this return IS a byte count, and the 65,536 cap it must stay
    under is measured in UTF-8 bytes. invlang carries `⟂ → ⟺` freely, so a `len(str)` would
    under-report against the very bound the gate applies and a model budgeting from it would
    be refused a write it computed was safe."""
    from defender.runtime.tools import _tool_append_block

    deps, _run = _main_deps(tmp_path)
    text = "+ v-001 ⟂ v-002 → v-003\n"

    result = _tool_append_block(deps, text)

    assert len(text.encode("utf-8")) > len(text), "the fixture lost its multibyte glyphs"
    assert f"appended {len(text.encode('utf-8'))} bytes" in result


def test_a_refused_append_leaves_no_residue(tmp_path):
    """The property the refusal text is claiming. If a denied append left a partial write, the
    notice would be a lie and the model's next append would build on rubble."""
    from pydantic_ai.exceptions import ModelRetry

    from defender.runtime.tools import _tool_append_block

    deps, run = _main_deps(tmp_path)
    inv = run / "investigation.md"
    _tool_append_block(deps, "+ committed\n")

    with pytest.raises(ModelRetry) as exc:
        _tool_append_block(deps, "```yaml\nfoo: bar\n```\n")

    assert UNCHANGED_NOTICE in str(exc.value)
    assert inv.read_text() == "+ committed\n", "the refused append left residue on disk"


def test_a_duplicate_append_is_accepted_so_the_refusal_must_be_believed(tmp_path):
    """The finding that makes the truthful refusal load-bearing rather than cosmetic.

    `_check_append_only` compares FENCE COUNTS and indexes records by first occurrence, so
    re-appending a block it has already seen passes the gate. Under `edit_file` a model that
    wrongly believed its write had failed got caught by `old_string not found`; there is no
    such accident here. The refusal text and the tail read are the only two things standing
    between a mistaken belief and a doubled block, which is why both shipped together."""
    from defender.runtime.tools import _tool_append_block, _tail_chars

    deps, run = _main_deps(tmp_path)
    block = ("```invlang\n:L findings [id|loop|name|target|tests|system|window]\n"
             "l-001|1|cmdb-lookup|v-001||cmdb|n/a\n```\n")

    _tool_append_block(deps, block)
    _tool_append_block(deps, block)

    text = (run / "investigation.md").read_text()
    assert text == block * 2, "the gate is expected NOT to catch this — see the docstring"
    # ...and the tail is what lets the model see it happened.
    assert _tail_chars(text, len(block)).strip() == block.strip()


# the roster has one owner, and the prompt does not carry a second copy

def test_no_skill_frontmatter_reaches_a_system_prompt():
    """`_main_instructions` used to read SKILL.md whole, so its `allowed-tools:` line was the
    first thing in MAIN's system prompt — naming `Write, Edit` above a body that says to use
    `append_block`. Nothing in this runtime parses that frontmatter, so it was pure
    mis-instruction. Both prompt loaders now splice the BODY."""
    from defender.runtime.driver import _gather_instructions, _main_instructions

    main = _main_instructions(DEFENDER)
    gather = _gather_instructions(DEFENDER)

    assert not main.lstrip().startswith("---"), "MAIN's prompt still opens with frontmatter"
    assert not gather.lstrip().startswith("---")
    assert "allowed-tools" not in main
    assert "name: defender-gather" not in gather
    # ...and the body itself still arrived, so this is not passing on an empty read.
    assert "You are the **defender**" in main
    assert "gather subagent" in gather


def test_the_skill_declares_no_tool_roster_of_its_own():
    """The roster has one owner — `MAIN_DEF.tools`, which decides what `register_tools`
    registers. A prose copy can only drift, and did: it kept naming `Write, Edit` after #810
    removed them. Asserted on the FILE, not the prompt, because the point is that the second
    copy is gone rather than merely hidden from the model."""
    text = (DEFENDER / "SKILL.md").read_text(encoding="utf-8")

    assert "allowed-tools" not in text, (
        "SKILL.md declares a tool roster again — it will drift from MAIN_DEF.tools"
    )


def test_the_registered_roster_is_what_the_toolset_grants():
    """The other half: whatever the enforced owner says is what actually registers. Pins the
    roster this PR leaves MAIN with, so a future grant change has to be deliberate."""
    from defender.runtime.agent_definition import ToolSet
    from defender.runtime.driver import MAIN_DEF

    assert MAIN_DEF.tools == ToolSet(read=True, bash=True, append=True, close=True)
    assert MAIN_DEF.tools.write is False


# #825 — the correction follows the block's DECLARED header, not a convention

_TRANSPOSED = """```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-003|compute|workstation/internal/known-corp|office-ws-1|

:L findings [id|loop|name|target|tests|system|window]
l-003|1|cmdb-lookup|v-001||cmdb|n/a
```

```invlang
:R attr_updates [resolved_by|target|value|key]
l-003|v-003|svc.config-mgmt|owner
```
"""


def test_a_transposed_header_gets_a_correction_in_its_own_column_order():
    """#825. `resolved_by|target|key|value` is what every real document happens to declare,
    but `_cells._row_dict` zips whatever header the block names — the order is convention,
    not grammar. Rebuilding the row from the folded `{key: value}` map assumed the
    convention, so a block declaring `[…|value|key]` was handed a correction with its columns
    swapped: pasting it would put `class` in the `value` cell and earn a second refusal.

    The row now comes from the parser verbatim and only the `key` CELL is substituted, so the
    suggestion is valid against the header the author actually wrote."""
    d = _only(diagnose(_TRANSPOSED, None), lambda d: "refinement key" in d.message)

    assert d.locus is not None
    assert d.locus.row_text == "l-003|v-003|svc.config-mgmt|owner"
    assert d.fix == (
        "l-003|v-003|svc.config-mgmt|class",
        "l-003|v-003|svc.config-mgmt|attrs.owner",
    )
    # the value cell is untouched and stays where the author put it
    assert all(f.split("|")[2] == "svc.config-mgmt" for f in d.fix)


def test_the_canonical_header_is_unchanged_by_that_fix():
    """The regression guard for the common path: reading the row off the parser must produce
    exactly what rebuilding it used to, for the order every real document declares."""
    d = _only(diagnose(_BAD_ATTR_KEY, None), lambda d: "refinement key" in d.message)

    assert d.locus.row_text == "l-003|v-003|owner|svc.config-mgmt"
    assert d.fix == (
        "l-003|v-003|class|svc.config-mgmt",
        "l-003|v-003|attrs.owner|svc.config-mgmt",
    )


def test_a_header_without_a_key_column_degrades_instead_of_guessing():
    """When the header names no `key` column there is no cell to substitute and no row this
    can honestly point at. It degrades to the prose-only diagnostic — the same shape as the
    seven checks that never had a row — rather than inventing a correction. A wrong fix is
    worse than no fix, which is the whole finding behind #825."""
    headerless = """```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-003|compute|workstation/internal/known-corp|office-ws-1|

:L findings [id|loop|name|target|tests|system|window]
l-003|1|cmdb-lookup|v-001||cmdb|n/a
```

```invlang
:R attr_updates [resolved_by|target|key|value]
l-003|v-003|owner|svc.config-mgmt
```
""".replace("[resolved_by|target|key|value]", "[resolved_by|target|attribute|value]")
    diags = [d for d in diagnose(headerless, None) if "refinement key" in d.message]

    # the row parses with no `key` column, so the key check has nothing to complain about;
    # what matters is that NOTHING here fabricates a locus.
    assert all(d.locus is None and d.fix == () for d in diags)

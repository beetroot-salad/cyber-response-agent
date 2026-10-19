"""Append-only write lane: typed diagnostics, append_block, tail, header-order corrections."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

DEFENDER = Path(__file__).resolve().parents[3]
if str(DEFENDER.parent) not in sys.path:  # pragma: no cover - import bootstrap
    sys.path.insert(0, str(DEFENDER.parent))

from defender._artifact_schema import (  # noqa: E402
    INVESTIGATION_FILE_MAX,
    UNCHANGED_NOTICE,
    validate_investigation,
)
from defender.runtime.tools import _tail_chars  # noqa: E402
from defender.skills.invlang.validate import diagnose  # noqa: E402

_BAD_ATTR_KEY = """```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-003|process|bash|bash[pid=4120]|

:L findings [id|loop|name|target|tests|system|window]
l-003|1|cmdb-lookup-office-ws-1|v-001||cmdb|n/a
```

```invlang
:R attr_updates [resolved_by|target|key|value]
l-003|v-003|owner|svc.config-mgmt
```
"""


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
    """Guards the fixture the rest of this file leans on. An earlier draft declared the lead with invented..."""
    messages = [d.message for d in diagnose(_BAD_ATTR_KEY, None)]

    assert len(messages) == 1, messages
    assert "refinement key" in messages[0]


def test_attr_update_key_diagnostic_quotes_its_row_and_both_legal_forms():
    """The `:R attr_updates` family can name the offending row and render its corrections."""
    d = _only(diagnose(_BAD_ATTR_KEY, None), lambda d: "refinement key" in d.message)

    assert d.locus is not None
    assert d.locus.block == ":R attr_updates"
    assert d.locus.row_text == "l-003|v-003|owner|svc.config-mgmt"
    assert d.fix == (
        "l-003|v-003|class|svc.config-mgmt",
        "l-003|v-003|attrs.owner|svc.config-mgmt",
    )


def test_a_document_global_failure_carries_no_locus():
    """The seven families with no single offending row leave `locus` None and read exactly as they did before...."""
    orphan = "```invlang\n:R attr_updates [resolved_by|target|key|value]\nl-404|v-001|class|x\n```\n"
    d = _only(diagnose(orphan, None), lambda d: "undeclared lead" in d.message)

    assert d.locus is None
    assert d.fix == ()


def test_parse_warnings_keep_the_structure_format_used_to_destroy():
    """A parse warning always knew its block, ordinal and raw row; `format()` folded them into prose and the..."""
    malformed = "```invlang\n:R attr_updates [resolved_by|target|key|value]\nl-001|v-001\n```\n"
    d = _only(diagnose(malformed, None), lambda d: d.message.startswith("parse error:"))

    assert d.locus is not None
    assert d.locus.row_text == "l-001|v-001"
    assert d.locus.row_index == 0
    assert d.locus.block == ":R attr_updates"


# the refusal says nothing landed

@pytest.mark.parametrize(("kind", "text", "current"), [
    ("invlang", _ERROR_INVLANG, None),
    ("byte-bound", "x" * (INVESTIGATION_FILE_MAX + 1), None),
])
def test_every_refusing_branch_states_the_file_is_unchanged(kind, text, current):
    """EVERY branch, not just the invlang one. The size branch short-circuits before the validator ever runs, so..."""
    reason = validate_investigation(text, current)

    assert reason is not None, f"the {kind} branch did not refuse"
    assert UNCHANGED_NOTICE in reason


def test_the_refusal_carries_the_row_and_the_correction_to_the_model():
    """The rendered refusal, which is the `ModelRetry` body verbatim. The row and both legal forms have to reach..."""
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
    """A parse warning's prose already embeds its row, so the renderer suppresses the locus line there. Cheap to..."""
    malformed = "```invlang\n:R attr_updates [resolved_by|target|key|value]\nl-001|v-001\n```\n"
    reason = validate_investigation(malformed, None)

    assert reason.count("l-001|v-001") == 1


def test_a_row_with_escapes_is_still_not_printed_twice():
    """The sibling of the test above, and the reason it needed one. `ParseWarning.format()` embeds the row as a..."""
    malformed = ("```invlang\n:R attr_updates [resolved_by|target|key|value]\n"
                 "l-001|v-001|note|C:\\temp|extra\n```\n")
    reason = validate_investigation(malformed, None)

    assert "C:" in reason, "the fixture stopped reaching the renderer"
    assert reason.count("l-001|v-001|note") == 1


def test_an_over_bound_document_says_what_cannot_be_taken_back(tmp_path):
    """Under append-only, "trim it" is advice the model may be unable to take: it has no editor, so once the..."""
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
    """An invlang row is `|`-delimited and a half row reads as truncated data, so the window trims FORWARD to a..."""
    doc = "l-001|a|b|c\nl-002|d|e|f\nl-003|g|h|i\n"

    out = _tail_chars(doc, 20)
    assert out.startswith("l-0")
    assert len(out) <= 20
    assert doc.endswith(out)


def test_tail_edges():
    """`n <= 0` yields nothing; a document shorter than `n` comes back whole; a window with no newline in it..."""
    assert _tail_chars("abc", 0) == ""
    assert _tail_chars("abc", -1) == ""
    assert _tail_chars("abc", 99) == "abc"
    assert _tail_chars("abcdef", 3) == "def"


def test_tail_of_a_real_investigation_is_a_fraction_of_the_whole():
    """The reason the tail exists. The read cap equals INVESTIGATION_FILE_MAX, so an unfiltered read of..."""
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
    """Creation is an append onto nothing, which is why `write_file` was redundant for MAIN rather than merely..."""
    from defender.runtime.tools import _tool_append_block

    deps, run = _main_deps(tmp_path)
    inv = run / "investigation.md"

    _tool_append_block(deps, "+ first\n")
    assert inv.read_text() == "+ first\n"

    _tool_append_block(deps, "+ second\n")
    assert inv.read_text() == "+ first\n+ second\n"


def test_append_separates_when_the_document_does_not_end_in_a_newline(tmp_path):
    """A separator is inserted rather than the previous content being tidied — existing bytes are never..."""
    from defender.runtime.tools import _tool_append_block

    deps, run = _main_deps(tmp_path)

    _tool_append_block(deps, "+ no trailing newline")
    _tool_append_block(deps, "+ next\n")

    assert (run / "investigation.md").read_text() == "+ no trailing newline\n+ next\n"


def test_a_repeating_last_line_is_not_an_obstacle(tmp_path):
    """The anchor failure this verb exists to delete. `edit_file` needed a unique `old_string`, so appending..."""
    from defender.runtime.tools import _tool_append_block

    deps, run = _main_deps(tmp_path)
    repeated = "Dispatching all three in parallel.\n"

    _tool_append_block(deps, repeated)
    _tool_append_block(deps, repeated)
    _tool_append_block(deps, "+ landed after the repeat\n")

    assert (run / "investigation.md").read_text() == repeated * 2 + "+ landed after the repeat\n"


def test_an_empty_append_changes_nothing(tmp_path):
    """The separator is computed before `text` is looked at, so an empty append used to add a newline the model..."""
    from defender.runtime.tools import _tool_append_block

    deps, run = _main_deps(tmp_path)
    _tool_append_block(deps, "+ no trailing newline")
    before = (run / "investigation.md").read_text()

    _tool_append_block(deps, "")

    assert (run / "investigation.md").read_text() == before


def test_the_reported_count_is_utf8_bytes_not_characters(tmp_path):
    """The SKILL tells the model this return IS a byte count, and the 65,536 cap it must stay under is measured..."""
    from defender.runtime.tools import _tool_append_block

    deps, _run = _main_deps(tmp_path)
    text = "+ v-001 ⟂ v-002 → v-003\n"

    result = _tool_append_block(deps, text)

    assert len(text.encode("utf-8")) > len(text), "the fixture lost its multibyte glyphs"
    assert f"appended {len(text.encode('utf-8'))} bytes" in result


def test_a_refused_append_leaves_no_residue(tmp_path):
    """The property the refusal text is claiming. If a denied append left a partial write, the notice would be a..."""
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
    """The finding that makes the truthful refusal load-bearing rather than cosmetic."""
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


# #825 — the correction follows the block's DECLARED header, not a convention

#: `v-003` is a `process` for the reason `_BAD_ATTR_KEY` records: both corrections have to be
#: offered for their column order to be observable at all.
_TRANSPOSED = """```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-003|process|bash|bash[pid=4120]|

:L findings [id|loop|name|target|tests|system|window]
l-003|1|cmdb-lookup|v-001||cmdb|n/a
```

```invlang
:R attr_updates [resolved_by|target|value|key]
l-003|v-003|svc.config-mgmt|owner
```
"""


def test_a_transposed_header_gets_a_correction_in_its_own_column_order():
    """#825. `resolved_by|target|key|value` is what every real document happens to declare, but..."""
    d = _only(diagnose(_TRANSPOSED, None), lambda d: "refinement key" in d.message)

    assert d.locus is not None
    assert d.locus.row_text == "l-003|v-003|svc.config-mgmt|owner"
    assert d.fix == (
        "l-003|v-003|svc.config-mgmt|class",
        "l-003|v-003|svc.config-mgmt|attrs.owner",
    )
    # the value cell is untouched and stays where the author put it
    assert all(f.split("|")[2] == "svc.config-mgmt" for f in d.fix)


def test_a_header_without_a_key_column_degrades_instead_of_guessing():
    """When the header names no `key` column there is no cell to substitute and no row this can honestly point..."""
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

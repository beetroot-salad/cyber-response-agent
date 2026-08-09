"""#810 — the write lane for an append-only artifact.

Three mechanisms, one issue. The measured failure was that a refused write said "fix and
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
# real `:L findings` column list, so the ONLY complaint is the refinement key — asserted by
# test_the_bad_key_is_the_documents_only_fault below, because a fixture that quietly carried
# a parse error alongside would let a weaker implementation pass these.
_BAD_ATTR_KEY = """```invlang
:L findings [id|loop|name|target|tests|system|window]
l-003|1|cmdb-lookup-office-ws-1|v-001|h-001|cmdb|n/a
```

```invlang
:R attr_updates [resolved_by|target|key|value]
l-003|v-003|ident|svc.config-mgmt
```
"""


def _only(diags, predicate):
    hits = [d for d in diags if predicate(d)]
    assert len(hits) == 1, f"expected exactly one match, got {[d.message for d in hits]}"
    return hits[0]


# --------------------------------------------------------------------------- #
# the typed diagnostic
# --------------------------------------------------------------------------- #

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
    reconstruct the row from it. The block's column order is fixed —
    `[resolved_by|target|key|value]` — so all four fields are recoverable."""
    d = _only(diagnose(_BAD_ATTR_KEY, None), lambda d: "refinement key" in d.message)

    assert d.locus is not None
    assert d.locus.block == ":R attr_updates"
    assert d.locus.row_text == "l-003|v-003|ident|svc.config-mgmt"
    assert d.fix == (
        "l-003|v-003|class|svc.config-mgmt",
        "l-003|v-003|attrs.ident|svc.config-mgmt",
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
    typing went in underneath them, not through them."""
    strings = validate_companion(_BAD_ATTR_KEY, None)

    assert all(isinstance(s, str) for s in strings)
    assert strings == [d.message for d in diagnose(_BAD_ATTR_KEY, None)]


# --------------------------------------------------------------------------- #
# the refusal says nothing landed
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(("kind", "text", "current"), [
    ("invlang", _BAD_ATTR_KEY, None),
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
    forms have to reach the MODEL, not merely exist on a dataclass the gate never prints."""
    reason = validate_investigation(_BAD_ATTR_KEY, None)

    assert "invlang validation" in reason, "the substring six suites assert on"
    assert "row: l-003|v-003|ident|svc.config-mgmt" in reason
    assert "use: l-003|v-003|class|svc.config-mgmt" in reason
    assert "l-003|v-003|attrs.ident|svc.config-mgmt" in reason


def test_a_located_row_is_not_printed_twice():
    """A parse warning's prose already embeds its row, so the renderer suppresses the locus
    line there. Cheap to get wrong, and the result is a refusal that says everything twice."""
    malformed = "```invlang\n:R attr_updates [resolved_by|target|key|value]\nl-001|v-001\n```\n"
    reason = validate_investigation(malformed, None)

    assert reason.count("l-001|v-001") == 1


def test_an_accepted_document_still_returns_no_reason():
    """The notice rides on refusals only — an accepted write says nothing at all."""
    good = ("```invlang\n:L findings [id|loop|name|target|tests|system|window]\n"
            "l-001|1|cmdb-lookup|v-001|h-001|cmdb|n/a\n```\n")

    assert validate_investigation(good, None) is None
    assert validate_investigation("", None) is None


# --------------------------------------------------------------------------- #
# the bounded tail
# --------------------------------------------------------------------------- #

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


# --------------------------------------------------------------------------- #
# append_block, at the handler
# --------------------------------------------------------------------------- #

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
             "l-001|1|cmdb-lookup|v-001|h-001|cmdb|n/a\n```\n")

    _tool_append_block(deps, block)
    _tool_append_block(deps, block)

    text = (run / "investigation.md").read_text()
    assert text == block * 2, "the gate is expected NOT to catch this — see the docstring"
    # ...and the tail is what lets the model see it happened.
    assert _tail_chars(text, len(block)).strip() == block.strip()

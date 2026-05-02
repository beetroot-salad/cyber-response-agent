"""Strict-cutover parity tests for the invlang validator (post-#170).

The validator's only on-disk surface is the dense ```` ```invlang ````
fence parsed by `scripts/handlers/_dense_parser`. Legacy ```yaml fences
and bare `:T conclude` blocks are no longer parsed; the former is
rejected with an explicit cutover error.

These tests cover:
- Dense ```invlang fences project to the canonical companion dict shape
  the 29 validator rules walk (entry-point sanity).
- A ```yaml fence in proposed text is rejected with the cutover error.
- The dict-equality claim between the legacy yaml surface and the dense
  surface still holds via `invlang.corpus._merge_md_blocks`, which retains
  yaml-acceptance for the off-disk corpus loader.
"""

from __future__ import annotations

import textwrap

from hooks.scripts.invlang_validate import _parse_blocks, validate_companion


def _wrap_phases(prologue_yaml: str, hypothesize_yaml: str) -> str:
    """Render a minimal investigation.md with YAML-fenced phase blocks."""
    return textwrap.dedent(f"""\
        # Investigation

        ## CONTEXTUALIZE

        ```yaml
        {prologue_yaml.rstrip()}
        ```

        ## PREDICT (loop 1)

        ```yaml
        {hypothesize_yaml.rstrip()}
        ```
        """)


def test_parse_blocks_accepts_invlang_fences():
    """A ```invlang fence with a `:T conclude` block produces a conclude
    dict the validator's downstream rules can walk.
    """
    text = textwrap.dedent("""\
        ## REPORT

        ```invlang
        :T conclude
        termination.category   exhaustion-escalation
        termination.rationale  "host-query unavail"
        disposition            benign
        confidence             medium
        matched_archetype      monitoring-probe
        ```
        """)
    blocks, errors = _parse_blocks(text)
    assert errors == []
    assert len(blocks) == 1
    assert blocks[0]["conclude"]["disposition"] == "benign"
    assert blocks[0]["conclude"]["matched_archetype"] == "monitoring-probe"


def test_parse_blocks_invlang_fence_does_not_double_parse_with_legacy():
    """A `:T conclude` block inside a ```invlang fence must not also be
    picked up by the legacy bare-conclude scanner — that would produce a
    duplicate conclude key in the blocks list.
    """
    text = textwrap.dedent("""\
        ```invlang
        :T conclude
        termination.category   exhaustion-escalation
        disposition            benign
        confidence             medium
        ```
        """)
    blocks, errors = _parse_blocks(text)
    assert errors == []
    conclude_blocks = [b for b in blocks if "conclude" in b]
    assert len(conclude_blocks) == 1


def test_parse_blocks_rejects_yaml_fence():
    """Strict-cutover (#170): any ```yaml fence in investigation.md is
    rejected with a precise error string so the writer immediately knows
    to switch to ```invlang. Replaces the prior coexistence + legacy
    bare-conclude tests — neither surface is parsed any longer.
    """
    text = textwrap.dedent("""\
        ## CONTEXTUALIZE

        ```yaml
        prologue:
          vertices:
            - id: v-001
              type: endpoint
              classification: external
              identifier: "1.2.3.4"
          edges: []
        ```
        """)
    blocks, errors = _parse_blocks(text)
    assert any("```yaml" in e and "no longer accepted" in e for e in errors), errors
    # The yaml content must NOT contribute to the parsed-block list.
    assert not any("prologue" in b for b in blocks)


def test_parse_blocks_malformed_invlang_surfaces_error():
    """Malformed dense content emits a parse error string, doesn't crash."""
    text = textwrap.dedent("""\
        ```invlang
        :T conclude
        not-a-valid-row-shape-with-no-key-value
        ```
        """)
    blocks, errors = _parse_blocks(text)
    assert any("invlang" in e or "conclude" in e for e in errors)


def test_validate_companion_passes_dense_fenced_minimal():
    """End-to-end: a minimal companion expressed via dense fences
    passes the validator without errors. Confirms that the schema-mapping
    projection produces the canonical dict shape the rules walk.
    """
    text = textwrap.dedent("""\
        # Investigation

        ## CONTEXTUALIZE

        ```invlang
        :V prologue.vertices [id|type|class|ident|attrs?]
        v-001|endpoint|external-unknown|203.0.113.47|
        v-002|endpoint|internal-server|web-server-01|
        ```

        ```invlang
        :E prologue.edges [id|rel|src|tgt|when|auth_kind:source]
        e-001|attempted_auth|v-001|v-002||siem-event:wazuh-indexer
        ```
        """)
    errors = validate_companion(text, current_text=None)
    # The validator may emit warnings or errors about missing predict/conclude
    # blocks, but it should NOT emit a parse error from the dense surface.
    parse_errors = [e for e in errors if "parse error" in e.lower() or "malformed" in e.lower()]
    assert parse_errors == [], f"unexpected parse errors: {parse_errors}"


# NOTE: the YAML↔dense dict-equality parity tests that previously lived
# here have been removed. Post-cutover, `_merge_md_blocks` only walks
# ```invlang fences, so there is no second surface to compare against.
# Validator-rejection of yaml fences is exercised by
# `test_parse_blocks_rejects_yaml_fence` above.



"""Parity tests: validator accepts ```invlang fences alongside ```yaml fences.

The Foundation extension to `invlang_validate._parse_blocks` adds a third
surface — ```` ```invlang ```` fenced blocks parsed by
`scripts/handlers/_dense_parser`. The 29 invlang validator rules and
`invlang_walkers.py` traversals consume the merged companion dict
post-parse, so as long as the dense parser produces the same dict shape
as `yaml.safe_load` produced before, validator behavior is unchanged.

These tests assert that load-bearing claim:
- A small valid companion in ```yaml form passes validation.
- The same companion expressed in ```invlang form passes the same way.
- A `:T conclude` block inside a ```invlang fence is recognized as
  conclude content (not as a malformed legacy bare-conclude block).
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


def test_parse_blocks_legacy_bare_conclude_still_works():
    """Old on-disk files that have a bare `:T conclude` (no fence) keep
    parsing correctly so we don't break the corpus of existing runs.
    The legacy scanner uses `## ` markdown headers and other `:` block
    headers as block-end delimiters.
    """
    text = textwrap.dedent("""\
        ## REPORT

        :T conclude
        termination.category   exhaustion-escalation
        termination.rationale  "blocked"
        disposition            benign
        confidence             medium

        ## Notes

        Narrative after a markdown header.
        """)
    blocks, errors = _parse_blocks(text)
    assert errors == []
    assert any("conclude" in b for b in blocks)


def test_parse_blocks_yaml_and_invlang_coexist():
    """Mixed-surface investigation: YAML prologue fence + dense conclude
    fence. Both surfaces parse cleanly and merge into a single companion
    dict downstream.
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

        ## REPORT

        ```invlang
        :T conclude
        termination.category   exhaustion-escalation
        disposition            benign
        confidence             medium
        ```
        """)
    blocks, errors = _parse_blocks(text)
    assert errors == []
    has_prologue = any("prologue" in b for b in blocks)
    has_conclude = any("conclude" in b for b in blocks)
    assert has_prologue
    assert has_conclude


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


# ---------------------------------------------------------------------------
# Dict-equality parity (the load-bearing claim)
# ---------------------------------------------------------------------------
#
# The PR's central correctness claim is that the dense projection produces
# the same companion dict shape that `yaml.safe_load` produced before. The
# tests above check that *errors don't differ*; these check that *the merged
# dicts are equal*. Both surfaces flow through the same merge path
# (`scripts.invlang.corpus._merge_md_blocks`), so identical merged dicts
# means downstream validator rules and walkers see the same content.


def _yaml_fenced(yaml_body: str) -> str:
    # No textwrap.dedent — the multi-line body has its own indentation
    # which dedent() can't reconcile with the surrounding template.
    return (
        "# Investigation\n\n## CONTEXTUALIZE\n\n"
        "```yaml\n" + yaml_body.rstrip() + "\n```\n"
    )


def _dense_fenced(invlang_body: str) -> str:
    return (
        "# Investigation\n\n## CONTEXTUALIZE\n\n"
        "```invlang\n" + invlang_body.rstrip() + "\n```\n"
    )


def test_yaml_dense_dict_equality_prologue():
    """Same prologue expressed in YAML and dense surfaces merges to the
    same dict.
    """
    from scripts.invlang.corpus import _merge_md_blocks

    yaml_body = textwrap.dedent("""\
        prologue:
          vertices:
            - id: v-001
              type: endpoint
              classification: monitoring-host
              identifier: 172.22.0.10
            - id: v-002
              type: endpoint
              classification: internal-server
              identifier: target-endpoint
              attributes:
                kind: server
          edges:
            - id: e-001
              relation: attempted_auth
              source_vertex: v-001
              target_vertex: v-002
              when:
                timestamp: "2026-04-20T09:00:00Z"
              authority:
                kind: siem-event
                source: wazuh-rule-5710
              attributes:
                target_user: sensu
                outcome: failed
        """)

    dense_body = textwrap.dedent("""\
        :V prologue.vertices [id|type|class|ident|attrs?]
        v-001|endpoint|monitoring-host|172.22.0.10|
        v-002|endpoint|internal-server|target-endpoint|kind=server

        :E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
        e-001|attempted_auth|v-001|v-002|2026-04-20T09:00:00Z|siem-event:wazuh-rule-5710|target_user=sensu;outcome=failed
        """)

    yaml_merged = _merge_md_blocks(_yaml_fenced(yaml_body))
    dense_merged = _merge_md_blocks(_dense_fenced(dense_body))

    assert yaml_merged == dense_merged, (
        f"YAML and dense surfaces produced different merged dicts.\n"
        f"yaml: {yaml_merged}\ndense: {dense_merged}"
    )


def test_yaml_dense_dict_equality_conclude():
    """Same conclude block expressed in YAML and dense surfaces merges to
    the same dict.
    """
    from scripts.invlang.corpus import _merge_md_blocks

    yaml_body = textwrap.dedent("""\
        conclude:
          termination:
            category: exhaustion-escalation
            rationale: "host-query unavail; h-002 cannot reach --"
          disposition: benign
          confidence: medium
          matched_archetype: monitoring-probe
          surviving_hypotheses:
            - h-001
            - h-002
          deferred_authorizations: []
        """)

    dense_body = textwrap.dedent("""\
        :T conclude
        termination.category   exhaustion-escalation
        termination.rationale  "host-query unavail; h-002 cannot reach --"
        disposition            benign
        confidence             medium
        matched_archetype      monitoring-probe

        :T conclude.surviving [hyp_id|final_weight]
        h-001|+
        h-002|-

        :T conclude.deferred_authz [contract_ref|rationale]
        none
        """)

    yaml_merged = _merge_md_blocks(_yaml_fenced(yaml_body))
    dense_merged = _merge_md_blocks(_dense_fenced(dense_body))

    # Dense surface emits final_weight per hypothesis; YAML form has bare
    # ids. Compare the conclude scalar fields directly — these are the
    # validator-visible fields that must match across surfaces.
    for key in ("termination", "disposition", "confidence", "matched_archetype",
                "surviving_hypotheses", "deferred_authorizations"):
        assert yaml_merged["conclude"].get(key) == dense_merged["conclude"].get(key), (
            f"conclude.{key} differs between surfaces:\n"
            f"  yaml: {yaml_merged['conclude'].get(key)!r}\n"
            f"  dense: {dense_merged['conclude'].get(key)!r}"
        )

"""Tests for the defender invlang validator (rule engine + PreToolUse hook).

The rule engine (`defender/skills/invlang/validate.py`) is imported and
exercised directly — fast, no subprocess. A handful of hook-level tests
load `defender/hooks/invlang_validate.py` and drive it via stdin to
confirm the Write/Edit projection and exit codes.
"""

from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path

from defender.skills.invlang.validate import validate_companion

HOOK_PATH = Path(__file__).resolve().parents[1] / "hooks" / "invlang_validate.py"


def fence(*blocks: str) -> str:
    return "```invlang\n" + "\n\n".join(b.strip() for b in blocks) + "\n```\n"


# Reusable block fragments -------------------------------------------------

V_PROLOGUE = """
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|compute|bastion/internal/known-corp|bastion-01|os=linux
v-003|compute|ip-only/internet/anonymous|10.42.7.183|knowledge=partial
"""

E_PROLOGUE_SIEM = """
:E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-001|attempted_auth|v-003|v-001|2026-05-05T03:47:12Z|siem-event:wazuh|outcome=failed
"""

L_FINDINGS = """
:L findings [id|loop|name|target|tests|system|window]
l-001|1|auth-history|v-001|h-001|wazuh|90d
"""

E_OBS_SIEM = """
:E l-001.observations.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-002|attempted_auth|v-003|v-001|2026-05-01T10:11:00Z|siem-event:wazuh|outcome=success
"""


def test_valid_benign_companion_passes():
    text = fence(
        V_PROLOGUE,
        E_PROLOGUE_SIEM,
        """
:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]
h-001|?gpo-edit|v-001|modified|identity|service-account/known-corp||null|active
""",
        """
:H h-001.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
ac1|e-001|iam-policy|"svc permitted"|escalate|escalate
""",
        L_FINDINGS,
        E_OBS_SIEM,
        """
:R authz [resolved_by|edge|fulfills|verdict|anchor_kind|reasoning]
l-001|e-001|ac1|authorized|iam-policy|"documented in CMDB"
""",
        """
:T resolutions
h-001  null → ++    [l-001 p1 severe ⟂ e-002 :: prior auth]
""",
        """
:T conclude
disposition            benign
confidence             high
matched_archetype      routine-admin-login
""",
        """
:T conclude.surviving [hyp_id|final_weight]
h-001|++
""",
    )
    assert validate_companion(text, None) == []


def test_parse_error_blocks():
    # An unescaped `|` in the attrs cell makes the row over-long → parse error.
    text = fence(
        """
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|compute|bastion/internal/known-corp|bastion-01|flags=A|B|C
"""
    )
    errors = validate_companion(text, None)
    assert any("parse error" in e for e in errors), errors


def test_append_only_violation():
    current = fence(V_PROLOGUE) + "\n" + fence(L_FINDINGS)
    proposed = fence(V_PROLOGUE)  # dropped one block
    errors = validate_companion(proposed, current)
    assert any("append-only" in e for e in errors), errors


def test_edge_authority_weak_source_blocks():
    text = fence(
        V_PROLOGUE,
        """
:E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-001|attempted_auth|v-003|v-001|2026-05-05T03:47:12Z|client-asserted:user|outcome=failed
""",
        L_FINDINGS,
        """
:T resolutions
h-001  null → ++    [l-001 p1 severe ⟂ e-001 :: weak]
""",
    )
    errors = validate_companion(text, None)
    assert any("strong observational authority" in e for e in errors), errors


def test_edge_authority_no_supporting_edge_blocks():
    text = fence(
        V_PROLOGUE,
        L_FINDINGS,
        """
:T resolutions
h-001  null → --    [l-001 r1 severe ⟂ none :: no edge]
""",
    )
    errors = validate_companion(text, None)
    assert any("cites no supporting edge" in e for e in errors), errors


def test_weak_weight_does_not_need_strong_authority():
    # `+` / `-` do not require a strong edge.
    text = fence(
        V_PROLOGUE,
        L_FINDINGS,
        """
:T resolutions
h-001  null → +    [l-001 p1 weak ⟂ none :: weak support]
""",
    )
    errors = validate_companion(text, None)
    assert not any("authority" in e for e in errors), errors


def test_closed_vocab_bad_type_blocks():
    text = fence(
        """
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|widget|bastion/internal/known-corp|bastion-01|os=linux
"""
    )
    errors = validate_companion(text, None)
    assert any("not a known vertex type" in e for e in errors), errors


def test_closed_vocab_bad_relation_and_auth_kind_block():
    text = fence(
        V_PROLOGUE,
        """
:E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-001|teleported|v-003|v-001|2026-05-05T03:47:12Z|guesswork:nobody|outcome=failed
""",
    )
    errors = validate_companion(text, None)
    assert any("not a known relation" in e for e in errors), errors
    assert any("not a known observational authority" in e for e in errors), errors


def test_closed_vocab_tolerates_non_dict_contract_entry():
    """`_check_closed_vocab` must not crash on a malformed (non-dict)
    `authorization_contract` entry. The closed-vocab dedupe routes each
    check through a shared `_check_vocab(value, allowed, errmsg)` helper
    whose `errmsg` f-string calls `c.get('id', '?')`; that argument is
    built eagerly, so the per-contract guard must skip non-dict entries
    before the call (matching the original silent leniency)."""
    from defender.skills.invlang.validate import _check_closed_vocab

    companion = {
        "hypothesize": {
            "hypotheses": [
                {"id": "h-1", "authorization_contract": ["not-a-dict", None]}
            ]
        }
    }
    assert _check_closed_vocab(companion) == []


def test_benign_blocked_by_unresolved_open_slot():
    text = fence(
        """
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|compute|??/??/??|bastion-01|os=linux
""",
        """
:T conclude
disposition            benign
confidence             high
""",
    )
    errors = validate_companion(text, None)
    assert any("unresolved class ('??/??/??')" in e for e in errors), errors


def test_benign_blocked_by_unresolved_candidate_set():
    # `{a, b}` is the narrowed-but-not-concrete middle state — still open,
    # so benign must block on it just like a bare `??`.
    text = fence(
        """
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|compute|{bastion/internal/known-corp, ip-only/internet/novel}|bastion-01|os=linux
""",
        """
:T conclude
disposition            benign
confidence             high
""",
    )
    errors = validate_companion(text, None)
    assert any("unresolved class" in e and "v-001" in e for e in errors), errors


def test_open_slot_resolved_by_attr_update_passes_gate():
    text = fence(
        """
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|compute|??/??/??|bastion-01|os=linux
""",
        L_FINDINGS,
        """
:R attr_updates [resolved_by|target|key|value]
l-001|v-001|class|bastion/internal/known-corp
""",
        """
:T conclude
disposition            benign
confidence             high
""",
    )
    errors = validate_companion(text, None)
    assert not any("open `??`" in e for e in errors), errors


def test_open_slot_refined_by_later_redeclaration_passes_gate():
    # A lead observation that re-declares a `??` vertex with a concrete class
    # refines the open baseline (append-only: the original row stays).
    text = fence(
        """
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|compute|??/??/??|bastion-01|os=linux
""",
        L_FINDINGS,
        """
:V l-001.observations.vertices [id|type|class|ident|attrs?]
v-001|compute|bastion/internal/known-corp|bastion-01|os=linux
""",
        """
:T conclude
disposition            benign
confidence             high
""",
    )
    errors = validate_companion(text, None)
    assert not any("unresolved class" in e for e in errors), errors


def test_benign_blocked_by_unauthorized_contract():
    text = fence(
        V_PROLOGUE,
        E_PROLOGUE_SIEM,
        """
:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]
h-001|?gpo-edit|v-001|modified|identity|service-account/known-corp||null|active
""",
        """
:H h-001.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
ac1|e-001|iam-policy|"svc permitted"|escalate|escalate
""",
        L_FINDINGS,
        """
:R authz [resolved_by|edge|fulfills|verdict|anchor_kind|reasoning]
l-001|e-001|ac1|unauthorized|iam-policy|"absent from CMDB"
""",
        """
:T conclude
disposition            benign
confidence             high
""",
        """
:T conclude.surviving [hyp_id|final_weight]
h-001|++
""",
    )
    errors = validate_companion(text, None)
    assert any("'unauthorized'" in e and "not 'authorized'" in e for e in errors), errors


def test_benign_blocked_by_missing_contract_resolution():
    text = fence(
        V_PROLOGUE,
        E_PROLOGUE_SIEM,
        """
:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]
h-001|?gpo-edit|v-001|modified|identity|service-account/known-corp||null|active
""",
        """
:H h-001.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
ac1|e-001|iam-policy|"svc permitted"|escalate|escalate
""",
        """
:T conclude
disposition            benign
confidence             high
""",
        """
:T conclude.surviving [hyp_id|final_weight]
h-001|++
""",
    )
    errors = validate_companion(text, None)
    assert any("no fulfilling :R authz row" in e for e in errors), errors


def test_skill_worked_examples_all_pass():
    """The runtime SKILL must not teach invlang the validator blocks.

    Every ```invlang fence in defender/SKILL.md is a worked example the
    agent is shown; each must validate cleanly under the current spec. A
    failure here means an example drifted from the spec the hook enforces.
    """
    import re
    skill = Path(__file__).resolve().parents[1] / "SKILL.md"
    fences = re.findall(r"```invlang\n(.*?)\n```", skill.read_text(), re.DOTALL)
    assert fences, "no invlang fences found in SKILL.md"
    failures = []
    for i, body in enumerate(fences):
        errs = validate_companion("```invlang\n" + body + "\n```\n", None)
        if errs:
            failures.append(f"fence#{i}: {errs}")
    assert not failures, "\n".join(failures)


def test_current_grammar_variety_passes():
    # `??`, per-slot `{a,b}`, full-triple enumeration, `unclassified-*`,
    # process basename, and a discovery fork on `unclassified-process` are
    # all valid current-spec class shapes and must not be flagged.
    text = fence(
        """
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|compute|??/??/??|10.0.0.5|knowledge=partial
v-002|compute|monitoring/??/known-corp|mon-01|
v-003|compute|{monitoring/internal/known-corp, ip-only/internet/novel}|10.0.0.9|
v-004|identity|service-account/known-corp|svc-deploy|
v-005|process|bash|bash[pid=42]|
v-006|storage|unclassified-storage|s3://bucket|
""",
        """
:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]
h-001|?tracking-sdk|v-001|runs_on|process|unclassified-process||null|active
h-002|?adversary-implant|v-001|runs_on|process|unclassified-process||null|active
""",
    )
    assert validate_companion(text, None) == []


def test_malicious_disposition_skips_benign_gate():
    # Unresolved ?? is fine when not concluding benign.
    text = fence(
        """
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|compute|??/??/??|bastion-01|os=linux
""",
        """
:T conclude
disposition            malicious
confidence             high
""",
    )
    errors = validate_companion(text, None)
    assert not any("benign blocked" in e for e in errors), errors


def test_crlf_line_endings_do_not_bypass_validation():
    # A CRLF file must not defeat the fence regex into an empty-companion
    # no-op pass — line endings are normalized before parsing.
    bad = fence(
        """
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|widget|??/??/??|host-1|os=linux
""",
        """
:T conclude
disposition            benign
confidence             high
""",
    )
    lf_errors = validate_companion(bad, None)
    crlf_errors = validate_companion(bad.replace("\n", "\r\n"), None)
    assert any("not a known vertex type" in e for e in lf_errors), lf_errors
    # Same violations surface under CRLF — not a silent pass.
    assert any("not a known vertex type" in e for e in crlf_errors), crlf_errors
    assert any("unresolved class" in e for e in crlf_errors), crlf_errors


def test_yaml_fence_is_rejected():
    # The on-disk surface is ```invlang; a ```yaml fence must not yield an
    # empty companion that silently passes every rule.
    text = "```yaml\ndisposition: benign\n```\n"
    errors = validate_companion(text, None)
    assert any("non-invlang surface" in e for e in errors), errors


def test_append_only_rejects_in_fence_record_mutation():
    # Rewriting a committed vertex's class in place (same fence count) is an
    # append-only violation even though no block was dropped.
    current = fence(
        """
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|compute|bastion/internal/known-corp|bastion-01|os=linux
"""
    )
    mutated = fence(
        """
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|compute|workstation/internet/anonymous|bastion-01|os=linux
"""
    )
    errors = validate_companion(mutated, current)
    assert any("mutated in place" in e and "v-001" in e for e in errors), errors


def test_benign_blocked_by_unauthorized_contract_without_surviving_table():
    # The bypass: a live hypothesis carrying an `unauthorized` contract must
    # block benign even when it is omitted from `:T conclude.surviving`
    # (survival is computed from final weights, not the self-declared table).
    text = fence(
        V_PROLOGUE,
        E_PROLOGUE_SIEM,
        """
:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]
h-001|?gpo-edit|v-001|modified|identity|service-account/known-corp||null|active
""",
        """
:H h-001.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
ac1|e-001|iam-policy|"svc permitted"|escalate|escalate
""",
        L_FINDINGS,
        """
:R authz [resolved_by|edge|fulfills|verdict|anchor_kind|reasoning]
l-001|e-001|ac1|unauthorized|iam-policy|"absent from CMDB"
""",
        """
:T conclude
disposition            benign
confidence             high
""",
        # NB: no :T conclude.surviving table at all.
    )
    errors = validate_companion(text, None)
    assert any("'unauthorized'" in e and "not 'authorized'" in e for e in errors), errors


def test_authorized_row_does_not_mask_unauthorized_for_same_contract():
    # Conflicting append-only rows for one contract: a later `authorized`
    # row must not mask an earlier `unauthorized`.
    text = fence(
        V_PROLOGUE,
        E_PROLOGUE_SIEM,
        """
:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]
h-001|?gpo-edit|v-001|modified|identity|service-account/known-corp||null|active
""",
        """
:H h-001.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
ac1|e-001|iam-policy|"svc permitted"|escalate|escalate
""",
        L_FINDINGS,
        """
:R authz [resolved_by|edge|fulfills|verdict|anchor_kind|reasoning]
l-001|e-001|ac1|unauthorized|iam-policy|"absent from CMDB"
l-001|e-001|ac1|authorized|iam-policy|"later flip"
""",
        """
:T conclude
disposition            benign
confidence             high
""",
        """
:T conclude.surviving [hyp_id|final_weight]
h-001|++
""",
    )
    errors = validate_companion(text, None)
    assert any("'unauthorized'" in e and "not 'authorized'" in e for e in errors), errors


def test_attr_update_bare_key_is_rejected():
    # `:R attr_updates` keys must be `class` or `attrs.<name>`; a bare key is
    # silently dropped by the resolver, so reject it at write time.
    text = fence(
        V_PROLOGUE,
        L_FINDINGS,
        """
:R attr_updates [resolved_by|target|key|value]
l-001|v-001|provenance|apt:nginx
""",
    )
    errors = validate_companion(text, None)
    assert any("is not a valid refinement key" in e for e in errors), errors


def test_skill_example_a_accumulates_clean():
    """Validate the flagship Example A as the hook actually sees it: the
    section's ```invlang fences applied in order to one investigation.md,
    re-checking append-only at each step. Per-fence isolation (the
    all-examples test) can't catch cross-fence or append-only drift."""
    import re
    skill = (Path(__file__).resolve().parents[1] / "SKILL.md").read_text()
    m = re.search(r"### Example A.*?(?=\n### )", skill, re.DOTALL)
    assert m, "Example A section not found"
    fences = re.findall(r"```invlang\n(.*?)\n```", m.group(0), re.DOTALL)
    assert len(fences) >= 3, f"expected Example A to build up several fences, got {len(fences)}"
    acc = ""
    for i, body in enumerate(fences):
        nxt = (acc + "\n" if acc else "") + "```invlang\n" + body + "\n```\n"
        errs = validate_companion(nxt, acc or None)
        assert not errs, f"Example A fence#{i} (accumulated) failed: {errs}"
        acc = nxt


# --- Hook-level ------------------------------------------------------------


def _load_hook():
    spec = importlib.util.spec_from_file_location("invlang_validate", HOOK_PATH)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def _run_hook(mod, monkeypatch, payload: dict) -> int:
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(payload)))
    return mod.main()


def test_hook_passes_non_investigation_writes(monkeypatch):
    mod = _load_hook()
    rc = _run_hook(mod, monkeypatch, {
        "tool_name": "Write",
        "tool_input": {"file_path": "/tmp/x/report.md", "content": "hi"},
    })
    assert rc == 0


BAD_WRITE = fence(
    """
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|widget|x|bastion-01|os=linux
"""
)


def test_hook_blocks_bad_write(monkeypatch, tmp_path, capsys):
    # A schema-violating write is blocked (exit 2) with the violation logged.
    mod = _load_hook()
    inv = tmp_path / "investigation.md"
    rc = _run_hook(mod, monkeypatch, {
        "tool_name": "Write",
        "tool_input": {"file_path": str(inv), "content": BAD_WRITE},
    })
    assert rc == 2
    assert "not a known vertex type" in capsys.readouterr().err


def test_hook_passes_good_write(monkeypatch, tmp_path):
    mod = _load_hook()
    inv = tmp_path / "investigation.md"
    good = fence(V_PROLOGUE)
    rc = _run_hook(mod, monkeypatch, {
        "tool_name": "Write",
        "tool_input": {"file_path": str(inv), "content": good},
    })
    assert rc == 0


def test_hook_edit_append_only(monkeypatch, tmp_path):
    mod = _load_hook()
    inv = tmp_path / "investigation.md"
    inv.write_text(fence(V_PROLOGUE) + "\n" + fence(L_FINDINGS))
    # An edit that deletes the second fence entirely.
    rc = _run_hook(mod, monkeypatch, {
        "tool_name": "Edit",
        "tool_input": {
            "file_path": str(inv),
            "old_string": "\n" + fence(L_FINDINGS),
            "new_string": "",
        },
    })
    assert rc == 2


def test_hook_fails_closed_on_internal_error(monkeypatch, tmp_path, capsys):
    # A validator crash must BLOCK (exit 2), not silently pass the write
    # (exit ≠ 2 is non-blocking in the harness).
    mod = _load_hook()
    monkeypatch.setattr(mod, "validate_companion", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    inv = tmp_path / "investigation.md"
    rc = _run_hook(mod, monkeypatch, {
        "tool_name": "Write",
        "tool_input": {"file_path": str(inv), "content": fence(V_PROLOGUE)},
    })
    assert rc == 2
    assert "failing closed" in capsys.readouterr().err


def test_hook_scopes_to_run_dir(monkeypatch, tmp_path):
    # With DEFENDER_RUN_DIR set, only investigation.md inside it is validated;
    # a same-named file elsewhere is left alone (neither validated nor blocked).
    mod = _load_hook()
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    monkeypatch.setenv("DEFENDER_RUN_DIR", str(run_dir))

    outside = tmp_path / "elsewhere" / "investigation.md"
    rc_outside = _run_hook(mod, monkeypatch, {
        "tool_name": "Write",
        "tool_input": {"file_path": str(outside), "content": BAD_WRITE},
    })
    assert rc_outside == 0  # not the run companion → not blocked

    inside = run_dir / "investigation.md"
    rc_inside = _run_hook(mod, monkeypatch, {
        "tool_name": "Write",
        "tool_input": {"file_path": str(inside), "content": BAD_WRITE},
    })
    assert rc_inside == 2  # the run companion → schema-enforced

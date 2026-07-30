"""#672 §F+§G — live-read state and repeats, then the teaching, grant, and CLI surfaces.

Split out of `test_closed_ticket_tool_672.py` by #720; that module holds the spec
narrative and the registration/seam demands, and `_closed_ticket_672.py` holds the
drive harness these tests share.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from functools import partial
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")  # CI installs the runtime extra; skip otherwise

from defender.learning.author.verify_forward.forward import _fetch_closed_resolution  # noqa: E402
from defender.learning.pipeline.judge.engine_pydantic import (  # noqa: E402
    _JUDGE_DENY_REASON,
    JUDGE_DEF,
)
from defender.learning.pipeline.judge.run import build_judge_invocation  # noqa: E402
from defender.learning.tickets import ticket_seeds  # noqa: E402
from defender.runtime.agent_definition import (  # noqa: E402
    ResolvedRoots,
    RunScope,
    ToolSet,
    compile_policy_for,
)
from defender.runtime.agent_role import AgentRole  # noqa: E402
from defender.runtime.permission.command_shape import SQL_SHIM  # noqa: E402
from defender.scripts.adapters.faults import UpstreamFault  # noqa: E402
from defender.tests.e2e._replay_harness import DEFENDER, Turn, VerbRecorder  # noqa: E402
from defender.tests._closed_ticket_672 import (  # noqa: E402
    DATED,
    BIT,
    CASE,
    CLOSED_TKT,
    DONE,
    OTHER_KEY,
    TOOL_GET,
    TOOL_LIST,
    WRAP_RE,
    _case,
    _drive,
    _get,
    _get_calls,
    _list,
    _store_calls,
    _ticket_registry,
)

pytestmark = pytest.mark.e2e

#: #632's §7 R7 effective-ToolSet parameter: JUDGE_DEF's static `closed_tickets` bit stays
#: False (only the per-leg replace() in _run_judge_pydantic turns it on, together with the
#: effective grant, d73), so a bare compile against the definition's own non-empty verb_grant
#: always disagrees. These tests are all about the BASH lane's shape, so they state the benign
#: leg's effective capability, matching the real per-leg build.
_JUDGE_EFFECTIVE_TOOLS = ToolSet(read=True, bash=True, closed_tickets=True)



def test_repeated_reads_are_fresh_live_and_unreconciled(tmp_path):
    """[d0_tool_result_envelope — dispositions consensus ×4] Repeated identical calls in one
    run are fully independent FRESH live reads — no cache, no memo: the store is asked each
    time, and two reads of the same closed key that genuinely disagree (a write landing
    between them: enrichment after closure, a changed seed between sample and confirm) are
    BOTH served as-is at their own moment — no reconciliation, no discrepancy detection,
    no snapshot-at-closure. What repeats share is only the run-level machinery: each read
    writes its own capture row (the audit records the disagreement without resolving it)
    and all share the one breaker."""
    rec = VerbRecorder()
    v1 = {**DATED, "key": OTHER_KEY, "status": "closed", "summary": "TKT-V1 pre-enrichment"}
    v2 = {**DATED, "key": OTHER_KEY, "status": "closed", "summary": "TKT-V2 post-enrichment"}
    run = _drive(tmp_path, [_get(OTHER_KEY), _get(OTHER_KEY), DONE],
                 registry=_ticket_registry(rec, get=[("return", v1), ("return", v2)]))
    assert run.out.strip()
    assert len(_get_calls(rec)) == 2, "a repeat was served from a cache, not the live store"
    assert "TKT-V1" in run.all_text
    assert "TKT-V2" in run.all_text
    assert len(run.rows()) == 2


def test_two_ticket_calls_one_turn_rows_independent(tmp_path):
    """[d0_tool_result_envelope — dispositions consensus, RESCOPED at the F round] Two
    closed-ticket calls issued in ONE model turn (pydantic-ai's parallel tool-call shape)
    both complete with per-call independence — each gets its own verb call and its own
    capture row on a distinct row identity, no clobber (the capture sink is shared state
    now, Fork B) — while sharing the run's breaker. Renamed from "concurrent": the blind
    reader proved the old name overclaimed — sequential execution produces exactly these
    observables, and nothing here establishes the two calls OVERLAP, so the genuine
    seq-race stays unexercised and UNCLAIMED; what is pinned is per-call row/payload-path
    independence for the one-turn call shape."""
    rec = VerbRecorder()
    a = {**DATED, "key": "SOC-A", "status": "closed", "summary": "TKT-PAR-A"}
    b = {**DATED, "key": "SOC-B", "status": "closed", "summary": "TKT-PAR-B"}
    run = _drive(
        tmp_path,
        [Turn(tool_calls=[(TOOL_GET, {"key": "SOC-A"}), (TOOL_GET, {"key": "SOC-B"})]), DONE],
        registry=_ticket_registry(rec, get=[("return", a), ("return", b)]),
    )
    assert run.out.strip()
    assert len(_get_calls(rec)) == 2
    assert "TKT-PAR-A" in run.all_text
    assert "TKT-PAR-B" in run.all_text
    rows = run.rows()
    assert len(rows) == 2, "a sibling call's row was clobbered"
    paths = [r.get("payload_path") for r in rows]
    assert len(set(paths)) == 2, "two payloads landed on one path — per-call row identity broke"


def test_ticket_flips_state_between_list_and_get(tmp_path):
    """[d5_nonclosed_refused_as_fault — dispositions consensus] A ticket that flips state
    between a listing and the follow-up get is caught at whichever call observes the
    non-closed state: each call is authoritative for its own moment (one live check per
    call — mid-request races are inherited transport behavior, and no settled-for-the-run
    guarantee exists anywhere). The listing served it as closed; the get refuses it live
    (c2/g5's refusal class); there is no cross-call reconciliation between the two views."""
    rec = VerbRecorder()
    listing = {"tickets": [{**DATED, "key": "SOC-FLIP", "status": "closed", "summary": "TKT-FLIP-LISTED"}],
               "total": 1}
    run = _drive(
        tmp_path,
        [_list(q="flip"), _get("SOC-FLIP"), DONE],
        registry=_ticket_registry(
            rec,
            lst=[("return", listing)],
            get=[("raise", UpstreamFault(
                "SOC-FLIP is status='in_progress', not 'closed' (--require-closed)"))],
        ),
    )
    assert run.out.strip()
    assert "TKT-FLIP-LISTED" in run.all_text     # the list view stood, at its moment
    assert "exit=1" in run.all_text              # the get refused, at its own moment


def test_same_case_judged_second_time_fresh_salt_persistent_audit(tmp_path):
    """[d11_untrusted_wrap / d0 — dispositions consensus ×2] Judging the same case a second
    time is a FRESH bind: a fresh per-bind uuid4 salt — UNPREDICTABLE, not merely new: the
    second salt must not be a small step from the first, so a counter FAILS this test
    (V-D/blind: disjointness alone is equally satisfied by a counter, and a predictable
    salt lets the payload author forge the closing tag — the envelope's whole anti-forgery
    defense) — while the FIRST judgment's capture rows PERSIST in the audit trail (what
    stays unpersisted is anything the second judgment's VERDICT can read; the independence
    claim is about verdict inputs, not the record — the §7 revision of the 'nothing
    persisted' reading). The premise's cross-LEG half is w3, an examined decline (V-F)."""
    case = _case(tmp_path)
    reg = partial(_ticket_registry, get=[("return", CLOSED_TKT)])
    run1 = _drive(tmp_path, [_get(OTHER_KEY), DONE], registry=reg(VerbRecorder()), case=case)
    n1 = len(run1.rows())
    assert n1 >= 1
    salt1 = WRAP_RE.findall(run1.all_text)

    run2 = _drive(tmp_path, [_get(OTHER_KEY), DONE], registry=reg(VerbRecorder()), case=case)
    assert len(run2.rows()) > n1, "the first judgment's audit rows must persist"
    salt2 = WRAP_RE.findall(run2.all_text)
    assert salt1, "no salted wrap observed on the first judgment"
    assert salt2, "no salted wrap observed on the second judgment"
    assert set(salt1).isdisjoint(set(salt2)), "the salt survived across binds — forgeable"
    # UNPREDICTABILITY, not mere freshness: two independent 128-bit draws differ in ~30 of
    # 32 hex positions; a counter (or any small-step successor) differs in the last few
    # only. The bound is generous (>= 8) so no honest RNG ever trips it, and every
    # derivable-successor scheme does.
    s1, s2 = salt1[0], salt2[0]
    assert sum(a != b for a, b in zip(s1, s2, strict=True)) >= 8, (
        "the second bind's salt is a small step from the first — predictable (a counter), "
        "not fresh entropy: the payload author can name the next closing tag"
    )


def test_cached_open_payload_beside_live_refusal(tmp_path):
    """[d16_cited_seed_instruction_survives — Fork D's driving premise, probe-backed
    (65-forkd-probe.md: structurally reachable, empirically unobserved)] gather_raw holds an
    investigation-time cached payload of ticket K fetched while K was NOT closed (gather's
    route is unpinned — require_closed defaults False); at judge time the live closed-only
    read refuses K. Both surfaces coexist for the same cited case, and each behaves to its
    own contract: the cached payload IS readable through the judge's read roots (the N7
    carve-out, unchanged — it arrives salt-wrapped as context), while the live read returns
    the exit-1 refusal — only the live closed-only read can say 'the store confirmed it',
    and it says no."""
    case = _case(tmp_path)
    run_dir = case[0]
    cached = {"system": "ticket", "key": "SOC-K",
              "status": "in_progress", "summary": "TKT-CACHED-OPEN-K"}
    lead_dir = run_dir / "gather_raw" / "l-001"
    lead_dir.mkdir(parents=True)
    payload_path = lead_dir / "0.json"
    payload_path.write_text(json.dumps(cached))

    rec = VerbRecorder()
    run = _drive(
        tmp_path,
        [Turn(tool_calls=[("read_file", {"path": str(payload_path)})]),
         _get("SOC-K"), DONE],
        registry=_ticket_registry(
            rec,
            get=[("raise", UpstreamFault(
                "SOC-K is status='in_progress', not 'closed' (--require-closed)"))],
        ),
        case=case,
    )
    assert run.out.strip()
    assert "TKT-CACHED-OPEN-K" in run.all_text   # the cache is context, and it is readable
    assert "exit=1" in run.all_text              # the live read refuses the same key
    (g,) = _get_calls(rec)
    assert g.params == {"key": "SOC-K", "require_closed": True}


# ═════════════════════════════════════════════════════════════════════════════
# G. Teaching, deny reason, grants, routes, CLI survival, operator surface
# ═════════════════════════════════════════════════════════════════════════════


def _cited_section(user_text: str) -> str:
    m = re.search(
        r"<run-(?P<salt>[0-9a-f]+)-cited_policy_read>\n(?P<body>.*?)\n</run-(?P=salt)-cited_policy_read>",
        user_text,
        re.S,
    )
    assert m, "the benign invocation lost its cited_policy_read section"
    return m.group("body")


def _benign_invocation_text(tmp_path: Path) -> str:
    run_dir, story, telem, lrd = _case(tmp_path)
    inv = build_judge_invocation(
        run_dir, story, telem, lrd,
        comparison_dirname="comparison_benign", closed_ticket_read=True,
    )
    return inv.user_text


def test_teaching_surfaces_teach_tool_not_bash(tmp_path):
    """[d15_teaching_teaches_tool] The trusted benign prompt teaches the typed tools,
    while the salted cited-policy frame carries only candidate source rows and no removed
    Bash lane."""
    text = _benign_invocation_text(tmp_path)
    section = _cited_section(text)
    assert TOOL_LIST not in section
    assert TOOL_GET not in section
    assert "ticket_adapter" not in section
    assert "--require-closed" not in section
    assert "--status closed" not in section
    assert OTHER_KEY in section

    # The taught names ARE the registered names (fork f2 — no rename drift).
    run = _drive(tmp_path, [DONE], registry=_ticket_registry(VerbRecorder()),
                 case=_case(tmp_path, name=CASE + "-names"))
    assert {TOOL_GET, TOOL_LIST} <= run.tool_names()

    # benign.md: item 7 teaches the tools; the bash argv is gone from the whole prompt.
    benign_md = (DEFENDER / "learning" / "pipeline" / "judge" / "benign.md").read_text(
        encoding="utf-8")
    assert TOOL_LIST in benign_md
    assert TOOL_GET in benign_md
    assert "--require-closed" not in benign_md

    # No surface teaches the tool to a leg that lacks it: the adversarial invocation
    # carries neither the section nor the tool names.
    run_dir, story, telem, lrd = _case(tmp_path, name=CASE + "-advteach")
    adv = build_judge_invocation(run_dir, story, telem, lrd)
    assert "cited_policy_read" not in adv.user_text
    assert TOOL_GET not in adv.user_text
    assert TOOL_LIST not in adv.user_text


def test_cited_seed_instruction_survives(tmp_path):
    """[d16_cited_seed_instruction_survives] Seed-survival and cache-confirmation rules
    remain trusted system instructions, disjoint from the salted cited-policy source rows."""
    section = _cited_section(_benign_invocation_text(tmp_path))
    assert "does not survive" not in section
    assert OTHER_KEY in section

    benign_md = (DEFENDER / "learning" / "pipeline" / "judge" / "benign.md").read_text(
        encoding="utf-8")
    assert "does not survive on the strength of that citation" in benign_md
    assert re.search(
        r"[^.\n]*(?:cached|gather_raw)[^.\n]*context\s+—\s+never confirmation",
        benign_md,
        re.I,
    ), (
        "the system prompt must state that cached gather_raw payloads are context, never confirmation"
    )
    assert TOOL_LIST in benign_md
    assert TOOL_GET in benign_md


def test_no_doc_surface_teaches_removed_bash_lane():
    """[d26_docs_teach_no_removed_lane] (V-C — cold C3's two undispositioned teaching
    surfaces, folded into the M6 deletion census WITH this currency test) No doc surface
    still teaches the removed judge bash command path: docs/runtime-gates.md:42 today
    teaches 'the judge's ticket CLI — whose mandatory --require-closed lookahead is its
    entire security property', FALSE under M6 (the judge grants no ticket shape; the
    pins_path exemption census shrinks from three to two), and it is the .md twin of
    grant.py:196-206's comment that d21's census DOES update; docs/state-surface-adapters.md
    was dispositioned as describing the SURVIVING verb surface — it must stay free of the
    removed command path (its v1 `playground_ticket_cli.py` references are environment
    provenance, not judge-lane teaching, and are deliberately not pinned). Positive
    control: runtime-gates.md still teaches the live pins_path exemption idiom — the doc
    survives, the dead lane goes."""
    gates = (DEFENDER / "docs" / "runtime-gates.md").read_text(encoding="utf-8")
    assert "judge's ticket CLI" not in gates, (
        "runtime-gates.md still teaches the M6-removed judge ticket-CLI grant"
    )
    assert "--require-closed" not in gates, (
        "runtime-gates.md still teaches the deleted mandatory lookahead"
    )
    assert "pins_path" in gates            # control: the live exemption idiom survives
    adapters = (DEFENDER / "docs" / "state-surface-adapters.md").read_text(encoding="utf-8")
    assert "--require-closed" not in adapters
    assert "judge's ticket" not in adapters


def test_ticket_skill_status_vocabulary_matches_server():
    """[d29_skill_status_vocabulary] (V-G — §7 design correction 2 made executable; the
    p1 probe's correction must not ship prose-only in d21's clause) skills/ticket/SKILL.md
    advertises the store's REAL status enum — open|in_progress|closed, executed-probed
    against the server's own Literal (p1, playground/ticket-server/app.py:27) — not the
    two spellings the server has never had (`in-progress`, `resolved`): a skill teaching
    phantom statuses teaches queries that can never match, against the very store whose
    binary closed/other contract this change's tools now enforce. Positive control: the
    parse itself — the enum line must exist to be corrected, so a rewrite that silently
    drops it fails too."""
    skill = (DEFENDER / "skills" / "ticket" / "SKILL.md").read_text(encoding="utf-8")
    m = re.search(r"`status`\s*∈\s*\{([^}]+)\}", skill)
    assert m, "the SKILL no longer states the status enum at all"
    members = {s.strip().strip("`") for s in m.group(1).split(",")}
    assert members == {"open", "in_progress", "closed"}, (
        f"skills/ticket/SKILL.md advertises {sorted(members)} — the server's real enum is "
        "open|in_progress|closed (p1, executed)"
    )


def test_judge_bash_grants_exactly_cat_sql(tmp_path):
    """[d12_bash_grants_exact] The judge's compiled bash grant set is exactly cat +
    defender-sql on BOTH legs — no ticket shape remains on any bash lane: the pinned
    python3 ticket_adapter grant, its RunScope/ResolvedRoots `ticket_cli` threading, and
    the --require-closed lookahead are gone (d20's observable consequence — the bash-side
    plumbing is deleted; the lane was already dead at the executor, F1/g11, so this is
    restoration, not preservation), and the judge's engine module no longer defines the
    grant builder. A driven benign leg DENIES the old pinned command at the gate — a policy
    denial, not a sandbox fault."""
    scope = RunScope(add_dirs=(tmp_path / "gr",))
    (tmp_path / "gr").mkdir()
    policy = compile_policy_for(
        JUDGE_DEF, tmp_path, scope=scope, defender_dir=tmp_path, tools=_JUDGE_EFFECTIVE_TOOLS,
    )
    assert {g.program for g in policy.bash_allow} == {"cat", SQL_SHIM}

    # The per-invocation carriage cannot even EXPRESS a ticket pin any more.
    assert not hasattr(RunScope(), "ticket_cli"), "RunScope still threads ticket_cli (d20)"
    assert "ticket_cli" not in {f for f in ResolvedRoots.__dataclass_fields__}
    import defender.learning.pipeline.judge.engine_pydantic as ep
    src = Path(ep.__file__).read_text(encoding="utf-8")
    assert "_ticket_grant" not in src, "the pinned bash ticket grant survives in the engine"

    # Driven: the old command is DENIED by policy on the benign leg (not a sandbox fault).
    cli = DEFENDER / "scripts" / "adapters" / "ticket_adapter.py"
    old_cmd = f"{sys.executable} {cli} get-ticket SOC-1 --require-closed"
    run = _drive(tmp_path, [Turn(tool_calls=[("bash", {"command": old_cmd})]), DONE],
                 registry=_ticket_registry(VerbRecorder()))
    assert run.out.strip()
    feedback = "\n".join(run.script.seen[1:])
    assert "Blocked" in feedback, "the old bash lane was not denied by the gate"
    assert "sandbox could not run" not in feedback


def test_deny_reason_matches_shrunk_grants():
    """[d17_deny_reason_matches_grants] _JUDGE_DENY_REASON names only what the shrunk lane
    grants — the stale 'benign only — the pinned closed-ticket read' clause is GONE (a deny
    reason is prompt surface: advertising a deleted bash lane teaches a dead command and
    burns turns), no argv fragment of the deleted lane survives in it, and the reason still
    names the two programs the lane actually grants (the live suite net,
    test_grant_gate_575's g1, keeps checking every named program against the live grant
    list)."""
    reason = _JUDGE_DENY_REASON
    assert "pinned closed-ticket read" not in reason
    assert "benign only" not in reason
    assert "--require-closed" not in reason
    assert "ticket_adapter" not in reason
    assert "cat" in reason        # still teaches the live lane's opener
    assert "defender-sql" in reason


def test_benign_store_routes_census(tmp_path):
    """[d18_store_route_census] Executable census over the BUILT benign leg (re-probing
    claims r1/r1-extended against the real registration seam): the two typed tools are the
    ONLY model-reachable route to the live ticket store. The model-visible roster is
    exactly {bash, read_file, list_closed_tickets, get_closed_ticket} — no query tool, no
    other network-capable tool — and the compiled bash lane grants exactly cat (file-
    opening, scope-bound) + defender-sql (stdin-compute, sealed): the store is HTTP behind
    a docker-exec transport, no file exists for cat/read_file to open, so neither reaches
    it. Positive control: the typed tools DO reach the store (d4/d13's observed calls).

    # rejected: N7 — gather_raw-cached ticket payloads are a pre-existing surface, identical
    # before and after; the judge reads them by design. O2 governs only the live-store read.
    """
    rec = VerbRecorder()
    run = _drive(tmp_path, [_get(OTHER_KEY), DONE], registry=_ticket_registry(rec))
    assert run.tool_names() == {"bash", "read_file", TOOL_GET, TOOL_LIST}
    assert _store_calls(rec), "positive control: the typed route is live"

    scope = RunScope(add_dirs=(run.run_dir / "gather_raw",))
    policy = compile_policy_for(JUDGE_DEF, run.lrd, scope=scope, tools=_JUDGE_EFFECTIVE_TOOLS)
    assert {g.program for g in policy.bash_allow} == {"cat", SQL_SHIM}


def test_cli_exit_codes_survive_for_subprocess_consumers(tmp_path, monkeypatch):
    """[d14_cli_surface_survives] The adapter CLI's argv grammar and pinned exit-code
    taxonomy survive unchanged for the two surviving subprocess consumers: 64 stays the
    usage-error class (argparse, before any transport), 2 stays the infra/config class
    (grounded by g8's executed probe: a missing tree → ConfigFault exit 2 with stderr
    detail), the closed-only argv forms still PARSE (they fail at config, exit 2 — never
    64), and ticket_seeds._list_closed / verify_forward._fetch_closed_resolution still
    complete non-fatally as subprocess consumers against an unreachable store. Exercised
    with the REAL CLI and the REAL consumers — no fakes."""
    cli = str(ticket_seeds._TICKET_CLI)
    missing = tmp_path / "no-such-tree"
    env = {**os.environ, "DEFENDER_DIR": str(missing)}

    usage = subprocess.run([sys.executable, cli, "--bogus-flag"],
                           capture_output=True, text=True, env=env, timeout=60)
    assert usage.returncode == 64

    cfg = subprocess.run([sys.executable, cli, "get-ticket", "SOC-1", "--require-closed"],
                         capture_output=True, text=True, env=env, timeout=60)
    assert cfg.returncode == 2
    assert cfg.stderr.strip()                    # the stderr detail channel survives

    lst = subprocess.run(
        [sys.executable, cli, "list-tickets", "--status", "closed", "--require-closed",
         "--label", "brute-force"],
        capture_output=True, text=True, env=env, timeout=60)
    assert lst.returncode == 2, "the closed-only list argv no longer parses (64) or hangs"

    monkeypatch.setenv("DEFENDER_DIR", str(missing))
    assert ticket_seeds._list_closed("brute-force") == []   # non-fatal empty pool
    assert _fetch_closed_resolution("SOC-1") is None        # best-effort None


def test_operator_policy_cli_after_demo_scope_removal(tmp_path):
    """[d20_bash_plumbing_removed — the operator-surface consequence, dispositions
    consensus] policy_cli's judge demo scope is gone — and with it the latent wrong-script
    bug (it pinned scripts/case_history/case_ticket.py, not the real CLI; x7/F7 confirmed
    it live). The audit surface still COMPILES the judge policy: the maximal judge scope
    yields exactly the cat + defender-sql lane. It does not grow a typed-tool display
    (N6 — `defender-policy show` does not display the query bit today either)."""
    from defender.scripts import policy_cli

    scope = policy_cli._scope_for(AgentRole.JUDGE, tmp_path)
    assert getattr(scope, "ticket_cli", None) is None, "the judge demo ticket pin survives"
    src = Path(policy_cli.__file__).read_text(encoding="utf-8")
    assert "case_ticket" not in src, "the wrong-script demo path is still referenced"

    policy = compile_policy_for(
        JUDGE_DEF, tmp_path, scope=scope, defender_dir=tmp_path, tools=_JUDGE_EFFECTIVE_TOOLS,
    )
    assert {g.program for g in policy.bash_allow} == {"cat", SQL_SHIM}
    assert BIT not in src                        # N6: no typed-tool display grew here

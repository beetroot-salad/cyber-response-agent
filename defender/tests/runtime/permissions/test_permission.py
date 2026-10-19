"""Pure unit tests for the runtime permission gate (runtime/permission/): bash, read and write allow/deny decisions."""
from __future__ import annotations

import re
import functools
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")  # CI installs the runtime extra; skip otherwise

from defender.agents import MAIN_DEF  # noqa: E402
from defender.runtime import permission  # noqa: E402
from defender.runtime.agent_definition import compile_policy_for  # noqa: E402
from defender.runtime.permission.grant import PathShapes, under  # noqa: E402
from defender.tests.support.tenancy import _tenants1106 as T1106

_RUN = Path("/run")
_DFN = Path("/dfn")
MAIN = compile_policy_for(MAIN_DEF, run_dir=_RUN, defender_dir=_DFN)


@functools.cache
def _gather():
    """Gather's policy over the synthetic roots, compiled with a RUN's grant (#1106 M4:
    `GATHER_DEF` carries none) — lazily, so the module collects before the tenant folder exists."""
    return compile_policy_for(T1106.fixture_gather_def(), run_dir=_RUN, defender_dir=_DFN)


def _bash(cmd, policy):
    """Every decide_bash call threads the run roots: a `cat` operand is RESOLVED against the
    executor's cwd (`defender_dir.parent`) before its scope check, so a gate call without them
    fails closed on any file-opening stage (by design — see `bash._in_scope`)."""
    return permission.decide_bash(cmd, policy=policy, run_dir=_RUN, defender_dir=_DFN)


# bash, main loop

@pytest.mark.parametrize("cmd", [
    "defender-invlang enum types",
    "defender-lessons --tags",
    "cat /run/executed_queries.jsonl | tail -1 | wc -c",
    '''cat /run/investigation.md | defender-sql 'SELECT * FROM data WHERE ts >= "2026-01-01" AND x <= "2026-12-31"' ''',
    '''cat /run/investigation.md | grep 'trust_edges_out > 0' ''',
])
def test_main_allows_safe_commands_and_quoted_comparisons(cmd):
    assert _bash(cmd, MAIN).allow


@pytest.mark.parametrize(("cmd", "reason_substr"), [
    ("defender-elastic query foo", "not runnable from bash"),
    ("cat /run/gather_raw/l-001/0.json", "only the defender-* shims"),
    ("python3 integrations/elastic_adapter.py query foo", "not runnable from bash"),
    ("curl http://evil", "arbitrary shell"),
    ("env | grep PASSWORD", "arbitrary shell"),
])
def test_main_loop_denies(cmd, reason_substr):
    d = _bash(cmd, MAIN)
    assert not d.allow
    assert reason_substr in d.reason


# bash, gather subagent (#611: the adapter lane is gone)

def test_gather_denies_standalone_adapter():
    d = _bash("defender-elastic query foo", _gather())
    assert not d.allow
    assert d.reason == permission.ADAPTER_RETIRED_REASON
    assert "`query` tool" in d.reason


@pytest.mark.parametrize("cmd", [
    "defender-elastic query foo | wc -l",                     # piped
    "defender-elastic query foo && cat /run/report.md",       # chained (with a GRANTED viewer)
    "cat /run/report.md; defender-elastic query foo",         # sequenced
])
def test_gather_denies_compound_with_adapter(cmd):
    d = _bash(cmd, _gather())
    assert not d.allow
    assert d.reason == permission.ADAPTER_RETIRED_REASON


# The reader lane's shapes: `cat` opens (and is scope-checked), the rest read stdin.
@pytest.mark.parametrize("cmd", [
    "cat /run/gather_raw/l-001/0.json | grep hits",
    "defender-invlang enum types",
    "cat /run/gather_raw/l-001/0.json",
    '''cat /run/gather_raw/l-001/0.json | defender-sql 'SELECT * FROM data WHERE ts >= "2026-01-01" AND x <= "2026-12-31"' ''',
    '''cat /run/gather_raw/l-001/0.json | grep 'trust_edges_out > 0' ''',
])
def test_gather_allows_readonly_commands_and_quoted_comparisons(cmd):
    assert _bash(cmd, _gather()).allow


@pytest.mark.parametrize("cmd", ["curl http://evil", "rm -rf /", "python3 -c 'x'"])
def test_gather_denies_arbitrary_shell(cmd):
    assert not _bash(cmd, _gather()).allow


@pytest.mark.parametrize("cmd", [
    "cat /run/report.md > /tmp/out",
    "cat /run/report.md 1> /tmp/out",
    "cat /run/report.md >> /tmp/out",
    "cat $(cat injected)",
    'cat "$(rm -rf /)"',
    "cat /run/report.md >| /tmp/out",
    "cat secret >| /tmp/exfil",
    "cat /run/report.md &>| /tmp/out",
    "cat /run/report.md |& rm -rf /",
    "cat /run/report.md & rm -rf /",
    "cat /run/report.md 2>1",
    "cat /run/report.md 2 > 1",
    "cat /run/report.md\nrm -rf /tmp/x",
    "cat /run/report.md\ncurl http://evil",
    "bash -c 'cat /run/report.md' ; rm -rf /tmp/x",
    "bash -c 'cat /run/report.md'\nrm -rf /tmp/x",
    "bash -c 'cat /run/report.md' && curl http://evil",
    "bash -c 'cat /run/report.md' | sh",
    'bash -c "cat /run/report.md\nrm -rf /tmp/x"',
    "timeout 5 cat /run/report.md\nrm -rf /tmp/x",
    "timeout 5 cat /run/report.md ; rm -rf /tmp/x",
    "cat /run/report.md ;; rm -rf /tmp/x",
    "echo a ;& curl http://evil",
    "bash evil.sh -c 'cat /run/report.md'",
    "sh evil.sh -c 'cat /run/report.md'",
    "timeout 5 bash evil.sh -c 'cat /run/report.md'",
])
def test_both_roles_deny_redirects_substitution_and_hidden_commands(cmd):
    assert not _bash(cmd, _gather()).allow
    assert not _bash(cmd, MAIN).allow


@pytest.mark.parametrize(("wrapped", "payload"), [
    ("bash -c 'cat /run/investigation.md'", "cat /run/investigation.md"),
    ("sh -c 'cat /run/investigation.md'", "cat /run/investigation.md"),
    ("bash -c 'cat /run/investigation.md | wc -l'", "cat /run/investigation.md | wc -l"),
])
def test_a_wrapped_viewer_denies_and_its_payload_alone_does_not(wrapped, payload):
    for policy in (MAIN, _gather()):
        assert not _bash(wrapped, policy).allow, f"{wrapped!r}: `bash`/`sh` is not granted"
        assert _bash(wrapped, policy).reason == policy.deny_reason
        assert _bash(payload, policy).allow, (
            f"{payload!r} is denied too — the refusal above is not about the wrapper at all"
        )


@pytest.mark.parametrize("cmd", [
    "timeout 30 cat /run/investigation.md | wc -l",
    "timeout 5 cat /run/investigation.md",
])
def test_a_timeout_prefix_denies_and_the_same_command_without_it_does_not(cmd):
    """#971: the prefix used to be STRIPPED before the decision, so these were allows."""
    for policy in (MAIN, _gather()):
        assert not _bash(cmd, policy).allow, f"{cmd!r}: `timeout` is not a granted program"
        assert _bash(cmd, policy).reason == policy.deny_reason
        without = cmd.split(" ", 2)[2]
        assert _bash(without, policy).allow, (
            f"{without!r} is denied too — the refusal above is not about the prefix at all"
        )


@pytest.mark.parametrize("cmd", [
    "defender-elastic query 'unterminated\nrest'",
    "cat /run/report.md | jq '.a\n.b'",
    "cat /run/report.md |\nwc -l",
    "cat /run/report.md\n| wc -l",
    "cat /run/report.md &&\nwc -l /run/report.md",
    "cat /run/report.md\n&& wc -l /run/report.md",
    "cat /run/report.md | ; wc -l",
    "cat /run/report.md | && wc -l",
    "cat /run/report.md | || wc -l",
    "cat /run/report.md | | wc -l",
])
def test_unparseable_command_fails_closed_at_the_gate(cmd):
    d = _bash(cmd, _gather())
    assert not d.allow
    assert not _bash(cmd, MAIN).allow
    # the LEXING reason, not a policy one — the deny is decided before the command has a shape
    assert d.reason == permission.UNTOKENIZABLE_REASON
    assert d.pipelines is None  # nothing was parsed, so nothing is handed downstream


_LEXING_FAILURES = [
    ("unbalanced quote",            "cat /run/report.md | grep 'unterminated", "unbalanced quote"),
    ("newline in a quoted arg",     "cat /run/report.md | grep 'a\nb'",        "quoted argument"),
    ("trailing backslash",          "cat /run/report.md \\\n | wc -l",         "continues nothing"),
    ("connector opens a line",      "cat /run/report.md\n| wc -l",             "line boundary"),
    ("connector closes a line",     "cat /run/report.md |\nwc -l",             "line boundary"),
    ("leading connector, one line", "| wc -l",                                 "BOTH sides"),
    ("pipe then `;`",               "cat /run/report.md | ; wc -l",            "BOTH sides"),
    ("pipe then `|`",               "cat /run/report.md | | wc -l",            "BOTH sides"),
    ("connector then bare `;`",     "cat /run/report.md && ;",                 "BOTH sides"),
    ("pipe into a bare redirect",   "cat /run/report.md | 2> /dev/null",       "BOTH sides"),
]


@pytest.mark.parametrize("cmd", [
    "cat /run/report.md > /tmp/out",     # a write
    "cat /run/report.md & rm -rf /",     # a background job + an ungranted program
    "cat $(cat injected)",               # substitution
])
def test_a_shape_this_surface_does_not_offer_stays_a_capability_refusal(cmd):
    d = _bash(cmd, _gather())
    assert not d.allow
    assert d.reason != permission.UNTOKENIZABLE_REASON, \
        "a capability refusal was reported as a syntax error"
    assert d.reason == _gather().deny_reason


def test_the_real_pipe_the_gather_deny_reason_teaches_is_still_allowed():
    d = _bash("cat /run/gather_raw/l-1/0.json | grep hits", _gather())
    assert d.allow
    assert [[list(st.argv) for st in pl.stages] for pl in d.pipelines] == [
        [["cat", "/run/gather_raw/l-1/0.json"], ["grep", "hits"]]
    ]


# read: deny-by-default allowlist over {run_dir, defender_dir}

def _read_roots(tmp_path):
    """A run dir + a defender corpus dir for the read allowlist (both real dirs so
    `resolve()` has something to anchor)."""
    run = tmp_path / "run"
    (run / "gather_raw" / "l-001").mkdir(parents=True)
    dfn = tmp_path / "defender"
    (dfn / "skills" / "elastic").mkdir(parents=True)
    (dfn / "lessons").mkdir(parents=True)
    return run, dfn


def test_read_allows_in_root_corpus_and_run(tmp_path):
    run, dfn = _read_roots(tmp_path)
    main = compile_policy_for(MAIN_DEF, run_dir=run, defender_dir=dfn)
    for p in (run / "alert.json", run / "investigation.md", run / "executed_queries.jsonl",
              dfn / "skills" / "elastic" / "SKILL.md"):
        assert permission.decide_read(
            p, run_dir=run, defender_dir=dfn, policy=main).allow, p
    # a bare SKILL.md directly under defender_dir (outside lessons/skills/examples) is NOT a tight
    # corpus `.md`, so the read_allow shapes deny it — parity with the bash cat lane.
    assert not permission.decide_read(
        dfn / "SKILL.md", run_dir=run, defender_dir=dfn, policy=main).allow


@pytest.mark.parametrize("path", [
    "/workspace/.env",                               # the secret-grope the policy targets
    "/etc/passwd",
    "/home/user/.ssh/id_rsa",
    "/workspace/docs/playground-elastic-stack.md",   # real env doc, but out of corpus
    "fixtures/held-out/cases.json",                  # relative → resolves outside roots
])
def test_read_denies_outside_roots(tmp_path, path):
    # Deny-by-default: a read outside {run_dir, defender_dir} fails closed regardless
    # of filename — the structural close for the cat-.env / basename / case gaps.
    run, dfn = _read_roots(tmp_path)
    main = compile_policy_for(MAIN_DEF, run_dir=run, defender_dir=dfn)
    assert not permission.decide_read(
        Path(path), run_dir=run, defender_dir=dfn, policy=main).allow, path


def test_read_traversal_escape_denied(tmp_path):
    # resolve() collapses `..`, so a path whose prefix is in-root but which escapes
    # the root fails the allowlist.
    run, dfn = _read_roots(tmp_path)
    main = compile_policy_for(MAIN_DEF, run_dir=run, defender_dir=dfn)
    assert not permission.decide_read(
        run / ".." / "outside.txt", run_dir=run, defender_dir=dfn, policy=main).allow


@pytest.mark.parametrize("name", [".env", "credentials.txt", "ground_truth.yaml", "cases.json"])
def test_read_denylist_is_belt_and_suspenders_inside_a_root(tmp_path, name):
    run, dfn = _read_roots(tmp_path)
    main = compile_policy_for(MAIN_DEF, run_dir=run, defender_dir=dfn)
    assert not permission.decide_read(
        run / name, run_dir=run, defender_dir=dfn, policy=main).allow, name
    assert permission.decide_read(          # positive control: same root, benign name
        run / "report.md", run_dir=run, defender_dir=dfn, policy=main).allow


def test_read_ssh_dir_component_denied_inside_a_shape(tmp_path):
    run, dfn = _read_roots(tmp_path)
    main = compile_policy_for(MAIN_DEF, run_dir=run, defender_dir=dfn)
    assert not permission.decide_read(
        dfn / "lessons" / ".ssh" / "id_rsa.md", run_dir=run, defender_dir=dfn, policy=main).allow
    assert permission.decide_read(          # positive control: same shape, no denied component
        dfn / "lessons" / "auth" / "scope.md", run_dir=run, defender_dir=dfn, policy=main).allow


def test_read_main_loop_gather_raw_not_enumerated_gather_allowed(tmp_path):
    run, dfn = _read_roots(tmp_path)
    main = compile_policy_for(MAIN_DEF, run_dir=run, defender_dir=dfn)
    gather = compile_policy_for(T1106.fixture_gather_def(), run_dir=run, defender_dir=dfn)
    raw = run / "gather_raw" / "l-001" / "0.json"
    d = permission.decide_read(raw, run_dir=run, defender_dir=dfn, policy=main)
    assert not d.allow
    assert "must not read gather_raw" in d.reason
    assert permission.decide_read(raw, run_dir=run, defender_dir=dfn, policy=gather).allow


def test_alert_is_untrusted():
    assert permission.is_untrusted_read(Path("/tmp/defender-runs/x/alert.json"))
    assert not permission.is_untrusted_read(Path("/tmp/defender-runs/x/report.md"))


_VALID_REPORT = "---\ndisposition: benign\n---\nConcise analysis.\n"


def _run_dir_pol(run_dir):
    """A main-style policy: its one declared write surface is the run-dir subtree."""
    return permission.AgentPolicy(write_allow=(permission.build_write_allow(run_dir),))


def _skills_pol(skills):
    """A lead-author-style policy: defender/skills/**.md only."""
    return permission.AgentPolicy(write_allow=(permission.build_write_allow(skills, suffix=".md"),))


def test_write_outside_run_dir_denied(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    d = permission.decide_write(tmp_path / "evil.txt", "x", run_dir=run_dir,
                                defender_dir=tmp_path / "defender", policy=_run_dir_pol(run_dir))
    assert not d.allow


def test_write_report_allowed(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    d = permission.decide_write(run_dir / "report.md", _VALID_REPORT, run_dir=run_dir,
                                defender_dir=tmp_path / "defender", policy=_run_dir_pol(run_dir))
    assert d.allow


def test_write_investigation_invalid_invlang_denied(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    # A ```yaml fence is rejected by the invlang surface check (Rule 0).
    bad = "```yaml\nfoo: bar\n```\n"
    d = permission.decide_write(run_dir / "investigation.md", bad, run_dir=run_dir,
                                defender_dir=tmp_path / "defender", policy=_run_dir_pol(run_dir))
    assert not d.allow
    assert "invlang validation" in d.reason


def test_decide_write_requires_policy_and_roots(tmp_path):
    """decide_write requires an explicit policy AND both run roots — omitting any of the three is a TypeError, never a silent default."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    with pytest.raises(TypeError):
        permission.decide_write(run_dir / "x.md", "b\n")  # no policy=, no roots
    with pytest.raises(TypeError):
        permission.decide_write(run_dir / "x.md", "b\n", policy=_run_dir_pol(run_dir))  # no roots
    with pytest.raises(TypeError):  # run_dir only — read containment needs BOTH roots
        permission.decide_write(run_dir / "x.md", "b\n", run_dir=run_dir,
                                policy=_run_dir_pol(run_dir))
    with pytest.raises(TypeError):  # defender_dir only — and `run_dir` is THE root #681 is about,
        permission.decide_write(run_dir / "x.md", "b\n",  # so its omission is the leg to pin
                                defender_dir=tmp_path / "defender", policy=_run_dir_pol(run_dir))


def test_write_allow_admits_declared_denies_sibling(tmp_path):
    skills = tmp_path / "defender" / "skills"
    (skills / "elastic").mkdir(parents=True)
    (tmp_path / "defender" / "lessons").mkdir(parents=True)
    pol = _skills_pol(skills)
    dfn = tmp_path / "defender"
    assert permission.decide_write(skills / "elastic" / "x.md", "b\n", run_dir=tmp_path / "run",
                                   defender_dir=dfn, policy=pol).allow
    assert not permission.decide_write(dfn / "lessons" / "z.md", "b\n", run_dir=tmp_path / "run",
                                       defender_dir=dfn, policy=pol).allow


def test_write_allow_md_only_denies_non_md(tmp_path):
    skills = tmp_path / "defender" / "skills"
    (skills / "invlang").mkdir(parents=True)
    pol = _skills_pol(skills)
    dfn = tmp_path / "defender"
    assert permission.decide_write(skills / "elastic.md", "b\n", run_dir=tmp_path / "run",
                                   defender_dir=dfn, policy=pol).allow
    assert not permission.decide_write(skills / "invlang" / "validate.py", "evil\n",
                                       run_dir=tmp_path / "run", defender_dir=dfn, policy=pol).allow
    # rejected: allow any file under skills — that lets the writer clobber invlang/connect .py code,
    #           caught only late by the loop's .md-only scope gate (after the worktree carries it)


def test_write_allow_no_implicit_run_dir(tmp_path):
    """the flat allowlist REPLACES the old run-dir base (no implicit run_dir): a writer that declares only a skills subtree may NOT write run_dir."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    skills = tmp_path / "defender" / "skills"
    skills.mkdir(parents=True)
    pol = _skills_pol(skills)
    dfn = tmp_path / "defender"
    assert not permission.decide_write(run_dir / "report.md", _VALID_REPORT, run_dir=run_dir,
                                       defender_dir=dfn, policy=pol).allow
    assert permission.decide_write(skills / "x.md", "b\n", run_dir=run_dir,
                                   defender_dir=dfn, policy=pol).allow


def test_write_allow_traversal_escape_denied(tmp_path):
    """a `..` escape out of the declared subtree is denied after resolve() collapses it (the pattern
    matches the RESOLVED path, so `skills/../lessons/z.md` lands outside the allowlist)."""
    skills = tmp_path / "defender" / "skills"
    skills.mkdir(parents=True)
    (tmp_path / "defender" / "lessons").mkdir(parents=True)
    pol = _skills_pol(skills)
    escape = skills / ".." / "lessons" / "z.md"
    assert not permission.decide_write(escape, "b\n", run_dir=tmp_path / "run",
                                       defender_dir=tmp_path / "defender", policy=pol).allow


def test_write_empty_allow_denies_all(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    pol = permission.AgentPolicy()  # write_allow=()
    assert not permission.decide_write(run_dir / "report.md", _VALID_REPORT, run_dir=run_dir,
                                       defender_dir=tmp_path / "defender", policy=pol).allow
    # rejected: an implicit run_dir base — it silently granted every agent (incl. read-only
    #           predictors) run-dir writes; deny-by-default forces each writer to declare its paths


def test_write_allow_corpus_file_named_investigation_not_gated(tmp_path):
    """invlang validation is keyed on `<run_dir>/investigation.md`, so a CORPUS file that merely"""
    skills = tmp_path / "defender" / "skills"
    skills.mkdir(parents=True)
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    dfn = tmp_path / "defender"
    bad = "```yaml\nfoo: bar\n```\n"
    pol = _skills_pol(skills)
    assert permission.decide_write(skills / "investigation.md", bad, run_dir=run_dir,
                                   defender_dir=dfn, policy=pol).allow
    assert permission.decide_write(skills / "note.md", "plain text\n", run_dir=run_dir,
                                   defender_dir=dfn, policy=pol).allow
    # positive control: the run-dir root artifact, same text, same gate → denies on invlang.
    d = permission.decide_write(run_dir / "investigation.md", bad, run_dir=run_dir,
                                defender_dir=dfn, policy=_run_dir_pol(run_dir))
    assert not d.allow
    assert "invlang validation" in d.reason


# gather subagent: compute + adapter surface

def test_gather_drops_find():
    for cmd in ("find /workspace -type d -name gather",
                "find skills/gather/queries -name '*.md'"):
        assert not _bash(cmd, _gather()).allow, cmd
        assert not _bash(cmd, MAIN).allow, cmd


def test_gather_keeps_local_computation():
    for cmd in ("cat /run/gather_raw/l-001/1.json | defender-sql 'SELECT count(*) FROM data'",
                "cat /run/gather_raw/l-001/1.json | wc -c"):
        assert _bash(cmd, _gather()).allow, cmd


_PAYLOAD_PIPE = "cat /run/gather_raw/l-001/0.json | defender-sql"


@pytest.mark.parametrize("flags", [
    "--rows values --names columns",
    "--names columns --rows values",
    "--rows tables[0].rows --names tables[0].columns",
    "--rows=tables[0].rows --names=tables[0].columns",
    "--rows=values --names columns",
    # The gate admits `--rows` alone: both-or-neither is the TOOL's check (its exit 1 names the
    # missing flag and routes the call to the pitfalls curator as a lesson).
    "--rows values",
])
def test_gather_admits_the_declared_rows_flags_on_defender_sql(flags):
    """#1138 O7: the lead can INVOKE the declaration from gather's bash lane — `--rows` and"""
    for cmd in (f"{_PAYLOAD_PIPE} {flags} 'SELECT count(*) AS n FROM data'",
                f"{_PAYLOAD_PIPE} 'SELECT count(*) AS n FROM data' {flags}"):
        decision = _bash(cmd, _gather())
        assert decision.allow, (cmd, decision.reason)


from defender.execution import bash_exec  # noqa: E402 — grouped with its test section


def _shape(cmd):
    # `parse` takes the raw command text directly (#959 D1/C3) — the standalone wrapper step
    # has folded into it, so there is no second function to apply first any more.
    return bash_exec.parse(cmd)


from defender.runtime.permission import AgentPolicy, Grant  # noqa: E402


def test_policy_read_roots_extend_the_allowlist(tmp_path):
    run, dfn = _read_roots(tmp_path)
    main = compile_policy_for(MAIN_DEF, run_dir=run, defender_dir=dfn)
    extra = tmp_path / "learning_run" / "comparison"
    extra.mkdir(parents=True)
    target = extra / "l-001.md"
    with_root = AgentPolicy(read_roots=(extra,))
    assert permission.decide_read(target, run_dir=run, defender_dir=dfn, policy=with_root).allow
    assert not permission.decide_read(target, run_dir=run, defender_dir=dfn, policy=main).allow


def test_policy_read_roots_still_subject_to_denylist(tmp_path):
    run, dfn = _read_roots(tmp_path)
    extra = tmp_path / "learning_run"
    extra.mkdir(parents=True)
    pol = AgentPolicy(read_roots=(extra,))
    assert not permission.decide_read(
        extra / "ground_truth.yaml", run_dir=run, defender_dir=dfn, policy=pol).allow
    assert not permission.decide_read(
        extra / ".env", run_dir=run, defender_dir=dfn, policy=pol).allow
    assert permission.decide_read(          # positive control: the root really is granted
        extra / "l-001.md", run_dir=run, defender_dir=dfn, policy=pol).allow


_PY_CLI = Grant(
    program="python3",
    pattern=re.compile(r"^python3 integrations/elastic_adapter\.py .*$"),
    pins_path=True,
)


def test_policy_bash_allow_claims_before_adapter_classification():
    cmd = "python3 integrations/elastic_adapter.py query foo"
    no_allow = AgentPolicy(deny_reason="nope")
    assert not _bash(cmd, no_allow).allow  # adapter-denied
    with_allow = AgentPolicy(bash_allow=(_PY_CLI,), deny_reason="nope")
    assert _bash(cmd, with_allow).allow


def test_policy_bash_allow_non_match_falls_through_to_deny():
    # A command matching no `bash_allow` grant does not widen anything — a non-adapter,
    # non-matching command fails closed.
    pol = AgentPolicy(bash_allow=(_PY_CLI,), deny_reason="nope")
    assert not _bash("rm -rf /tmp/x", pol).allow


def test_policy_untabled_program_fails_loud():
    with pytest.raises(ValueError, match="untabled"):
        AgentPolicy(bash_allow=(Grant(program="strings", pattern=re.compile(r"^strings .*$")),))


def test_policy_scope_not_shape_breadth_is_containment():
    claim_all = AgentPolicy(bash_allow=(Grant(
        program="cat",
        pattern=re.compile(r"^cat .*$"),
        scope=PathShapes([under(_RUN, r"[\w.@=+-]+")]),
    ),))
    assert not _bash("cat /run/gather_raw/l-001/0.json", claim_all).allow
    assert not _bash("cat /etc/passwd", claim_all).allow
    assert _bash("cat /run/report.md", claim_all).allow  # positive control: in scope

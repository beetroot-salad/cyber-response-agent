"""#1107 — the censuses and the env lint that keep tenant settings out of the environment (D2, D4,
N3, S3, F7, O7, NF-7, MF-14).

Two instruments, each a production-shaped observation of the source tree:

  * the CENSUSES (`_census_1107`): test-side AST / line scanners, each ONE function over a root.
    The negative runs it over the checkout and asserts no finding — with the in-test precondition
    that it scanned a non-empty file set; its paired `*_detects_planted` control runs the SAME
    function over a tmp tree laid out like the repo holding one planted violation and asserts the
    finding names that file and line. The two together are what make the negative evidence;
  * the LINT (`scripts/lint/lint_tenant_env_reads.py`, O7/NF-7, absent at base): loaded fresh by
    path and driven through its own `main(argv) -> int` (d0: 0 clean, non-zero with `path:line`
    findings) — over the checkout (`[]`) or over a planted tree (`--root <tree>`, coined in
    `_spec1107.run_env_lint`). Every planted tree is first given all four swept trees (an
    innocuous module in each), so a lint that refuses a tree missing a swept directory (the
    `lint_monkeypatch` exit-2 shape) is not what a test observes.

s017's second half drives the REAL `cmdb_adapter.get_host` on a record the real resolver built,
with the config key exported into both the process env and the verb's `ctx.env`, through the
`docker` shim first on that env's PATH (CX8: the shim receives the argv the transport forked).
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import yaml

from defender.scripts.adapters import cmdb_adapter
from defender.tests.tenant_1107_settings import _census_1107 as C
from defender.tests.tenant_1107_settings import _spec1107 as S

REPO = S.REPO_ROOT
LINT_REL = f"scripts/lint/{S.ENV_LINT}.py"
BASELINE = REPO / "scripts" / "lint" / f"{S.ENV_LINT}_baseline.json"

# ======================================================================================
# Planted trees.
# ======================================================================================

def _skeleton(root: Path) -> Path:
    """Give `root` all four swept trees (C.SWEPT), each holding one clean module, and return it."""
    for rel in C.SWEPT:
        target = rel if rel.endswith(".py") else f"{rel}/clean_1107.py"
        S.plant_module(root, target, "VALUE = 1\n")
    return root


def _lines(text: str) -> dict[str, int]:
    """`{label: line}` for every line ending in a `# @label` marker."""
    out = {}
    for n, line in enumerate(text.splitlines(), start=1):
        m = re.search(r"#\s*@([\w-]+)\s*$", line)
        if m:
            out[m.group(1)] = n
    return out


def _reported(output: str, rel: str, line: int) -> bool:
    """Whether the lint's output names `rel` (repo-relative) at `line` — root-relative,
    defender-relative or absolute spelling alike."""
    tail = rel.removeprefix("defender/")
    return re.search(rf"(?:^|[\s/'\"(]){re.escape(tail)}:{line}(?!\d)", output, re.M) is not None


def _names(output: str, rel: str) -> bool:
    return rel.removeprefix("defender/") in output


def _has(findings: list[str], rel: str, line: int) -> bool:
    return any(f.startswith(f"{rel}:{line}:") for f in findings)


# ======================================================================================
# D4 — the Elastic keys are interpreted in one place.
# ======================================================================================

@pytest.mark.gate
def test_d4_elastic_keys_one_place():
    """Outside the ElasticSettings view and the elastic adapter, no platform module (runtime/,
    learning/, run.py) reads an ELASTIC_* or ELASTICSEARCH_URL key out of a SystemConfig or a config
    file. Platform code interprets the Elastic keys only through record.elastic. F12 resolved
    (auto): the census flags reads of a key's value from a SystemConfig or a config file outside the
    view; a verb-to-field mapping re-expressed over ElasticSettings attributes passes."""
    # The interacting sites at base: the estate stager's configured_patterns / default-index map,
    # staging's write_door_from_env, lead-zero's _resolve_item1 — each reads the keys raw.
    scanned, found = C.elastic_key_reads(REPO)
    assert scanned > 0, "the key census scanned no platform module — it can see nothing"
    assert found == [], (
        "platform code reads Elastic keys raw instead of through record.elastic:\n"
        + "\n".join(found))


def test_d4_keys_census_detects_planted(tmp_path):
    """The same key census, run over a planted platform module that reads ELASTIC_ALERTS_INDEX from
    a SystemConfig, reports that module."""
    planted = ("def alerts_index(record):\n"
               "    cfg = record.systems['elastic']\n"
               "    return cfg['ELASTIC_ALERTS_INDEX']  # @subscript\n"
               "\n"
               "_KEY = 'ELASTIC_ALERTS_INDEX'\n"
               "\n"
               "def alerts_index_by_name(cfg):\n"
               "    return cfg.get(_KEY)  # @named-key\n")
    # F12's pass case: a verb-to-field mapping over ElasticSettings attributes.
    passing = ("_FIELD = {'query': 'events_index', 'alerts': 'alerts_index'}\n"
               "\n"
               "def index_for(record, verb):\n"
               "    return getattr(record.elastic, _FIELD[verb])\n")
    S.plant_module(tmp_path, "defender/runtime/planted_1107.py", planted)
    S.plant_module(tmp_path, "defender/learning/branch/view_user_1107.py", passing)
    at = _lines(planted)

    scanned, found = C.elastic_key_reads(tmp_path)

    assert scanned == 2, f"the census did not scan both planted modules: {scanned}"
    for label in ("subscript", "named-key"):
        assert _has(found, "defender/runtime/planted_1107.py", at[label]), (
            f"the key census missed the planted {label} read of ELASTIC_ALERTS_INDEX: {found}")
    assert not [f for f in found if "view_user_1107" in f], (
        f"the census flagged a mapping over ElasticSettings attributes (F12 passes it): {found}")


# ======================================================================================
# S3 — nothing copies settings/ into a run or an episode.
# ======================================================================================

@pytest.mark.gate
def test_s3_no_settings_copy_census():
    """No production code copies a file or its bytes from a tenant's settings/ folder into a run dir
    or an episode dir. A census over every copy and write call whose source derives from
    RunTenant.settings or a settings/ path finds none."""
    scanned, found = C.settings_copies(REPO)
    assert scanned > 0, "the copy census scanned no production module — it can see nothing"
    assert found == [], "production code copies out of a tenant's settings/:\n" + "\n".join(found)


def test_s3_census_detects_planted_copy(tmp_path):
    """The same census, run over a planted module that shutil.copy's a file from record.settings
    into run_dir, reports it."""
    planted = ("import shutil\n"
               "\n"
               "\n"
               "def stage(record, run_dir, episode_dir):\n"
               "    shutil.copy(record.settings / 'systems' / 'cmdb' / 'config.env',  # @copy\n"
               "                run_dir / 'config.env')\n"
               "    src = record.settings / 'secrets.env'\n"
               "    (episode_dir / 'secrets.env').write_bytes(src.read_bytes())  # @bytes\n")
    rel = "defender/learning/branch/planted_1107.py"
    S.plant_module(tmp_path, rel, planted)
    at = _lines(planted)

    scanned, found = C.settings_copies(tmp_path)

    assert scanned == 1, f"the census did not scan the planted module: {scanned}"
    assert _has(found, rel, at["copy"]), f"the census missed shutil.copy from record.settings: {found}"
    assert _has(found, rel, at["bytes"]), f"the census missed a byte copy from settings: {found}"


# ======================================================================================
# F7 — settings_dir survives only on the resolver side.
# ======================================================================================

def test_d_settings_dir_grep_rule():
    """A census of settings_dir over non-test code finds every remaining hit either on RunTenant/the
    resolver or naming the path without reading under it (F7 resolved auto: the allow-list is the
    resolver and its components run_tenant.py, _tenants.py, verb_dispositions.py and
    lead_zero_config.py; the path-namer query_tool._model_visible; and validate_scaffold, a folder
    validator reading the folder it validates). No adapter, screen, applier, writer, stager, door or
    lead-zero frame reads a file under a settings_dir."""
    scanned, found = C.settings_dir_hits(REPO)
    assert scanned > 0, "the settings_dir census scanned no production module — it can see nothing"
    assert found == [], (
        "settings_dir outside F7's allow-list (resolver, its components, _model_visible, "
        "validate_scaffold):\n" + "\n".join(found))


def test_d_settings_dir_census_detects_planted(tmp_path):
    """The same census, run over a planted module that reads settings_dir / 'systems' / x /
    'config.env', reports it."""
    planted = ("def load(settings_dir, x):\n"
               "    return (settings_dir / 'systems' / x / 'config.env').read_text()  # @read\n")
    rel = "defender/scripts/adapters/planted_1107.py"
    S.plant_module(tmp_path, rel, planted)
    # The allow-list is by file: the same text in the resolver is not a finding.
    S.plant_module(tmp_path, "defender/runtime/run_tenant.py", planted)

    scanned, found = C.settings_dir_hits(tmp_path)

    assert scanned == 2, f"the census did not scan both planted modules: {scanned}"
    assert _has(found, rel, _lines(planted)["read"]), (
        f"the census missed a read under settings_dir in an adapter: {found}")
    assert not [f for f in found if "run_tenant.py" in f], (
        f"the census flagged the resolver, which F7 allows: {found}")


# ======================================================================================
# N3 — the swept trees take their location and env from the caller.
# ======================================================================================

def test_n3_helper_lookups_removed():
    """In the four swept trees (scripts/adapters, learning/branch/estate,
    scripts/case_history, runtime/lead_zero*), no function other than
    one named main calls process_defender_dir() or run_common.run_env(), or looks up DEFENDER_DIR or
    DEFENDER_RUN_DIR. The location and the env come from the caller (F6 resolved: run.py passes its
    run env)."""
    # rejected: N3: PATHS.defender_dir stays; it is a module constant from the checkout, not an environment read (CX18)
    scanned, found = C.helper_location_lookups(REPO)
    assert scanned > 0, "the helper census scanned no module in the four trees — it can see nothing"
    assert found == [], (
        "a swept-tree function finds its location/env for itself:\n" + "\n".join(found))


def test_n3_census_detects_planted(tmp_path):
    """That census, run over a planted module in one of the trees that calls process_defender_dir()
    outside main, reports it."""
    planted = ("from defender._paths import process_defender_dir\n"
               "\n"
               "\n"
               "def locate():\n"
               "    return process_defender_dir()  # @helper\n"
               "\n"
               "\n"
               "def main(argv=None):\n"
               "    return process_defender_dir()  # @main\n")
    rel = "defender/scripts/case_history/planted_1107.py"
    S.plant_module(tmp_path, rel, planted)
    at = _lines(planted)

    scanned, found = C.helper_location_lookups(tmp_path)

    assert scanned == 1, f"the census did not scan the planted module: {scanned}"
    assert _has(found, rel, at["helper"]), (
        f"the census missed process_defender_dir() outside main: {found}")
    assert not _has(found, rel, at["main"]), f"the census flagged the call inside main: {found}"


# ======================================================================================
# D2 — no SOC_PLAYGROUND_* setting is read from an environment.
# ======================================================================================

@pytest.mark.gate
def test_d2_soc_playground_not_read(tmp_path):
    """No production module under defender/ reads a SOC_PLAYGROUND_* name from any environment,
    whether os.environ or ctx.env."""
    # rejected: N8: infra/bin/es.sh keeps reading its variables; it is lab tooling outside the census
    # Positive control (no paired planted demand): the census DOES report both lookup shapes.
    planted = ("import os\n"
               "\n"
               "\n"
               "def context(ctx):\n"
               "    a = ctx.env.get('SOC_PLAYGROUND_DOCKER_CONTEXT', 'x')  # @ctx-env\n"
               "    b = os.environ['SOC_PLAYGROUND_ES_CONTAINER']  # @os-environ\n"
               "    return a, b\n")
    rel = "defender/scripts/adapters/planted_1107.py"
    S.plant_module(tmp_path, rel, planted)
    _, control = C.soc_playground_reads(tmp_path)
    at = _lines(planted)
    missed = [label for label in at if not _has(control, rel, at[label])]
    assert missed == [], f"the census cannot see a planted SOC_PLAYGROUND_* read ({missed}): {control}"

    scanned, found = C.soc_playground_reads(REPO)
    assert scanned > 0, "the SOC_PLAYGROUND census scanned no production module — it can see nothing"
    assert found == [], "production code reads SOC_PLAYGROUND_* settings:\n" + "\n".join(found)


# ======================================================================================
# O7 / NF-7 — the lint.
# ======================================================================================

_EACH_FORM = """\
import os

from defender._env import env_bool, env_choice, env_int, env_str


def verb(ctx):
    a = os.environ["X_1107"]  # @environ-subscript
    b = os.environ.get("X_1107")  # @environ-get
    c = os.environ  # @environ-bare
    d = dict(os.environ)  # @environ-dict
    e = os.getenv("X_1107")  # @getenv
    f = env_str("X_1107", "")  # @env_str
    g = env_int("X_1107", 0)  # @env_int
    h = env_bool("X_1107", False)  # @env_bool
    i = ctx.env.get("X_1107")  # @ctx-env-get
    j = ctx.env["X_1107"]  # @ctx-env-subscript
    k = env_choice("X_1107", "a", ("a", "b"))  # @env_choice
    return a, b, c, d, e, f, g, h, i, j, k
"""


def test_o7_lint_flags_each_form(tmp_path):
    """lint_tenant_env_reads, run over a planted module in each of the four trees, reports each of
    these: os.environ in any use (subscript, .get, bare reference, dict(os.environ)); os.getenv;
    env_str, env_int, env_bool and env_choice; and ctx.env.get(...) or ctx.env[...] on a
    context."""
    # R8 (auto): F15's third bullet — `_env.env_choice` arrives with the rebase (G35); the lint is
    # AST-based, so the planted call needs no symbol at base. `_env.deployment()` is a platform
    # accessor (N5) and is recorded as no-consequence, not pinned either way.
    # rejected: D6/N3: a lookup made through a shared helper (process_defender_dir, run_common.run_env) is not the lint's to catch
    # rejected: N5: platform settings (data root, log format, provider keys, budgets) stay in the environment, outside the four trees
    _skeleton(tmp_path)
    planted = [
        "defender/scripts/adapters/planted_1107.py",
        "defender/learning/branch/estate/planted_1107.py",
        "defender/scripts/case_history/planted_1107.py",
        "defender/runtime/lead_zero/planted_1107.py",
        "defender/runtime/lead_zero_config.py",
    ]
    for rel in planted:
        S.plant_module(tmp_path, rel, _EACH_FORM)
    at = _lines(_EACH_FORM)

    rc, out = S.run_env_lint(tmp_path)

    assert rc != 0, f"the lint exited 0 over {len(planted)} planted violating modules:\n{out}"
    missed = [f"{rel}:{at[label]} ({label})" for rel in planted for label in at
              if not _reported(out, rel, at[label])]
    assert missed == [], "the lint did not report:\n" + "\n".join(missed) + f"\n--- output:\n{out}"


def test_o7_lint_allows_passthrough(tmp_path):
    """The lint reports none of these: dict(ctx.env); env=ctx.env passed to a child; any lookup
    inside a function named main; any module outside the four trees."""
    # rejected: N4: adapters still hand the run's cleaned env to their children untouched
    _skeleton(tmp_path)
    inside = ("import os\n"
              "import subprocess\n"
              "\n"
              "\n"
              "def verb(ctx, argv):\n"
              "    child_env = dict(ctx.env)\n"
              "    subprocess.run(argv, env=ctx.env, check=False, timeout=5)\n"
              "    subprocess.run(argv, env=dict(ctx.env), check=False, timeout=5)\n"
              "    return child_env\n"
              "\n"
              "\n"
              "def main(argv=None):\n"
              "    run_dir = os.environ.get('DEFENDER_RUN_DIR')\n"
              "    token = os.environ['X_1107']\n"
              "    return run_dir, token, os.getenv('X_1107')\n")
    outside = ("import os\n"
               "\n"
               "DATA_ROOT = os.environ.get('X_1107')\n"
               "\n"
               "\n"
               "def verb(ctx):\n"
               "    return ctx.env.get('X_1107'), os.getenv('X_1107')\n")
    in_tree = "defender/scripts/adapters/pass_1107.py"
    out_of_tree = ["defender/runtime/elsewhere_1107.py", "defender/learning/branch/cli_1107.py",
                   "defender/run_1107.py"]
    S.plant_module(tmp_path, in_tree, inside)
    for rel in out_of_tree:
        S.plant_module(tmp_path, rel, outside)

    rc, out = S.run_env_lint(tmp_path)

    assert rc == 0, f"the lint failed a tree holding only passthrough, main and out-of-tree reads:\n{out}"
    named = [rel for rel in [in_tree, *out_of_tree] if _names(out, rel)]
    assert named == [], f"the lint reported allowed shapes in {named}:\n{out}"

    # Positive control: the same tree with one flagged lookup added IS reported.
    flagged = "def verb(ctx):\n    return ctx.env.get('X_1107')  # @flagged\n"
    S.plant_module(tmp_path, "defender/scripts/adapters/flagged_1107.py", flagged)
    rc2, out2 = S.run_env_lint(tmp_path)
    assert rc2 != 0, f"the control lookup was not reported, so the clean result above proves nothing:\n{out2}"
    assert (_reported(out2, "defender/scripts/adapters/flagged_1107.py",
                                  _lines(flagged)["flagged"])), f"the control lookup was not reported, so the clean result above proves nothing:\n{out2}"


@pytest.mark.gate
def test_o7_lint_clean_empty_allowlist(tmp_path):
    """The lint, run over the repository's four trees with an empty allow-list (no baseline and no
    suppression), exits 0."""
    rc, out = S.run_env_lint()
    assert rc == 0, f"{LINT_REL} over the repository's four trees:\n{out}"

    # The allow-list is empty: no baseline entry, no suppression marker in a swept file.
    if BASELINE.exists():
        entries = json.loads(BASELINE.read_text(encoding="utf-8")).get("entries", {})
        assert not entries, f"{BASELINE.name} carries an allow-list: {sorted(entries)}"
    swept = C.swept_py(REPO)
    assert swept, "no module found in the four swept trees"
    suppressed = [f"{p.relative_to(REPO)}:{n}" for p in swept
                  for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), start=1)
                  if S.ENV_LINT_SUPPRESSION.search(line)]
    assert suppressed == [], f"swept files suppress the lint: {suppressed}"

    # Positive control: the same lint fails a tree with one violation in it.
    _skeleton(tmp_path)
    S.plant_module(tmp_path, "defender/scripts/adapters/flagged_1107.py",
                   "import os\n\n\ndef verb(ctx):\n    return os.environ['X_1107']\n")
    rc2, out2 = S.run_env_lint(tmp_path)
    assert rc2 != 0, f"the lint passed a planted os.environ read, so exit 0 above proves nothing:\n{out2}"


def test_o7_lint_refuses_a_swept_entry_missing_from_this_repo(tmp_path):
    """Over this repo, a swept entry that no longer exists is a blind scan (exit 2), not a clean
    one: a move that takes swept code elsewhere without carrying its entry along would otherwise
    drop that code from the sweep while the lint keeps passing. Under `--root` the same missing
    entry is still just not scanned, so a planted partial tree is checked as before.

    Driven on a fresh copy of the lint with one non-existent entry added to its swept list.
    Positive control: the unmodified copy scans this repo cleanly."""
    clean = S.env_lint()
    assert clean.main([]) == 0, "control: the lint does not pass this repo as it is"

    lint = S.env_lint()
    gone = "defender/runtime/moved_away_1190.py"
    lint.SWEPT = (*lint.SWEPT, gone)
    with pytest.raises(lint.ScanBlind, match=re.escape(gone)):
        lint.scan(REPO)
    assert lint.main([]) == 2, "a missing swept entry over this repo did not fail the lint"

    _skeleton(tmp_path)
    assert lint.main(["--root", str(tmp_path)]) == 0, (
        "a planted tree without the extra entry is refused: --root must still allow partial trees")


def test_o7_lint_in_ci():
    """.github/workflows/ci.yml runs scripts/lint/lint_tenant_env_reads.py as a step beside the other
    custom lints (CX20)."""
    ci = yaml.safe_load((REPO / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
    jobs = ci.get("jobs") or {}
    assert jobs, "ci.yml has no jobs"

    def runs(job: dict) -> list[str]:
        return [str(step.get("run", "")) for step in job.get("steps") or []]

    lint_jobs = [name for name, job in jobs.items() if any(LINT_REL in r for r in runs(job))]
    peer_jobs = [name for name, job in jobs.items()
                 if any("scripts/lint/lint_monkeypatch.py" in r for r in runs(job))]
    assert peer_jobs, "ci.yml no longer runs lint_monkeypatch.py — the custom-lint job moved"
    assert lint_jobs, f"no ci.yml step runs {LINT_REL}"
    assert set(lint_jobs) & set(peer_jobs), (
        f"{LINT_REL} runs in {lint_jobs}, not beside the other custom lints in {peer_jobs}")


_NF7 = """\
import os
from os import environ as e  # @environ-alias-import

MODULE_SCOPE = os.environ.get("X_1107")  # @module-scope


def verb(ctx, deps):
    v1 = e["X_1107"]  # @environ-alias-use
    env = ctx.env
    v2 = env.get("X_1107")  # @bound-name-get
    v3 = env["X_1107"]  # @bound-name-subscript
    v4 = dict(ctx.env)["X_1107"]  # @dict-copy-subscript
    v5 = {**ctx.env}.get("X_1107")  # @splat-copy-get
    v6 = "X_1107" in ctx.env  # @in-test
    v7 = [k for k in ctx.env]  # @comprehension-iteration
    for k in ctx.env:  # @for-iteration
        v7.append(k)
    v8 = deps.ctx.env.get("X_1107")  # @dotted-env-get
    return v1, v2, v3, v4, v5, v6, v7, v8


def outer():
    def main():
        return os.environ.get("X_1107")  # @nested-main
    return main


class Tool:
    def main(self):
        return os.environ.get("X_1107")  # @method-main
"""


def test_s7_nf7_lint_flags_indirect_and_module_scope_reads(tmp_path):
    """In the four trees, with an empty allow-list, the lint also flags: environ imported under any
    name (from os import environ as e); .get(...), subscripts, in-tests and iteration on any
    expression ending in .env or on a name bound from one (env = ctx.env; env.get(k)), including
    dict(ctx.env)["X"] and {**ctx.env}.get("X"); and reads at module scope. Only a module-level def
    main is exempt: a nested or method main is flagged."""
    # rejected: dynamic getattr(os, "environ"), /proc/self/environ and lookups inside shared helpers outside the trees (D6: direct lookups only)
    # rejected: flagging a child fork with no env= argument (#18: not a lookup; the four existing forks pass env=dict(ctx.env), G28)
    _skeleton(tmp_path)
    rel = "defender/learning/branch/estate/nf7_1107.py"
    S.plant_module(tmp_path, rel, _NF7)
    at = _lines(_NF7)

    rc, out = S.run_env_lint(tmp_path)

    assert rc != 0, f"the lint exited 0 over the planted indirect reads:\n{out}"
    # The aliased import is one finding: at the import or at its use.
    assert _reported(out, rel, at["environ-alias-import"]) or _reported(
        out, rel, at["environ-alias-use"]), f"`from os import environ as e` not reported:\n{out}"
    must = [label for label in at if not label.startswith("environ-alias")]
    missed = [f"{label} (line {at[label]})" for label in must if not _reported(out, rel, at[label])]
    assert missed == [], "the lint did not report:\n" + "\n".join(missed) + f"\n--- output:\n{out}"


def test_whole_run_env_handed_to_an_in_tree_helper_that_looks_keys_up(tmp_path, monkeypatch):
    """The lint does not flag handing the whole ctx.env to an in-tree helper (dict(ctx.env) and
    env=ctx.env are the allowed shapes) and does not follow the mapping into the helper. With a
    config-key variable exported, the run's call still uses the tenant file's value: O1's run tests
    are the net the lint is not."""
    lint_tree = _skeleton(tmp_path / "lint-tree")
    adapter = ("from defender.scripts.adapters import helper_1107\n"
               "\n"
               "\n"
               "def verb(ctx):\n"
               "    base = helper_1107.url_base(dict(ctx.env))\n"
               "    other = helper_1107.url_base_kw(env=ctx.env)\n"
               "    return base, other\n")
    helper = ("def url_base(mapping):\n"
              "    return mapping.get('CMDB_URL_BASE')\n"
              "\n"
              "\n"
              "def url_base_kw(*, env):\n"
              "    return url_base(env)\n")
    adapter_rel = "defender/scripts/adapters/hands_env_1107.py"
    helper_rel = "defender/scripts/adapters/helper_1107.py"
    S.plant_module(lint_tree, adapter_rel, adapter)
    S.plant_module(lint_tree, helper_rel, helper)

    rc, out = S.run_env_lint(lint_tree)

    assert rc == 0, f"the lint flagged the whole env handed to an in-tree helper:\n{out}"
    assert not _names(out, adapter_rel), out
    assert not _names(out, helper_rel), out
    flagged = "def verb(ctx):\n    return ctx.env.get('CMDB_URL_BASE')  # @flagged\n"
    S.plant_module(lint_tree, "defender/scripts/adapters/flagged_1107.py", flagged)
    rc2, out2 = S.run_env_lint(lint_tree)
    assert rc2 != 0, f"the control lookup was not reported, so the clean result above proves nothing:\n{out2}"
    assert (_reported(out2, "defender/scripts/adapters/flagged_1107.py",
                                  _lines(flagged)["flagged"])), f"the control lookup was not reported, so the clean result above proves nothing:\n{out2}"

    # The net the lint is not: the run's cmdb call with CMDB_URL_BASE exported.
    marker = "s017"
    exported = "http://exported-s017:9"
    S.plant(tmp_path / "tenants", marker=marker)
    record = S.resolve(tmp_path / "tenants")
    # CX8: the shim on the verb env's PATH receives the argv the transport forks.
    shim = S.DockerShim(tmp_path / "shim", [S.answer('{"host": "web-1"}', "200")])
    monkeypatch.setenv("CMDB_URL_BASE", exported)
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    ctx = S.verb_context(record, run_dir, shim.env(CMDB_URL_BASE=exported))

    cmdb_adapter.get_host(ctx, host="web-1")

    calls = shim.calls()
    assert calls, "the cmdb verb never reached the docker shim — nothing was observed"
    url = S.curl_url(calls[-1]["argv"])
    assert url is not None, f"the cmdb call did not use the tenant file's CMDB_URL_BASE: {url!r}"
    assert url.startswith(f"http://cmdb-{marker}:8080/"), f"the cmdb call did not use the tenant file's CMDB_URL_BASE: {url!r}"
    assert exported not in " ".join(calls[-1]["argv"]), (
        f"the exported CMDB_URL_BASE reached the call's argv: {calls[-1]['argv']}")


# ======================================================================================
# MF-14 — the model-facing docs.
# ======================================================================================

#: G34's homonyms of "override": (file, a phrase on the listed line). They stay.
HOMONYMS: tuple[tuple[str, str], ...] = (
    ("defender/skills/identity/SKILL.md", 'via: "override"'),
    ("defender/skills/cmdb/SKILL.md", "per-host override"),
    ("defender/skills/elastic/execution.md", "verb overrides the"),
    ("defender/skills/gather/queries/identity/user-authorization.md", "per-host override"),
    ("defender/skills/connect/SKILL.md", "overrideable with cause"),
    ("defender/skills/tacit-knowledge/execution.md", "no environment variable to resolve"),
)


def test_s7_mf14_docs_teach_no_env_override():
    """No line of G34's eight model-facing files (cmdb/execution.md, identity/execution.md,
    host-state/execution.md, scripts/adapters/README.md, connect/SKILL.md, connect decisions.md,
    connect checklist.md, connect adapter.md) says a config key can be overridden by an environment
    variable, names a SOC_PLAYGROUND_* variable as a setting, teaches environment-variable secrets or
    the _ENV suffix, or says host-state's context is hard-coded; host-state/execution.md names its
    config.env lines. The domain homonyms of "override" G34 lists (identity/SKILL.md:59-61,
    cmdb/SKILL.md:50,91, elastic/execution.md:112, user-authorization.md:17, connect/SKILL.md:296,
    tacit-knowledge/execution.md:39) stay."""
    read, found = C.doc_env_teaching(REPO)
    assert read == len(C.MODEL_DOCS), f"the doc census read {read} of G34's {len(C.MODEL_DOCS)} files"
    assert found == [], "model-facing docs still teach the environment:\n" + "\n".join(found)

    host_state = (REPO / "defender/skills/host-state/execution.md").read_text(encoding="utf-8")
    prefix = S.PREFIX["host-state"]
    missing = [k for k in (f"{prefix}_TRANSPORT", f"{prefix}_DOCKER_CONTEXT") if k not in host_state]
    assert missing == [], f"host-state/execution.md does not name its config.env lines {missing}"

    _, homonym_findings = C.doc_env_teaching(REPO, [rel for rel, _ in HOMONYMS])
    for rel, phrase in HOMONYMS:
        lines = (REPO / rel).read_text(encoding="utf-8").splitlines()
        at = [n for n, line in enumerate(lines, start=1) if phrase in line]
        assert at, f"G34's homonym {phrase!r} is gone from {rel}"
        flagged = [n for n in at if _has(homonym_findings, rel, n)]
        assert flagged == [], f"the census flags G34's homonym {phrase!r} at {rel}:{flagged}"


def test_s7_mf14_doc_census_detects_planted(tmp_path):
    """The same doc census, run over a planted doc line saying CMDB_URL_BASE can be overridden by
    exporting it, reports that file and line."""
    doc = ("# CMDB — execution\n"
           "\n"
           "CMDB_URL_BASE can be overridden by exporting it.  # @planted\n"
           "\n"
           "Per-host `users:` overrides in `hosts/inventory.yaml` are signal-bearing.\n"
           "An exported variable no longer overrides a `config.env` key.\n")
    rel = "defender/skills/cmdb/execution.md"
    S.plant_module(tmp_path, rel, doc)

    read, found = C.doc_env_teaching(tmp_path)

    assert read == 1, f"the doc census did not read the planted doc: {read}"
    line = _lines(doc)["planted"]
    assert _has(found, rel, line), f"the doc census missed {rel}:{line}: {found}"
    assert [f for f in found if not f.startswith(f"{rel}:{line}:")] == [], (
        f"the census flagged a homonym or a negation beside the planted line: {found}")

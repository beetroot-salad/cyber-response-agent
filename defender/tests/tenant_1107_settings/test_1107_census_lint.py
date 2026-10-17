"""lint_tenant_env_reads: flags env reads in the swept trees, allows whole-env passthrough."""
from __future__ import annotations

import re
from pathlib import Path


from defender.scripts.adapters import cmdb_adapter
from defender.tests.tenant_1107_settings import _census_1107 as C
from defender.tests.tenant_1107_settings import _spec1107 as S


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




# ======================================================================================
# D4 — the Elastic keys are interpreted in one place.
# ======================================================================================





# ======================================================================================
# S3 — nothing copies settings/ into a run or an episode.
# ======================================================================================





# ======================================================================================
# F7 — settings_dir survives only on the resolver side.
# ======================================================================================





# ======================================================================================
# N3 — the swept trees take their location and env from the caller.
# ======================================================================================





# ======================================================================================
# D2 — no SOC_PLAYGROUND_* setting is read from an environment.
# ======================================================================================



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





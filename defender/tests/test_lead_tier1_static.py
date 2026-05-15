"""Tier 1 static checks — per-rule good / bad path."""
from __future__ import annotations

from pathlib import Path

import pytest

from defender.learning.lead_tier1 import (
    PLUMBING_PARAMS,
    static_checks,
)


# Mirrors the on-disk template shape closely enough that the
# prose-scanning rule has realistic input. Placeholders are
# ``__STEM__`` / ``__GOAL__`` (replaced by ``_render``) — using
# ``str.format`` would clash with the ``${...}`` query-parameter
# syntax inside the body.
_GOOD_TEMPLATE = """---
id: wazuh.__STEM__
---

## Goal

Retrieve __GOAL__ from the wazuh alerts index.

## What to characterize

- something
- and another

## Query

```bash
python3 defender/scripts/tools/wazuh_cli.py query \\
  --query 'rule.groups:syscheck${host_clause}' \\
  --window ${window} \\
  --run-dir ${run_dir}
```

`${host_clause}` is `" AND agent.name:<host>"` when filtering by host,
empty otherwise.

## Filter binding

- `host` → `agent.name:<hostname>`.

## Common pitfalls

- nothing yet
"""


def _render(stem: str, goal: str = "x") -> str:
    return _GOOD_TEMPLATE.replace("__STEM__", stem).replace("__GOAL__", goal)


def _write(qdir: Path, name: str, body: str) -> Path:
    path = qdir / f"{name}.md"
    path.write_text(body)
    return path


def _good(qdir: Path, name: str = "alpha") -> Path:
    return _write(qdir, name, _render(name, "auth events"))


def test_good_template_passes(queries_dir: Path) -> None:
    result = static_checks(_good(queries_dir, "fresh-template"))
    assert result["passed"], result["errors"]
    assert result["errors"] == []


def test_missing_frontmatter_fails(queries_dir: Path) -> None:
    p = _write(queries_dir, "noproc", "## Goal\n\nbody\n")
    result = static_checks(p)
    assert not result["passed"]
    assert any("frontmatter" in e for e in result["errors"])


def test_id_mismatch_fails(queries_dir: Path) -> None:
    # File is `mismatch.md` but frontmatter id is wazuh.something-else.
    p = _write(
        queries_dir,
        "mismatch",
        _render("mismatch").replace("wazuh.mismatch", "wazuh.something-else"),
    )
    result = static_checks(p)
    assert not result["passed"]
    assert any("does not match path" in e for e in result["errors"])


def test_missing_goal_section_fails(queries_dir: Path) -> None:
    good = _render("noGoal")
    # Strip the Goal section but keep its frontmatter + other sections.
    body = good.replace(
        "## Goal\n\nRetrieve x from the wazuh alerts index.\n\n", ""
    )
    p = _write(queries_dir, "noGoal", body)
    result = static_checks(p)
    assert not result["passed"]
    assert any("## Goal" in e for e in result["errors"])


def test_empty_what_to_characterize_fails(queries_dir: Path) -> None:
    good = _render("emptywtc")
    body = good.replace("- something\n- and another\n", "\n")
    p = _write(queries_dir, "emptywtc", body)
    result = static_checks(p)
    assert not result["passed"]
    assert any("≥1 bullet" in e for e in result["errors"])


def test_filter_binding_is_optional(queries_dir: Path) -> None:
    good = _render("nofilter")
    body = good.replace(
        "## Filter binding\n\n- `host` → `agent.name:<hostname>`.\n\n", ""
    )
    p = _write(queries_dir, "nofilter", body)
    result = static_checks(p)
    # No filter section present but params are still documented in the
    # prose immediately after the ## Query fence (the `${host_clause}` is...`
    # line), so the static check must pass.
    assert result["passed"], result["errors"]


def test_undocumented_content_param_fails(queries_dir: Path) -> None:
    """A `${param}` only appearing inside the fenced block is undocumented."""
    body = """---
id: wazuh.undoc
---

## Goal

g

## What to characterize

- x

## Query

```bash
python3 defender/scripts/tools/wazuh_cli.py query --query 'rule.id:${rule_id}'
```

## Common pitfalls

- nothing
"""
    p = _write(queries_dir, "undoc", body)
    result = static_checks(p)
    assert not result["passed"]
    assert any("rule_id" in e for e in result["errors"])


def test_dotted_form_satisfies_documentation(queries_dir: Path) -> None:
    """Documenting `rule.id` in prose satisfies the `${rule_id}` discipline.

    Regression for the underscore↔dot equivalence the rule explicitly
    accepts: many params name a dotted field (rule.id, data.srcip) but
    must be referenced in the query template as underscored
    identifiers (rule_id, data_srcip aren't legit shell identifiers
    with dots).
    """
    body = """---
id: wazuh.dotted
---

## Goal

g

## What to characterize

- x

## Query

```bash
python3 defender/scripts/tools/wazuh_cli.py query --query 'rule.id:${rule_id}'
```

The query filters by `rule.id` — pass the numeric id as a string.

## Common pitfalls

- nothing
"""
    p = _write(queries_dir, "dotted", body)
    result = static_checks(p)
    assert result["passed"], result["errors"]


def test_plumbing_params_allowlisted(queries_dir: Path) -> None:
    """`${run_dir}`, `${window}`, etc. need no prose mention."""
    body = """---
id: wazuh.plumbingonly
---

## Goal

g

## What to characterize

- x

## Query

```bash
python3 defender/scripts/tools/wazuh_cli.py query \\
  --query 'rule.id:5710' \\
  --window ${window} \\
  --start ${start} \\
  --end ${end} \\
  --limit ${limit} \\
  --run-dir ${run_dir} \\
  --position ${position}
```

## Common pitfalls

- nothing
"""
    p = _write(queries_dir, "plumbingonly", body)
    result = static_checks(p)
    assert result["passed"], result["errors"]
    # Sanity: all params resolved are plumbing.
    assert set(result["params_in_query"]) <= PLUMBING_PARAMS


def test_documented_in_prose_after_fence_passes(queries_dir: Path) -> None:
    """auth-events-style: param documented immediately after `## Query`'s fence.

    Regression for the prose-scan calibration call-out — the prose must
    be detected anywhere outside fenced blocks, including the same
    section as the fence that introduces the param.
    """
    body = """---
id: wazuh.afterfence
---

## Goal

g

## What to characterize

- x

## Query

```bash
python3 defender/scripts/tools/wazuh_cli.py query \\
  --query 'rule.groups:auth${host_clause}'
```

`${host_clause}` is `" AND agent.name:<host>"` when filtering by host,
empty otherwise.

## Common pitfalls

- nothing
"""
    p = _write(queries_dir, "afterfence", body)
    result = static_checks(p)
    assert result["passed"], result["errors"]


def test_agent_name_must_be_documented(queries_dir: Path) -> None:
    """`agent_name` is content (host identity), not plumbing.

    Regression-guard: ``agent_name`` must NOT be in PLUMBING_PARAMS;
    if it is, this test silently passes when prose documentation is
    absent (because the static rule treats agent_name as plumbing) —
    which would let `${agent_name}` slip into the catalog without any
    description.
    """
    assert "agent_name" not in PLUMBING_PARAMS, (
        "agent_name is content (a host identifier), not plumbing — "
        "moving it to PLUMBING_PARAMS removes the documentation gate"
    )
    body = """---
id: wazuh.bareagent
---

## Goal

g

## What to characterize

- x

## Query

```bash
python3 defender/scripts/tools/wazuh_cli.py query --query 'agent.name:${agent_name}'
```

## Common pitfalls

- nothing
"""
    p = _write(queries_dir, "bareagent", body)
    result = static_checks(p)
    assert not result["passed"]
    assert any("agent_name" in e for e in result["errors"])


@pytest.mark.parametrize(
    "template_path",
    sorted(
        (
            Path(__file__).resolve().parents[1]
            / "skills"
            / "gather"
            / "queries"
            / "wazuh"
        ).glob("*.md")
    ),
)
def test_real_catalog_passes(template_path: Path) -> None:
    """Every tracked Wazuh template must satisfy the static rule.

    Calibration gate — if this fails, either the catalog drifted or
    the static rule got too strict. Both deserve attention.
    """
    result = static_checks(template_path)
    assert result["passed"], (template_path.name, result["errors"])

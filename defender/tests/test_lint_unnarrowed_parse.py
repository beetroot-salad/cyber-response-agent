"""The lint gate for the un-narrowed parse seam: lint_unnarrowed_parse (#878).

Same shape as test_lint_unsafe_jsonl_io.py / test_lint_hand_rolled_frontmatter.py — the gate
is a standalone program under repo-root ``scripts/lint/``, so it is reached by path (never by
import) and driven through its testability seam:

  - ``main(argv, *, scope=..., baseline_path=...) -> int``
  - ``_scan(scope) -> list[Finding]``

What is pinned here is the CONSTRUCTION BOUNDARY, not a list of spellings: the same violation
written through an alias, a from-import or the repo's own ``_yaml`` wrapper is one case, and
the near-miss that hands the parse straight to a validator is the cure the gate must leave
alone. The two motivating shapes of #878 — ``read_json_locked``'s ``-> dict`` over
``json.loads``, and a bare ``datetime.fromisoformat`` — each get a test that fires, and each
gets a paired control that does not.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from defender.tests._by_path import import_lint_lib, load_lint_gate

_ASTLIB = import_lint_lib("_astlib")
_GATE = load_lint_gate("lint_unnarrowed_parse")


# The motivating seam, verbatim in shape: a `-> dict` claim over raw `json.loads` output.
_SEAM = (
    "import json\n"
    "from pathlib import Path\n"
    "\n"
    "def read_json_locked(path: Path) -> dict:\n"
    "    raw = path.read_text(encoding='utf-8')\n"
    "    return json.loads(raw) if raw else {}\n"
)

# The cure: the parse and the shape check are ONE construction.
_NARROWED_BY_VALIDATOR = (
    "import json\n"
    "from pathlib import Path\n"
    "\n"
    "def read_json_locked(path: Path, validate) -> dict:\n"
    "    doc = validate(json.loads(path.read_text(encoding='utf-8')))\n"
    "    return doc\n"
)

_NARROWED_BY_ISINSTANCE = (
    "import json\n"
    "from pathlib import Path\n"
    "\n"
    "def read_json_locked(path: Path) -> dict:\n"
    "    state = json.loads(path.read_text(encoding='utf-8'))\n"
    "    if not isinstance(state, dict):\n"
    "        return {}\n"
    "    return state\n"
)

_ISO = (
    "from datetime import datetime\n"
    "\n"
    "def _wall_origin(raw):\n"
    "    return datetime.fromisoformat(raw)\n"
)


def _pyfile(tree: Path, rel: str, src: str) -> Path:
    p = tree / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(src, encoding="utf-8")
    return p


def _write_baseline(path: Path, fingerprints: list[str]) -> None:
    path.write_text(
        json.dumps(
            {"//": "test", "entries": {fp: "test fixture reason" for fp in fingerprints}}
        )
        + "\n",
        encoding="utf-8",
    )


def _scan_src(tmp_path: Path, src: str, *, rel: str = "prod.py"):
    tree = tmp_path / "scope"
    _pyfile(tree, rel, src)
    return _GATE._scan(tree)


def _checks(findings) -> set[str]:
    return {f.fingerprint.rsplit(":", 1)[-1] for f in findings}


# (a) it fires


def test_the_seam_is_flagged(tmp_path):
    findings = _scan_src(tmp_path, _SEAM)
    assert _checks(findings) == {"unnarrowed-parse"}
    assert findings[0].fingerprint == "prod.py:read_json_locked:unnarrowed-parse"
    assert "prod.py:6:" in findings[0].display, findings[0].display


def test_bare_fromisoformat_is_flagged(tmp_path):
    findings = _scan_src(tmp_path, _ISO)
    assert _checks(findings) == {"unowned-iso-parse"}
    assert "parse_iso_utc" in findings[0].display


@pytest.mark.parametrize(
    "src",
    [
        # An alias and a from-import are the SAME case as the dotted spelling — the whole
        # reason the gates resolve the callee instead of reading how it was written (#602).
        "import json as j\ndef f(t) -> dict:\n    return j.loads(t)\n",
        "from json import loads\ndef f(t) -> dict:\n    return loads(t)\n",
        "import yaml\ndef f(t) -> dict:\n    return yaml.safe_load(t)\n",
        "import tomllib\ndef f(t) -> dict:\n    return tomllib.loads(t)\n",
        # This repo's hardened YAML front door bounds recursion; it does NOT establish a shape.
        "from defender._yaml import safe_load\ndef f(t) -> dict:\n    return safe_load(t)\n",
        # A claim behind a container, a forward-ref, and a union all still claim a shape.
        "import json\ndef f(t) -> list[dict]:\n    return json.loads(t)\n",
        "import json\ndef f(t) -> 'CaseRecord':\n    return json.loads(t)\n",
        "import json\ndef f(t) -> dict | None:\n    return json.loads(t)\n",
    ],
)
def test_every_spelling_of_the_construction_is_one_case(tmp_path, src):
    assert _checks(_scan_src(tmp_path, src)) == {"unnarrowed-parse"}


def test_taint_survives_a_deref_chain(tmp_path):
    """`.get()` off raw output is still raw: the receiver is `Any`, so the result is. A gate
    that treated the dot as a boundary would let one deref launder the whole chain."""
    assert _checks(_scan_src(tmp_path, (
        "import yaml\n"
        "def scenario_entry(t) -> dict:\n"
        "    catalog = yaml.safe_load(t) or {}\n"
        "    entries = catalog.get('scenarios') or []\n"
        "    for entry in entries:\n"
        "        if entry.get('id') == 'x':\n"
        "            return entry\n"
        "    raise KeyError('x')\n"
    ))) == {"unnarrowed-parse"}


def test_an_async_seam_is_flagged(tmp_path):
    assert _checks(_scan_src(tmp_path, (
        "import json\n"
        "async def f(t) -> dict:\n"
        "    return json.loads(t)\n"
    ))) == {"unnarrowed-parse"}


def test_two_same_named_siblings_get_distinct_fingerprints(tmp_path):
    findings = _scan_src(tmp_path, (
        "import json\n"
        "class A:\n"
        "    def breaker(self, t) -> dict:\n"
        "        return json.loads(t)\n"
        "class B:\n"
        "    def breaker(self, t) -> dict:\n"
        "        return json.loads(t)\n"
    ))
    assert {f.fingerprint for f in findings} == {
        "prod.py:A.breaker:unnarrowed-parse",
        "prod.py:B.breaker:unnarrowed-parse",
    }


# (b) the legitimate near-misses


def test_the_validator_construction_is_not_flagged(tmp_path):
    """The cure, not the disease: the parse is consumed by the check in ONE expression, so the
    raw value is never bound, never deref'd, never returned. This is the shape
    `learning/core/run_cycle._validate_judge_yaml` uses with an injected `Callable`."""
    assert _scan_src(tmp_path, _NARROWED_BY_VALIDATOR) == []


def test_an_isinstance_guard_is_not_flagged(tmp_path):
    assert _scan_src(tmp_path, _NARROWED_BY_ISINSTANCE) == []


def test_a_first_party_validator_call_is_not_flagged(tmp_path):
    """`learning/core/validate.parse_judge_verdict`'s shape: the raw doc is bound, but what
    reaches `return` is the first-party validator's result, not the raw doc."""
    assert _scan_src(tmp_path, (
        "from defender._yaml import safe_load\n"
        "from defender.learning.core.validate import validate_judge_doc\n"
        "\n"
        "def parse_verdict(text) -> dict:\n"
        "    doc = safe_load(text)\n"
        "    validated = validate_judge_doc(doc)\n"
        "    return validated\n"
    )) == []


def test_a_pydantic_validator_is_not_flagged(tmp_path):
    assert _scan_src(tmp_path, (
        "import json\n"
        "def f(t, Model) -> dict:\n"
        "    raw = json.loads(t)\n"
        "    return Model.model_validate(raw)\n"
    )) == []


def test_a_function_claiming_no_shape_is_not_flagged(tmp_path):
    """`-> Any` / a scalar / an un-annotated def claim nothing a parse could violate. This is
    the skip that keeps the gate a claim-checker rather than a json.loads census."""
    for index, src in enumerate((
        "import json\nfrom typing import Any\ndef f(t) -> Any:\n    return json.loads(t)\n",
        "import json\ndef f(t) -> str:\n    return json.loads(t)\n",
        "import json\ndef f(t) -> bool | None:\n    return json.loads(t)\n",
        "import json\ndef f(t):\n    return json.loads(t)\n",
    )):
        assert _scan_src(tmp_path / f"claim{index}", src) == [], src


def test_a_nested_def_is_visited_on_its_own_claim(tmp_path):
    """The outer function neither parses nor returns raw output; the inner one does both. The
    body walk stops at nested scopes precisely so the claim charged is the inner def's."""
    findings = _scan_src(tmp_path, (
        "import json\n"
        "def outer(t) -> str:\n"
        "    def inner(x) -> dict:\n"
        "        return json.loads(x)\n"
        "    return str(inner(t))\n"
    ))
    assert {f.fingerprint for f in findings} == {"prod.py:outer.inner:unnarrowed-parse"}


def test_the_clock_owner_may_call_fromisoformat(tmp_path):
    """The exemption follows the OWNER's definition, not a hardcoded path: the module that
    defines `parse_iso_utc` is the one place the raw constructor belongs."""
    owner = (
        "import datetime as _dt\n"
        "\n"
        "def parse_iso_utc(raw):\n"
        "    return _dt.datetime.fromisoformat(raw.replace('Z', '+00:00'))\n"
    )
    assert _scan_src(tmp_path / "owner", owner, rel="_clock.py") == []
    # Control: the identical call in a module that does NOT own the vocabulary fires.
    assert _checks(_scan_src(tmp_path / "other", _ISO)) == {"unowned-iso-parse"}


def test_tests_are_out_of_scope(tmp_path):
    tree = tmp_path / "scope"
    _pyfile(tree, "tests/test_thing.py", _SEAM)
    assert _GATE._scan(tree) == []
    _pyfile(tree, "prod.py", _SEAM)
    assert all("prod.py" in f.fingerprint for f in _GATE._scan(tree))


# (c) suppression


def test_suppression_on_the_signature(tmp_path):
    assert _scan_src(tmp_path, (
        "import json\n"
        "from pathlib import Path\n"
        "\n"
        "def read_json_locked(path: Path) -> dict:  # lint-parse: ok — checked one frame out\n"
        "    return json.loads(path.read_text(encoding='utf-8'))\n"
    )) == []


def test_suppression_in_the_comment_block_above(tmp_path):
    assert _scan_src(tmp_path, (
        "import json\n"
        "\n"
        "# lint-parse: ok — the caller owns the shape and this seam is its private helper,\n"
        "# so narrowing here would be the second copy of that check.\n"
        "def f(t) -> dict:\n"
        "    return json.loads(t)\n"
    )) == []


def test_suppression_on_the_return_and_on_the_iso_call(tmp_path):
    assert _scan_src(tmp_path, (
        "import json\n"
        "def f(t) -> dict:\n"
        "    return json.loads(t)  # lint-parse: ok — deliberate\n"
    )) == []
    assert _scan_src(tmp_path / "iso", (
        "from datetime import datetime\n"
        "def g(raw):\n"
        "    return datetime.fromisoformat(raw)  # lint-parse: ok — offsets are guaranteed\n"
    )) == []


def test_a_marker_buried_in_the_body_does_not_suppress(tmp_path):
    """The signature span, not the whole function: a marker deep inside a long body would
    exempt a seam nobody reading the `def` line can see."""
    assert _scan_src(tmp_path, (
        "import json\n"
        "def f(t) -> dict:\n"
        "    x = 1  # lint-parse: ok — far from the seam\n"
        "    y = 2\n"
        "    return json.loads(t)\n"
    ))


# (d) ScanBlind, and the ratchet


def test_unparseable_file_in_scope_is_not_silently_clean(tmp_path):
    """A file the gate could not parse never entered the corpus, so a seam could sit in it
    while the gate printed 0 findings. It raises instead (#618/#621/#652)."""
    tree = tmp_path / "scope"
    _pyfile(tree, "broken.py", "def f(:\n    this is not python\n")
    _pyfile(tree, "prod.py", _SEAM)
    with pytest.raises(_ASTLIB.ScanBlind) as exc:
        _GATE._scan(tree)
    assert "broken.py" in str(exc.value)
    assert _GATE.main([], scope=tree, baseline_path=tmp_path / "bp.json") == 2


def test_clean_tree_still_scans(tmp_path):
    """The control: without the unparseable file the same tree scans and finds the seam, so
    the raises-test above cannot pass against a gate that raises unconditionally."""
    tree = tmp_path / "scope"
    _pyfile(tree, "prod.py", _SEAM)
    assert any("prod.py" in f.fingerprint for f in _GATE._scan(tree))


def test_ratchet_contract(tmp_path):
    tree = tmp_path / "scope"
    _pyfile(tree, "prod.py", _SEAM)
    findings = _GATE._scan(tree)
    assert findings

    assert _GATE.main([], scope=tree, baseline_path=tmp_path / "missing.json") == 1
    bp = tmp_path / "bp.json"
    _write_baseline(bp, [f.fingerprint for f in findings])
    assert _GATE.main([], scope=tree, baseline_path=bp) == 0
    assert _GATE.main([], scope=tmp_path / "does-not-exist") == 2


def test_an_unreasoned_baseline_entry_fails(tmp_path):
    """`require_reasons=True`: burying a finding costs a sentence saying why. Without it the
    ratchet's own escape hatch is `--update-baseline` plus silence."""
    tree = tmp_path / "scope"
    _pyfile(tree, "prod.py", _SEAM)
    bp = tmp_path / "bp.json"
    assert _GATE.main(["--update-baseline"], scope=tree, baseline_path=bp) == 0
    data = json.loads(bp.read_text(encoding="utf-8"))
    assert set(data["entries"].values()) == {""}
    assert _GATE.main([], scope=tree, baseline_path=bp) == 1
    data["entries"] = {k: "deliberate: reason" for k in data["entries"]}
    bp.write_text(json.dumps(data) + "\n", encoding="utf-8")
    assert _GATE.main([], scope=tree, baseline_path=bp) == 0


def test_the_shipped_baseline_carries_a_reason_for_every_entry():
    entries = json.loads(
        (Path(_GATE.__file__).with_name("lint_unnarrowed_parse_baseline.json")).read_text(
            encoding="utf-8"
        )
    )["entries"]
    assert entries, "the shipped baseline is not empty today"
    unreasoned = sorted(fp for fp, why in entries.items() if not why.strip())
    assert not unreasoned, unreasoned


def test_the_motivating_findings_are_in_the_shipped_baseline():
    """A gate that does not fire on the defect it exists for is not landed. One of #878's four
    motivating sites is still open and still reported — the positive control that this gate
    fires on REAL code and not only on the synthetic seams above.

    THE OTHER THREE ARE FIXED, and are asserted GONE rather than deleted from this test (#878).
    They were the whole reason the gate was landed, so "the gate no longer reports them" is the
    statement worth keeping: `read_json_locked` and `update_json_locked` now narrow their parse
    to a dict at the seam, and `_wall_origin` now goes through `_clock.parse_iso_utc`. Each is
    also out of the shipped baseline, so a re-widening comes back as a NEW finding and fails the
    ratchet — which is the regression this direction of the assertion protects.

    `_l0_items._correlation_contract` stays open deliberately: it is the same hand-rolled half
    of `parse_iso_utc`, but it PARSES ONLY TO VALIDATE and discards the value, so no naive-vs-
    aware comparison is reachable from it. It is a debt this gate names, not one of #878's five
    reachable faults, and #878 did not widen its scope to collect it."""
    fingerprints = {f.fingerprint for f in _GATE._scan(_GATE.DEFENDER)}
    assert "defender/runtime/_l0_items.py:_correlation_contract:unowned-iso-parse" in fingerprints

    for fixed in (
        "defender/hooks/_run_dir.py:read_json_locked:unnarrowed-parse",
        "defender/hooks/_run_dir.py:update_json_locked:unnarrowed-parse",
        "defender/hooks/budget_enforcer.py:_wall_origin:unowned-iso-parse",
    ):
        assert fixed not in fingerprints, f"{fixed} was re-widened after #878 narrowed it"


def test_the_readers_of_a_laundered_value_are_not_reported():
    """The deliberate half-coverage, pinned so a later widening is a decision rather than a
    drift. The gate fires at the SEAM; the readers that subscript `_run_dir`'s laundered dict
    — `circuit_breaker._record`'s `state["systems"]`, `budget_enforcer`'s `state.get(...)` —
    are NOT reported, because narrowing the seam fixes them and every future reader.

    A clean run of this gate therefore says nothing about those derefs. That is what the
    module docstring's "what is NOT mechanized" paragraph exists to keep a reader from
    forgetting."""
    reported = {
        f.fingerprint.split(":", 1)[0]
        for f in _GATE._scan(_GATE.DEFENDER)
        if f.fingerprint.endswith(":unnarrowed-parse")
    }
    for reader in ("defender/runtime/circuit_breaker.py", "defender/hooks/budget_enforcer.py"):
        assert reader not in reported


@pytest.mark.gate  # covered by code-smells' "Un-narrowed-parse gate"
def test_real_tree_clean():
    """`gate`-marked: the code-smells step runs this same `main([])` over this same tree and
    blocks on it, so the `test` job's copy would be duplicate cost on CI's critical path."""
    assert _GATE.main([]) == 0

"""The lint gate for the un-narrowed parse seam: lint_unnarrowed_parse (#878)."""
from __future__ import annotations

from pathlib import Path

import pytest

from defender.tests._by_path import load_lint_gate

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
        "def catalog_entry(t) -> dict:\n"
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
    raw value is never bound, never deref'd, never returned. This is the shape the retired
    run cycle's judge-YAML check used with an injected `Callable`."""
    assert _scan_src(tmp_path, _NARROWED_BY_VALIDATOR) == []


def test_an_isinstance_guard_is_not_flagged(tmp_path):
    assert _scan_src(tmp_path, _NARROWED_BY_ISINSTANCE) == []


def test_a_first_party_validator_call_is_not_flagged(tmp_path):
    """The retired judge-verdict parser's shape: the raw doc is bound, but what reaches
    `return` is the first-party validator's result, not the raw doc."""
    assert _scan_src(tmp_path, (
        "from defender._yaml import safe_load\n"
        "from defender.learning.core.validate import validate_doc\n"
        "\n"
        "def parse_verdict(text) -> dict:\n"
        "    doc = safe_load(text)\n"
        "    validated = validate_doc(doc)\n"
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



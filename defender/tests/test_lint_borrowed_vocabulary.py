"""The gate that keeps #785's fold from silently regrowing.

#785 was six consumers borrowing one vocabulary and each re-deriving what a value in it means.
Nothing about any single site looked wrong — the divergence existed only BETWEEN them, and five
of the six had quietly lost the #722 zero-width strip along the way. A census found it; review
had not. This gate is the census, run every build.

The property worth testing is the ARMING rule, because it is what keeps the gate honest as the
tree changes: a vocabulary becomes watched exactly when its owner starts answering for it. Get
that wrong in the permissive direction and the gate never fires; wrong in the strict direction
and it flags every closed set in the repo and gets baselined into silence.

The gate is driven through its `scope=` seam over throwaway trees, as the other tested gates
are — arming is a whole-corpus property, so it cannot be shown on the real tree alone.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

LINT_DIR = Path(__file__).resolve().parents[2] / "scripts" / "lint"
LINT_PATH = LINT_DIR / "lint_borrowed_vocabulary.py"

# A vocabulary owner: defines the set AND answers for it.
_OWNER_ARMED = (
    "COLOURS = {'red', 'green'}\n"
    "\n"
    "def normalized(v):\n"
    "    return v if v in COLOURS else None\n"
)
# The same vocabulary with no answer beside it — nothing for a consumer to call.
_OWNER_BARE = "COLOURS = {'red', 'green'}\n"

_BORROWER = (
    "from owner import COLOURS\n"
    "\n"
    "def check(v):\n"
    "    return v in COLOURS\n"
)


@pytest.fixture
def gate():
    if str(LINT_DIR) not in sys.path:
        sys.path.insert(0, str(LINT_DIR))
    spec = importlib.util.spec_from_file_location("lint_borrowed_vocabulary", LINT_PATH)
    assert spec is not None
    assert spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _tree(tmp_path: Path, files: dict[str, str]) -> Path:
    root = tmp_path / "defender"
    for rel, src in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(src, encoding="utf-8")
    return root


def _names(findings) -> list[str]:
    return [f.fingerprint for f in findings]


# ═══════════════════════════════════════════════════════════════════════════
# the arming rule
# ═══════════════════════════════════════════════════════════════════════════

def test_a_borrowed_vocabulary_with_an_owners_answer_is_flagged(gate, tmp_path):
    root = _tree(tmp_path, {"owner.py": _OWNER_ARMED, "borrower.py": _BORROWER})
    assert _names(gate._scan(root)) == ["defender/borrower.py:check:COLOURS"]


def test_a_vocabulary_with_no_owners_answer_is_not_watched(gate, tmp_path):
    """The permissive half of the rule, and the reason the gate does not need a large baseline:
    until someone writes the normalizer there is nothing for a consumer to call, so a plain
    membership test is the only thing it COULD do."""
    root = _tree(tmp_path, {"owner.py": _OWNER_BARE, "borrower.py": _BORROWER})
    assert gate._scan(root) == []


def test_writing_the_normalizer_arms_the_vocabulary(gate, tmp_path):
    """Self-arming, stated as a transition: the same borrower goes from clean to flagged with no
    edit to the gate. This is what makes it a rule about the tree rather than a list of names —
    the next fold protects its own vocabulary the moment it lands."""
    bare = _tree(tmp_path / "before", {"owner.py": _OWNER_BARE, "borrower.py": _BORROWER})
    armed = _tree(tmp_path / "after", {"owner.py": _OWNER_ARMED, "borrower.py": _BORROWER})
    assert gate._scan(bare) == []
    assert len(gate._scan(armed)) == 1


def test_the_owner_testing_its_own_vocabulary_is_the_answer_not_the_smell(gate, tmp_path):
    """Most membership tests in the tree are this shape and must stay silent, or the gate is
    noise."""
    assert gate._scan(_tree(tmp_path, {"owner.py": _OWNER_ARMED})) == []


# ═══════════════════════════════════════════════════════════════════════════
# what must not slip past, and what must not be caught
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize(
    ("spelling", "borrower"),
    [
        ("import-alias",
         "from owner import COLOURS as PALETTE\n\ndef check(v):\n    return v in PALETTE\n"),
        ("module-attribute",
         "import owner\n\ndef check(v):\n    return v in owner.COLOURS\n"),
        ("module-attribute-from-package",
         "from pkg import owner\n\ndef check(v):\n    return v in owner.COLOURS\n"),
        ("module-level-rebind",
         "from owner import COLOURS\nLOCAL = COLOURS\n\ndef check(v):\n    return v in LOCAL\n"),
        ("module-level-rebind-of-attribute",
         "import owner\nLOCAL = owner.COLOURS\n\ndef check(v):\n    return v in LOCAL\n"),
    ],
)
def test_no_spelling_of_the_borrow_hides_it(gate, tmp_path, spelling, borrower):
    """How the borrow is SPELLED must not decide whether the gate sees it — the #602 rule the
    other AST gates already follow. The rebinding pair matters most: a module-level
    `LOCAL = COLOURS` is the ordinary way to shorten a long import, and a gate that reads it as
    "this module owns COLOURS" is disarmed by the cheapest possible refactor rather than
    evaded by a deliberate one."""
    root = _tree(tmp_path / spelling, {"owner.py": _OWNER_ARMED, "borrower.py": borrower})
    assert _names(gate._scan(root)) == ["defender/borrower.py:check:COLOURS"]


def test_an_attribute_off_a_local_object_is_not_a_vocabulary(gate, tmp_path):
    """The control for the attribute form: `v in obj.LONGFIELD` reads a field off a value, not
    a constant off a module, and a same-named field must not fabricate a finding."""
    local = (
        "class C:\n"
        "    COLOURS = ()\n"
        "\n"
        "def check(v, obj):\n"
        "    return v in obj.COLOURS\n"
    )
    root = _tree(tmp_path, {"owner.py": _OWNER_ARMED, "borrower.py": local})
    assert gate._scan(root) == []


def test_negated_membership_is_the_same_smell(gate, tmp_path):
    negated = (
        "from owner import COLOURS\n"
        "\n"
        "def check(v):\n"
        "    if v not in COLOURS:\n"
        "        raise ValueError(v)\n"
    )
    root = _tree(tmp_path, {"owner.py": _OWNER_ARMED, "borrower.py": negated})
    assert len(gate._scan(root)) == 1


def test_passing_the_vocabulary_to_a_shared_checker_is_the_cure(gate, tmp_path):
    """Delegation is what the gate pushes toward — flagging it would push callers back to
    re-deriving the test, which is the smell itself."""
    delegating = (
        "from owner import COLOURS\n"
        "\n"
        "def check(v):\n"
        "    return _check_vocab(v, COLOURS, 'bad colour')\n"
    )
    root = _tree(tmp_path, {"owner.py": _OWNER_ARMED, "borrower.py": delegating})
    assert gate._scan(root) == []


def test_a_suppression_needs_its_reason_above_or_beside_the_site(gate, tmp_path):
    """A deliberate exemption exists — a write gate is exact where readers normalize — and the
    marker is how that reason gets written down at the site."""
    beside = (
        "from owner import COLOURS\n"
        "\n"
        "def check(v):\n"
        "    return v in COLOURS  # lint-vocabulary: ok — write gate, exact on purpose\n"
    )
    above = (
        "from owner import COLOURS\n"
        "\n"
        "def check(v):\n"
        "    # lint-vocabulary: ok — write gate: an exact test denies with retry text\n"
        "    # the author can act on, where normalizing would silently accept.\n"
        "    return v in COLOURS\n"
    )
    for src in (beside, above):
        root = _tree(tmp_path / str(len(src)), {"owner.py": _OWNER_ARMED, "borrower.py": src})
        assert gate._scan(root) == []


def test_tests_are_out_of_scope(gate, tmp_path):
    """A test parametrizing over a vocabulary is asserting on it, not interpreting it."""
    root = _tree(
        tmp_path, {"owner.py": _OWNER_ARMED, "tests/test_colours.py": _BORROWER}
    )
    assert gate._scan(root) == []


# ═══════════════════════════════════════════════════════════════════════════
# the gate cannot report clean on source it never read
# ═══════════════════════════════════════════════════════════════════════════

def test_an_unparseable_file_fails_the_gate_rather_than_passing_it(gate, tmp_path):
    """#618/#621/#652's rule, and sharper here than for a single-pass lint: an unreadable OWNER
    disarms its vocabulary for the entire corpus, so "0 findings" over a partial corpus would be
    actively misleading. Exit 2 — the gate could not run, which is not clean.

    Paired with a control over the same tree minus the broken file, so this cannot pass by the
    gate simply being broken."""
    files = {"owner.py": _OWNER_ARMED, "borrower.py": _BORROWER}
    clean_root = _tree(tmp_path / "clean", files)
    assert gate.main([], scope=clean_root, baseline_path=tmp_path / "none.json") == 1

    broken_root = _tree(tmp_path / "broken", {**files, "broken.py": "def (\n"})
    assert gate.main([], scope=broken_root, baseline_path=tmp_path / "none.json") == 2


def test_the_real_tree_passes_the_ratchet(gate):
    """The gate is green on the tree it ships with, through its own baseline."""
    assert gate.main([]) == 0


def test_no_disposition_site_is_baselined(gate):
    """#785's own claim, stated as the property rather than as "the baseline is empty": every
    borrow of the run vocabulary is folded, and the one deliberate exemption — the write gate,
    exact where every reader normalizes — states its reason at the site instead of being
    baselined into silence. The two entries the baseline does carry are older debt in other
    vocabularies, so asserting an EMPTY baseline would conflate the two claims."""
    assert [f for f in gate._scan() if "DISPOSITION" in f.fingerprint] == []

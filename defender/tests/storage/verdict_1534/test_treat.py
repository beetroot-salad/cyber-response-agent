"""#1534 V-TEXT: `closing.treat(text, bound)`, the one treatment of model text (design "Model text").

The literal cases are the design's own examples and rules. The properties draw seeded random inputs, built from
known pieces where the expected output is known by construction, so no test re-implements the treatment."""
from __future__ import annotations

import json
import os
import random
import re
import subprocess
import sys
import unicodedata

import pytest

#: The whitespace-like Cc characters step 1 turns into spaces (design "Precision for implementers").
SPACE_LIKE = (0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x85, 0x1C, 0x1D, 0x1E, 0x1F)

#: `(input, expected)`, unbounded: each is a rule of the design, with a positive control beside the negatives.
LITERALS = [
    pytest.param("see https://evil.example/x", "see hxxps://evil[.]example/x", id="scenario-https-url"),
    pytest.param("http://a.example.org/p", "hxxp://a[.]example[.]org/p", id="http-url"),
    pytest.param("ftp://files.example.net/f", "fxp://files[.]example[.]net/f", id="ftp-url"),
    pytest.param("Visit www.google.com now", "Visit www[.]google[.]com now", id="www-host"),
    pytest.param("google.com", "google[.]com", id="bare-host"),
    pytest.param("mail bob@mail.example.com ok", "mail bob@mail[.]example[.]com ok", id="email-host"),
    pytest.param("from 10.0.0.5 to 192.168.1.20", "from 10[.]0[.]0[.]5 to 192[.]168[.]1[.]20", id="ipv4"),
    pytest.param("my-site.example-host.com", "my-site[.]example-host[.]com", id="hyphen-labels"),
    pytest.param("evil。example", "evil[.]example", id="dot-U+3002"),
    pytest.param("evil．example", "evil[.]example", id="dot-U+FF0E"),
    pytest.param("evil｡example", "evil[.]example", id="dot-U+FF61"),
    pytest.param("пример.рф", "пример[.]рф",
                 id="non-ascii-labels"),
    pytest.param("bücher.example", "bücher[.]example", id="non-ascii-label-before-ascii"),
    # Owner decision (c): a label may carry marks (Mn/Mc/Me); a host's last label is 2+ letters-or-marks or `xn--…`.
    pytest.param("evil.xn--p1ai", "evil[.]xn--p1ai", id="punycode-tld-p1ai"),
    pytest.param("evil.xn--j1amh", "evil[.]xn--j1amh", id="punycode-tld-j1amh"),
    pytest.param("example.भारत", "example[.]भारत", id="mark-tld-devanagari"),
    pytest.param("example.বাংলা", "example[.]বাংলা", id="mark-tld-bengali"),
    pytest.param("example.இந்தியா", "example[.]இந்தியா", id="mark-tld-tamil"),
    pytest.param("example.ไทย", "example[.]ไทย", id="thai-tld"),
    pytest.param("नमस्ते.भारत", "नमस्ते[.]भारत", id="mark-labels-both-sides"),
    pytest.param("evil.xn-p1ai", "evil.xn-p1ai", id="control-single-hyphen-is-not-punycode"),
    pytest.param("https://example.com/a.b.cd", "hxxps://example[.]com/a[.]b[.]cd", id="host-rule-runs-over-url-paths"),
    pytest.param("http://example.com/file.txt", "hxxp://example[.]com/file[.]txt", id="url-path-file-name"),
    # Positive controls: dotted text the rule does not call host-shaped keeps every dot.
    pytest.param("version 1.2 done", "version 1.2 done", id="control-number-pair"),
    pytest.param("release 1.2.3 and cost 3.50", "release 1.2.3 and cost 3.50", id="control-numbers"),
    pytest.param("a.b and v2.1", "a.b and v2.1", id="control-last-label-not-two-letters"),
    pytest.param("plain text with no link", "plain text with no link", id="control-plain"),
    pytest.param("a\tb\nc\rd", "a b c d", id="step1-tab-lf-cr"),
    pytest.param("a\x0bb\x0cc\x85d\x1ce\x1df\x1eg\x1fh", "a b c d e f g h", id="step1-vt-ff-nel-fs-gs-rs-us"),
    pytest.param("a   b \n\n c", "a b c", id="step3-collapse"),
    pytest.param("evil​.example", "evil[.]example", id="zero-width-removed-before-defang"),
    pytest.param("ht​tp://x.example", "hxxp://x[.]example", id="zero-width-inside-scheme"),
]


@pytest.mark.parametrize(("text", "expected"), LITERALS)
def test_v_text_the_design_rules_on_literal_inputs(text, expected):
    """Each rule of the treatment on its own input, and the dotted text it must leave alone. (V-TEXT)"""
    from defender.records import closing as C

    assert C.treat(text, None) == expected


@pytest.mark.parametrize(("text", "defanged"), [
    ("HTTP://Evil.Example/x", "hxxp://evil[.]example/x"),
    ("HtTpS://a.example", "hxxps://a[.]example"),
    ("FTP://f.example", "fxp://f[.]example"),
])
def test_v_text_a_scheme_is_matched_case_insensitively(text, defanged):
    """`HTTP`, `HtTpS` and `FTP` are schemes too; the replacement's own case is not pinned. (V-TEXT)"""
    from defender.records import closing as C

    assert C.treat(text, None).lower() == defanged


@pytest.mark.parametrize("text", [expected for _text, expected in (p.values for p in LITERALS)])
def test_v_text_the_treated_output_treats_to_itself(text):
    """`treat` of a treated literal is itself, `[.]` and `hxxp` included (a second pass does not defang again). (V-TEXT)"""
    from defender.records import closing as C

    assert C.treat(text, None) == text
    assert C.treat(text, 40) == C.treat(C.treat(text, 40), 40)


def _removed_or_spaced(cp: int) -> tuple[bool, bool]:
    """(category C, whitespace-like Cc) of a code point, read from `unicodedata` and the design's list."""
    return unicodedata.category(chr(cp)).startswith("C"), cp in SPACE_LIKE


#: Code points swept: the Basic Multilingual Plane's start, the surrogate and private-use blocks, the planes' ends.
SWEPT = (*range(0, 0x3000), *range(0xD800, 0xE100), *range(0xFFF0, 0x10000), *range(0xE0000, 0xE0100),
         *range(0xF0000, 0xF0010), *range(0x10FFF0, 0x110000))


def test_v_text_category_c_is_removed_and_only_the_whitespace_like_controls_become_spaces():
    """Every swept Cc/Cf/Cs/Co/Cn code point leaves no trace; the listed whitespace-like ones leave one space. (V-TEXT)"""
    from defender.records import closing as C

    wrong: list[str] = []
    swept_c = 0
    for cp in SWEPT:
        is_c, spaced = _removed_or_spaced(cp)
        out = C.treat(f"a{chr(cp)}b", None)
        if is_c:
            swept_c += 1
            want = "a b" if spaced else "ab"
            if out != want:
                wrong.append(f"U+{cp:04X} {unicodedata.category(chr(cp))}: {out!r} != {want!r}")
        elif not chr(cp).isspace() and chr(cp) not in ".。．｡" and chr(cp) not in out:
            wrong.append(f"U+{cp:04X} (not category C) was removed: {out!r}")
    assert wrong == []
    assert swept_c > 2000, "the sweep reached too few category C code points to say anything"


@pytest.mark.parametrize("char", ["​", "‍", "⁠", "﻿", "‮", "⁦", "\x00", "\x7f", "", "\ud800",
                                  "͸", "￿"], ids=lambda c: f"U+{ord(c):04X}")
def test_v_text_named_invisible_characters_are_removed(char):
    """Zero-width, bidi, NUL, DEL, private-use, a lone surrogate, an unassigned point and a non-character vanish. (V-TEXT)"""
    from defender.records import closing as C

    assert C.treat(f"a{char}b", None) == "ab"


# --- the bound ------------------------------------------------------------------------------------------------------

def test_v_text_the_ellipsis_is_one_character():
    """`ELLIPSIS` is the single U+2026 the bound counts inside itself. (V-TEXT)"""
    from defender.records import closing as C

    assert C.ELLIPSIS == "…"


def test_v_text_a_cut_is_at_the_last_space_before_the_bound_with_the_ellipsis_inside_it():
    """`alpha beta gamma delta` at 14 cuts after `beta`; at its own length it is not cut. (V-TEXT)"""
    from defender.records import closing as C

    assert C.treat("alpha beta gamma delta", 14) == "alpha beta…"
    assert C.treat("alpha beta gamma delta", len("alpha beta gamma delta")) == "alpha beta gamma delta"
    assert C.treat("alpha beta gamma delta", None) == "alpha beta gamma delta"


@pytest.mark.parametrize("length", [10, 25, 80])
def test_v_text_text_one_over_the_bound_is_cut_and_text_at_the_bound_is_not(length):
    """A text of exactly `length` characters passes; one more is cut to at most `length`, ending in the ellipsis. (V-TEXT)"""
    from defender.records import closing as C

    fits, over = "x" * length, "x" * (length + 1)
    assert C.treat(fits, length) == fits
    cut = C.treat(over, length)
    assert len(cut) <= length
    assert cut.endswith(C.ELLIPSIS)
    assert over.startswith(cut[:-1])


def test_v_text_the_cut_falls_before_a_host_that_would_straddle_it():
    """A host after the last space that fits is dropped whole, not left half-defanged. (V-TEXT)"""
    from defender.records import closing as C

    assert C.treat("see alpha.bravo.charlie.delta", 12) == "see…"


@pytest.mark.parametrize(("text", "bound", "expected"), [
    ("abcdefghijklmnop", 8, "abcdefg…"),
    ("(foo.example1zzz", 9, "(…"),
    ("(alpha.bravo.charlie.delta", 12, "(alpha[.]br…"),
    ("(10.20.30.40", 8, "(10[.]2…"),
], ids=["control-no-dot-keeps-bound-minus-one", "raw-run-backs-off-to-its-start", "defanged-host-keeps-text",
        "defanged-ipv4-keeps-text"])
def test_v_text_a_hard_cut_keeps_text_and_backs_off_only_over_a_dotted_run(text, bound, expected):
    """With no space before the bound: `bound - 1` characters and the ellipsis, backing off only over a raw dotted run. (V-TEXT)"""
    from defender.records import closing as C

    assert C.treat(text, bound) == expected


#: G4: a space-free run this long, treated whole and at two bounds, inside a budget a linear treatment never nears
#: (each 64k input takes well under a second) and a treatment quadratic in the run's length always overruns.
LONG_RUN = 1 << 16
TIME_BUDGET_S = 60.0
_LONG_RUN_CHILD = """
import json, sys
from defender.records.closing import treat
n = int(sys.argv[1])
texts = {
    "label": "a" * n,
    "dotted": ("ab." * n)[:n - 1] + "b",
    "dotted-every-dot-form": ("a.b。c．d｡" * n)[:n - 1] + "e",
    "digits-dotted": ("10.0.0." * n)[:n - 1] + "1",
    "label-then-host": "a" * (n - 4) + ".com",
    "marked-label": ("\u0915\u094d" * n)[:n],
    "scheme-then-label": "http://" + "a" * (n - 7),
}
facts = {}
for name, text in texts.items():
    whole = treat(text, None)
    cuts = [treat(text, b) for b in (400, len(whole) - 1)]
    facts[name] = [len(whole), whole.count("[.]"), *(len(c) for c in cuts), *(c.endswith("\u2026") for c in cuts)]
print(json.dumps(facts))
"""


def test_v_text_a_64k_space_free_run_treats_within_a_generous_time_budget():
    """Long space-free labels and dotted runs treat, whole and cut, in a child killed at the budget. (V-TEXT, G4)"""
    env = {**os.environ, "PYTHONPATH": os.pathsep.join(p for p in sys.path if p)}
    try:
        done = subprocess.run([sys.executable, "-c", _LONG_RUN_CHILD, str(LONG_RUN)], env=env, capture_output=True,
                              text=True, timeout=TIME_BUDGET_S, check=False)
    except subprocess.TimeoutExpired:
        pytest.fail(f"treating 64k-character space-free runs took over {TIME_BUDGET_S}s (the child was killed)")
    assert done.returncode == 0, done.stderr[-2000:]
    facts = json.loads(done.stdout)
    n = LONG_RUN
    assert facts["label"] == [n, 0, 400, n - 1, True, True]
    assert facts["dotted"][1] == n // 3, "every dot of a host-shaped run is defanged"
    assert facts["label-then-host"][:2] == [n + 2, 1]
    assert facts["marked-label"][:2] == [n, 0]
    for name, (whole, _dots, small, large, small_cut, large_cut) in facts.items():
        assert (small <= 400, large <= whole - 1, small_cut, large_cut) == (True,) * 4, (name, facts[name])


DOTS = ".。．｡"
#: Readings recorded in design r3.2 "Precision for implementers": a host-shaped token is any whole-label sub-run of a
#: dotted run ending in a host label (`_HOST`), and the scheme rule applies wherever `scheme://` appears, whatever
#: follows, a bare `ftp://` included (`_SCHEME`). Owner decision (c): a label is letters, digits, `-` and Unicode marks
#: (category M); a host label is two or more letters-or-marks, or an `xn--` label.
#: A scheme preceded by a non-letter or the start (the defang rule's own word boundary), an IPv4 address, and a
#: host-shaped token: labels joined by raw dot-set characters ending in a host label.


def _class_of(category: str) -> str:
    """A regex class body for every code point whose Unicode category starts with `category`, as ranges."""
    points = [cp for cp in range(0x110000) if unicodedata.category(chr(cp)).startswith(category)]
    ranges: list[tuple[int, int]] = []
    for cp in points:
        if ranges and ranges[-1][1] == cp - 1:
            ranges[-1] = (ranges[-1][0], cp)
        else:
            ranges.append((cp, cp))
    return "".join(re.escape(chr(a)) if a == b else f"{re.escape(chr(a))}-{re.escape(chr(b))}" for a, b in ranges)


_MARKS = _class_of("M")
_LABEL_CHAR = rf"(?:[^\W_]|[-{_MARKS}])"
_HOST_LABEL = rf"(?:(?:[^\W\d_]|[{_MARKS}]){{2,}}|xn--{_LABEL_CHAR}+)"
_SCHEME = re.compile(r"(?<![^\W\d_])(?:https?|ftp)://", re.IGNORECASE)
_IPV4 = re.compile(r"(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?![\w])")
_HOST = re.compile(rf"(?<![-\w{_MARKS}])(?:{_LABEL_CHAR}+[.。．｡])+{_HOST_LABEL}(?![-\w{_MARKS}])")


def _cut_inputs() -> list[str]:
    """Seeded strings of every shape the cut meets, plus runs shaped like `foo.example1zzz…` and `10.0.0.255x…`."""
    rng = random.Random(15345)
    parts = ("foo", "example", "a1", "zzz", "10", "255", "x", "(", "-", "/", "http://", "HTTPS://", "ftp://", "www.", "[.]",
             ".", ".", ".", "。", "．", "｡", " ", "e", "1", "@", "xn--p1ai", "xn--", "भारत", "ि", "্", "বাংলা", "ไทย")
    texts = ["".join(rng.choice(parts) for _ in range(rng.randint(1, 30))) for _ in range(600)]
    for pad in range(0, 12):
        texts.append("foo.example1" + "z" * pad)
        texts.append("(foo.example1" + "z" * pad)
        texts.append("10.0.0.255x" + "y" * pad)
        texts.append("see 10.0.0.255x" + "y" * pad)
        texts.append("foo.example.com.example1" + "z" * pad)
        texts.append("foo.example.xn--p1a" + "i" * pad)
        texts.append("(foo.भारत" + "ि" * pad)
    return texts


def test_v_text_a_cut_text_is_a_fixed_point_with_no_partial_host_scheme_or_split_dot_at_every_bound():
    """Over arbitrary strings and every bound: idempotent, within the bound, no `[.]` split, nothing left undefanged. (V-TEXT)"""
    from defender.records import closing as C

    cut = 0
    for text in _cut_inputs():
        for bound in range(2, 48):
            out = C.treat(text, bound)
            assert C.treat(out, bound) == out, (text, bound, out)
            assert len(out) <= bound, (text, bound, out)
            assert out.count("[") == out.count("[.]") == out.count("]"), (text, bound, out)
            assert not _SCHEME.search(out), (text, bound, out)
            assert not _IPV4.search(out), (text, bound, out)
            assert not _HOST.search(out), (text, bound, out)
            cut += out.endswith(C.ELLIPSIS)
    assert cut > 5000, "the generated inputs cut too rarely to say anything"


def test_v_text_a_cut_with_no_space_and_no_dot_character_keeps_exactly_bound_minus_one_characters():
    """No space and no dot-set character before the bound: `bound - 1` characters of the text, then the ellipsis. (V-TEXT)"""
    from defender.records import closing as C

    rng = random.Random(15346)
    checked = 0
    for _ in range(400):
        text = "".join(rng.choice("abcXYZ019-/:(") for _ in range(rng.randint(1, 60)))
        for bound in range(2, 40):
            whole = C.treat(text, None)
            assert not any(d in whole for d in DOTS)
            if len(whole) > bound:
                assert C.treat(text, bound) == whole[: bound - 1] + C.ELLIPSIS, (text, bound)
                checked += 1
    assert checked > 5000


def test_v_text_no_bound_cuts_inside_a_defanged_dot():
    """Every `[` in a bounded result opens a whole `[.]`, at every bound across a text dense in dots. (V-TEXT)"""
    from defender.records import closing as C

    text = "a b.cc.dd e1 f.gg 10.0.0.5 h.ii.jj k"
    for bound in range(3, len(C.treat(text, None)) + 2):
        out = C.treat(text, bound)
        assert out.count("[") == out.count("[.]") == out.count("]"), (bound, out)
        assert len(out) <= bound, (bound, out)


# --- properties over seeded random inputs -------------------------------------------------------------------------------

#: Pieces with the output the design's rules give them by construction (one space between pieces, never at an end).
PIECES = {
    "alpha": "alpha", "plain-text": "plain-text", "a.b": "a.b", "v2.1": "v2.1", "1.2.3": "1.2.3",
    "10.0.0.5": "10[.]0[.]0[.]5", "192.168.1.20": "192[.]168[.]1[.]20", "evil.example.com": "evil[.]example[.]com",
    "www.site.org": "www[.]site[.]org", "user@mail.example.com": "user@mail[.]example[.]com",
    "http://x.example/p": "hxxp://x[.]example/p", "https://y.test/a.b.cd": "hxxps://y[.]test/a[.]b[.]cd",
    "ftp://f.example": "fxp://f[.]example",
    "evil.xn--p1ai": "evil[.]xn--p1ai", "example.भारत": "example[.]भारत", "site.বাংলা": "site[.]বাংলা",
}

#: Fragments for inputs with no expected output: controls, every dot form, schemes in any case, wide characters.
WILD = ("a", "bc", " ", "  ", "\t", "\n", "\r\n", "\x0b", "\x85", "\x1c", "​", "‮", "\x00", "\ud800", "",
        ".", "。", "．", "｡", "evil.example", "10.0.0.5", "HTTP://", "https://", "ftp://", "www.", "x@y.zz",
        "[.]", "hxxp://", "пр.рф", "bü.cher", "a.xn--p1ai", "x.भारत", "ि", "-", "/", ":", "1", "e.g.", "...")


def _pieces_text(rng: random.Random) -> tuple[str, str]:
    chosen = [rng.choice(list(PIECES)) for _ in range(rng.randint(1, 8))]
    return " ".join(chosen), " ".join(PIECES[p] for p in chosen)


def _wild_text(rng: random.Random) -> str:
    return "".join(rng.choice(WILD) for _ in range(rng.randint(0, 40)))


def test_v_text_a_text_of_known_pieces_is_defanged_exactly_where_the_rules_say():
    """Words, hosts, addresses and URLs joined by spaces come out as their known defanged forms, joined likewise. (V-TEXT)"""
    from defender.records import closing as C

    rng = random.Random(1534)
    for _ in range(300):
        text, expected = _pieces_text(rng)
        assert C.treat(text, None) == expected, text


def test_v_text_defanging_removes_no_character():
    """Turning each `[.]` back into a dot and each scheme word back into its scheme gives the input again. (V-TEXT)"""
    from defender.records import closing as C

    rng = random.Random(15341)
    for _ in range(300):
        text, _expected = _pieces_text(rng)
        out = C.treat(text, None)
        restored = out.replace("[.]", ".").replace("hxxps://", "https://").replace("hxxp://", "http://")
        restored = restored.replace("fxp://", "ftp://")
        assert restored == text, (text, out)


def test_v_text_the_treatment_is_idempotent_at_every_bound():
    """`treat(treat(x, b), b) == treat(x, b)` for random text full of controls, dot forms, schemes and hosts. (V-TEXT)"""
    from defender.records import closing as C

    rng = random.Random(15342)
    for _ in range(400):
        text = _wild_text(rng)
        for bound in (None, 8, 17, 40, 120):
            once = C.treat(text, bound)
            assert C.treat(once, bound) == once, (text, bound, once)


def test_v_text_every_result_fits_its_bound_and_has_no_control_or_doubled_space():
    """Length at most the bound with the ellipsis inside it; no category C; no tab, newline or run of spaces. (V-TEXT)"""
    from defender.records import closing as C

    rng = random.Random(15343)
    for _ in range(400):
        text = _wild_text(rng)
        for bound in (8, 17, 40, None):
            out = C.treat(text, bound)
            if bound is not None:
                assert len(out) <= bound, (text, bound, out)
            assert not any(unicodedata.category(ch).startswith("C") for ch in out), (text, bound, out)
            assert "  " not in out, (text, bound, out)


def test_v_text_a_text_that_fits_is_unchanged_by_its_bound_and_one_that_does_not_is_a_cut_of_it():
    """A bound at least the treated length changes nothing; a smaller one ends in the ellipsis and cuts a prefix. (V-TEXT)"""
    from defender.records import closing as C

    rng = random.Random(15344)
    cuts = 0
    for _ in range(300):
        text, _expected = _pieces_text(rng)
        whole = C.treat(text, None)
        assert C.treat(text, len(whole)) == whole, text
        if len(whole) > 12:
            cuts += 1
            out = C.treat(text, 12)
            assert out.endswith(C.ELLIPSIS), (text, out)
            assert whole.startswith(out[:-1].rstrip()), (text, out)
            assert out.count("[") == out.count("[.]"), (text, out)
    assert cuts > 50, "the sample cut too few texts to say anything"

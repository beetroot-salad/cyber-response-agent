"""#1534 V-TEXT: `closing.treat(text, bound)`, the one treatment of model text (design "Model text").

The literal cases are the design's own examples and rules. The properties draw seeded random inputs, built from
known pieces where the expected output is known by construction, so no test re-implements the treatment."""
from __future__ import annotations

import random
import re
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
    ("(alpha.bravo.charlie.delta", 12, "(…"),
    ("(10.20.30.40", 8, "(…"),
], ids=["control-no-dot-keeps-bound-minus-one", "host-backs-off-to-its-start", "ipv4-backs-off-to-its-start"])
def test_v_text_a_hard_cut_keeps_text_and_backs_off_only_over_a_dotted_run(text, bound, expected):
    """With no space before the bound: `bound - 1` characters and the ellipsis, backing off to the start of a dotted run. (V-TEXT)"""
    from defender.records import closing as C

    assert C.treat(text, bound) == expected


DOTS = ".。．｡"
#: A scheme preceded by a non-letter or the start (the defang rule's own word boundary), an IPv4 address, and a
#: host-shaped token: labels joined by raw dot-set characters ending in an alphabetic label of two or more letters.
_SCHEME = re.compile(r"(?<![^\W\d_])(?:https?|ftp)://", re.IGNORECASE)
_IPV4 = re.compile(r"(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?![\w])")
_HOST = re.compile(r"(?<![-\w])(?:[-\w]+[.。．｡])+[^\W\d_]{2,}(?![-\w])")


def _cut_inputs() -> list[str]:
    """Seeded strings of every shape the cut meets, plus runs shaped like `foo.example1zzz…` and `10.0.0.255x…`."""
    rng = random.Random(15345)
    parts = ("foo", "example", "a1", "zzz", "10", "255", "x", "(", "-", "/", "http://", "HTTPS://", "ftp://", "www.", "[.]",
             ".", ".", ".", "。", "．", "｡", " ", "e", "1", "@")
    texts = ["".join(rng.choice(parts) for _ in range(rng.randint(1, 30))) for _ in range(600)]
    for pad in range(0, 12):
        texts.append("foo.example1" + "z" * pad)
        texts.append("(foo.example1" + "z" * pad)
        texts.append("10.0.0.255x" + "y" * pad)
        texts.append("see 10.0.0.255x" + "y" * pad)
        texts.append("foo.example.com.example1" + "z" * pad)
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
}

#: Fragments for inputs with no expected output: controls, every dot form, schemes in any case, wide characters.
WILD = ("a", "bc", " ", "  ", "\t", "\n", "\r\n", "\x0b", "\x85", "\x1c", "​", "‮", "\x00", "\ud800", "",
        ".", "。", "．", "｡", "evil.example", "10.0.0.5", "HTTP://", "https://", "ftp://", "www.", "x@y.zz",
        "[.]", "hxxp://", "пр.рф", "bü.cher", "-", "/", ":", "1", "e.g.", "...")


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

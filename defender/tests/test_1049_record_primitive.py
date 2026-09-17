"""#1049 — the primitive: `_io.bind(root)` and the bound reader's `read` / `read_jsonl` / `under`.

The resolved shape (70-resolutions.md, 47-dispositions-v2.md): the root enters ONCE, at the
bind; a name is a sequence of plain components by construction; every component is opened
no-follow from the previous directory handle and the handle is `fstat`-classified; the answer
is a frozen `RecordRead` in exactly one of three states — present / absent / refused — and the
refusal is `f"{name}: {reason}"`, the whole relative name as given, said once. Nothing is
`lstat`ed ahead of an open; nothing is remembered between reads.

Every shape here is a real entry planted on the filesystem by `_record_1049.plant_shape` and
re-probed on every run; the only fake is `RecordingOs`, a pass-through recorder entering
through `bind`'s `os_=` seam. The permission arms are `@NOT_ROOT` (uid 0 ignores mode bits;
CI is non-root — g2/v2-1 executed them as uid 65534 via `setpriv`).

RED AGAINST BASE by construction: `_io.bind` does not exist, and every test imports it per
call through `R.io()` so the failure is the missing primitive, once per test.
"""
from __future__ import annotations

import dataclasses
import errno
import os
from pathlib import Path, PurePosixPath

import pytest

from defender.tests import _record_1049 as R

NOT_ROOT = R.NOT_ROOT


@pytest.fixture
def root(tmp_path: Path) -> Path:
    """A root whose spelling carries a marker no fixture content spells (`SECRET`), so the
    root-free assertions cannot pass on a short tmp path by accident."""
    r = tmp_path / R.SECRET / "episode"
    r.mkdir(parents=True)
    yield r
    R.restore_tree(r)


# ---------------------------------------------------------------------------------------
# d-00 — the bind contract
# ---------------------------------------------------------------------------------------


def test_1049_a_bound_reader_answers_exactly_one_of_present_absent_or_refused(root):
    """bind(root) is the only operation that takes a path; bound.read(name, errors='strict')
    answers a frozen RecordRead in exactly one state — present (text is a str, possibly empty:
    an empty file is text '', a read, not absent), absent (absent=True: ENOENT at any
    component), refused (refusal=f'{name}: {reason}', the whole relative name as given, once,
    no component attribution) — and bound.read_jsonl(name) answers (rows, malformed,
    RecordRead) with the same RecordRead it would answer for the text. A name is a str in
    POSIX spelling (or a PurePath rendered as_posix) split on '/' into plain components and
    echoed exactly as given (a constructible name is echoed exactly as given — './family.yaml'
    and 'worlds//w/report.md' are no longer expressible); two calls are two walks — nothing
    is remembered between them.
    """
    bound = R.bind(root)
    plain = R.plant_shape(root, "plain")
    empty = R.plant_shape(root, "empty_file")
    absent = R.plant_shape(root, "absent")
    link = R.plant_shape(root, "symlink")
    deep = R.plant_shape(root, "deep")

    present = bound.read(plain)
    assert R.state(present) == 'present'
    assert present.text == 'plain text\n'
    emptied = bound.read(empty)
    assert R.state(emptied) == 'present', 'an empty file is a read, not absent'
    assert emptied.text == '', 'an empty file is a read, not absent'
    assert R.state(bound.read(absent)) == "absent"
    refused = bound.read(link)
    assert R.refusal(refused, link) == R.ALIAS
    assert R.state(bound.read(deep)) == "present"

    # a PurePath in POSIX spelling constructs the same name as the str and answers identically
    assert bound.read(PurePosixPath(deep)) == bound.read(deep)
    assert bound.read(PurePosixPath(link)) == refused
    # the name is echoed exactly as given — a component with an inner '..' is one plain
    # component ('served/tok..jsonl' names nothing, so it reads absent, and says itself)
    odd = "served/tok..jsonl"
    assert R.state(bound.read(odd)) == "absent"
    R.plant_link(root / odd, root / "plain.md")
    assert R.refusal(bound.read(odd), odd) == R.ALIAS

    # the JSONL twin hands back the very RecordRead the text read would answer
    ledger = "served/tok.b.jsonl"
    R.write_bytes(root / ledger, '{"a": 1}\nnot json\n{"b": 2}\n')
    rows, malformed, rec = bound.read_jsonl(ledger)
    assert rows == [{'a': 1}, {'b': 2}]
    assert malformed == 1
    assert rec == bound.read(ledger, errors="replace")
    assert bound.read_jsonl(absent) == ([], 0, bound.read(absent))
    assert bound.read_jsonl(link) == ([], 0, refused)

    # frozen: the value cannot be edited into another state
    with pytest.raises(AttributeError):
        present.absent = True  # type: ignore[misc]
    assert dataclasses.is_dataclass(present)

    # two calls are two walks: the entry's shape at ITS moment, nothing cached
    later = "later.md"
    assert R.state(bound.read(later)) == "absent"
    R.write_bytes(root / later, "now here\n")
    assert bound.read(later).text == "now here\n"
    (root / later).unlink()
    assert R.state(bound.read(later)) == "absent"


# ---------------------------------------------------------------------------------------
# d-01 — absent is ENOENT, at whichever step
# ---------------------------------------------------------------------------------------


def test_1049_nothing_at_the_name_is_absent_and_nothing_else_is(root, tmp_path):
    """bound.read over a name with nothing at it answers absent=True with no refusal; the
    decision is ENOENT out of the walk's OWN open, at whichever step — nothing at the leaf,
    or a missing parent component (absent_parent) — and an absent ROOT makes every name
    absent (F-C: the fault is the bind's, the observable is per name). A dangling parent is
    NOT absent (RF-R3: it is refused at that component, d-02's row).
    """
    bound = R.bind(root)
    leaf_absent = R.plant_shape(root, "absent")
    parent_absent = R.plant_shape(root, "absent_parent")
    for name in (leaf_absent, parent_absent, "nowhere/deeper/still.md"):
        read = bound.read(name)
        assert R.state(read) == "absent", (name, read)
        assert read.absent is True
        assert read.refusal is None
        assert read.text is None

    gone = R.bind(tmp_path / "no-such-episode")
    for name in ("family.yaml", "worlds/b/report.md", "served/tok.b.jsonl"):
        assert R.state(gone.read(name)) == "absent", name
        assert gone.read_jsonl(name) == ([], 0, gone.read(name))

    dangling_parent = R.plant_shape(root, "dangling_parent")
    read = bound.read(dangling_parent)
    assert R.state(read) == "refused", "a dangling parent link is not 'nothing there'"
    assert read.absent is False


# ---------------------------------------------------------------------------------------
# d-02 — the shape table: present-but-not-the-record
# ---------------------------------------------------------------------------------------


def test_1049_every_present_but_not_the_record_shape_is_refused_with_the_relative_name(root, tmp_path):
    """A symlink, hard link, directory, fifo, dangling link, undecodable bytes, a file OR a
    fifo squatting a parent component, an over-long name, a SYMLINKED parent and a DANGLING
    parent each answer absent=False with refusal '<name>: <reason>' — the alias shapes with
    ALIAS_READ_REFUSAL (ELOOP; EMLINK for the hard link; the two parent aliases off the
    intermediate `O_PATH` handle's own S_ISLNK, v2-1), the parent-is-file with 'Not a directory', the
    over-long name with 'File name too long' (rg1), the undecodable with the codec's own
    message — the WHOLE relative name said once (RF-R6), and the reason is never 'None'
    (D-J6). A symlink whose target is itself unreadable is exactly one ELOOP refusal; a file
    at the ROOT makes every name '<name>: Not a directory'.
    """
    assert R.ALIAS == R.io().ALIAS_READ_REFUSAL, "the suite's alias sentence drifted from _io's"
    bound = R.bind(root)
    for shape, reason in R.REFUSED_SHAPES.items():
        name = R.plant_shape(root, shape)
        read = bound.read(name)
        assert R.refusal(read, name) == reason, (shape, read.refusal)
        assert read.refusal == f"{name}: {reason}", shape
    undecodable = R.plant_shape(root, "undecodable")
    reason = R.refusal(bound.read(undecodable), undecodable)
    assert 'codec' in reason, reason
    assert 'decode' in reason, reason
    assert "/" not in reason, reason
    # a symlink whose target is itself unreadable: refused by the open, the target unexamined
    unreadable_target = R.plant_shape(root, "symlink_to_unreadable")
    sentence = bound.read(unreadable_target).refusal
    assert sentence.count(R.ALIAS) == 1, sentence
    assert 'Permission denied' not in sentence, sentence

    afile = tmp_path / "a-file-not-an-episode"
    afile.write_text("not a directory\n", encoding="utf-8")
    file_root = R.bind(afile)
    for name in ("family.yaml", "worlds/b/report.md"):
        assert file_root.read(name).refusal == f"{name}: {R.strerror(errno.ENOTDIR)}"
    # positive control: a plain file under the same root is a read
    assert bound.read(R.plant_shape(root, "plain")).text == "plain text\n"


# ---------------------------------------------------------------------------------------
# d-03 — permission faults are refused, never absent (NOT_ROOT)
# ---------------------------------------------------------------------------------------


@NOT_ROOT
def test_1049_a_mode_000_file_or_parent_is_refused_never_absent(root, tmp_path):
    """A mode-000 file, a readable file AND an absent name under a mode-000 parent (never
    absent — v2-1: EACCES for both as uid 65534) answer refusal '<name>: Permission denied'
    with absent=False; a name under a search-only (0o111) parent READS — the intermediate
    step is an `O_PATH` handle, granted on search permission alone, as traversing the path
    by name always was (the row the portable O_RDONLY flag set refused; Linux-only by
    decision); a mode-000 ROOT answers the same per name, six independent
    '<name>: Permission denied' slots and no aggregate (F-C).
    """
    bound = R.bind(root)
    denied = R.strerror(errno.EACCES)
    for shape in R.PERMISSION_SHAPES:
        name = R.plant_shape(root, shape)
        read = bound.read(name)
        assert R.refusal(read, name) == denied, (shape, read.refusal)
        assert read.absent is False, shape
        assert bound.read_jsonl(name) == ([], 0, read), shape
    search_only = R.plant_shape(root, "search_only_parent")
    assert bound.read(search_only).text == "under a closed parent\n", "a search-only parent did not traverse"

    closed_root = tmp_path / "closed-episode"
    R.write_bytes(closed_root / "family.yaml", "worlds: []\n")
    closed_root.chmod(0)
    with R.restoring_modes(closed_root):
        sealed = R.bind(closed_root)
        names = ("family.yaml", "judge.yaml", "review.yaml", "samples.yaml", "staged.yaml",
                 "worlds/b/report.md")
        sentences = [sealed.read(n).refusal for n in names]
    assert sentences == [f"{n}: {denied}" for n in names], sentences


# ---------------------------------------------------------------------------------------
# d-04 — the open decides; nothing is asked of the name ahead of it
# ---------------------------------------------------------------------------------------


def test_1049_the_primitive_asks_nothing_of_the_name_ahead_of_the_open(root):
    """The bind, read and read_jsonl make no lstat, stat(, exists, is_symlink, entry_present,
    artifact_*, resolve or realpath call anywhere (an AST census over the three bodies and
    the bound reader's class names none of those); a recording os seam sees exactly one open
    per component and one fstat per opened handle — absent-vs-refused is the open's own
    answer, and an ENOENT, or a symlink, at a component stops the walk there with no further open.
    """
    rec = R.RecordingOs()
    bound = R.bind(root, os_=rec)
    deep = R.plant_shape(root, "deep")
    assert R.state(bound.read(deep)) == "present"
    opens = rec.component_opens
    assert len(opens) == 2, [(o[0], o[2]) for o in opens]
    component_fds = [o[3] for o in opens]
    assert sorted(rec.fstats) == sorted(component_fds), (rec.fstats, component_fds)
    assert not (set(rec.asked) & R.FORBIDDEN_OS_NAMES), rec.asked

    for shape, steps in (("absent", 1), ("absent_parent", 1), ("symlinked_parent", 1),
                         ("dangling_parent", 1), ("symlink", 1), ("parent_is_file", 1)):
        rec = R.RecordingOs()
        name = R.plant_shape(root, shape)
        R.bind(root, os_=rec).read(name)
        assert len(rec.component_opens) == steps, (shape, [(o[0], o[3]) for o in rec.component_opens])
        assert not (set(rec.asked) & R.FORBIDDEN_OS_NAMES), (shape, rec.asked)
        # the JSONL twin walks the same way
        rec2 = R.RecordingOs()
        R.bind(root, os_=rec2).read_jsonl(name)
        assert len(rec2.component_opens) == steps, shape

    forbidden = {"lstat", "stat", "exists", "is_symlink", "entry_present", "artifact_file",
                 "artifact_dir", "resolve", "realpath", "is_file", "is_dir", "readlink",
                 "read_plain", "read_guarded", "read_jsonl_rows_guarded"}
    for target in (R.io().bind, type(bound)):
        tree = R.parsed(target)
        assert not (R.called_names(tree) & forbidden), (target, R.called_names(tree) & forbidden)
        assert not (R.attribute_names(tree) & forbidden), (target, R.attribute_names(tree) & forbidden)


# ---------------------------------------------------------------------------------------
# d-05 — no refusal names the root
# ---------------------------------------------------------------------------------------


def test_1049_no_refusal_the_primitive_formats_contains_the_root(root, tmp_path):
    """Over every shape in d-02 and d-03 (the parent rows included), neither str(root) nor
    os.path.realpath(root) nor the root's parent is a substring of the refusal; only the
    name as given is — and a root reached through a symlinked spelling is not named in that
    spelling either. Positive control: every shape IS refused, each said.
    """
    link_spelling = tmp_path / "episode-by-link"
    link_spelling.symlink_to(root)
    spellings = {str(root), os.path.realpath(root), str(root.parent), str(link_spelling),
                 R.SECRET}
    said = []
    for spelled in (root, link_spelling):
        bound = R.bind(spelled)
        for shape in (*R.REFUSED_SHAPES, "undecodable", "symlink_to_unreadable"):
            name = R.plant_shape(root, shape)
            sentence = bound.read(name).refusal
            assert sentence is not None, (shape, "not refused")
            for spelling in spellings:
                assert spelling not in sentence, (shape, spelling, sentence)
            assert name in sentence, (shape, sentence)
            said.append(sentence)
        _rows, _bad, rec = bound.read_jsonl(R.plant_shape(root, "symlinked_parent"))
        assert rec.refusal, rec.refusal
        assert not any(s in rec.refusal for s in spellings), rec.refusal
    assert len(said) == 2 * (len(R.REFUSED_SHAPES) + 2)


# ---------------------------------------------------------------------------------------
# d-06 — errors=
# ---------------------------------------------------------------------------------------


def test_1049_strict_is_the_default_and_replace_is_the_only_admitted_alternative(root):
    """With the default errors='strict' an undecodable byte is a refusal; with
    errors='replace' the same bytes read as text with U+FFFD — the gather-summary read's
    policy; any other value ('ignore', 'surrogateescape', 'bogus') raises ValueError naming
    no path at the read call, before any open (a recording os seam sees none) — rg2's
    LookupError-at-the-first-bad-byte is unreachable.
    """
    rec = R.RecordingOs()
    bound = R.bind(root, os_=rec)
    bad = R.plant_shape(root, "undecodable")
    strict = bound.read(bad)
    assert R.state(strict) == 'refused'
    assert bound.read(bad, errors='strict') == strict
    replaced = bound.read(bad, errors="replace")
    assert R.state(replaced) == 'present', replaced
    assert '�' in replaced.text, replaced
    assert "not text" in replaced.text

    before = len(rec.opens)
    for handler in ("ignore", "surrogateescape", "bogus", ""):
        with pytest.raises(ValueError) as caught:  # noqa: PT011 - the message is asserted below: no path, no root
            bound.read(bad, errors=handler)
        message = str(caught.value)
        assert '/' not in message, message
        assert str(root) not in message, message
        assert not isinstance(caught.value, LookupError), "the codec's own LookupError leaked"
    assert len(rec.opens) == before, "a bad errors= reached an open"


# ---------------------------------------------------------------------------------------
# d-07 — the JSONL twin
# ---------------------------------------------------------------------------------------


def test_1049_read_jsonl_answers_rows_malformed_and_the_same_record_read(root):
    """bound.read_jsonl over an absent name answers ([], 0, absent); over a refused shape —
    a refused PARENT included — ([], 0, refused naming the relative name); over a readable
    file the rows, the count of non-blank lines that were not rows, and a RecordRead carrying
    the text. The tolerant policy is _jsonl_rows_of's, the per-line rule
    read_jsonl_rows_guarded shares (rg3): a line that parses but is not an object is one
    malformed row; a repeated key keeps its last value; a final row without a newline counts
    and trailing blank lines are neither rows nor malformed; rows and the RecordRead come off
    ONE walk, so rows non-empty with a refusal is impossible; a ledger whose every line is
    undecodable reads as replaced text with N malformed rows and no refusal — errors='replace'
    is fixed on the twin; a torn last line is one malformed row, never a refusal.
    """
    bound = R.bind(root)
    absent = R.plant_shape(root, "absent")
    rows, malformed, rec = bound.read_jsonl(absent)
    assert (rows, malformed, R.state(rec)) == ([], 0, "absent")
    for shape in ("symlink", "symlinked_parent", "dangling_parent", "parent_is_file"):
        name = R.plant_shape(root, shape)
        rows, malformed, rec = bound.read_jsonl(name)
        assert (rows, malformed) == ([], 0), shape
        assert R.refusal(rec, name) == R.REFUSED_SHAPES[shape], shape

    text = '{"a": 1}\n[1, 2]\n{"k": 1, "k": 2}\n\n\n{"last": true}'
    name = "served/tok.b.jsonl"
    R.write_bytes(root / name, text)
    rows, malformed, rec = bound.read_jsonl(name)
    assert rows == [{"a": 1}, {"k": 2}, {"last": True}], rows
    assert malformed == 1, malformed
    assert R.state(rec) == 'present'
    assert rec.text == text
    assert (rows, malformed) == R.io()._jsonl_rows_of(rec.text), "the twin's policy is not _jsonl_rows_of's"

    R.write_bytes(root / name, text + "\n\n\n")
    assert bound.read_jsonl(name)[:2] == (rows, 1), "trailing blank lines counted"

    torn = '{"a": 1}\n{"b": '
    R.write_bytes(root / name, torn)
    rows, malformed, rec = bound.read_jsonl(name)
    assert (rows, malformed, R.state(rec)) == ([{"a": 1}], 1, "present")

    R.write_bytes(root / name, b"\xff\xfe\n\xff\xfe\n\xff\n")
    rows, malformed, rec = bound.read_jsonl(name)
    assert (rows, malformed, R.state(rec)) == ([], 3, "present"), (rows, malformed, rec)
    assert "�" in rec.text
    assert R.state(bound.read(name)) == "refused", "positive control: strict refuses the same bytes"


# ---------------------------------------------------------------------------------------
# D-J1 — the component grammar
# ---------------------------------------------------------------------------------------


NOT_A_NAME = ("", ".", "..", "/etc/hostname", "worlds/../x", "a//b", "./family.yaml", "a\x00b",
              "worlds/./x", "a/", "/", PurePosixPath("/abs"), PurePosixPath("worlds/../x"),
              "served/../../secret", "gather_summaries/..")


def test_1049_a_name_that_is_not_a_sequence_of_plain_components_cannot_be_constructed(root, tmp_path):
    """Over '', '.', '..', '/etc/hostname', 'worlds/../x', 'a//b', './family.yaml', 'a\\x00b',
    'a/' and PurePosixPath('/abs'): constructing the name — through bound.read, bound.read_jsonl
    and bound.under alike — raises ValueError whose message carries no '/'-bearing spelling
    and no root, and a recording os seam sees no open; bound.read(name, errors='bogus')
    raises ValueError naming no path before any open. Positive control: 'worlds/w/report.md'
    and 'gather_summaries/l-0.md' construct and answer one of the three states, and a lead id
    carrying an inner '/' only deepens the walk under the root (it names 'a/b' inside
    gather_summaries/, never a sibling).
    """
    rec = R.RecordingOs()
    bound = R.bind(root, os_=rec)
    outside = tmp_path / "outside.md"
    outside.write_text("OUTSIDE\n", encoding="utf-8")
    before = len(rec.opens)
    for bad in NOT_A_NAME:
        for ask in (bound.read, bound.read_jsonl, bound.under):
            with pytest.raises(ValueError) as caught:  # noqa: PT011 - the message is asserted below: no path, no root
                ask(bad)
            message = str(caught.value)
            assert "/" not in message, (bad, message)
            assert str(root) not in message, (bad, message)
            assert R.SECRET not in message, (bad, message)
    assert len(rec.opens) == before, "an inexpressible name reached an open"
    with pytest.raises(ValueError):  # noqa: PT011 - d-06 asserts the message; here only that no open follows
        bound.read("worlds/w/report.md", errors="bogus")
    assert len(rec.opens) == before

    assert R.state(bound.read("worlds/w/report.md")) == "absent"
    assert R.state(bound.read("gather_summaries/l-0.md")) == "absent"
    R.write_bytes(root / "gather_summaries" / "a" / "b.md", "deepened\n")
    assert bound.read("gather_summaries/a/b.md").text == "deepened\n"
    assert R.state(bound.under("gather_summaries").read("a/b.md")) == "present"


# ---------------------------------------------------------------------------------------
# D-V3 — the per-component walk
# ---------------------------------------------------------------------------------------


def test_1049_every_component_is_opened_no_follow_from_the_previous_handle_and_the_handle_is_classified_by_fstat(root):
    """Each intermediate component is opened os.open(c, O_PATH|O_NOFOLLOW|O_CLOEXEC,
    dir_fd=<previous handle>) and the HANDLE is fstat-classified: S_ISDIR → it is the next
    dir_fd; S_ISLNK (a symlink, live or dangling — O_PATH|O_NOFOLLOW opens the link itself)
    → refused ALIAS_READ_REFUSAL; ENOENT → absent; any other non-directory handle (a file, a
    fifo — an O_PATH open never wedges) → refused 'Not a directory'; any other OSError → its
    strerror. The leaf is opened O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC from the last handle
    and fstat-classified (S_ISREG and st_nlink>1 → EMLINK alias; not S_ISREG → alias). Every
    handle is closed on every path; nothing is cached between reads; the walk is per name from
    the root handle every time. A recording os seam sees exactly one open per component and
    one fstat per opened handle and no lstat/stat/exists anywhere. Linux-only: os.open
    supports dir_fd and O_PATH/O_NOFOLLOW/O_NONBLOCK/O_CLOEXEC/O_DIRECTORY are present, and
    the primitive's source names O_PATH for the step. The EACCES arms are d-03's.
    """
    assert os.open in os.supports_dir_fd
    for flag in ("O_PATH", "O_NOFOLLOW", "O_NONBLOCK", "O_CLOEXEC", "O_DIRECTORY"):
        assert hasattr(os, flag), flag

    rec = R.RecordingOs()
    bound = R.bind(root, os_=rec)
    R.write_bytes(root / "worlds" / "b" / "report.md", "---\ndisposition: benign\n---\n")
    read = bound.read("worlds/b/report.md")
    assert R.state(read) == "present"
    steps = rec.component_opens
    assert [str(o[0]) for o in steps] == ["worlds", "b", "report.md"], steps
    assert [o[1] for o in steps] == [R.STEP_FLAGS, R.STEP_FLAGS, R.WALK_FLAGS], [o[1] for o in steps]
    fds = [o[3] for o in steps]
    assert all(isinstance(fd, int) for fd in fds), fds
    # the chain: each step's dir_fd is the handle the previous step opened
    assert steps[1][2] == fds[0], [(o[0], o[2], o[3]) for o in steps]
    assert steps[2][2] == fds[1], [(o[0], o[2], o[3]) for o in steps]
    root_opens = [o for o in rec.opens if o[2] is None]
    if root_opens:
        assert steps[0][2] == root_opens[-1][3], "the first component was not opened from the root's handle"
    assert sorted(rec.fstats) == sorted(fds), (rec.fstats, fds)
    assert rec.all_closed(), (rec.opens, rec.closes, rec.fdopens)
    assert not (set(rec.asked) & R.FORBIDDEN_OS_NAMES), rec.asked

    def walk(name: str) -> tuple[R.RecordingOs, object]:
        r = R.RecordingOs()
        return r, R.bind(root, os_=r).read(name)

    # a symlinked / dangling parent: the O_PATH step opens the LINK ITSELF, and its handle's
    # own fstat says S_ISLNK — the alias refusal, with no further open
    for shape in ("symlinked_parent", "dangling_parent"):
        name = R.plant_shape(root, shape)
        r, got = walk(name)
        assert R.refusal(got, name) == R.ALIAS, shape
        opened = r.component_opens
        assert len(opened) == 1, (shape, opened)
        assert isinstance(opened[0][3], int), (shape, opened)
        assert r.fstats == [opened[0][3]], shape
        assert r.all_closed()
    # a file or a fifo squatting a parent: the open succeeds, the fstat says not a directory
    for shape in ("parent_is_file", "parent_is_fifo"):
        name = R.plant_shape(root, shape)
        r, got = walk(name)
        assert R.refusal(got, name) == R.strerror(errno.ENOTDIR), shape
        opened = r.component_opens
        assert len(opened) == 1, (shape, opened)
        assert isinstance(opened[0][3], int), (shape, opened)
        assert r.fstats == [opened[0][3]], shape
        assert r.all_closed(), (shape, r.closes)
    # nothing at a parent: ENOENT at that component, no further open
    r, got = walk(R.plant_shape(root, "absent_parent"))
    assert R.state(got) == "absent"
    assert len(r.component_opens) == 1
    assert r.component_opens[0][3].errno == errno.ENOENT
    # the leaf: a fifo does not wedge, a hard link is EMLINK's alias, a directory is an alias
    for shape in ("fifo", "hard_link", "directory"):
        name = R.plant_shape(root, shape)
        r, got = walk(name)
        assert R.refusal(got, name) == R.ALIAS, shape
        assert r.all_closed(), shape

    # nothing cached: the same name, re-walked, sees the entry's shape now
    R.plant_link(root / "worlds" / "b" / "report.md", root / "plain.md")
    assert R.refusal(bound.read("worlds/b/report.md"), "worlds/b/report.md") == R.ALIAS

    assert R.io()._STEP_FLAGS & os.O_PATH, "the primitive's step is no longer an O_PATH handle"
    assert R.io()._ROOT_FLAGS & os.O_PATH, "the root handle is no longer O_PATH"


# ---------------------------------------------------------------------------------------
# s-22 — a hard link refuses BOTH names
# ---------------------------------------------------------------------------------------


def test_a_hard_link_makes_a_second_unrelated_record_refuse_too(root):
    """Hard-linking record A's file to a scratch name makes A's OWN name refused too —
    '<A's name>: refusing to read through a non-plain or aliased entry' (EMLINK, nlink 2),
    root-free, and nothing ties the two refusals (g1, g13: a hard link to family.yaml made the
    manifest itself refused). Fixture consequence for every hard-link arm in this suite: link
    a scratch file, never a live record. Positive control: with the second name gone, A reads
    again.
    """
    bound = R.bind(root)
    record = R.write_bytes(root / "family.yaml", "worlds: []\n")
    assert bound.read("family.yaml").text == "worlds: []\n"
    scratch = root / "scratch" / "alias-of-the-manifest"
    scratch.parent.mkdir(parents=True, exist_ok=True)
    os.link(record, scratch)
    own = bound.read("family.yaml")
    assert R.refusal(own, "family.yaml") == R.ALIAS, own
    other = bound.read("scratch/alias-of-the-manifest")
    assert R.refusal(other, "scratch/alias-of-the-manifest") == R.ALIAS
    for sentence in (own.refusal, other.refusal):
        assert str(root) not in sentence
        assert R.SECRET not in sentence
    assert "scratch" not in own.refusal, "A's refusal names the other name"
    scratch.unlink()
    assert bound.read("family.yaml").text == "worlds: []\n", "the control failed"

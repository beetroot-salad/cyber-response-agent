"""Regression coverage for a claims-adversary finding on #773 (write-code-from-spec's
claims-adversary pass, PR #1064): `drain._byte_identical_to_head` compared DECODED TEXT
(via `_git.git_show_file` / `read_text_utf8`, both of which apply universal-newline
translation) rather than raw bytes, despite its name and its caller's own docstring
promising a byte comparison. A CRLF-only rewrite of an LF-committed file decodes identical
on both sides and was silently treated as "unchanged" — dropped from
`_changed_corpus_records` even though git itself reports the file dirty, so the file got no
vouching, no forward-check verdict, and was left dirty in the worktree with no error, at
odds with the tick's own "the corpus is clean at the top of every tick" invariant.

NOT part of the locked #773 spec suite (`test_773_*.py`) — this is a regression test for a
bug the claims-adversary pass found in this PR's own code, added after (not part of) the
committed spec, so it lives in its own file rather than editing a locked one.
"""
from __future__ import annotations

from defender.learning.author import drain
from defender.tests._drain719 import git


def test_a_crlf_only_rewrite_is_not_byte_identical_to_head(tmp_path):
    """The exact counterexample the claims-adversary pass ran: HEAD holds LF line endings,
    the working tree rewrites the same text with CRLF line endings. Genuinely different
    bytes (`git status --porcelain` reports the file dirty), but decode-identical — the bug
    was comparing the decoded strings instead of the bytes."""
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q")
    git(repo, "config", "user.email", "a@b.com")
    git(repo, "config", "user.name", "test")
    f = repo / "f.txt"
    f.write_bytes(b"line one\nline two\nline three\n")
    git(repo, "add", "f.txt")
    git(repo, "commit", "-q", "-m", "init")

    f.write_bytes(b"line one\r\nline two\r\nline three\r\n")

    status = git(repo, "status", "--porcelain")
    assert status.stdout.strip() == "M f.txt", "git itself must see this as a dirty file"

    assert drain._byte_identical_to_head(repo, "f.txt") is False


def test_a_genuine_byte_identical_file_is_still_recognised(tmp_path):
    """Positive control beside the fix: an ACTUAL byte-identical rewrite (chmod only, same
    bytes) must still be recognised as unchanged — the fix must not overcorrect into
    flagging every touched file as changed."""
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q")
    git(repo, "config", "user.email", "a@b.com")
    git(repo, "config", "user.name", "test")
    f = repo / "f.txt"
    f.write_bytes(b"line one\nline two\n")
    git(repo, "add", "f.txt")
    git(repo, "commit", "-q", "-m", "init")

    f.chmod(0o755)

    assert drain._byte_identical_to_head(repo, "f.txt") is True

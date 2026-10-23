"""Tenant delivery: changes behavior through the public API."""
from __future__ import annotations


import os


import socket


from types import SimpleNamespace


import pytest


from ._support import (
    LANES,
    ForgeHTTP,
    LockHolder,
    agent_blobs,
    batch_base,
    bounded,
    branch_tip,
    delivery,
    files_under,
    git,
    git_bytes,
    odd_entries,
    opened,
    plain_file,
    plant_raw_commit,
    push_to_remote,
    target,
)


from ._scenarios import (
    _name_status,
    _modes,
    _changes,
    _branches,
    _write,
    _clone_state,
    _BYTE_CHANGERS,
    _replace,
    _REFUSED_OUTPUT,
    _REFUSED_BASE,
    _gitdir_file,
    _nested_repository,
    _mutable_containers,
)

def test_change_set_is_the_draft_against_the_batch_base_and_commits_as_plain_files(repo, tmp_path):
    """O-C/O-D: added, changed and deleted regular files in a lane become `AgentChange`s (repo-
    relative path, exact bytes, `None` for a deletion)."""
    def edit(checkout):
        _write(checkout / "agent/lessons/merged.md", "human-reviewed merge\n")
        _write(checkout / "agent/lessons/tool.md", "#!/bin/sh\n")
        (checkout / "agent/lessons/tool.md").chmod(0o755)
    base = push_to_remote(repo, tmp_path, edit)
    assert _modes(repo[1], base, "agent/lessons/tool.md") == {"agent/lessons/tool.md": "100755"}
    batch = delivery(repo, ForgeHTTP()).start_batch("derive", lanes=LANES)
    lane = batch.draft_root / "agent/lessons"
    (lane / "seed.md").write_bytes(b"seed, revised\r\n")
    (lane / "merged.md").unlink()
    (lane / "tool.md").write_bytes(b"#!/bin/sh\necho revised\n")
    (lane / "deep").mkdir()
    (lane / "deep/new.md").write_bytes(b"\x00binary\xff\n")
    (lane / "new.md").write_bytes(b"new lesson\n")
    (lane / "new.md").chmod(0o755)
    expected = {"agent/lessons/seed.md": b"seed, revised\r\n", "agent/lessons/merged.md": None,
                "agent/lessons/tool.md": b"#!/bin/sh\necho revised\n",
                "agent/lessons/deep/new.md": b"\x00binary\xff\n",
                "agent/lessons/new.md": b"new lesson\n"}
    change_set = batch.change_set()
    assert _changes(change_set) == expected
    assert all(isinstance(c.path, str) and (c.content is None or isinstance(c.content, bytes))
               for c in change_set)

    sha = batch.commit(change_set, "claim one")
    clone = repo[0].knowledge
    assert branch_tip(clone, batch.branch) == sha
    assert git(clone, "rev-parse", f"{sha}^") == batch.export.commit
    assert _name_status(clone, sha) == {"agent/lessons/seed.md": "M", "agent/lessons/merged.md": "D",
                                        "agent/lessons/tool.md": "M", "agent/lessons/deep/new.md": "A",
                                        "agent/lessons/new.md": "A"}
    assert set(_modes(clone, sha, "agent/lessons").values()) == {"100644"}
    for path, content in expected.items():
        if content is not None:
            assert git_bytes(clone, "cat-file", "blob", f"{sha}:{path}") == content


def test_an_existing_lesson_rewritten_lf_to_crlf_with_the_same_text_is_a_change_of_those_bytes(repo):
    """O-C/O-D (review R-4): the ChangeSet compares raw bytes, so a lane file the box rewrites
    from LF to CRLF endings, its text otherwise unchanged, is a change carrying the CRLF bytes,
    and the commit stores exactly those bytes."""
    batch = delivery(repo, ForgeHTTP()).start_batch("crlfonly", lanes=LANES)
    lane = batch.draft_root / "agent/lessons"
    lesson = sorted(p for p in lane.rglob("*") if p.is_file())[0]
    data = lesson.read_bytes()
    assert b"\n" in data, f"precondition: {lesson} has a line ending to rewrite"
    assert b"\r\n" not in data, f"precondition: {lesson} is not already CRLF"
    crlf = data.replace(b"\n", b"\r\n")
    lesson.write_bytes(crlf)
    rel = lesson.relative_to(batch.draft_root).as_posix()
    change_set = batch.change_set()
    assert _changes(change_set) == {rel: crlf}, "an LF-to-CRLF rewrite is not a change of its bytes"
    sha = batch.commit(change_set, "crlf only")
    clone = repo[0].knowledge
    assert _name_status(clone, sha) == {rel: "M"}
    assert git_bytes(clone, "cat-file", "blob", f"{sha}:{rel}") == crlf


def test_a_mode_only_edit_of_an_existing_lesson_is_no_change(repo):
    """O-C/O-D (review R-4): the commit-maker stores plain files (mode 100644 whatever the box
    set), so a chmod of an unchanged lane file, its bytes untouched, is no change at all."""
    batch = delivery(repo, ForgeHTTP()).start_batch("modeonly", lanes=LANES)
    lane = batch.draft_root / "agent/lessons"
    lesson = sorted(p for p in lane.rglob("*") if p.is_file())[0]
    data = lesson.read_bytes()
    lesson.chmod(0o755)
    assert lesson.stat().st_mode & 0o111, "precondition: the chmod took"
    assert lesson.read_bytes() == data
    assert _changes(batch.change_set()) == {}, "a mode-only edit became a change"


@pytest.mark.parametrize("changer", sorted(_BYTE_CHANGERS))
def test_the_commit_maker_stores_the_boxs_bytes_whatever_mains_attributes_say(repo, tmp_path, changer):
    """O-C: the commit-maker stores each changed file's bytes exactly as the box wrote them."""
    attributes, driver = _BYTE_CHANGERS[changer]
    push_to_remote(repo, tmp_path, lambda c: _write(c / ".gitattributes", attributes))
    clone = repo[0].knowledge
    if driver is not None:
        git(clone, "config", "filter.p3upper.clean", driver)
    batch = delivery(repo, ForgeHTTP()).start_batch("bytes", lanes=LANES)
    data = b"Line One\r\n$Id: 0123456789abcdef $\r\nlower case, mixed endings\n"
    (batch.draft_root / "agent/lessons/exact.md").write_bytes(data)
    sha = batch.commit(batch.change_set(), "exact bytes")
    assert _name_status(clone, sha) == {"agent/lessons/exact.md": "A"}
    assert git_bytes(clone, "cat-file", "blob", f"{sha}:agent/lessons/exact.md") == data


@pytest.mark.parametrize("attributes", ["*.md text eol=crlf\n", "*.md text eol=crlf ident\n"],
                         ids=["eol", "eol-and-ident"])
def test_claim_after_claim_the_box_sees_exactly_the_committed_bytes(repo, tmp_path, attributes):
    """Claim after claim the box sees exactly the committed bytes."""
    def human(checkout):
        _write(checkout / ".gitattributes", attributes)
        (checkout / "agent/lessons/human.md").write_bytes(b"a human's lesson\n")
    push_to_remote(repo, tmp_path, human)
    batch = delivery(repo, ForgeHTTP()).start_batch("crlf", lanes=LANES)
    # Precondition: a checkout here converts (the clone's own checkout of the new lesson).
    assert (repo[0].agent / "lessons/human.md").read_bytes() == b"a human's lesson\r\n"
    agent, clone = batch.draft_root / "agent", repo[0].knowledge
    assert files_under(agent) == agent_blobs(clone, batch.export.commit) == files_under(batch.export.path / "agent")

    claim1 = {"agent/lessons/seed.md": b"seed, revised by the box\n",
              "agent/lessons/new.md": b"$Id$\nwritten by the box with LF\n"}
    for rel, data in claim1.items():
        (batch.draft_root / rel).write_bytes(data)
    change_set = batch.change_set()
    assert _changes(change_set) == claim1
    first = batch.commit(change_set, "claim one")
    assert {f"agent/{rel}": data for rel, data in agent_blobs(clone, first).items() if f"agent/{rel}" in claim1} == claim1
    batch.reset()
    assert files_under(agent) == agent_blobs(clone, first), "the reset handed the box other bytes than committed"

    assert _changes(batch.change_set()) == {}, "a claim with no edit by the box is not empty"

    claim3 = {"agent/lessons/new.md": claim1["agent/lessons/new.md"] + b"and appended\n"}
    (batch.draft_root / "agent/lessons/new.md").write_bytes(claim3["agent/lessons/new.md"])
    change_set = batch.change_set()
    assert _changes(change_set) == claim3
    third = batch.commit(change_set, "claim three")
    assert git(clone, "rev-parse", f"{third}^") == first
    assert agent_blobs(clone, third)["lessons/new.md"] == claim3["agent/lessons/new.md"]
    batch.reset()
    assert files_under(agent) == agent_blobs(clone, third)


@pytest.mark.parametrize("entry", sorted(_REFUSED_OUTPUT))
def test_a_claim_holding_anything_but_in_lane_regular_files_is_refused_whole(
        repo, tmp_path, monkeypatch, entry):
    """A claim holding anything but in lane regular files is refused whole."""
    if entry in _REFUSED_BASE:
        def base(checkout):
            for rel, text in _REFUSED_BASE[entry].items():
                _write(checkout / rel, text)
        push_to_remote(repo, tmp_path, base)
    clone = repo[0].knowledge
    batch = delivery(repo, ForgeHTTP()).start_batch("inert", lanes=LANES)
    agent = batch.draft_root / "agent"
    lane = agent / "lessons"
    outside = tmp_path / "host-folder"
    outside.mkdir()
    (outside / "secret.md").write_text("host only\n", encoding="utf-8")
    _write(lane / "valid.md", "a valid change beside it\n")
    sockets = []
    if entry == "socket":
        monkeypatch.chdir(lane)
        sockets.append(socket.socket(socket.AF_UNIX))
        sockets[0].bind("sock.md")
    else:
        _REFUSED_OUTPUT[entry](lane, agent, outside, clone)
    fifos = [lane / "pipe.md", lane / "seed.md"]
    base, state = batch_base(clone, batch), _clone_state(clone)
    try:
        _, error, hung = bounded(batch.change_set, fifos=fifos)
    finally:
        for listener in sockets:
            listener.close()
    assert not hung, "deriving the change set blocked on box output"
    assert isinstance(error, target().DeliveryRefused), error
    assert branch_tip(clone, batch.branch) is None
    assert _clone_state(clone) == state

    _, error, hung = bounded(batch.reset, fifos=fifos)
    assert not hung, "the reset blocked on box output"
    assert error is None, error
    assert files_under(outside) == {"secret.md": b"host only\n"}, "a reset wrote through a link"
    blobs = agent_blobs(clone, base)
    for rel, data in blobs.items():
        assert plain_file(agent / rel, data), f"the reset left agent/{rel} other than git's blob"
    assert odd_entries(agent) == []
    assert files_under(agent) == blobs
    assert _changes(batch.change_set()) == {}


@pytest.mark.parametrize("plant", [_gitdir_file, _nested_repository], ids=["gitdir-file", "repository"])
def test_git_metadata_in_a_lane_never_becomes_a_commit(repo, plant):
    batch = delivery(repo, ForgeHTTP()).start_batch("nested", lanes=LANES)
    clone = repo[0].knowledge
    lane = batch.draft_root / "agent/lessons"
    _write(lane / "valid.md", "a valid change beside it\n")
    plant(lane, clone)
    state = _clone_state(clone)
    with pytest.raises(target().DeliveryRefused):
        batch.commit(batch.change_set(), "nested repository")
    assert branch_tip(clone, batch.branch) is None
    assert _clone_state(clone) == state


@pytest.mark.parametrize("shape", ["list-of-changes", "tuple-of-changes", "bare-change",
                                   "path-list", "mapping"])
def test_the_commit_maker_takes_nothing_but_a_change_set(repo, shape):
    """O-C: the commit-maker's sole input is a `ChangeSet`; anything else, however close in
    shape, is refused before any branch moves. A real `ChangeSet` commits (control)."""
    mod = target()
    clone = repo[0].knowledge
    batch = delivery(repo, ForgeHTTP()).start_batch("only", lanes=LANES)
    change = mod.AgentChange("agent/lessons/x.md", b"x\n")
    not_a_change_set = {"list-of-changes": [change], "tuple-of-changes": (change,),
                        "bare-change": change, "path-list": ["agent/lessons/x.md"],
                        "mapping": {"agent/lessons/x.md": b"x\n"}}[shape]
    state = _clone_state(clone)
    with pytest.raises((TypeError, mod.DeliveryRefused)):
        batch.commit(not_a_change_set, "not a change set")
    assert branch_tip(clone, batch.branch) is None
    assert _clone_state(clone) == state
    sha = batch.commit(mod.ChangeSet((change,)), "a change set")
    assert _name_status(clone, sha) == {"agent/lessons/x.md": "A"}


def test_a_change_set_cannot_change_once_built(repo):
    """A change set cannot change once built."""
    clone = repo[0].knowledge
    batch = delivery(repo, ForgeHTTP()).start_batch("frozen", lanes=LANES)
    _write(batch.draft_root / "agent/lessons/ok.md", "ok\n")
    built = batch.change_set()
    [change] = list(built)
    reassigned = []
    for obj, name, value in [(change, "path", "settings/rogue.yaml"), (change, "content", b"x\n"),
                             *((built, name, None) for name in getattr(built, "__dict__", {}))]:
        try:
            setattr(obj, name, value)
        except (AttributeError, TypeError):
            continue
        reassigned.append(f"{type(obj).__name__}.{name}")
    mutable = _mutable_containers(built)
    for container in mutable:
        if isinstance(container, list):
            container.append(SimpleNamespace(path="settings/rogue.yaml", content=b"smuggled\n"))
    _, error, _ = bounded(lambda: batch.commit(built, "claim"))
    tip = branch_tip(clone, batch.branch)
    if tip is not None:
        assert "settings/rogue.yaml" not in _name_status(clone, tip)
    assert reassigned == [], "an attribute of a built change set was reassigned"
    assert mutable == [], "a built change set holds a mutable container"
    assert error is None, error
    assert _name_status(clone, tip) == {"agent/lessons/ok.md": "A"}


@pytest.mark.parametrize(("path", "content"), [
    ("agent/.tenant-id", b"red\n"), ("settings/rogue.yaml", b"x\n"), ("product.py", b"x\n"),
    ("agent/../settings/rogue.yaml", b"x\n"), ("agent/lessons/../.tenant-id", b"red\n"),
    ("/abs/agent/lessons/x.md", b"x\n"), (" agent/lessons/x.md", b"x\n"),
    ("\tagent/lessons/x.md", b"x\n"), ("\nagent/lessons/x.md", b"x\n"),
    ("agent/lessons/.gitattributes", b"* filter=planted\n"),
    ("agent/lessons/deep/.gitignore", b"*\n"), ("agent/.gitmodules", b"[submodule]\n"),
    ("agent/notes.md", b"outside every lane\n"), ("agent/lessons-questioner/x.md", b"x\n"),
    ("agent/AGENT.md", None), ("agent/lessons/x.md", "text, not bytes"),
])
def test_no_change_set_commits_outside_the_lanes_or_touches_a_forbidden_name(repo, path, content):
    """No change set commits outside the lanes or touches a forbidden name."""
    mod = target()
    clone = repo[0].knowledge
    batch = delivery(repo, ForgeHTTP()).start_batch("bounded", lanes=LANES)
    state = _clone_state(clone)
    with pytest.raises((mod.DeliveryRefused, ValueError, TypeError)):
        batch.commit(mod.ChangeSet((mod.AgentChange("agent/lessons/ok.md", b"ok\n"),
                                    mod.AgentChange(path, content))), "forbidden")
    assert branch_tip(clone, batch.branch) is None
    assert _clone_state(clone) == state


def test_claims_commit_and_reset_one_after_another_within_one_batch(repo):
    http = ForgeHTTP()
    d = delivery(repo, http)
    batch = d.start_batch("loop", lanes=LANES)
    lane = batch.draft_root / "agent/lessons"
    clone = repo[0].knowledge
    shas = []

    _write(lane / "a.md", "a, first\n")
    shas.append(batch.commit(batch.change_set(), "claim 1"))
    batch.reset()
    assert files_under(batch.draft_root / "agent") == agent_blobs(clone, shas[0])
    assert _changes(batch.change_set()) == {}

    _write(lane / "a.md", "a, second\n")
    (lane / "seed.md").unlink()
    shas.append(batch.commit(batch.change_set(), "claim 2"))
    batch.reset()

    (lane / "link.md").symlink_to("/etc/passwd")
    with pytest.raises(target().DeliveryRefused):
        batch.change_set()
    batch.reset()
    assert _changes(batch.change_set()) == {}

    _write(lane / "b.md", "b\n")
    shas.append(batch.commit(batch.change_set(), "claim 4"))

    assert [git(clone, "rev-parse", f"{sha}^") for sha in shas] == [batch.export.commit, *shas[:2]]
    assert [_name_status(clone, sha) for sha in shas] == [
        {"agent/lessons/a.md": "A"},
        {"agent/lessons/a.md": "M", "agent/lessons/seed.md": "D"},
        {"agent/lessons/b.md": "A"}]
    opened(d.finish(batch))
    assert git(repo[1], "rev-parse", f"refs/heads/{batch.branch}") == shas[-1]
    assert git(repo[1], "rev-parse", "main") == batch.export.commit
    assert [(c["base"], c["head"]) for c in http.creates] == [("main", batch.branch)]


def test_a_claim_reset_resyncs_the_draft_and_never_follows_box_links(repo, tmp_path):
    """A claim reset resyncs the draft and never follows box links."""
    batch = delivery(repo, ForgeHTTP()).start_batch("reset", lanes=LANES)
    lane = batch.draft_root / "agent/lessons"
    for name in ("a.md", "edited.md", "fifo.md", "deep/b.md"):
        _write(lane / name, "committed\n")
    sha = batch.commit(batch.change_set(), "claim")
    outside = tmp_path / "host-folder"
    outside.mkdir()
    (outside / "keep.md").write_text("host\n", encoding="utf-8")
    _write(lane / "edited.md", "changed after the commit\n")
    _write(lane / "stray.md", "stray\n")
    _write(lane / "fresh/stray.md", "stray\n")
    (lane / "seed.md").unlink()
    (lane / "linked").symlink_to(outside, target_is_directory=True)
    os.mkfifo(lane / "pipe")
    _replace(lane / "a.md", lambda e: e.symlink_to(outside / "keep.md"))
    _replace(lane / "fifo.md", os.mkfifo)
    _replace(lane / "deep", lambda e: e.symlink_to(outside, target_is_directory=True))
    _, error, hung = bounded(batch.reset, fifos=[lane / "pipe", lane / "fifo.md"])
    assert not hung, "the reset blocked on box output"
    assert error is None, error
    assert files_under(outside) == {"keep.md": b"host\n"}, "the reset wrote through a link"
    for name in ("a.md", "edited.md", "fifo.md", "deep/b.md"):
        assert plain_file(lane / name, b"committed\n"), name
    assert odd_entries(batch.draft_root) == []
    assert files_under(batch.draft_root / "agent") == agent_blobs(repo[0].knowledge, sha)


def test_the_first_commit_makes_the_branch_and_never_takes_one_over(repo):
    """C2: the commit-maker moves the batch's branch by compare-and-swap, and the first commit
    expects no branch at all: it creates it."""
    http = ForgeHTTP()
    d = delivery(repo, http)
    clone = repo[0].knowledge
    batch = d.start_batch("taken-over", lanes=LANES)
    laid = plant_raw_commit(clone, f"refs/heads/{batch.branch}", "agent/lessons/raw.md",
                            b"raw git, not the commit-maker\n", base=batch.export.commit)
    _write(batch.draft_root / "agent/lessons/new.md", "the first claim\n")
    with pytest.raises(target().DeliveryRefused):
        batch.commit(batch.change_set(), "the first claim")
    assert branch_tip(clone, batch.branch) == laid
    assert _branches(repo[1]) == ["refs/heads/main"]
    assert not http.creates


def test_the_commit_maker_takes_no_lock_and_leaves_main_the_index_and_the_checkout_alone(
        repo, tmp_path):
    """C2 / O-F (narrowed): the commit-maker writes git objects and moves its own branch by
    compare-and-swap, with no lock (a lock there would fall inside a box window)."""
    tenant = repo[0]
    clone = tenant.knowledge
    batch = delivery(repo, ForgeHTTP()).start_batch("lockless", lanes=LANES)
    state = _clone_state(clone)
    with LockHolder(tenant, tmp_path / "holder"):
        for number in (1, 2):
            _write(batch.draft_root / f"agent/lessons/claim-{number}.md", f"claim {number}\n")
            (batch.draft_root / "agent/lessons/seed.md").write_bytes(f"seed, claim {number}\n".encode())
            for step in (lambda: batch.commit(batch.change_set(), "claim"), batch.reset):
                _, error, hung = bounded(step)
                assert not hung, "the commit-maker waited on the tenant's lock"
                assert error is None, error
    assert _clone_state(clone) == state
    tip = branch_tip(clone, batch.branch)
    assert git(clone, "rev-parse", f"{tip}^^") == batch.export.commit
    assert agent_blobs(clone, tip)["lessons/seed.md"] == b"seed, claim 2\n"
    assert files_under(batch.draft_root / "agent") == agent_blobs(clone, tip)

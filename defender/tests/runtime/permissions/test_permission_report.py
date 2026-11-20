"""decide_write's investigation.md size bound, and the absence of any `report.md` rule (retired by #1534), driven on real bytes."""
from __future__ import annotations
from defender.tests.support.shared._fixture_uuid import fixture_uuid


from dataclasses import dataclass
from pathlib import Path

import pytest
from defender.investigation import permission

# The gate's bound, in UTF-8 bytes.
INV_BOUND = 65536

GOLDEN_INV = (Path(__file__).resolve().parents[3]
              / "tests" / "fixtures" / "e2e" / "golden-sshpivot-ab3" / "investigation.md").read_text(encoding="utf-8")


# fixtures + builders

@dataclass
class Env:
    run: Path
    dfn: Path
    pol: permission.AgentPolicy

    def decide(self, name: str, text: str) -> permission.Decision:
        """Drive the REAL gate on `<run_dir>/name` with run_dir threaded (the branch keys on
        it) and defender_dir supplying the read-containment root."""
        return permission.decide_write(
            self.run / name, text, run_dir=self.run, defender_dir=self.dfn, policy=self.pol
        )

    def decide_path(self, path: Path, text: str = "") -> permission.Decision:
        return permission.decide_write(
            path, text, run_dir=self.run, defender_dir=self.dfn, policy=self.pol
        )


@pytest.fixture
def env(tmp_path):
    run = tmp_path / fixture_uuid("run")
    run.mkdir()
    dfn = tmp_path / "defender"
    dfn.mkdir()
    pol = permission.AgentPolicy(write_allow=(permission.build_write_allow(run),))
    return Env(run, dfn, pol)



# the retired report.md rules: absent, so the file is an ordinary run-dir file

#: Texts the retired rules refused: no fence, bad or case-variant disposition, a duplicate key, a YAML alias, the close
#: delimiter and an oversize body.
FORMER_REFUSALS = (
    "", "no fence at all\n", "---\ndisposition: hostile\n---\nbody\n", "---\ndisposition: Benign\n---\nbody\n",
    "---\ndisposition: benign\ndisposition: benign\n---\nbody\n", "---\n- benign\n---\nbody\n",
    "---\ndisposition: benign\na: &a x\nb: *a\n---\nbody\n", "---\ndisposition: benign\n---\nan </report> close\n",
    "---\ndisposition: benign\n---\n" + "x" * 9000,
)


def test_report_md_is_not_a_keyed_artifact():
    """The file's name is not among the artifacts the write gate keys on, and the report-write gate is gone. (the design's Removal list)"""
    from defender.records import formats

    assert "report.md" not in formats.artifact_names()
    assert "investigation.md" in formats.artifact_names(), "control: the investigation is still keyed"
    assert not hasattr(permission.files, "_decide_report_write")


@pytest.mark.parametrize("text", FORMER_REFUSALS, ids=[f"former-{i}" for i in range(len(FORMER_REFUSALS))])
def test_a_report_md_write_meets_no_content_rule(env, text):
    """What the retired gate refused is allowed at `report.md` exactly as at any other run-dir file (no frontmatter, size or delimiter rule)."""
    assert env.decide("report.md", text).allow is True
    assert env.decide("scratch-notes.txt", text).allow is True


def test_report_md_is_still_bound_by_the_write_scope(env, tmp_path):
    """Control: the allowance is the write scope's alone: `report.md` outside the agent's declared paths is refused."""
    assert env.decide("report.md", "anything\n").allow is True
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    assert env.decide_path(outside / "report.md", "anything\n").allow is False
    assert env.decide_path(outside / "scratch-notes.txt", "anything\n").allow is False


def test_investigation_size_bound(env):
    """An investigation.md is denied when the proposed text (the whole file: there is no append)
    exceeds 64 KiB, counted in bytes."""
    assert env.decide("investigation.md", GOLDEN_INV).allow is True                    # valid, under
    over = GOLDEN_INV + "\n" + "x" * (INV_BOUND + 5000) + "\n"                          # invlang-valid, over
    assert len(over.encode("utf-8")) > INV_BOUND
    assert env.decide("investigation.md", over).allow is False
    mb = GOLDEN_INV + "\n" + "\U0001F600" * (INV_BOUND // 4 + 100) + "\n"
    assert len(mb.encode("utf-8")) > INV_BOUND
    assert len(mb) <= INV_BOUND
    assert env.decide("investigation.md", mb).allow is False


# path keying: the exact name, at the run-dir root, after resolving symlinks

@pytest.mark.parametrize("near", ["my_investigation.md", "investigation.md.bak", "investigationxmd"])
def test_filename_near_miss_does_not_collide_with_investigation_md(env, near):
    """A near-miss name carries no investigation rule; the exact name is the positive control."""
    bad = GOLDEN_INV + "x" * (INV_BOUND + 100)
    assert env.decide(near, bad).allow is True
    assert env.decide("investigation.md", bad).allow is False


def test_main_writes_an_arbitrarily_named_file_into_the_run_dir(env):
    """An arbitrarily-named run-dir file matches no artifact key, so no content rule or bound applies to it."""
    junk = "x" * (INV_BOUND + 1)
    assert env.decide("scratch-notes.txt", junk).allow is True
    assert env.decide("investigation.md", GOLDEN_INV + junk).allow is False  # positive control


def test_a_symlink_operand_resolves_before_keying(env):
    """Resolution decides, not the reported name: a decoy linked onto the investigation is gated, and the artifact's own name linked elsewhere is not."""
    import os
    (env.run / "sub").mkdir()
    bad = GOLDEN_INV + "x" * (INV_BOUND + 100)

    decoy = env.run / "decoy2.md"
    os.symlink(env.run / "investigation.md", decoy)
    assert decoy.resolve() == (env.run / "investigation.md").resolve()
    assert env.decide_path(decoy, bad).allow is False

    disguised_root = env.run / "investigation.md"
    os.symlink(env.run / "sub" / "other.md", disguised_root)
    assert disguised_root.resolve() != (env.run / "investigation.md")
    assert env.decide_path(disguised_root, bad).allow is True


def test_forward_check_lesson_named_investigation_md_not_gated(tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    dfn = tmp_path / "defender"
    skills = dfn / "skills" / "elastic"
    skills.mkdir(parents=True)
    curator_pol = permission.AgentPolicy(
        write_allow=(permission.build_write_allow(skills, suffix=".md"),)
    )
    bad = GOLDEN_INV + "x" * (INV_BOUND + 100)
    lesson = skills / "investigation.md"  # a corpus file that merely SHARES the basename
    d = permission.decide_write(lesson, bad, run_dir=run, defender_dir=dfn, policy=curator_pol)
    assert d.allow is True, "a lesson named investigation.md must not be routed into the artifact branch"
    # Positive control: the real run-dir-root investigation.md with the same text IS gated -> deny.
    main_pol = permission.AgentPolicy(write_allow=(permission.build_write_allow(run),))
    d2 = permission.decide_write(run / "investigation.md", bad, run_dir=run, defender_dir=dfn, policy=main_pol)
    assert d2.allow is False


def test_investigation_case_variant_not_gated(env):
    bad = GOLDEN_INV + "x" * (INV_BOUND + 100)
    for variant in ("Investigation.md", "INVESTIGATION.MD", "investigation.MD"):
        assert env.decide(variant, bad).allow is True, variant
    assert env.decide("investigation.md", bad).allow is False  # positive control — exact match fires


def test_investigation_md_in_subdir_not_gated(env):
    (env.run / "sub").mkdir()
    bad = GOLDEN_INV + "x" * (INV_BOUND + 100)
    assert env.decide("sub/investigation.md", bad).allow is True
    assert env.decide("investigation.md", bad).allow is False  # positive control


def test_investigation_empty_or_whitespace_commits(env):
    """Empty and whitespace-only writes are accepted (there is no minimum); an oversized one is
    the negative control."""
    assert env.decide("investigation.md", "").allow is True
    assert env.decide("investigation.md", "   \n\t\n").allow is True
    assert env.decide("investigation.md", GOLDEN_INV + "x" * (INV_BOUND + 100)).allow is False


def test_investigation_over_bound_and_invlang_invalid_single_feedback(env):
    """A write both over the bound and invlang-invalid gets one reason, the size one: size is
    checked first."""
    bad_and_big = "```yaml\nnot invlang\n```\n" + "x" * (INV_BOUND + 5000)
    assert len(bad_and_big.encode("utf-8")) > INV_BOUND
    d = env.decide("investigation.md", bad_and_big)
    assert d.allow is False
    assert "invlang validation" not in d.reason, "size must be checked first (short-circuit)"
    assert d.reason, "the single feedback reason is non-empty"
    # positive control: a small invlang-invalid doc reaches the invlang branch and names it.
    small_bad = env.decide("investigation.md", "```yaml\nnot invlang\n```\n")
    assert small_bad.allow is False
    assert "invlang validation" in small_bad.reason


# the gate fails closed, never raises

def test_investigation_gate_cannot_be_skipped_by_omitting_the_run_root(env):
    """The artifact gate keys on `<run_dir>/investigation.md`, so omitting the run root is a `TypeError` and an explicit `None` fails closed (#681)."""
    repro = GOLDEN_INV + "x" * (INV_BOUND + 100)
    with pytest.raises(TypeError):
        permission.decide_write(env.run / "investigation.md", repro, policy=env.pol)
    explicit_none = permission.decide_write(
        env.run / "investigation.md", repro, run_dir=None, defender_dir=None, policy=env.pol
    )
    assert explicit_none.allow is False
    assert "read roots" in explicit_none.reason
    gated = env.decide("investigation.md", repro)  # positive control — the gate itself, not containment
    assert gated.allow is False
    assert "read roots" not in gated.reason


def test_non_utf8_encodable_content_fails_closed_not_raises(env):
    """A lone surrogate (`\ud800`, reachable from a model tool-call JSON arg) cannot be encoded as UTF-8; the gate denies it with a reason instead of raising."""
    surrogate = "\ud800"
    i = env.decide("investigation.md", surrogate)
    assert i.allow is False
    assert i.reason
    other = env.decide("scratch-notes.txt", surrogate)
    assert other.allow is False, "an ordinary run-dir file is checked for encodability too"
    assert other.reason
    assert env.decide("investigation.md", "").allow is True  # positive control

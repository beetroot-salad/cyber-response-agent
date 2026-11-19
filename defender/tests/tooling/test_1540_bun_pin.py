"""#1540 F6: Bun is downloaded in one place, `tooling/install-bun.sh`, which pins one version and one sha256 and checks
that sha on the downloaded file before unpacking it. Every CI job and dev-image stage that runs a `bun` command runs
that script itself (found by search, not by a list); nothing else downloads Bun or takes it from `setup-bun`.

The check is a function over texts, so it also runs on a synthetic good input and on mutations of it: a check that
cannot fail would be vacuous. It reads the script the way a shell would: `${VAR}`/`$VAR` are replaced from the
script's own upper-case assignments, so it does not care what the variables are called. It does need: the release URL
spelled out (`.../releases/download/bun-vX.Y.Z/`), the sha256 as the literal value of a variable or a literal hex in
the verifying `sha256sum -c` line, and the download written to a named file (`-o`/`-O`).
"""
from __future__ import annotations

import re
from collections.abc import Mapping

import pytest
import yaml

from defender._git import REPO_ROOT

SCRIPT = "tooling/install-bun.sh"
_DOWNLOAD = "oven-sh/bun/releases/download"
_VERSION = re.compile(r"/releases/download/bun-v(\d+\.\d+\.\d+)/")
_TARGET = re.compile(r"\s(?:-[A-Za-z]*[oO]|--output(?:-document)?)[ =](\S+)")
_SHA_LINE = re.compile(r"\b([0-9a-f]{64})\s+\*?(\S+)")
_VERIFY = re.compile(r"sha256sum\s+(?:-c|--check)\b|shasum\s+-a\s+256\s+(?:-c|--check)\b")
_ASSIGNMENT = re.compile(r"^([A-Z][A-Z0-9_]*)=(\S+)$", re.M)
#: A `bun` command word in a shell text: not a path's last segment (`/usr/local/bin/bun`) or part of a name (`bun-v1`,
#: `install-bun.sh`).
_BUN_COMMAND = re.compile(r"(?<![\w./-])bun(?=\s|$)", re.M)


def _expand(text: str, env: Mapping[str, str]) -> str:
    def name(match: re.Match[str]) -> str:
        return str(env.get(match.group(1), match.group(0)))

    for pattern in (r"\$\{(\w+)\}", r"\$(\w+)"):
        text = re.sub(pattern, name, text)
    return text


def script_problems(text: str) -> list[str]:
    """What is wrong with the install script: its pin, its sha check, or the order of check and unpack."""
    text = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    env = {key: value.strip("\"'") for key, value in _ASSIGNMENT.findall(text)}
    text = _expand(text, env)
    problems = []
    if not _VERSION.search(text):
        problems.append("the release URL does not spell out `bun-vX.Y.Z`")
    target = _TARGET.search(text)
    if not target:
        return [*problems, "the download is not written to a named file (`-o FILE`)"]
    path = target.group(1).strip("\"'")
    checks = [m for m in _SHA_LINE.finditer(text) if m.group(2).strip("\"'") == path]
    verify = _VERIFY.search(text)
    if not checks or not verify:
        return [*problems, f"no sha256 check of {path}: need a literal sha256 line for it and `sha256sum -c`"]
    unpack = re.search(r"\bunzip\b", text)
    if unpack and unpack.start() < verify.start():
        problems.append("the zip is unpacked before its sha256 is checked")
    return problems


def _instructions(text: str) -> list[str]:
    """A Dockerfile's instructions, continuation lines joined, comments dropped."""
    joined = re.sub(r"\\\r?\n", " ", "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#")))
    return [line.strip() for line in joined.splitlines() if line.strip()]


def _dockerfile(label: str, text: str) -> dict[str, set[str]]:
    """Per stage of a Dockerfile: whether it runs `bun`, runs the script, copies the script in, or downloads Bun."""
    found: dict[str, set[str]] = {}
    stage = 0
    for instruction in _instructions(text):
        words = instruction.split(None, 1)
        if words[0] == "FROM":
            stage += 1
        rest = words[1] if len(words) > 1 else ""
        marks = found.setdefault(f"{label}:stage{stage}", set())
        if words[0] == "COPY" and SCRIPT in rest:
            marks.add("copies")
        if words[0] == "RUN":
            if "install-bun.sh" in rest:
                marks.add("installs")
            if _BUN_COMMAND.search(rest):
                marks.add("runs")
            if _DOWNLOAD in rest:
                marks.add("downloads")
    return found


def _workflow(label: str, text: str) -> dict[str, set[str]]:
    """Per job of a workflow: whether it runs `bun`, runs the script, downloads Bun, or uses `setup-bun`."""
    found: dict[str, set[str]] = {}
    for job_id, job in ((yaml.safe_load(text) or {}).get("jobs") or {}).items():
        marks = found.setdefault(f"{label}:{job_id}", set())
        for step in job.get("steps") or []:
            run = str(step.get("run", ""))
            if SCRIPT in run:
                marks.add("installs")
            if _BUN_COMMAND.search(run):
                marks.add("runs")
            if _DOWNLOAD in run:
                marks.add("downloads")
            if "setup-bun" in str(step.get("uses", "")):
                marks.add("setup-bun")
    return found


def check_bun_comes_from_one_script(script: str, texts: Mapping[str, str]) -> None:
    """F6: the script holds the one pin and checks it; two CI jobs (test, lint) and a dev image run it; every job or
    image stage that runs `bun` runs it there too (an image stage after copying it in); nothing else downloads Bun or
    takes it from `setup-bun`."""
    problems = [f"{SCRIPT}: {p}" for p in script_problems(script)]
    places: dict[str, set[str]] = {}
    for label, text in texts.items():
        places |= _workflow(label, text) if label.endswith((".yml", ".yaml")) else _dockerfile(label, text)
    for place, marks in sorted(places.items()):
        if "downloads" in marks:
            problems.append(f"{place}: downloads Bun itself; run {SCRIPT} instead")
        if "setup-bun" in marks:
            problems.append(f"{place}: Bun from `setup-bun`, not {SCRIPT}")
        if "runs" in marks and "installs" not in marks:
            problems.append(f"{place}: runs `bun` but does not run {SCRIPT} in the same job or stage")
        if "installs" in marks and ":stage" in place and "copies" not in marks:
            problems.append(f"{place}: runs {SCRIPT} without copying it into that stage")
    assert not problems, problems
    jobs = sorted(p for p, m in places.items() if "installs" in m and ":stage" not in p)
    images = sorted(p for p, m in places.items() if "installs" in m and ":stage" in p)
    assert len(jobs) >= 2, f"expected {SCRIPT} run in two workflow jobs, found {jobs}"
    assert images, f"expected {SCRIPT} run in a dev image, found {sorted(places)}"


def _repo_texts() -> dict[str, str]:
    workflows = sorted((REPO_ROOT / ".github" / "workflows").glob("*.y*ml"))
    images = sorted((REPO_ROOT / ".devcontainer").rglob("Dockerfile*"))
    assert workflows, "control: the search finds the workflow files"
    assert images, "control: the search finds the Dockerfiles"
    return {str(p.relative_to(REPO_ROOT)): p.read_text(encoding="utf-8") for p in [*workflows, *images]}


def test_1540_f6_bun_comes_from_the_one_pinned_and_checked_install_script_everywhere_it_runs():
    """CI's jobs and the dev image get Bun from `tooling/install-bun.sh`, which pins and checks it. (F6)"""
    check_bun_comes_from_one_script((REPO_ROOT / SCRIPT).read_text(encoding="utf-8"), _repo_texts())


# --- the check itself can fail ---------------------------------------------------------------------

SHA = "a" * 64
GOOD_SCRIPT = f"""#!/bin/sh
# Needs curl, sha256sum and unzip.
set -eu
BUN_VERSION=1.4.4
BUN_SHA256={SHA}
curl -fsSL -o "$work/bun.zip" "https://github.com/oven-sh/bun/releases/download/bun-v${{BUN_VERSION}}/bun-linux-x64.zip"
echo "${{BUN_SHA256}}  $work/bun.zip" | sha256sum -c -
unzip -q "$work/bun.zip" -d "$work"
"""
_INSTALL = "      - run: sudo sh tooling/install-bun.sh\n"
_RUNS_BUN = "      - run: bun install --frozen-lockfile\n"
_INLINE = ('      - run: curl -fsSL -o /tmp/b.zip "https://github.com/oven-sh/bun/releases/download/bun-v1.4.4/x.zip"\n')
GOOD = {
    ".github/workflows/ci.yml": "on: push\njobs:\n  test:\n    runs-on: x\n    steps:\n" + _INSTALL
    + "  lint:\n    runs-on: x\n    steps:\n" + _INSTALL + _RUNS_BUN,
    ".devcontainer/Dockerfile.dev": ("FROM x\nCOPY tooling/install-bun.sh /tmp/install-bun.sh\n"
                                     "RUN sh /tmp/install-bun.sh && rm /tmp/install-bun.sh\nRUN bun --version\n"),
}


def _mutated(path: str, old: str, new: str) -> dict[str, str]:
    assert old in GOOD[path], f"control: {old!r} is in the good text"
    return {**GOOD, path: GOOD[path].replace(old, new, 1)}


def _script(old: str, new: str) -> str:
    assert old in GOOD_SCRIPT, f"control: {old!r} is in the good script"
    return GOOD_SCRIPT.replace(old, new, 1)


SCRIPT_MUTATIONS = {
    "version-not-spelled-out": _script("bun-v${BUN_VERSION}/", "latest/"),
    "no-sha-check": _script('echo "${BUN_SHA256}  $work/bun.zip" | sha256sum -c -\n', ""),
    "sha-names-another-file": _script('  $work/bun.zip" | sha256sum', '  $work/other.zip" | sha256sum'),
    "checked-after-unpacking": _script(
        'echo "${BUN_SHA256}  $work/bun.zip" | sha256sum -c -\nunzip -q "$work/bun.zip" -d "$work"\n',
        'unzip -q "$work/bun.zip" -d "$work"\necho "${BUN_SHA256}  $work/bun.zip" | sha256sum -c -\n'),
    "no-named-download-file": _script('-o "$work/bun.zip" ', ""),
}

TEXT_MUTATIONS = {
    "a-job-downloads-bun-itself": {**GOOD, ".github/workflows/ci.yml": GOOD[".github/workflows/ci.yml"] + _INLINE},
    "the-image-downloads-bun-itself": _mutated(
        ".devcontainer/Dockerfile.dev", "RUN bun --version\n",
        'RUN curl -o /tmp/b.zip "https://github.com/oven-sh/bun/releases/download/bun-v1.4.3/x.zip"\nRUN bun --version\n'),
    "a-job-takes-bun-from-setup-bun": _mutated(
        ".github/workflows/ci.yml", "  lint:\n    runs-on: x\n    steps:\n" + _INSTALL,
        "  lint:\n    runs-on: x\n    steps:\n      - uses: oven-sh/setup-bun@v2\n" + _INSTALL),
    "a-job-runs-bun-without-the-script": {
        **GOOD, ".github/workflows/ci.yml": GOOD[".github/workflows/ci.yml"] + "  other:\n    runs-on: x\n    steps:\n" + _RUNS_BUN},
    "an-image-stage-runs-bun-installed-in-another-stage": {
        **GOOD, ".devcontainer/Dockerfile.dev": GOOD[".devcontainer/Dockerfile.dev"] + "FROM y\nRUN bun install\n"},
    "the-image-runs-the-script-without-copying-it": _mutated(
        ".devcontainer/Dockerfile.dev", "COPY tooling/install-bun.sh /tmp/install-bun.sh\n", ""),
    "only-one-job-runs-the-script": {**GOOD, ".github/workflows/ci.yml": GOOD[".github/workflows/ci.yml"].split("  lint:")[0]},
    "no-dev-image": {k: v for k, v in GOOD.items() if "Dockerfile" not in k},
}


def test_1540_f6_the_pin_check_accepts_a_good_script_and_good_sites():
    """Positive control for the mutations below. (F6)"""
    check_bun_comes_from_one_script(GOOD_SCRIPT, GOOD)


@pytest.mark.parametrize("script", SCRIPT_MUTATIONS.values(), ids=SCRIPT_MUTATIONS.keys())
def test_1540_f6_the_pin_check_refuses_each_break_of_the_script(script):
    """A version not spelled out, a missing or misdirected sha check, a check after unpacking, no named file. (F6)"""
    with pytest.raises(AssertionError):
        check_bun_comes_from_one_script(script, GOOD)


@pytest.mark.parametrize("texts", TEXT_MUTATIONS.values(), ids=TEXT_MUTATIONS.keys())
def test_1540_f6_the_pin_check_refuses_each_place_that_gets_bun_another_way(texts):
    """A second download (a job, an image), `setup-bun`, a job or image stage that runs `bun` without running the script
    itself, an image that runs it without copying it in, fewer than two jobs or no image running it. (F6)"""
    with pytest.raises(AssertionError):
        check_bun_comes_from_one_script(GOOD_SCRIPT, texts)

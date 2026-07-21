"""Site A-E fold contracts for #591 (spec_graph_591-frontmatter-fold.yaml).

Each folded reader (predicted_disposition / read_description + descriptor_catalog /
parse_report / check_skill / _strip_frontmatter) must route through the ONE
canonical grammar in defender/_frontmatter.py. Most tests here are RED against
HEAD — they fail on the OLD loose/hand-rolled behavior, on a missing seam, or on
a read that raises where the fold makes it fall back. That red is the point; it
goes green when the implementation lands.

Fixtures that carry CRLF or non-UTF8 bytes are written with ``write_bytes`` so
text-mode newline translation / decode cannot mask them.

Import conventions mirror the collected neighbors:
  - the hook + validate_scaffold are __main__ scripts -> importlib.spec_from_file_location
    (as tests/test_inject_system_skill_description.py loads the hook);
  - orient / held_out / visualize resolve through the ``defender.*`` namespace
    (as tests/test_orient.py and tests/test_visualize_runtime.py do);
  - evals/_pipeline + evals/secondary have no package __init__ and rely on a
    sys.path insert of evals/ -> importlib (as evals/test_secondary.py loads them).
"""
from __future__ import annotations

import importlib.util
import inspect
import sys
from pathlib import Path

from defender._frontmatter import parse_frontmatter_or_none
from defender.evals.held_out import predicted_disposition
from defender.learning.core.config import DISPOSITION_ENUM
from defender.runtime import orient
from defender.scripts.visualize import visualize_primitives as vp

DEFENDER = Path(__file__).resolve().parents[1]
WORKTREE = Path(__file__).resolve().parents[2]
_EVALS = DEFENDER / "evals"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None
    assert spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _hook():
    """A FRESH hook module — a fresh ``descriptor_catalog`` lru_cache per test."""
    return _load("inject591", DEFENDER / "hooks" / "inject_system_skill_description.py")


def _scaffold():
    return _load("vscaffold591", DEFENDER / "skills" / "connect" / "validate_scaffold.py")


def _load_pipeline():
    if str(_EVALS) not in sys.path:
        sys.path.insert(0, str(_EVALS))
    return _load("pipeline591", _EVALS / "_pipeline.py")


def _load_secondary():
    if str(_EVALS) not in sys.path:
        sys.path.insert(0, str(_EVALS))
    return _load("secondary591", _EVALS / "secondary.py")


def _report_run(tmp: Path, name: str, content: bytes) -> Path:
    r = tmp / name
    r.mkdir(parents=True, exist_ok=True)
    (r / "report.md").write_bytes(content)
    return r


def _skill(skills_dir: Path, system: str, content: bytes) -> None:
    d = skills_dir / system
    d.mkdir(parents=True, exist_ok=True)
    (d / "SKILL.md").write_bytes(content)


def _name_status(scaffold, defroot: Path, system: str) -> str:
    """The name-check outcome of check_skill: 'PASS', 'FAIL', or 'MISSING' — or the
    raised exception propagates (the pre-fold crash on unreadable bytes)."""
    rep = scaffold.Report()
    scaffold.check_skill(rep, defroot, system)
    for status, msg in rep.rows:
        if "frontmatter name" in msg:
            return status
        if "is missing" in msg:
            return "MISSING"
    return "NONE"


def _mk_scaffold_tree(tmp: Path, system: str, content: bytes) -> Path:
    """A minimal defender-dir with skills/<system>/{SKILL.md,execution.md}."""
    defroot = tmp / "def"
    sk = defroot / "skills" / system
    sk.mkdir(parents=True, exist_ok=True)
    (sk / "SKILL.md").write_bytes(content)
    (sk / "execution.md").write_text("## execution stub\n", encoding="utf-8")
    return defroot


def test_d0_predicted_disposition(tmp_path):
    assert predicted_disposition(
        _report_run(tmp_path, "ok", b"---\ndisposition: benign\n---\nbody\n")
    ) == "benign"
    assert predicted_disposition(tmp_path / "nope") is None
    assert predicted_disposition(
        _report_run(tmp_path, "junk", b"---disposition: benign\n...\n---\nbody\n")
    ) is None
    assert predicted_disposition(
        _report_run(tmp_path, "absent", b"---\ncase_id: x\n---\nbody\n")
    ) is None
    assert predicted_disposition(
        _report_run(tmp_path, "nonstr", b"---\ndisposition: 123\n---\nbody\n")
    ) is None
    assert predicted_disposition(
        _report_run(tmp_path, "nonenum", b"---\ndisposition: escalate\n---\nbody\n")
    ) is None
    assert predicted_disposition(
        _report_run(tmp_path, "nonutf8", b"---\ndisposition: benign\n---\n\xff\xfe\n")
    ) is None


def test_d0_read_description(tmp_path):
    skills = tmp_path / "skills"
    _skill(skills, "good", b"---\nname: defender-good\ndescription:   real desc  \n---\nbody\n")
    assert _hook().read_description("good", skills_dir=skills) == "real desc"
    assert _hook().read_description("absent", skills_dir=skills) is None
    assert _hook().read_description("../../secret", skills_dir=skills) is None
    _skill(skills, "unf", b"intro prose\n\n---\ndescription: BOGUS\n---\n\nmore\n")
    assert _hook().read_description("unf", skills_dir=skills) is None
    _skill(skills, "list", b"---\n- a\n- b\n---\nbody\n")
    assert _hook().read_description("list", skills_dir=skills) is None
    _skill(skills, "nodesc", b"---\nname: defender-nodesc\n---\nbody\n")
    assert _hook().read_description("nodesc", skills_dir=skills) is None
    _skill(skills, "intdesc", b"---\ndescription: 123\n---\nbody\n")
    assert _hook().read_description("intdesc", skills_dir=skills) is None
    _skill(skills, "wsdesc", b"---\ndescription: '   '\n---\nbody\n")
    assert _hook().read_description("wsdesc", skills_dir=skills) is None
    _skill(skills, "nb", b"---\ndescription: x\xff\xfey\n---\n")
    assert _hook().read_description("nb", skills_dir=skills) is None


def test_d0_descriptor_catalog_seam(tmp_path):
    hook = _hook()
    skills = tmp_path / "skills"
    adapters = tmp_path / "adapters"
    adapters.mkdir(parents=True)
    (adapters / "alpha_adapter.py").write_text("# adapter\nVERBS = {\"ping\": lambda ctx: {}}\n", encoding="utf-8")
    (adapters / "beta_adapter.py").write_text("# adapter\nVERBS = {\"ping\": lambda ctx: {}}\n", encoding="utf-8")
    _skill(skills, "alpha", b"---\nname: defender-alpha\ndescription: alpha desc\n---\nbody\n")
    _skill(skills, "beta", b"---\nname: defender-beta\n---\nbody\n")

    hook.descriptor_catalog.cache_clear()
    out = hook.descriptor_catalog(skills_dir=skills, adapters_dir=adapters)
    assert out == "- `alpha`: alpha desc"

    empty_adapters = tmp_path / "adapters2"
    empty_adapters.mkdir()
    (empty_adapters / "beta_adapter.py").write_text("# adapter\nVERBS = {\"ping\": lambda ctx: {}}\n", encoding="utf-8")
    hook.descriptor_catalog.cache_clear()
    assert hook.descriptor_catalog(skills_dir=skills, adapters_dir=empty_adapters) is None

    hook.descriptor_catalog.cache_clear()
    a = hook.descriptor_catalog(skills_dir=skills, adapters_dir=adapters)
    b = hook.descriptor_catalog(skills_dir=skills, adapters_dir=empty_adapters)
    assert a == "- `alpha`: alpha desc"
    assert b is None


def test_d0_parse_report(tmp_path):
    assert vp.parse_report(tmp_path / "nope") == {}
    assert vp.parse_report(
        _report_run(tmp_path, "nb", b"---\ndisposition: benign\n---\n\xff\xfe\n")
    ) == {}
    whole = b"---\ndisposition: [unterminated\n---\nbody text\n"
    assert vp.parse_report(_report_run(tmp_path, "mal", whole)) == {"body": whole.decode()}
    got = vp.parse_report(
        _report_run(tmp_path, "ok", b"---\ndisposition: benign\n---\n\n  body middle  \n\n")
    )
    assert got == {"disposition": "benign", "body": "body middle"}


def test_d0_check_skill(tmp_path):
    scaffold = _scaffold()
    assert _name_status(
        scaffold, _mk_scaffold_tree(tmp_path, "good", b"---\nname: defender-good\n---\n## Execution\n"),
        "good",
    ) == "PASS"
    defroot = tmp_path / "empty"
    (defroot / "skills" / "gone").mkdir(parents=True)
    assert _name_status(scaffold, defroot, "gone") == "MISSING"
    assert _name_status(
        scaffold, _mk_scaffold_tree(tmp_path, "unf", b"prose\nname: defender-unf\n"), "unf"
    ) == "FAIL"
    assert _name_status(
        scaffold, _mk_scaffold_tree(tmp_path, "nc", b"---\nname: defender-nc\nno closer\n"), "nc"
    ) == "FAIL"
    assert _name_status(
        scaffold, _mk_scaffold_tree(tmp_path, "lst", b"---\n- a\n- b\n---\n"), "lst"
    ) == "FAIL"
    assert _name_status(
        scaffold, _mk_scaffold_tree(tmp_path, "nn", b"---\nmap:\n  name: defender-nn\n---\n"), "nn"
    ) == "FAIL"
    assert _name_status(
        scaffold, _mk_scaffold_tree(tmp_path, "nb", b"---\nname: defender-nb\ndesc: x\xff\xfe\n---\n"), "nb"
    ) == "FAIL"


def test_d0_strip_frontmatter():
    assert orient._strip_frontmatter("---\ndescription: x\n---\nBODY\n") == "BODY"
    no_fence = "no fence here\nplain body\n"
    assert orient._strip_frontmatter(no_fence) == no_fence


def test_d_parity_grammar(tmp_path):
    """Over a shared corpus, predicted_disposition is non-None exactly when
    parse_frontmatter_or_none yields a mapping whose disposition is a str in the
    enum — so primary + secondary (which now call this same function) accept and
    reject identical documents by construction."""
    corpus = {
        "well-formed": b"---\ndisposition: benign\n---\nbody\n",
        "junk-opener": b"---disposition: benign\n...\n---\nbody\n",
        "trailing-space-opener": b"--- \ndisposition: benign\n---\nbody\n",
        "four-dash-opener": b"----\ndisposition: benign\n---\nbody\n",
        "crlf": b"---\r\ndisposition: benign\r\n---\r\nbody\r\n",
        "no-closer": b"---\ndisposition: benign\nbody no closer\n",
        "loose-closer": b"---\ndisposition: benign\n--- junk\nbody\n",
        "empty-mapping": b"---\n---\n",
        "non-mapping": b"---\n- a\n- b\n---\nbody\n",
        "second-fence-block": b"---\ndisposition: benign\n---\nbody\n---\nother: x\n---\n",
        "non-str-disposition": b"---\ndisposition: 123\n---\nbody\n",
        "non-enum-disposition": b"---\ndisposition: escalate\n---\nbody\n",
    }
    for label, content in corpus.items():
        run = _report_run(tmp_path, label, content)
        pred = predicted_disposition(run)
        fm = parse_frontmatter_or_none(content.decode("utf-8"))
        ref_disp = fm.get("disposition") if isinstance(fm, dict) else None
        ref_valid = isinstance(ref_disp, str) and ref_disp in DISPOSITION_ENUM
        assert (pred is not None) == ref_valid, label
        if ref_valid:
            assert pred == ref_disp, label


def test_d_read_head_removed():
    pipeline = _load_pipeline()
    assert not hasattr(pipeline, "read_head_disposition")
    sec = _load_secondary()
    assert hasattr(sec, "predicted_disposition")
    assert Path(inspect.getfile(sec.predicted_disposition)).name == "held_out.py"


def test_d_junk_opener_none(tmp_path):
    run = _report_run(tmp_path, "junk", b"---disposition: benign\n...\n---\nbody\n")
    assert predicted_disposition(run) is None


def test_d_crlf_report_parses(tmp_path):
    run = _report_run(tmp_path, "crlf", b"---\r\ndisposition: benign\r\n---\r\nbody\r\n")
    assert predicted_disposition(run) == "benign"


def test_d_non_enum_none(tmp_path):
    run = _report_run(tmp_path, "esc", b"---\ndisposition: escalate\n---\nbody\n")
    assert "escalate" not in DISPOSITION_ENUM
    assert predicted_disposition(run) is None


def test_d_non_utf8_report_none(tmp_path):
    run = _report_run(tmp_path, "nb", b"---\ndisposition: benign\n---\n\xff\xfe body\n")
    assert predicted_disposition(run) is None


def test_d_wellformed_report_unflipped(tmp_path):
    run = _report_run(tmp_path, "wf", b"---\ndisposition: benign\n---\nbody\n")
    assert predicted_disposition(run) == "benign"


def test_d_secondary_import_safe():
    sec = _load_secondary()
    assert sec.__name__ == "secondary591"
    assert callable(sec.main)


def test_d_unfenced_skill_none(tmp_path):
    """NEGATIVE: an unfenced SKILL.md with interior '---' thematic breaks around
    attacker text reaches neither read_description nor the descriptor_catalog.
    Positive control (same tree/address): a well-fenced sibling DOES surface."""
    hook = _hook()
    skills = tmp_path / "skills"
    adapters = tmp_path / "adapters"
    adapters.mkdir(parents=True)
    _skill(skills, "evil", b"intro prose no fence\n\n---\ndescription: BOGUS ATTACKER\n---\n\nmore\n")
    _skill(skills, "good", b"---\nname: defender-good\ndescription: real desc\n---\nbody\n")
    (adapters / "evil_adapter.py").write_text("# a\nVERBS = {\"ping\": lambda ctx: {}}\n", encoding="utf-8")
    (adapters / "good_adapter.py").write_text("# a\nVERBS = {\"ping\": lambda ctx: {}}\n", encoding="utf-8")

    assert hook.read_description("evil", skills_dir=skills) is None
    hook.descriptor_catalog.cache_clear()
    catalog = hook.descriptor_catalog(skills_dir=skills, adapters_dir=adapters) or ""
    assert "BOGUS" not in catalog
    assert "`evil`" not in catalog
    assert hook.read_description("good", skills_dir=skills) == "real desc"
    assert "- `good`: real desc" in catalog


def test_d_fenced_skill_desc(tmp_path):
    hook = _hook()
    skills = tmp_path / "skills"
    adapters = tmp_path / "adapters"
    adapters.mkdir(parents=True)
    _skill(skills, "good", b"---\nname: defender-good\ndescription: real desc\n---\nbody\n")
    (adapters / "good_adapter.py").write_text("# a\nVERBS = {\"ping\": lambda ctx: {}}\n", encoding="utf-8")
    assert hook.read_description("good", skills_dir=skills) == "real desc"
    hook.descriptor_catalog.cache_clear()
    assert hook.descriptor_catalog(skills_dir=skills, adapters_dir=adapters) == "- `good`: real desc"


def test_d_trailing_space_opener_none(tmp_path):
    hook = _hook()
    skills = tmp_path / "skills"
    _skill(skills, "tsp", b"--- \ndescription: tsp desc\n---\nbody\n")
    assert hook.read_description("tsp", skills_dir=skills) is None


def test_d_crlf_skill_gains_description(tmp_path):
    hook = _hook()
    skills = tmp_path / "skills"
    _skill(skills, "crlf", b"---\r\nname: defender-crlf\r\ndescription: crlf desc\r\n---\r\nbody\r\n")
    assert hook.read_description("crlf", skills_dir=skills) == "crlf desc"


def test_d_block_scalar_fence_truncation(tmp_path):
    hook = _hook()
    skills = tmp_path / "skills"
    _skill(skills, "un", b"---\ndescription: |\n  line one\n---\n  line two\n---\nbody\n")
    assert hook.read_description("un", skills_dir=skills) == "line one"
    _skill(skills, "ind", b"---\ndescription: |\n  line one\n  ---\n  line two\n---\nbody\n")
    assert hook.read_description("ind", skills_dir=skills) == "line one\n---\nline two"


def test_d_traversal_guard_regression(tmp_path):
    hook = _hook()
    skills = tmp_path / "skills"
    _skill(skills, "good", b"---\nname: defender-good\ndescription: real desc\n---\nbody\n")
    assert hook.read_description("../../secret", skills_dir=skills) is None
    assert hook.read_description("good", skills_dir=skills) == "real desc"


def test_d_non_utf8_skill_none(tmp_path):
    hook = _hook()
    skills = tmp_path / "skills"
    _skill(skills, "nb", b"---\nname: defender-nb\ndescription: x\xff\xfey\n---\nbody\n")
    assert hook.read_description("nb", skills_dir=skills) is None


def test_d_block_scalar_multiparagraph_green(tmp_path):
    hook = _hook()
    skills = tmp_path / "skills"
    _skill(
        skills, "mp",
        b"---\nname: defender-mp\ndescription: |\n"
        b"  First paragraph names the system.\n"
        b"\n"
        b"  Second paragraph carries a caveat.\n"
        b"---\nbody\n",
    )
    desc = hook.read_description("mp", skills_dir=skills)
    assert desc is not None
    assert "First paragraph names the system." in desc
    assert "Second paragraph carries a caveat." in desc


def test_d_catalog_survival():
    hook = _hook()
    hook.descriptor_catalog.cache_clear()
    out = hook.descriptor_catalog()
    assert out is not None
    adapters_dir = DEFENDER / "scripts" / "adapters"
    systems = sorted(
        p.name[: -len("_adapter.py")].replace("_", "-")
        for p in adapters_dir.glob("*_adapter.py")
    )
    assert systems
    lines = out.splitlines()
    assert len(lines) == len(systems)
    assert "- `elastic`:" in out


def test_d_malformed_yaml_collapse(tmp_path):
    whole = b"---\ndisposition: [unterminated\n---\nbody text\n"
    got = vp.parse_report(_report_run(tmp_path, "mal", whole))
    assert got == {"body": whole.decode()}
    ok = vp.parse_report(_report_run(tmp_path, "ok", b"---\ndisposition: benign\n---\nbody\n"))
    assert ok.get("disposition") == "benign"


def test_d_non_mapping_collapse(tmp_path):
    whole = b"---\n- a\n- b\n---\nbody\n"
    got = vp.parse_report(_report_run(tmp_path, "lst", whole))
    assert got == {"body": whole.decode()}


def test_d_crlf_viewer_fix(tmp_path):
    got = vp.parse_report(_report_run(tmp_path, "crlf", b"---\r\ndisposition: benign\r\n---\r\nbody\r\n"))
    assert got.get("disposition") == "benign"
    assert got.get("body") is not None


def test_d_parse_report_body_strip(tmp_path):
    got = vp.parse_report(
        _report_run(tmp_path, "wf", b"---\ndisposition: benign\n---\n\nbody with trailing  \n\n")
    )
    assert got["body"] == "body with trailing"


def test_d_no_closer_fail(tmp_path):
    scaffold = _scaffold()
    defroot = _mk_scaffold_tree(tmp_path, "nc", b"---\nname: defender-nc\nno closing fence here\n")
    assert _name_status(scaffold, defroot, "nc") == "FAIL"
    ok = _mk_scaffold_tree(tmp_path, "okc", b"---\nname: defender-okc\n---\n## Execution\n")
    assert _name_status(scaffold, ok, "okc") == "PASS"


def test_d_nested_name_fail(tmp_path):
    scaffold = _scaffold()
    defroot = _mk_scaffold_tree(tmp_path, "nn", b"---\nmap:\n  name: defender-nn\n---\nbody\n")
    assert _name_status(scaffold, defroot, "nn") == "FAIL"


def test_d_uniform_indent_name_pass(tmp_path):
    scaffold = _scaffold()
    defroot = _mk_scaffold_tree(tmp_path, "ui", b"---\n  name: defender-ui\n---\nbody\n")
    assert _name_status(scaffold, defroot, "ui") == "PASS"


def test_d_scaffold_wellformed_pass(tmp_path):
    scaffold = _scaffold()
    defroot = _mk_scaffold_tree(
        tmp_path, "foo", b"---\nname: defender-foo\n---\n## Execution pointer\n"
    )
    assert _name_status(scaffold, defroot, "foo") == "PASS"


def test_d_unreadable_skill_fail_row(tmp_path):
    scaffold = _scaffold()
    nb = _mk_scaffold_tree(tmp_path, "nb", b"---\nname: defender-nb\ndesc: x\xff\xfe\n---\n")
    assert _name_status(scaffold, nb, "nb") == "FAIL"
    defroot = tmp_path / "missing"
    (defroot / "skills" / "gone").mkdir(parents=True)
    assert _name_status(scaffold, defroot, "gone") == "MISSING"


def test_d_closer_at_eof_strips():
    stripped = orient._strip_frontmatter("---\ndescription: x\n---")
    assert "---" not in stripped
    assert "description" not in stripped
    assert orient._strip_frontmatter("---\ndescription: x\n---\nBODY\n") == "BODY"


def test_d_no_fence_unchanged():
    no_fence = "no leading fence\njust body\n"
    assert orient._strip_frontmatter(no_fence) == no_fence
    empty_mapping = "---\n---\n"
    assert orient._strip_frontmatter(empty_mapping) == empty_mapping

"""Tests for the lint_scrub_order gate: the lifecycle scrubs before any reader of the run folder, no
handler swallows the taint signal, and the bash tool has no in-process fallback."""
from __future__ import annotations

from pathlib import Path

import pytest

from _by_path import load_lint_gate

_GATE = load_lint_gate("lint_scrub_order")

# #1342 M3: `main` and `job_main` are compositions; each calls the lifecycle, then the shared
# post-steps phase, which alone holds the readers of the scrubbed folder. The ticket comment and
# the curation enqueue stay in the operator composition, after the lifecycle.
_MAIN = (
    "def main():\n"
    "    summary = lifecycle()\n"
    "    _post_steps(summary)\n"
    "    ticket_writer.record_case_ticket()\n"
    "    enqueue_curation()\n"
    "def job_main():\n"
    "    summary = lifecycle()\n"
    "    _post_steps(summary)\n"
    "def _post_steps(summary):\n"
    "    run_dir.iterdir()\n"
    "    _run.cross_check_tables(run_dir)\n"
    "    visualize()\n"
    "def _run_investigation_lifecycle():\n"
    "    try:\n"
    "        pass\n"
    "    except ValueError:\n"
    "        pass\n")
_BASH = "def _tool_bash():\n    return runner.run_parsed(cmd)\n"


def _tree(tmp_path: Path, run: str = _MAIN, bash: str = _BASH) -> Path:
    root = tmp_path / "defender"
    (root / "investigation/tools").mkdir(parents=True)
    (root / "run.py").write_text(run, encoding="utf-8")
    (root / "investigation/tools/_bash.py").write_text(bash, encoding="utf-8")
    return root


def test_a_clean_tree_has_no_findings(tmp_path):
    assert _GATE.scan(_tree(tmp_path)) == []


@pytest.mark.parametrize("composition", ["main", "job_main"])
def test_the_post_steps_before_the_lifecycle_is_found(tmp_path, composition):
    head = f"def {composition}():\n    summary = lifecycle()\n    _post_steps(summary)\n"
    swapped = f"def {composition}():\n    _post_steps(None)\n    summary = lifecycle()\n"
    found = _GATE.scan(_tree(tmp_path, run=_MAIN.replace(head, swapped)))
    assert len(found) == 1, found
    assert composition in found[0], found
    assert "_post_steps" in found[0], found


@pytest.mark.parametrize("composition", ["main", "job_main"])
@pytest.mark.parametrize("reader", ["run_dir.iterdir()", "_run.cross_check_tables(run_dir)", "visualize()"])
def test_a_reader_called_from_a_composition_instead_of_the_post_steps_is_found(tmp_path, composition, reader):
    marker = f"def {composition}():\n    summary = lifecycle()\n"
    run = _MAIN.replace(marker, marker + f"    {reader}\n")
    found = _GATE.scan(_tree(tmp_path, run=run))
    assert len(found) == 1, found
    assert composition in found[0], found


_READER_CALLS = {"iterdir": "run_dir.iterdir()", "cross_check_tables": "_run.cross_check_tables(run_dir)",
                 "visualize": "visualize()"}


@pytest.mark.parametrize("reader", sorted(_READER_CALLS))
def test_a_post_steps_that_loses_a_reader_is_a_finding(tmp_path, reader):
    """`_post_steps` must itself call each reader; moving one behind a helper leaves a finding naming it. (M3)"""
    assert _GATE.scan(_tree(tmp_path / "clean")) == [], "control: the unchanged tree is clean"
    call = _READER_CALLS[reader]
    assert f"    {call}\n" in _MAIN, "premise: the fixture's post-steps makes the call"
    run = _MAIN.replace(f"    {call}\n", "    _helper()\n")
    found = _GATE.scan(_tree(tmp_path / "cut", run=run))
    assert any("_post_steps" in f and reader in f for f in found), found


@pytest.mark.parametrize("reader", sorted(_READER_CALLS))
@pytest.mark.parametrize("home", ["def _page(started):\n    {call}\n",
                                  "class Steps:\n    def page(self):\n        {call}\n"],
                         ids=["helper function", "method"])
def test_any_function_other_than_the_post_steps_calling_a_reader_is_a_finding(tmp_path, reader, home):
    """A reader called from any other `run.py` function (a helper the compositions reach) is found, wherever it sits. (M3)"""
    call = _READER_CALLS[reader]
    run = _MAIN + home.format(call=call)
    found = _GATE.scan(_tree(tmp_path, run=run))
    assert any(reader in f for f in found), found
    assert _GATE.scan(_tree(tmp_path / "clean")) == [], "control: without the helper the tree is clean"


_REFS = {"iterdir": "run_dir.iterdir", "cross_check_tables": "_run.cross_check_tables", "visualize": "visualize"}
_FORMS = {  # (where, source with {r} the reader and {ref} a reference to it)
    "getattr string": ("body", 'getattr(_run, "{r}")(run_dir)'),
    "alias": ("body", "f = {ref}"),
    "partial": ("body", "functools.partial({ref}, run_dir)"),
    "lambda in a composition": ("body", "g = lambda: {ref}()"),
    "module-scope lambda": ("module", "L = lambda: {ref}()"),
    "module-scope call": ("module", "{ref}()"),
    "class body": ("module", "class Steps:\n    x = {ref}()"),
}


def _with(form: str, reader: str) -> str:
    """`_MAIN` with one reference to `reader` in `form`: inside `job_main`, or at module level."""
    where, source = _FORMS[form]
    text = source.format(r=reader, ref=_REFS[reader])
    marker = "def job_main():\n    summary = lifecycle()\n"
    if where == "body":
        return _MAIN.replace(marker, marker + f"    {text}\n", 1)
    return _MAIN + text + "\n"


@pytest.mark.parametrize("reader", sorted(_REFS))
@pytest.mark.parametrize("form", sorted(_FORMS))
def test_a_reference_to_a_reader_in_any_form_outside_the_post_steps_is_a_finding(tmp_path, form, reader):
    """A reader named outside `_post_steps` as an alias, string, `partial`, lambda or class body is found, not only a direct call. (M3)"""
    assert _GATE.scan(_tree(tmp_path / "clean")) == [], "control: the unchanged tree is clean"
    found = _GATE.scan(_tree(tmp_path / "cut", run=_with(form, reader)))
    assert any(reader in f for f in found), found
    if _FORMS[form][0] == "body":
        assert any("job_main" in f for f in found), found


_LISTINGS = ["os.listdir(run_dir)", "os.scandir(run_dir)", "os.walk(run_dir)", "glob.glob(pattern)",
             "run_dir.glob('*')", "run_dir.rglob('*')", "[*map(g, [1])] if (g := glob.iglob) else 0"]


@pytest.mark.parametrize("listing", _LISTINGS)
@pytest.mark.parametrize("where", ["a composition", "a helper", "the module"])
def test_another_way_to_list_the_folder_outside_the_post_steps_is_a_finding(tmp_path, listing, where):
    """`os.listdir`, `scandir`, `walk` or a `glob` in place of `iterdir` is the listing reader and lives only in `_post_steps`. (M3)"""
    marker = "def job_main():\n    summary = lifecycle()\n"
    run = {"a composition": _MAIN.replace(marker, marker + f"    {listing}\n", 1),
           "a helper": _MAIN + f"def _page(started):\n    {listing}\n",
           "the module": _MAIN + f"{listing}\n"}[where]
    found = _GATE.scan(_tree(tmp_path, run=run))
    assert found, f"{listing} in {where} passed"


@pytest.mark.parametrize("statement", ["from os import listdir", "from glob import glob as find",
                                       "from run_common import cross_check_tables as check",
                                       "from run_common import visualize"])
def test_importing_a_reader_into_run_py_is_a_finding(tmp_path, statement):
    """A reader imported by name into `run.py` is a reference outside `_post_steps`, whatever it is bound to. (M3)"""
    found = _GATE.scan(_tree(tmp_path, run=statement + "\n" + _MAIN))
    assert found, found


def test_the_page_render_seam_handed_to_the_post_steps_is_the_one_allowed_reference(tmp_path):
    """A `visualize` parameter defaulting to the reader and `visualize=visualize` passed to `_post_steps` are clean. (M3)"""
    seamed = (_MAIN.replace("def main():", "def main(visualize=_run.visualize):")
              .replace("def job_main():", "def job_main(*, visualize=_run.visualize):")
              .replace("_post_steps(summary)\n", "_post_steps(summary, visualize=visualize)\n"))
    assert "visualize=visualize" in seamed, "premise: the fixture hands the seam on"
    assert _GATE.scan(_tree(tmp_path, run=seamed)) == []


@pytest.mark.parametrize("handed", ["other(visualize=visualize)", "other(visualize)", "v = visualize"])
def test_the_page_render_seam_handed_anywhere_but_the_post_steps_is_a_finding(tmp_path, handed):
    """The seam passed on to anything but `_post_steps` is a reference to the reader and is found. (M3)"""
    seamed = (_MAIN.replace("def job_main():\n    summary = lifecycle()\n",
                            f"def job_main(visualize=_run.visualize):\n    summary = lifecycle()\n    {handed}\n"))
    found = _GATE.scan(_tree(tmp_path, run=seamed))
    assert any("visualize" in f and "job_main" in f for f in found), found


def test_a_reader_before_the_lifecycle_is_found(tmp_path):
    run = _MAIN.replace("def main():\n    summary = lifecycle()", "def main():\n    enqueue_curation()\n    summary = lifecycle()")
    found = _GATE.scan(_tree(tmp_path, run=run))
    assert len(found) == 1, found
    assert "enqueue_curation" in found[0], found


@pytest.mark.parametrize(("composition", "name"), [
    ("job_main", "lifecycle"), ("job_main", "_post_steps"),
    ("main", "lifecycle"), ("main", "_post_steps"), ("main", "record_case_ticket"), ("main", "enqueue_curation"),
])
def test_a_vanished_call_in_a_composition_is_a_finding_not_a_pass(tmp_path, composition, name):
    start = _MAIN.index(f"def {composition}():\n")
    end = _MAIN.index("def ", start + 1)
    body = _MAIN[start:end]
    assert name + "(" in body, "premise: the composition makes the call"
    run = _MAIN[:start] + body.replace(name + "(", "other(") + _MAIN[end:]
    assert _GATE.scan(_tree(tmp_path / "clean", run=_MAIN)) == [], "control: the unchanged composition is clean"
    assert any(composition in f and name in f for f in _GATE.scan(_tree(tmp_path / "cut", run=run)))


def test_a_missing_job_main_or_post_steps_is_a_finding(tmp_path):
    without_job = _MAIN.replace("def job_main():\n    summary = lifecycle()\n    _post_steps(summary)\n", "")
    without_steps = _MAIN.replace("def _post_steps(summary):", "def _renamed(summary):")
    assert any("job_main" in f for f in _GATE.scan(_tree(tmp_path / "a", run=without_job)))
    assert any("_post_steps" in f for f in _GATE.scan(_tree(tmp_path / "b", run=without_steps)))


@pytest.mark.parametrize("function", ["main", "job_main", "_post_steps", "_run_investigation_lifecycle"])
@pytest.mark.parametrize("handler", ["RunTainted", "Exception", "BaseException",
                                     "(OSError, Exception)", "errors.RunTainted"])
def test_a_handler_that_swallows_the_taint_is_found(tmp_path, function, handler):
    guarded = f"    try:\n        pass\n    except {handler}:\n        pass\n"
    run = _plant_handler(function, guarded)
    found = _GATE.scan(_tree(tmp_path, run=run))
    assert len(found) == 1, found
    assert "swallow" in found[0], found
    assert function in found[0], found


@pytest.mark.parametrize("function", ["main", "job_main", "_post_steps"])
def test_a_bare_except_is_found(tmp_path, function):
    run = _plant_handler(function, "    try:\n        pass\n    except:\n        pass\n")
    found = _GATE.scan(_tree(tmp_path, run=run))
    assert len(found) == 1, found
    assert "bare" in found[0], found


@pytest.mark.parametrize("function", ["main", "job_main", "_post_steps"])
def test_a_handler_for_an_unrelated_error_is_not_a_finding(tmp_path, function):
    run = _plant_handler(function, "    try:\n        pass\n    except ValueError:\n        pass\n")
    assert _GATE.scan(_tree(tmp_path, run=run)) == []


@pytest.mark.parametrize("function", ["main", "job_main", "_post_steps", "_run_investigation_lifecycle"])
@pytest.mark.parametrize("context", ["contextlib.suppress(RunTainted)", "contextlib.suppress(errors.RunTainted)",
                                     "suppress(*errors)", "contextlib.suppress(Exception)"])
def test_a_with_that_suppresses_the_taint_is_found(tmp_path, function, context):
    """`contextlib.suppress` ends the taint signal without an `except`: a `with` naming it or a swallower is found. (M3)"""
    run = _plant_handler(function, f"    with {context}:\n        pass\n")
    found = _GATE.scan(_tree(tmp_path, run=run))
    assert len(found) == 1, found
    assert "swallow" in found[0], found
    assert function in found[0], found


@pytest.mark.parametrize("function", ["main", "job_main", "_post_steps"])
def test_a_with_for_something_else_is_not_a_finding(tmp_path, function):
    run = _plant_handler(function, "    with contextlib.nullcontext():\n        pass\n")
    assert _GATE.scan(_tree(tmp_path, run=run)) == []


_SECOND = {
    "def": "def {name}():\n    pass\n",
    "assignment": "{name} = other\n",
    "annotated assignment": "{name}: object = other\n",
    "import": "from elsewhere import other as {name}\n",
    "class": "class {name}:\n    pass\n",
    "for target": "for {name} in other:\n    pass\n",
}


@pytest.mark.parametrize("name", ["main", "job_main", "_post_steps", "_run_investigation_lifecycle"])
@pytest.mark.parametrize("form", sorted(_SECOND))
def test_a_second_binding_of_a_composition_or_phase_name_is_a_finding(tmp_path, name, form):
    """Each of the four functions is bound once in `run.py`; a later `def`, assignment, import or class shadows the one read. (M3)"""
    assert _GATE.scan(_tree(tmp_path / "clean")) == [], "control: the unchanged tree is clean"
    run = _MAIN + _SECOND[form].format(name=name)
    found = _GATE.scan(_tree(tmp_path / "cut", run=run))
    assert any(f"`{name}` is bound 2 times" in f for f in found), found


def _plant_handler(function: str, block: str) -> str:
    """`_MAIN` with `block` added at the end of `function`'s body."""
    if function == "_run_investigation_lifecycle":
        return _MAIN.replace("    try:\n        pass\n    except ValueError:\n        pass\n", block)
    marker = {"main": "    enqueue_curation()\n", "job_main": "def job_main():\n    summary = lifecycle()\n    _post_steps(summary)\n",
              "_post_steps": "    visualize()\n"}[function]
    return _MAIN.replace(marker, marker + block, 1)


def test_the_bash_tool_calling_the_in_process_executor_is_found(tmp_path):
    bash = "def _tool_bash():\n    return bash_exec.run_parsed(cmd)\n"
    found = _GATE.scan(_tree(tmp_path, bash=bash))
    assert len(found) == 1, found
    assert "in-process" in found[0], found


def test_a_missing_function_is_a_finding(tmp_path):
    found = _GATE.scan(_tree(tmp_path, bash="x = 1\n"))
    assert any("_tool_bash" in f for f in found), found


def test_a_file_that_does_not_parse_is_exit_2(tmp_path):
    assert _GATE.main(["--root", str(_tree(tmp_path, run="def (:\n"))]) == 2

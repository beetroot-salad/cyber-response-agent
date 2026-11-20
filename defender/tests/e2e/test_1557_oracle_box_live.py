"""#1557 O1, O2 (operator lane): the oracle's box against a real Docker daemon. Its saved reads are readable from the
scratch folder it runs in; a write there fails (the mount is read-only); a write under `/tmp` succeeds.

The job lane's box is the same `start_oracle_box` with the helper's folders (`job_host/_learning.py:_oracle_box`);
its folders (`.job-scratch/<claim>/shared/`) and mount shape are pinned in `tests/jobs/test_job_helper_learning.py`
(`test_1557_*`) under the docker stand-in."""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from _box665 import requires_live_box  # noqa: E402

from defender.tests.support.shared.contracts._data_root_1078 import current_data_root
from defender.tests.support.tenancy._host1214 import TEST_TENANT

pytestmark = [pytest.mark.e2e, pytest.mark.live, requires_live_box]

#: Prints the index and the named read the host saved, then tries a write in the current folder and one under `/tmp`.
CODE = """
import json, os
index = json.load(open("inputs/index.json"))
base = json.load(open("inputs/" + index["base"]))
outcome = {"index": index, "base": base}
try:
    with open("work.json", "w") as f:
        f.write("{}")
    outcome["scratch_write"] = "ok"
except OSError as e:
    outcome["scratch_write"] = type(e).__name__
try:
    os.makedirs("/tmp/mine", exist_ok=True)
    with open("/tmp/mine/work.json", "w") as f:
        f.write("{}")
    outcome["tmp_write"] = open("/tmp/mine/work.json").read()
except OSError as e:
    outcome["tmp_write"] = type(e).__name__
print(json.dumps(outcome))
"""


def test_1557_o1_o2_the_oracles_code_reads_its_saved_reads_cannot_write_its_scratch_and_can_write_tmp(tmp_path):
    """O2: code run in the oracle's box, in its scratch folder, prints `inputs/index.json` and the read it names. O1: a
    write in that folder fails and leaves nothing on the host; a write under `/tmp` succeeds."""
    from defender import box as box_mod
    from defender.execution.bash_exec import Pipeline, Stage

    env = {"PATH": os.environ["PATH"], "DEFENDER_BOX_RUNTIME": os.environ.get("DEFENDER_BOX_RUNTIME", "runc")}
    # `folder=` (the job lane's shape) rather than host /tmp: a devcontainer whose daemon does not share /tmp needs the
    # run's --basetemp on a shared path.
    oracle = box_mod.start_oracle_box(env=env, tenant_id=TEST_TENANT, data_root=current_data_root(), folder=tmp_path)
    try:
        scratch = Path(oracle.scratch)
        (scratch / "inputs").mkdir()
        index = {"base": "base-0001.json", "against": "base-0001.json", "frozen": None, "reads": [], "servings": []}
        (scratch / "inputs" / "index.json").write_text(json.dumps(index), encoding="utf-8")
        (scratch / "inputs" / "base-0001.json").write_text(json.dumps({"rows": [{"user": "alice"}]}), encoding="utf-8")

        result = oracle.run_parsed([Pipeline("first", [Stage(["python3", "-c", CODE])])], command="python",
                                   cwd=scratch, timeout=60.0)

        assert result.rc == 0, result
        printed = json.loads(result.out)
        assert printed["index"] == index, "O2: the code did not read the saved index"
        assert printed["base"] == {"rows": [{"user": "alice"}]}, "O2: the code did not read the read the index names"
        assert printed["scratch_write"] != "ok", "O1: the oracle's code wrote into its scratch folder"
        assert not (scratch / "work.json").exists(), "O1: a file the box wrote is on the host"
        assert printed["tmp_write"] == "{}", f"O1: a write under /tmp failed: {printed['tmp_write']}"
    finally:
        box_mod.stop_oracle_box(oracle)

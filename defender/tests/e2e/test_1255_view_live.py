"""#1255 slice B — what only a real box shows (design rev 4: "A gated live test covers what only a
real box shows: the shims' environment and `/proc/self/mountinfo`").

`live`-marked (deselected in CI by `-m "not live"`, per the dossier) and skipped without a native
daemon (`_box665.requires_live_box`). Each test starts the run box through the real `start_box`
for a natural run made under a set-up tenant, and asks the box itself — `box.run_parsed`, the
executor's own transport, below the permission gate on purpose: the gate is not what is being
observed here.

U1 (does gVisor's mountinfo show host bind sources?) is a RESIDUAL in the design, not an
obligation: it is held by the read scope (G10, `test_1255_view_replay::
test_b2_g10_proc_stays_outside_read_scope`). The U1 test therefore asserts what the design does
promise (the mount POINTS are the model view) and RECORDS whether host sources show, as a
`record_property` and a warning, without failing on it.
"""
from __future__ import annotations

import re
import warnings
from pathlib import Path

import pytest

from _box665 import requires_live_box  # noqa: E402

from defender.run_repository import RUN_LAYOUT  # noqa: E402
from defender.runtime import bash_exec  # noqa: E402
from defender.runtime import box as box_mod  # noqa: E402
from defender.tests import _1255_view as V  # noqa: E402

pytestmark = [pytest.mark.e2e, pytest.mark.live, requires_live_box]

ALERT = (Path(__file__).resolve().parents[2] / "fixtures-e2e" / "golden-sshpivot-ab3"
         / "alert.json").read_bytes()
EXEC_TIMEOUT = 60.0


def _in_box(box, command: str) -> tuple[int, str, str]:
    res = box.run_parsed(bash_exec.parse(command), command=command, cwd=Path(V.MODEL_RUN),
                         timeout=EXEC_TIMEOUT)
    return res.rc, res.out.decode("utf-8", "replace"), res.err.decode("utf-8", "replace")


def _real_box(tmp_path: Path, run_id: str):
    layout = V.make_layout(tmp_path / "a", V.TENANT_A)
    run_dir = V.natural_run(layout, ALERT, run_id)
    box = box_mod.start_box(run_dir, layout.checkout, docker=box_mod._docker,
                            tenant_agent=layout.agent, tenant_id=layout.tenant.id)
    return layout, run_dir, box


def test_b8_live_the_shims_environment_in_a_real_box_is_the_model_view(tmp_path):
    """P1 / O3, live: inside a real box, the environment every program (every shim) runs under
    carries `DEFENDER_RUN_DIR=/runs/current`, `DEFENDER_RUNS_BASE=/runs`, `DEFENDER_DIR=/defender`,
    `DEFENDER_AGENT_DIR=/agent`, and no value names the data root, the tenant, the checkout or
    the home. The run's alert is at its model path (`cat` succeeds, control), and invlang's corpus
    walk over `/runs` scans exactly the one mounted run (H2)."""
    layout, run_dir, box = _real_box(tmp_path, "20261015t120000z-view-live-env")
    try:
        rc, out, err = _in_box(box, "env")
        assert rc == 0, err
        env = dict(line.partition("=")[::2] for line in out.splitlines() if "=" in line)
        for key, value in V.MODEL_ENV.items():
            assert env.get(key) == value, f"{key}={env.get(key)!r} in the box, expected {value!r}"
        hits = V.scan(out, V.host_tokens(layout))
        assert not hits, "the box's environment shows host layout:\n" + "\n".join(hits)

        rc, out, err = _in_box(box, f"cat {V.MODEL_ALERT}")
        assert rc == 0, (rc, err[:300])
        assert "v2-cross-tier-ssh-pivot" in out, (rc, err[:300])

        rc, out, err = _in_box(box, "defender-invlang sequence")
        m = re.search(r"loaded (\d+)/(\d+) cases", err)
        assert m, f"control: the shim ran and reported its load: rc={rc} {err[:500]}"
        assert m.group(2) == "1", f"invlang scanned {m.group(2)} case folders in the box"
    finally:
        box_mod.stop_box(box)


def test_b8_live_u1_the_mount_points_are_the_model_view_and_sources_are_recorded(
    tmp_path, record_property,
):
    """P1 (Box bullet), live: the box's own mount table has its binds at `/runs/current`,
    `/runs/current/alert_input`, `/defender` and `/agent`, and at no host path of this layout.
    U1 (residual): whether the table's SOURCE column shows host paths under this runtime is
    recorded (`u1_host_sources_visible`) and warned about, not failed on — `/proc` stays outside
    every agent's read scope (G10), which is the holding control."""
    layout, run_dir, box = _real_box(tmp_path, "20261015t120000z-view-live-u1")
    try:
        rc, out, err = _in_box(box, "cat /proc/self/mountinfo")
        assert rc == 0, err
        points = {line.split()[4] for line in out.splitlines() if len(line.split()) > 4}
        for point in (V.MODEL_RUN, f"{V.MODEL_RUN}/{RUN_LAYOUT.alert_input_dir}",
                      V.MODEL_DEFENDER, V.MODEL_AGENT):
            assert point in points, f"no mount at {point}: {sorted(points)}"
        assert str(run_dir) not in points, sorted(points)
        assert str(layout.checkout) not in points, sorted(points)

        sources = V.scan(out, V.host_tokens(layout))
        record_property("u1_runtime", box.spec.runtime)
        record_property("u1_host_sources_visible", bool(sources))
        if sources:
            warnings.warn(
                f"U1 under {box.spec.runtime}: /proc/self/mountinfo shows host bind sources "
                f"({len(sources)} hits) — held only by the read scope (G10)", stacklevel=1)
    finally:
        box_mod.stop_box(box)

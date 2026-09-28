"""The post-run page step's one failure type, in a stdlib-only leaf (#1110).

Both sides name it without importing each other: the renderer (`visualize_run.publish_page`)
raises it, and `run_common.visualize` raises it when the renderer cannot even be loaded — so it
cannot live in the module whose loading is what failed.
"""
from __future__ import annotations


class VisualizeFailed(Exception):
    """This render did not save the run's page as its record — the renderer could not be
    loaded, the render failed, or the record write failed; the message says which, and the cause
    is chained. A page left over from a prior render is not proof this one succeeded. Never
    raised for the dev-only copy: a record that was written is a rendered run, whatever became
    of the copy."""

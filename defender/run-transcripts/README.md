# Run transcripts

Snapshots of defender runs preserved in-tree for review. Live runs land
in `/tmp/defender-runs/{run_id}/` (see `defender/run_artifacts.md`); a
copy lands here when a run is worth pinning to history — first pilot,
representative regression cases, anything we want a PR reviewer to be
able to open without rerunning.

`transcript.html` is the entry point — open it in a browser to see the
phase-by-phase agent transcript alongside the run artifacts.

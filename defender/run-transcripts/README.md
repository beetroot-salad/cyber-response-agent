# Run transcripts

Snapshots of defender runs preserved in-tree for review. Live runs land
in `/tmp/defender-runs/{run_id}/` (see `defender/CLAUDE.md` §Run dir layout); a
copy lands here when a run is worth pinning to history — representative
regression cases, anything we want a PR reviewer to be able to open
without rerunning.

`pilot-*/` directories are gitignored — those are scratch. Pin a run
under a non-pilot name (or `git add -f`) when it's worth keeping.

`transcript.html` is the entry point — open it in a browser to see the
phase-by-phase agent transcript alongside the run artifacts.

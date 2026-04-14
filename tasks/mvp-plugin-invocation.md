---
title: Wire up investigate as actual Claude Code plugin invocation
status: done
groups: mvp
---

`playground/scripts/eval_run.sh` loads the plugin via `--plugin-dir "$PLUGIN_DIR"` and invokes it as `/investigate $SIGNATURE_ID '$ALERT_JSON'`. All hook firing order, plugin.json manifest loading, and MCP config are exercised end-to-end on every eval run.

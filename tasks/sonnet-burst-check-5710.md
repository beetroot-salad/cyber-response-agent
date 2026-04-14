---
title: Forward-looking burst check on 5710 screen indicator
status: backlog
groups: sonnet
---

The attempt_count_5min indicator in wazuh-rule-5710/playbook.md is backward-looking only ("5 minutes PRECEDING the alert"). For the first alert of a burst, the preceding window is empty so count=1 passes the screen — subsequent burst attempts never get queried.

Add a second indicator: attempts_from_source_60s_after <= 0 (forward-looking), so a burst's first alert correctly fails the screen.

Low priority but worth doing before the next Sonnet-main eval cycle on bait-shape scenarios.

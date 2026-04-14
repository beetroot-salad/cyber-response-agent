---
title: Analytics suite — high-volume alert detection, fatigue metrics, auto-close tracking
status: backlog
groups: phase-2
---

High-volume alert detection: track alert frequency per signature over time windows.

Open question: should this live at the SIEM level (correlation rules) or the application level? Probably SIEM correlation rules — they have the raw stream and temporal operators.

Consider: alert fatigue metrics, auto-close rate tracking, escalation patterns across signatures.

---
name: environment
description: Org-specific deployment knowledge — classification heuristics, data source mappings, and system-specific query patterns. Load when you need to find where data lives or how to interpret entities in this org.
---

# Environment Knowledge

Org-specific knowledge that complements the portable methodology in `common/`. This layer captures how *this* organization's infrastructure is set up.

## Subdirectories

### context/
Classification heuristics for IPs, identities, data sensitivity, and system criticality. Use as fallbacks when external system lookups are unavailable.

### data-sources/
Maps data needs to available systems — both state lookups ("what IS this entity?") and event queries ("what DID this entity do?"). Start here when a lead needs data.

### operations/
Queryable lookups against external authorities — primarily trust anchors that confirm whether an observed activity is sanctioned. Load when an investigation needs to confirm legitimacy instead of deriving it from telemetry alone.

### systems/
System-specific implementation knowledge: query patterns, field mappings, and known quirks. Currently includes Wazuh; add directories for other tools as they are integrated.

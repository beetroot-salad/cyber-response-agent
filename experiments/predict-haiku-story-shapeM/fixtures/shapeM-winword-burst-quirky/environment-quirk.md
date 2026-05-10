# Environment quirk — legal-team e-discovery addin

This file is a synthesized environment-knowledge layer for the experiment fixture. It is dispatched to the PREDICT prompt as `<environment-context>` for arms that include env context (`current`, `proposed-A`). Stripped from arm `proposed-B`.

## Identity patterns

- `DOMAIN\ksilva` — legal-team identity. Member of the `LegalSupport-EvLoader-Users` AD group. Workstation `WIN-DEV-3211` is provisioned from the legal-team golden image.

## Workload manifest — EvidenceLoader

The org runs a 3rd-party Word addin called **EvidenceLoader** for legal-team identities. It is deployed via the Word startup folder by the `EvidenceLoader-Deploy` Intune package (rolled out 2025-Q4) and is active on every legal-team workstation.

Recurring runtime shape, established by 90-day baseline on legal-team hosts:

- Spawned by `WINWORD.EXE` when a user opens a `.docm` from the case-management share `\\legal-fs01\Cases\`.
- Per case-folder iteration, EvidenceLoader spawns helper child processes — typically 80–250 child processes per 5-min window per case load.
- Child images follow the pattern `EvLoader-{caseid}-{step}.exe` where `{caseid}` is 6 hex chars and `{step}` ∈ `{ingest, hash, ocr, classify, export}`. Distinct-image count grows roughly with case complexity (10–50 distinct images per 5-min window are typical).
- All EvidenceLoader children are signed by `Acme Legal Software CA` (cert thumbprint `8E3C…41F2`); signing distribution is uniform.
- Child-image-name length: 12–18 chars. Image-name entropy: 2.8–3.4 (the hex `{caseid}` + structured suffix produces mid-range entropy that overlaps with mainstream droppers).

## Adversarial collision

The EvidenceLoader runtime shape collides with the macro-payload-dropper baseline on three of the four window-level features Sysmon reports:
- child-process count (overlap)
- distinct-image count (overlap)
- name-length / entropy (overlap — *especially* the entropy band)

It diverges on:
- **signing distribution** — EvidenceLoader children are uniformly signed by `Acme Legal Software CA`; macro-dropper payloads are typically unsigned or self-signed with no recurring CA.
- **name pattern stability** — EvidenceLoader children match `EvLoader-[0-9a-f]{6}-(ingest|hash|ocr|classify|export)\.exe`; macro-dropper payloads do not exhibit a stable structured pattern across the burst.

## Deployment notes for the experiment

- Mailmerge bursts on this workstation type historically max at ~30 children with ≤ 5 distinct images (per workload-manifest baseline) — well below the alert's 142 / 38.
- This identity (`ksilva`) has not had a security incident in 24 months.
- Sysmon collector for this host is in nominal health; no telemetry gaps in the alert window.

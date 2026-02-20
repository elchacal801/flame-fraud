# TP-0018: Deepfake Document Fraud

```yaml
---
id: TP-0018
title: "Deepfake Document Fraud"
category: ThreatPath
date: 2026-02-20
author: "FLAME Project"
source: "Internal Knowledge Base"
tlp: WHITE
sector:
  - banking
  - credit-union
  - fintech
fraud_types:
  - documentary-fraud
  - identity-theft
  - synthetic-identity
  - new-account-fraud
cfpf_phases:
  - P1
  - P2
  - P3
mitre_attack:
  - T1583  # Acquire Infrastructure
ft3_tactics: []
mitre_f3: []
groupib_stages:
  - "Resource Development"
  - "Trust Abuse"
  - "Account Access"
tags:
  - deepfake
  - kyc-bypass
  - onboarding
  - synthetic-identity
---
```

---

## Summary

Deepfake document fraud targets the Know Your Customer (KYC) and remote account onboarding processes. Criminals utilize advanced generative AI models (GANs, diffusion models) to manufacture highly realistic, synthetic identifying documents (e.g., driver's licenses, passports, utility bills) that match the details of a synthetic or stolen identity. This bypasses automated optical character recognition (OCR) and facial recognition checks used by financial institutions during self-service digital onboarding.

---

## Threat Path Hypothesis

> **Hypothesis**: Threat actors leverage low-cost, publicly available generative AI tooling to create photo-realistic identity documents that can defeat automated remote identity verification controls, allowing them to open vast numbers of fraudulent accounts with stolen or synthetic PII for downstream exploitation (mule networks or bust-outs).

**Confidence**: High — Widely observed accelerating trend across the fintech and banking sector. Vendors specializing in document verification report a massive spike in deepfake ID submissions.

**Estimated Impact**: Initial impact is creating a "sleeper" account. The downstream impact (when the account is used for muling or bust-outs) ranges from thousands to millions of dollars. The primary issue is the sheer volume and velocity enabled by automated generation.

---

## CFPF Phase Mapping

### Phase 1: Recon

| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P1-001: Tool acquisition | Threat actors source AI generation tools (often via Telegram or dark web forums like "OnlyFakes") that specifically specialize in template-based generation of KYC documents. | (External to financial institution) |

**Data Sources**: Dark web monitoring, specialized cyber threat intelligence.

---

### Phase 2: Initial Access

| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P2-001: Remote Account Opening | The actor attempts to open a new digital account using the AI-generated document and a live-injected or deepfake video selfie to bypass liveness checks. | Micro-anomalies in uploaded photo or video (lighting inconsistencies, blurring around text, unnatural facial movements in liveness checks); matching Exif metadata across supposedly distinct applicants. |

**Data Sources**: Document verification vendor logs, KYC metadata, webcam/camera feed metrics.

---

### Phase 3: Positioning

| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P3-001: Sleeper Account Maturation | Accounts successfully created with deepfake documents are allowed to "age" to bypass neo-account restrictions before being sold as drop accounts. | Initial funding of account with bare minimum amounts; subsequent dormancy for 30-90 days. |

**Data Sources**: Account activity monitoring, login frequency analytics.

---

## Look Left / Look Right Analysis

**Discovery Phase**: Frequently discovered at **Phase 2** if the document vendor has robust AI detection, or later at **Phase 5** when the account is flagged for money laundering or bust-out behavior.

**Look Left**:

- Could document verification metadata have flagged the anomaly earlier? Frequently, the deepfake images lack normal physical artifacts (lens distortion, natural shadows) or contain AI-specific artifacts.
- Analysis of application velocity from similar device fingerprints or IP ranges.

**Look Right**:

- If untracked, these accounts populate the institution's customer base with dormant "sleeper cells" ready to be activated for massive money mule networks or organized loan fraud.

---

## Controls & Mitigations

| Phase | Control | Type | Owner |
|-------|---------|------|-------|
| P2 | Active/Passive Liveness Detection (requiring specific physical responses) | Preventive | KYC/Onboarding |
| P2 | Injection Attack Prevention (preventing virtual cameras from feeding the onboarding flow) | Preventive | Digital Channels |
| P2 | Specialized deepfake detection algorithms (spectral analysis of images) | Detective | Fraud Strategy |
| P3 | Sleeper Account Monitoring (flagging sudden activity after 90 days of dormancy) | Detective | Transaction Monitoring |

---

## Detection Approaches

### Queries / Rules

**Splunk — Detecting Shared Device Fingerprints Across Multiple AI Onboarding Attempts**

```spl
index=onboarding action="document_verification"
| stats count dc(applicant_name) as distinct_names sum(eval(status="rejected_ai_suspected")) as deepfake_rejects by device_fingerprint, source_ip
| where count > 3 AND distinct_names > 2
| table device_fingerprint, source_ip, count, distinct_names, deepfake_rejects
| sort - deepfake_rejects
```

### Behavioral Analytics

- **Application Behavior**: Flag applicants taking zero time to "take a photo" or whose interaction times are superhumanly fast, suggesting automated injection rather than a human holding a camera.
- **Biometric Matching**: Cross-reference the facial embeddings generated during the liveness check against the institution's existing customer database to find "one face, many identities" scenarios.

---

## References

- FLAME Project Internal Knowledge Base.
- Document Verification Industry Reports (e.g., Onfido, Socure, ID R&D regarding GenAI threats).

---

## Revision History

| Date | Author | Change |
|------|--------|--------|
| 2026-02-20 | FLAME Project | Initial creation |

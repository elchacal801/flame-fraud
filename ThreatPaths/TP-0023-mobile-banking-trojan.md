# TP-0023: Mobile Banking Trojan / Overlay Attack

```yaml
---
id: TP-0023
title: "Mobile Banking Trojan / Overlay Attack"
category: ThreatPath
date: 2026-02-20
author: "FLAME Project"
source: "Internal Knowledge Base"
tlp: WHITE
sector:
  - banking
  - fintech
  - crypto
fraud_types:
  - account-takeover
  - malware
  - unauthorized-transaction
cfpf_phases:
  - P1
  - P2
  - P3
  - P4
  - P5
mitre_attack:
  - T1624     # Event Triggered Execution (Overlay)
  - T1626     # Device Lockout
  - T1417     # Input Capture
  - T1636     # Protected User Data (SMS MFA bypass)
ft3_tactics: []
mitre_f3: []
groupib_stages:
  - "Resource Development"
  - "Initial Access"
  - "Execution"
  - "Credential Access"
  - "Perform Fraud"
tags:
  - mbanking
  - android-malware
  - overlay-attack
  - ats
---
```

---

## Summary

Mobile Banking Trojans (primarily targeting Android environments) are sophisticated malware variants that deceive users into granting extensive device "Accessibility" permissions. Once installed, the malware monitors the foreground applications. When the user launches a targeted banking app, the malware draws a pixel-perfect "overlay" (a fake login screen) on top of the legitimate app. It captures the user's credentials and SMS MFA tokens, sending them to the threat actor, or uses an Automated Transfer System (ATS) to initiate fraudulent transactions invisibly on the victim's device.

---

## Threat Path Hypothesis

> **Hypothesis**: Threat actors distribute malicious Android APKs via smishing or third-party app stores. The malware convinces the victim to grant accessibility services, allowing the malware to detect banking app launches, present spoofed overlays to harvest credentials, intercept SMS-based MFA, and autonomously execute wire transfers via the legitimate banking app.

**Confidence**: High — Widely documented by threat intelligence firms analyzing malware families such as Anubis, Cerberus, Octo, and Vultur.

**Estimated Impact**: Complete Account Takeover (ATO) with the ability to drain the victim's deposit accounts up to daily transaction limits. Severe reputational damage to the institution due to the compromise occurring on the "trusted" mobile channel.

---

## CFPF Phase Mapping

### Phase 1: Recon & Resource Dev

| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P1-002: Malware Infrastructure | Actors lease Banking-Trojan-as-a-Service (MaaS) panels, pack malicious APKs (often disguising them as PDF readers, utility apps, or fake software updates), and set up C2 infrastructure. | (External to financial institution) |

**Data Sources**: Mobile Threat Defense (MTD) telemetry, malware sandboxes.

---

### Phase 2: Initial Access & Trust Abuse

| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P2-001: Smishing/Malvertising Delivery | Victims receive SMS messages urging them to install an app (e.g., "DHL package tracking") or encounter malicious ads. The app requests extensive Accessibility permissions. | (External to financial institution) |
| CFPF-P2-004: Credential Harvesting via Overlay | The malware detects the user opening the bank app, injects the fake overlay, logs the username/password, and intercepts the subsequent SMS OTP sent by the bank. | Victim completes login, but the bank sees repeated authentication failures (if the overlay doesn't pass the creds through) or login from anomalous IP (if the actor logs in from their own device). |

**Data Sources**: App analytics (time to login, unusual UI interactions), MFA logs.

---

### Phase 3 & 4: Execution (ATO & Transfer)

| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P4-001: ATS (Automated Transfer System) Execution | Modern variants don't rely on the actor logging in manually. Instead, the malware's ATS module uses Accessibility permissions to click through the legitimate banking app *on the victim's own device*, initiating a transfer to a mule account while dimming the screen or displaying a fake "System Updating" overlay to the user. | Lightning-fast navigation through the app interface; transaction sourced from the victim's trusted device and normal IP (bypassing traditional risk engines). |

**Data Sources**: Mobile app behavioral analytics (keystroke dynamics, screen dimming events, navigation velocity).

---

### Phase 5: Monetization

| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P5-001: Mule Network Dispersion | The funds are immediately wired to a mule account and withdrawn. | Instant transfer to unrecognized beneficiary followed by rapid cash-out. |

**Data Sources**: Transaction monitoring.

---

## Look Left / Look Right Analysis

**Discovery Phase**: Frequently discovered at **Phase 5** when the victim notices the missing funds.

**Look Left**:

- **P4/3 → P2**: Traditional fraud systems fail because the transaction originates from the victim's *known, trusted device* and *recognized IP address* via the ATS.
- The failure point is lacking visibility into the device posture (e.g., detecting sideloaded apps running with Accessibility permissions active).

**Look Right**:

- Unless the malware is removed from the device, the actor maintains a persistent foothold to intercept further communications or attack other financial apps.

---

## Controls & Mitigations

| Phase | Control | Type | Owner |
|-------|---------|------|-------|
| P2 | Implement RASP (Runtime Application Self-Protection) checks within the banking app to detect overlays, sideloading, or active screen-readers. | Preventive | Mobile Engineering |
| P2 | Transition away from SMS OTPs to strong, out-of-band push notifications or FIDO2/WebAuthn. | Preventive | IAM |
| P4 | Implement Mobile Behavioral Biometrics (analyzing swipe pressure, navigation speed, device angle) to detect ATS bot behavior vs. human interaction. | Detective | Fraud Risk |

---

## Detection Approaches

### Queries / Rules

**Sigma — Fast Navigation ATS Anomaly (Conceptual)**

```yaml
title: Mobile Banking - Impossible Navigation Speed (ATS Indicator)
status: experimental
description: Detects when the time between app launch, login, and transaction initiation is faster than humanly possible, indicating an Automated Transfer System.
logsource:
    product: mobile_banking
    service: telemetry
detection:
    selection:
        action: 'transaction_initiated'
    condition: selection | time_since(session_start) < 4s
level: high
tags:
    - attack.t1624
    - cfpf.phase4.execution
```

### Behavioral Analytics

- **Screen State Anomalies**: Flag transactions initiated while the device screen brightness is registered at 0% or while an overlay window is currently active.
- **Accessibility Service Auditing**: Upon app launch, the mobile app queries the OS for active Accessibility services. If anomalous or non-standard services are active, elevate the session risk score.

---

## References

- FLAME Project Internal Knowledge Base.
- ThreatFabric and Cleafy reports on Android Banking Malware (Anubis, Octo).

---

## Revision History

| Date | Author | Change |
|------|--------|--------|
| 2026-02-20 | FLAME Project | Initial creation |

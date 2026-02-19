# FLAME Taxonomy Reference

This document defines the taxonomy elements used across FLAME threat path submissions.

---

## CFPF Phases (Primary Framework)

Every threat path maps to the FS-ISAC **Cyber Fraud Prevention Framework (CFPF)** five-phase lifecycle:

| Phase | Name | Description |
|-------|------|-------------|
| **P1** | Recon | Target identification, OSINT, social engineering preparation |
| **P2** | Initial Access | Account compromise, credential theft, phishing entry |
| **P3** | Positioning | Establishing persistence, privilege escalation, internal movement |
| **P4** | Execution | Executing the fraudulent action (transfers, claims, diversions) |
| **P5** | Monetization | Cashing out, laundering, converting stolen value |

## Fraud Types

Standardized lowercase-hyphenated labels. Each threat path must have at least one.

| Fraud Type | Description |
|-----------|-------------|
| `account-takeover` | Unauthorized control of legitimate accounts |
| `application-fraud` | Fraudulent account/credit applications |
| `BEC` | Business email compromise schemes |
| `check-fraud` | Check washing, counterfeiting, mobile deposit fraud |
| `collusion` | Coordinated fraud involving insiders or multiple actors |
| `credential-stuffing` | Automated credential reuse attacks |
| `crypto-laundering` | Money laundering via cryptocurrency |
| `data-theft` | Exfiltration of PII or financial data |
| `deepfake` | AI-generated audio/video impersonation |
| `disability-fraud` | Fraudulent disability insurance claims |
| `fraudulent-claim` | False or exaggerated insurance claims |
| `impersonation` | Identity impersonation (non-synthetic) |
| `insider-threat` | Employee or contractor abuse of access |
| `invoice-fraud` | Fraudulent or manipulated invoices |
| `malvertising` | Malicious advertising to redirect victims |
| `money-mule` | Use of intermediaries to move stolen funds |
| `new-account-fraud` | Fraud using newly opened accounts |
| `payment-diversion` | Redirecting legitimate payments |
| `payroll-diversion` | Redirecting employee payroll deposits |
| `phishing` | Email/SMS/voice phishing campaigns |
| `premium-diversion` | Insurance premium payment redirection |
| `provider-fraud` | Healthcare or service provider collusion |
| `romance-scam` | Relationship-based social engineering fraud |
| `synthetic-identity` | Fabricated identities using real + fake PII |
| `vishing` | Voice-based phishing and social engineering |
| `wire-fraud` | Fraudulent wire transfer schemes |

## Sectors

Standardized sector labels for targeting context:

| Sector | Description |
|--------|-------------|
| `banking` | Commercial and retail banking |
| `credit-union` | Credit unions and member-owned FIs |
| `cross-sector` | Schemes targeting multiple sectors |
| `crypto` | Cryptocurrency exchanges and DeFi |
| `fintech` | Financial technology platforms |
| `insurance` | Insurance carriers and agents |

## Cross-Framework Mappings

FLAME supports mapping to supplementary frameworks:

### MITRE ATT&CK

Technique IDs in `TXXXX` or `TXXXX.XXX` format. Links resolve to [attack.mitre.org](https://attack.mitre.org/).

### Group-IB Fraud Matrix 2.0

Ten-stage lifecycle providing an alternative perspective to CFPF:

| # | Stage |
|---|-------|
| 1 | Reconnaissance |
| 2 | Resource Development |
| 3 | Trust Abuse |
| 4 | End-user Interaction |
| 5 | Credential Access |
| 6 | Account Access |
| 7 | Defence Evasion |
| 8 | Perform Fraud |
| 9 | Monetization |
| 10 | Laundering |

### Stripe FT3

MIT-licensed fraud taxonomy. Tactic IDs mapped when available.

### MITRE F3

Placeholder — will map when MITRE ships the F3 extension. Field included in frontmatter schema for forward compatibility.

## Frontmatter Schema

Every threat path markdown file uses this YAML frontmatter:

```yaml
---
id: TP-XXXX
title: "Descriptive title"
category: ThreatPath
date: YYYY-MM-DD
author: "Name or Handle"
source: "URL or 'Original Research'"
tlp: WHITE
sector:
  - banking
fraud_types:
  - account-takeover
cfpf_phases: [P1, P2, P3, P4, P5]
mitre_attack: []
ft3_tactics: []
mitre_f3: []
groupib_stages: []
tags:
  - descriptive-tag
---
```

See [CONTRIBUTING.md](../CONTRIBUTING.md) for full field guidelines.

# TP-0006: Real Estate Wire Fraud — Closing Scam

```yaml
---
id: TP-0006
title: "Real Estate Wire Fraud — Closing Scam"
category: ThreatPath
date: 2026-02-12
author: "FLAME Project"
source: "FBI IC3 / American Land Title Association (ALTA) reporting"
tlp: WHITE
sector:
  - banking
  - cross-sector
fraud_types:
  - BEC
  - wire-fraud
  - payment-diversion
  - impersonation
cfpf_phases: [P1, P2, P3, P4, P5]
mitre_attack: [T1566.001, T1114.003, T1534, T1657]
ft3_tactics: []                  # Stripe FT3 (when mapped)
mitre_f3: []                     # MITRE F3 (placeholder)
groupib_stages: []               # Group-IB Fraud Matrix (reference)
tags:
  - real-estate
  - title-company
  - escrow
  - closing-funds
  - high-value
  - time-sensitive
---
```

## Summary

Actors compromise email accounts of real estate agents, title companies, attorneys, or mortgage lenders to monitor pending transactions and send fraudulent wire instructions to homebuyers at closing. The scheme exploits the time-sensitive, high-value nature of real estate closings and the expectation that wire instructions will arrive via email. FBI IC3 reports real estate BEC as one of the fastest-growing BEC subcategories, with average losses of $150,000+ (often representing a buyer's entire down payment or full purchase price).

## Threat Path Hypothesis

> **Hypothesis**: Actors are compromising email accounts within the real estate transaction chain (agent, title company, lender, attorney) to monitor pending closings and inject fraudulent wire instructions timed to coincide with legitimate closing fund requests.

**Confidence**: High — extensively documented, FBI PSAs, ALTA industry alerts.
**Estimated Impact**: $100,000 – $500,000+ per incident (often entire home purchase price).

## CFPF Phase Mapping

### Phase 1: Recon
| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P1-005: Real estate transaction monitoring | Identify pending closings from MLS listings (status changes to "pending/under contract"), county recorder filings, or compromised email threads | Correlation between listing status changes and phishing campaigns |
| CFPF-P1-003: Lookalike domain | Register domains resembling title companies or law firms | Domain registrations matching title company names in active transaction areas |

### Phase 2: Initial Access
| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P2-004: Email phishing | Target real estate professionals — agents, title officers, closing attorneys — to compromise their email accounts | Phishing campaigns themed around MLS access, e-signature platforms, or title company portals |
| CFPF-P2-007: BEC | Gain access to an email account within the transaction chain to monitor closing timelines, amounts, and participants | Unusual login locations on real estate professional email accounts; mail forwarding rules |

### Phase 3: Positioning
| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P3-007: Email forwarding/filtering | Create inbox rules to monitor keywords like "closing", "wire instructions", "escrow", "title" and suppress legitimate wire instruction emails | New rules containing real estate keywords; rules forwarding to external addresses |
| CFPF-P3-008: Transaction data harvesting | Extract closing details: buyer name, property address, closing date, amount, title company contact, lender details | Mailbox search queries for real estate terms from compromised account |
| Timing calibration | Monitor email thread to identify exact moment legitimate wire instructions will be sent, then preempt or replace them | N/A (occurs within compromised mailbox) |

### Phase 4: Execution
| Technique | Description | Indicators |
|-----------|-------------|------------|
| Fraudulent wire instruction injection | Send wire instructions from compromised or spoofed email, often minutes before or instead of legitimate instructions. Instructions direct closing funds to actor-controlled account. | Wire instructions from slightly different email address; instructions differing from previous communications; urgency language; last-minute "updated" banking details |

### Phase 5: Monetization
| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P5-001: Domestic wire to mule | Closing funds wired to domestic mule account, rapidly redistributed | Large incoming wire to recently opened account; immediate outbound transfers |
| CFPF-P5-002: International wire | Funds wired directly to overseas accounts | International wire from domestic title/escrow transaction |

## Look Left / Look Right

**Discovery Phase**: **P4/P5** — discovered when title company or buyer realizes funds went to wrong account (sometimes within hours, sometimes days). Recovery success drops dramatically after 48 hours.

**Look Left**: Which email in the transaction chain was compromised? Were there forwarding rules created in the weeks before closing? Was the real estate professional targeted by phishing prior to the transaction?

**Look Right**: Is the same compromised email being used to target other pending transactions? Wire recall — has the receiving bank been notified within the recovery window?

## Controls & Mitigations

| Phase | Control | Type |
|-------|---------|------|
| P2 | MFA on all real estate professional email accounts | Preventive |
| P3 | Real estate firms: monitor for email forwarding rules containing transaction keywords | Detective |
| P4 | **Mandatory verbal verification** of wire instructions via phone call to known number (not from email) | Preventive |
| P4 | Title companies: include "we will NEVER change wire instructions via email" disclaimer on all communications | Preventive |
| P4 | Banks: enhanced scrutiny on large incoming wires to newly opened accounts | Detective |
| P5 | Immediate wire recall protocol — financial institutions should have <2hr response SLA | Responsive |

## Detection Approaches

**Email — Wire Instruction Anomaly (M365 / Google Workspace)**
```kql
EmailEvents
| where Subject has_any ("wire", "closing", "escrow", "wiring instructions")
| extend sender_domain = tostring(split(SenderFromAddress, "@")[1])
| where sender_domain !in (known_title_company_domains)
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject
```

## References
- FBI IC3 PSA: "Real Estate Wire Fraud"
- American Land Title Association (ALTA): Wire Fraud Prevention Best Practices
- CertifID: Real Estate Wire Fraud Report (annual)

## Revision History
| Date | Author | Change |
|------|--------|--------|
| 2026-02-12 | FLAME Project | Initial submission |

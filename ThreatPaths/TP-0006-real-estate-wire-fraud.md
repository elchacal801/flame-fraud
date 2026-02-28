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
ft3_tactics: ["FTA001", "FTA002", "FTA003", "FTA004", "FTA005", "FTA006", "FTA007", "FTA009", "FTA010", "FT052.003", "FT055", "FT012", "FT026.001", "FT031", "FT008.002", "FT016", "FT018", "FT020", "FT021"]                  # Stripe FT3 (when mapped)
mitre_f3: []                     # MITRE F3 (placeholder)
groupib_stages:
  - "Reconnaissance"
  - "Resource Development"
  - "Trust Abuse"
  - "End-user Interaction"
  - "Perform Fraud"
  - "Monetization"
  - "Laundering"
ucff_domains:
  commit: "Level 2"
  assess: "Level 2"
  plan: "Level 2"
  act: "Level 3"
  monitor: "Level 2"
  report: "Level 2"
  improve: "Level 2"
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

## UCFF Alignment

### Required Organizational Maturity for Effective Detection

| UCFF Domain | Minimum Maturity | Key Deliverables for This Threat Path |
|-------------|-----------------|--------------------------------------|
| COMMIT | Level 2 (Developing) | Institutional policy on wire transfer verification for real estate closings; commitment to customer friction (mandatory callbacks) to prevent loss |
| ASSESS | Level 2 (Developing) | Assessment of real estate wire volume exposure, email compromise risk across title company and attorney communication channels |
| PLAN | Level 2 (Developing) | Wire verification callback procedures for real estate transactions, title company authentication protocols, customer-facing closing wire safety guidance |
| ACT | Level 3 (Established) | New payee validation controls on incoming wire instructions, email domain verification against known title company domains, beneficiary name matching against closing documents |
| MONITOR | Level 2 (Developing) | Tracking of wire fraud attempt volume and trends, false positive rates on wire holds, wire recall success rates within recovery windows |
| REPORT | Level 2 (Developing) | IC3 and FinCEN reporting for real estate BEC, customer notification procedures, coordination with receiving banks on wire recall |
| IMPROVE | Level 2 (Developing) | Tracking of loss recovery rates by response time, updating callback procedures and customer warnings based on emerging BEC TTPs targeting real estate |

### Maturity Levels Reference
- **Level 1 (Initial):** Ad hoc, reactive fraud management
- **Level 2 (Developing):** Basic fraud function exists with some defined processes
- **Level 3 (Established):** Formalized fraud program with proactive capabilities
- **Level 4 (Advanced):** Data-driven, continuously improving fraud program
- **Level 5 (Leading):** Industry-leading, predictive fraud management

## Detection Approaches

**Email — Wire Instruction Anomaly (M365 / Google Workspace)**

```kql
EmailEvents
| where Subject has_any ("wire", "closing", "escrow", "wiring instructions")
| extend sender_domain = tostring(split(SenderFromAddress, "@")[1])
| where sender_domain !in (known_title_company_domains)
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject
```

**Email — Suspicious Inbox Rule Creation (M365)**

```sigma
title: Suspicious Inbox Rule Creation
status: experimental
description: Detects the creation of inbox rules looking for real estate keywords like wire, closing, escrow to suppress legitimate communication.
logsource:
    product: m365
    service: exchange
detection:
    selection:
        ActionType: 'New-InboxRule'
        RuleParameters|contains:
            - 'wire'
            - 'closing'
            - 'escrow'
    condition: selection
```

## Analyst Notes

**IC3 2024 Data:** The FBI IC3 2024 Internet Crime Report (covering 2024 incidents, released April 2025) reported $2.8B in total BEC losses, of which real estate wire fraud is a significant subcategory. Real estate closings remain a high-value BEC target due to the time-sensitive nature and large dollar amounts involved. Elderly victims (60+) accounted for $4.9B in total IC3-reported losses across all categories in 2024, and are disproportionately targeted in real estate wire schemes.

## References

- FBI IC3 PSA: "Real Estate Wire Fraud"
- FBI IC3: "2024 Internet Crime Report" (April 2025) — annual loss and complaint statistics
- American Land Title Association (ALTA): Wire Fraud Prevention Best Practices
- CertifID: Real Estate Wire Fraud Report (annual)

## Revision History

| Date | Author | Change |
|------|--------|--------|
| 2026-02-12 | FLAME Project | Initial submission |

# TP-0004: Payroll Diversion via HR Portal Compromise

```yaml
---
id: TP-0004
title: "Payroll Diversion via HR Portal Compromise"
category: ThreatPath
date: 2026-02-12
author: "FLAME Project"
source: "FBI IC3 PSA I-091819-PSA / multiple industry reports"
tlp: WHITE
sector:
  - cross-sector
fraud_types:
  - payroll-diversion
  - BEC
  - phishing
  - account-takeover
cfpf_phases: [P1, P2, P3, P4, P5]
mitre_attack: [T1566.001, T1078, T1657]
ft3_tactics: ["FTA001", "FTA002", "FTA003", "FTA004", "FTA005", "FTA006", "FTA007", "FTA008", "FTA009", "FTA010", "FT011.002", "FT028", "FT016", "FT003", "FT037.002", "FT038.002", "FT042.001", "FT001", "FT006.001", "FT008.002"]                  # Stripe FT3 (when mapped)
mitre_f3: []                     # MITRE F3 (placeholder)
groupib_stages:
  - "Reconnaissance"
  - "Resource Development"
  - "Trust Abuse"
  - "Account Access"
  - "Perform Fraud"
  - "Monetization"
tags:
  - HR-portal
  - direct-deposit
  - W2-theft
  - employee-targeting
---
```

## Summary

Actors compromise employee self-service HR portals (Workday, ADP, UKG, etc.) to change direct deposit routing information, diverting paychecks to actor-controlled accounts. Often combined with email rule manipulation to suppress payroll notifications. FBI IC3 flagged this as a growing BEC variant. Low per-incident amounts ($2,000-$10,000) but high volume and often undetected for multiple pay cycles.

## Threat Path Hypothesis

> **Hypothesis**: Actors are using credential phishing targeting employees to access self-service HR portals and modify direct deposit information, diverting payroll payments to prepaid card or mule accounts, exploiting the gap between HR systems and fraud monitoring.

**Confidence**: High — FBI PSA, multiple confirmed campaigns across industries.
**Estimated Impact**: $2,000 – $10,000 per employee per pay cycle. Campaigns may target dozens of employees at a single organization.

## CFPF Phase Mapping

### Phase 1: Recon

| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P1-005: Social media recon | Identify target organization's HR portal vendor (often visible on employee LinkedIn profiles or corporate job postings) | N/A |
| CFPF-P1-003: Lookalike domain | Register domains mimicking HR portal login pages (e.g., `workday-login-[company].com`) | Domain registrations containing HR vendor names + target company |

### Phase 2: Initial Access

| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P2-004: Email phishing | Send phishing emails impersonating HR department — "Update your direct deposit for tax season" / "Verify your benefits enrollment" / "Action required: payroll system migration" | Phishing emails referencing HR portal by name; credential harvesting pages mimicking specific HR vendor |
| CFPF-P2-005: Credential stuffing | Use breached credentials to access HR portals (many employees reuse personal passwords for corporate self-service) | Failed login spikes on HR portal; successful logins from anomalous locations |

### Phase 3: Positioning

| Technique | Description | Indicators |
|-----------|-------------|------------|
| Direct deposit modification | Change bank routing and account number for direct deposit to actor-controlled account | Deposit changes from new IPs/devices; changes outside enrollment windows; multiple employees changing deposits in short period |
| CFPF-P3-003: Modify contact info | Change email or phone to prevent employee from receiving payroll deposit confirmations | Contact info changes correlated with deposit changes |
| Tax form harvesting | Download W-2s, pay stubs, or tax documents for identity theft (secondary objective) | Document downloads from unusual sessions |

### Phase 4: Execution

| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P4-005: Payroll diversion | Next payroll cycle processes with modified direct deposit info, sending employee's pay to actor's account | ACH credits to newly specified account; deposit to account with no prior relationship to employee |

### Phase 5: Monetization

| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P5-005: Prepaid card loading | Funds deposited to prepaid debit cards, rapidly withdrawn or spent | Payroll ACH deposits to prepaid card programs |
| CFPF-P5-004: Cash withdrawal | Rapid ATM withdrawals from mule accounts receiving diverted payroll | Full-balance withdrawals within hours of payroll deposit |

## Look Left / Look Right

**Discovery Phase**: Typically **P4** — employee notices missing direct deposit, usually 1-3 days after payday. Sometimes not discovered until next pay cycle if employee doesn't check promptly.

**Look Left**: Were there phishing emails targeting employees in the days/weeks before? Did the HR portal show login anomalies? Were multiple employees at the same organization targeted (campaign-level indicator)?

**Look Right**: Were W-2s or tax documents also harvested (identity theft)? Are the same mule accounts receiving diverted payroll from multiple organizations?

## Controls & Mitigations

| Phase | Control | Type |
|-------|---------|------|
| P2 | Phishing-resistant MFA on HR self-service portals | Preventive |
| P3 | Out-of-band confirmation (email + SMS to original contact info) for any direct deposit change | Preventive |
| P3 | Lockout period: no direct deposit changes within 48hrs of contact info changes | Preventive |
| P3 | HR/IT alert: flag multiple employees changing direct deposit in same time window | Detective |
| P4 | Payroll team review of all deposit routing changes before processing | Preventive |

## Detection Approaches

**Sigma — Multiple Direct Deposit Changes from Anomalous Source**

```yaml
title: HR Portal - Bulk Direct Deposit Modifications
status: experimental
description: Multiple employees modifying direct deposit within short window from unusual IPs
logsource:
    product: hr_portal
    service: audit
detection:
    selection:
        action: "modify_direct_deposit"
    timeframe: 72h
    condition: selection | count(distinct employee_id) by source_ip > 3
level: critical
tags:
    - cfpf.phase3.positioning
```

## Analyst Notes

Payroll diversion is a high-confidence, low-complexity variant of BEC that exploits HR processes rather than accounts payable. Unlike traditional BEC wire fraud (TP-0002), payroll diversion targets recurring payment streams — once the direct deposit is changed, the attacker receives every subsequent paycheck until discovered, often spanning 1-3 pay cycles. The FBI IC3 has issued multiple public service announcements specifically addressing payroll diversion, noting that it accounts for a material subset of BEC complaints. Detection is complicated by the fact that direct deposit changes are routine business operations; the signal-to-noise ratio is inherently low. Organizations with self-service HR portals face elevated risk because the attacker can bypass the HR department entirely by phishing the employee's portal credentials. MFA on HR portals and out-of-band confirmation of banking changes (e.g., calling the employee at a known number) remain the most effective preventive controls.

## References

- FBI IC3 PSA I-091819-PSA: "Cybercriminals Use Social Engineering and Technical Attacks to Circumvent Multi-Factor Authentication"
- FBI IC3 PSA: "Business Email Compromise: Payroll Diversion"
- KnowBe4: Payroll Diversion Phishing Trends

## Revision History

| Date | Author | Change |
|------|--------|--------|
| 2026-02-12 | FLAME Project | Initial submission |
| 2026-02-28 | FLAME Project | v1.5 enrichment: added Stripe FT3 tactic mappings, Analyst Notes |

# TP-0014: Insider-Enabled Account Fraud at Financial Institution

```yaml
---
id: TP-0014
title: "Insider-Enabled Account Fraud at Financial Institution"
category: ThreatPath
date: 2026-02-12
author: "FLAME Project"
source: "DOJ prosecution records / ACFE / FinCEN SAR data / FDIC enforcement actions"
tlp: WHITE
sector:
  - banking
  - credit-union
  - insurance
fraud_types:
  - insider-threat
  - collusion
  - account-takeover
  - data-theft
cfpf_phases: [P1, P2, P3, P4, P5]
mitre_attack: [T1078, T1530, T1657]
ft3_tactics: ["FTA001", "FTA002", "FTA003", "FTA004", "FTA005", "FTA006", "FTA007", "FTA008", "FTA009", "FTA010", "FT011.002", "FT038", "FT003", "FT006", "FT007.005", "FT039.001", "FT016", "FT028", "FT037.002", "FT042"]                  # Stripe FT3 (when mapped)
mitre_f3: []                     # MITRE F3 (placeholder)
groupib_stages:               # Group-IB Fraud Matrix (reference)
  - "Reconnaissance"
  - "Account Access"
  - "Defence Evasion"
  - "Perform Fraud"
  - "Monetization"
  - "Laundering"
tags:
  - insider
  - employee-fraud
  - collusion
  - customer-data
  - access-abuse
  - branch-operations
---
```

## Summary

Employees of financial institutions abuse their legitimate system access to commit or enable fraud — opening accounts with stolen identities, modifying customer records to facilitate unauthorized transactions, exfiltrating customer data to external fraud rings, or directly siphoning funds. The ACFE estimates that insider fraud accounts for 5% of organizational revenue globally. Financial institution insiders are particularly dangerous because they understand internal controls and know how to avoid triggering detection. Schemes often involve collusion with external actors who provide stolen identities or receive diverted funds.

## Threat Path Hypothesis

> **Hypothesis**: Financial institution employees with access to core banking, account management, or claims systems are either independently committing fraud or colluding with external actors to open fraudulent accounts, modify customer data, bypass controls, or directly extract funds — exploiting their knowledge of internal detection mechanisms to operate below detection thresholds.

**Confidence**: High — major category in ACFE, DOJ, and FDIC enforcement data.
**Estimated Impact**: $50,000 – $10,000,000+ per insider. Long-running schemes compound.

## CFPF Phase Mapping

### Phase 1: Recon

| Technique | Description | Indicators |
|-----------|-------------|------------|
| Internal control mapping | Insider identifies detection thresholds, monitoring gaps, review cadences, and system access boundaries through normal job activity | Unusual access to policy/procedure documentation; queries about audit processes |
| Customer data harvesting | Insider identifies vulnerable customer accounts — dormant accounts, deceased customers, high-balance accounts with minimal monitoring | Access patterns targeting dormant/low-activity accounts; queries outside normal job scope |
| External actor recruitment (collusion variant) | Insider connects with external fraud actors who provide stolen identities, receive funds, or fence stolen data | Communications between employee and known fraud actors (often discovered retrospectively) |

### Phase 2: Initial Access

| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P2-009: Insider access abuse | Insider uses legitimate credentials and system access — no technical compromise needed. Access is authorized; the intent is not. | Employee accessing accounts outside their normal portfolio or branch; off-hours system access; access volume spikes |
| Fraudulent account opening | Insider opens new accounts using stolen, synthetic, or deceased individual identities — bypassing KYC checks they're responsible for | New accounts with PII matching breach data; accounts where employee is the sole contact; accounts with no customer-initiated activity |

### Phase 3: Positioning

| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P3-002: Modify account information | Change beneficiary info, contact details, or payment routing on existing customer accounts to redirect funds | Account modifications performed by employee on accounts outside their assignment; modifications with no corresponding customer request |
| CFPF-P3-006: Increase limits | Override or modify transaction limits, credit limits, or approval thresholds on accounts targeted for exploitation | Limit overrides by employee on accounts with no documented customer request; pattern of limit changes preceding large transactions |
| CFPF-P3-004: Suppress alerts | Disable customer-facing alerts, SAR filing, or internal monitoring on target accounts | Alert suppression on accounts with subsequent high-risk activity |
| Customer data exfiltration | Export customer PII, account details, or transaction histories for use by external fraud rings | Bulk data access or export; USB usage; email of customer data to personal accounts; screenshot activity |

### Phase 4: Execution

| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P4-001: Unauthorized wire/transfer | Initiate wire transfers, ACH payments, or internal transfers from customer accounts to insider-controlled or accomplice accounts | Transfers initiated by employee from customer accounts with no customer authorization; transfers to accounts linked to employee |
| Fictitious loan origination | Approve loans to fictitious borrowers or inflate appraisals for insider benefit | Loan approvals with minimal documentation; appraisals significantly above market; loans to borrowers connected to employee |
| CFPF-P4-006: Fraudulent claims (insurance variant) | Insurance employee approves fraudulent claims, inflates settlements, or routes claim payments to accomplice accounts | Claims approved outside normal authority; settlements above comparable averages; claim payments to non-policyholder accounts |
| Cash manipulation (branch) | Teller or branch employee manipulates cash transactions — skimming, kiting, or fictitious deposits | Cash drawer discrepancies; CTR structuring below $10K; balancing anomalies |

### Phase 5: Monetization

| Technique | Description | Indicators |
|-----------|-------------|------------|
| Direct fund diversion | Stolen funds sent to insider's own accounts or immediate family | Transfers to accounts with same surname/address as employee |
| Accomplice network | Funds routed through accounts of external accomplices | Transfers to accounts that opened at same branch or through same employee |
| CFPF-P5-004: Cash extraction | Cash withdrawals or cashier's checks to avoid electronic trail | Large cash transactions from manipulated accounts |
| Data monetization | Exfiltrated customer data sold on dark web or to identity fraud rings | Customer PII appearing in dark web markets traceable to institution's data |

## Look Left / Look Right

**Discovery Phase**: Variable — sometimes detected by internal audit (P3/P4), sometimes by customer complaint (P4), sometimes by SAR filing (P5), sometimes not until employee departure. Average detection time for insider fraud: 18 months (ACFE).

**Look Left**: Were there HR red flags (financial stress, lifestyle changes, behavioral indicators)? Were there access pattern anomalies detectable in SIEM/UEBA that weren't investigated? Did the insider's transactions stay consistently below monitoring thresholds (structuring behavior)?

**Look Right**: How many accounts and customers were affected? Has the exfiltrated data been used in other fraud schemes? Were other employees involved or aware?

## Controls & Mitigations

| Phase | Control | Type |
|-------|---------|------|
| P1 | Separation of duties: no single employee can open account + modify details + initiate transactions | Preventive |
| P2 | UEBA (User and Entity Behavior Analytics): baseline employee access patterns, alert on deviations | Detective |
| P2 | Access reviews: periodic re-certification of employee access rights; remove access not needed for current role | Preventive |
| P3 | Dual control for account modifications on high-balance or dormant accounts | Preventive |
| P3 | DLP (Data Loss Prevention): monitor for bulk data access, USB usage, email of customer data | Detective |
| P4 | Mandatory vacation policies: require employees to take consecutive days off (allows anomaly detection when cover handles accounts) | Detective |
| P4 | Transaction peer review: second-party approval for transactions on accounts employee has modified | Preventive |
| P5 | Post-employment monitoring: watch for account activity connected to recently separated employees | Detective |

## Detection Approaches

**UEBA — Employee Access Anomaly Scoring**

```yaml
title: Anomalous Internal Account Access Volume
status: experimental
description: Detects when an employee accesses 3x their baseline account volume within 24 hours
logsource:
    product: core_banking
    service: ueba
detection:
    selection:
        action: "account_view"
    timeframe: 24h
    condition: selection | count(distinct account_id) by employee_id > 3 * baseline_volume_24h
level: high
tags:
    - cfpf.phase2.initial_access
    - insider.threat
```

**Graph Analytics — Employee-Account-Beneficiary Relationship**

```
Build graph: Employee → Accounts Accessed → Beneficiaries/Transfers
Flag when:
  - Beneficiary accounts share attributes with employee (address, phone, name)
  - Employee-modified accounts show transfer patterns to same destination accounts
  - Employee opened accounts that subsequently received funds from other employee-serviced accounts
```

## Analyst Notes

Insider fraud is the hardest threat path to detect because the actor has legitimate access and understands the controls. The CFPF's cross-functional approach is essential here: HR behavioral indicators + IT access monitoring + fraud transaction analytics + audit findings must be correlated. No single team sees the full picture.

**Insurance sector specificity**: At insurance companies, insider risk extends to claims adjusters (inflating settlements), underwriters (approving high-risk policies for kickbacks), and agents (premium diversion per TP-0005). The positioning phase often looks like normal job activity — the key differentiator is the pattern of decisions, not any single event.

## References

- ACFE: Report to the Nations (biennial) — occupational fraud statistics
- FDIC: Enforcement Decisions (insider fraud)
- DOJ: Bank fraud prosecution press releases
- CERT National Insider Threat Center: Common Sense Guide

## Revision History

| Date | Author | Change |
|------|--------|--------|
| 2026-02-12 | FLAME Project | Initial submission |
| 2026-02-28 | FLAME Project | v1.5 enrichment: added Stripe FT3 tactic mappings |

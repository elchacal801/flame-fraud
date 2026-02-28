# TP-0022: Government Program Fraud

```yaml
---
id: TP-0022
title: "Government Program Fraud (Unemployment/Tax)"
category: ThreatPath
date: 2026-02-20
author: "FLAME Project"
source: "Internal Knowledge Base"
tlp: WHITE
sector:
  - government
  - banking
fraud_types:
  - benefit-fraud
  - identity-theft
  - synthetic-identity
  - tax-fraud
cfpf_phases:
  - P1
  - P3
  - P4
  - P5
mitre_attack: []
ft3_tactics: ["FTA001", "FTA002", "FTA003", "FTA005", "FTA006", "FTA007", "FTA009", "FTA010", "FT052.004", "FT026.004", "FT016.001", "FT020", "FT005.001", "FT011.002", "FT018", "FT025", "FT051.003", "FT006"]
mitre_f3: []
groupib_stages:
  - "Resource Development"
  - "Perform Fraud"
  - "Monetization"
tags:
  - benefits-scam
  - irs-fraud
  - targeted-demographics
---
```

---

## Summary

Government Program Fraud involves threat actors leveraging stolen Personally Identifiable Information (PII) to file fraudulent claims for government benefits (e.g., UI, SNAP, FEMA disaster relief) or tax refunds. The actor directs the government payout to a pre-paid debit card, a digitally opened neo-bank account, or an established mule account, depriving the legitimate citizen of their benefits and defrauding the state.

---

## Threat Path Hypothesis

> **Hypothesis**: Threat actors source massive quantities of PII from data broker breaches, use automation to bulk-file claims with state workforce or tax agencies, and route the approved funds into networks of "drop" accounts or prepaid debit cards.

**Confidence**: High — Verified by the massive wave of unemployment fraud observed globally during the 2020-2022 pandemic, and ongoing persistent tax return fraud.

**Estimated Impact**: Micro-impacts of $1,000 to $20,000 per victimized identity, but macro-impacts totaling hundreds of billions of dollars across federal and state governments when executed via automated botnets.

---

## CFPF Phase Mapping

### Phase 1: Recon

| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P1-001: Data Sourcing | Actors purchase bulk "Fullz" (full PII profiles) from dark web marketplaces, specifically targeting demographics likely to qualify for specific benefits or not actively filing taxes (e.g., the elderly, the incarcerated). | Large dark web data dumps involving SSNs, DOBs, and historical employment data. |

**Data Sources**: Cyber Threat Intelligence feeds.

---

### Phase 3: Positioning

| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P3-001: Account Setup (Benefits Portal) | Actor creates a portal account with the state agency using the victim's PII, often using variations of a single email domain (e.g., Gmail dot-trick) to manage thousands of profiles. | High volume of accounts registered from the same IP range; email addresses following patterned or alias structures. |
| CFPF-P3-002: Drop Account Creation | Actor opens accounts at fintechs or banks to receive the funds, or requests prepaid debit cards be mailed to compromised physical addresses. | New account opening velocity anomalies associated with specific IP or device clusters. |

**Data Sources**: State agency portal logs, financial institution onboarding logs.

---

### Phase 4: Execution

| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P4-001: Claim Submission | The actor submits the fraudulent UI claim or forged tax return, instructing the agency to deposit the money to the drop account. | High velocity of claims filed outside normal seasonal parameters; "bursts" of claims from similar IP blocks. |

**Data Sources**: Government system audit logs.

---

### Phase 5: Monetization

| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P5-001: ACH Deposit & Rapid Withdrawal | State agency originates the ACH deposit. Once it lands in the bank account, the actor immediately withdraws it via ATM, wire, or crypto purchase. | Multiple government ACH deposits (often in different names) hitting a single account, followed by immediate ATM cash-outs. |

**Data Sources**: Bank ACH monitoring, ATM transaction logs.

---

## Look Left / Look Right Analysis

**Discovery Phase**: Discovered at **Phase 5** by financial institutions when identifying suspicious volumes of inbound government ACHs, or later when the true citizen attempts to file their real tax return and is rejected.

**Look Left**:

- Financial institutions see the ACH deposit, but the state agency operates independently. Frictionless information sharing between the FI (which sees the anomalous bank account) and the State (which sees the anomalous login) is historically poor.

**Look Right**:

- Uncaught botnets will iterate through databases, finding vulnerabilities across different state systems, migrating from high-security states to those with weaker controls.

---

## Controls & Mitigations

| Phase | Control | Type | Owner |
|-------|---------|------|-------|
| P3 | Identity Verification (NIST IAL2) at government portals prior to account creation | Preventive | Government Agency |
| P4 | Analytics to identify highly coordinated claim submissions (IP pooling, device fingerprints) | Detective | Government Agency |
| P5 | FI AML rules flagging Name Mismatches: Inbound ACH name doesn't match the Bank Account holder name | Preventive | Bank AML/Fraud |
| P5 | Rules flagging >1 distinct government benefit deposits hitting a single consumer account | Detective | Bank Fraud |

---

## Detection Approaches

### Queries / Rules

**SQL — Multiple UI/Tax Deposits to Single Account (Mule Indicator)**

```sql
SELECT 
    a.account_id,
    COUNT(DISTINCT t.originator_name) as distinct_state_agencies,
    SUM(t.amount) as total_government_deposits,
    MAX(t.transaction_date) as latest_deposit
FROM ach_inbound t
JOIN accounts a ON t.account_id = a.account_id
WHERE t.sec_code = 'PPD' 
  AND t.originator_name SIMILAR TO '%(UI|UNEMPLOYMENT|TREAS 310|TAX REF)% '
  AND t.transaction_date >= CURRENT_DATE - INTERVAL '30 days'
GROUP BY 1
HAVING COUNT(*) > 2 -- More than 2 distinct benefit deposits
   AND COUNT(DISTINCT t.receiver_name) > 1; -- For different individuals
```

### Behavioral Analytics

- **Name Mismatch Analysis**: Utilize fuzzy matching (Levenshtein distance) between the ACH Receiver Name and the KYC Account Holder Name. Wide divergence in consumer accounts receiving government funds indicates a "drop" account for stolen UI/Tax refunds.

---

## Analyst Notes

**IC3 2024 Data:** The FBI IC3 2024 Internet Crime Report (covering 2024 incidents, released April 2025) reported $405M in government impersonation losses. This figure captures cases where actors impersonate government agencies to extract payments from victims, which overlaps with this threat path's use of stolen identities to file fraudulent government benefit claims. IC3 also recorded over 108,000 identity theft complaints in 2024, representing the PII theft pipeline that fuels bulk fraudulent benefit filings.

---

## References

- FBI IC3: "2024 Internet Crime Report" (April 2025) — annual loss and complaint statistics
- FLAME Project Internal Knowledge Base.
- U.S. Secret Service Advisories on Pandemic Fraud Networks.

---

## Revision History

| Date | Author | Change |
|------|--------|--------|
| 2026-02-20 | FLAME Project | Initial creation |

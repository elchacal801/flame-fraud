# TP-0009: Check Washing and Fraudulent Mobile Deposit

```yaml
---
id: TP-0009
title: "Check Washing and Fraudulent Mobile Deposit"
category: ThreatPath
date: 2026-02-12
author: "FLAME Project"
source: "USPS OIG / FinCEN / banking industry reporting"
tlp: WHITE
sector:
  - banking
  - credit-union
fraud_types:
  - check-fraud
cfpf_phases: [P1, P2, P3, P4, P5]
mitre_attack: []
ft3_tactics: []                  # Stripe FT3 (when mapped)
mitre_f3: []                     # MITRE F3 (placeholder)
groupib_stages:
  - "Reconnaissance"
  - "Resource Development"
  - "Account Access"
  - "Perform Fraud"
  - "Monetization"
tags:
  - check-washing
  - mail-theft
  - mobile-deposit
  - duplicate-deposit
  - USPS
---
```

## Summary

Actors steal checks from USPS mailboxes (using stolen arrow keys or by fishing mail from collection boxes), chemically wash the payee and amount fields, then rewrite checks to themselves or accomplices for higher amounts. Washed checks are deposited via mobile banking apps — sometimes the same stolen check is deposited multiple times across different institutions. FinCEN data shows check fraud SARs surged 200%+ from 2021-2023. Despite being a "low-tech" fraud, it's one of the fastest-growing categories due to the explosion of USPS mail theft and the ease of mobile deposit.

## Threat Path Hypothesis

> **Hypothesis**: Organized rings are systematically stealing outbound mail containing checks from USPS collection boxes, chemically altering check details, and depositing them via mobile banking apps across multiple institutions simultaneously, exploiting the lag between deposit and check clearing.

**Confidence**: High — FinCEN SAR data, USPS OIG investigations, massive industry loss growth.
**Estimated Impact**: $1,000 – $50,000 per check. Rings process hundreds of checks.

## CFPF Phase Mapping

### Phase 1: Recon

| Technique | Description | Indicators |
|-----------|-------------|------------|
| USPS collection box targeting | Identify collection boxes in high-value residential/commercial areas. Acquire stolen USPS arrow keys (master keys for collection boxes) from dark web or theft. | Dark web listings for USPS arrow keys ($500-$2,000); reports of collection box tampering |
| Mail carrier route mapping | Identify mail carrier schedules and collection times to time theft for maximum check volume | Surveillance of collection routes |

### Phase 2: Initial Access

| Technique | Description | Indicators |
|-----------|-------------|------------|
| Mail theft | Physically steal outbound mail from USPS collection boxes or individual mailboxes. Target bill payment envelopes (identifiable by pre-printed return envelopes). | USPS mail theft reports; customer complaints of checks not received by payees |
| Stolen check acquisition | Purchase stolen checks from theft rings via dark web or social media (Telegram, Instagram) | Stolen check images posted on social media marketplaces |

### Phase 3: Positioning

| Technique | Description | Indicators |
|-----------|-------------|------------|
| Chemical check washing | Use acetone, bleach, or commercial solvents to dissolve ink on payee line and amount field while preserving signature and MICR line | N/A (physical process) |
| Check alteration | Rewrite payee name and amount on washed check. High-quality washing preserves check stock, watermarks, and security features. | Checks with inconsistent ink density; UV fluorescence anomalies |
| Mule account setup | Open new accounts using stolen or synthetic identities specifically for depositing washed checks | Multiple new accounts at different institutions with similar opening patterns |

### Phase 4: Execution

| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P4-003: Mobile deposit fraud | Deposit washed check via mobile banking app. Same check may be deposited at multiple institutions simultaneously (duplicate deposit). | Mobile deposits of high-value checks to new accounts; same check number deposited at multiple banks; deposits from device fingerprints associated with multiple accounts |
| Counter deposit | Present washed check for in-branch deposit or cash, sometimes with fake ID matching the altered payee | In-branch deposits to new accounts with immediate cash-back requests |

### Phase 5: Monetization

| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P5-004: Cash withdrawal | Withdraw deposited funds before check returns unpaid (exploiting Reg CC funds availability requirements) | Maximum ATM withdrawals within Reg CC availability window; branch cash withdrawals on newly deposited items |
| CFPF-P5-007: Digital payment transfer | Transfer funds from deposit account to digital payment platforms before check clears | P2P transfers (Zelle, Venmo) immediately after check deposit |

## Look Left / Look Right

**Discovery Phase**: **P4** — check returns unpaid (NSF or fraud stop) after the original account holder or their bank identifies the alteration. Typically 3-10 business days after deposit.

**Look Left**: Was there a USPS mail theft report in the geographic area? Are multiple checks from the same collection box showing up as altered? Is the depositing account associated with known mule infrastructure?

**Look Right**: Are the same mule accounts or device fingerprints being used for other check deposits? Is the ring also conducting ACH fraud or new account fraud using identities harvested from the stolen mail?

## Controls & Mitigations

| Phase | Control | Type |
|-------|---------|------|
| P1 | Use Informed Delivery (USPS) to monitor expected vs. received mail | Detective |
| P2 | Use gel-based pens (resistant to chemical washing) for check writing | Preventive |
| P3 | Positive Pay: business customers upload issued check files for bank to match against presented items | Preventive |
| P4 | Device fingerprinting: flag mobile deposits from devices associated with multiple accounts | Detective |
| P4 | Check image analytics: AI-based detection of washed/altered checks (ink consistency, font matching, paper anomalies) | Detective |
| P4 | Duplicate deposit detection across institutions (consortium-level data sharing) | Detective |
| P5 | Extended hold on mobile deposits to new accounts above threshold | Preventive |

## Detection Approaches

**SQL — Suspicious Mobile Deposit Patterns**

```sql
SELECT d.account_id, d.device_fingerprint, d.check_amount,
       COUNT(*) OVER (PARTITION BY d.device_fingerprint) as deposits_from_device,
       a.account_open_date, DATEDIFF(day, a.account_open_date, d.deposit_date) as account_age_days
FROM mobile_deposits d
JOIN accounts a ON d.account_id = a.account_id
WHERE d.check_amount > 1000
  AND DATEDIFF(day, a.account_open_date, d.deposit_date) < 30
  AND deposits_from_device > 3
ORDER BY d.device_fingerprint, d.deposit_date;
```

## References

- FinCEN: Check Fraud SAR Trends (2023-2024)
- USPS OIG: Mail Theft and Check Fraud Reports
- ABA Banking Journal: "The Check Fraud Epidemic"
- Frank on Fraud: Check washing methodology analysis

## Revision History

| Date | Author | Change |
|------|--------|--------|
| 2026-02-12 | FLAME Project | Initial submission |

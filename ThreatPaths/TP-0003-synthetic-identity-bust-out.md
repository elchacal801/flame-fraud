# TP-0003: Synthetic Identity — Credit Card Bust-Out

```yaml
---
id: TP-0003
title: "Synthetic Identity — Credit Card Bust-Out"
category: ThreatPath
date: 2026-02-12
author: "FLAME Project"
source: "Federal Reserve / FinCEN / ACFE reporting"
tlp: WHITE
sector:
  - banking
  - fintech
fraud_types:
  - synthetic-identity
  - new-account-fraud
  - application-fraud
cfpf_phases: [P1, P2, P3, P4, P5]
mitre_attack: []
ft3_tactics: ["FTA001", "FTA002", "FTA003", "FTA004", "FTA005", "FTA006", "FTA007", "FTA009", "FTA010", "FT052.002", "FT026.004", "FT049", "FT010", "FT011.005", "FT020", "FT025", "FT033.004", "FT005", "FT012"]                  # Stripe FT3 (when mapped)
mitre_f3: []                     # MITRE F3 (placeholder)
groupib_stages:
  - "Reconnaissance"
  - "Resource Development"
  - "Account Access"
  - "Perform Fraud"
  - "Monetization"
tags:
  - credit-building
  - bust-out
  - thin-file
  - long-game
  - organized-crime
---
```

## Summary

Actors create fictitious identities by combining real SSNs (often belonging to children, elderly, deceased, or immigrants) with fabricated PII. They then "nurture" these synthetic identities over months or years — opening accounts, building credit history, and establishing legitimacy — before executing a coordinated "bust-out" where all available credit is maxed and the identities are abandoned. The Federal Reserve estimates synthetic identity fraud costs U.S. lenders $6B+ annually.

## Threat Path Hypothesis

> **Hypothesis**: Organized fraud rings are fabricating synthetic identities using stolen SSNs paired with fictitious PII, cultivating these identities through credit-building activity over 12-24 months, then executing coordinated bust-outs across multiple credit products simultaneously.

**Confidence**: High — well-documented by Federal Reserve, OCC, and industry research.
**Estimated Impact**: $15,000 – $200,000 per identity. Rings may operate 50-100+ identities.

## CFPF Phase Mapping

### Phase 1: Recon

| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P1-004: Dark web recon | Acquire SSNs from breach data, dark web marketplaces. SSNs belonging to minors, recently deceased, or non-citizens are preferred (less likely to be monitored) | SSN usage patterns inconsistent with age/history |
| PII fabrication | Assemble synthetic identity: real SSN + fake name + fake DOB + fabricated address. Create supporting infrastructure (phone, email, mailing address) | Multiple identities sharing addresses, phone numbers, or devices |

### Phase 2: Initial Access

| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P2-008: Synthetic identity creation | Apply for initial credit products. First application typically gets denied but creates a credit file with the bureaus ("credit profile fabrication") | Application for credit with SSN that has no bureau history; SSN randomization patterns (post-2011 SSNs not matching SSA issuance geography) |
| Authorized user piggybacking | Get added as authorized user on established accounts (purchased service) to rapidly age the synthetic identity's credit file | Multiple thin-file identities added as authorized users to same seasoned account |

### Phase 3: Positioning

| Technique | Description | Indicators |
|-----------|-------------|------------|
| Credit building / nurturing | Open small credit accounts, make regular payments, maintain low utilization. This phase lasts 12-24 months. | Credit file growth patterns inconsistent with normal consumer behavior; identical payment patterns across multiple identities; addresses/phones shared across thin-file applicants |
| Credit limit increases | Request and receive credit limit increases based on established payment history | Rapid limit increase requests across multiple products near bust-out timing |
| Multi-product diversification | Open accounts across multiple lenders to maximize available credit before bust-out | Application velocity increase after long dormancy; applications across many lenders in short window |

### Phase 4: Execution

| Technique | Description | Indicators |
|-----------|-------------|------------|
| Coordinated bust-out | Simultaneously max out all credit lines across all products. Cash advances, balance transfers to controlled accounts, high-value purchases for resale | Sudden utilization spike from <30% to 100% across multiple accounts; cash advance activity on previously low-activity accounts; purchases at high-resale-value merchants |
| CFPF-P4-007: Loan application fraud | Apply for personal loans, auto loans, or HELOC using the established synthetic identity at the point of maximum creditworthiness | Loan applications timed to coincide with peak credit scores; applications across multiple lenders in days |

### Phase 5: Monetization

| Technique | Description | Indicators |
|-----------|-------------|------------|
| Purchase and resale | High-value purchases (electronics, luxury goods) resold through secondary markets, pawn shops, or online marketplaces | Purchases skewing toward high-resale categories; shipping to addresses different from account address |
| Cash advance extraction | Direct cash withdrawals and cash advance transactions across ATM networks | Cash advance activity from multiple cards at nearby ATMs; maximum daily withdrawal patterns |
| CFPF-P5-003: Crypto conversion | Cash advances or balance transfers converted to cryptocurrency | Fiat-to-crypto transactions from newly active accounts |

## Look Left / Look Right

**Discovery Phase**: Typically **P4/P5** — accounts charge off as uncollectable 60-120 days after bust-out. Often written off as credit loss, not recognized as fraud.

**Look Left**: Were there shared attributes across the synthetic identities (address, phone, device fingerprint, IP, authorized user relationships) that could have linked them during the P3 nurturing phase? Did the credit-building patterns look artificial (identical payment amounts, timing)?

**Look Right**: Are the same SSNs being reused in new synthetic identities? Is the same ring applying at other lenders? Are the mailing addresses receiving cards for multiple thin-file identities?

## Controls & Mitigations

| Phase | Control | Type |
|-------|---------|------|
| P2 | SSN validation against SSA records (eCBSV — electronic Consent Based SSN Verification) | Preventive |
| P2 | Identity document verification with liveness detection for new applications | Preventive |
| P3 | Graph analytics linking applicants by shared attributes (address, phone, device, IP, authorized user chains) | Detective |
| P3 | Behavioral analytics on credit-building velocity and pattern uniformity | Detective |
| P4 | Real-time utilization velocity monitoring — flag accounts going from low to max utilization rapidly | Detective |
| P4 | Cross-lender bust-out detection via consortium data sharing | Detective |

## Detection Approaches

**Graph Analytics — Shared Attribute Clustering**

```
Build identity graph where nodes = applicants, edges = shared attributes:
  - Same mailing address
  - Same phone number
  - Same device fingerprint
  - Same IP address
  - Authorized user relationships
  - Same email domain pattern

Flag clusters where:
  - 3+ thin-file identities share 2+ attributes
  - Cluster members opened accounts within similar timeframes
  - Credit-building patterns show statistical uniformity
```

**SQL — Bust-Out Velocity Detection**

```sql
SELECT account_id, identity_id,
       MAX(utilization_pct) - LAG(MAX(utilization_pct), 30) 
         OVER (PARTITION BY identity_id ORDER BY report_date) as util_change_30d
FROM credit_monitoring
WHERE report_date >= CURRENT_DATE - INTERVAL '90 days'
GROUP BY account_id, identity_id
HAVING util_change_30d > 60  -- 60%+ utilization jump in 30 days
ORDER BY util_change_30d DESC;
```

## Operational Evidence

### EV-TP0003-2026-001: OVH Disposable Email Infrastructure Cluster

- **Source**: domain_intel investigation 2026-02-19
- **Cluster**: 51.254.35.55 (OVH, France)
- **Domain Count**: 7,003 domains
- **Key Indicators**: cprapid.com nameservers, bulk disposable email domain registrations, uniform cPanel hosting configuration
- **CFPF Phase Coverage**: P1, P2
- **Confidence**: High
- **Summary**: Massive cluster of disposable email domains hosted on a single OVH IP with uniform cprapid.com nameserver patterns. This infrastructure directly supports synthetic identity creation at scale — disposable email addresses are used during credit bureau file fabrication (P1 recon) and initial application submission (P2 initial access). The volume (7,003 domains) and uniform hosting pattern indicate organized, purpose-built infrastructure rather than opportunistic registration.

### EV-TP0003-2026-002: GTHost Crypto/Finance Co-hosting Pattern

- **Source**: domain_intel investigation 2026-02-19
- **Cluster**: 193.108.118.7 (GTHost, Netherlands)
- **Domain Count**: 3 key domains (fex.plus, btc.glass, bridgecredit.org)
- **Key Indicators**: file sharing (fex.plus), cryptocurrency interface (btc.glass), financial services impersonation (bridgecredit.org), co-hosted on single IP
- **CFPF Phase Coverage**: P4, P5
- **Confidence**: Medium
- **Summary**: Co-location of file sharing, cryptocurrency, and financial services impersonation domains on a single GTHost IP suggests bust-out monetization infrastructure. The btc.glass cryptocurrency interface maps to P5 crypto conversion, while bridgecredit.org impersonates legitimate lending services relevant to P4 loan application fraud. The file sharing service (fex.plus) may facilitate document exchange for fraudulent applications.

## References

- Federal Reserve: "Synthetic Identity Fraud in the U.S. Payment System" (2021)
- OCC Bulletin on Synthetic Identity Fraud Risk
- Socure: Synthetic Identity Fraud Report
- ACFE: "The Growing Threat of Synthetic Identity Fraud"

## Revision History

| Date | Author | Change |
|------|--------|--------|
| 2026-02-12 | FLAME Project | Initial submission |

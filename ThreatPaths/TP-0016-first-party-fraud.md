# TP-0016: First-Party Fraud (Bust-Out)

```yaml
---
id: TP-0016
title: "First-Party Fraud (Bust-Out)"
category: ThreatPath
date: 2026-02-20
author: "FLAME Project"
source: "Internal Knowledge Base"
tlp: WHITE
sector:
  - banking
  - credit-union
fraud_types:
  - first-party-fraud
  - bust-out
cfpf_phases:
  - P1
  - P3
  - P4
  - P5
mitre_attack: []
ft3_tactics: ["FTA001", "FTA002", "FTA003", "FTA005", "FTA006", "FTA007", "FTA009", "FTA010", "FT023", "FT035", "FT022", "FT036", "FT032", "FT011", "FT016", "FT012", "FT015", "FT017"]
mitre_f3: []
groupib_stages:
  - "Reconnaissance"
  - "Perform Fraud"
  - "Monetization"
tags:
  - first-party
  - credit-card
  - consumer-banking
---
```

---

## Summary

First-party fraud occurs when an individual intentionally misrepresents their identity, intent, or financial situation to obtain credit or services with no intention of repayment. This threat path focuses on the "bust-out" variation, where a customer establishes a seemingly legitimate relationship with an institution, uses the account normally for a period, and then suddenly maximizes their credit utilization before abandoning the account.

---

## Threat Path Hypothesis

> **Hypothesis**: A legitimate customer (or a synthetic identity acting indistinguishably from a legitimate customer) will slowly build a positive credit profile, then engage in sudden, high-velocity borrowing across multiple credit products, maximizing utilization and withdrawing cash or equivalents, with no intention of repayment.

**Confidence**: High — based on established banking typologies for credit risk management and consumer fraud.

**Estimated Impact**: Ranging from $5k to $100k+ per individual depending on credit limits. Often coordinated by professional bust-out rings resulting in aggregate losses in the millions.

---

## CFPF Phase Mapping

### Phase 1: Recon

| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P1-002: Domain infrastructure | Actors study institutional credit limit increase policies, billing cycles, and over-limit tolerances. | Application velocity; repeated inquiries on credit bureau files |

**Data Sources**: External credit bureau data, account opening records.

---

### Phase 3: Positioning

| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P3-002: Modify account information | The customer steadily pays statements, sometimes overpaying, to request credit line increases and establish a 'trusted' behavioral baseline. | Steady cadence of small purchases with full payoffs; multiple requests for credit limit increases |
| CFPF-P3-003: Establish persistence | Contact information may be altered prior to the bust-out event to hinder collections efforts. | Changing phone numbers or addresses to VoIP lines or mail drops |

**Data Sources**: Account maintenance logs, customer profiles, credit limit change requests.

---

### Phase 4: Execution

| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P4-001: Unauthorized wire transfer | (In this case, Authorized but fraudulent intention) User executes rapid, high-value transactions — maximizing credit cards, drawing down lines of credit, or taking cash advances. | Sudden spike in utilization ratio (e.g., from 10% to 95% in <24 hours); high-frequency cash advance activity |

**Data Sources**: Transaction processing systems, ATM logs, authorization networks.

---

### Phase 5: Monetization

| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P5-001: Wire to domestic mule account | Cash withdrawals are deposited into untraceable assets or moved out of the financial system. Purchases of high-value resalable goods (electronics, luxury items). | Merchant category codes (MCCs) skewed toward electronics, jewelry, or cash equivalents |

**Data Sources**: Transaction MCC analysis, withdrawal metadata.

---

## Look Left / Look Right Analysis

**Discovery Phase**: Typically discovered in **Phase 5 (Monetization)** or during collections (post-event) when statements go unpaid.

**Look Left** (what was missed before discovery):

- **P4 → P3**: Could the rapid utilization spike be predicted? Yes, by tracking the ratio of overpayments or the frequency of credit limit increases shortly before the utilization event.
- **P3**: Sudden changes to contact information combined with a recent limit increase is a leading indicator.

**Look Right** (predicted next steps if uninterrupted):

- The actor will abandon the identity and likely create new synthetic identities to repeat the cycle at other institutions.
- The debt will roll into charge-off status.

---

## Controls & Mitigations

| Phase | Control | Type | Owner |
|-------|---------|------|-------|
| P1 | Enhanced identity verification during onboarding | Preventive | Fraud Strategy |
| P3 | "Velocity" checks on credit limit increase requests | Preventive | Credit Risk |
| P3 | Alert on contact info changes preceding high-value draws | Detective | Fraud Ops |
| P4 | Real-time monitoring for rapid utilization spikes (Sleep/Wake pattern) | Detective | Fraud Ops |
| P5 | Block or review high-velocity cash advances | Preventive | Transaction Monitoring |

---

## Detection Approaches

### Queries / Rules

**SQL — Rapid Utilization Spike (Bust-Out Indicator)**

```sql
SELECT 
    c.customer_id, 
    c.account_id, 
    c.credit_limit, 
    SUM(t.amount) as total_drawn,
    (SUM(t.amount) / c.credit_limit) as utilization_ratio
FROM credit_accounts c
JOIN transactions t ON c.account_id = t.account_id
WHERE t.transaction_date >= CURRENT_DATE - INTERVAL '3 days'
GROUP BY 1, 2, 3
HAVING SUM(t.amount) / c.credit_limit > 0.85 
   AND c.account_age_days > 180 -- Established accounts
   AND c.historical_avg_utilization < 0.30; -- Previously low-balance
```

### Behavioral Analytics

- **Sleep/Wake Pattern Detection**: Alert on accounts that maintain low activity for 6+ months followed by a sudden burst of high-value transactions.
- **Payment Behavior**: Flag instances of repeated overpayments (often using bad checks) meant to temporarily artificially inflate available credit.

---

## References

- FLAME Project Internal Knowledge Base.
- Industry typologies for First-Party and Synthetic Fraud.

---

## Revision History

| Date | Author | Change |
|------|--------|--------|
| 2026-02-20 | FLAME Project | Initial creation |

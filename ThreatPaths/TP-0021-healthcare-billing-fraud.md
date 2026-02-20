# TP-0021: Healthcare Provider Billing Fraud

```yaml
---
id: TP-0021
title: "Healthcare Provider Billing Fraud"
category: ThreatPath
date: 2026-02-20
author: "FLAME Project"
source: "Internal Knowledge Base"
tlp: WHITE
sector:
  - healthcare
  - insurance
fraud_types:
  - healthcare-fraud
  - phantom-billing
  - upcoding
cfpf_phases:
  - P3
  - P4
  - P5
mitre_attack: []
ft3_tactics: []
mitre_f3: []
groupib_stages:
  - "Trust Abuse"
  - "Perform Fraud"
  - "Monetization"
tags:
  - medicare-fraud
  - medical-billing
  - upcoding
  - phantom-billing
---
```

---

## Summary

Healthcare Provider Billing Fraud involves legitimate or seemingly legitimate medical providers intentionally submitting false or inflated claims to health insurance networks or government programs (like Medicare/Medicaid) for financial gain. This typically takes the form of "phantom billing" (billing for services never rendered), "upcoding" (billing for a more expensive service than provided), or "unbundling" (billing stages of a procedure separately to increase total payout).

---

## Threat Path Hypothesis

> **Hypothesis**: A medical provider or a synthetic clinic will obtain patient demographic data (often through theft, bribery, or providing trivial kickbacks), submit claims for high-value procedures that were never performed or unnecessarily prescribed, and route the insurance payouts to corporate bank accounts before authorities recognize the anomaly.

**Confidence**: High — This is a systemic issue within the U.S. healthcare system, costing tens of billions of dollars annually.

**Estimated Impact**: Aggregate losses to insurers and government programs run into the billions. Individual organized fraud rings routinely steal $1M to $50M+ before detection.

---

## CFPF Phase Mapping

### Phase 3: Positioning

| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P3-001: Data Generation | Actors acquire patient Medicare numbers or private insurance IDs (via kickbacks to nursing homes, data breaches, or telemarketing scams) to generate patient lists for fake billing. | Unusual volumes of out-of-network or distant-geography patients mapped to a single provider. |
| CFPF-P3-002: Clinic Setup | Establishing a "shell" clinic or DME (Durable Medical Equipment) supplier solely designed to route fraudulent claims. | Clinics registered to residential addresses; sudden burst of credentialing requests to insurance networks. |

**Data Sources**: Provider credentialing databases, patient geography analysis.

---

### Phase 4: Execution

| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P4-001: Claim Submission | The provider bulk-submits claims using specialized CPT (Current Procedural Terminology) codes known to have high reimbursement rates and low immediate audit rates. | Statistical deviations in CPT code usage compared to peer providers of the same specialty. |
| CFPF-P4-002: Upcoding | Provider systematically alters diagnosis codes to justify more expensive procedures. | Impossible combinations of procedures (e.g., billing 30 hours of therapy in a 24-hour period); generic templates applied to diverse patients. |

**Data Sources**: Claims processing systems (EDI 837), medical coding analytics platforms.

---

### Phase 5: Monetization

| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P5-001: Commercial Payout & Laundering | The insurer pays the claims into the clinic's bank account. Fraud rings immediately sweep the funds via wire transfers to shell companies, offshore accounts, or luxury goods purchases. | High-volume commercial ACH deposits from Medicare followed by immediate outgoing international wires or crypto purchases. |

**Data Sources**: Bank treasury logs, AML transaction monitoring.

---

## Look Left / Look Right Analysis

**Discovery Phase**: Usually discovered at **Phase 4 or 5** via statistical outlier analysis of claims data (post-payment audit) or when patients receive an Explanation of Benefits (EOB) reporting procedures they never had and complain to the insurer.

**Look Left**:

- **P4 → P3**: Were proper site visits conducted during provider credentialing? Shell clinics often lack basic medical infrastructure.
- **P4**: Predictive analytics on claims submissions should flag "impossible" billing metrics (e.g., a single doctor billing 24+ hours of active procedures in one calendar day).

**Look Right**:

- Fraudulent providers will "burn out" the clinic, close the bank accounts, abandon the LLC, and reconstitute under a new Tax ID in a different state to evade SIU (Special Investigation Unit) recovery efforts.

---

## Controls & Mitigations

| Phase | Control | Type | Owner |
|-------|---------|------|-------|
| P3 | Enhanced vetting and site verification for new DME suppliers and clinics | Preventive | Provider Credentialing |
| P4 | Pre-payment statistical auditing of claims (flagging high-risk CPT codes) | Preventive | Claims Processing / SIU |
| P4 | "Impossible Day" logic implemented in claims adjudication engines | Preventive | IT / Engineering |
| P5 | FI AML rules targeting healthcare providers making luxury/crypto expenditures | Detective | Bank AML/BSA |

---

## Detection Approaches

### Queries / Rules

**SQL — "Impossible Day" Logic (Overbilling Indicator)**

```sql
SELECT 
    p.national_provider_identifier,
    p.provider_name,
    c.date_of_service,
    SUM(c.estimated_procedure_minutes) as total_minutes_billed
FROM healthcare_claims c
JOIN providers p ON c.provider_id = p.provider_id
WHERE c.date_of_service >= CURRENT_DATE - INTERVAL '30 days'
GROUP BY 1, 2, 3
HAVING SUM(c.estimated_procedure_minutes) > 1080 -- 18 hours of direct patient care
ORDER BY total_minutes_billed DESC;
```

### Behavioral Analytics

- **Peer Group Outlier Detection**: Clustering providers by specialty and geography, then flagging providers whose billing volume for specific lucrative codes (e.g., allergy testing, complex genetic screening, durable medical equipment) is > 3 standard deviations above the peer mean.

---

## References

- FLAME Project Internal Knowledge Base.
- U.S. Department of Justice (DOJ) National Health Care Fraud Takedown reports.
- Medicare Fraud Strike Force Typologies.

---

## Revision History

| Date | Author | Change |
|------|--------|--------|
| 2026-02-20 | FLAME Project | Initial creation |

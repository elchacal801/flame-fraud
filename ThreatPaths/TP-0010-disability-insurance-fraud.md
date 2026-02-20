# TP-0010: Disability Insurance Fraud via Fabricated Medical Documentation

```yaml
---
id: TP-0010
title: "Disability Insurance Fraud via Fabricated Medical Documentation"
category: ThreatPath
date: 2026-02-12
author: "FLAME Project"
source: "DOJ prosecution records / Coalition Against Insurance Fraud / industry experience"
tlp: WHITE
sector:
  - insurance
fraud_types:
  - fraudulent-claim
  - disability-fraud
  - provider-fraud
cfpf_phases: [P1, P2, P3, P4, P5]
mitre_attack: []
ft3_tactics: []                  # Stripe FT3 (when mapped)
mitre_f3: []                     # MITRE F3 (placeholder)
groupib_stages:
  - "Reconnaissance"
  - "Resource Development"
  - "Trust Abuse"
  - "Perform Fraud"
  - "Monetization"
tags:
  - disability
  - group-benefits
  - medical-documentation
  - provider-collusion
  - claims-fraud
  - long-tail
---
```

## Summary

Actors file fraudulent long-term or short-term disability claims using fabricated, exaggerated, or collusively obtained medical documentation. Schemes range from individual claimants exaggerating symptoms with a complicit provider to organized rings where providers generate documentation for dozens of fictitious or exaggerated claims. DOJ prosecutions reveal schemes lasting years with cumulative payouts in the millions. The long-tail nature of disability payments means a single fraudulent claim can generate $100,000+ in benefits before detection.

## Threat Path Hypothesis

> **Hypothesis**: Actors — either individual claimants with provider collusion or organized fraud rings — are submitting disability claims supported by fabricated or materially misleading medical documentation, exploiting the inherent information asymmetry between treating providers and insurance carrier claims reviewers.

**Confidence**: High — established fraud category with extensive DOJ prosecution history and industry loss data.
**Estimated Impact**: $20,000 – $2,000,000+ per claim (long-term disability claims can pay for years). Organized rings generate $5M-$50M+.

## CFPF Phase Mapping

### Phase 1: Recon

| Technique | Description | Indicators |
|-----------|-------------|------------|
| Policy benefit analysis | Identify employers with generous disability coverage, understand elimination periods, benefit formulas, and definition of disability provisions | Targeted applications to employers with rich benefits; inquiries about disability policy details during onboarding |
| Provider recruitment | Identify or recruit medical providers willing to fabricate or exaggerate documentation. Some providers are unwitting (patient manipulates symptoms); others are actively complicit. | Providers with disproportionate claim volume; providers previously flagged for documentation quality issues |
| Occupational targeting | Target occupations where disability is harder to objectively verify — subjective conditions (chronic pain, mental health, fatigue syndromes) in sedentary occupations | Claim concentration in specific subjective diagnosis categories |

### Phase 2: Initial Access

| Technique | Description | Indicators |
|-----------|-------------|------------|
| Claim filing | Submit disability claim with supporting medical documentation from treating provider. Initial filing often cites acute event (injury, surgery) but transitions to chronic subjective condition. | Claim filed shortly after policy effective date; claim diagnosis difficult to objectively verify; initial documentation unusually thorough (suggests pre-preparation) |
| CFPF-P2-009: Insider access (variant) | In some schemes, HR or benefits administrators collude to file claims on behalf of fictitious employees or to backdate coverage | Claims from employees with minimal employment history; claims coinciding with recent enrollment |

### Phase 3: Positioning

| Technique | Description | Indicators |
|-----------|-------------|------------|
| Documentation chain construction | Build a medical record trail supporting ongoing disability — regular office visits, imaging, referrals — creating a paper trail that's difficult to challenge | Unusually consistent documentation cadence; provider notes that read as template-driven; diagnoses that escalate in severity timed to elimination period end |
| Activity concealment | Maintain appearance of disability while potentially working, traveling, or engaging in physical activity inconsistent with claimed limitations | Social media activity contradicting claimed limitations; surveillance findings; employment records at other employers |
| Physician shopping | Obtain supporting documentation from multiple providers to strengthen claim and counter IME (Independent Medical Exam) findings | Multiple providers for same condition; provider changes when existing provider offers improving prognosis |

### Phase 4: Execution

| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P4-006: Fraudulent insurance claim | Carrier approves claim based on medical documentation; benefit payments begin after elimination period. Claimant continues to provide periodic certification of ongoing disability. | Monthly/quarterly benefit payments to claimant; periodic recertification accepted based on ongoing provider documentation |
| Benefit stacking | File disability claims across multiple carriers simultaneously (employer group + individual policy + Social Security Disability) | SIU cross-referencing reveals claims at multiple carriers; SSDI award concurrent with private disability claim |

### Phase 5: Monetization

| Technique | Description | Indicators |
|-----------|-------------|------------|
| Direct benefit payment | Monthly disability benefit payments deposited to claimant's account — payments continue as long as claim remains approved | Ongoing monthly payments; claimant lifestyle inconsistent with stated level of disability |
| Provider kickback | In organized schemes, a portion of disability benefits is returned to the complicit provider as payment for fraudulent documentation | Financial relationship between claimant and provider outside of patient-provider context |

## Look Left / Look Right

**Discovery Phase**: Typically **P4** during ongoing claim management — triggered by surveillance findings, social media investigation (SIU), IME contradicting treating physician, or tip from employer/colleague. Sometimes not discovered until years into payment.

**Look Left**: Was the policy recently acquired (pre-planning indicator)? Does the provider have a pattern of supporting disability claims at higher rates than peers? Are multiple claimants from the same employer or provider?

**Look Right**: Are there claims at other carriers for the same individual? Is the claimant employed elsewhere? Does social media or open-source investigation reveal activity inconsistent with claimed disability?

## Controls & Mitigations

| Phase | Control | Type |
|-------|---------|------|
| P2 | Pre-existing condition analysis: flag claims where diagnosis predates or closely follows policy effective date | Detective |
| P2 | Provider profiling: identify providers with disproportionate claim volume or unusual approval rates | Detective |
| P3 | Predictive modeling: score claims for fraud likelihood based on diagnosis type, documentation patterns, provider history, employment tenure | Detective |
| P3 | Social media monitoring during active claims (within legal and ethical boundaries) | Detective |
| P4 | Independent Medical Examinations on high-risk claims | Detective |
| P4 | Activity checks and surveillance on outlier claims | Detective |
| P4 | Cross-carrier data sharing (index bureau checks for concurrent claims) | Detective |

## Detection Approaches

**Predictive Model — Claim Risk Scoring**

```sql
SELECT c.claim_id, c.claimant_id, c.provider_id, c.claim_amount
FROM claims c
JOIN policies p ON c.policy_id = p.policy_id
JOIN providers prov ON c.provider_id = prov.provider_id
WHERE DATEDIFF('day', p.effective_date, c.filing_date) <= 90
AND prov.risk_tier = 'High'
AND c.claim_amount > (
    SELECT PERCENTILE_CONT(0.9) WITHIN GROUP (ORDER BY claim_amount) FROM claims
);
```

**Graph Analytics — Provider Ring Detection**

```
Build provider-claimant graph:
  - Nodes: providers and claimants
  - Edges: treatment relationships
  
Flag provider nodes where:
  - Connected claimant nodes have disproportionate disability claim rate
  - Multiple connected claimants file claims within similar timeframes
  - Connected claimants share other attributes (employer, geography, referral patterns)
```

## Analyst Notes

This threat path is uniquely relevant to Unum's business as a leading disability insurance carrier. The CFPF framework maps cleanly here even though it was designed for financial institution fraud — the five phases still apply, just with different execution mechanics. The key insight is that Phase 1-2 (recon and access) may occur months or years before Phase 4 (ongoing benefit payments), making the "look left" analysis particularly valuable.

**AI/GenAI emerging risk**: Generative AI tools can now produce convincing medical documentation, clinical notes, and diagnostic narratives. This lowers the barrier for claimants to fabricate supporting documentation without provider collusion. Detection of AI-generated medical documentation is an emerging challenge.

**Cross-functional opportunity**: Claims adjusters see Phases 3-5. SIU sees Phase 4 investigation findings. Cybersecurity could contribute by monitoring for data breaches that expose policyholder information (enabling targeted claim fraud) and for AI-generated document detection.

## References

- DOJ: Various disability fraud prosecution press releases
- Coalition Against Insurance Fraud: annual reports
- NICB: Insurance Fraud Reporting
- Unum Group / industry: Claims fraud detection best practices

## Revision History

| Date | Author | Change |
|------|--------|--------|
| 2026-02-12 | FLAME Project | Initial submission |

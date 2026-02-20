# TP-0019: Business Identity Theft

```yaml
---
id: TP-0019
title: "Business Identity Theft"
category: ThreatPath
date: 2026-02-20
author: "FLAME Project"
source: "Internal Knowledge Base"
tlp: WHITE
sector:
  - banking
  - investment
fraud_types:
  - identity-theft
  - business-email-compromise
  - loan-fraud
  - account-takeover
cfpf_phases:
  - P1
  - P2
  - P3
  - P4
  - P5
mitre_attack:
  - T1566  # Phishing
  - T1589  # Gather Victim Identity Information
ft3_tactics: []
mitre_f3: []
groupib_stages:
  - "Reconnaissance"
  - "Account Access"
  - "Trust Abuse"
  - "Perform Fraud"
tags:
  - corporate-hijacking
  - commercial-banking
  - ppp-fraud-typology
  - business-loans
---
```

---

## Summary

Business Identity Theft (or Corporate Hijacking) involves threat actors impersonating a legitimate, functioning business — typically a small to medium-sized enterprise (SME) — to open financial accounts, lines of credit, or secure loans. They exploit public corporate registration details, file fraudulent amendments with the Secretary of State, and forge documents to assume the identity of corporate officers.

---

## Threat Path Hypothesis

> **Hypothesis**: Threat actors will gather public corporate filings to identify a viable business target, forge or illegitimately alter those filings (e.g., changing the registered agent or officers) with state authorities, and use the hijacked corporate identity to apply for commercial loans and bank accounts, ultimately absconding with the line of credit proceeds.

**Confidence**: High — Widely observed phenomenon, heavily popularized during pandemic-era relief programs (PPP, EIDL) and continuing to plague commercial lenders.

**Estimated Impact**: Extremely high. Average commercial loan fraud or corporate line of credit bust-out ranges from $100k to $1M+.

---

## CFPF Phase Mapping

### Phase 1: Recon

| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P1-003: Target identification | Actors scrape Secretary of State databases for businesses with excellent credit but limited online footprints (e.g., dormant holding companies, old LLCs). | (External to financial institution) |
| CFPF-P1-002: Domain infrastructure | Registration of near-identical domains for the target business to establish professional-looking email communications with lenders. | Newly registered lookalike domains associated with Secretary of State modification requests. |

**Data Sources**: Threat intelligence on newly registered domains, Secretary of State public APIs.

---

### Phase 2: Initial Access

| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P2-003: Corporate Hijacking / State Filing | The actor files an amendment with the state modifying the registered agent, address, or officers of the target LLC/Corp. | Conflict between historical Dun & Bradstreet data and recent state filings; sudden address changes in SOS databases. |

**Data Sources**: Secretary of State data, Dun & Bradstreet, LexisNexis.

---

### Phase 3: Positioning

| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P3-001: New Account Opening | Using the hijacked state filings, forged EIN letters, and lookalike domains, the actors apply for a commercial account or loan with a financial institution. | Application emails utilizing domains < 6 months old; mismatches between applicant's physical address IP and the registered business address. |

**Data Sources**: Commercial loan origination systems, KYC tools, device fingerprinting at application.

---

### Phase 4: Execution

| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P4-001: Loan Funding & Withdrawal | The institution approves the fake officer and funds the commercial loan or line of credit. The actor immediately requests a wire transfer out of the institution. | First-time commercial draw requests for the maximum allowable amount immediately following account opening. |

**Data Sources**: Loan management systems, commercial treasury management platforms.

---

### Phase 5: Monetization

| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P5-001: Wire to domestic mule account | The loan proceeds are wired to complex webs of shell companies to launder the funds. | Wire destinations matching high-risk jurisdictions or recently opened corporate accounts. |

**Data Sources**: Wire transaction logs, AML screening networks.

---

## Look Left / Look Right Analysis

**Discovery Phase**: Frequently discovered at **Phase 4 or 5**, or later when the legitimate business owner is hit with collection notices or credit reporting issues and reports the fraud.

**Look Left**:

- **P3 → P2**: Did the financial institution rely solely on a *recent* state filing without verifying the historical chain of command? Unverified, recent amendments to an old LLC are a classic red flag.
- **P3 → P1**: Did the email domain used on the application match the age of the business? A 10-year-old business applying using a domain registered 3 weeks ago is highly anomalous.

**Look Right**:

- The hijacked entity will quickly go into delinquency, and the legitimate business owner will face severe reputational and legal hurdles to clear their name.

---

## Controls & Mitigations

| Phase | Control | Type | Owner |
|-------|---------|------|-------|
| P1 | Monitor corporate customer names against newly registered domains | Detective | Cyber Fraud |
| P2/3 | Enhanced Due Diligence on recent SOS amendments (e.g., officers changing within 60 days of application) | Preventive | Commercial Underwriting |
| P3 | Domain age checks: Auto-flag commercial applications using emails on domains < 1 year old | Preventive | Loan Origination |
| P4 | Out-of-band verification (using historical phone numbers from credit bureaus, not application data) prior to funding | Preventive | Commercial Ops |

---

## Detection Approaches

### Queries / Rules

**SQL — High-Risk Commercial Application (Recent Filing + Young Domain)**

```sql
SELECT 
    a.application_id, 
    a.business_name, 
    a.applicant_email,
    d.domain_age_days,
    s.days_since_last_amendment
FROM commercial_applications a
LEFT JOIN domain_intel d ON SPLIT_PART(a.applicant_email, '@', 2) = d.domain_name
LEFT JOIN sos_data s ON a.tax_id = s.tax_id
WHERE d.domain_age_days < 180 
  AND s.days_since_last_amendment < 60
  AND a.loan_amount_requested > 50000;
```

### Behavioral Analytics

- **Cross-Reference Anomalies**: Compare the applicant's stated physical address, state filing address, and the IP geolocation of their application session. Severe divergence across these three points is highly suspect for hijacking.

---

## References

- FLAME Project Internal Knowledge Base.
- FinCEN Alerts on Business Email Compromise and Shell Companies.

---

## Revision History

| Date | Author | Change |
|------|--------|--------|
| 2026-02-20 | FLAME Project | Initial creation |

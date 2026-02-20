# TP-0015: Employment Fraud via Brand Impersonation

```yaml
---
id: TP-0015
title: "Employment Fraud via Brand Impersonation"
category: ThreatPath
date: 2026-02-19
author: "FLAME Project"
source: "domain_intel DEA investigation / FBI IC3 employment scam advisories"
tlp: WHITE
sector:
  - healthcare
  - staffing
  - employment
fraud_types:
  - impersonation
  - advance-fee-fraud
  - identity-theft
cfpf_phases: [P1, P2, P3, P4, P5]
mitre_attack: [T1566.001, T1583.001]
ft3_tactics: []
mitre_f3: []
groupib_stages:
  - "Reconnaissance"
  - "Resource Development"
  - "Trust Abuse"
  - "End-user Interaction"
  - "Perform Fraud"
  - "Monetization"
tags:
  - employment-fraud
  - brand-impersonation
  - job-scam
  - advance-fee
  - pii-harvesting
  - disposable-email
  - healthcare-staffing
---
```

## Summary

Actors impersonate legitimate employers — particularly in healthcare staffing, home care, and remote work sectors — by registering lookalike domains and creating fake job postings. Victims are "hired" through a fake onboarding process that harvests PII (SSN, banking info, government ID) for identity theft, or are charged advance fees for equipment, training, or background checks. The FBI IC3 reported $367M in employment fraud losses in 2023, with fake job scams increasing 118% year-over-year. This threat path is distinct from BEC in that the victim is the job applicant, not an employee of the impersonated company.

## Threat Path Hypothesis

> **Hypothesis**: Organized actors are registering domains that impersonate legitimate employers (particularly healthcare staffing agencies), creating fake job listings on major job boards, and using fake hiring processes to harvest PII and extract advance fees from job seekers.

**Confidence**: High — well-documented by FBI IC3, FTC, and directly observed in domain_intel investigation. Infrastructure patterns confirm organized operation.
**Estimated Impact**: $2,000 – $50,000 per victim (identity theft downstream); potential mass-scale PII harvesting affecting hundreds of applicants per campaign.

## CFPF Phase Mapping

### Phase 1: Recon

| Technique | Description | Indicators |
|-----------|-------------|------------|
| Brand target selection | Identify legitimate employers with active hiring (healthcare staffing, home care agencies, remote-first companies). Monitor job boards for active listings to clone. | Registration of domains similar to legitimate employer names |
| CFPF-P1-003: Domain infrastructure | Register lookalike domains impersonating target employer. Set up email infrastructure on separate domains for "HR" communications. | Bulk domain registration with employer name variations; email domains distinct from web domains (e.g., @newjobrequire.com for multiple "employers") |
| Job board reconnaissance | Study legitimate job postings to create convincing replicas with matching job titles, salary ranges, and requirements. | Cloned job descriptions appearing on multiple boards simultaneously |

### Phase 2: Initial Access

| Technique | Description | Indicators |
|-----------|-------------|------------|
| Fake job posting distribution | Post cloned job listings on Indeed, LinkedIn, ZipRecruiter, and social media. Use legitimate job board infrastructure to gain credibility. | Job postings from newly created employer accounts; postings that redirect to external application portals |
| CFPF-P2-001: Phishing — fake application portal | Direct applicants to lookalike employer website with online application form. Capture initial PII (name, email, phone, address, work history). | Application portals on recently registered domains; SSL certificates issued within days of first posting |
| Email-based "hiring" contact | Send interview invitations and offer letters from professional-looking email addresses on controlled domains. | HR communications from non-corporate email domains; offers extended without video/phone interview |

### Phase 3: Positioning

| Technique | Description | Indicators |
|-----------|-------------|------------|
| Fake interview process | Conduct text-based "interviews" via messaging apps or email (avoid video/voice to prevent identification). May use AI chatbots for initial screening. | Interview conducted entirely via text/chat; interviewer refuses video call; generic interview questions |
| Offer letter with PII request | Send official-looking offer letter requesting onboarding documentation: SSN, bank account for direct deposit, government ID scan, W-4 form. | Offer letter requesting SSN and banking info before any in-person contact; offer contingent on immediate document submission |
| Trust building | Reference real company details, benefits packages, and employee handbooks. May create fake employee portals for "onboarding." | Employee portals on non-corporate domains; onboarding materials copied from legitimate employer |

### Phase 4: Execution

| Technique | Description | Indicators |
|-----------|-------------|------------|
| PII harvesting | Collect SSN, banking details, government ID via "onboarding" forms. Data used for synthetic identity creation, account takeover, or sold on dark web. | Bulk PII collection without corresponding employment verification; same PII collection infrastructure used across multiple "employers" |
| Advance fee extraction | Charge victim for "equipment" (laptop, headset), "training materials," "background check fees," or "software licenses." Payment via wire transfer, gift cards, or crypto. | Equipment fees charged before start date; payment requested via non-refundable methods; "employer" ships equipment that never arrives |
| Check overpayment scheme | Send victim a fraudulent check for "equipment purchase" — victim deposits, buys equipment from actor-controlled vendor, check bounces. | Checks from unfamiliar banks; instructions to purchase from specific vendors; urgency around equipment procurement |

### Phase 5: Monetization

| Technique | Description | Indicators |
|-----------|-------------|------------|
| Identity theft | Harvested PII used to open credit accounts, file fraudulent tax returns, or create synthetic identities for bust-out schemes (see TP-0003). | Credit applications using victim's SSN from new addresses; tax returns filed from unexpected states |
| PII resale | Bulk sale of harvested PII packages (fullz) on dark web marketplaces. | Victim PII appearing in breach databases linked to employment fraud domains |
| CFPF-P5-002: Advance fee laundering | Fees collected via wire, gift cards, or crypto laundered through mule networks or converted to cryptocurrency. | Mule accounts receiving small wire transfers from multiple victims |

## Look Left / Look Right

**Discovery Phase**: Typically **P3/P4** — victim realizes fraud when "start date" passes with no contact, equipment never arrives, or employer's real HR department has no record of the hire.

**Look Left**: Were there earlier signals — the domain was recently registered? The job posting appeared on boards without the employer's knowledge? The email domain didn't match the company's actual domain? Was the interview process unusually text-only?

**Look Right**: Is the same infrastructure being used to impersonate other employers? Are the harvested identities appearing in synthetic identity fraud schemes? Are the same email domains (@newjobrequire.com pattern) being reused across campaigns?

## Controls & Mitigations

| Phase | Control | Type |
|-------|---------|------|
| P1 | Brand monitoring for lookalike domain registrations (employer-side) | Detective |
| P2 | Job board verification of employer accounts and posting authenticity | Preventive |
| P2 | Browser-based warnings for recently registered domains posing as employers | Detective |
| P3 | Applicant education: verify offers through company's official website/phone | Preventive |
| P4 | Payment processor flags for "equipment fee" patterns from employment contexts | Detective |
| P5 | Identity monitoring for applicants who submitted PII to unverified employers | Responsive |

## Detection Approaches

### Domain-Based Detection

```sql
SELECT d.domain_name, d.creation_date, d.registrar
FROM recently_registered_domains d
JOIN mx_records m ON d.domain_id = m.domain_id
JOIN ssl_certificates s ON d.domain_id = s.domain_id
WHERE d.domain_name SIMILAR TO '%(health|staffing|rightathome)%'
AND d.creation_date >= CURRENT_DATE - INTERVAL '90 days'
AND d.hosting_provider IN ('Hostinger', 'GoDaddy', 'OVH')
AND m.mx_domain != d.domain_name
AND s.issuer = 'Let''s Encrypt'
AND DATEDIFF('day', d.creation_date, s.issue_date) <= 3;
```

### Job Board Anomaly Detection

```
Flag job postings where:
  - Employer account created within 30 days of first posting
  - Job description text matches known legitimate posting with minor changes
  - Application redirects to external domain (not employer's known career page)
  - Multiple postings across locations with identical descriptions
  - Contact email domain differs from employer's known domain
```

## Operational Evidence

### EV-TP0015-2026-001: DEA Multi-Cluster Employment Fraud Infrastructure

- **Source**: domain_intel investigation 2026-02-19
- **Cluster**: 72.167.126.201 (GoDaddy, US), 51.81.93.75 (OVH, US), 84.32.84.32 (Hostinger, LT)
- **Domain Count**: Multiple domains across 3 hosting providers
- **Key Indicators**: rightathometx.com impersonating Right at Home healthcare staffing, @newjobrequire.com email infrastructure for HR communications, cross-provider hosting distribution (GoDaddy/OVH US/Hostinger), use of budget shared hosting providers
- **CFPF Phase Coverage**: P1, P2, P3, P4
- **Confidence**: High
- **Summary**: Multi-cluster employment fraud infrastructure impersonating Right at Home, a legitimate healthcare staffing agency. The rightathometx.com domain creates a convincing regional brand presence while @newjobrequire.com provides shared email infrastructure across multiple impersonation campaigns. Distribution across three hosting providers (GoDaddy, OVH US, Hostinger) provides resilience against takedowns. The pattern — brand impersonation domain on one provider, email infrastructure on another, with budget shared hosting throughout — is consistent with organized employment fraud operations targeting healthcare job seekers.

## References

- FBI IC3: Internet Crime Report 2023 — Employment/Business Fraud
- FTC: Job Scams Report (2024)
- Better Business Bureau: Employment Scam Tracker
- Right at Home: Official careers page (for brand impersonation comparison)

## Revision History

| Date | Author | Change |
|------|--------|--------|
| 2026-02-19 | FLAME Project | Initial submission with DEA investigation evidence |

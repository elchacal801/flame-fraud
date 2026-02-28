# TP-0002: Business Email Compromise — Vendor Impersonation Wire Fraud

```yaml
---
id: TP-0002
title: "Business Email Compromise — Vendor Impersonation Wire Fraud"
category: ThreatPath
date: 2026-02-12
author: "FLAME Project"
source: "FBI IC3 / FinCEN Advisory FIN-2019-A005 / multiple public reporting"
tlp: WHITE
sector:
  - banking
  - cross-sector
fraud_types:
  - BEC
  - wire-fraud
  - invoice-fraud
  - payment-diversion
cfpf_phases: [P1, P2, P3, P4, P5]
mitre_attack: [T1566.001, T1534, T1114.003, T1657]
ft3_tactics: ["FTA001", "FTA002", "FTA003", "FTA004", "FTA005", "FTA006", "FTA007", "FTA009", "FTA010", "FT052.003", "FT026.001", "FT028", "FT031", "FT012", "FT027", "FT039", "FT042.001", "FT043", "FT053.001"]                  # Stripe FT3 (when mapped)
mitre_f3: []                     # MITRE F3 (placeholder)
groupib_stages:
  - "Reconnaissance"
  - "Resource Development"
  - "Trust Abuse"
  - "Account Access"
  - "Perform Fraud"
  - "Monetization"
  - "Laundering"
tags:
  - vendor-impersonation
  - accounts-payable
  - email-compromise
  - high-value
---
```

## Summary

Threat actors compromise or spoof vendor email accounts, then impersonate the vendor to redirect legitimate invoice payments to actor-controlled accounts. BEC caused $2.9B+ in reported losses in 2023 per FBI IC3. The scheme exploits trust relationships between businesses and their vendors, often going undetected until the legitimate vendor inquires about unpaid invoices weeks or months later.

## Threat Path Hypothesis

> **Hypothesis**: Actors are compromising vendor email infrastructure or registering lookalike domains to intercept ongoing business relationships and redirect invoice payments via modified banking details, targeting accounts payable departments across all sectors.

**Confidence**: High — most-reported financial cybercrime category globally.
**Estimated Impact**: $50,000 – $5,000,000+ per incident. Median BEC loss ~$125,000.

## CFPF Phase Mapping

### Phase 1: Recon

| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P1-005: Social media recon | Identify target company's vendors, AP staff, and payment workflows via LinkedIn, corporate websites, SEC filings, press releases | Unusual profile views on AP staff LinkedIn accounts |
| CFPF-P1-003: Lookalike domain registration | Register domains resembling vendor (e.g., `vendorname-invoices.com`, `vendornarne.com`) | Domain monitoring alerts; CT log entries |
| CFPF-P1-008: Target list compilation | Build target lists of companies with known vendor relationships from public contract data, supplier directories | N/A (pre-attack) |

### Phase 2: Initial Access

| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P2-004: Email phishing | Phish vendor employees to gain access to vendor's email system, or phish target company's AP staff directly | Credential harvesting URLs in emails to vendor employees |
| CFPF-P2-007: Business email compromise | Gain access to vendor's actual email account, or establish convincing spoofed email infrastructure | Email forwarding rules created in vendor mailbox; authentication from unusual locations |

### Phase 3: Positioning

| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P3-007: Email forwarding rule | Create inbox rules in compromised vendor account to monitor invoice-related correspondence and suppress replies from legitimate vendor staff | New forwarding rules to external addresses; rules filtering keywords like "payment", "invoice", "wire" |
| CFPF-P3-008: Data exfiltration | Harvest invoice templates, payment schedules, contract terms, and AP contact details from compromised email to craft convincing impersonation | Unusual mailbox search activity; bulk email export |

### Phase 4: Execution

| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P4-004: Fraudulent invoice submission | Send modified invoice with updated banking details from compromised or spoofed vendor email. Often timed to coincide with legitimate payment cycles. | Banking detail changes on invoices; invoices from slightly different email addresses; urgency language ("updated bank details effective immediately") |

### Phase 5: Monetization

| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P5-001: Domestic wire to mule | Funds wired to domestic mule accounts, often business accounts opened with fraudulent documentation | Recently opened business accounts receiving large inbound wires |
| CFPF-P5-002: International wire | Funds wired to foreign accounts, commonly in West Africa, Southeast Asia, or Eastern Europe | Wire destinations to high-risk jurisdictions with no prior relationship |

## Evasion Techniques

| Technique | Description | Detection Signal |
|-----------|-------------|------------------|
| Strategic HTTP Redirect | Lookalike vendor domain redirects to the real vendor's website; appears legitimate in basic checks, but email from the domain reaches the attacker | FP-0007: `redirects_to_brand=True` in domain_intel |
| Geo-Targeted Content | Domain serves different content based on visitor geography — benign pages for scanners/researchers in certain regions, malicious content for targets | Manual verification required; inconsistent scan results across geolocations |

**Source**: CrowdStrike Counter Adversary Operations — typosquatting evasion research.

---

## Look Left / Look Right

**Discovery Phase**: Typically **P4/P5** — discovered when the legitimate vendor contacts the target about unpaid invoices, sometimes 30-90 days after payment diversion.

**Look Left**: Did the vendor's email account show signs of compromise (unusual login locations, forwarding rules) before the fraudulent invoice? Were there phishing campaigns targeting the vendor's employees in the weeks prior?

**Look Right**: Are there parallel BEC campaigns using the same compromised vendor email against other customers of that vendor? Is the same mule network being used across multiple BEC schemes?

## Controls & Mitigations

| Phase | Control | Type |
|-------|---------|------|
| P2 | Implement DMARC/DKIM/SPF enforcement for vendor email validation | Preventive |
| P3 | Monitor for email forwarding rule creation in M365/Google Workspace | Detective |
| P4 | Mandatory out-of-band verification (phone call to known number) for any banking detail change on invoices | Preventive |
| P4 | AP process: flag invoices where beneficiary bank differs from previous payments to same vendor | Detective |
| P5 | Wire recall procedures within 24-72 hour window | Responsive |

## Detection Approaches

**Splunk — Invoice Banking Detail Change Detection**

```spl
index=ap_system action="payment_update"
| eval prev_bank=coalesce(previous_routing_number, "none")
| where prev_bank != routing_number AND prev_bank != "none"
| table vendor_name, invoice_id, prev_bank, routing_number, modified_by, _time
```

**Email — Forwarding Rule Monitoring (M365)**

```kql
OfficeActivity
| where Operation in ("New-InboxRule", "Set-InboxRule")
| where Parameters has_any ("ForwardTo", "ForwardAsAttachmentTo", "RedirectTo")
| project TimeGenerated, UserId, Parameters, ClientIP
```

## Analyst Notes

**IC3 2024 Data:** The FBI IC3 2024 Internet Crime Report (covering 2024 incidents, released April 2025) reported $2.8B in BEC losses, making it the second-highest loss category after investment fraud. Total reported internet crime losses reached $16.6B in 2024, up 33% from 2023's $12.5B. BEC remains among the most financially damaging cybercrime categories despite a slight decline from 2023's $2.9B figure, reflecting improved corporate awareness alongside persistent attacker adaptation.

## References

- FBI IC3: "2024 Internet Crime Report" (April 2025) — annual loss and complaint statistics
- FinCEN Advisory FIN-2019-A005: "Advisory on Business Email Compromise"
- Abnormal Security: Annual BEC Trends Report

## Revision History

| Date | Author | Change |
|------|--------|--------|
| 2026-02-12 | FLAME Project | Initial submission |
| 2026-02-28 | FLAME Project | v1.5 enrichment: added Stripe FT3 tactic mappings, IC3 2024 loss figures in Analyst Notes |

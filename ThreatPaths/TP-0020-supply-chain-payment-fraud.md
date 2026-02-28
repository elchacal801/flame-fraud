# TP-0020: Supply Chain Payment Fraud

```yaml
---
id: TP-0020
title: "Supply Chain Payment Fraud"
category: ThreatPath
date: 2026-02-20
author: "FLAME Project"
source: "Internal Knowledge Base"
tlp: WHITE
sector:
  - banking
  - cross-sector
fraud_types:
  - business-email-compromise
  - vendor-impersonation
  - wire-fraud
cfpf_phases:
  - P1
  - P2
  - P3
  - P4
  - P5
mitre_attack:
  - T1566.001 # Phishing: Spearphishing Attachment
  - T1586     # Compromise Accounts
  - T1562.012 # Impair Defenses: Disable or Modify System Firewall (Inbox Rules)
ft3_tactics: ["FTA001", "FTA002", "FTA003", "FTA004", "FTA005", "FTA006", "FTA007", "FTA009", "FTA010", "FT007.009", "FT028", "FT008.002", "FT014", "FT043", "FT003", "FT031", "FT042.001", "FT052.003", "FT011.003"]
mitre_f3: []
groupib_stages:
  - "Reconnaissance"
  - "Account Access"
  - "Trust Abuse"
  - "Perform Fraud"
  - "Monetization"
tags:
  - supply-chain
  - b2b-payments
  - invoice-fraud
  - vendor-fraud
---
```

---

## Summary

Supply Chain Payment Fraud (a variant of Vendor Impersonation / BEC) involves threat actors compromising the email account of a legitimate vendor or supplier. The actors monitor email traffic to identify upcoming large invoice payments, insert themselves into the communication chain, and provide updated, fraudulent banking instructions to the buyer. When the buyer processes the invoice, the funds are wired to a threat-actor-controlled account instead of the true vendor.

---

## Threat Path Hypothesis

> **Hypothesis**: Threat actors will gain unauthorized access to a vendor's email system, observe billing cycles, intercept legitimate invoices in transit to a corporate buyer, modify the payment instructions to a mule account, and use inbox rules to hide the buyer's clarifying questions from the real vendor, resulting in the misdirection of B2B wire payments.

**Confidence**: High — This is consistently one of the most financially damaging forms of Business Email Compromise according to the FBI IC3.

**Estimated Impact**: Typically $50k to $5M+ per incident, depending on the size of the targeted supply chain relationship.

---

## CFPF Phase Mapping

### Phase 1: Recon

| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P1-003: Target identification | Actors scrape LinkedIn or corporate websites to map out supply chain relationships, identifying accounting departments at corporate buyers and account managers at vendors. | Lookalike domain registrations targeting specific vendor-buyer relationships. |

**Data Sources**: Brand monitoring, threat intelligence feeds.

---

### Phase 2: Initial Access

| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P2-001: Email Account Compromise | The actor compromises the vendor's email account via credential stuffing, phishing, or malware. | Successful logins from anomalous IP geolocations; multiple failed logins followed by success. |

**Data Sources**: Vendor's M365/Google Workspace audit logs (external to the financial institution).

---

### Phase 3: Positioning

| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P3-002: Establish persistence / Inbox manipulation | The actor sets up email forwarding rules or deletes emails to prevent the true vendor from seeing communications from the targeted buyer. | Creation of new inbox rules involving keywords ("invoice", "wire", "payment", the buyer's domain). |
| CFPF-P3-004: Payment instruction alteration | The actor sends a seemingly legitimate email from the compromised vendor account (or a lookalike domain if access is lost) providing "updated banking details" for an upcoming invoice. | Vendor master data changes in the buyer's ERP system. |

**Data Sources**: M365 Security logs, ERP audit logs.

---

### Phase 4: Execution

| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P4-001: Unauthorized wire transfer | The buyer updates their vendor master file and initiates the wire transfer or ACH payment to the new, fraudulent account. | Outbound commercial wires to accounts/banks not previously associated with the vendor's historical payment profile. |

**Data Sources**: Treasury management platform logs, corporate banking wire logs.

---

### Phase 5: Monetization

| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P5-001: Wire to domestic mule account | Funds hit the actor-controlled account and are rapidly dispersed to secondary accounts or converted to cryptocurrency. | Large inbound commercial wire followed within 24 hours by multiple sub-$10k outbound wires or crypto purchases. |

**Data Sources**: AML transaction monitoring, wire transfer logs.

---

## Look Left / Look Right Analysis

**Discovery Phase**: Frequently discovered at **Phase 5 (or weeks later)** when the true vendor follows up on the unpaid invoice, at which point the buyer realizes they paid a fraudulent account.

**Look Left**:

- **P4 → P3**: Did the buyer's accounts payable team verify the changing bank account details "out-of-band" (e.g., calling a known phone number rather than replying to the email)?
- **P3 → P2**: If the vendor had enforced MFA or impossible travel rules, the initial email compromise could have been prevented.

**Look Right**:

- Recovery of funds is often impossible if discovery takes weeks. The financial loss often leads to intense legal disputes between the buyer and vendor over who is liable for the breach.

---

## Controls & Mitigations

| Phase | Control | Type | Owner |
|-------|---------|------|-------|
| P3 | Mandatory out-of-band verification for all vendor banking detail changes | Preventive | Accounts Payable |
| P3 | Alerting on vendor master data changes in ERP systems | Detective | AP / IT Security |
| P4 | Outbound transaction monitoring comparing beneficiary against historical payees | Detective | Corporate Banking |
| P5 | Inbound transaction monitoring flagging large B2B wires into consumer accounts | Detective | Bank AML/Fraud |

---

## Detection Approaches

### Queries / Rules

**Sigma — Malicious Inbox Rule Creation (Positioning)**

```yaml
title: Supply Chain Fraud - Suspicious Inbox Rule Creation
status: active
description: Detects creation of inbox rules common in Invoice Fraud/BEC to hide communications from the victim.
logsource:
    product: m365
    service: exchange
detection:
    selection:
        operation: 'New-InboxRule'
    keywords:
        - '*invoice*'
        - '*payment*'
        - '*wire*'
        - '*bank*'
        - '*updated detail*'
    actions:
        - '*MoveToFolder*'
        - '*Delete*'
        - '*MarkAsRead*'
    condition: selection and keywords and actions
level: high
tags:
    - attack.t1562.012
    - cfpf.phase3.positioning
```

**SQL — B2B Payment to First-Time Beneficiary**

```sql
SELECT 
    t.transaction_id,
    t.originator_company_name,
    t.amount,
    t.beneficiary_name,
    t.beneficiary_routing_number,
    t.beneficiary_account_number
FROM b2b_wire_transfers t
WHERE t.amount > 50000 
  AND NOT EXISTS (
      -- Has this company ever paid this specific routing/account combo before?
      SELECT 1 FROM b2b_wire_transfers t_hist
      WHERE t_hist.originator_id = t.originator_id
        AND t_hist.beneficiary_routing_number = t.beneficiary_routing_number
        AND t_hist.beneficiary_account_number = t.beneficiary_account_number
        AND t_hist.transaction_date < CURRENT_DATE
  );
```

---

## References

- FBI IC3 2024 Internet Crime Report (BEC Statistics).
- FLAME Project Internal Knowledge Base.

---

## Revision History

| Date | Author | Change |
|------|--------|--------|
| 2026-02-20 | FLAME Project | Initial creation |

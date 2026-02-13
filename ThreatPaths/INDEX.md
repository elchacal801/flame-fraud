# FLAME Threat Path Index — Seed Collection v0.2

> 14 threat paths covering 10 fraud types across 6 sectors
> Framework-agnostic: mapped to CFPF phases with cross-references to FT3, ATT&CK, and Group-IB Fraud Matrix

## Coverage Summary

| ID | Title | Fraud Types | Sectors | CFPF Phases |
|----|-------|-------------|---------|-------------|
| TP-0001 | Treasury Management ATO via Malvertising | ATO, vishing, wire-fraud, malvertising | Banking | P1-P5 |
| TP-0002 | BEC — Vendor Impersonation Wire Fraud | BEC, wire-fraud, invoice-fraud, payment-diversion | Banking, Cross-sector | P1-P5 |
| TP-0003 | Synthetic Identity — Credit Card Bust-Out | Synthetic-identity, new-account-fraud, application-fraud | Banking, Fintech | P1-P5 |
| TP-0004 | Payroll Diversion via HR Portal Compromise | Payroll-diversion, BEC, phishing, ATO | Cross-sector | P1-P5 |
| TP-0005 | Insurance Premium Diversion via Agent Portal ATO | ATO, premium-diversion, phishing | Insurance | P1-P5 |
| TP-0006 | Real Estate Wire Fraud — Closing Scam | BEC, wire-fraud, payment-diversion, impersonation | Banking, Cross-sector | P1-P5 |
| TP-0007 | Deepfake Voice Authorization for Wire Transfer | Wire-fraud, impersonation, BEC, deepfake | Banking, Cross-sector | P1-P5 |
| TP-0008 | SIM Swap to Cryptocurrency Exchange ATO | ATO, crypto-laundering | Crypto, Fintech, Banking | P1-P5 |
| TP-0009 | Check Washing and Fraudulent Mobile Deposit | Check-fraud | Banking, Credit-union | P1-P5 |
| TP-0010 | Disability Insurance Fraud via Fabricated Medical Documentation | Fraudulent-claim, disability-fraud, provider-fraud | Insurance | P1-P5 |
| TP-0011 | Romance Scam to Money Mule Recruitment Pipeline | Romance-scam, money-mule | Cross-sector | P1-P5 |
| TP-0012 | APP Fraud — Tech Support / Bank Impersonation | Vishing, impersonation, ATO | Banking, Credit-union | P1-P5 |
| TP-0013 | Credential Stuffing to Loyalty Point / Gift Card Drain | Credential-stuffing, ATO | Fintech, Banking, Cross-sector | P1-P5 |
| TP-0014 | Insider-Enabled Account Fraud at Financial Institution | Insider-threat, collusion, ATO, data-theft | Banking, Credit-union, Insurance | P1-P5 |

## Coverage by Fraud Type

| Fraud Type | Threat Paths |
|------------|-------------|
| Account Takeover | TP-0001, TP-0004, TP-0005, TP-0008, TP-0012, TP-0013, TP-0014 |
| BEC / Invoice Fraud | TP-0002, TP-0004, TP-0006, TP-0007 |
| Wire Fraud | TP-0001, TP-0002, TP-0006, TP-0007 |
| Synthetic Identity / Application Fraud | TP-0003 |
| Check Fraud | TP-0009 |
| Insurance Claims Fraud | TP-0010, TP-0014 |
| Romance Scam / Money Mule | TP-0011 |
| Authorized Push Payment | TP-0012 |
| Credential Stuffing / Loyalty Fraud | TP-0013 |
| Insider Threat | TP-0014 |
| Deepfake / AI-Enabled | TP-0007 |
| SIM Swap | TP-0008 |
| Payroll Diversion | TP-0004 |

## Coverage by Sector

| Sector | Threat Paths |
|--------|-------------|
| Banking | TP-0001, TP-0002, TP-0006, TP-0007, TP-0008, TP-0009, TP-0012, TP-0013, TP-0014 |
| Insurance | TP-0005, TP-0010, TP-0014 |
| Credit Union | TP-0009, TP-0012, TP-0014 |
| Fintech | TP-0003, TP-0008, TP-0013 |
| Crypto | TP-0008 |
| Cross-sector | TP-0002, TP-0004, TP-0006, TP-0007, TP-0011, TP-0013 |

## Cross-Threat Path Connections

The fraud ecosystem is interconnected. Key relationships:

```
TP-0011 (Romance/Mule Recruitment) ──provides mule accounts to──▶ TP-0001, TP-0002, TP-0006, TP-0009
TP-0003 (Synthetic Identity) ──provides fraudulent accounts to──▶ TP-0009, TP-0013
TP-0014 (Insider Threat) ──provides customer data to──▶ TP-0001, TP-0005, TP-0008, TP-0012
TP-0007 (Deepfake Voice) ──enhances social engineering in──▶ TP-0001, TP-0006, TP-0012
TP-0008 (SIM Swap) ──bypasses MFA controls in──▶ TP-0001, TP-0005, TP-0013
```

## Framework Coverage Status

| Framework | Mapping Status | Notes |
|-----------|---------------|-------|
| FS-ISAC CFPF | All 14 TPs mapped | Primary organizational structure |
| MITRE ATT&CK | 12 of 14 TPs mapped | Where applicable (some fraud-only TPs lack ATT&CK equivalents) |
| Stripe FT3 | Pending | MIT-licensed JSON available for parsing |
| MITRE F3 | Awaiting release | Will map when F3 ships |
| Group-IB Fraud Matrix | 6 of 14 TPs mapped | 10-stage lifecycle; stage names referenced for interoperability |

## Gaps to Fill (Future Submissions)

Priority threat paths not yet covered:

- **Trade-based money laundering** (P5-heavy, AML-focused)
- **First-party fraud / friendly fraud** (chargebacks, return fraud)
- **Crypto investment scam platforms** (pig butchering execution variant)
- **Healthcare insurance fraud** (provider billing schemes)
- **PPP/SBA loan fraud** (government program abuse — relevant template for future crisis programs)
- **Account opening fraud via stolen business identity** (business identity theft)
- **Deepfake document fraud** (AI-generated KYC documents, medical records)
- **Supply chain payment fraud** (compromised procurement platforms)

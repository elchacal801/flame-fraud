# TP-0012: Authorized Push Payment Fraud — Tech Support / Bank Impersonation

```yaml
---
id: TP-0012
title: "Authorized Push Payment Fraud — Tech Support / Bank Impersonation"
category: ThreatPath
date: 2026-02-12
author: "FLAME Project"
source: "FBI IC3 / UK PSR APP fraud data / FTC consumer reports"
tlp: WHITE
sector:
  - banking
  - credit-union
fraud_types:
  - vishing
  - impersonation
  - account-takeover
cfpf_phases: [P1, P2, P3, P4, P5]
mitre_attack: [T1656, T1657]
ft3_tactics: ["FTA001", "FTA002", "FTA003", "FTA004", "FTA005", "FTA006", "FTA007", "FTA009", "FTA010", "FT011.002", "FT016", "FT018", "FT021", "FT028", "FT008.002", "FT052.003", "FT001", "FT003", "FT007.009"]                  # Stripe FT3 (when mapped)
mitre_f3: []                     # MITRE F3 (placeholder)
groupib_stages:
  - "Reconnaissance"
  - "Resource Development"
  - "Trust Abuse"
  - "End-user Interaction"
  - "Perform Fraud"
  - "Monetization"
  - "Laundering"
tags:
  - authorized-push-payment
  - APP-fraud
  - tech-support-scam
  - bank-impersonation
  - remote-access
  - screen-sharing
  - elder-fraud
---
```

## Summary

Actors contact victims impersonating bank fraud departments, tech support (Microsoft, Apple, Amazon), or government agencies (IRS, SSA), convincing them that their accounts are compromised and they must urgently transfer funds to a "safe account." Unlike traditional ATO, the victim themselves authorizes and executes the payment — making recovery extremely difficult. The UK's Payment Systems Regulator reported £460M+ in APP fraud losses in 2023. FBI IC3 reports tech support fraud as one of the highest-loss categories for victims over 60.

## Threat Path Hypothesis

> **Hypothesis**: Actors are impersonating bank fraud departments and tech support services to convince victims their accounts are compromised, then directing them to transfer funds to "safe" or "holding" accounts controlled by the actors, exploiting the victim's trust in institutional authority and urgency to protect their money.

**Confidence**: High — top consumer fraud category globally. Extensively documented.
**Estimated Impact**: $5,000 – $500,000 per victim. UK mandatory reimbursement rules (2024) shift liability.

## CFPF Phase Mapping

### Phase 1: Recon

| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P1-006: Callback infrastructure | Set up caller ID spoofing to display bank's legitimate phone number, tech company support number, or government agency number | VoIP infrastructure spoofing known institutional numbers |
| Pop-up ad infrastructure | Deploy browser pop-ups impersonating virus warnings or system alerts with "call this number" prompts | Malvertising campaigns on content sites targeting elder demographics |
| CFPF-P1-004: Victim data acquisition | Purchase consumer PII (name, phone, bank relationship, account details) from data brokers or breach data to make calls more convincing | Scam calls that reference specific account details or recent transactions |

### Phase 2: Initial Access

| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P2-002: Vishing — bank impersonation | Call victim from spoofed bank number: "We've detected fraudulent activity on your account. We need to help you secure your funds." | Spoofed caller ID matching victim's bank; call referencing real account details |
| CFPF-P2-002: Vishing — tech support | Pop-up or cold call: "Your computer is infected / your Amazon account was hacked / unauthorized purchase detected" → escalate to "your bank account is compromised" | Remote access tool installation (AnyDesk, TeamViewer); victim calling fake support number from pop-up |
| Remote access establishment | Convince victim to install screen-sharing or remote access software, giving actor visibility into banking sessions | AnyDesk/TeamViewer installation followed by online banking session |

### Phase 3: Positioning

| Technique | Description | Indicators |
|-----------|-------------|------------|
| Authority and urgency | Convince victim the threat is real and immediate — "If you don't move your money now, the hackers will drain your account." Transfer to fake "fraud supervisor" to add authority layers. | Multiple actors involved in same call; escalation to "supervisors"; claims of law enforcement involvement |
| "Safe account" narrative | Direct victim to transfer funds to a "safe" or "holding" account (actually actor-controlled) for "protection" while the "investigation" is completed | Victim initiating transfers they wouldn't normally make; transfers described as "temporary" |
| Coaching through controls | Talk victim through authentication challenges, transaction confirmation screens, and fraud warning prompts — "That warning is from the hackers, ignore it and click confirm" | Victim overriding fraud alerts during coached transaction |

### Phase 4: Execution

| Technique | Description | Indicators |
|-----------|-------------|------------|
| Victim-initiated wire/transfer | Victim personally authorizes wire transfer, ACH, or Zelle payment to actor's "safe" account. The victim is the authenticated, authorized user. | Wire/transfer authorized by legitimate account holder to new beneficiary; transfer during or immediately after extended phone call; victim overriding confirmation prompts |
| Multiple transactions | Actor coaches victim through multiple smaller transfers (to avoid single-transaction thresholds) or returns for additional transfers over days | Series of transfers from same victim to same or related beneficiaries; repeat transactions escalating in amount |

### Phase 5: Monetization

| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P5-001: Domestic mule | Funds sent to domestic mule accounts, rapidly redistributed | Mule accounts receiving APP fraud funds from multiple victims |
| CFPF-P5-003: Crypto conversion | Victim directed to purchase crypto and send to actor's wallet, or convert bank funds to crypto | Crypto purchases by elderly customers with no prior crypto activity |
| CFPF-P5-005: Gift cards | Victim directed to purchase gift cards and read redemption codes to actor | Large gift card purchases; victim reading card numbers over phone at POS |

## Look Left / Look Right

**Discovery Phase**: **P4/P5** — victim realizes fraud after call ends, or bank flags unusual transfer. Sometimes days later when victim contacts their "case officer" and the number is disconnected.

**Look Left**: Was there a pop-up/malvertising campaign targeting the victim's browsing profile? Were there earlier "test calls" to the victim or their geographic area? Did the bank's fraud warning trigger and get overridden?

**Look Right**: Same scam infrastructure targeting multiple victims simultaneously. Mule accounts receiving funds from multiple APP fraud victims. Victim may be re-targeted ("recovery scam" claiming to help recover initial losses).

## Controls & Mitigations

| Phase | Control | Type |
|-------|---------|------|
| P2 | Carrier-level call labeling for suspected spoofed numbers (STIR/SHAKEN) | Preventive |
| P3 | Banking app: real-time warning when customer is on phone call during transaction ("Are you being asked to make this transfer by someone on the phone?") | Preventive |
| P3 | Confirmation of Payee: verify recipient name matches account before processing | Detective |
| P4 | **Cooling off period**: mandatory delay on first-time large wire transfers to new beneficiaries | Preventive |
| P4 | Branch intervention: train tellers to recognize APP fraud indicators (elderly customer, large wire, on phone during transaction, visibly stressed) | Preventive |
| P5 | UK PSR mandatory reimbursement (shifts liability, incentivizes bank prevention investment) | Responsive |

## Detection Approaches

**Real-Time Transaction Risk Scoring**

```sql
SELECT t.transaction_id, t.account_id
FROM transactions t
JOIN active_calls c ON t.customer_phone = c.phone_number
JOIN customer_profiles cp ON t.account_id = cp.account_id
WHERE t.beneficiary_is_new = TRUE
AND t.amount > 5000
AND cp.age > 60
AND c.call_start <= t.timestamp 
AND c.call_end >= t.timestamp;
```

## Operational Evidence

### EV-TP0012-2026-001: Alibaba Cloud Mobile Sideloading Infrastructure

- **Source**: domain_intel investigation 2026-02-19
- **Cluster**: 47.88.24.103 (Alibaba Cloud, US)
- **Domain Count**: 2 key domains (deploygate.io, diawi.io)
- **Key Indicators**: mobile app sideloading platforms, Alibaba Cloud hosting, .io TLD pattern, app distribution bypassing official store review
- **CFPF Phase Coverage**: P2, P3
- **Confidence**: Medium
- **Summary**: Mobile app sideloading infrastructure hosted on Alibaba Cloud enables distribution of malicious applications outside App Store and Google Play review processes. DeployGate and Diawi are legitimate beta testing platforms, but these impersonation domains facilitate delivery of fraudulent apps used in tech support scams (P2 initial access via fake "security" or "banking" apps) and remote access establishment (P3 positioning). This infrastructure is adjacent to the core TP-0012 attack chain — actors can direct victims to sideload fake bank/support apps instead of using commercial remote access tools.

## Analyst Notes

**IC3 2024 Data:** The FBI IC3 2024 Internet Crime Report (covering 2024 incidents, released April 2025) reported $1.46B in tech support scam losses, confirming it as one of the highest-loss fraud categories. Elderly victims (60+) are disproportionately impacted, contributing to $4.9B in total IC3-reported losses across all categories in 2024. Tech support and bank impersonation scams exploit the authority trust dynamic, making them particularly effective against older demographics who are more likely to respond to unsolicited phone calls.

## References

- FBI IC3: "2024 Internet Crime Report" (April 2025) — annual loss and complaint statistics
- FBI IC3: Tech Support Fraud PSAs
- UK Payment Systems Regulator: APP Fraud Data (annual)
- FTC: Consumer Sentinel Data — Impersonation Scams
- Which?: "Authorized Push Payment Scam" investigation

## Revision History

| Date | Author | Change |
|------|--------|--------|
| 2026-02-12 | FLAME Project | Initial submission |

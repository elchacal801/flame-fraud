# TP-0005: Insurance Premium Diversion via Agent Portal ATO

```yaml
---
id: TP-0005
title: "Insurance Premium Diversion via Agent Portal ATO"
category: ThreatPath
date: 2026-02-12
author: "FLAME Project"
source: "Coalition Against Insurance Fraud / industry reporting"
tlp: WHITE
sector:
  - insurance
fraud_types:
  - account-takeover
  - premium-diversion
  - phishing
cfpf_phases: [P1, P2, P3, P4, P5]
mitre_attack: [T1566.001, T1078, T1657]
ft3_tactics: []                  # Stripe FT3 (when mapped)
mitre_f3: []                     # MITRE F3 (placeholder)
groupib_stages:
  - "Reconnaissance"
  - "Resource Development"
  - "Trust Abuse"
  - "Account Access"
  - "Perform Fraud"
  - "Monetization"
tags:
  - insurance-agent
  - agent-portal
  - premium-trust-account
  - policy-servicing
---
```

## Summary

Actors compromise insurance agent portals to modify policy payment routing, diverting premium payments from policyholders to actor-controlled accounts. Alternatively, actors gain access to agent trust accounts where premiums are held before remittance to the carrier. This scheme exploits the distributed nature of insurance distribution — independent agents operate semi-autonomously with significant system access. Discovery is often delayed because policyholders believe they've paid and carriers may not flag gaps until policy cancellation for non-payment.

## Threat Path Hypothesis

> **Hypothesis**: Actors are compromising independent insurance agent portal credentials to modify premium payment routing or access agent trust accounts, diverting policyholder premium payments and creating coverage gaps that may not be discovered until a claim is filed.

**Confidence**: Medium — confirmed incidents but less publicly documented than banking fraud. Insurance sector underreports cyber-enabled fraud.
**Estimated Impact**: $10,000 – $500,000 per compromised agency. Coverage gap liability potentially much higher.

## CFPF Phase Mapping

### Phase 1: Recon

| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P1-005: Social media / web recon | Identify independent insurance agencies and their carrier relationships from agency websites, state licensing databases, and industry directories | Scraping of state insurance commissioner databases |
| CFPF-P1-007: Credential acquisition | Purchase agent portal credentials from infostealer log marketplaces (agents often use personal devices with poor hygiene) | Agency email domains appearing in stealer log dumps |

### Phase 2: Initial Access

| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P2-004: Phishing | Spearphishing targeting agency staff with carrier-branded emails — "Portal migration", "Commission statement available", "License renewal required" | Phishing emails mimicking specific carrier communications |
| CFPF-P2-010: Infostealer malware | Agent's personal/business device infected with infostealer, capturing portal session cookies and credentials | Stealer log entries containing carrier portal URLs |
| CFPF-P2-005: Credential stuffing | Automated login attempts against carrier agent portals using breached credentials | Login anomalies on agent portal; failed auth spikes |

### Phase 3: Positioning

| Technique | Description | Indicators |
|-----------|-------------|------------|
| Payment routing modification | Modify EFT/ACH routing for premium remittance from agent trust account to carrier | Bank routing changes on agent accounts; changes from unusual sessions |
| Policy servicing manipulation | Modify policyholder payment methods, add new payment destinations, or change policy billing addresses | Policy changes from agent sessions with anomalous device/IP; changes across multiple policies in bulk |
| CFPF-P3-004: Disable alerts | Turn off agent notifications for payment discrepancies or policy status changes | Notification preference changes on agent account |

### Phase 4: Execution

| Technique | Description | Indicators |
|-----------|-------------|------------|
| Premium payment diversion | Policyholder premium payments routed to actor-controlled account instead of carrier | Premiums not received by carrier despite policyholder payment; agent trust account discrepancies |
| Fraudulent policy servicing | Issue unauthorized policy changes, endorsements, or cancellations to extract cash value or create refund payments | Unusual policy change volume from agent; cash value withdrawals; refund checks to non-policyholder addresses |

### Phase 5: Monetization

| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P5-001: Domestic wire/ACH | Diverted premiums sent to mule accounts via the modified payment routing | ACH deposits to accounts with no insurance industry relationship |
| CFPF-P5-007: Digital payment | Refund payments or cash value withdrawals directed to digital payment platforms | Policy refund checks deposited via mobile to non-policyholder accounts |

## Look Left / Look Right

**Discovery Phase**: Typically **P4** — carrier notices premium gap when policy is flagged for cancellation due to non-payment (30-90 day lag). Or policyholder files a claim on a lapsed policy.

**Look Left**: Were there login anomalies on the agent portal? Did the agent's credentials appear in any stealer log feeds? Were there phishing campaigns targeting agencies associated with the carrier?

**Look Right**: Are multiple agencies compromised in the same campaign? Are policyholders aware their coverage may have lapsed? What is the carrier's liability for claims filed during the coverage gap?

## Controls & Mitigations

| Phase | Control | Type |
|-------|---------|------|
| P2 | MFA enforcement on all agent portal access | Preventive |
| P2 | Credential monitoring: alert when agent email domains appear in stealer log feeds | Detective |
| P3 | Out-of-band verification for any payment routing changes on agent accounts | Preventive |
| P3 | Anomaly detection on agent session patterns (device, IP, time-of-day, action velocity) | Detective |
| P4 | Automated premium reconciliation: flag policies where expected premiums don't match received | Detective |
| P4 | Policyholder confirmation for any servicing changes initiated through agent portal | Preventive |

## Detection Approaches

**SQL — Agent Portal Payment Routing Anomaly**

```sql
SELECT agent_id, agency_name, 
       old_routing_number, new_routing_number,
       change_timestamp, session_ip, device_fingerprint
FROM agent_payment_changes
WHERE change_timestamp >= CURRENT_DATE - INTERVAL '30 days'
  AND old_routing_number != new_routing_number
  AND session_ip NOT IN (SELECT known_ip FROM agent_known_locations WHERE agent_id = agent_payment_changes.agent_id)
ORDER BY change_timestamp DESC;
```

## Analyst Notes

This threat path is particularly relevant for insurance carriers because the agent distribution model creates a massive, distributed attack surface. Independent agents may have 10+ carrier portal credentials, often on personal devices without endpoint protection. The insurance sector's delayed detection cycle (premium non-payment takes 30-90 days to trigger cancellation) gives actors significantly more operational time than banking fraud.

**Disability/group benefits variant**: For disability and group life carriers, the agent portal ATO could target employer-level billing — diverting employer premium payments creates coverage gaps affecting hundreds of employees under a single group policy.

## References

- Coalition Against Insurance Fraud: Annual Report
- NAIC: Cybersecurity and Insurance Fraud Whitepaper
- State insurance commissioner enforcement actions (various)

## Revision History

| Date | Author | Change |
|------|--------|--------|
| 2026-02-12 | FLAME Project | Initial submission |

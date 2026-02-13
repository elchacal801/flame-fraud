# TP-0013: Credential Stuffing to Loyalty Point / Gift Card Account Drain

```yaml
---
id: TP-0013
title: "Credential Stuffing to Loyalty Point / Gift Card Account Drain"
category: ThreatPath
date: 2026-02-12
author: "FLAME Project"
source: "Akamai State of the Internet reports / industry reporting"
tlp: WHITE
sector:
  - fintech
  - banking
  - cross-sector
fraud_types:
  - credential-stuffing
  - account-takeover
cfpf_phases: [P1, P2, P3, P4, P5]
mitre_attack: [T1110.004, T1078, T1657]
ft3_tactics: []                  # Stripe FT3 (when mapped)
mitre_f3: []                     # MITRE F3 (placeholder)
groupib_stages:               # Group-IB Fraud Matrix (reference)
  - "Reconnaissance"           # Gather Compromised Account, Buy Compromised Accounts
  - "Resource Development"     # Anonymity Capabilities
  - "Account Access"           # Access from Fraudster Device
  - "Defence Evasion"          # Device Fingerprint Spoofing, Virtual Machines, Geolocation Spoofing, VPN/Proxy/Hosting Services
  - "Monetization"             # Sale of Compromised Credentials to 3rd Party
tags:
  - loyalty-fraud
  - rewards-points
  - gift-card
  - stored-value
  - automated-attack
  - credential-reuse
---
```

## Summary

Actors use large-scale credential stuffing (automated testing of stolen username/password pairs from unrelated breaches) against loyalty program portals, bank rewards platforms, and gift card balance-check sites. Successful logins are used to drain stored value — transferring loyalty points to actor-controlled accounts, converting rewards to gift cards, or transferring gift card balances. Loyalty points and gift cards are attractive targets because they're less monitored than bank accounts, rarely have MFA, and can be monetized quickly through resale markets. Akamai reports billions of credential stuffing attempts per year targeting financial services.

## Threat Path Hypothesis

> **Hypothesis**: Actors are conducting automated credential stuffing at scale against loyalty program and rewards platforms to identify accounts with stored value, then draining points/balances through redemption, transfer, or gift card conversion — exploiting weak authentication on "non-financial" portals that hold significant monetary value.

**Confidence**: High — Akamai, Shape Security, and PerimeterX document billions of credential stuffing attempts annually.
**Estimated Impact**: $50 – $5,000 per account (lower individual value, massive volume). Programs lose $1B+ annually to points fraud.

## CFPF Phase Mapping

### Phase 1: Recon
| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P1-004: Credential list acquisition | Purchase combo lists (email:password pairs) from dark web markets, sourced from previous data breaches | Credential dumps containing emails associated with loyalty programs |
| Target portal identification | Identify loyalty programs and rewards platforms with: no MFA, high stored value, transferable points, gift card redemption options | Reconnaissance against login endpoints; API enumeration |
| Tool/infrastructure setup | Configure credential stuffing tools (OpenBullet, SentryMBA, custom scripts) with target-specific configs, CAPTCHA-solving services, and residential proxy networks | Bulk proxy purchases; CAPTCHA-solving service subscriptions |

### Phase 2: Initial Access
| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P2-005: Credential stuffing | Automated testing of millions of credential pairs against target portal. Success rates typically 0.1-2% but yield thousands of valid accounts at scale. | Login attempt velocity spikes; distributed source IPs (residential proxies); high failure-to-success ratio; user-agent anomalies |
| Valid account access | Successful logins used to check account balances and identify high-value targets for draining | Authenticated sessions with immediate balance-check and no other activity |

### Phase 3: Positioning
| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P3-003: Contact info modification | Change email/notification preferences to prevent legitimate account holder from receiving redemption alerts | Contact info changes from new IPs immediately after first login from that IP |
| Account inventory | Catalog compromised accounts by balance/value; prioritize highest-value for draining | Rapid sequential access to multiple accounts from same IP range; balance-check-only sessions |

### Phase 4: Execution
| Technique | Description | Indicators |
|-----------|-------------|------------|
| Points transfer | Transfer loyalty points to actor-controlled accounts within the same program | Point transfers to accounts with no relationship to transferring account; bulk transfers from multiple source accounts to single destination |
| Gift card redemption | Convert loyalty points to digital gift cards (Amazon, Visa, etc.) delivered to actor-controlled email | Gift card redemptions to new/changed email addresses; bulk redemptions across multiple accounts in short window |
| Stored value transfer | Transfer gift card balances to other cards or mobile payment platforms | Balance transfers from gift card checking portals |

### Phase 5: Monetization
| Technique | Description | Indicators |
|-----------|-------------|------------|
| Gift card resale | Sell redeemed gift cards on secondary markets (CardCash, Raise, Telegram channels) at 60-80% face value | Gift cards appearing on resale platforms shortly after redemption |
| Direct purchase | Use redeemed gift cards for purchases of high-resale-value items (electronics, luxury goods) | Shipping addresses different from account addresses |
| CFPF-P5-003: Crypto conversion | Convert gift card values to cryptocurrency through gift-card-to-crypto exchange services | Gift card codes exchanged on Paxful, Bitrefill, or similar platforms |

## Cross-Framework Mapping

**Group-IB Fraud Matrix technique-level mapping** (corroborated via Group-IB Fraud Intelligence report: "Credentials Stuffing using BAS"):

| Group-IB Stage | Techniques Used |
|---------------|----------------|
| Reconnaissance | Gather Compromised Account, Buy Compromised Accounts |
| Resource Development | Anonymity Capabilities |
| Account Access | Access from Fraudster Device |
| Defence Evasion | Device Fingerprint Spoofing, Virtual Machines, Geolocation Spoofing, VPN/Proxy/Hosting Services |
| Monetization | Sale of Compromised Credentials to 3rd Party |

**Notable Group-IB intelligence additions:**
- **Browser Automation Studio (BAS)** is a primary tooling platform for credential stuffing. BAS functions as a visual IDE for creating stuffing scripts, with integrated CAPTCHA-solving modules, phone verification services, and the ability to compile scripts into standalone executables for distribution to other actors. The BAS ecosystem (Bablosoft) provides purpose-built infrastructure for this attack chain.
- A critical detection-evasion technique involves **stolen device fingerprint reuse**: actors import legitimate user fingerprints into BAS, making automated login attempts appear to originate from real user devices. This has a secondary victim impact — legitimate users whose fingerprints are reused may be wrongfully blocked by fraud protection systems that flag their device profiles as high-risk.
- BAS operates on the **Chromium Embedded Framework (CEF)**, which makes its browser behavior closely mimic legitimate Chrome sessions. Detection should focus on browser API inconsistencies, anomalous device characteristics, and behavioral patterns rather than simple user-agent analysis.
- The credential stuffing supply chain is now industrialized: actors can purchase pre-built BAS configs for specific target websites on darknet markets, lowering the skill barrier for entry.

**MITRE ATT&CK:**
- T1110.004: Credential Stuffing
- T1078: Valid Accounts
- T1657: Financial Theft

## Controls & Mitigations

| Phase | Control | Type |
|-------|---------|------|
| P2 | **Implement MFA on loyalty/rewards portals** (even basic SMS MFA dramatically reduces credential stuffing success) | Preventive |
| P2 | Rate limiting and CAPTCHA on login endpoints; bot detection (device fingerprinting, behavioral analysis) | Preventive |
| P2 | Credential breach monitoring: proactively reset passwords for accounts whose credentials appear in breach dumps | Preventive |
| P3 | Alert account holders on email/contact changes and point redemptions | Detective |
| P4 | Velocity limits on point transfers and gift card redemptions | Preventive |
| P4 | Flag bulk redemptions from accounts with no prior redemption history | Detective |

## Detection Approaches

**WAF / API Gateway — Credential Stuffing Detection**
```
Flag traffic where:
  - Login failure rate from source IP/subnet > 95% AND
  - Successful logins show immediate balance-check behavior AND
  - Source uses residential proxy IP ranges AND
  - User-agent or TLS fingerprint matches known stuffing tools
```

**Post-Auth — Account Drain Pattern**
```sql
SELECT account_id, 
       SUM(points_redeemed) as total_redeemed,
       COUNT(DISTINCT gift_card_id) as cards_generated,
       MIN(session_ip) as source_ip
FROM redemption_log
WHERE redemption_date >= CURRENT_DATE - INTERVAL '7 days'
GROUP BY account_id
HAVING total_redeemed > 10000  -- threshold
   AND cards_generated > 2
   AND source_ip NOT IN (SELECT known_ip FROM account_known_ips WHERE account_id = redemption_log.account_id)
ORDER BY total_redeemed DESC;
```

**Browser Automation Studio (BAS) Detection Indicators**
```
Flag sessions where:
  - Browser fingerprint matches known stolen fingerprint from breach databases AND
  - Login source IP is residential proxy or VPN AND
  - Session exhibits automated timing patterns (consistent inter-request intervals)
  
  OR
  
  - Chromium Embedded Framework (CEF) artifacts detected in browser API responses AND
  - WebGL/Canvas fingerprint shows inconsistencies with declared user-agent AND
  - Multiple accounts accessed from same underlying device within short timeframe
```

## References
- Akamai: State of the Internet — Credential Stuffing Reports
- Shape Security (F5): Credential Spill Report
- Loyalty Security Alliance: Points Fraud Prevention
- OWASP: Credential Stuffing Prevention Cheat Sheet
- Group-IB Fraud Intelligence: "Credentials Stuffing using BAS" scheme report (BAS tooling analysis, technique-level Fraud Matrix mapping)

## Revision History
| Date | Author | Change |
|------|--------|--------|
| 2026-02-12 | FLAME Project | Initial submission |

# TP-0007: Deepfake Voice Authorization for Wire Transfer

```yaml
---
id: TP-0007
title: "Deepfake Voice Authorization for Wire Transfer"
category: ThreatPath
date: 2026-02-12
author: "FLAME Project"
source: "Wall Street Journal (2019 UK energy firm case) / Regula AI deepfake fraud surveys"
tlp: WHITE
sector:
  - banking
  - cross-sector
fraud_types:
  - wire-fraud
  - impersonation
  - BEC
  - deepfake
cfpf_phases: [P1, P2, P3, P4, P5]
mitre_attack: [T1656, T1657]
ft3_tactics: ["FTA001", "FTA002", "FTA003", "FTA004", "FTA005", "FTA006", "FTA007", "FTA009", "FTA010", "FT052.003", "FT026.001", "FT020", "FT007.009", "FT016", "FT028", "FT031", "FT055", "FT008.002", "FT018"]                  # Stripe FT3 (when mapped)
mitre_f3: []                     # MITRE F3 (placeholder)
groupib_stages:               # Group-IB Fraud Matrix (reference)
  - "Reconnaissance"           # Search Closed Sources, Search Open Sources, Gather Victim Business Relationships
  - "Resource Development"     # Data Leaks, Anonymity Capabilities, Returned/One-Time Phone Number
  - "Trust Abuse"              # Recipient Impersonation, Deep voice
  - "End-user Interaction"     # Scam Message in Social Network/Instant Messenger
  - "Defence Evasion"          # Layered transactions, Shell Companies and Fronts, Payment by Legitimate Account Owner
  - "Perform Fraud"
  - "Monetization"
  - "Laundering"
tags:
  - deepfake-voice
  - CEO-fraud
  - AI-enabled
  - dual-authorization-bypass
  - emerging-threat
---
```

## Summary

Actors use AI-generated voice deepfakes to impersonate executives, clients, or authorized signers during phone-based wire transfer authorization. The first publicly documented case (2019) involved a UK energy firm's CEO impersonated via deepfake voice, resulting in a $243,000 transfer. As voice cloning technology becomes more accessible and convincing, this threat path is accelerating. It specifically targets institutions that rely on voice-based dual authorization as a fraud control — turning a security measure into an attack vector.

## Threat Path Hypothesis

> **Hypothesis**: Actors are using commercially available AI voice cloning tools to generate convincing deepfake audio of executives or authorized signers, using these to bypass phone-based wire authorization controls and social-engineer financial operations staff into processing unauthorized transfers.

**Confidence**: Medium-High — confirmed incidents, rapidly improving technology, but still relatively rare compared to traditional BEC.
**Estimated Impact**: $100,000 – $35,000,000 (Arup case, 2024). Targeting dual-authorization controls means per-incident amounts tend to be high.

## CFPF Phase Mapping

### Phase 1: Recon

| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P1-005: Executive voice harvesting | Collect audio samples of target executives from earnings calls, conference presentations, YouTube, podcasts, media interviews | Unusual access patterns to corporate media pages; social engineering to elicit voice samples |
| CFPF-P1-008: Target list / org chart mapping | Identify who has wire authorization authority and who in treasury/finance processes those requests | Corporate website, SEC filings, LinkedIn reconnaissance |
| CFPF-P1-006: Callback infrastructure | Set up phone infrastructure with caller ID spoofing to appear as executive's number or corporate main line | VoIP setup with corporate number spoofing capability |

### Phase 2: Initial Access

| Technique | Description | Indicators |
|-----------|-------------|------------|
| Deepfake voice call | Call treasury operations or wire processing team using AI-generated voice of CEO/CFO/authorized signer. Establish urgency: "I need an emergency wire processed before market close" | Call from executive during unusual hours; unusual urgency; request deviating from standard process |
| CFPF-P2-002: Vishing (enhanced) | Combine deepfake voice with social engineering knowledge from recon — reference real deals, real contacts, real deadlines to increase credibility | Caller demonstrates knowledge of internal matters but requests process exceptions |

### Phase 3: Positioning

| Technique | Description | Indicators |
|-----------|-------------|------------|
| Authority assertion | Use impersonated executive authority to override standard verification procedures — "I'm authorizing this personally, skip the usual process" | Requests to bypass controls; pushback when verification procedures are followed |
| Urgency/secrecy framing | Frame request as confidential acquisition, regulatory matter, or time-sensitive deal to prevent verification with others | "Don't discuss this with anyone else"; "This is confidential M&A activity" |

### Phase 4: Execution

| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P4-001: Unauthorized wire | Treasury/finance staff processes wire transfer based on deepfake-authorized request | Wire to new beneficiary authorized only by phone; deviation from dual-authorization log; no corresponding email trail for voice-authorized wire |

### Phase 5: Monetization

| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P5-002: International wire | Funds wired to overseas accounts (frequently Hong Kong, Singapore, UK intermediary banks) | International wire to new counterparty with no contract on file |
| CFPF-P5-001: Domestic mule layering | Funds routed through domestic business accounts before international transfer | Multi-hop wire pattern within 24-48 hours |

## Cross-Framework Mapping

**Group-IB Fraud Matrix technique-level mapping** (corroborated via Group-IB Fraud Intelligence report: "C-level impersonation Using Deepvoice"):

| Group-IB Stage | Techniques Used |
|---------------|----------------|
| Reconnaissance | Search Closed Sources, Search Open Sources, Gather Victim Business Relationships |
| Resource Development | Data Leaks, Anonymity Capabilities, Returned Phone Number, One-Time Phone Number |
| Trust Abuse | Recipient Impersonation, Deep voice |
| End-user Interaction | Scam Message in Social Network/Instant Messenger |
| Defence Evasion | Layered transactions, Shell Companies and Fronts, Payment by Legitimate Account Owner |

**Notable Group-IB intelligence additions:**

- The scheme extends beyond traditional voice calls — actors also use **messaging platforms (WhatsApp)** to deliver the impersonation, sending initial messages that establish a pretext before transitioning to deepfake voice calls
- The target chain involves **cross-organizational impersonation**: actors impersonate a C-level executive at Institution A to manipulate a C-level executive at Institution B, exploiting established business relationships between organizations
- Defence evasion is a key post-execution phase: funds are routed through **layered transactions** and **shell companies/fronts** to obscure the trail, and in some cases the victim organization's legitimate account owner is manipulated into authorizing the payment themselves (Payment by Legitimate Account Owner), further complicating attribution

**MITRE ATT&CK:**

- T1656: Impersonation
- T1657: Financial Theft

## Look Left / Look Right

**Discovery Phase**: **P4/P5** — discovered when real executive is contacted about the wire, or when wire destination is flagged by compliance. Sometimes discovered within hours (if callback verification catches it), sometimes days.

**Look Left**: Were executive voice samples recently exposed (new earnings call, conference)? Were there prior reconnaissance calls to treasury staff ("verification calls" to test processes)?

**Look Right**: Was the same deepfake voice used against other institutions? Are the destination accounts linked to other fraud schemes?

## Controls & Mitigations

| Phase | Control | Type |
|-------|---------|------|
| P1 | Limit executive audio exposure where possible (recorded earnings calls are difficult to avoid) | Preventive |
| P2 | **Never authorize wires based solely on phone calls** — require multi-channel verification (phone + email + in-person or secure messaging) | Preventive |
| P2 | Establish code word / passphrase for wire authorization that is not transmitted via email or phone (in-person exchange) | Preventive |
| P3 | Train treasury staff: any request to bypass controls or invoke secrecy is a red flag, regardless of caller identity | Preventive |
| P4 | Mandatory callback to executive on **independently verified number** (not caller-provided) before processing | Preventive |
| P4 | Voice biometric analysis on authorization calls (emerging technology) | Detective |

## Detection Approaches

**Process-Based Detection**

```sql
SELECT * FROM wire_authorizations 
WHERE auth_method = 'voice_only' 
AND amount > 50000 
AND NOT EXISTS (
    SELECT 1 FROM email_approvals WHERE wire_id = wire_authorizations.id
);
```

**Behavioral Analytics**

- Monitor for pattern of "test calls" to treasury/finance staff in weeks before a fraudulent authorization attempt — actors often probe processes before executing
- Flag wire requests that deviate from the executive's normal authorization patterns (different amounts, different beneficiaries, different times of day)

## Analyst Notes

This threat path is evolving rapidly. In 2019, deepfake voice was novel and expensive. By 2025-2026, real-time voice cloning is available through commercial APIs for under $50/month. The Arup case (2024) demonstrated a multi-person deepfake video call — the entire authorization meeting was synthetic. Controls that rely on "call them back to verify" are necessary but may not be sufficient as voice cloning improves. Organizations should move toward out-of-band verification methods that don't rely on voice.

## References

- Wall Street Journal: "Fraudsters Used AI to Mimic CEO's Voice in Unusual Cybercrime Case" (2019)
- Arup Engineering deepfake video call fraud ($25M, 2024)
- Regula: "The Deepfake Trends 2024" survey
- FS-ISAC: Generative AI in Financial Services guidance
- Group-IB Fraud Intelligence: "C-level impersonation Using Deepvoice" scheme report (technique-level Fraud Matrix mapping)

## Revision History

| Date | Author | Change |
|------|--------|--------|
| 2026-02-12 | FLAME Project | Initial submission |

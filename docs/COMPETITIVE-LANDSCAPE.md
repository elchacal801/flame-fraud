# FLAME Competitive Landscape — Fraud Framework Ecosystem

> Last updated: February 2026
> This document analyzes the fraud taxonomy and intelligence platform landscape to position FLAME within the ecosystem.

---

## The Convergence

Between April 2025 and February 2026, five organizations independently concluded that fraud needs structured taxonomy frameworks — an "ATT&CK for fraud." This convergence validates the problem space but also clarifies where the gap remains.

**The gap: everyone is building the dictionary. Nobody is building the library.**

Taxonomies define the language. FLAME provides the community knowledge exchange where practitioners use that language to share operational intelligence.

---

## Framework Comparison

### FS-ISAC Cyber Fraud Prevention Framework (CFPF)

| Attribute | Detail |
|-----------|--------|
| **Owner** | FS-ISAC, 300+ member working group |
| **Published** | April 2025 |
| **Type** | 5-phase lifecycle model |
| **Access** | TLP:WHITE paper (public) |
| **Scope** | Financial services cyber fraud |

**Lifecycle Phases:**

| Phase | Name | Focus |
|-------|------|-------|
| P1 | Recon | Target selection, infrastructure setup, OSINT |
| P2 | Initial Access | Phishing, social engineering, credential theft |
| P3 | Positioning | Account modification, persistence, data collection |
| P4 | Execution | Unauthorized transactions, fraudulent actions |
| P5 | Monetization | Funds extraction, laundering, cash-out |

**Strengths:** Practitioner-originated, strong "look left / look right" analytical methodology, sector-wide adoption potential, public availability.

**Limitations:** Framework only — no community platform, no structured technique library with IDs, no detection logic catalog. The CFPF paper explicitly calls for a "sector-wide library of threat paths" and "heat mapping feedback tool" that haven't been built.

**FLAME relationship:** Primary organizational structure. FLAME operationalizes what the CFPF envisioned but didn't build.

---

### Group-IB Fraud Matrix 2.0

| Attribute | Detail |
|-----------|--------|
| **Owner** | Group-IB |
| **Version** | 2.0 (August 2025) |
| **Type** | 10-stage lifecycle + detection/mitigation catalogs + scheme reports |
| **Access** | Commercial, vendor-gated (requires Group-IB Fraud Intelligence subscription) |
| **Scope** | Cross-industry financial fraud, heavy mobile/banking focus |
| **Adoption** | 80+ organizations |

**Lifecycle Stages:**

| # | Stage | Technique Count | CFPF Mapping |
|---|-------|----------------|--------------|
| 1 | Reconnaissance | ~35 | P1 |
| 2 | Resource Development | ~32 | P1 |
| 3 | Trust Abuse | ~17 | P2 (social engineering vector) |
| 4 | End-user Interaction | ~17 | P2 (delivery mechanism) |
| 5 | Credential Access | ~23 | P2 (credential theft) |
| 6 | Account Access | ~10 | P3 |
| 7 | Defence Evasion | ~39 | P3 |
| 8 | Perform Fraud | ~17 | P4 |
| 9 | Monetization | ~7 | P5 |
| 10 | Laundering | ~16 | P5 |

**~213 total techniques** across 10 stages.

**Additional components:**
- **Reports library**: 70+ fraud scheme reports (Scheme, Report & Insights, Threat Actor Group, Software, Campaign categories). Covers: pig butchering, mule tactics, deepfake impersonation, SIM swapping, credential stuffing, NFC relay malware, AI trading scams, and more.
- **Software reports**: Dedicated category documenting fraud tooling — including Verif Tools (API-enabled document forgery FaaS), Browser Automation Studio (credential stuffing IDE with CAPTCHA solving), Selenium Python Library (stealth browser automation), and various banking trojans and RATs. These provide actionable intelligence on the tools actors use, not just the schemes they execute.
- **Mitigations catalog**: 36 structured mitigations (M2000-M2035) with technique linkages. Includes: Adaptive Capability Clipping, User Confirmation, Token Rotation, Withdrawal Delay Policies, Device Binding, Enhanced Card Verification, Push Notification MFA.
- **Detections catalog**: 60+ detection methods with data source and component mappings. Heavily weighted toward mobile application instrumentation (Android AccessibilityManager, NotificationListenerService, TelephonyManager, etc.) and browser-based detections (WebGL, Canvas API, Document Interface).
- **Heat mapping**: Technique frequency counts showing how many scheme reports reference each technique. Highest-frequency techniques observed: Access from Fraudster Device (29), Payment to Mule Account (28), External Mule Account (25), Malware (23), Mule accounts in Laundering (21), Phishing Resource (20).
- **Company-specific filtering**: Organizations can filter the matrix by their own profile for tailored risk scoring.

**Strengths:** Most mature fraud taxonomy platform. Structured technique IDs, heat mapping, detection/mitigation catalogs, threat actor profiles, company-specific filtering. Active development and growing adoption.

**Limitations:**
- **Commercially gated** — requires Group-IB Fraud Intelligence subscription. Practitioners without vendor relationships can't access the taxonomy, reports, or detection logic.
- **Mobile-heavy detection model** — detection catalog is dominated by Android/iOS app instrumentation. Organizations without mobile banking apps get less value from the detection layer.
- **Report format is prose, not structured kill-chains** — scheme reports describe fraud campaigns but don't provide structured technique-by-technique phase mappings with detection queries, Sigma rules, or Splunk SPL that practitioners can deploy directly.
- **Vendor ecosystem dependency** — embedded in Group-IB's Unified Risk Platform. The taxonomy and community are tied to Group-IB's commercial interests.
- **No community contribution model** — practitioners consume Group-IB's analysis but don't contribute their own threat paths or detection logic to the platform.

**FLAME relationship:** Group-IB Fraud Matrix is the closest functional analog to what FLAME aims to build. FLAME differentiates on three axes:
1. **Open access** — MIT-licensed, no vendor dependency
2. **Structured operational intelligence** — threat paths with detection queries, Sigma rules, cross-team correlation guidance
3. **Community-contributed** — practitioners submit their own threat paths, not just consume vendor analysis

FLAME maps to Group-IB stages as a cross-reference layer for organizations that use both platforms.

> **Note on referencing Group-IB Fraud Matrix:** Group-IB Fraud Matrix is a commercial product. FLAME references the framework's stage names for cross-taxonomy interoperability purposes only, similar to how security tools reference MITRE ATT&CK technique IDs. FLAME does not reproduce Group-IB's proprietary report content, detection logic, or mitigation descriptions. Stage names and general framework structure are referenced as taxonomic facts for mapping purposes.

---

### Group-IB Fraud Matrix ↔ CFPF Stage Mapping (Detailed)

The CFPF compresses the fraud lifecycle into 5 phases where Group-IB uses 10 stages. The mapping is not 1:1 — Group-IB splits several CFPF phases into more granular stages, particularly around initial access and positioning.

```
CFPF P1 (Recon)           ──▶  Group-IB: Reconnaissance + Resource Development
CFPF P2 (Initial Access)  ──▶  Group-IB: Trust Abuse + End-user Interaction + Credential Access
CFPF P3 (Positioning)     ──▶  Group-IB: Account Access + Defence Evasion
CFPF P4 (Execution)       ──▶  Group-IB: Perform Fraud
CFPF P5 (Monetization)    ──▶  Group-IB: Monetization + Laundering
```

Key differences in granularity:
- **CFPF P2 splits three ways in Group-IB**: "Trust Abuse" (social engineering setup), "End-user Interaction" (delivery mechanism), and "Credential Access" (credential theft). This is a useful distinction — it separates the lure from the payload from the harvest.
- **CFPF P3 splits two ways**: "Account Access" (gaining access) vs. "Defence Evasion" (maintaining access and avoiding detection). Group-IB's Defence Evasion stage has the highest technique count (~39), reflecting the complexity of evading modern fraud detection systems.
- **CFPF P5 splits two ways**: "Monetization" (converting stolen access to funds) vs. "Laundering" (moving funds through layering networks). This is an important distinction for AML teams.

---

### Group-IB UCFF (Unified Cyber Fraud Framework)

| Attribute | Detail |
|-----------|--------|
| **Owner** | Group-IB |
| **Type** | Defense governance maturity model (7 domains) |
| **Access** | Public whitepaper |
| **Scope** | Organizational anti-fraud program maturity |

**Seven Domains:** Commit, Assess, Prevent, Detect, Respond, Investigate, Manage.

UCFF is Group-IB's defense-side complement to their attack-side Fraud Matrix. Where the Fraud Matrix maps how attackers operate, UCFF maps how defenders should organize. It provides a maturity model (Levels 1-5) for organizational readiness across seven governance domains.

**Strengths:** Structured maturity model, domain-based governance view, complements attack-side taxonomy.

**Limitations:** Defense-side only — does not describe attack techniques. Must be paired with an attack-side framework (Fraud Matrix, CFPF, etc.) for complete coverage.

**FLAME relationship:** UCFF provides defense-side maturity alignment for threat paths. FLAME maps `ucff_domains` in frontmatter with per-domain maturity levels and key deliverables. Currently mapped to 7 of 23 priority TPs.

---

### Stripe FT3 (Fraud Tactics, Techniques & Transfers)

| Attribute | Detail |
|-----------|--------|
| **Owner** | Stripe |
| **Published** | ~2024 |
| **Type** | ATT&CK-style tactics/techniques JSON |
| **Access** | MIT license, open source |
| **Status** | Abandoned (1 commit, no activity) |

**Structure:** JSON-based taxonomy following MITRE ATT&CK's tactic → technique hierarchy. Includes tactic IDs (FT.TA0001+) and technique IDs.

**Strengths:** MIT-licensed structured data, machine-parseable JSON format, ATT&CK-familiar structure.

**Limitations:** Abandoned after a single commit. No community, no tooling, no updates. A taxonomy without any operational content built on top of it.

**FLAME relationship:** FLAME parses FT3's MIT-licensed JSON and auto-maps FT3 tactics and techniques to all 23 threat paths via `ft3_mapper.py`. FT3 is a fully integrated mapping layer in FLAME's multi-taxonomy model.

---

### MITRE F3 (Fraud Framework for MITRE ATT&CK)

| Attribute | Detail |
|-----------|--------|
| **Owner** | MITRE |
| **Announced** | May 2025 |
| **Type** | ATT&CK extension for fraud |
| **Access** | Will be public (MITRE standard) |
| **Status** | Not yet shipped as of February 2026 |

**What we know:** MITRE announced F3 as a fraud-specific extension to the ATT&CK framework. Given MITRE's track record, it will likely be a taxonomy with technique IDs, descriptions, and potentially procedure examples — similar to how ATT&CK covers enterprise, mobile, and ICS domains.

**What we don't know:** Release timeline, scope (financial services only or broader), technique count, whether it will include detection/mitigation mappings.

**Strengths (projected):** MITRE brand authority, interoperability with existing ATT&CK ecosystem (Navigator, STIX, Sigma mappings), likely to become an industry standard.

**Risk to FLAME:** If MITRE ships F3 with a community platform (like ATT&CK Navigator for fraud), it could overlap FLAME's frontend. However, MITRE historically publishes frameworks and lets the community build tooling — they didn't build HEARTH, Sigma, ATT&CK Navigator (originally by the community), or major threat intel platforms. Most likely outcome: F3 gives FLAME a better taxonomy to map to, not a competing platform.

**FLAME relationship:** FLAME will add `mitre_f3` as a mapping field when F3 ships. F3 technique IDs become another cross-reference layer in FLAME's multi-taxonomy model.

---

### Axur Fraud Neuron

| Attribute | Detail |
|-----------|--------|
| **Owner** | Axur |
| **Type** | Regional fraud taxonomy |
| **Access** | Open source (GitHub) |
| **Status** | Minimal traction (~4 GitHub stars) |

**Strengths:** Open source, LatAM regional expertise.

**Limitations:** Minimal adoption, regional focus, limited technique coverage.

**FLAME relationship:** Potential future mapping layer for LatAM-focused practitioners.

---

## Adjacent Tools (Not Direct Competitors)

| Tool | What It Does | Relationship to FLAME |
|------|-------------|----------------------|
| **HEARTH** (THOR Collective) | Threat hunting hypothesis exchange (PEAK framework) | FLAME's architectural model. Fork-friendly, MIT licensed. |
| **MISP** | Open-source threat intelligence sharing (IOCs, indicators) | MISP shares raw indicators; FLAME shares detection knowledge and investigation playbooks. Complementary, not competing. |
| **Marble** | Open-source fraud/AML decision engine | Marble executes fraud rules; FLAME shares the knowledge that informs those rules. |
| **UK FIRE** | Bank ↔ Meta intelligence sharing for scam takedowns | Bilateral and operational; FLAME is multilateral and analytical. |
| **GitHub fraud-detection repos** | ML models for transaction scoring | Focus on model training/scoring, not operational knowledge of how fraud schemes work across the full lifecycle. |

---

## Positioning Matrix

|  | Open Source | Community Contributed | Structured Detection Logic | Multi-Taxonomy | Framework-Agnostic |
|--|-----------|---------------------|--------------------------|---------------|-------------------|
| **FLAME** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Group-IB Fraud Matrix** | ❌ | ❌ | ✅ (mobile-heavy) | ❌ (own taxonomy) | ❌ |
| **Group-IB UCFF** | ✅ (whitepaper) | ❌ | ❌ (governance only) | ❌ (defense-side) | ❌ |
| **FS-ISAC CFPF** | ✅ (paper) | ❌ (no platform) | ❌ | ❌ | ❌ |
| **Stripe FT3** | ✅ | ❌ (abandoned) | ❌ | ❌ | ❌ |
| **MITRE F3** | TBD | TBD | TBD | TBD | ❌ |
| **HEARTH** | ✅ | ✅ | ✅ | ✅ (ATT&CK) | N/A (threat hunting) |

---

## Key Takeaway

The fraud taxonomy problem is being solved by well-resourced organizations. The community knowledge exchange problem — where practitioners share structured operational intelligence across organizational and framework boundaries — remains entirely unserved in open source.

FLAME fills that gap. As more taxonomies emerge, FLAME becomes more valuable, not less — each new framework is another mapping layer the platform supports.

---

*This analysis is based on publicly available information, published framework documentation, and general structural observations. Commercial product references are for positioning purposes and do not reproduce proprietary content.*

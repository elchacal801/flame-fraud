# FLAME Threat Path Template

> Use this template to document fraud schemes mapped across fraud lifecycle frameworks.
> FLAME is framework-agnostic: map to CFPF, FT3, MITRE F3, Group-IB Fraud Matrix, ATT&CK — or all of them.
> Replace all placeholders `[...]` with specific details. Delete sections that don't apply.
> For guidance on finding fraud intel sources, see `Templates/resources.md`.

---

## Metadata

```yaml
---
id: TP-XXXX                     # Assigned by maintainers
title: "[Descriptive title]"
category: ThreatPath             # ThreatPath | Baseline | DetectionLogic
date: YYYY-MM-DD
author: "[Name or Handle]"
source: "[URL or 'Original Research']"
tlp: WHITE                       # WHITE only for public submissions
sector:                          # Primary sector(s) affected
  - banking
fraud_types:                     # See taxonomy — at least one required
  - account-takeover

# Multi-taxonomy mapping (map to all frameworks that apply)
cfpf_phases:                     # FS-ISAC CFPF (primary structure)
  - P1
  - P2
  - P3
  - P4
  - P5
ft3_tactics: []                  # Stripe FT3 tactic/technique IDs (MIT, when mapped)
mitre_f3: []                     # MITRE F3 IDs (placeholder, add when shipped)
groupib_stages: []               # Group-IB Fraud Matrix stages (reference only)
ucff_domains:                    # Group-IB UCFF domain alignment
  commit: ""
  assess: ""
  plan: ""
  act: ""
  monitor: ""
  report: ""
  improve: ""
mitre_attack:                    # MITRE ATT&CK technique IDs (supplementary)
  - T1566

tags:                            # Additional descriptive tags
  - tag1
---
```

---

## Summary

[2-3 sentence overview of the fraud scheme. Who is targeted? What is the end goal? What makes this threat path notable or distinct from similar schemes?]

---

## Threat Path Hypothesis

> **Hypothesis**: [Actors are using `[technique/method]` to `[achieve objective]` against `[target type]` in the `[sector]` sector, resulting in `[impact type]`.]

**Confidence**: [High | Medium | Low] — based on [volume of reporting / direct observation / single source / theoretical]

**Estimated Impact**: [Dollar range per incident if known, or qualitative: low/medium/high/critical]

---

## CFPF Phase Mapping

### Phase 1: Recon

*How does the threat actor identify and prepare to target the victim?*

| Technique | Description | Indicators |
|-----------|-------------|------------|
| [CFPF-P1-XXX: Technique name] | [How the actor uses this technique in this scheme] | [Observable indicators at this phase] |
| | | |

**Data Sources**: [What logs, feeds, or intelligence sources reveal Phase 1 activity?]

---

### Phase 2: Initial Access

*How does the threat actor gain their initial foothold?*

| Technique | Description | Indicators |
|-----------|-------------|------------|
| [CFPF-P2-XXX: Technique name] | [How the actor uses this technique] | [Observable indicators] |
| | | |

**Target**: [Consumer | Institution | Third Party]

**Data Sources**: [Email logs, auth logs, call center records, web analytics, etc.]

---

### Phase 3: Positioning

*How does the threat actor set up for the fraudulent action?*

| Technique | Description | Indicators |
|-----------|-------------|------------|
| [CFPF-P3-XXX: Technique name] | [What account changes, persistence, or data collection occurs] | [Observable indicators] |
| | | |

**Data Sources**: [Account modification logs, session data, admin audit trails, etc.]

---

### Phase 4: Execution

*How does the threat actor convert access into financial action?*

| Technique | Description | Indicators |
|-----------|-------------|------------|
| [CFPF-P4-XXX: Technique name] | [What fraudulent transaction or action is performed] | [Observable indicators] |
| | | |

**Data Sources**: [Transaction monitoring, wire transfer logs, claims systems, etc.]

---

### Phase 5: Monetization

*How does the threat actor extract and launder the stolen funds?*

| Technique | Description | Indicators |
|-----------|-------------|------------|
| [CFPF-P5-XXX: Technique name] | [How funds are moved to actor-controlled infrastructure] | [Observable indicators] |
| | | |

**Data Sources**: [Payment rail logs, blockchain analysis, correspondent banking records, etc.]

---

## Cross-Framework Mapping

> *Optional but encouraged. Mapping to multiple frameworks helps practitioners who use different taxonomies find and apply this threat path.*

**FT3 (Stripe Fraud Taxonomy):**

- [FT3 tactic/technique IDs that correspond to this threat path's techniques]

**MITRE ATT&CK:**

- [ATT&CK technique IDs with brief description of relevance]

**Group-IB Fraud Matrix:**

- [Corresponding stages if known — reference only, not required]

---

## Look Left / Look Right Analysis

> The CFPF's core methodology: start from the phase where you discovered the fraud, then work backward ("look left") to find earlier indicators and forward ("look right") to predict next steps.

**Discovery Phase**: [Which phase is this scheme typically discovered at?]

**Look Left** (what did you miss before discovery?):

- [Earlier phase indicators that could have caught this sooner]
- [Data sources that would reveal upstream activity]
- [Teams that might have visibility into earlier phases]

**Look Right** (what comes next after discovery?):

- [Predicted next steps if the scheme isn't interrupted]
- [Parallel schemes that might be running simultaneously]
- [Monetization patterns to watch for]

---

## Underground Ecosystem Context

> *Optional section — include when underground market intelligence is available for this threat path. Focus on structural patterns (roles, service categories, availability levels) rather than specific actor handles or product names that will go stale.*

### Service Supply Chain
| Role | Service Type | Underground Availability | Typical Cost Range |
|------|-------------|--------------------------|-------------------|
| [Role name] | [Service category] | [High/Medium/Low] | [Price range] |

### Tool Ecosystem
[Named tool *categories* relevant to this threat path — e.g., "anti-detect browsers," "infostealer MaaS kits," "document forgery services" — not specific actor handles or product names that will go stale]

### Underground Marketplace Presence
[Types of underground venues where this scheme is discussed, sold, or recruited for, with estimated activity level. Reference forum *categories* (Russian-language carding forums, Telegram fraud channels, dark web marketplaces) rather than specific named forums that may be seized]

### Intelligence Sources
[Recommended open-source or TLP:WHITE reports for deeper ecosystem context on this threat path]

---

## Controls & Mitigations

| Phase | Control | Type | Owner |
|-------|---------|------|-------|
| P1 | [Specific control recommendation] | [Preventive\|Detective\|Responsive] | [Cyber\|Fraud\|AML\|IT] |
| P2 | | | |
| P3 | | | |
| P4 | | | |
| P5 | | | |

---

## UCFF Alignment

> *Optional section — Group-IB Unified Counter Fraud Framework (UCFF) maturity mapping. Documents the minimum organizational maturity required to effectively detect and prevent this threat path.*

### Required Organizational Maturity for Effective Detection

| UCFF Domain | Minimum Maturity | Key Deliverables for This Threat Path |
|-------------|-----------------|--------------------------------------|
| COMMIT | Level X (Label) | [Specific governance requirement] |
| ASSESS | Level X (Label) | [Specific risk assessment requirement] |
| PLAN | Level X (Label) | [Specific planning deliverable] |
| ACT | Level X (Label) | [Specific detection/response capability] |
| MONITOR | Level X (Label) | [Specific KRI or monitoring requirement] |
| REPORT | Level X (Label) | [Specific reporting requirement] |
| IMPROVE | Level X (Label) | [Specific feedback loop] |

### Maturity Levels Reference
- **Level 1 (Initial):** Ad hoc, reactive fraud management
- **Level 2 (Developing):** Basic fraud function exists with some defined processes
- **Level 3 (Established):** Formalized fraud program with proactive capabilities
- **Level 4 (Advanced):** Data-driven, continuously improving fraud program
- **Level 5 (Leading):** Industry-leading, predictive fraud management

---

## Detection Approaches

### Queries / Rules

```
[SIEM query, Sigma rule, SQL query, or pseudocode for detecting this scheme.
Specify the platform/language: Splunk SPL, KQL, Sigma, SQL, etc.]
```

### Behavioral Analytics

[Description of behavioral patterns that could be modeled — anomalous session behavior, transaction velocity changes, communication pattern shifts, etc.]

### Cross-Team Correlation

[What data from different teams (cyber, fraud, AML) should be correlated to detect this scheme?]

---

## Operational Evidence

> Evidence entries are contributed by operational investigations and linked to this threat path. Each entry documents observed infrastructure, indicators, and investigation context. Evidence IDs use the format `EV-[TP-ID]-[YYYY]-[NNN]`.

### EV-TPXXXX-YYYY-NNN: [Title]

- **Source**: domain_intel investigation [YYYY-MM-DD]
- **Cluster**: [IP] ([Provider], [Country])
- **Domain Count**: [N] domains
- **Key Indicators**: [comma-separated IOCs: nameserver patterns, hosting co-location, domain naming conventions]
- **CFPF Phase Coverage**: [P1, P2, etc.]
- **Confidence**: [High/Medium/Low]
- **Summary**: [2-3 sentence narrative describing the observed infrastructure and its relationship to this threat path. Include what makes this cluster notable and how it maps to the CFPF phases above.]

---

## Case Studies & References

- [Source 1: Title, URL, date — what it contributes to this threat path]
- [Source 2: ...]
- [FBI IC3 PSA, FinCEN advisory, DOJ indictment, vendor blog, news article, etc.]

---

## Analyst Notes

[Optional: Additional context, caveats, regional variations, emerging trends, or connections to other threat paths in FLAME. This is the space for practitioner insights that don't fit neatly into the structured fields above.]

---

## Revision History

| Date | Author | Change |
|------|--------|--------|
| YYYY-MM-DD | [Author] | Initial submission |

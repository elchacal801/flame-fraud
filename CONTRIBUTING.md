# Contributing to FLAME

FLAME is a community-driven platform. Contributions of threat paths, baselines, and detection logic are welcome from practitioners across all financial sectors.

## Submission Types

| Type | Prefix | Template | Description |
|------|--------|----------|-------------|
| Threat Path | TP-XXXX | `Templates/threat-path-template.md` | Fraud scheme mapped across the CFPF lifecycle |
| Baseline | BL-XXXX | (coming soon) | Environmental profiling and benchmarks |
| Detection Logic | DL-XXXX | (coming soon) | Detection rules, queries, and analytics |

## How to Submit

### Option 1: AI-Assisted Intake (Recommended)

1. Open a new Issue using the **Intel Submission** template
2. Paste a URL to a fraud advisory, report, or indictment
3. The AI pipeline generates a structured threat path draft
4. Maintainers review and merge

### Option 2: Manual Submission

1. Fork the repository
2. Copy `Templates/threat-path-template.md` to `ThreatPaths/TP-XXXX-descriptive-name.md`
3. Fill in all sections, replacing placeholders with specific details
4. Submit a pull request

### Option 3: Manual Issue

1. Open a new Issue using the **Manual Submission** template
2. Paste your threat path content
3. Maintainers will review, assign an ID, and format as needed

## Frontmatter Requirements

Every submission must include YAML frontmatter with these required fields:

```yaml
---
id: TP-XXXX
title: "Descriptive title"
category: ThreatPath
date: YYYY-MM-DD
author: "Name or Handle"
source: "URL or 'Original Research'"
tlp: WHITE
sector:
  - banking
fraud_types:
  - account-takeover
cfpf_phases: [P1, P2, P3, P4, P5]
mitre_attack: []
ft3_tactics: []
mitre_f3: []
groupib_stages: []
tags:
  - descriptive-tag
---
```

### Field Guidelines

- **sector**: Use standard values: `banking`, `insurance`, `credit-union`, `investment`, `fintech`, `payments`, `crypto`, `healthcare`, `government`, `cross-sector`
- **fraud_types**: At least one required. Use lowercase-hyphenated format.
- **cfpf_phases**: Map to all CFPF phases the scheme covers (P1 through P5)
- **mitre_attack**: MITRE ATT&CK technique IDs (e.g., T1566.001). Include where applicable.
- **ft3_tactics**: Stripe FT3 tactic IDs. Leave as empty list if not mapped.
- **mitre_f3**: MITRE F3 IDs. Leave as empty list (placeholder for when F3 ships).
- **groupib_stages**: Group-IB Fraud Matrix stage names. Include where applicable.
- **tlp**: PUBLIC submissions only. Use `WHITE`.

## Required Sections

At minimum, every threat path must include:

1. **Summary** -- Overview of the fraud scheme
2. **Threat Path Hypothesis** -- Analytical hypothesis with confidence assessment
3. **CFPF Phase Mapping** -- Technique-by-technique mapping across P1-P5
4. **Controls & Mitigations** -- Preventive and detective controls by phase
5. **Detection Approaches** -- Concrete detection queries, rules, or analytics

Optional but encouraged:

- Cross-Framework Mapping
- Look Left / Look Right analysis
- Underground Ecosystem Context
- Case Studies & References
- Analyst Notes

### Underground Ecosystem Context (Optional)

The **Underground Ecosystem Context** section documents the underground service supply chain, tool ecosystem, and marketplace presence for a given fraud type. It is positioned after Look Left / Look Right Analysis and before Controls & Mitigations in the template.

**Design rationale**: Full actor profiles are a maintenance trap — handles change, forums get seized, actors get arrested. This section deliberately focuses on **structural patterns** that persist even as specific actors rotate. When filling out this section:

- **Service Supply Chain**: Document the *roles* and *service categories* that enable the scheme (e.g., "credential supplier," "money mule recruiter"), not specific actor handles.
- **Tool Ecosystem**: Reference tool *categories* (e.g., "anti-detect browsers," "infostealer MaaS kits") rather than specific product names that will go stale.
- **Underground Marketplace Presence**: Reference forum *categories* (e.g., "Russian-language carding forums," "Telegram fraud channels") rather than specific named forums that may be seized.
- **Intelligence Sources**: Link to open-source or TLP:WHITE reports for deeper ecosystem context.

Only include this section when underground market intelligence is genuinely available for the threat path. Do not speculate or fabricate ecosystem details.

## Quality Guidelines

- Map techniques to specific CFPF technique IDs from `cfpf_techniques.json` where possible
- Include concrete indicators for each technique
- Detection queries should be deployable (Splunk SPL, KQL, SQL, Sigma rules)
- Cite sources for statistics and claims
- All submissions must be TLP:WHITE (publicly shareable)

## Validation

Before submitting, run the validator locally:

```bash
python scripts/validate_submission.py ThreatPaths/your-file.md
```

The validator checks:

- Required frontmatter fields present
- CFPF phases are valid (P1-P5)
- Fraud types and sectors match known taxonomy
- ID format matches category prefix
- Required body sections exist

The same validator runs automatically on pull requests via GitHub Actions.

## Code of Conduct

- Submissions must be based on TLP:WHITE or publicly available information
- Do not include PII, customer data, or proprietary detection logic
- Attribution is required -- credit sources and prior work
- Be professional and constructive in reviews

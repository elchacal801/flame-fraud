# 🔥 FLAME: Fraud Lifecycle Analysis & Mitigation Exchange

## Project Design Document — v0.2 DRAFT

> A community-driven, open-source platform for sharing fraud detection hypotheses, threat paths, and investigation playbooks — framework-agnostic, mapping to CFPF, FT3, MITRE F3, Group-IB Fraud Matrix, and MITRE ATT&CK simultaneously.

---

## Concept

FLAME does for **cyber fraud detection** what [HEARTH](https://hearth.thorcollective.com/) does for **threat hunting**: it provides a searchable, community-curated knowledge base where practitioners can discover, contribute, and collaborate on structured intelligence about how fraud schemes work and how to detect them.

The fraud taxonomy landscape is converging rapidly. Five organizations independently concluded that fraud needs its own ATT&CK-style framework:

| Framework | Owner | Status | Type |
|-----------|-------|--------|------|
| **FS-ISAC CFPF** | FS-ISAC (300+ member WG) | Published April 2025 | 5-phase lifecycle model |
| **Stripe FT3** | Stripe | Abandoned (1 commit, MIT) | ATT&CK-style tactics/techniques JSON |
| **MITRE F3** | MITRE | Announced May 2025, not shipped | ATT&CK extension for fraud |
| **Group-IB Fraud Matrix 2.0** | Group-IB | Active, 80+ orgs, v2.0 Aug 2025 | 10-stage commercial taxonomy |
| **Axur Fraud Neuron** | Axur | Minimal traction (4 stars) | Regional LatAM taxonomy |

**Everyone is building the dictionary. Nobody is building the library.**

FLAME is the library. A framework-agnostic community knowledge exchange where practitioners share operational fraud intelligence — actual threat paths, detection logic, investigation playbooks — mapped to whichever taxonomy (or taxonomies) their organization uses. Each threat path can simultaneously reference CFPF phases, FT3 technique IDs, MITRE F3 mappings (when available), Group-IB stages, and ATT&CK techniques.

FLAME uses the **FS-ISAC Cyber Fraud Prevention Framework (CFPF)** as its primary organizational structure:

```
┌──────────┐    ┌──────────────┐    ┌─────────────┐    ┌───────────┐    ┌──────────────┐
│  Phase 1  │───▶│   Phase 2    │───▶│   Phase 3   │───▶│  Phase 4  │───▶│   Phase 5    │
│   Recon   │    │Initial Access│    │ Positioning │    │ Execution │    │Monetization  │
└──────────┘    └──────────────┘    └─────────────┘    └───────────┘    └──────────────┘
     ◀── Look Left                                              Look Right ──▶
```

But FLAME is deliberately **not locked to any single taxonomy**. As the fraud framework landscape matures, FLAME becomes more valuable — each new framework is another mapping layer the platform supports. FLAME is the Rosetta Stone connecting all fraud frameworks.

---

## Why This Matters

### The Problem
- Fraud analysts, cybersecurity teams, AML investigators, and financial crime units **see different slices** of the same campaigns but rarely share structured intelligence
- Multiple organizations are building fraud taxonomies (CFPF, FT3, F3, Group-IB Fraud Matrix), but **no one is building the community platform** for sharing operational intelligence that sits on top of those taxonomies
- Group-IB Fraud Matrix 2.0 is powerful (80+ orgs, 10-stage lifecycle, self-assessment wizard) but it's **commercial and vendor-gated** — embedded in Group-IB's Unified Risk Platform, not open to the community
- MITRE F3 will likely be taxonomy-only (MITRE historically publishes frameworks, not platforms — they didn't build HEARTH, Sigma, or ATT&CK Navigator)
- Stripe FT3 is a dead JSON file (1 commit, no activity)
- ML-based fraud detection repos on GitHub focus on **transaction scoring models**, not the operational knowledge of how fraud schemes work

### The Opportunity
- The taxonomy layer is converging — multiple well-resourced organizations are solving it. What remains unsolved: the **community knowledge exchange layer**
- The "HEARTH model" (GitHub-native, AI-assisted, community-contributed) is proven and its architecture is MIT-licensed
- Insurance companies see fraud through one lens; banks see another; credit unions another — cross-sector sharing reveals the full picture
- Framework-agnostic design means FLAME gets **more valuable** as more taxonomies emerge, not less
- A practitioner-built open-source platform differentiates sharply from commercial offerings (Group-IB) and institutional frameworks (MITRE, FS-ISAC)

---

## Strategic Positioning

### Old Framing (v0.1)
"We built our own fraud taxonomy."

### New Framing (v0.2)
"The industry is converging on fraud taxonomies — CFPF, FT3, F3, Group-IB Fraud Matrix. What's missing: an open platform where practitioners share operational intelligence that sits on top of those taxonomies. FLAME is framework-agnostic: map your threat paths to CFPF phases, FT3 techniques, MITRE F3, Group-IB stages, or all of the above."

### Why This Is Stronger
- Not competing with MITRE or Group-IB on taxonomy definition
- Open-source complement to whatever taxonomy wins (or all of them)
- Gets MORE valuable as more taxonomies emerge (each new framework = another mapping layer FLAME supports)
- The Rosetta Stone connecting all fraud frameworks
- Community-driven vs. vendor-gated (Group-IB) or institutional (MITRE, FS-ISAC)

---

## Taxonomy & Categories

### Submission Categories

| Category | Icon | Description | HEARTH Equivalent |
|----------|------|-------------|-------------------|
| **Threat Paths** | 🔥 | Complete or partial fraud scheme mappings across lifecycle phases. Hypothesis-driven: "Actors are using X technique in Phase 2 to achieve Y in Phase 4." | Flames |
| **Baselines** | 📊 | Environmental profiling and normalization. "What does legitimate beneficiary change volume look like?" Supports outlier detection. | Embers |
| **Detection Logic** | ⚡ | Algorithmic, rule-based, or model-assisted detection approaches. Sigma rules, SIEM queries, behavioral analytics patterns. | Alchemy |

### Multi-Taxonomy Mapping (Core Design Principle)

Every threat path supports **simultaneous mapping** to multiple fraud frameworks. This is FLAME's architectural differentiator.

**Primary taxonomy — CFPF Phases (organizational structure):**

| Phase | Name | Description | Typical Owners |
|-------|------|-------------|----------------|
| P1 | **Recon** | Target selection, info gathering, infrastructure setup | Cyber Threat Intel, OSINT |
| P2 | **Initial Access** | Gaining foothold — phishing, social engineering, credential stuffing, insider | Cybersecurity, SOC |
| P3 | **Positioning** | Account modifications, data collection, persistence establishment | Fraud Ops, Cybersecurity |
| P4 | **Execution** | Converting stolen data/access to financial action | Fraud Ops, Treasury, Claims |
| P5 | **Monetization** | Funds transfer method — wire, ACH, crypto, check, digital payment | AML, Financial Crimes |

**Supplementary taxonomy mappings (optional per submission):**

| Framework | Field | Format | Status |
|-----------|-------|--------|--------|
| Stripe FT3 | `ft3_tactics` | FT3 tactic/technique IDs | Available (MIT, parse from JSON) |
| MITRE F3 | `mitre_f3` | F3 technique IDs | Placeholder (add when F3 ships) |
| Group-IB Fraud Matrix | `groupib_stages` | Stage names/numbers | Reference only (commercial) |
| MITRE ATT&CK | `mitre_attack` | ATT&CK technique IDs | Available |

### Fraud Type Tags (Secondary Taxonomy)

**Account-Based:**
`account-takeover` · `new-account-fraud` · `synthetic-identity` · `application-fraud` · `credential-stuffing`

**Payment-Based:**
`BEC` · `wire-fraud` · `ACH-fraud` · `check-fraud` · `payment-diversion` · `invoice-fraud` · `payroll-diversion`

**Social Engineering:**
`vishing` · `smishing` · `phishing` · `romance-scam` · `tech-support-scam` · `impersonation`

**Insurance-Specific:**
`fraudulent-claim` · `premium-diversion` · `provider-fraud` · `disability-fraud`

**Infrastructure:**
`money-mule` · `mule-network` · `crypto-laundering` · `malvertising` · `SEO-poisoning` · `deepfake`

**Insider:**
`insider-threat` · `collusion` · `data-theft`

### Sector Tags

`banking` · `insurance` · `credit-union` · `investment` · `fintech` · `payments` · `crypto` · `healthcare` · `government` · `cross-sector`

---

## Architecture

### Design Principles

1. **Framework-agnostic**: Support multiple fraud taxonomies simultaneously; no lock-in to any single framework
2. **Fork-friendly**: Based on HEARTH's proven architecture (MIT license)
3. **Markdown as source of truth**: Human-readable, Git-versioned, diffable
4. **Zero server infrastructure**: GitHub Pages + GitHub Actions
5. **AI-assisted intake**: Submit a URL to a fraud advisory, AI generates a structured threat path
6. **Low barrier to contribute**: Issue template → automated processing → maintainer review
7. **Interoperable**: Outputs compatible with MISP, STIX, and the CFPF workbook format

### Repository Structure

```
flame-fraud/
├── ThreatPaths/              # 🔥 Complete fraud scheme mappings (source of truth)
│   ├── TP-0001-treasury-mgmt-ato-malvertising.md
│   ├── TP-0002-bec-vendor-impersonation-wire.md
│   └── ...
├── Baselines/                # 📊 Environmental profiling submissions
│   ├── BL-0001-beneficiary-change-velocity.md
│   └── ...
├── DetectionLogic/           # ⚡ Rules, queries, and algorithmic approaches
│   ├── DL-0001-email-header-bec-infrastructure.md
│   └── ...
├── Templates/                # Submission templates and guides
│   ├── threat-path-template.md
│   ├── baseline-template.md
│   ├── detection-logic-template.md
│   └── resources.md          # Intel sources for fraud research
├── database/                 # SQLite index for fast queries/dedup
│   ├── flame.db
│   └── README.md
├── scripts/                  # Automation backend
│   ├── generate_from_intel.py     # AI-assisted threat path generation
│   ├── build_database.py          # SQLite index builder
│   ├── validate_submission.py     # Phase/technique validation
│   ├── check_duplicates.py        # Embedding-based dedup
│   └── cfpf_techniques.json       # CFPF technique reference data
├── docs/                     # Project documentation
│   ├── FRAMEWORK-MAPPING.md       # How FLAME maps across taxonomies
│   ├── CONTRIBUTING.md
│   ├── TAXONOMY.md
│   ├── COMPETITIVE-LANDSCAPE.md   # Analysis of existing frameworks
│   └── INTEL-SOURCES.md           # Fraud intel source directory
├── .github/
│   ├── workflows/
│   │   ├── intel-submission.yml   # AI-assisted processing
│   │   ├── manual-submission.yml  # Manual review flow
│   │   ├── update-database.yml    # Auto-rebuild index on merge
│   │   └── validate-pr.yml       # PR quality checks
│   └── ISSUE_TEMPLATE/
│       ├── intel_submission.yml   # "Submit a fraud intel URL"
│       └── manual_submission.yml  # "Submit a threat path manually"
├── Assets/                   # Logo, images
├── index.html                # Frontend (GitHub Pages)
├── app.js                    # Frontend logic
├── style.css
├── flame-data.js             # Frontend data loader
├── README.md
└── LICENSE                   # MIT
```

### Data Flow

```
                                    ┌─────────────────────┐
                                    │  Fraud Intel Source  │
                                    │ (IC3, FinCEN, blog)  │
                                    └──────────┬──────────┘
                                               │
                              ┌────────────────▼────────────────┐
                              │     GitHub Issue Submission      │
                              │  (URL + contributor name/handle) │
                              └────────────────┬────────────────┘
                                               │
                              ┌────────────────▼────────────────┐
                              │     GitHub Actions Workflow      │
                              │                                  │
                              │  1. Scrape/extract content       │
                              │  2. AI analysis (Claude API)     │
                              │  3. Generate threat path draft   │
                              │  4. Map to CFPF phases + FT3    │
                              │  5. Validate techniques/tags     │
                              │  6. Check for duplicates         │
                              │  7. Create branch + PR           │
                              └────────────────┬────────────────┘
                                               │
                              ┌────────────────▼────────────────┐
                              │      Maintainer Review           │
                              │  (approve / request changes /    │
                              │   regenerate label)              │
                              └────────────────┬────────────────┘
                                               │
                    ┌──────────────────────────▼──────────────────────────┐
                    │                    Merge to Main                     │
                    │                                                      │
                    │  ┌──────────────┐  ┌──────────────┐  ┌────────────┐ │
                    │  │ Markdown file │  │ SQLite index │  │  Frontend  │ │
                    │  │  (source of   │  │  (auto-      │  │  (auto-    │ │
                    │  │   truth)      │  │   rebuilt)   │  │   deploy)  │ │
                    │  └──────────────┘  └──────────────┘  └────────────┘ │
                    └─────────────────────────────────────────────────────┘
```

### Frontend Visualization — The Threat Path View

The key UI differentiator: each threat path renders as a **horizontal five-phase timeline** with the ability to **toggle between taxonomy views** (CFPF phases, FT3 tactics, Group-IB stages).

```
┌─────────────────────────────────────────────────────────────────────────┐
│  TP-0001: Treasury Management ATO via Malvertising                      │
│  Type: 🔥 Threat Path  |  Sector: Banking  |  Author: CFPF WG          │
│                                                                          │
│  View: [CFPF ▼]  [FT3]  [ATT&CK]                                       │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  P1 Recon        P2 Initial Access    P3 Positioning                     │
│  ┌──────────┐    ┌──────────────┐    ┌─────────────┐                    │
│  │ ● Domain  │───▶│ ● Social Eng │───▶│ ● Add auth  │                    │
│  │   infra   │    │ ● Vishing    │    │   user      │                    │
│  │ ● OSINT   │    │              │    │ ● Change    │                    │
│  │ ● Spoofing│    │              │    │   acct info │                    │
│  └──────────┘    └──────────────┘    └──────┬──────┘                    │
│                                              │                           │
│  P4 Execution                    P5 Monetization                         │
│  ┌───────────────┐               ┌──────────────┐                       │
│  │ ● Unauthorized │──────────────▶│ ● Wire to    │                       │
│  │   wire xfer   │               │   mule acct  │                       │
│  └───────────────┘               └──────────────┘                       │
│                                                                          │
│  Tags: account-takeover · vishing · malvertising · money-mule · banking  │
│  ATT&CK: T1566 · T1656 · T1657  |  FT3: FT.TA0001 · FT.TA0003         │
└─────────────────────────────────────────────────────────────────────────┘
```

### AI-Assisted Intel Intake

**Supported fraud intel sources:**
- FBI IC3 Public Service Announcements
- FinCEN Advisories and SAR trends
- APWG eCrime reports
- Vendor threat blogs (Featurespace, BioCatch, Feedzai, Abnormal Security, Proofpoint)
- DOJ press releases (fraud ring indictments/takedowns)
- FS-ISAC public alerts
- Insurance fraud bureau reports
- Academic papers on fraud schemes
- News articles on major fraud cases
- Group-IB and Recorded Future threat reports (as intel sources to ingest)

**AI prompt engineering priorities:**
1. Extract the fraud scheme from the source
2. Identify techniques at each CFPF phase (map to technique library)
3. Cross-reference to FT3 tactics and ATT&CK techniques where applicable
4. Identify indicators of fraud at each phase
5. Suggest detection approaches and controls
6. Tag with fraud type, sector, and framework mappings
7. Check for duplicate/overlapping threat paths in the database

---

## Frontmatter Schema (v0.2)

```yaml
---
id: TP-XXXX
title: "[Descriptive title]"
category: ThreatPath
date: YYYY-MM-DD
author: "Name/Handle"
source: "URL or 'Original Research'"
tlp: WHITE
sector: [banking]
fraud_types: [account-takeover]

# Multi-taxonomy mapping (FLAME's core differentiator)
cfpf_phases: [P1, P2, P3, P4, P5]      # Primary: FS-ISAC CFPF
ft3_tactics: []                          # Stripe Fraud Taxonomy (MIT, when mapped)
mitre_f3: []                             # MITRE F3 (placeholder, add when shipped)
groupib_stages: []                       # Group-IB Fraud Matrix (reference only)
mitre_attack: [T1566]                    # MITRE ATT&CK (supplementary)

tags: [additional-tags]
---
```

---

## Competitive Landscape

| Project | Type | Open? | Status | What It Does | FLAME Relationship |
|---------|------|-------|--------|--------------|-------------------|
| **FS-ISAC CFPF** | Lifecycle framework | TLP:WHITE paper | Published Apr 2025 | 5-phase fraud lifecycle | FLAME's primary organizational structure |
| **Stripe FT3** | Fraud taxonomy (JSON) | MIT, open source | Abandoned (1 commit) | ATT&CK-style tactics/techniques | FLAME ingests as mapping layer |
| **MITRE F3** | Fraud taxonomy | Will be public | Announced May 2025, not shipped | ATT&CK extension for fraud | FLAME will map to when available |
| **Group-IB Fraud Matrix 2.0** | Taxonomy + analytics | Commercial, closed | Active, 80+ orgs | 10-stage lifecycle, threat intel | FLAME is the open alternative |
| **Axur Fraud Neuron** | Fraud taxonomy (LatAM) | Open source | Minimal traction | Regional focus | Potential mapping layer |
| **HEARTH** | Threat hunting exchange | MIT | Active | PEAK framework hunts | FLAME's architectural model |
| **MISP** | Threat intel platform | Open source | Active | IOC sharing infrastructure | FLAME shares knowledge, not IOCs |
| **Marble** | Fraud decision engine | Open source | Active | Rule execution | Marble executes; FLAME informs |

### Key Differentiator

Group-IB Fraud Matrix 2.0 is the closest functional comparison — it has 80+ organizations, a 10-stage lifecycle, threat actor profiles, and self-assessment tooling. But it's **commercial and vendor-gated**, embedded in Group-IB's Unified Risk Platform. You need a Group-IB relationship to access it.

FLAME is the **open-source, community-driven alternative**. Built by practitioners, for practitioners. MIT-licensed. No vendor lock-in. And framework-agnostic — if your org uses Group-IB's taxonomy, FLAME can map to it. If your org uses CFPF, same. Both? FLAME handles that too.

---

## Implementation Phases

### Phase 1: Foundation (Weeks 1-3)
- [ ] Repository setup (`flame-fraud` on GitHub)
- [ ] Threat path markdown template with multi-taxonomy frontmatter
- [ ] Baseline and detection logic templates
- [ ] CFPF technique reference JSON (initial set from CFPF paper + appendix)
- [ ] FT3 technique cross-reference parsing (MIT-licensed JSON available)
- [ ] 14 seed threat paths (manually authored from public sources)
- [ ] README, CONTRIBUTING guide, taxonomy documentation
- [ ] Basic static frontend (search, filter by phase/type/sector, taxonomy toggle)
- [ ] SQLite database builder script

### Phase 2: Automation (Weeks 4-6)
- [ ] GitHub Actions workflow for intel URL submissions
- [ ] AI-assisted threat path generation (Claude API integration)
- [ ] CFPF phase/technique validation script
- [ ] Duplicate detection (embedding-based similarity)
- [ ] Automated branch creation and PR workflow
- [ ] Issue templates for both submission types

### Phase 3: Community (Weeks 7+)
- [ ] Contributor leaderboard
- [ ] Heat map visualization (technique frequency across submissions)
- [ ] Framework coverage dashboard (which taxonomies have mappings per threat path)
- [ ] MISP export format support
- [ ] STIX 2.1 export support
- [ ] Community outreach (conference CFP, blog post, social)
- [ ] MCP server integration (like THOR Collective's threat-hunting-mcp-server)

---

## Intel Source Directory

### Government / Law Enforcement
- [FBI IC3 Public Service Announcements](https://www.ic3.gov/PSA)
- [FinCEN Advisories](https://www.fincen.gov/resources/advisories)
- [DOJ Fraud Section Press Releases](https://www.justice.gov/criminal/criminal-fraud)
- [FTC Consumer Sentinel](https://www.ftc.gov/enforcement/consumer-sentinel-network)
- [CISA Alerts](https://www.cisa.gov/news-events/cybersecurity-advisories)
- [Secret Service Cyber Investigations](https://www.secretservice.gov/investigation/cyber)

### Industry / ISACs
- [FS-ISAC Public Resources](https://www.fsisac.com/resources)
- [APWG eCrime Research](https://apwg.org/trendsreports/)
- [ACFE Fraud Resources](https://www.acfe.com/fraud-resources)
- [Coalition Against Insurance Fraud](https://insurancefraud.org/)

### Vendor Research (as intel sources, not competitors)
- Proofpoint Threat Blog (BEC/phishing campaigns)
- Abnormal Security Blog (email fraud)
- BioCatch Research (behavioral biometrics, ATO patterns)
- Featurespace/Feedzai (transaction fraud)
- Socure / Jumio (identity fraud, synthetic identity)
- Chainalysis Blog (crypto fraud and laundering)
- Group-IB Blog (fraud matrix use cases, campaign intelligence)
- Recorded Future (state of security reports, fraud trends)

### News / Investigative
- KrebsOnSecurity
- BankInfoSecurity / ISMG
- The Record by Recorded Future
- Organized Crime and Corruption Reporting Project (OCCRP)

---

## Naming

**FLAME** — Fraud Lifecycle Analysis & Mitigation Exchange

The name connects to HEARTH's fire theme: a flame lives in a hearth. If HEARTH is where the threat hunting community gathers, FLAME is what fraud defenders carry away to light their own defenses.

- "Mitigation" replaces the original "Research" — the platform isn't just research, it's actionable detection and mitigation content
- "Exchange" stays — the core value proposition is community knowledge sharing
- GitHub repo: `flame-fraud` (disambiguates from unrelated "flame" projects)

Note: Flame was also a well-known nation-state malware tool (2012, Stuxnet-associated). In the security community this is a conversation starter, not a confusion risk — it's 14 years old and in a completely different domain.

---

## Risk Monitoring

**MITRE F3 platform risk**: If MITRE ships F3 with a community platform (like ATT&CK Navigator for fraud), it could overlap FLAME's frontend. But MITRE historically publishes frameworks and lets the community build tooling — they didn't build HEARTH, Sigma, or major ATT&CK platforms. Likely outcome: F3 gives FLAME a better taxonomy to map to, not a competing platform.

**FS-ISAC member-gated tool risk**: If FS-ISAC ships a member-gated threat path database in the next 6-12 months, FLAME's positioning shifts from "building thing nobody built" to "open-source alternative to FS-ISAC's tool." Both are viable but first story is stronger — shipping quickly matters.

**First mover timeline**: CFPF is 10 months old. FS-ISAC working group has 300+ members. Getting repo live + CFP submitted in next 4-6 weeks gives the cleanest narrative.

---

## Open Questions

1. **Scope**: Financial services only (aligned with CFPF) or broader (healthcare, government, retail)?
   - Starting FinServ-focused and expanding seems safest
2. **Relationship with FS-ISAC**: Independent project that references CFPF, or seek formal endorsement?
   - Independent first, then engage if traction builds
3. **TLP handling**: All submissions TLP:WHITE, or support TLP:GREEN/AMBER for gated sharing?
   - Start with TLP:WHITE only (public, open). Gated sharing adds complexity.
4. **FT3 integration depth**: Auto-parse Stripe's JSON and suggest FT3 mappings during AI intake?
   - Yes — FT3 is MIT licensed, structured JSON. Parse and cross-reference from day one.
5. **Community platform**: GitHub Discussions sufficient, or stand up a Discord/Slack?
   - Start with GitHub Discussions, add Discord if community grows

---

*Draft: February 2026*
*Author: Diego*

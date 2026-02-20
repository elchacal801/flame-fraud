**CODE REVIEW, THREAT PATH AUDIT & GROWTH PLAN**

FLAME — Fraud Lifecycle Analysis & Mitigation Exchange

Repository: github.com/elchacal801/flame-fraud  |  Review Date: 20 February 2026

# **1\. Executive Assessment**

FLAME has grown from a concept into a functional, multi-layered fraud intelligence platform with 15 threat paths, a build pipeline producing SQLite, JSON index, STIX 2.1 bundles, and per-TP detection rules, an AI-assisted intake system, a polished search-driven frontend, and comprehensive documentation. The codebase spans 4 Python scripts (2,214 lines), a 753-line JavaScript frontend, and 156K of structured threat path markdown. For a solo developer working in parallel with domain\_intel, this represents significant and disciplined output.

**Overall Grade: B+.** The architecture is sound and the content quality is strong. The markdown-first approach is validated. The primary gaps are in detection rule coverage (only 7 of 15 TPs have machine-parseable rules), consistency across threat path quality (earlier TPs are more polished than later ones), a SQL injection surface in the build script, and the INDEX.md being out of sync with TP-0015. None of these are blocking, but they represent the difference between a good project and a showcase-quality one.

| Dimension | Score | Assessment |
| :---- | :---- | :---- |
| **Architecture** | **A** | Markdown-first → SQLite \+ JSON → STIX pipeline is clean. Lazy-load frontend is well-designed. |
| **Content Quality** | **B+** | 15 TPs with real tradecraft. CFPF mapping is strong. Detection rules inconsistent across TPs. |
| **Code Quality** | **B+** | Clean Python, proper logging, type hints. One SQL injection surface. No tests. |
| **Security** | **C+** | SQL injection in \_insert\_multi/\_fetch\_list via f-string. No input sanitization on YAML. |
| **Test Coverage** | **F** | Zero test files. Build script, validator, AI intake, STIX exporter all untested. |
| **Framework Mappings** | **B** | CFPF: 15/15. MITRE ATT\&CK: 12/15. Group-IB: 6/15. FT3/F3: 0/15 (expected). |
| **Detection Rules** | **C+** | 8 parseable rules (SPL/SQL/Sigma) from 7 TPs. 8 TPs have zero extractable rules. |
| **Frontend** | **A-** | Clean search/filter UI, lazy loading, heat map, taxonomy toggle. No accessibility audit. |
| **Documentation** | **A** | Taxonomy ref, competitive landscape, project design, CONTRIBUTING, CHANGELOG — exemplary. |
| **Domain Intel Integration** | **A-** | Evidence index, STIX bridge, TP-0015 from investigation. Strong bidirectional flow. |

# **2\. Findings Summary (Prioritized)**

| Severity | Area | Finding | Recommendation |
| :---- | :---- | :---- | :---- |
| **HIGH** | Security | build\_database.py \_insert\_multi() and \_fetch\_list() use f-strings to construct SQL with table/column names. While these are hardcoded internally, not from user input, this is still a SQL injection antipattern that should be fixed before accepting community PRs. | Use a whitelist of valid table/column names and validate before query construction. Or use parameterized queries with explicit column mapping. |
| **HIGH** | Testing | Zero test files across the entire project. The build script, STIX exporter, validator, and AI intake have no automated tests. A malformed YAML frontmatter could silently corrupt the database. | Add tests for: frontmatter extraction, evidence parsing, STIX generation, validator logic, detection rule extraction. These are all pure functions — highly testable. |
| **HIGH** | Content | 8 of 15 TPs have no machine-parseable detection rules. Many TPs use untagged code blocks (plain \`\`\`) that the STIX exporter cannot parse. TP-0006 through TP-0015 use 'pseudocode' style detection that is human-readable but not extractable. | Retrofit all TPs with at least one tagged detection block (spl, sql, sigma). Convert pseudocode blocks to proper Sigma rules or SQL queries where possible. Add 'kql' to DETECTION\_BLOCK\_RE in export\_flame\_stix.py. |
| **MEDIUM** | Consistency | INDEX.md lists 14 TPs but 15 exist (TP-0015 missing). The INDEX header says 'Seed Collection v0.2' and '14 threat paths' which is stale. | Regenerate INDEX.md from build\_database.py output, or make it a generated artifact rather than manually maintained. |
| **MEDIUM** | Consistency | Group-IB Fraud Matrix mapping is inconsistent: 6 TPs have mappings, 9 have empty arrays or empty values. TP-0001 has 9 stages mapped but TP-0002-TP-0006 have zero. | Complete Group-IB mapping for all 15 TPs. Group-IB stages map cleanly to CFPF phases — batch-process using the mapping table in TAXONOMY.md. |
| **MEDIUM** | Security | ai\_intake.py fetches arbitrary URLs (user-provided via \--url) and sends content to LLM. No URL validation, no SSRF protection, no content-type restrictions beyond basic PDF detection. | Add URL allowlist/blocklist. Validate scheme (http/https only). Add timeout and max response size. Consider running fetch in a sandboxed subprocess. |
| **MEDIUM** | Code | export\_flame\_stix.py DETECTION\_BLOCK\_RE regex misses 'kql' language tag. 2 TPs (TP-0002, TP-0006) use KQL blocks that are not extracted. | Add 'kql' to the regex: r'\`\`\`(spl|sql|yaml|yara|pseudocode|sigma|kql)'. Verify no other language tags are being missed. |
| **MEDIUM** | Schema | TP-0015 introduces sector values 'healthcare', 'staffing', 'employment' and fraud types 'advance-fee-fraud', 'identity-theft' that are not in validate\_submission.py's VALID\_SECTORS and VALID\_FRAUD\_TYPES sets. | Update validate\_submission.py with new sector/fraud\_type values. Or make validator read from a canonical taxonomy file rather than hardcoding. |
| **LOW** | Code | flame-stats.json 'generatedAt' uses file mtime of the script rather than current timestamp. This gives a misleading generation time. | Use datetime.now(timezone.utc).isoformat() instead of Path(\_\_file\_\_).stat().st\_mtime. |
| **LOW** | Frontend | app.js uses var instead of let/const throughout. Not a bug but signals older JS style. escapeHtml() creates DOM elements per call which is inefficient. | Modernize to let/const. Use a simple regex or map-based escaper for HTML entities. |
| **LOW** | Build | The build pipeline has no CI/CD. Manual execution of build\_database.py and export\_flame\_stix.py. No GitHub Actions workflow. | Add a GitHub Actions workflow that runs: validate\_submission.py on all TPs, build\_database.py, export\_flame\_stix.py, and deploys to GitHub Pages. |

# **3\. Threat Path Quality Audit**

## **3.1 Individual TP Assessment**

| ID | Title | Quality | Notes |
| :---- | :---- | :---- | :---- |
| **TP-0001** | Treasury Mgmt ATO via Malvertising | **Excellent** | Gold standard. FS-ISAC CFPF case study. 3 detection blocks (SPL \+ Sigma). Full Group-IB mapping. Best TP in the collection. |
| **TP-0002** | BEC Vendor Impersonation Wire | **Strong** | Good SPL \+ KQL detection. 4 MITRE techniques. Missing Group-IB stages. |
| **TP-0003** | Synthetic Identity Bust-Out | **Strong** | SQL detection rule. Graph analysis pseudocode. No MITRE ATT\&CK (correct — not cyber-enabled). Has 2 evidence entries from domain\_intel. |
| **TP-0004** | Payroll Diversion via HR Portal | **Good** | Sigma rule for bulk direct deposit changes. 3 MITRE techniques. Short but focused. |
| **TP-0005** | Insurance Premium Diversion | **Strong** | SQL detection for agent portal anomalies. Insurance-specific — unique coverage. Missing Group-IB. |
| **TP-0006** | Real Estate Wire Fraud | **Good** | KQL rule not extracted (missing from regex). Good CFPF mapping but detection needs strengthening. |
| **TP-0007** | Deepfake Voice Wire Auth | **Strong** | Novel AI threat. Group-IB mapped. Detection is pseudocode only — needs Sigma rules for voice auth anomalies. |
| **TP-0008** | SIM Swap Crypto ATO | **Good** | 3 pseudocode detection blocks. Group-IB mapped. Needs at least one SQL/SPL rule for SIM change correlation. |
| **TP-0009** | Check Washing Mobile Deposit | **Good** | SQL detection for suspicious mobile deposits. Physical+digital hybrid — interesting coverage gap filled. |
| **TP-0010** | Disability Insurance Fraud | **Strong** | Very relevant to Unum. ML feature engineering pseudocode \+ graph analysis. Needs formal detection rules. |
| **TP-0011** | Romance Scam Mule Pipeline | **Excellent** | Longest TP (15K). Enriched with Group-IB reports. 3 pseudocode detection blocks. Cross-references to TP-0001/0002/0006/0009. Needs tagged rules. |
| **TP-0012** | APP Fraud Tech Support | **Strong** | Has evidence from domain\_intel (Alibaba cluster). Pseudocode detection for concurrent-call pattern. |
| **TP-0013** | Credential Stuffing Loyalty Drain | **Strong** | SQL post-auth detection. Group-IB mapped. 3 detection blocks including antibot pseudocode. |
| **TP-0014** | Insider-Enabled Fraud | **Good** | Group-IB mapped. UEBA pseudocode \+ graph analysis. Insurance \+ banking. Needs formal Sigma rules. |
| **TP-0015** | Employment Fraud Brand Impersonation | **Good** | New from domain\_intel investigation. Real evidence. Missing from INDEX.md. Missing Group-IB. New fraud types not in validator. |

## **3.2 CFPF Phase Mapping Accuracy**

All 15 TPs map to all five CFPF phases (P1-P5). This is plausible for a threat path collection focused on end-to-end fraud schemes, but it's worth noting that the coverage heat map shows a perfectly uniform grid. In practice, some TPs have stronger phase coverage than others. For example, TP-0009 (Check Washing) has a very thin P1 section because check theft reconnaissance is predominantly physical, not cyber. TP-0010 (Disability Fraud) similarly has a thin P2 because initial access is via legitimate policy enrollment, not credential theft.

Recommendation: Consider adding a 'phase\_strength' field to frontmatter (e.g., strong/moderate/weak per phase) so the heat map can show intensity rather than binary coverage. This would make the coverage matrix significantly more useful for gap analysis.

## **3.3 MITRE ATT\&CK Mapping Accuracy**

10 unique ATT\&CK technique IDs are referenced across 12 TPs. The mappings are generally accurate. T1657 (Financial Theft) appears most frequently (correct — it's the catch-all for fraud execution). T1566.001 (Spearphishing Attachment) is used where phishing is the initial access vector. T1656 (Impersonation) correctly maps to deepfake and social engineering TPs.

Three TPs correctly have empty ATT\&CK mappings: TP-0003 (Synthetic Identity), TP-0009 (Check Washing), and TP-0010 (Disability Fraud). These are predominantly non-cyber fraud schemes where force-mapping to ATT\&CK would be inaccurate. This restraint is a sign of good tradecraft.

**One concern:** T1111 is listed in TP-0008 (SIM Swap). T1111 is 'Multi-Factor Authentication Interception' which is conceptually close but technically refers to intercepting MFA tokens in transit, not SIM swapping which is a social engineering attack on the carrier. T1111 may be the closest available technique, but this mapping should include a note about the imprecise fit. T1078 (Valid Accounts) in the same TP is accurate for the post-SIM-swap account access phase.

# **4\. Code Review Deep Dive**

## **4.1 build\_database.py (684 lines) — Core Engine**

The build script is the heart of the project and it's well-constructed. The frontmatter extraction regex correctly handles the FLAME convention of YAML inside code fences. The evidence parsing (extract\_evidence) is robust with state-machine logic for section boundaries. The multi-export pipeline (legacy JSON \+ v2 index \+ per-TP content \+ evidence index \+ stats) is clean and each function has a clear responsibility.

**SQL injection surface:** \_insert\_multi() on line 307 uses f"INSERT INTO {table} (submission\_id, {col}) VALUES (?, ?)" and \_fetch\_list() on line 381 uses f"SELECT {col} FROM {table} WHERE submission\_id \= ?". While table and col come from hardcoded strings within the script (not user input), this is still dangerous if the code is ever refactored to accept dynamic inputs or if a malicious YAML frontmatter key name somehow reaches these functions. Fix: create a whitelist dict mapping expected table+column pairs and validate before query construction.

**Stats generation:** export\_stats\_json() uses nested queries to build the coverage matrix (fraud\_type × phase). This works at 15 TPs but will become quadratic at scale. For 50+ TPs, consider a single JOIN query instead of N+1 selects.

**Strength:** The extract\_body() function correctly finds content after the frontmatter fence. The extract\_summary() function uses section-header detection to isolate the Summary section. Both are clean implementations.

## **4.2 ai\_intake.py (506 lines) — AI Intake**

The AI intake system is well-designed with a thorough system prompt, CFPF technique reference injection, and LLM fallback chain (Claude → GPT-4o). The clean\_output() function handles the common LLM output problems (wrapping in markdown fences, raw frontmatter without code fences). The slugify() function is correct for filename generation.

**SSRF risk:** fetch\_url\_content() takes a user-provided URL and fetches it with no validation. An attacker could provide internal network URLs (http://169.254.169.254/latest/meta-data/ for AWS metadata, http://localhost:8080/ for internal services). Add URL scheme validation (https only) and block RFC 1918 ranges.

**PDF handling:** PDF content is not extracted — the function returns a placeholder string. For a production intake system, adding PyMuPDF or pdfplumber for text extraction would significantly expand the source material FLAME can ingest.

**API key exposure:** The Anthropic API key is sent via x-api-key header (correct). The OpenAI key uses Bearer auth (correct). Both use raw requests rather than official SDKs, which means no automatic retry or streaming support. Acceptable for current scope but consider switching to SDKs as usage grows.

## **4.3 export\_flame\_stix.py (386 lines) — STIX Bridge**

Solid implementation. Deterministic UUIDs via uuid5 ensure idempotent builds. The CFPF kill chain definition is correct. The cross-reference detection (TP\_REF\_RE finding TP-XXXX patterns in body text) is clever and produces the 6 relationships in the bundle. STIX validation via parse-back is correct.

**Detection regex gap:** DETECTION\_BLOCK\_RE matches spl|sql|yaml|yara|pseudocode|sigma but misses 'kql'. Two TPs (TP-0002, TP-0006) use KQL blocks that are silently skipped. This is a one-line fix.

**Title extraction:** The rule title extraction looks backward through preceding lines for \*\*bold\*\* or \#\#\# headers. This is fragile and produces generic fallback titles like 'TP-0001 detection rule (spl)' when the preceding context doesn't match. Consider adding an optional title comment within code blocks.

## **4.4 validate\_submission.py (248 lines) — Schema Validator**

Clean and thorough. The ValidationResult class with error/warning separation is good design. MITRE ATT\&CK ID format validation with regex is correct. Body section checking works.

**Stale schema:** VALID\_SECTORS and VALID\_FRAUD\_TYPES are hardcoded and already out of sync with TP-0015 (which uses 'healthcare', 'staffing', 'employment', 'advance-fee-fraud', 'identity-theft'). These should be loaded from an external canonical file (the TAXONOMY.md or a taxonomy.yaml) rather than hardcoded in the script.

**Missing validation:** The validator doesn't check for required body sections beyond 'Summary' and 'CFPF Phase Mapping'. It should also verify 'Detection Approaches', 'Controls & Mitigations', and 'References' sections exist.

## **4.5 Frontend (app.js \+ style.css \+ flame-data.js)**

The v2 frontend is well-architected. The lazy-loading pattern (index for browse, on-demand content for detail view) keeps initial load fast. The filter system with chip UI, URL hash routing, and debounced search is production-quality. The heat map modal showing fraud\_type × CFPF phase coverage is a strong data visualization.

**Markdown rendering:** The detail view uses marked.js to render TP body content. This is correct but there's no DOMPurify or sanitization of the rendered HTML. Since the content comes from the build pipeline (trusted), this is low risk, but if community contributions are accepted via PR, a sanitization layer should be added.

**Accessibility:** No ARIA attributes beyond aria-label on the filter toggle. The modal close buttons use \&times; without aria-label. Tab order and keyboard navigation are not explicitly managed. Low priority but worth a pass before public launch.

# **5\. Detection Opportunities — Expanding Rule Coverage**

Currently 8 machine-parseable detection rules exist across 7 TPs (2 SPL, 2 Sigma, 4 SQL). The remaining 8 TPs use untagged pseudocode blocks that the STIX exporter cannot extract. This is the single highest-leverage improvement area for FLAME's practical value. Below are specific detection rules that should be added to each TP:

## **5.1 TPs with Zero Extractable Rules (Priority)**

**TP-0006 (Real Estate Wire Fraud):** The existing KQL block is not extracted because 'kql' is missing from the regex. Fix the regex and this TP gains a rule immediately. Additionally, add a Sigma rule for email rule creation (New-InboxRule targeting 'wire', 'closing', 'escrow' keywords) which is the key detection point.

**TP-0007 (Deepfake Voice):** Add a SQL rule: SELECT \* FROM wire\_authorizations WHERE auth\_method \= 'voice\_only' AND amount \> 50000 AND NOT EXISTS (SELECT 1 FROM email\_approvals WHERE wire\_id \= wire\_authorizations.id). The core detection is voice-only authorization for high-value wires with no email trail.

**TP-0008 (SIM Swap):** Add a Sigma rule for new-device-login-after-SIM-change correlation. The existing pseudocode describes this perfectly — it just needs Sigma formatting.

**TP-0010 (Disability Fraud):** Add a SQL rule for claim velocity: claims filed within 90 days of policy effective date, with provider in high-risk list, and claim amount in top decile. This is the core actuarial fraud signal.

**TP-0011 (Romance Scam Mule):** Add a SQL rule for mule account detection: accounts receiving inbound transfers from 3+ unique senders within 30 days, followed by outbound crypto/wire within 48 hours. This maps directly to the P5 monetization phase.

**TP-0012 (APP Fraud):** Add a SQL rule for concurrent-call-during-transaction pattern. The pseudocode is already clear: flag transactions where the account holder was on an active phone call (from IVR/telecom logs) during online banking session.

**TP-0014 (Insider Fraud):** Add a Sigma rule for anomalous account access volume: employee accessing 3× their baseline number of customer accounts in a 24-hour period.

**TP-0015 (Employment Fraud):** Add a SQL rule for domain\_intel integration: flag domains registered within 90 days that contain known employer brand names and are hosted on budget providers (Hostinger, GoDaddy shared).

## **5.2 Cross-TP Detection Patterns**

Several detection opportunities span multiple TPs and should be documented as shared detection logic:

* Mule account detection (TP-0001, TP-0002, TP-0006, TP-0009, TP-0011): Flag accounts with inbound-to-outbound velocity \> 0.8 ratio within 48-hour windows. This single rule covers the P5 monetization phase across 5 TPs.

* New device \+ high-value action correlation (TP-0001, TP-0004, TP-0005, TP-0008, TP-0013): Flag any financial action exceeding threshold within 24 hours of new device login. Covers the P3→P4 transition across 5 TPs.

* Email rule manipulation (TP-0002, TP-0004, TP-0006): Inbox rules that auto-delete or redirect emails containing financial keywords. Single Sigma rule covers BEC, payroll diversion, and real estate wire fraud.

# **6\. Project Growth Plan**

## **6.1 Immediate (This Sprint)**

* Fix DETECTION\_BLOCK\_RE to include 'kql'. Immediately recovers 2 detection rules from TP-0002 and TP-0006.

* Update INDEX.md to include TP-0015. Fix the header count from 14 to 15\.

* Add 'healthcare', 'staffing', 'employment' to VALID\_SECTORS and 'advance-fee-fraud', 'identity-theft' to VALID\_FRAUD\_TYPES in validate\_submission.py.

* Fix the SQL injection surface in \_insert\_multi() and \_fetch\_list() with a table/column whitelist.

* Fix flame-stats.json generatedAt to use datetime.now(timezone.utc).isoformat().

## **6.2 Short-Term: Detection Rule Retrofit (1-2 Weeks)**

* Retrofit all 8 TPs that lack machine-parseable rules with at least one tagged detection block each (see Section 5.1 for specific rules).

* Convert existing untagged pseudocode blocks to proper Sigma/SQL where feasible. Target: 2+ extractable rules per TP.

* Complete Group-IB Fraud Matrix mapping for remaining 9 TPs.

* Add a GitHub Actions workflow: validate all TPs, run build\_database.py, run export\_flame\_stix.py, deploy to GitHub Pages.

* Write tests for: extract\_frontmatter(), extract\_evidence(), extract\_detection\_rules(), validate\_file(). These are pure functions with clear inputs/outputs.

## **6.3 Medium-Term: New Threat Paths (Next Month)**

Based on the INDEX.md gap analysis, the competitive landscape, and current fraud trends, these are the highest-priority new TPs:

**TP-0016: First-Party Fraud / Friendly Fraud.** Chargebacks, return fraud, 'item not received' claims. This is the most common fraud type by volume in e-commerce and fintech. Sectors: banking, fintech, payments. High value because it's underrepresented in all existing frameworks.

**TP-0017: Pig Butchering (Investment Scam).** Crypto investment scam platforms with romance-scam recruitment. Extends TP-0011 (romance scam) into the investment fraud execution phase. FBI IC3 reported $4.57B in investment fraud losses in 2023\. Sectors: crypto, cross-sector.

**TP-0018: Deepfake Document Fraud / AI-Generated KYC.** AI-generated government IDs, utility bills, paystubs, and medical documentation used for new account opening, loan applications, and insurance claims. Extends TP-0007 (deepfake voice) into document-based fraud. Sectors: banking, insurance, fintech.

**TP-0019: Business Identity Theft / Business Account Fraud.** Opening fraudulent business accounts using stolen EIN/business registration data. Different from synthetic identity (TP-0003) because the business identity is real but stolen. Sectors: banking, fintech.

**TP-0020: Supply Chain / Procurement Payment Fraud.** Compromised procurement platforms, fake vendor registration, invoice manipulation at scale. Extends TP-0002 (BEC) into automated procurement fraud. Sectors: cross-sector.

**TP-0021: Healthcare Provider Billing Fraud.** Upcoding, unbundling, phantom billing, and kickback schemes. Extends TP-0010 (disability fraud) into the provider-side fraud vector. Sectors: healthcare, insurance.

**TP-0022: Government Program Fraud.** PPP/SBA loan fraud template applicable to future crisis relief programs. Historical precedent from COVID-era fraud provides rich source material. Sectors: government, banking.

**TP-0023: Mobile Banking Trojan / Overlay Attack.** Covers the mobile-specific fraud vector discovered in domain\_intel's Cluster 3 (deploygate.io/diawi.io). Trojanized apps distributed via sideloading that overlay legitimate banking apps. Sectors: banking, fintech.

## **6.4 Research Recommendations**

Yes, deep research should be performed to expand the threat path count. Here's where to focus:

* FBI IC3 Internet Crime Report 2024 (publish date typically Q2): Primary source for US fraud loss statistics by type. Will provide updated numbers for all existing TPs and identify emerging threats.

* Group-IB Fraud Intelligence reports: Continue using these for enrichment. The mule tactics, deepfake voice, credential stuffing, and document forgery reports have already enriched 6 TPs. Focus on their mobile banking trojan and overlay attack reports for TP-0023.

* FS-ISAC threat briefings: If available through your membership or public releases, these directly map to CFPF and provide case studies ready for TP conversion.

* CFPB complaint database: Public data on consumer financial complaints. Can identify emerging fraud patterns by complaint category volume trends.

* DOJ press releases on fraud prosecutions: Each prosecution describes the complete scheme lifecycle. Excellent source material for the AI intake system.

* FTC Sentinel data and reports: Consumer fraud reporting trends by category.

* Intelligence for Good case studies (Gary Warner): Infrastructure analysis patterns relevant to domain\_intel integration evidence.

## **6.5 Feature Expansion Roadmap**

* Shared Detection Logic library: Create a DetectionLogic/ directory for cross-TP rules that apply to multiple threat paths. This was in the original design doc but never implemented. Each rule would reference the TPs it covers.

* Baselines directory: Also in the original design doc. Industry baselines for normal patterns (e.g., 'typical wire transfer velocity by institution size') that provide the false-positive context for detection rules.

* Automated INDEX.md generation: Make build\_database.py output a regenerated INDEX.md so it's never stale.

* STIX relationship enrichment: Add 'uses' relationships between TP attack-patterns and MITRE ATT\&CK techniques. Currently only 'related-to' between TPs exists.

* Confidence scoring on CFPF phase mappings: Add per-phase confidence to frontmatter so the heat map shows intensity, not just binary coverage.

* Community contribution pipeline: The AI intake \+ validator \+ build pipeline is ready. Add GitHub Issue template that accepts a URL and triggers ai\_intake.py via GitHub Actions.

* Stripe FT3 mapping: FT3 JSON is MIT-licensed and available. Write a mapping script that cross-references FT3 technique descriptions with FLAME TP content to suggest mappings.

* MITRE F3 readiness: F3 was announced May 2025 but hasn't shipped. The frontmatter schema already includes mitre\_f3 field. When F3 launches, FLAME will be the first community platform to map to it.

# **7\. Strategic Assessment**

FLAME occupies a unique position in the fraud intelligence ecosystem. The competitive landscape doc correctly identifies that everyone is building the dictionary but nobody is building the library. FLAME is the library.

The integration with domain\_intel creates a flywheel that no other fraud intelligence project has: operational threat intelligence (domain\_intel) generates investigation evidence that enriches structured knowledge (FLAME), which in turn improves domain\_intel's classification accuracy via FLAME TP IDs. The TP-0015 employment fraud threat path, created directly from investigation findings, demonstrates this flywheel in action.

The project's 15 TPs cover the fraud types that matter most: ATO, BEC, synthetic identity, insider threat, romance scams, credential stuffing, and several insurance-specific threats. The gaps identified (first-party fraud, pig butchering, deepfake documents, mobile trojans) are all addressable via the AI intake system with good source material.

The path to 30 TPs by Q2 2026 is realistic with the AI intake pipeline. Each new TP should be generated via ai\_intake.py from a quality source article, then manually reviewed and enriched with detection rules, Group-IB mappings, and evidence from domain\_intel investigations where applicable. The detection rule retrofit of existing TPs should happen in parallel.

**Conference readiness:** FLAME \+ domain\_intel together make a strong SLEUTHCON or BSides submission. The narrative: 'How a solo analyst built an automated fraud detection pipeline that feeds a community threat intelligence platform, demonstrated with a live investigation of employment fraud infrastructure.' The TP-0015 creation from DEA clusters 4-6 is the concrete case study. The detection rule extraction into STIX bundles shows the operational output.

*END OF REVIEW  |  Prepared: 20 February 2026  |  Reviewer: Claude Opus 4.6 (Expert Fraud Intelligence Review)*
# FLAME -- Fraud Lifecycle Analysis & Mitigation Exchange

**Everyone built the dictionary. Nobody built the library.**

Between April 2025 and February 2026, five organizations independently concluded that fraud needs structured taxonomy frameworks. Stripe published FT3 (then abandoned it). MITRE announced F3 (still hasn't shipped). Group-IB released Fraud Matrix 2.0 (commercially gated). FS-ISAC assembled 300+ members for the Cyber Fraud Prevention Framework. The taxonomy layer is converging. The community knowledge exchange layer remains entirely unserved in open source.

FLAME fills that gap.

---

## What is FLAME?

FLAME is an open-source, community-driven platform for sharing structured fraud detection intelligence. It is framework-agnostic: each submission maps simultaneously to multiple fraud taxonomies so practitioners can use whichever framework their organization adopted.

**Supported frameworks:**

| Framework | Status |
|-----------|--------|
| FS-ISAC Cyber Fraud Prevention Framework (CFPF) | Primary structure -- all submissions mapped |
| MITRE ATT&CK | Supplementary mapping where applicable |
| Group-IB Fraud Matrix 2.0 | Cross-reference mapping (stage names) |
| Stripe FT3 | Pending (MIT-licensed JSON available) |
| MITRE F3 | Placeholder (will map when shipped) |

**What FLAME is not:** FLAME is not a taxonomy project. It is a knowledge exchange that sits on top of existing taxonomies, providing the operational intelligence -- threat paths, detection queries, investigation playbooks, and cross-team correlation guidance -- that no taxonomy alone delivers.

## Architecture

FLAME is modeled on [HEARTH](https://github.com/THOR-Collective/HEARTH), the threat hunting hypothesis exchange created by the THOR Collective.

- **Markdown-first**: Threat paths are authored as structured markdown files with YAML frontmatter. Markdown is the source of truth.
- **Database is derived**: A Python build script parses the markdown, builds a SQLite index, and exports JSON for the frontend. The database is regenerated on every push.
- **Static frontend**: A vanilla HTML/CSS/JS frontend served via GitHub Pages. No build step, no framework dependencies.
- **CI/CD**: GitHub Actions validate PR submissions and auto-rebuild the database on merge.

```
ThreatPaths/          Fraud scheme lifecycle mappings (TP-XXXX)
Baselines/            Environmental profiling (BL-XXXX, future)
DetectionLogic/       Rules, queries, analytics (DL-XXXX, future)
Templates/            Submission templates
scripts/              Build and validation scripts
database/             Generated SQLite + JSON (auto-built)
docs/                 Project documentation and design
.github/              Workflows and issue templates
```

## Seed Collection

FLAME ships with **14 seed threat paths** covering major fraud categories:

| ID | Scheme | Key Fraud Types |
|----|--------|-----------------|
| TP-0001 | Treasury Management ATO via Malvertising | ATO, vishing, wire fraud |
| TP-0002 | BEC -- Vendor Impersonation Wire Fraud | BEC, invoice fraud |
| TP-0003 | Synthetic Identity -- Credit Card Bust-Out | Synthetic identity, application fraud |
| TP-0004 | Payroll Diversion via HR Portal Compromise | Payroll diversion, BEC |
| TP-0005 | Insurance Premium Diversion via Agent Portal ATO | ATO, premium diversion |
| TP-0006 | Real Estate Wire Fraud -- Closing Scam | BEC, wire fraud |
| TP-0007 | Deepfake Voice Authorization for Wire Transfer | Deepfake, impersonation |
| TP-0008 | SIM Swap to Cryptocurrency Exchange ATO | ATO, crypto laundering |
| TP-0009 | Check Washing and Fraudulent Mobile Deposit | Check fraud |
| TP-0010 | Disability Insurance Fraud via Fabricated Medical Docs | Fraudulent claims |
| TP-0011 | Romance Scam to Money Mule Recruitment Pipeline | Romance scam, money mule |
| TP-0012 | APP Fraud -- Tech Support / Bank Impersonation | Vishing, impersonation |
| TP-0013 | Credential Stuffing to Loyalty Point / Gift Card Drain | Credential stuffing, ATO |
| TP-0014 | Insider-Enabled Account Fraud at Financial Institution | Insider threat, collusion |

## Quick Start

### View the database

Open `index.html` in a browser (via local server) or visit the [GitHub Pages site](https://github.com/flame-fraud/flame-fraud).

### Build the database locally

```bash
pip install -r requirements.txt
python scripts/build_database.py
```

### Validate a submission

```bash
python scripts/validate_submission.py ThreatPaths/TP-0001-treasury-mgmt-ato-malvertising.md
```

### Contribute a threat path

See [CONTRIBUTING.md](CONTRIBUTING.md) for submission guidelines.

## Contributing

FLAME is community-driven. Contributions of threat paths, baselines, and detection logic are welcome from practitioners across all financial sectors. See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## Credits

- **HEARTH / THOR Collective** -- Architectural model and inspiration
- **FS-ISAC CFPF Working Group** -- Primary fraud lifecycle framework
- **Group-IB** -- Fraud Matrix 2.0 stage names referenced for cross-taxonomy interoperability
- **Stripe** -- FT3 (MIT-licensed) taxonomy structure
- **MITRE** -- ATT&CK framework; F3 fraud extension (pending)

## License

MIT License. See [LICENSE](LICENSE).

# Changelog

All notable changes to the FLAME project will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [0.2.0] — 2026-02-19

### Added

- **Search-driven discovery interface** — Card grid replaces sidebar list
- **Lazy content loading** — Individual TP content fetched on demand via `flame-content/TP-XXXX.json`
- **Pre-computed statistics** — `flame-stats.json` with aggregate counts and coverage matrix
- **Metadata-only index** — `flame-index.json` for fast initial load
- **Coverage heat map** — Modal showing fraud types × CFPF phases matrix
- **Taxonomy toggle** — Switch between CFPF, MITRE ATT&CK, and Group-IB views in detail
- **Copy-to-clipboard** — All code blocks in detail view have copy buttons
- **Look Left / Look Right** — Visual callouts in detail view
- **URL hash routing** — Direct links to threat paths via `#detail/TP-XXXX`
- **Filter panel** — CFPF phase, sector, and fraud type chip filters with clear-all
- **Mobile responsive** — Collapsible filter panel, stacked cards on narrow screens
- **`docs/TAXONOMY.md`** — Complete taxonomy reference
- **`CHANGELOG.md`** — This file

### Changed

- `build_database.py` — Generates three new export files alongside legacy `flame-data.json`
- `index.html` — Complete rewrite with new layout structure
- `app.js` — Complete rewrite with card grid, hash routing, and lazy loading
- `flame-data.js` — Rewritten for v2 data architecture
- `style.css` — Premium dark theme redesign with animations

### Fixed

- TP count corrected to 14 (TP-0015 not yet submitted)

---

## [0.1.0] — 2026-02-12

### Added

- Initial release with 14 seed threat paths (TP-0001 through TP-0014)
- Python build pipeline (`build_database.py`, `validate_submission.py`)
- AI-assisted intake pipeline (`ai_intake.py`)
- GitHub Actions for PR validation and database rebuild
- SQLite index + JSON export
- Vanilla HTML/CSS/JS frontend with sidebar list view
- FS-ISAC CFPF framework as primary mapping structure
- Cross-framework support: MITRE ATT&CK, Group-IB Fraud Matrix 2.0, Stripe FT3, MITRE F3
- Project documentation: `FLAME-project-design.md`, `COMPETITIVE-LANDSCAPE.md`
- GitHub Issue templates for AI-assisted and manual submissions

# Stripe FT3 (Fraud Tools, Tactics & Techniques) Reference Data

## Source

- **Repository:** https://github.com/stripe/ft3
- **License:** MIT License
- **Downloaded:** 2026-02-28

## Files

| File | Description | Count |
|------|-------------|-------|
| `FT3_Tactics.json` | FT3 fraud tactic definitions | 12 tactics |
| `FT3_Techniques.json` | FT3 fraud technique definitions | 137 techniques (56 top-level, 79 sub-techniques, 2 unlabeled) |

## Hierarchy

The FT3 taxonomy organizes fraud attack patterns into 12 tactics, each
containing one or more techniques. Techniques may have sub-techniques
for finer-grained classification.

## Notes

- The tactics file uses uppercase `"ID"` while the techniques file uses
  lowercase `"id"`. Downstream parsers must account for this difference.
- Two sub-techniques (FT033.003, FT033.004) have an empty `is_sub-technique`
  field instead of `"TRUE"` — this is an upstream data quality issue.
- Tactics use `"domain": "fraud-attack"` while techniques use `"domain": "ft3"`.

## Usage in FLAME

These files are vendored as read-only reference data. Threat paths
reference FT3 tactics and techniques via the `ft3_tactics` field in
YAML frontmatter. The FLAME frontend renders these as `.ft3-tag` badges.

## License

The FT3 taxonomy is released under the MIT License by Stripe, Inc.
See the upstream repository for full license text.

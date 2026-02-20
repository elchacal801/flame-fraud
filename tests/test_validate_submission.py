"""
test_validate_submission.py — Tests for FLAME validate_submission.py

Tests validation logic: valid files pass, missing fields fail,
new sectors/fraud types are accepted, required body sections checked.
"""

from pathlib import Path

import pytest

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from validate_submission import validate_file, VALID_SECTORS, VALID_FRAUD_TYPES


# ---------------------------------------------------------------------------
# Test content templates
# ---------------------------------------------------------------------------

VALID_CONTENT = """\
# TP-9999: Test Threat Path

```yaml
---
id: TP-9999
title: "Test Threat Path"
category: ThreatPath
date: 2026-01-01
author: "Test Author"
source: "https://example.com"
tlp: WHITE
sector:
  - banking
fraud_types:
  - account-takeover
cfpf_phases: [P1, P2, P3]
mitre_attack: [T1566.001]
ft3_tactics: []
mitre_f3: []
groupib_stages: []
tags:
  - test
---
```

## Summary

This is a test threat path summary.

## CFPF Phase Mapping

### Phase 1: Recon

Content.

## Detection Approaches

Detection content.

## Controls & Mitigations

Control content.

## References

- Test reference
"""

TP0015_CONTENT = """\
# TP-0015: Employment Fraud

```yaml
---
id: TP-0015
title: "Employment Fraud via Brand Impersonation"
category: ThreatPath
date: 2026-02-19
author: "FLAME Project"
source: "https://example.com"
tlp: WHITE
sector:
  - healthcare
  - staffing
  - employment
fraud_types:
  - impersonation
  - advance-fee-fraud
  - identity-theft
cfpf_phases: [P1, P2, P3, P4, P5]
mitre_attack: [T1566.001, T1583.001]
ft3_tactics: []
mitre_f3: []
groupib_stages: []
tags:
  - employment-fraud
---
```

## Summary

Employment fraud summary.

## CFPF Phase Mapping

Content.

## Detection Approaches

Detection content.

## Controls & Mitigations

Control content.

## References

- Ref 1
"""


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestValidateFile:
    def test_valid_file_passes(self, tmp_path):
        fp = tmp_path / "TP-9999-test.md"
        fp.write_text(VALID_CONTENT, encoding="utf-8")
        result = validate_file(fp)
        assert result.passed, f"Errors: {result.errors}"

    def test_missing_frontmatter_fails(self, tmp_path):
        fp = tmp_path / "bad.md"
        fp.write_text("# No frontmatter\n\nJust text.", encoding="utf-8")
        result = validate_file(fp)
        assert not result.passed
        assert any("frontmatter" in e.lower() for e in result.errors)

    def test_missing_required_field_fails(self, tmp_path):
        content = VALID_CONTENT.replace('id: TP-9999\n', '')
        fp = tmp_path / "no-id.md"
        fp.write_text(content, encoding="utf-8")
        result = validate_file(fp)
        assert not result.passed
        assert any("id" in e.lower() for e in result.errors)

    def test_invalid_category_fails(self, tmp_path):
        content = VALID_CONTENT.replace('category: ThreatPath', 'category: InvalidCat')
        fp = tmp_path / "bad-cat.md"
        fp.write_text(content, encoding="utf-8")
        result = validate_file(fp)
        assert not result.passed

    def test_tp0015_sectors_accepted(self, tmp_path):
        """New sectors from TP-0015 should be accepted without warnings."""
        fp = tmp_path / "TP-0015-test.md"
        fp.write_text(TP0015_CONTENT, encoding="utf-8")
        result = validate_file(fp)
        assert result.passed, f"Errors: {result.errors}"
        # Should not have unrecognized sector warnings
        sector_warnings = [w for w in result.warnings if "sector" in w.lower()]
        assert len(sector_warnings) == 0, f"Sector warnings: {sector_warnings}"

    def test_tp0015_fraud_types_accepted(self, tmp_path):
        """New fraud types from TP-0015 should be accepted without warnings."""
        fp = tmp_path / "TP-0015-test.md"
        fp.write_text(TP0015_CONTENT, encoding="utf-8")
        result = validate_file(fp)
        fraud_warnings = [w for w in result.warnings if "fraud type" in w.lower()]
        assert len(fraud_warnings) == 0, f"Fraud type warnings: {fraud_warnings}"

    def test_invalid_cfpf_phase_fails(self, tmp_path):
        content = VALID_CONTENT.replace("cfpf_phases: [P1, P2, P3]",
                                         "cfpf_phases: [P1, P99]")
        fp = tmp_path / "bad-phase.md"
        fp.write_text(content, encoding="utf-8")
        result = validate_file(fp)
        assert not result.passed

    def test_missing_detection_section_fails(self, tmp_path):
        """Detection Approaches is now a required body section."""
        content = VALID_CONTENT.replace("## Detection Approaches\n\nDetection content.\n\n", "")
        fp = tmp_path / "no-detection.md"
        fp.write_text(content, encoding="utf-8")
        result = validate_file(fp)
        assert not result.passed
        assert any("Detection Approaches" in e for e in result.errors)

    def test_missing_controls_section_fails(self, tmp_path):
        content = VALID_CONTENT.replace("## Controls & Mitigations\n\nControl content.\n\n", "")
        fp = tmp_path / "no-controls.md"
        fp.write_text(content, encoding="utf-8")
        result = validate_file(fp)
        assert not result.passed
        assert any("Controls" in e for e in result.errors)

    def test_missing_references_section_fails(self, tmp_path):
        content = VALID_CONTENT.replace("## References\n\n- Test reference\n", "")
        fp = tmp_path / "no-refs.md"
        fp.write_text(content, encoding="utf-8")
        result = validate_file(fp)
        assert not result.passed
        assert any("References" in e for e in result.errors)

    def test_nonexistent_file_fails(self, tmp_path):
        fp = tmp_path / "nonexistent.md"
        result = validate_file(fp)
        assert not result.passed

    def test_non_md_file_fails(self, tmp_path):
        fp = tmp_path / "readme.txt"
        fp.write_text("content", encoding="utf-8")
        result = validate_file(fp)
        assert not result.passed

    def test_mitre_attack_format_warning(self, tmp_path):
        content = VALID_CONTENT.replace("mitre_attack: [T1566.001]",
                                         "mitre_attack: [INVALID_ID]")
        fp = tmp_path / "bad-mitre.md"
        fp.write_text(content, encoding="utf-8")
        result = validate_file(fp)
        # Should warn but not error
        assert result.passed
        assert any("MITRE" in w for w in result.warnings)


class TestTaxonomyConstants:
    """Verify taxonomy constants include the new values from TP-0015."""

    def test_new_sectors_present(self):
        assert "staffing" in VALID_SECTORS
        assert "employment" in VALID_SECTORS
        assert "healthcare" in VALID_SECTORS

    def test_new_fraud_types_present(self):
        assert "advance-fee-fraud" in VALID_FRAUD_TYPES
        assert "identity-theft" in VALID_FRAUD_TYPES
        assert "employment-fraud" in VALID_FRAUD_TYPES
        assert "brand-impersonation" in VALID_FRAUD_TYPES

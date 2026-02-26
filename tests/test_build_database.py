"""
test_build_database.py — Tests for FLAME build_database.py

Tests pure functions: frontmatter extraction, body extraction,
summary extraction, evidence parsing, and SQL whitelist validation.
"""

import sqlite3
import tempfile
from pathlib import Path

import pytest

# Add scripts dir to path for imports
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from build_database import (
    extract_frontmatter,
    extract_body,
    extract_summary,
    extract_evidence,
    _insert_multi,
    _fetch_list,
    _VALID_MULTI_TABLES,
    init_database,
    build_regulatory_alerts,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

VALID_TP_CONTENT = """\
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

This is a test threat path for unit testing purposes.
It covers account takeover scenarios in the banking sector.

## CFPF Phase Mapping

### Phase 1: Recon

Content here.

## Detection Approaches

Some detection content.

## Controls & Mitigations

Control content.

## References

- Test reference

## Operational Evidence

### EV-TP9999-2026-001: Test Evidence Entry

- **Source**: test investigation
- **Cluster**: 10.0.0.1
- **Domain Count**: 5
- **Confidence**: High
- **Summary**: Test evidence for unit testing.

### EV-TP9999-2026-002: Second Evidence Entry

- **Source**: second test
- **Cluster**: 10.0.0.2
- **Domain Count**: 3
- **Confidence**: Medium
"""

MALFORMED_YAML_CONTENT = """\
# TP-9998: Malformed

```yaml
---
id: TP-9998
title: [invalid yaml: ::: {{
---
```

## Summary

Malformed.
"""

NO_FRONTMATTER_CONTENT = """\
# No Frontmatter

Just a plain markdown file without any YAML frontmatter block.

## Summary

Nothing here.
"""


@pytest.fixture
def valid_tp_file(tmp_path):
    """Create a temporary valid threat path file."""
    fp = tmp_path / "TP-9999-test.md"
    fp.write_text(VALID_TP_CONTENT, encoding="utf-8")
    return fp


@pytest.fixture
def malformed_yaml_file(tmp_path):
    fp = tmp_path / "TP-9998-malformed.md"
    fp.write_text(MALFORMED_YAML_CONTENT, encoding="utf-8")
    return fp


@pytest.fixture
def no_frontmatter_file(tmp_path):
    fp = tmp_path / "no-frontmatter.md"
    fp.write_text(NO_FRONTMATTER_CONTENT, encoding="utf-8")
    return fp


@pytest.fixture
def test_db(tmp_path):
    """Create a test database with schema."""
    db_path = tmp_path / "test.db"
    conn = init_database(db_path)
    yield conn
    conn.close()


# ---------------------------------------------------------------------------
# extract_frontmatter tests
# ---------------------------------------------------------------------------

class TestExtractFrontmatter:
    def test_valid_frontmatter(self, valid_tp_file):
        meta = extract_frontmatter(valid_tp_file)
        assert meta is not None
        assert meta["id"] == "TP-9999"
        assert meta["title"] == "Test Threat Path"
        assert meta["category"] == "ThreatPath"
        assert meta["sector"] == ["banking"]
        assert meta["fraud_types"] == ["account-takeover"]
        assert meta["cfpf_phases"] == ["P1", "P2", "P3"]
        assert meta["mitre_attack"] == ["T1566.001"]

    def test_malformed_yaml_returns_none(self, malformed_yaml_file):
        meta = extract_frontmatter(malformed_yaml_file)
        assert meta is None

    def test_no_frontmatter_returns_none(self, no_frontmatter_file):
        meta = extract_frontmatter(no_frontmatter_file)
        assert meta is None


# ---------------------------------------------------------------------------
# extract_body tests
# ---------------------------------------------------------------------------

class TestExtractBody:
    def test_body_starts_after_frontmatter(self, valid_tp_file):
        body = extract_body(valid_tp_file)
        assert body.startswith("## Summary")
        assert "```yaml" not in body
        assert "id: TP-9999" not in body

    def test_body_without_frontmatter(self, no_frontmatter_file):
        body = extract_body(no_frontmatter_file)
        assert "# No Frontmatter" in body


# ---------------------------------------------------------------------------
# extract_summary tests
# ---------------------------------------------------------------------------

class TestExtractSummary:
    def test_summary_extraction(self):
        body = """\
## Summary

This is the summary text.
It spans multiple lines.

## CFPF Phase Mapping

Other content here.
"""
        summary = extract_summary(body)
        assert "This is the summary text." in summary
        assert "It spans multiple lines." in summary
        assert "CFPF Phase Mapping" not in summary

    def test_empty_summary(self):
        body = "## Other Section\n\nContent."
        summary = extract_summary(body)
        assert summary == ""


# ---------------------------------------------------------------------------
# extract_evidence tests
# ---------------------------------------------------------------------------

class TestExtractEvidence:
    def test_evidence_parsing(self, valid_tp_file):
        body = extract_body(valid_tp_file)
        entries = extract_evidence(body)
        assert len(entries) == 2

        ev1 = entries[0]
        assert ev1["evidence_id"] == "EV-TP9999-2026-001"
        assert ev1["title"] == "Test Evidence Entry"
        assert ev1["source"] == "test investigation"
        assert ev1["cluster"] == "10.0.0.1"
        assert ev1["domain_count"] == "5"
        assert ev1["confidence"] == "High"

        ev2 = entries[1]
        assert ev2["evidence_id"] == "EV-TP9999-2026-002"
        assert ev2["confidence"] == "Medium"

    def test_no_evidence_section(self):
        body = "## Summary\n\nJust a summary."
        entries = extract_evidence(body)
        assert entries == []


# ---------------------------------------------------------------------------
# _insert_multi / _fetch_list whitelist tests
# ---------------------------------------------------------------------------

class TestSQLWhitelist:
    def test_valid_table_column_pairs(self, test_db):
        """All valid pairs should work without error."""
        for table, col in _VALID_MULTI_TABLES:
            _insert_multi(test_db, table, "TP-TEST", col, ["test-value"])
            result = _fetch_list(test_db, table, col, "TP-TEST")
            assert "test-value" in result

    def test_invalid_table_raises_error(self, test_db):
        """Invalid table/column pairs should raise ValueError."""
        with pytest.raises(ValueError, match="Invalid table/column pair"):
            _insert_multi(test_db, "evil_table", "TP-TEST", "sector", ["val"])

    def test_invalid_column_raises_error(self, test_db):
        with pytest.raises(ValueError, match="Invalid table/column pair"):
            _fetch_list(test_db, "submission_sectors", "evil_col", "TP-TEST")

    def test_empty_values_skipped(self, test_db):
        """Empty or None values should be silently skipped."""
        _insert_multi(test_db, "submission_sectors", "TP-TEST2", "sector",
                       ["banking", "", None, "insurance"])
        result = _fetch_list(test_db, "submission_sectors", "sector", "TP-TEST2")
        assert result == ["banking", "insurance"]

    def test_non_list_values_skipped(self, test_db):
        """Non-list values should be silently ignored."""
        _insert_multi(test_db, "submission_sectors", "TP-TEST3", "sector", "not-a-list")
        result = _fetch_list(test_db, "submission_sectors", "sector", "TP-TEST3")
        assert result == []


# ---------------------------------------------------------------------------
# Regulatory alerts tests
# ---------------------------------------------------------------------------

class TestRegulatoryAlerts:
    def test_regulatory_schema_creates_tables(self, test_db):
        """Verify both regulatory tables exist after init_database."""
        tables = test_db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        ).fetchall()
        table_names = [r[0] for r in tables]
        assert "regulatory_alerts" in table_names
        assert "regulatory_alert_tp_mapping" in table_names

    def test_build_regulatory_alerts_from_csv(self, tmp_path, test_db):
        """Write a test CSV, call build_regulatory_alerts, verify rows in both tables."""
        csv_path = tmp_path / "regulatory_alerts.csv"
        csv_path.write_text(
            "alert_id,source,title,date,category,severity,url,summary,mapped_tp_ids\n"
            "REG-001,fincen,Test Alert 1,2026-01-15,money-laundering,high,https://example.com/1,Summary one,TP-0001|TP-0003\n"
            "REG-002,cfpb,Test Alert 2,2026-01-20,elder-fraud,medium,https://example.com/2,Summary two,TP-0005\n",
            encoding="utf-8",
        )
        count = build_regulatory_alerts(test_db, csv_path)
        assert count == 2

        # Verify alerts table
        rows = test_db.execute(
            "SELECT alert_id, source, title, severity FROM regulatory_alerts ORDER BY alert_id"
        ).fetchall()
        assert len(rows) == 2
        assert rows[0] == ("REG-001", "fincen", "Test Alert 1", "high")
        assert rows[1] == ("REG-002", "cfpb", "Test Alert 2", "medium")

        # Verify TP mapping table
        mappings = test_db.execute(
            "SELECT alert_id, tp_id FROM regulatory_alert_tp_mapping ORDER BY alert_id, tp_id"
        ).fetchall()
        assert len(mappings) == 3
        assert mappings[0] == ("REG-001", "TP-0001")
        assert mappings[1] == ("REG-001", "TP-0003")
        assert mappings[2] == ("REG-002", "TP-0005")

    def test_build_regulatory_alerts_missing_csv(self, tmp_path, test_db):
        """Pass nonexistent path, verify returns 0."""
        missing_path = tmp_path / "nonexistent.csv"
        count = build_regulatory_alerts(test_db, missing_path)
        assert count == 0
